'use strict';
/* ---------------------------------------------------------------------------
   SIGCF · Pasarela de diagnóstico SAT

   Existe por una razón concreta: los endpoints del SAT no envían cabeceras
   CORS, así que el SPA no puede llamarlos directamente desde el navegador.
   Este proceso hace la llamada del lado servidor y devuelve el resultado real.

   Reglas de manejo de credenciales (no negociables):
     · Los archivos viajan en memoria (multer memoryStorage). Nunca tocan disco.
     · La contraseña y la llave se descartan al terminar la petición.
     · No se registran en bitácora ni en logs: sólo metadatos del certificado.
     · No hay persistencia de ningún tipo. Este servicio no tiene base de datos.
   ------------------------------------------------------------------------- */
const express = require('express');
const cors = require('cors');
const multer = require('multer');

const { leerCertificado, leerLlavePrivada, verificarPar } = require('./lib/fiel');
const { autenticar, sondear, ENDPOINTS } = require('./lib/soap-sat');

const PUERTO = process.env.PORT || 87 * 100 + 87; // 8787
const ORIGENES = (process.env.CORS_ORIGIN || '*').split(',').map(s => s.trim());
const LIMITE_ARCHIVO = 64 * 1024; // un .cer/.key de la e.firma pesa unos pocos KB

const app = express();
app.use(cors({ origin: ORIGENES.includes('*') ? true : ORIGENES }));
app.use(express.json({ limit: '256kb' }));

const subida = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: LIMITE_ARCHIVO, files: 2 },
});

/** Borra el contenido de los buffers en cuanto dejan de usarse. */
const limpiar = (...buffers) => buffers.forEach(b => { if (Buffer.isBuffer(b)) b.fill(0); });

const paso = (nombre, ok, detalle, extra = {}) => ({ paso: nombre, ok, detalle, ...extra });

/* ---- Salud y alcance de red --------------------------------------------- */
app.get('/api/sat/salud', async (_req, res) => {
  const endpoints = await sondear();
  res.json({
    servicio: 'sigcf-sat-gateway',
    version: require('./package.json').version,
    node: process.version,
    hora: new Date().toISOString(),
    endpoints,
  });
});

/* ---- Diagnóstico completo ------------------------------------------------ */
app.post('/api/sat/diagnostico',
  subida.fields([{ name: 'cer', maxCount: 1 }, { name: 'key', maxCount: 1 }]),
  async (req, res) => {
    const pasos = [];
    const cerBuf = req.files?.cer?.[0]?.buffer;
    const keyBuf = req.files?.key?.[0]?.buffer;
    const password = req.body?.password || '';
    const rfcEsperado = String(req.body?.rfc || '').trim().toUpperCase();
    const modo = req.body?.modo || 'efirma';
    const conectar = String(req.body?.conectar ?? 'true') !== 'false';

    // El SAT no expone API para CIEC. Se dice, no se simula.
    if (modo === 'ciec') {
      return res.status(400).json({
        ok: false,
        codigo: 'CIEC_NO_SOPORTADA',
        mensaje: 'El SAT no publica ninguna API para autenticación con RFC + CIEC. '
          + 'El acceso con CIEC es un portal web protegido con captcha, no un servicio '
          + 'programable. El único servicio automatizable es Descarga Masiva de CFDI, '
          + 'que se autentica con la e.firma (.cer + .key).',
        pasos: [paso('Modo de autenticación', false, 'CIEC no es automatizable por diseño del SAT.')],
      });
    }

    if (!cerBuf || !keyBuf) {
      return res.status(400).json({
        ok: false, codigo: 'ARCHIVOS_FALTANTES',
        mensaje: 'Se requieren ambos archivos de la e.firma: el certificado (.cer) y la llave privada (.key).',
        pasos,
      });
    }
    if (!password) {
      return res.status(400).json({
        ok: false, codigo: 'PASSWORD_FALTANTE',
        mensaje: 'Falta la contraseña de la llave privada.',
        pasos,
      });
    }

    let cert = null, llave = null;

    try {
      /* 1 · Certificado ---------------------------------------------------- */
      try {
        cert = leerCertificado(cerBuf);
        pasos.push(paso('Lectura del certificado', true,
          `Certificado X.509 válido, emitido por ${cert.emisor || 'emisor desconocido'}.`,
          { datos: {
            rfc: cert.rfc, titular: cert.titular, curp: cert.curp,
            numeroCertificado: cert.numeroCertificado,
            validoDesde: cert.validoDesde, validoHasta: cert.validoHasta,
            huellaSHA1: cert.huellaSHA1, algoritmo: cert.algoritmoLlave,
            bits: cert.bitsLlave, keyUsage: cert.keyUsage,
          } }));
      } catch (e) {
        pasos.push(paso('Lectura del certificado', false,
          `No se pudo interpretar el archivo .cer: ${e.message}`));
        return res.status(422).json({ ok: false, codigo: 'CER_INVALIDO',
          mensaje: 'El archivo .cer no es un certificado X.509 legible.', pasos });
      }

      /* 2 · Vigencia ------------------------------------------------------- */
      pasos.push(paso('Vigencia del certificado', cert.vigente,
        cert.vigente
          ? `Vigente. Expira el ${cert.validoHasta.slice(0, 10)} (${cert.diasRestantes} días).`
          : `FUERA DE VIGENCIA. Periodo válido: ${cert.validoDesde.slice(0, 10)} a ${cert.validoHasta.slice(0, 10)}.`));

      /* 3 · RFC ------------------------------------------------------------ */
      if (rfcEsperado) {
        const coincide = cert.rfc === rfcEsperado;
        pasos.push(paso('RFC declarado vs. certificado', coincide,
          coincide ? `Coincide: ${cert.rfc}.`
                   : `NO coincide. Capturó ${rfcEsperado}; el certificado pertenece a ${cert.rfc || 'un RFC no legible'}.`));
      }

      /* 4 · Llave privada -------------------------------------------------- */
      try {
        llave = leerLlavePrivada(keyBuf, password);
        pasos.push(paso('Descifrado de la llave privada', true,
          'La contraseña abrió correctamente la llave PKCS#8.'));
      } catch (e) {
        pasos.push(paso('Descifrado de la llave privada', false, e.message));
        return res.status(422).json({ ok: false, codigo: e.codigo || 'KEY_INVALIDA',
          mensaje: e.message, pasos });
      }

      /* 5 · Correspondencia .cer <-> .key (prueba criptográfica) ------------ */
      const par = verificarPar(cert.x509, llave);
      pasos.push(paso('Correspondencia .cer / .key', par,
        par ? 'La llave privada corresponde al certificado (firma verificada con la clave pública).'
            : 'La llave privada NO corresponde a este certificado. Son de pares distintos.'));
      if (!par) {
        return res.status(422).json({ ok: false, codigo: 'PAR_NO_COINCIDE',
          mensaje: 'El .key no pertenece al .cer proporcionado.', pasos });
      }

      /* 6 · Autenticación real contra el SAT ------------------------------- */
      if (!conectar) {
        return res.json({ ok: true, codigo: 'SOLO_LOCAL',
          mensaje: 'Validación criptográfica local completada. No se contactó al SAT.', pasos });
      }

      const auth = await autenticar({ cerDer: cerBuf, privateKey: llave });
      if (auth.ok) {
        pasos.push(paso('Autenticación con el SAT', true,
          `El SAT emitió un token de acceso en ${auth.ms} ms.`,
          { datos: {
            http: auth.http, ms: auth.ms,
            tokenExpira: auth.expiraToken,
            // Sólo el prefijo: el token es una credencial viva.
            tokenPrefijo: String(auth.token).slice(0, 24) + '…',
            endpoint: ENDPOINTS.autenticacion,
          } }));
        return res.json({ ok: true, codigo: 'AUTENTICADO',
          mensaje: 'Conexión con el SAT verificada de extremo a extremo.', pasos });
      }

      pasos.push(paso('Autenticación con el SAT', false, auth.detalle,
        { datos: { codigo: auth.codigo, http: auth.http ?? null, ms: auth.ms,
                   endpoint: ENDPOINTS.autenticacion, respuesta: auth.respuesta } }));
      return res.status(502).json({ ok: false, codigo: auth.codigo,
        mensaje: auth.detalle, pasos });

    } catch (e) {
      pasos.push(paso('Error no controlado', false, e.message));
      return res.status(500).json({ ok: false, codigo: 'ERROR_INTERNO',
        mensaje: e.message, pasos });
    } finally {
      // La credencial deja de existir en este proceso.
      limpiar(cerBuf, keyBuf);
      llave = null;
    }
  });

/* Multer devuelve errores propios (archivo grande, exceso de campos). */
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ ok: false, codigo: 'ARCHIVO_RECHAZADO',
      mensaje: `${err.message} (límite ${LIMITE_ARCHIVO / 1024} KB por archivo).` });
  }
  return res.status(500).json({ ok: false, codigo: 'ERROR_INTERNO', mensaje: err.message });
});

if (require.main === module) {
  app.listen(PUERTO, () => {
    console.log(`SIGCF · pasarela SAT escuchando en http://localhost:${PUERTO}`);
    console.log(`Orígenes CORS permitidos: ${ORIGENES.join(', ')}`);
    console.log('Las credenciales se procesan en memoria y no se persisten.');
  });
}

module.exports = app;
