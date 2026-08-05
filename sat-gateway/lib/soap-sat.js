'use strict';
/* ---------------------------------------------------------------------------
   Cliente SOAP del Servicio de Descarga Masiva de CFDI del SAT.

   Es el único servicio del SAT realmente programable con la e.firma. El acceso
   con RFC + CIEC NO tiene API: es un portal web con captcha, y por eso este
   módulo lo rechaza explícitamente en vez de simularlo.

   Flujo de autenticación (WS-Security + XML-DSig):
     1 · Se arma un <u:Timestamp> con Created/Expires.
     2 · Se calcula su digest SHA-1 sobre la forma canónica exc-c14n.
     3 · Se firma el <SignedInfo> con RSA-SHA1 usando la llave de la e.firma.
     4 · Se envía el certificado en un <o:BinarySecurityToken>.
     5 · El SAT responde <AutenticaResult> con un token que se usa después como
         cabecera  Authorization: WRAP access_token="<token>".

   Nota de canonicalización: en exc-c14n los elementos vacíos se serializan
   expandidos (<X></X>, nunca <X/>). Por eso tanto lo que se firma como lo que
   se envía usan la forma expandida: así el digest que calcula el SAT coincide
   byte a byte con el nuestro.
   ------------------------------------------------------------------------- */
const crypto = require('crypto');

const ENDPOINTS = {
  autenticacion: 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc',
  solicitud:     'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc',
  verificacion:  'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc',
  descarga:      'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc',
};

const NS = {
  wsu:  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
  wsse: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
  ds:   'http://www.w3.org/2000/09/xmldsig#',
  x509: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3',
  b64:  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary',
  sat:  'http://DescargaMasivaTerceros.gob.mx',
};

const isoSat = d => d.toISOString().replace(/\.\d{3}Z$/, '.000Z');

/** Arma el sobre SOAP firmado de la operación Autentica. */
function sobreAutenticacion({ cerDer, privateKey, vigenciaSegundos = 300 }) {
  const creado = new Date();
  const expira = new Date(creado.getTime() + vigenciaSegundos * 1000);
  const idToken = `uuid-${crypto.randomUUID()}-1`;
  const cerB64 = Buffer.from(cerDer).toString('base64');

  // 1 · Timestamp en forma canónica: se firma exactamente esta cadena.
  const timestamp =
    `<u:Timestamp xmlns:u="${NS.wsu}" u:Id="_0">` +
    `<u:Created>${isoSat(creado)}</u:Created>` +
    `<u:Expires>${isoSat(expira)}</u:Expires>` +
    `</u:Timestamp>`;

  const digest = crypto.createHash('sha1').update(timestamp, 'utf8').digest('base64');

  // 2 · SignedInfo canónico (elementos vacíos expandidos).
  const signedInfo =
    `<SignedInfo xmlns="${NS.ds}">` +
    `<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>` +
    `<SignatureMethod Algorithm="${NS.ds}rsa-sha1"></SignatureMethod>` +
    `<Reference URI="#_0">` +
    `<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms>` +
    `<DigestMethod Algorithm="${NS.ds}sha1"></DigestMethod>` +
    `<DigestValue>${digest}</DigestValue>` +
    `</Reference></SignedInfo>`;

  // 3 · Firma RSA-SHA1 sobre el SignedInfo canónico.
  const signatureValue = crypto.createSign('RSA-SHA1')
    .update(signedInfo, 'utf8').sign(privateKey, 'base64');

  const envelope =
    `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="${NS.wsu}">` +
    `<s:Header>` +
    `<o:Security s:mustUnderstand="1" xmlns:o="${NS.wsse}">` +
    timestamp +
    `<o:BinarySecurityToken u:Id="${idToken}" ValueType="${NS.x509}" EncodingType="${NS.b64}">${cerB64}</o:BinarySecurityToken>` +
    `<Signature xmlns="${NS.ds}">` +
    signedInfo +
    `<SignatureValue>${signatureValue}</SignatureValue>` +
    `<KeyInfo><o:SecurityTokenReference>` +
    `<o:Reference URI="#${idToken}" ValueType="${NS.x509}"></o:Reference>` +
    `</o:SecurityTokenReference></KeyInfo>` +
    `</Signature>` +
    `</o:Security>` +
    `</s:Header>` +
    `<s:Body><Autentica xmlns="${NS.sat}"></Autentica></s:Body>` +
    `</s:Envelope>`;

  return { envelope, created: isoSat(creado), expires: isoSat(expira), digest, signatureValue };
}

/** Extrae el contenido de una etiqueta, ignorando el prefijo de namespace. */
const etiqueta = (xml, nombre) => {
  const m = String(xml).match(new RegExp(`<(?:[\\w.-]+:)?${nombre}[^>]*>([\\s\\S]*?)</(?:[\\w.-]+:)?${nombre}>`, 'i'));
  return m ? m[1].trim() : null;
};

/** Lee un s:Fault del SAT y lo convierte en mensaje legible. */
function leerFault(xml) {
  const faultstring = etiqueta(xml, 'faultstring') || etiqueta(xml, 'Reason') || etiqueta(xml, 'Text');
  const faultcode = etiqueta(xml, 'faultcode') || etiqueta(xml, 'Value');
  if (!faultstring && !faultcode) return null;
  return [faultcode, faultstring].filter(Boolean).join(' · ');
}

/**
 * Ejecuta la autenticación real contra el SAT.
 * Devuelve siempre un objeto estructurado: nunca lanza por un fallo de red,
 * para que el diagnóstico pueda reportar la causa exacta al operador.
 */
async function autenticar({ cerDer, privateKey, timeoutMs = 20000 }) {
  const { envelope, created, expires } = sobreAutenticacion({ cerDer, privateKey });
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  const t0 = Date.now();

  try {
    const res = await fetch(ENDPOINTS.autenticacion, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': `${NS.sat}/IAutenticacion/Autentica`,
      },
      body: envelope,
      signal: ctl.signal,
    });
    clearTimeout(t);
    const ms = Date.now() - t0;
    const xml = await res.text();
    const token = etiqueta(xml, 'AutenticaResult');

    if (res.ok && token) {
      return {
        ok: true, http: res.status, ms, token,
        expiraToken: etiqueta(xml, 'Expires') || expires,
        ventana: { created, expires },
      };
    }
    return {
      ok: false, http: res.status, ms,
      codigo: res.status === 401 || res.status === 403 ? 'CREDENCIAL_RECHAZADA' : 'SOAP_FAULT',
      detalle: leerFault(xml) || `El SAT respondió HTTP ${res.status} sin token de acceso.`,
      // Fragmento acotado: suficiente para diagnosticar, sin volcar el sobre completo.
      respuesta: xml.slice(0, 1200),
    };
  } catch (e) {
    clearTimeout(t);
    const ms = Date.now() - t0;
    if (e.name === 'AbortError') {
      return { ok: false, ms, codigo: 'TIMEOUT',
        detalle: `El SAT no respondió en ${timeoutMs / 1000} s.` };
    }
    return { ok: false, ms, codigo: 'RED',
      detalle: `No se pudo alcanzar el servicio del SAT: ${e.message}` };
  }
}

/** Sonda de alcance: ¿responden los hosts del SAT desde este servidor? */
async function sondear(timeoutMs = 8000) {
  const salida = {};
  await Promise.all(Object.entries(ENDPOINTS).map(async ([nombre, url]) => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    const t0 = Date.now();
    try {
      // Un GET al .svc devuelve la página de metadatos del WCF: basta para
      // confirmar alcance de red y TLS sin enviar credencial alguna.
      const res = await fetch(url, { method: 'GET', signal: ctl.signal });
      clearTimeout(t);
      salida[nombre] = { url, alcanzable: true, http: res.status, ms: Date.now() - t0 };
    } catch (e) {
      clearTimeout(t);
      salida[nombre] = { url, alcanzable: false, ms: Date.now() - t0,
        error: e.name === 'AbortError' ? 'timeout' : e.message };
    }
  }));
  return salida;
}

module.exports = { ENDPOINTS, sobreAutenticacion, autenticar, sondear, etiqueta, leerFault };
