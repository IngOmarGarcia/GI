'use strict';
/* ---------------------------------------------------------------------------
   FIEL / e.firma — lectura real del par (.cer, .key)

   Todo lo de este módulo es criptografía verificable y funciona sin red:
     · Se parsea el certificado X.509 emitido por el SAT (viene en DER).
     · Se descifra la llave privada (PKCS#8 cifrado) con la contraseña.
     · Se comprueba que la llave corresponde al certificado firmando un nonce
       y verificando la firma con la clave pública del certificado.

   Ningún dato se escribe a disco ni se registra en bitácora.
   ------------------------------------------------------------------------- */
const crypto = require('crypto');
const { X509Certificate } = crypto;

/** El RFC va en el subject bajo el OID 2.5.4.45 (x500UniqueIdentifier). */
const OID_RFC = '2.5.4.45';
const RE_RFC = /\b([A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3})\b/;

/** Convierte el subject/issuer multilínea de Node a un mapa {clave: valor}. */
function campos(dn) {
  const out = {};
  String(dn || '').split('\n').forEach(linea => {
    const i = linea.indexOf('=');
    if (i > 0) out[linea.slice(0, i).trim()] = linea.slice(i + 1).trim();
  });
  return out;
}

/**
 * El «número de certificado» que exige el SAT (20 dígitos) es el serial
 * hexadecimal del X.509 interpretado como ASCII. Si no decodifica a 20
 * dígitos se devuelve el hexadecimal tal cual, sin inventar nada.
 */
function numeroCertificado(serialHex) {
  const hex = String(serialHex || '').replace(/[^0-9a-f]/gi, '');
  if (hex.length % 2 !== 0) return hex;
  const ascii = Buffer.from(hex, 'hex').toString('latin1');
  return /^\d{20}$/.test(ascii) ? ascii : hex;
}

/** Lee el .cer (DER o PEM) y devuelve sus datos reales. */
function leerCertificado(buffer) {
  const x509 = new X509Certificate(buffer);
  const sub = campos(x509.subject);
  const iss = campos(x509.issuer);

  // El RFC puede venir bajo el OID crudo o ya resuelto por OpenSSL.
  const crudoRfc = sub[OID_RFC] || sub['OID.' + OID_RFC] || sub.x500UniqueIdentifier || '';
  // Puede traer «RFC / RFC-del-representante»: nos quedamos con el primero.
  const rfc = (crudoRfc.split('/')[0].trim().toUpperCase().match(RE_RFC) || [])[1]
    || (String(x509.subject).toUpperCase().match(RE_RFC) || [])[1] || null;

  const desde = new Date(x509.validFrom);
  const hasta = new Date(x509.validTo);
  const ahora = new Date();

  return {
    rfc,
    titular: sub.CN || sub.O || null,
    curp: sub.serialNumber && /^[A-Z]{4}\d{6}[A-Z]{6}[A-Z0-9]{2}$/.test(sub.serialNumber)
      ? sub.serialNumber : null,
    numeroCertificado: numeroCertificado(x509.serialNumber),
    serialHex: x509.serialNumber,
    emisor: iss.CN || iss.O || null,
    validoDesde: desde.toISOString(),
    validoHasta: hasta.toISOString(),
    vigente: ahora >= desde && ahora <= hasta,
    diasRestantes: Math.floor((hasta - ahora) / 86400000),
    huellaSHA1: x509.fingerprint.replace(/:/g, '').toLowerCase(),
    huellaSHA256: x509.fingerprint256.replace(/:/g, '').toLowerCase(),
    algoritmoLlave: x509.publicKey.asymmetricKeyType,
    bitsLlave: x509.publicKey.asymmetricKeyDetails
      ? x509.publicKey.asymmetricKeyDetails.modulusLength : null,
    // Heurística documentada: el certificado de sello digital (CSD) declara
    // únicamente firma digital; la e.firma añade no repudio. No es normativo
    // — se informa el campo crudo para que el operador juzgue.
    keyUsage: x509.keyUsage || null,
    x509,
  };
}

/**
 * Descifra la llave privada. El .key del SAT es PKCS#8 CIFRADO en DER.
 * Node delega en OpenSSL, así que la contraseña se valida de verdad:
 * si es incorrecta, lanza y no hay forma de que un diagnóstico pase por error.
 */
function leerLlavePrivada(buffer, passphrase) {
  const esPem = buffer.slice(0, 11).toString('latin1').includes('-----BEGIN');
  try {
    return crypto.createPrivateKey({
      key: esPem ? buffer.toString('latin1') : buffer,
      format: esPem ? 'pem' : 'der',
      type: 'pkcs8',
      passphrase,
    });
  } catch (e) {
    const m = String(e.message || '');
    if (/bad decrypt|wrong final block|BAD_DECRYPT|incorrect password/i.test(m)) {
      const err = new Error('La contraseña de la llave privada es incorrecta.');
      err.codigo = 'PASSWORD_INCORRECTA';
      throw err;
    }
    if (/asn1|DECODER|unsupported|header too long/i.test(m)) {
      const err = new Error(
        'El archivo .key no tiene el formato PKCS#8 esperado. Verifique que sea la llave de la e.firma y no otro archivo.');
      err.codigo = 'KEY_FORMATO_INVALIDO';
      throw err;
    }
    throw e;
  }
}

/**
 * Comprueba que la llave privada corresponde al certificado.
 * No compara metadatos: firma un nonce aleatorio y verifica la firma con la
 * clave pública del .cer. Es prueba criptográfica, no una coincidencia de texto.
 */
function verificarPar(x509, privateKey) {
  const nonce = crypto.randomBytes(32);
  const firma = crypto.sign('sha256', nonce, privateKey);
  return crypto.verify('sha256', nonce, x509.publicKey, firma);
}

module.exports = { leerCertificado, leerLlavePrivada, verificarPar, numeroCertificado };
