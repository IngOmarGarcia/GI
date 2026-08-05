'use strict';
/* ---------------------------------------------------------------------------
   Verifica el pipeline criptográfico de la pasarela con un par (.cer/.key)
   generado al vuelo que imita la estructura de una e.firma del SAT:
   subject con el RFC bajo el OID 2.5.4.45 y llave PKCS#8 cifrada.

   NO contacta al SAT. Comprueba exactamente lo que corre de nuestro lado:
   lectura del certificado, descifrado de la llave, correspondencia del par y
   validez de la firma XML-DSig del sobre de autenticación.

   Uso:  node pruebas/crypto.test.js
   ------------------------------------------------------------------------- */
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { leerCertificado, leerLlavePrivada, verificarPar } = require('../lib/fiel');
const { sobreAutenticacion } = require('../lib/soap-sat');

const RFC = 'GIS210415AB7';
const TITULAR = 'GRUPO ISLO SA DE CV';
const PASS = 'contrasena-de-prueba-2026';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sigcf-fiel-'));
const p = f => path.join(dir, f);
const ssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });

let fallos = 0;
const eq = (etiqueta, real, esperado) => {
  const ok = JSON.stringify(real) === JSON.stringify(esperado);
  if (!ok) { fallos++; console.log(`FALLA  ${etiqueta}\n   real=${JSON.stringify(real)}\n   esp =${JSON.stringify(esperado)}`); }
  else console.log(`PASS   ${etiqueta}${real === true ? '' : '  -> ' + JSON.stringify(real)}`);
};

/* ---- 1 · Fabricar un par que imite la e.firma ---------------------------- */
// El SAT coloca el RFC en el subject bajo el OID 2.5.4.45 (x500UniqueIdentifier).
// El prefijo «0.» es sintaxis de OpenSSL para permitir campos repetidos: se
// descarta al leer, dejando el OID literal. Sin él, OpenSSL trunca a «5.4.45».
fs.writeFileSync(p('openssl.cnf'), [
  '[req]', 'distinguished_name = dn', 'prompt = no',
  '[dn]', `CN = ${TITULAR}`, `O = ${TITULAR}`, `0.2.5.4.45 = ${RFC}`, 'C = MX',
].join('\n'));

ssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '365', '-nodes',
    '-keyout', p('llave-plana.pem'), '-out', p('cert.pem'), '-config', p('openssl.cnf'));

// .cer del SAT = DER;  .key del SAT = PKCS#8 cifrado en DER.
ssl('x509', '-in', p('cert.pem'), '-outform', 'DER', '-out', p('cert.cer'));
ssl('pkcs8', '-topk8', '-in', p('llave-plana.pem'), '-outform', 'DER',
    '-out', p('llave.key'), '-passout', `pass:${PASS}`);

// Un segundo par, para probar que se detecta un .key que no corresponde.
ssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '365', '-nodes',
    '-keyout', p('otra-plana.pem'), '-out', p('otro.pem'), '-config', p('openssl.cnf'));
ssl('pkcs8', '-topk8', '-in', p('otra-plana.pem'), '-outform', 'DER',
    '-out', p('otra.key'), '-passout', `pass:${PASS}`);

const cerDer = fs.readFileSync(p('cert.cer'));
const keyDer = fs.readFileSync(p('llave.key'));
const otraKey = fs.readFileSync(p('otra.key'));

/* ---- 2 · Lectura del certificado ----------------------------------------- */
const cert = leerCertificado(cerDer);
eq('RFC extraído del OID 2.5.4.45', cert.rfc, RFC);
eq('Titular (CN)', cert.titular, TITULAR);
eq('Certificado vigente', cert.vigente, true);
eq('Algoritmo de llave', cert.algoritmoLlave, 'rsa');
eq('Tamaño de llave', cert.bitsLlave, 2048);
eq('Huella SHA-1 con 40 hex', /^[0-9a-f]{40}$/.test(cert.huellaSHA1), true);
eq('numeroCertificado presente', typeof cert.numeroCertificado === 'string' && cert.numeroCertificado.length > 0, true);

/* ---- 3 · Llave privada --------------------------------------------------- */
const llave = leerLlavePrivada(keyDer, PASS);
eq('Llave PKCS#8 descifrada', llave.asymmetricKeyType, 'rsa');

let codigoPass = null;
try { leerLlavePrivada(keyDer, 'contrasena-equivocada'); }
catch (e) { codigoPass = e.codigo; }
eq('Contraseña incorrecta se detecta', codigoPass, 'PASSWORD_INCORRECTA');

let codigoFormato = null;
try { leerLlavePrivada(Buffer.from('esto no es una llave'), PASS); }
catch (e) { codigoFormato = e.codigo; }
eq('Archivo .key basura se rechaza', codigoFormato, 'KEY_FORMATO_INVALIDO');

/* ---- 4 · Correspondencia del par ----------------------------------------- */
eq('Par correcto se acepta', verificarPar(cert.x509, llave), true);
eq('Par cruzado se rechaza', verificarPar(cert.x509, leerLlavePrivada(otraKey, PASS)), false);

/* ---- 5 · Sobre SOAP firmado ---------------------------------------------- */
const sobre = sobreAutenticacion({ cerDer, privateKey: llave });

// 5a · El digest del Timestamp debe corresponder al Timestamp realmente enviado.
const tsEnviado = sobre.envelope.match(/<u:Timestamp[\s\S]*?<\/u:Timestamp>/)[0];
const digestRecalculado = crypto.createHash('sha1').update(tsEnviado, 'utf8').digest('base64');
eq('DigestValue corresponde al Timestamp enviado', digestRecalculado, sobre.digest);

// 5b · La firma debe validar contra la clave pública del certificado.
const signedInfoEnviado = sobre.envelope.match(/<SignedInfo[\s\S]*?<\/SignedInfo>/)[0];
const firmaValida = crypto.createVerify('RSA-SHA1')
  .update(signedInfoEnviado, 'utf8')
  .verify(cert.x509.publicKey, sobre.signatureValue, 'base64');
eq('SignatureValue verifica con la clave pública del .cer', firmaValida, true);

// 5c · El digest declarado dentro del SignedInfo es el que se firmó.
eq('DigestValue incrustado en SignedInfo', signedInfoEnviado.includes(`<DigestValue>${sobre.digest}</DigestValue>`), true);

// 5d · Estructura WS-Security exigida por el SAT.
eq('BinarySecurityToken con el .cer en base64',
   sobre.envelope.includes(cerDer.toString('base64')), true);
eq('Referencia al Timestamp firmado (#_0)', sobre.envelope.includes('URI="#_0"'), true);
eq('Operación Autentica en el Body',
   sobre.envelope.includes('<Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"></Autentica>'), true);
eq('Elementos vacíos expandidos (exc-c14n)', /<CanonicalizationMethod [^>]*><\/CanonicalizationMethod>/.test(signedInfoEnviado), true);
eq('Created/Expires en formato del SAT',
   /<u:Created>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z<\/u:Created>/.test(tsEnviado), true);

// 5e · La ventana del timestamp es de 5 minutos.
eq('Ventana de vigencia de 5 min',
   (new Date(sobre.expires) - new Date(sobre.created)) / 60000, 5);

/* ---- Limpieza ------------------------------------------------------------ */
fs.rmSync(dir, { recursive: true, force: true });

console.log(fallos ? `\n${fallos} FALLA(S)` : '\nTodo correcto — pipeline criptográfico verificado');
process.exit(fallos ? 1 : 0);
