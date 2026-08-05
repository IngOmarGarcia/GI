'use strict';
/* ---------------------------------------------------------------------------
   Prueba de extremo a extremo de la API de la pasarela, con un par (.cer/.key)
   generado al vuelo. Levanta el servidor real en un puerto efímero y le manda
   peticiones multipart auténticas.

   La llamada al SAT se desactiva con conectar=false: aquí se verifica el
   contrato de la API y la cadena de validación local, no la red del SAT.

   Uso:  node pruebas/api.test.js
   ------------------------------------------------------------------------- */
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const app = require('../server');

const RFC = 'GIS210415AB7';
const PASS = 'contrasena-de-prueba-2026';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sigcf-api-'));
const p = f => path.join(dir, f);
const ssl = (...a) => execFileSync('openssl', a, { stdio: ['ignore', 'pipe', 'pipe'] });

let fallos = 0;
const eq = (etiqueta, real, esperado) => {
  const ok = JSON.stringify(real) === JSON.stringify(esperado);
  if (!ok) { fallos++; console.log(`FALLA  ${etiqueta}\n   real=${JSON.stringify(real)}\n   esp =${JSON.stringify(esperado)}`); }
  else console.log(`PASS   ${etiqueta}  -> ${JSON.stringify(real)}`);
};

fs.writeFileSync(p('o.cnf'), ['[req]', 'distinguished_name = dn', 'prompt = no',
  '[dn]', 'CN = GRUPO ISLO SA DE CV', `0.2.5.4.45 = ${RFC}`, 'C = MX'].join('\n'));
ssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '365', '-nodes',
    '-keyout', p('k.pem'), '-out', p('c.pem'), '-config', p('o.cnf'));
ssl('x509', '-in', p('c.pem'), '-outform', 'DER', '-out', p('c.cer'));
ssl('pkcs8', '-topk8', '-in', p('k.pem'), '-outform', 'DER', '-out', p('k.key'), '-passout', `pass:${PASS}`);

const cer = fs.readFileSync(p('c.cer'));
const key = fs.readFileSync(p('k.key'));

const servidor = app.listen(0);
const base = `http://127.0.0.1:${servidor.address().port}`;

/** Arma un multipart real y lo envía al endpoint de diagnóstico. */
async function diagnosticar(campos, archivos) {
  const fd = new FormData();
  Object.entries(campos).forEach(([k, v]) => fd.append(k, v));
  Object.entries(archivos).forEach(([k, buf]) =>
    fd.append(k, new Blob([buf], { type: 'application/octet-stream' }), `${k}.bin`));
  const res = await fetch(`${base}/api/sat/diagnostico`, { method: 'POST', body: fd });
  return { http: res.status, cuerpo: await res.json() };
}

(async () => {
  // 1 · Camino feliz, sin tocar la red del SAT.
  const ok = await diagnosticar({ rfc: RFC, password: PASS, conectar: 'false' }, { cer, key });
  eq('HTTP 200 en validación local', ok.http, 200);
  eq('ok=true', ok.cuerpo.ok, true);
  eq('código SOLO_LOCAL', ok.cuerpo.codigo, 'SOLO_LOCAL');
  eq('todos los pasos en verde', ok.cuerpo.pasos.every(s => s.ok), true);
  eq('RFC leído del certificado', ok.cuerpo.pasos[0].datos.rfc, RFC);
  eq('se ejecutaron los 5 pasos locales', ok.cuerpo.pasos.length, 5);

  // 2 · Contraseña incorrecta.
  const mala = await diagnosticar({ rfc: RFC, password: 'no-es', conectar: 'false' }, { cer, key });
  eq('HTTP 422 con contraseña mala', mala.http, 422);
  eq('código PASSWORD_INCORRECTA', mala.cuerpo.codigo, 'PASSWORD_INCORRECTA');

  // 3 · RFC que no corresponde al certificado.
  const otroRfc = await diagnosticar({ rfc: 'XAXX010101000', password: PASS, conectar: 'false' }, { cer, key });
  eq('paso de RFC marcado en rojo',
     otroRfc.cuerpo.pasos.find(s => s.paso.startsWith('RFC')).ok, false);

  // 4 · CIEC: se rechaza explícitamente en vez de simularse.
  const ciec = await diagnosticar({ rfc: RFC, password: PASS, modo: 'ciec' }, {});
  eq('HTTP 400 para CIEC', ciec.http, 400);
  eq('código CIEC_NO_SOPORTADA', ciec.cuerpo.codigo, 'CIEC_NO_SOPORTADA');

  // 5 · Faltan archivos.
  const sinArchivos = await diagnosticar({ rfc: RFC, password: PASS }, {});
  eq('HTTP 400 sin archivos', sinArchivos.http, 400);
  eq('código ARCHIVOS_FALTANTES', sinArchivos.cuerpo.codigo, 'ARCHIVOS_FALTANTES');

  // 6 · Falta contraseña.
  const sinPass = await diagnosticar({ rfc: RFC, password: '', conectar: 'false' }, { cer, key });
  eq('código PASSWORD_FALTANTE', sinPass.cuerpo.codigo, 'PASSWORD_FALTANTE');

  // 7 · .cer que no es un certificado.
  const cerMalo = await diagnosticar({ rfc: RFC, password: PASS, conectar: 'false' },
    { cer: Buffer.from('no soy un certificado'), key });
  eq('código CER_INVALIDO', cerMalo.cuerpo.codigo, 'CER_INVALIDO');

  // 8 · Ninguna respuesta debe filtrar la contraseña ni material de la llave.
  const serializado = JSON.stringify([ok, mala, otroRfc, cerMalo]);
  eq('la contraseña nunca aparece en las respuestas', serializado.includes(PASS), false);
  eq('la llave privada nunca aparece en las respuestas',
     serializado.includes(key.toString('base64').slice(0, 40)), false);

  // 9 · Health check de la plataforma: instantáneo y sin dependencias externas.
  const t0 = Date.now();
  const hz = await (await fetch(`${base}/healthz`)).json();
  const msHz = Date.now() - t0;
  eq('/healthz responde ok', hz.ok, true);
  eq('/healthz reporta el servicio', hz.servicio, 'sigcf-sat-gateway');
  // Si tardara, sería señal de que consulta a terceros: eso tumbaría el deploy.
  eq('/healthz responde en menos de 500 ms', msHz < 500, true);

  // 10 · Sonda de red real hacia el SAT (endpoint aparte, invocado a mano).
  const salud = await (await fetch(`${base}/api/sat/salud`)).json();
  eq('salud reporta los 4 endpoints del SAT', Object.keys(salud.endpoints).length, 4);
  console.log('\nAlcance real a los hosts del SAT desde esta máquina:');
  Object.entries(salud.endpoints).forEach(([k, v]) =>
    console.log(`   ${v.alcanzable ? 'OK  ' : 'FALLO'} ${k.padEnd(14)} ${v.alcanzable ? `HTTP ${v.http} (${v.ms} ms)` : v.error}`));

  servidor.close();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(fallos ? `\n${fallos} FALLA(S)` : '\nTodo correcto — contrato de la API verificado');
  process.exit(fallos ? 1 : 0);
})();
