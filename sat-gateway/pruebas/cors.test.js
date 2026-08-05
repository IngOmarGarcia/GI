'use strict';
/* ---------------------------------------------------------------------------
   Verifica que CORS_ORIGIN restrinja de verdad el acceso a la pasarela.

   Importa: sin esta restricción, cualquier página de internet podría usar la
   pasarela como intermediaria hacia el SAT. En Render el valor lo fija
   render.yaml (https://gi-gestion.netlify.app).

   Uso:  node pruebas/cors.test.js
   ------------------------------------------------------------------------- */
const NETLIFY = 'https://gi-gestion.netlify.app';
process.env.CORS_ORIGIN = NETLIFY;

const app = require('../server');
const servidor = app.listen(0);
const base = `http://127.0.0.1:${servidor.address().port}`;

let fallos = 0;
const eq = (etiqueta, real, esperado) => {
  const ok = JSON.stringify(real) === JSON.stringify(esperado);
  if (!ok) { fallos++; console.log(`FALLA  ${etiqueta}\n   real=${JSON.stringify(real)}\n   esp =${JSON.stringify(esperado)}`); }
  else console.log(`PASS   ${etiqueta}  -> ${JSON.stringify(real)}`);
};

/** Devuelve la cabecera Access-Control-Allow-Origin para un Origin dado. */
async function permitido(origin) {
  const res = await fetch(`${base}/api/sat/salud`, { headers: { Origin: origin } });
  return res.headers.get('access-control-allow-origin');
}

/** Simula el preflight que manda el navegador antes de un POST multipart. */
async function preflight(origin) {
  const res = await fetch(`${base}/api/sat/diagnostico`, {
    method: 'OPTIONS',
    headers: { Origin: origin, 'Access-Control-Request-Method': 'POST' },
  });
  return { status: res.status, allow: res.headers.get('access-control-allow-origin') };
}

(async () => {
  eq('el dominio de Netlify queda autorizado', await permitido(NETLIFY), NETLIFY);

  // Un origen ajeno no recibe la cabecera: el navegador bloqueará la respuesta.
  eq('un origen ajeno no recibe autorización', await permitido('https://sitio-malicioso.com'), null);
  eq('un subdominio parecido tampoco', await permitido('https://gi-gestion.netlify.app.evil.com'), null);
  eq('http en vez de https tampoco', await permitido('http://gi-gestion.netlify.app'), null);

  const okPre = await preflight(NETLIFY);
  eq('preflight autorizado para Netlify', okPre.allow, NETLIFY);
  eq('preflight responde sin error', okPre.status < 400, true);

  const malPre = await preflight('https://sitio-malicioso.com');
  eq('preflight de origen ajeno sin autorización', malPre.allow, null);

  servidor.close();
  console.log(fallos ? `\n${fallos} FALLA(S)` : '\nTodo correcto — CORS restringido al dominio del SPA');
  process.exit(fallos ? 1 : 0);
})();
