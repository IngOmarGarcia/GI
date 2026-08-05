# SIGCF · Pasarela de diagnóstico SAT

Servicio auxiliar que permite al SPA (`index.html`) probar la conexión **real** con
los servicios del SAT.

## Por qué existe

El SPA no puede llamar al SAT directamente. Tres obstáculos, ninguno evitable desde
el navegador:

1. **CORS.** Los endpoints del SAT no envían cabeceras `Access-Control-Allow-Origin`.
   El navegador bloquea la respuesta antes de que el JavaScript pueda leerla.
2. **Firma XML-DSig.** La autenticación exige firmar un sobre WS-Security con la
   llave privada de la e.firma (PKCS#8 cifrado), algo que WebCrypto no puede
   descifrar directamente.
3. **CIEC no es una API.** El acceso con RFC + contraseña CIEC es un portal web con
   captcha. No existe servicio programable. Esta pasarela lo rechaza explícitamente
   (`CIEC_NO_SOPORTADA`) en lugar de simular una respuesta.

El único servicio del SAT realmente automatizable con la e.firma es **Descarga
Masiva de CFDI**, y es contra el que se diagnostica.

## Arranque

```bash
cd sat-gateway
npm install
npm start                 # http://localhost:8787
```

Variables opcionales:

| Variable      | Por defecto | Uso                                              |
|---------------|-------------|--------------------------------------------------|
| `PORT`        | `8787`      | Puerto de escucha                                 |
| `CORS_ORIGIN` | `*`         | Orígenes permitidos, separados por coma           |

En producción fije `CORS_ORIGIN` al origen real del SPA.

## Endpoints

### `GET /api/sat/salud`
Sonda de alcance. Contacta los cuatro hosts del SAT **sin enviar credenciales** y
reporta si responden. Útil para separar "no hay red" de "la credencial falla".

### `POST /api/sat/diagnostico` (multipart)

| Campo      | Tipo    | Descripción                                              |
|------------|---------|-----------------------------------------------------------|
| `cer`      | archivo | Certificado de la e.firma (`.cer`, DER o PEM)             |
| `key`      | archivo | Llave privada (`.key`, PKCS#8 cifrado)                    |
| `password` | texto   | Contraseña de la llave privada                            |
| `rfc`      | texto   | RFC esperado; se contrasta contra el del certificado      |
| `conectar` | texto   | `false` para validar sólo en local, sin contactar al SAT  |

Ejecuta seis pasos y devuelve el resultado de cada uno:

1. Lectura del certificado X.509 (RFC, titular, número de certificado, vigencia)
2. Vigencia
3. RFC declarado vs. RFC del certificado
4. Descifrado de la llave privada con la contraseña
5. Correspondencia `.cer` ↔ `.key` — prueba criptográfica: firma un nonce y lo
   verifica con la clave pública del certificado, no compara metadatos
6. Autenticación real contra el SAT (obtención del token WRAP)

## Manejo de credenciales

- Los archivos viajan en memoria (`multer.memoryStorage()`). **Nunca tocan disco.**
- Los buffers se sobrescriben con ceros al terminar cada petición.
- La contraseña y la llave no se registran en logs ni se devuelven en la respuesta;
  hay una prueba automatizada que lo verifica (`pruebas/api.test.js`, casos 8).
- Del token del SAT sólo se devuelve un prefijo: es una credencial viva.
- No hay base de datos. Este servicio no persiste absolutamente nada.

## Pruebas

```bash
npm run prueba-crypto              # pipeline criptográfico (21 casos)
node pruebas/api.test.js           # contrato de la API (18 casos)
```

Ambas fabrican un par `.cer`/`.key` al vuelo con OpenSSL, imitando la estructura de
una e.firma real (RFC en el OID `2.5.4.45`, llave PKCS#8 cifrada). No requieren
credenciales reales.

## Estado de verificación

| Componente                                        | Estado                                    |
|---------------------------------------------------|-------------------------------------------|
| Lectura del `.cer`, descifrado del `.key`, par     | ✔ Verificado con pares generados          |
| Firma XML-DSig del sobre (digest + RSA-SHA1)       | ✔ Verificado: la firma valida contra el `.cer` |
| Contrato de la API y aislamiento de credenciales   | ✔ Verificado                              |
| Alcance de red a los hosts del SAT                 | ✔ Verificado (HTTP 200)                   |
| **Aceptación del sobre por el SAT**                | ⚠ **Sin verificar** — requiere una e.firma real |

El último punto es el único que no se puede comprobar sin una e.firma vigente. El
sobre está construido según la especificación de Descarga Masiva, pero el SAT es
estricto con la canonicalización: si devuelve un fault en el paso 6, el diagnóstico
muestra el XML de respuesta acotado para poder ajustarlo.
