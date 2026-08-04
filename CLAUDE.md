# 📄 ESPECIFICACIONES: Sistema Contable & Financiero (Demo 35 usuarios)

## 🎨 Paleta UI (RGB)
- Fondo: Crema `(253,247,240)` | Texto e Íconos: Gris Carbón `(74,74,74)`
- Acentuar: Dorado Claro `(238,187,98)` | Sombras: Bronce Oscuro `(145,91,31)`

## 🧱 Módulos & Funcionalidades
- **Contabilidad:** Reg. cronológico (compras, ventas, gastos, cobros), CxC, CxP, Conciliación bancaria, Balance general, Estado de resultados, Impuestos, Nómina (sueldos, extras, retenciones), Control interno, Presupuestos, Auditorías.
- **Finanzas:** Presupuesto anual, Análisis de costos, Estrategia económica, Inversión de excedentes, Financiamiento/créditos, Control de riesgos.
- **SAT & Fiscal:** Facturas mensuales, Constancia CSF, Opinión D-32, Declaraciones, Firma electrónica (e.firma).
- **IA & Configuración:** Config. RFC y Proveedor LLM (`OpenAI`, `Anthropic`, `Ollama`) -> Generación de análisis FODA.
- **Seguridad:** Autenticación 2FA (dos pasos), JWT, Cifrado, Auditoría, Control de sesiones.

## 👥 Roles
- **MASTER:** Acceso total, Monitor de errores en tiempo real, Logs, Estado del sistema.
- **ADMINISTRADOR:** Gestión de 35 usuarios (Alta/Baja/Asignación de claves/Permisos).
- **USUARIO:** Acceso restringido únicamente a sus módulos autorizados.

## 🗄️ Base de Datos (28 Tablas)
usuarios, roles, permisos, empresas, configuracion, sesiones, auditoria, operaciones_contables, cuentas_cobrar, cuentas_pagar, conciliaciones, estados_financieros, impuestos, nominas, presupuestos, auditorias, proyectos_financieros, inversiones, financiamientos, riesgos, facturas, declaraciones, constancias_sat, d32, firmas, foda, logs, integraciones.

## 💻 Tech Stack
SPA (Frontend) + API RESTful (Clean Architecture, SOLID, Repository Pattern).