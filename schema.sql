-- =============================================================================
--  SIGCF · Sistema Integral de Gestión Contable & Financiera
--  Esquema relacional — 28 tablas
--  Motor objetivo: PostgreSQL 15+
--  Codificación: UTF-8 · Zona horaria: America/Monterrey (UTC-6)
--
--  Convenciones
--    · Claves primarias BIGSERIAL; claves foráneas con ON DELETE explícito.
--    · Toda tabla operativa se particiona lógicamente por empresa_id (multi-RFC).
--    · Importes en NUMERIC(18,2); tasas en NUMERIC(9,6).
--    · created_at / updated_at en TIMESTAMPTZ, mantenidos por trigger.
--    · Los estados usan tipos ENUM para integridad a nivel de motor.
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS sigcf;
SET search_path TO sigcf, public;

-- -----------------------------------------------------------------------------
--  TIPOS ENUMERADOS
-- -----------------------------------------------------------------------------
CREATE TYPE rol_sistema      AS ENUM ('MASTER','ADMIN','USUARIO');
CREATE TYPE tipo_operacion   AS ENUM ('COMPRA','VENTA','GASTO','COBRO','PAGO','AJUSTE');
CREATE TYPE naturaleza_cta   AS ENUM ('DEUDORA','ACREEDORA');
CREATE TYPE estado_doc       AS ENUM ('BORRADOR','PENDIENTE','CONCILIADA','OBSERVADA','CANCELADA');
CREATE TYPE estado_fiscal    AS ENUM ('VIGENTE','POR_VENCER','VENCIDA','REVOCADA');
CREATE TYPE opinion_d32      AS ENUM ('POSITIVA','NEGATIVA','NO_INSCRITO','SIN_OBLIGACIONES');
CREATE TYPE estado_decl      AS ENUM ('BORRADOR','PENDIENTE','PRESENTADA','COMPLEMENTARIA','RECHAZADA');
CREATE TYPE nivel_riesgo     AS ENUM ('BAJO','MEDIO','ALTO','CRITICO');
CREATE TYPE nivel_log        AS ENUM ('DEBUG','INFO','WARN','ERROR','FATAL');
CREATE TYPE proveedor_llm    AS ENUM ('OPENAI','ANTHROPIC','OLLAMA');
CREATE TYPE tipo_auditoria   AS ENUM ('INTERNA','EXTERNA','FISCAL');
CREATE TYPE estado_generico  AS ENUM ('ACTIVO','INACTIVO','SUSPENDIDO','CONCLUIDO');

-- =============================================================================
--  BLOQUE 1 · NÚCLEO: IDENTIDAD, SEGURIDAD Y CONFIGURACIÓN            (1 – 7)
-- =============================================================================

-- 1 -------------------------------------------------------------------- empresas
CREATE TABLE empresas (
    id                BIGSERIAL PRIMARY KEY,
    razon_social      VARCHAR(255) NOT NULL,
    rfc               VARCHAR(13)  NOT NULL,
    regimen_fiscal    VARCHAR(120) NOT NULL,
    codigo_postal     CHAR(5)      NOT NULL,
    domicilio_fiscal  TEXT,
    ejercicio_actual  SMALLINT     NOT NULL DEFAULT EXTRACT(YEAR FROM CURRENT_DATE),
    licencia_usuarios SMALLINT     NOT NULL DEFAULT 35,
    estado            estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_empresas_rfc   UNIQUE (rfc),
    CONSTRAINT ck_empresas_rfc   CHECK (rfc ~ '^[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}$'),
    CONSTRAINT ck_empresas_cupo  CHECK (licencia_usuarios BETWEEN 1 AND 500)
);
COMMENT ON TABLE empresas IS 'Contribuyentes (multi-RFC). Raíz de la segmentación de datos.';

-- 2 ---------------------------------------------------------------------- roles
CREATE TABLE roles (
    id            BIGSERIAL PRIMARY KEY,
    empresa_id    BIGINT       NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    clave         rol_sistema  NOT NULL,
    nombre        VARCHAR(80)  NOT NULL,
    descripcion   TEXT,
    es_sistema    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_roles_empresa_clave UNIQUE (empresa_id, clave)
);

-- 3 -------------------------------------------------------------------- usuarios
CREATE TABLE usuarios (
    id                 BIGSERIAL PRIMARY KEY,
    empresa_id         BIGINT       NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    rol_id             BIGINT       NOT NULL REFERENCES roles(id)    ON DELETE RESTRICT,
    nombre_completo    VARCHAR(160) NOT NULL,
    email              VARCHAR(180) NOT NULL,
    password_hash      TEXT         NOT NULL,              -- Argon2id, jamás texto plano
    departamento       VARCHAR(80),
    dos_fa_habilitado  BOOLEAN      NOT NULL DEFAULT TRUE,
    dos_fa_secret      TEXT,                                -- TOTP cifrado AES-256-GCM
    activo             BOOLEAN      NOT NULL DEFAULT TRUE,
    intentos_fallidos  SMALLINT     NOT NULL DEFAULT 0,
    bloqueado_hasta    TIMESTAMPTZ,
    ultimo_acceso      TIMESTAMPTZ,
    creado_por         BIGINT       REFERENCES usuarios(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_usuarios_email  UNIQUE (empresa_id, email),
    CONSTRAINT ck_usuarios_email  CHECK (email ~* '^[^@\s]+@[^@\s]+\.[a-z]{2,}$')
);
CREATE INDEX ix_usuarios_empresa_activo ON usuarios (empresa_id, activo);
CREATE INDEX ix_usuarios_rol            ON usuarios (rol_id);

-- 4 -------------------------------------------------------------------- permisos
CREATE TABLE permisos (
    id            BIGSERIAL PRIMARY KEY,
    rol_id        BIGINT      NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
    usuario_id    BIGINT      REFERENCES usuarios(id)          ON DELETE CASCADE,
    modulo        VARCHAR(40) NOT NULL,   -- dashboard, contabilidad, sat, foda, …
    puede_ver     BOOLEAN     NOT NULL DEFAULT TRUE,
    puede_crear   BOOLEAN     NOT NULL DEFAULT FALSE,
    puede_editar  BOOLEAN     NOT NULL DEFAULT FALSE,
    puede_borrar  BOOLEAN     NOT NULL DEFAULT FALSE,
    puede_exportar BOOLEAN    NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_permisos_scope UNIQUE (rol_id, usuario_id, modulo)
);
COMMENT ON COLUMN permisos.usuario_id IS 'NULL = permiso heredado del rol; con valor = excepción individual.';

-- 5 -------------------------------------------------------------- configuracion
CREATE TABLE configuracion (
    id                 BIGSERIAL PRIMARY KEY,
    empresa_id         BIGINT      NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    clave              VARCHAR(80) NOT NULL,
    valor              TEXT,
    valor_cifrado      BYTEA,                                  -- secretos AES-256-GCM
    tipo_dato          VARCHAR(20) NOT NULL DEFAULT 'string',
    jwt_expiracion_min SMALLINT    NOT NULL DEFAULT 30,
    max_sesiones       SMALLINT    NOT NULL DEFAULT 2,
    max_intentos_login SMALLINT    NOT NULL DEFAULT 5,
    exigir_dos_fa      BOOLEAN     NOT NULL DEFAULT TRUE,
    algoritmo_cifrado  VARCHAR(30) NOT NULL DEFAULT 'AES-256-GCM',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_configuracion_clave UNIQUE (empresa_id, clave)
);

-- 6 -------------------------------------------------------------------- sesiones
CREATE TABLE sesiones (
    id                BIGSERIAL PRIMARY KEY,
    usuario_id        BIGINT      NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    jwt_jti           UUID        NOT NULL DEFAULT gen_random_uuid(),
    refresh_token_hash TEXT,
    ip_origen         INET,
    user_agent        TEXT,
    dos_fa_validado   BOOLEAN     NOT NULL DEFAULT FALSE,
    emitido_en        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expira_en         TIMESTAMPTZ NOT NULL,
    revocado_en       TIMESTAMPTZ,
    CONSTRAINT uq_sesiones_jti UNIQUE (jwt_jti),
    CONSTRAINT ck_sesiones_exp CHECK (expira_en > emitido_en)
);
CREATE INDEX ix_sesiones_usuario_activa ON sesiones (usuario_id) WHERE revocado_en IS NULL;

-- 7 ------------------------------------------------------------------- auditoria
CREATE TABLE auditoria (
    id           BIGSERIAL PRIMARY KEY,
    empresa_id   BIGINT      NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id   BIGINT      REFERENCES usuarios(id) ON DELETE SET NULL,
    accion       VARCHAR(60) NOT NULL,          -- INSERT, UPDATE, DELETE, LOGIN_2FA_OK…
    entidad      VARCHAR(80) NOT NULL,
    entidad_id   BIGINT,
    datos_previos  JSONB,
    datos_nuevos   JSONB,
    ip_origen    INET,
    hash_cadena  CHAR(64),                       -- encadenamiento SHA-256 (inmutabilidad)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_auditoria_entidad ON auditoria (empresa_id, entidad, entidad_id);
CREATE INDEX ix_auditoria_fecha   ON auditoria (created_at DESC);
COMMENT ON TABLE auditoria IS 'Bitácora inmutable. Sin UPDATE/DELETE: revocar por política de motor.';

-- =============================================================================
--  BLOQUE 2 · CONTABILIDAD                                           (8 – 16)
-- =============================================================================

-- 8 -------------------------------------------------- operaciones_contables
CREATE TABLE operaciones_contables (
    id              BIGSERIAL PRIMARY KEY,
    empresa_id      BIGINT         NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id      BIGINT         REFERENCES usuarios(id) ON DELETE SET NULL,
    folio           VARCHAR(30)    NOT NULL,
    fecha_operacion DATE           NOT NULL,
    tipo            tipo_operacion NOT NULL,
    concepto        TEXT           NOT NULL,
    cuenta_contable VARCHAR(20)    NOT NULL,
    naturaleza      naturaleza_cta NOT NULL,
    cargo           NUMERIC(18,2)  NOT NULL DEFAULT 0,
    abono           NUMERIC(18,2)  NOT NULL DEFAULT 0,
    moneda          CHAR(3)        NOT NULL DEFAULT 'MXN',
    tipo_cambio     NUMERIC(12,6)  NOT NULL DEFAULT 1,
    uuid_cfdi       UUID,
    estado          estado_doc     NOT NULL DEFAULT 'PENDIENTE',
    periodo         CHAR(7)        NOT NULL,     -- YYYY-MM
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ops_folio     UNIQUE (empresa_id, folio),
    CONSTRAINT ck_ops_partida   CHECK (cargo >= 0 AND abono >= 0 AND (cargo = 0 OR abono = 0)),
    CONSTRAINT ck_ops_importe   CHECK (cargo + abono > 0)
);
CREATE INDEX ix_ops_periodo ON operaciones_contables (empresa_id, periodo, tipo);
CREATE INDEX ix_ops_fecha   ON operaciones_contables (fecha_operacion DESC);
CREATE INDEX ix_ops_uuid    ON operaciones_contables (uuid_cfdi) WHERE uuid_cfdi IS NOT NULL;

-- 9 --------------------------------------------------------- cuentas_cobrar
CREATE TABLE cuentas_cobrar (
    id             BIGSERIAL PRIMARY KEY,
    empresa_id     BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    operacion_id   BIGINT        REFERENCES operaciones_contables(id) ON DELETE SET NULL,
    documento      VARCHAR(30)   NOT NULL,
    cliente_nombre VARCHAR(200)  NOT NULL,
    cliente_rfc    VARCHAR(13),
    fecha_emision  DATE          NOT NULL,
    fecha_vencimiento DATE       NOT NULL,
    importe_original  NUMERIC(18,2) NOT NULL,
    saldo_pendiente   NUMERIC(18,2) NOT NULL,
    dias_vencido   INTEGER       GENERATED ALWAYS AS (GREATEST(0, CURRENT_DATE - fecha_vencimiento)) STORED,
    estado         estado_doc    NOT NULL DEFAULT 'PENDIENTE',
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cxc_doc     UNIQUE (empresa_id, documento),
    CONSTRAINT ck_cxc_saldo   CHECK (saldo_pendiente >= 0 AND saldo_pendiente <= importe_original),
    CONSTRAINT ck_cxc_fechas  CHECK (fecha_vencimiento >= fecha_emision)
);
CREATE INDEX ix_cxc_vencimiento ON cuentas_cobrar (empresa_id, fecha_vencimiento)
    WHERE saldo_pendiente > 0;

-- 10 --------------------------------------------------------- cuentas_pagar
CREATE TABLE cuentas_pagar (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    operacion_id      BIGINT        REFERENCES operaciones_contables(id) ON DELETE SET NULL,
    documento         VARCHAR(30)   NOT NULL,
    proveedor_nombre  VARCHAR(200)  NOT NULL,
    proveedor_rfc     VARCHAR(13),
    fecha_emision     DATE          NOT NULL,
    fecha_vencimiento DATE          NOT NULL,
    importe_original  NUMERIC(18,2) NOT NULL,
    saldo_pendiente   NUMERIC(18,2) NOT NULL,
    dias_vencido      INTEGER       GENERATED ALWAYS AS (GREATEST(0, CURRENT_DATE - fecha_vencimiento)) STORED,
    estado            estado_doc    NOT NULL DEFAULT 'PENDIENTE',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cxp_doc    UNIQUE (empresa_id, documento),
    CONSTRAINT ck_cxp_saldo  CHECK (saldo_pendiente >= 0 AND saldo_pendiente <= importe_original),
    CONSTRAINT ck_cxp_fechas CHECK (fecha_vencimiento >= fecha_emision)
);
CREATE INDEX ix_cxp_vencimiento ON cuentas_pagar (empresa_id, fecha_vencimiento)
    WHERE saldo_pendiente > 0;

-- 11 -------------------------------------------------------- conciliaciones
CREATE TABLE conciliaciones (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id        BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    banco             VARCHAR(80)   NOT NULL,
    cuenta_bancaria   VARCHAR(30)   NOT NULL,
    clabe             CHAR(18),
    periodo           CHAR(7)       NOT NULL,
    saldo_banco       NUMERIC(18,2) NOT NULL,
    saldo_libros      NUMERIC(18,2) NOT NULL,
    diferencia        NUMERIC(18,2) GENERATED ALWAYS AS (saldo_banco - saldo_libros) STORED,
    movimientos_total INTEGER       NOT NULL DEFAULT 0,
    movimientos_conciliados INTEGER NOT NULL DEFAULT 0,
    porcentaje_conciliado NUMERIC(5,2) NOT NULL DEFAULT 0,
    estado            estado_doc    NOT NULL DEFAULT 'PENDIENTE',
    fecha_conciliacion TIMESTAMPTZ,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_conc_periodo UNIQUE (empresa_id, cuenta_bancaria, periodo),
    CONSTRAINT ck_conc_pct     CHECK (porcentaje_conciliado BETWEEN 0 AND 100),
    CONSTRAINT ck_conc_clabe   CHECK (clabe IS NULL OR clabe ~ '^[0-9]{18}$')
);

-- 12 --------------------------------------------------- estados_financieros
CREATE TABLE estados_financieros (
    id             BIGSERIAL PRIMARY KEY,
    empresa_id     BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    tipo           VARCHAR(30)   NOT NULL,   -- BALANCE_GENERAL | ESTADO_RESULTADOS | FLUJO_EFECTIVO
    ejercicio      SMALLINT      NOT NULL,
    periodo        CHAR(7)       NOT NULL,
    rubro          VARCHAR(120)  NOT NULL,
    grupo          VARCHAR(40)   NOT NULL,   -- ACTIVO | PASIVO | CAPITAL | INGRESO | COSTO | GASTO
    importe_actual   NUMERIC(18,2) NOT NULL DEFAULT 0,
    importe_anterior NUMERIC(18,2) NOT NULL DEFAULT 0,
    variacion_pct  NUMERIC(9,4)  GENERATED ALWAYS AS (
        CASE WHEN importe_anterior = 0 THEN NULL
             ELSE (importe_actual - importe_anterior) / ABS(importe_anterior) END) STORED,
    auditado       BOOLEAN       NOT NULL DEFAULT FALSE,
    generado_en    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ef_rubro UNIQUE (empresa_id, tipo, periodo, rubro)
);
CREATE INDEX ix_ef_periodo ON estados_financieros (empresa_id, ejercicio, tipo);

-- 13 ------------------------------------------------------------- impuestos
CREATE TABLE impuestos (
    id              BIGSERIAL PRIMARY KEY,
    empresa_id      BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    periodo         CHAR(7)       NOT NULL,
    concepto        VARCHAR(120)  NOT NULL,   -- IVA trasladado, ISR provisional, retenciones…
    base_gravable   NUMERIC(18,2) NOT NULL DEFAULT 0,
    tasa            NUMERIC(9,6)  NOT NULL DEFAULT 0,
    importe         NUMERIC(18,2) NOT NULL DEFAULT 0,
    a_favor         NUMERIC(18,2) NOT NULL DEFAULT 0,
    fecha_limite    DATE,
    fecha_pago      DATE,
    estado          estado_decl   NOT NULL DEFAULT 'PENDIENTE',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_imp_concepto UNIQUE (empresa_id, periodo, concepto),
    CONSTRAINT ck_imp_tasa     CHECK (tasa BETWEEN 0 AND 1)
);

-- 14 --------------------------------------------------------------- nominas
CREATE TABLE nominas (
    id                 BIGSERIAL PRIMARY KEY,
    empresa_id         BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id         BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    empleado_nombre    VARCHAR(160)  NOT NULL,
    empleado_rfc       VARCHAR(13),
    empleado_curp      CHAR(18),
    nss                VARCHAR(11),
    puesto             VARCHAR(100),
    periodo            CHAR(7)       NOT NULL,
    tipo_periodicidad  VARCHAR(20)   NOT NULL DEFAULT 'QUINCENAL',
    sueldo_base        NUMERIC(18,2) NOT NULL DEFAULT 0,
    horas_extra        NUMERIC(9,2)  NOT NULL DEFAULT 0,
    importe_extras     NUMERIC(18,2) NOT NULL DEFAULT 0,
    otras_percepciones NUMERIC(18,2) NOT NULL DEFAULT 0,
    retencion_isr      NUMERIC(18,2) NOT NULL DEFAULT 0,
    retencion_imss     NUMERIC(18,2) NOT NULL DEFAULT 0,
    otras_deducciones  NUMERIC(18,2) NOT NULL DEFAULT 0,
    neto_pagar         NUMERIC(18,2) GENERATED ALWAYS AS (
        sueldo_base + importe_extras + otras_percepciones
        - retencion_isr - retencion_imss - otras_deducciones) STORED,
    uuid_cfdi_nomina   UUID,
    timbrado           BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_nomina_periodo UNIQUE (empresa_id, empleado_rfc, periodo),
    CONSTRAINT ck_nomina_curp    CHECK (empleado_curp IS NULL OR empleado_curp ~ '^[A-Z0-9]{18}$')
);
CREATE INDEX ix_nomina_periodo ON nominas (empresa_id, periodo);

-- 15 ----------------------------------------------------------- presupuestos
CREATE TABLE presupuestos (
    id               BIGSERIAL PRIMARY KEY,
    empresa_id       BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    ejercicio        SMALLINT      NOT NULL,
    area             VARCHAR(100)  NOT NULL,
    centro_costos    VARCHAR(30),
    monto_autorizado NUMERIC(18,2) NOT NULL DEFAULT 0,
    monto_ejercido   NUMERIC(18,2) NOT NULL DEFAULT 0,
    monto_comprometido NUMERIC(18,2) NOT NULL DEFAULT 0,
    disponible       NUMERIC(18,2) GENERATED ALWAYS AS
        (monto_autorizado - monto_ejercido - monto_comprometido) STORED,
    aprobado_por     BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    fecha_aprobacion DATE,
    estado           estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_pres_area  UNIQUE (empresa_id, ejercicio, area),
    CONSTRAINT ck_pres_monto CHECK (monto_autorizado >= 0 AND monto_ejercido >= 0)
);

-- 16 ------------------------------------------------------------- auditorias
CREATE TABLE auditorias (
    id             BIGSERIAL PRIMARY KEY,
    empresa_id     BIGINT          NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    folio          VARCHAR(30)     NOT NULL,
    tipo           tipo_auditoria  NOT NULL,
    alcance        TEXT            NOT NULL,
    responsable    VARCHAR(160)    NOT NULL,
    despacho       VARCHAR(160),
    fecha_inicio   DATE            NOT NULL,
    fecha_fin      DATE,
    hallazgos      SMALLINT        NOT NULL DEFAULT 0,
    hallazgos_abiertos SMALLINT    NOT NULL DEFAULT 0,
    conclusiones   TEXT,
    estado         estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_aud_folio  UNIQUE (empresa_id, folio),
    CONSTRAINT ck_aud_fechas CHECK (fecha_fin IS NULL OR fecha_fin >= fecha_inicio),
    CONSTRAINT ck_aud_hall   CHECK (hallazgos_abiertos <= hallazgos)
);
COMMENT ON TABLE auditorias IS 'Programa de auditorías (proceso de negocio). No confundir con auditoria (bitácora).';

-- =============================================================================
--  BLOQUE 3 · FINANZAS                                              (17 – 20)
-- =============================================================================

-- 17 -------------------------------------------------- proyectos_financieros
CREATE TABLE proyectos_financieros (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    presupuesto_id    BIGINT        REFERENCES presupuestos(id) ON DELETE SET NULL,
    nombre            VARCHAR(180)  NOT NULL,
    descripcion       TEXT,
    responsable_id    BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    inversion_estimada NUMERIC(18,2) NOT NULL DEFAULT 0,
    inversion_real    NUMERIC(18,2) NOT NULL DEFAULT 0,
    roi_esperado      NUMERIC(9,4),
    van               NUMERIC(18,2),          -- Valor Actual Neto
    tir               NUMERIC(9,6),           -- Tasa Interna de Retorno
    payback_meses     SMALLINT,
    fecha_inicio      DATE          NOT NULL,
    fecha_fin_estimada DATE,
    estado            estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- 18 ----------------------------------------------------------- inversiones
CREATE TABLE inversiones (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    instrumento       VARCHAR(160)  NOT NULL,
    institucion       VARCHAR(120),
    monto_invertido   NUMERIC(18,2) NOT NULL,
    tasa_anual        NUMERIC(9,6)  NOT NULL,
    plazo_dias        INTEGER,
    fecha_inversion   DATE          NOT NULL,
    fecha_vencimiento DATE,
    rendimiento_estimado NUMERIC(18,2) NOT NULL DEFAULT 0,
    rendimiento_real  NUMERIC(18,2) NOT NULL DEFAULT 0,
    nivel_riesgo      nivel_riesgo  NOT NULL DEFAULT 'BAJO',
    estado            estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_inv_monto CHECK (monto_invertido > 0),
    CONSTRAINT ck_inv_tasa  CHECK (tasa_anual >= 0)
);

-- 19 ------------------------------------------------------- financiamientos
CREATE TABLE financiamientos (
    id                 BIGSERIAL PRIMARY KEY,
    empresa_id         BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    institucion        VARCHAR(120)  NOT NULL,
    tipo_credito       VARCHAR(80)   NOT NULL,   -- simple, revolvente, arrendamiento…
    monto_autorizado   NUMERIC(18,2) NOT NULL,
    saldo_insoluto     NUMERIC(18,2) NOT NULL,
    tasa_anual         NUMERIC(9,6)  NOT NULL,
    tasa_variable      BOOLEAN       NOT NULL DEFAULT FALSE,
    referencia_tasa    VARCHAR(30),               -- TIIE 28, TIIE 91…
    plazo_meses        SMALLINT,
    pago_mensual       NUMERIC(18,2),
    fecha_contratacion DATE          NOT NULL,
    fecha_vencimiento  DATE,
    garantia           TEXT,
    estado             estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_fin_saldo CHECK (saldo_insoluto >= 0 AND saldo_insoluto <= monto_autorizado)
);

-- 20 ---------------------------------------------------------------- riesgos
CREATE TABLE riesgos (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT       NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    folio             VARCHAR(20)  NOT NULL,
    descripcion       TEXT         NOT NULL,
    categoria         VARCHAR(60)  NOT NULL,   -- Financiero, Fiscal, Operativo, Tecnológico
    probabilidad      nivel_riesgo NOT NULL,
    impacto           nivel_riesgo NOT NULL,
    nivel_exposicion  nivel_riesgo NOT NULL,
    plan_mitigacion   TEXT,
    responsable_id    BIGINT       REFERENCES usuarios(id) ON DELETE SET NULL,
    fecha_deteccion   DATE         NOT NULL DEFAULT CURRENT_DATE,
    fecha_objetivo    DATE,
    estado            estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_riesgo_folio UNIQUE (empresa_id, folio)
);

-- =============================================================================
--  BLOQUE 4 · SAT & FISCAL                                          (21 – 25)
-- =============================================================================

-- 21 --------------------------------------------------------------- facturas
CREATE TABLE facturas (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    operacion_id      BIGINT        REFERENCES operaciones_contables(id) ON DELETE SET NULL,
    uuid_fiscal       UUID          NOT NULL,
    serie             VARCHAR(10),
    folio             VARCHAR(30)   NOT NULL,
    tipo_comprobante  CHAR(1)       NOT NULL,   -- I ingreso, E egreso, T traslado, N nómina, P pago
    receptor_rfc      VARCHAR(13)   NOT NULL,
    receptor_nombre   VARCHAR(200)  NOT NULL,
    uso_cfdi          VARCHAR(5),
    metodo_pago       VARCHAR(3),                -- PUE | PPD
    forma_pago        VARCHAR(2),
    subtotal          NUMERIC(18,2) NOT NULL,
    descuento         NUMERIC(18,2) NOT NULL DEFAULT 0,
    impuestos_trasladados NUMERIC(18,2) NOT NULL DEFAULT 0,
    impuestos_retenidos   NUMERIC(18,2) NOT NULL DEFAULT 0,
    total             NUMERIC(18,2) NOT NULL,
    moneda            CHAR(3)       NOT NULL DEFAULT 'MXN',
    fecha_emision     TIMESTAMPTZ   NOT NULL,
    fecha_timbrado    TIMESTAMPTZ,
    periodo           CHAR(7)       NOT NULL,
    xml_ruta          TEXT,
    pdf_ruta          TEXT,
    cancelada         BOOLEAN       NOT NULL DEFAULT FALSE,
    motivo_cancelacion VARCHAR(10),
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_fact_uuid  UNIQUE (uuid_fiscal),
    CONSTRAINT uq_fact_folio UNIQUE (empresa_id, serie, folio),
    CONSTRAINT ck_fact_tipo  CHECK (tipo_comprobante IN ('I','E','T','N','P')),
    CONSTRAINT ck_fact_total CHECK (total >= 0)
);
CREATE INDEX ix_fact_periodo  ON facturas (empresa_id, periodo) WHERE cancelada = FALSE;
CREATE INDEX ix_fact_receptor ON facturas (empresa_id, receptor_rfc);

-- 22 ----------------------------------------------------------- declaraciones
CREATE TABLE declaraciones (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    impuesto_id       BIGINT        REFERENCES impuestos(id) ON DELETE SET NULL,
    periodo           CHAR(7)       NOT NULL,
    ejercicio         SMALLINT      NOT NULL,
    tipo_declaracion  VARCHAR(120)  NOT NULL,   -- ISR provisional, IVA definitivo, DIOT, anual
    es_complementaria BOOLEAN       NOT NULL DEFAULT FALSE,
    numero_operacion  VARCHAR(40),
    linea_captura     VARCHAR(30),
    importe_a_cargo   NUMERIC(18,2) NOT NULL DEFAULT 0,
    importe_a_favor   NUMERIC(18,2) NOT NULL DEFAULT 0,
    fecha_limite      DATE,
    fecha_presentacion DATE,
    acuse_ruta        TEXT,
    estado            estado_decl   NOT NULL DEFAULT 'BORRADOR',
    presentada_por    BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_decl UNIQUE (empresa_id, periodo, tipo_declaracion, es_complementaria)
);

-- 23 -------------------------------------------------------- constancias_sat
CREATE TABLE constancias_sat (
    id               BIGSERIAL PRIMARY KEY,
    empresa_id       BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    folio            VARCHAR(40)   NOT NULL,
    rfc              VARCHAR(13)   NOT NULL,
    razon_social     VARCHAR(255)  NOT NULL,
    regimen_fiscal   VARCHAR(120)  NOT NULL,
    codigo_postal    CHAR(5)       NOT NULL,
    fecha_emision    DATE          NOT NULL,
    cadena_original  TEXT,
    documento_ruta   TEXT,
    estado           estado_fiscal NOT NULL DEFAULT 'VIGENTE',
    obtenida_en      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_csf_folio UNIQUE (empresa_id, folio)
);
COMMENT ON TABLE constancias_sat IS 'Constancia de Situación Fiscal (CSF) descargada del portal del SAT.';

-- 24 -------------------------------------------------------------------- d32
CREATE TABLE d32 (
    id               BIGSERIAL PRIMARY KEY,
    empresa_id       BIGINT       NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    folio            VARCHAR(40)  NOT NULL,
    sentido          opinion_d32  NOT NULL,
    fecha_emision    DATE         NOT NULL,
    fecha_vigencia   DATE         NOT NULL,
    obligaciones_incumplidas JSONB,
    documento_ruta   TEXT,
    consultado_por   BIGINT       REFERENCES usuarios(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_d32_folio  UNIQUE (empresa_id, folio),
    CONSTRAINT ck_d32_vigencia CHECK (fecha_vigencia >= fecha_emision)
);
COMMENT ON TABLE d32 IS 'Opinión del cumplimiento de obligaciones fiscales (artículo 32-D del CFF).';

-- 25 ----------------------------------------------------------------- firmas
CREATE TABLE firmas (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    tipo              VARCHAR(20)   NOT NULL DEFAULT 'EFIRMA',  -- EFIRMA | CSD
    numero_serie      VARCHAR(40)   NOT NULL,
    rfc_titular       VARCHAR(13)   NOT NULL,
    certificado_cer   BYTEA,                       -- almacenado cifrado
    llave_key         BYTEA,                       -- almacenada cifrada AES-256-GCM
    password_hash     TEXT,
    fecha_inicio      DATE          NOT NULL,
    fecha_vencimiento DATE          NOT NULL,
    dias_para_vencer  INTEGER       GENERATED ALWAYS AS (fecha_vencimiento - CURRENT_DATE) STORED,
    estado            estado_fiscal NOT NULL DEFAULT 'VIGENTE',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_firma_serie UNIQUE (numero_serie),
    CONSTRAINT ck_firma_vig   CHECK (fecha_vencimiento > fecha_inicio)
);

-- =============================================================================
--  BLOQUE 5 · INTELIGENCIA, OBSERVABILIDAD E INTEGRACIONES          (26 – 28)
-- =============================================================================

-- 26 ------------------------------------------------------------------- foda
CREATE TABLE foda (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id        BIGINT        REFERENCES usuarios(id) ON DELETE SET NULL,
    ejercicio         SMALLINT      NOT NULL,
    periodo           CHAR(7)       NOT NULL,
    proveedor         proveedor_llm NOT NULL,
    modelo            VARCHAR(80)   NOT NULL,
    prompt_contexto   TEXT,
    fortalezas        JSONB         NOT NULL DEFAULT '[]'::jsonb,
    oportunidades     JSONB         NOT NULL DEFAULT '[]'::jsonb,
    debilidades       JSONB         NOT NULL DEFAULT '[]'::jsonb,
    amenazas          JSONB         NOT NULL DEFAULT '[]'::jsonb,
    recomendacion     TEXT,
    tokens_entrada    INTEGER       NOT NULL DEFAULT 0,
    tokens_salida     INTEGER       NOT NULL DEFAULT 0,
    latencia_ms       INTEGER,
    costo_estimado    NUMERIC(12,4) NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_foda_periodo ON foda (empresa_id, ejercicio, periodo DESC);

-- 27 ------------------------------------------------------------------- logs
CREATE TABLE logs (
    id            BIGSERIAL PRIMARY KEY,
    empresa_id    BIGINT      REFERENCES empresas(id) ON DELETE CASCADE,
    usuario_id    BIGINT      REFERENCES usuarios(id) ON DELETE SET NULL,
    nivel         nivel_log   NOT NULL DEFAULT 'INFO',
    servicio      VARCHAR(80) NOT NULL,
    mensaje       TEXT        NOT NULL,
    contexto      JSONB,
    stack_trace   TEXT,
    trace_id      UUID,
    duracion_ms   INTEGER,
    resuelto      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_logs_nivel_fecha ON logs (nivel, created_at DESC);
CREATE INDEX ix_logs_errores     ON logs (created_at DESC) WHERE nivel IN ('ERROR','FATAL');
COMMENT ON TABLE logs IS 'Fuente del monitor de errores en tiempo real del rol MASTER.';

-- 28 ----------------------------------------------------------- integraciones
CREATE TABLE integraciones (
    id                BIGSERIAL PRIMARY KEY,
    empresa_id        BIGINT        NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
    nombre            VARCHAR(120)  NOT NULL,   -- SAT WS, Banca BBVA, LLM Anthropic…
    categoria         VARCHAR(40)   NOT NULL,   -- SAT | BANCA | LLM | ERP
    proveedor_llm     proveedor_llm,            -- sólo cuando categoria = 'LLM'
    modelo            VARCHAR(80),
    endpoint_url      TEXT,
    api_key_cifrada   BYTEA,                     -- AES-256-GCM; nunca en texto plano
    api_key_ultimos4  CHAR(4),                   -- para despliegue enmascarado en UI
    temperatura       NUMERIC(4,2)  DEFAULT 0.30,
    max_tokens        INTEGER       DEFAULT 2048,
    verificada        BOOLEAN       NOT NULL DEFAULT FALSE,
    ultima_verificacion TIMESTAMPTZ,
    estado            estado_generico NOT NULL DEFAULT 'ACTIVO',
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_integ_nombre UNIQUE (empresa_id, nombre),
    CONSTRAINT ck_integ_temp   CHECK (temperatura BETWEEN 0 AND 2),
    CONSTRAINT ck_integ_llm    CHECK (categoria <> 'LLM' OR proveedor_llm IS NOT NULL)
);

-- =============================================================================
--  TRIGGER GENÉRICO: updated_at
-- =============================================================================
CREATE OR REPLACE FUNCTION fn_touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE t TEXT;
BEGIN
    FOR t IN
        SELECT c.table_name
        FROM information_schema.columns c
        WHERE c.table_schema = 'sigcf' AND c.column_name = 'updated_at'
    LOOP
        EXECUTE format(
            'CREATE TRIGGER tg_%1$s_touch BEFORE UPDATE ON sigcf.%1$I
             FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();', t);
    END LOOP;
END $$;

-- =============================================================================
--  VISTAS DE APOYO PARA EL DASHBOARD
-- =============================================================================
CREATE OR REPLACE VIEW v_kpi_facturacion_mensual AS
SELECT empresa_id,
       periodo,
       COUNT(*)      AS cfdi_emitidos,
       SUM(total)    AS monto_total
FROM facturas
WHERE cancelada = FALSE AND tipo_comprobante = 'I'
GROUP BY empresa_id, periodo;

CREATE OR REPLACE VIEW v_kpi_presupuesto AS
SELECT empresa_id,
       ejercicio,
       SUM(monto_autorizado) AS autorizado,
       SUM(monto_ejercido)   AS ejercido,
       CASE WHEN SUM(monto_autorizado) = 0 THEN 0
            ELSE ROUND(SUM(monto_ejercido) / SUM(monto_autorizado), 4) END AS avance
FROM presupuestos
GROUP BY empresa_id, ejercicio;

CREATE OR REPLACE VIEW v_antiguedad_cxc AS
SELECT empresa_id,
       CASE WHEN dias_vencido = 0        THEN 'POR_VENCER'
            WHEN dias_vencido <= 30      THEN '01_30'
            WHEN dias_vencido <= 60      THEN '31_60'
            WHEN dias_vencido <= 90      THEN '61_90'
            ELSE 'MAS_90' END AS bucket,
       COUNT(*)             AS documentos,
       SUM(saldo_pendiente) AS saldo
FROM cuentas_cobrar
WHERE saldo_pendiente > 0
GROUP BY empresa_id, bucket;

CREATE OR REPLACE VIEW v_estado_sat AS
SELECT e.id AS empresa_id,
       (SELECT estado  FROM constancias_sat c WHERE c.empresa_id = e.id
         ORDER BY fecha_emision DESC LIMIT 1) AS csf_estado,
       (SELECT sentido FROM d32 d WHERE d.empresa_id = e.id
         ORDER BY fecha_emision DESC LIMIT 1) AS d32_sentido,
       (SELECT estado  FROM firmas f WHERE f.empresa_id = e.id AND f.tipo = 'EFIRMA'
         ORDER BY fecha_vencimiento DESC LIMIT 1) AS efirma_estado
FROM empresas e;

CREATE OR REPLACE VIEW v_monitor_errores AS
SELECT id, empresa_id, nivel, servicio, mensaje, trace_id, created_at
FROM logs
WHERE nivel IN ('WARN','ERROR','FATAL')
ORDER BY created_at DESC;

COMMIT;

-- =============================================================================
--  RESUMEN
--    Núcleo (7)     : empresas, roles, usuarios, permisos, configuracion,
--                     sesiones, auditoria
--    Contabilidad(9): operaciones_contables, cuentas_cobrar, cuentas_pagar,
--                     conciliaciones, estados_financieros, impuestos, nominas,
--                     presupuestos, auditorias
--    Finanzas (4)   : proyectos_financieros, inversiones, financiamientos, riesgos
--    SAT/Fiscal (5) : facturas, declaraciones, constancias_sat, d32, firmas
--    IA/Obs. (3)    : foda, logs, integraciones
--    ----------------------------------------------------------------
--    TOTAL          : 28 tablas
-- =============================================================================
