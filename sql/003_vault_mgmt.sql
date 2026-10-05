-- =============================================================================
-- VPG Contadores - Migracion 003: catalogo de colecciones de secretos.
--
-- Etapa 4. Da soporte a vault-mgmt-service: colecciones con esquema tipado,
-- indice de registros, consumidores de maquina, operaciones por recurso y
-- auditoria.
--
-- Ejecucion (cuenta ADMINISTRATIVA, no vpg_app):
--   bash scripts/vault_mgmt/apply-migrations.sh
--   # equivalente manual dentro del contenedor:
--   psql -v ON_ERROR_STOP=1 -v app_user=vpg_app -f 003_vault_mgmt.sql
--
-- Transaccional y repetible. NO sustituye un sistema de migraciones: este
-- archivo es la migracion 003 y se aplica explicitamente despues de
-- 002_vault_operations.sql. FastAPI nunca emite DDL.
--
-- Esquema PROPIO (vault_mgmt), no 'employees', por dos razones concretas:
--   1. Permisos DML minimos de verdad. scripts/postgres/pg-app-role.sh concede
--      SELECT/INSERT/UPDATE/DELETE sobre TODAS las tablas de 'employees' y deja
--      privilegios por defecto para las futuras. Meter aqui el catalogo daria a
--      vpg_app permiso de UPDATE y DELETE sobre la auditoria y sobre los
--      esquemas versionados, que deben ser de solo insercion.
--   2. employees.vault_operations no sirve para estas operaciones: su clave es
--      el empleado objetivo (FK a employees.users e indice de "una operacion
--      viva por usuario"). Una operacion sobre un registro de secretos no tiene
--      empleado objetivo, y su exclusion debe ser por coleccion/registro.
--
-- AVISO: aqui NO se guarda ningun valor de secreto, ni su hash, ni longitudes,
-- ni fragmentos. Solo metadatos de catalogo. El campo `detail` de la auditoria
-- y el `error` de las operaciones llegan ya saneados por la aplicacion.
-- =============================================================================

\if :{?app_user}
\else
\set app_user 'vpg_app'
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS vault_mgmt;

COMMENT ON SCHEMA vault_mgmt IS
  'Catalogo de colecciones de secretos, consumidores y auditoria (etapa 4). Nunca contiene valores de secretos.';

SET LOCAL search_path = vault_mgmt, pg_catalog;
SET LOCAL vault_mgmt.app_user = :'app_user';

-- -----------------------------------------------------------------------------
-- updated_at automatico. Funcion propia del esquema: no se depende de que
-- employees.set_updated_at siga existiendo ni de tener USAGE sobre su esquema.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault_mgmt.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;

COMMENT ON FUNCTION vault_mgmt.set_updated_at() IS
  'Trigger BEFORE UPDATE: fija updated_at = now() ignorando el valor enviado.';

-- =============================================================================
-- 1. Colecciones
-- =============================================================================
-- El nombre LOGICO (p. ej. 'sat/usuarios') es lo unico que se renombra. El
-- collection_id y el path fisico en Vault no cambian nunca: por eso renombrar
-- conserva historial, versiones y las referencias del crawler. KV v2 no tiene
-- rename nativo y aqui no se simula con copy/delete.
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_collections (
  collection_id          UUID        NOT NULL DEFAULT gen_random_uuid(),
  logical_name           TEXT        NOT NULL,
  description            TEXT        NULL,
  -- active   : operativa.
  -- archived : la API bloquea acceso y entregas futuras. NO revoca lo ya
  --            entregado ni impide a un administrador leer Vault directamente.
  -- purged   : sus datos y metadata se destruyeron; la fila permanece como
  --            auditoria minima.
  state                  TEXT        NOT NULL DEFAULT 'active',
  current_schema_version INTEGER     NOT NULL DEFAULT 1,
  -- Roles de APLICACION que pueden leer esta coleccion. No son politicas de
  -- Vault: la ACL de Vault se comprueba ademas, y manda ella.
  reader_role_codes      TEXT[]      NOT NULL DEFAULT ARRAY['admin']::TEXT[],
  -- Montaje y prefijo fisico. Se guardan por coleccion para que un cambio de
  -- configuracion del servicio no reescriba a donde apuntan las ya creadas.
  kv_mount               TEXT        NOT NULL DEFAULT 'secret',
  kv_prefix              TEXT        NOT NULL DEFAULT 'vpg-managed',
  created_by             UUID        NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  archived_at            TIMESTAMPTZ NULL,
  purged_at              TIMESTAMPTZ NULL,

  CONSTRAINT secret_collections_pk PRIMARY KEY (collection_id),
  CONSTRAINT secret_collections_name_ux UNIQUE (logical_name),
  -- Minusculas, digitos, '.', '_', '-' y '/' como separador. Sin '/' inicial o
  -- final, sin '//' y sin '..': el nombre logico no debe poder leerse como una
  -- ruta relativa.
  CONSTRAINT secret_collections_name_ck CHECK (
    logical_name ~ '^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$'
    AND logical_name NOT LIKE '%..%'
    AND length(logical_name) BETWEEN 3 AND 120
  ),
  CONSTRAINT secret_collections_state_ck CHECK (state IN ('active', 'archived', 'purged')),
  CONSTRAINT secret_collections_schema_version_ck CHECK (current_schema_version >= 1),
  -- Solo roles de aplicacion conocidos, y 'admin' siempre presente: una
  -- coleccion que nadie pueda administrar seria un recurso huerfano.
  CONSTRAINT secret_collections_readers_ck CHECK (
    reader_role_codes <@ ARRAY['admin', 'manager', 'employee']::TEXT[]
    AND array_position(reader_role_codes, 'admin') IS NOT NULL
    AND array_length(reader_role_codes, 1) BETWEEN 1 AND 3
  ),
  CONSTRAINT secret_collections_mount_ck CHECK (
    kv_mount ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
    AND kv_prefix ~ '^[a-z0-9][a-z0-9._/-]{0,63}$'
  ),
  CONSTRAINT secret_collections_archived_ck CHECK (
    (state <> 'archived') OR (archived_at IS NOT NULL)
  ),
  CONSTRAINT secret_collections_purged_ck CHECK (
    (state <> 'purged') OR (purged_at IS NOT NULL)
  ),
  CONSTRAINT secret_collections_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_collections IS
  'Catalogo de colecciones. El path fisico en Vault se deriva de collection_id, no del nombre logico: renombrar no mueve datos.';
COMMENT ON COLUMN vault_mgmt.secret_collections.reader_role_codes IS
  'Roles de aplicacion lectores. No sustituye la ACL de Vault, que se comprueba ademas.';
COMMENT ON COLUMN vault_mgmt.secret_collections.state IS
  'archived bloquea la API; no revoca entregas ya hechas ni el acceso directo a Vault.';

CREATE INDEX IF NOT EXISTS secret_collections_state_ix
  ON vault_mgmt.secret_collections (state, logical_name);

DROP TRIGGER IF EXISTS secret_collections_set_updated_at ON vault_mgmt.secret_collections;
CREATE TRIGGER secret_collections_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_collections
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- =============================================================================
-- 2. Esquemas versionados (solo insercion)
-- =============================================================================
-- Cada version se conserva. Una version de Vault guarda la envoltura
-- {"schema_version": N, "values": {...}}, asi que siempre se puede saber con
-- que esquema se valido, sin depender de custom_metadata (que es por clave y
-- no por version).
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_collection_schemas (
  collection_id  UUID        NOT NULL,
  schema_version INTEGER     NOT NULL,
  -- Definicion declarada: [{"name","type","required","sensitive",...}]
  fields         JSONB       NOT NULL,
  -- Documento JSON Schema (Draft 2020-12) derivado de `fields`. Se guarda para
  -- que la version historica conserve EXACTAMENTE el documento que la valido.
  json_schema    JSONB       NOT NULL,
  note           TEXT        NULL,
  created_by     UUID        NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT secret_collection_schemas_pk PRIMARY KEY (collection_id, schema_version),
  CONSTRAINT secret_collection_schemas_version_ck CHECK (schema_version >= 1),
  CONSTRAINT secret_collection_schemas_fields_ck CHECK (jsonb_typeof(fields) = 'array'),
  CONSTRAINT secret_collection_schemas_doc_ck CHECK (jsonb_typeof(json_schema) = 'object'),
  CONSTRAINT secret_collection_schemas_collection_fk FOREIGN KEY (collection_id)
    REFERENCES vault_mgmt.secret_collections (collection_id) ON DELETE CASCADE,
  CONSTRAINT secret_collection_schemas_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_collection_schemas IS
  'Versiones de esquema, inmutables. Sin UPDATE ni DELETE para la cuenta de ejecucion.';

-- =============================================================================
-- 3. Indice de registros
-- =============================================================================
-- N registros son N secretos de Vault, cada uno con su propio path y su propio
-- historial de versiones. Aqui NO hay valores: solo el indice.
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_records (
  record_id       UUID        NOT NULL DEFAULT gen_random_uuid(),
  collection_id   UUID        NOT NULL,
  -- active       : hay al menos una version viva.
  -- soft_deleted : la version actual esta borrada de forma reversible.
  -- destroyed    : destruida de forma irreversible (o metadata eliminada).
  state           TEXT        NOT NULL DEFAULT 'active',
  -- Ultima version conocida por el catalogo. Es la referencia que se devuelve
  -- como CAS esperado; la version autoritativa la tiene Vault y se relee antes
  -- de escribir.
  current_version INTEGER     NOT NULL DEFAULT 0,
  -- Version de esquema con la que se valido la ultima escritura.
  schema_version  INTEGER     NOT NULL DEFAULT 1,
  -- Etiqueta NO sensible para que una persona reconozca el registro sin leerlo.
  label           TEXT        NULL,
  created_by      UUID        NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at      TIMESTAMPTZ NULL,

  CONSTRAINT secret_records_pk PRIMARY KEY (record_id),
  CONSTRAINT secret_records_state_ck CHECK (state IN ('active', 'soft_deleted', 'destroyed')),
  CONSTRAINT secret_records_version_ck CHECK (current_version >= 0),
  CONSTRAINT secret_records_schema_version_ck CHECK (schema_version >= 1),
  CONSTRAINT secret_records_label_ck CHECK (
    label IS NULL OR (length(label) BETWEEN 1 AND 120 AND label !~ '[\n\r\t]')
  ),
  CONSTRAINT secret_records_collection_fk FOREIGN KEY (collection_id)
    REFERENCES vault_mgmt.secret_collections (collection_id) ON DELETE CASCADE,
  -- El registro apunta a una version de esquema que EXISTE. RESTRICT: no se
  -- puede borrar una version de esquema que algun registro usa.
  CONSTRAINT secret_records_schema_fk FOREIGN KEY (collection_id, schema_version)
    REFERENCES vault_mgmt.secret_collection_schemas (collection_id, schema_version)
    ON DELETE RESTRICT,
  CONSTRAINT secret_records_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_records IS
  'Indice de registros. Un registro = un secreto de Vault con su propio historial.';
COMMENT ON COLUMN vault_mgmt.secret_records.current_version IS
  'Referencia para el CAS esperado. La version autoritativa la tiene Vault.';

CREATE INDEX IF NOT EXISTS secret_records_collection_ix
  ON vault_mgmt.secret_records (collection_id, created_at DESC, record_id);

CREATE UNIQUE INDEX IF NOT EXISTS secret_records_label_ux
  ON vault_mgmt.secret_records (collection_id, label)
  WHERE label IS NOT NULL;

DROP TRIGGER IF EXISTS secret_records_set_updated_at ON vault_mgmt.secret_records;
CREATE TRIGGER secret_records_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_records
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- =============================================================================
-- 4. Consumidores de maquina y sus asignaciones
-- =============================================================================
-- Una identidad de maquina PRECONFIGURADA (AppRole dedicada de solo lectura).
-- No se crea desde la API: la prepara
-- scripts/vault_mgmt/crawler-approle-bootstrap.sh.
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_consumers (
  consumer_id       UUID        NOT NULL DEFAULT gen_random_uuid(),
  name              TEXT        NOT NULL,
  description       TEXT        NULL,
  -- Identidad esperada del token que se presente. Si no coincide: 403.
  approle_mount     TEXT        NOT NULL DEFAULT 'approle-crawler',
  approle_role_name TEXT        NOT NULL,
  -- Politica minima que debe llevar el token de esa maquina.
  expected_policy   TEXT        NOT NULL,
  state             TEXT        NOT NULL DEFAULT 'active',
  created_by        UUID        NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at        TIMESTAMPTZ NULL,

  CONSTRAINT secret_consumers_pk PRIMARY KEY (consumer_id),
  CONSTRAINT secret_consumers_name_ux UNIQUE (name),
  CONSTRAINT secret_consumers_name_ck CHECK (name ~ '^[a-z0-9][a-z0-9._-]{1,62}$'),
  CONSTRAINT secret_consumers_state_ck CHECK (state IN ('active', 'revoked')),
  CONSTRAINT secret_consumers_revoked_ck CHECK (
    (state <> 'revoked') OR (revoked_at IS NOT NULL)
  ),
  CONSTRAINT secret_consumers_mount_ck CHECK (
    approle_mount ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
    AND approle_role_name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
  ),
  CONSTRAINT secret_consumers_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_consumers IS
  'Identidades de maquina preconfiguradas (AppRole). No guarda role_id ni secret_id.';

-- Una identidad AppRole identifica EXACTAMENTE a un consumidor.
--
-- Es un invariante del contrato de maquina, no una comodidad: el servicio NO
-- acepta un consumer_id enviado por el cliente, sino que lo resuelve desde la
-- identidad del token (montaje + rol). Si dos consumidores compartieran rol, un
-- token no determinaria que alcance de entrega le corresponde, y elegir "el
-- primero" seria conceder a una maquina los permisos de otra.
CREATE UNIQUE INDEX IF NOT EXISTS secret_consumers_identity_ux
  ON vault_mgmt.secret_consumers (approle_mount, approle_role_name);

DROP TRIGGER IF EXISTS secret_consumers_set_updated_at ON vault_mgmt.secret_consumers;
CREATE TRIGGER secret_consumers_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_consumers
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- Que registros y que version puede resolver cada consumidor.
-- pinned_version NULL significa "la ultima viva" (latest), de forma explicita.
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_consumer_bindings (
  binding_id     UUID        NOT NULL DEFAULT gen_random_uuid(),
  consumer_id    UUID        NOT NULL,
  collection_id  UUID        NOT NULL,
  record_id      UUID        NOT NULL,
  pinned_version INTEGER     NULL,
  created_by     UUID        NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT secret_consumer_bindings_pk PRIMARY KEY (binding_id),
  CONSTRAINT secret_consumer_bindings_ux UNIQUE (consumer_id, record_id),
  CONSTRAINT secret_consumer_bindings_version_ck CHECK (
    pinned_version IS NULL OR pinned_version >= 1
  ),
  CONSTRAINT secret_consumer_bindings_consumer_fk FOREIGN KEY (consumer_id)
    REFERENCES vault_mgmt.secret_consumers (consumer_id) ON DELETE CASCADE,
  CONSTRAINT secret_consumer_bindings_collection_fk FOREIGN KEY (collection_id)
    REFERENCES vault_mgmt.secret_collections (collection_id) ON DELETE CASCADE,
  CONSTRAINT secret_consumer_bindings_record_fk FOREIGN KEY (record_id)
    REFERENCES vault_mgmt.secret_records (record_id) ON DELETE CASCADE,
  CONSTRAINT secret_consumer_bindings_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON COLUMN vault_mgmt.secret_consumer_bindings.pinned_version IS
  'NULL = latest. Un valor fija la version: no cambia aunque se escriba otra.';

CREATE INDEX IF NOT EXISTS secret_consumer_bindings_consumer_ix
  ON vault_mgmt.secret_consumer_bindings (consumer_id, collection_id);

-- =============================================================================
-- 5. Operaciones por recurso
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_operations (
  operation_id     UUID        NOT NULL DEFAULT gen_random_uuid(),
  operation_type   TEXT        NOT NULL,
  status           TEXT        NOT NULL DEFAULT 'pending',
  collection_id    UUID        NULL,
  -- Sin FK a secret_records: una purga borra el registro y la operacion debe
  -- sobrevivir como auditoria minima.
  record_id        UUID        NULL,
  actor_user_id    UUID        NULL,
  actor_username   TEXT        NULL,
  idempotency_key  TEXT        NULL,
  expected_version INTEGER     NULL,
  result_version   INTEGER     NULL,
  -- Fases durables: [{"phase","system","state","at","detail"}]
  phases           JSONB       NOT NULL DEFAULT '[]'::jsonb,
  -- Recuento para lotes de coleccion: inventariado / procesado / fallido.
  counters         JSONB       NOT NULL DEFAULT '{}'::jsonb,
  error            TEXT        NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at      TIMESTAMPTZ NULL,

  CONSTRAINT secret_operations_pk PRIMARY KEY (operation_id),
  CONSTRAINT secret_operations_type_ck CHECK (operation_type IN (
    'collection_create', 'collection_update', 'collection_schema_update',
    'collection_archive', 'collection_restore', 'collection_purge',
    'record_create', 'record_replace', 'record_patch', 'record_soft_delete',
    'versions_delete', 'versions_undelete', 'versions_destroy', 'record_purge',
    'consumer_bindings_update', 'inventory_import'
  )),
  CONSTRAINT secret_operations_status_ck CHECK (status IN (
    'pending', 'in_progress', 'completed', 'failed', 'needs_reconciliation'
  )),
  CONSTRAINT secret_operations_finished_ck CHECK (
    status IN ('pending', 'in_progress') OR finished_at IS NOT NULL
  ),
  CONSTRAINT secret_operations_phases_ck CHECK (jsonb_typeof(phases) = 'array'),
  CONSTRAINT secret_operations_counters_ck CHECK (jsonb_typeof(counters) = 'object'),
  CONSTRAINT secret_operations_version_ck CHECK (
    (expected_version IS NULL OR expected_version >= 0)
    AND (result_version IS NULL OR result_version >= 0)
  ),
  CONSTRAINT secret_operations_collection_fk FOREIGN KEY (collection_id)
    REFERENCES vault_mgmt.secret_collections (collection_id) ON DELETE SET NULL,
  CONSTRAINT secret_operations_actor_fk FOREIGN KEY (actor_user_id)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_operations IS
  'Registro durable de operaciones sobre colecciones y registros. Sin cuerpos ni valores.';
COMMENT ON COLUMN vault_mgmt.secret_operations.error IS
  'Error ya saneado por la aplicacion: nunca valores, tokens ni wrapping tokens.';

-- Idempotency-Key: la misma clave no crea dos operaciones.
CREATE UNIQUE INDEX IF NOT EXISTS secret_operations_idempotency_ux
  ON vault_mgmt.secret_operations (idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- Como maximo UNA operacion viva por recurso. El UUID todo-ceros representa
-- "la coleccion entera": asi dos operaciones del mismo alcance se excluyen en
-- la base, sin mantener abierta una transaccion durante las llamadas de red.
-- La exclusion entre una operacion de coleccion y las de sus registros no la
-- da este indice: la comprueba el servicio antes de abrir la operacion.
CREATE UNIQUE INDEX IF NOT EXISTS secret_operations_one_active_ux
  ON vault_mgmt.secret_operations (
    collection_id,
    COALESCE(record_id, '00000000-0000-0000-0000-000000000000'::uuid)
  )
  WHERE status IN ('pending', 'in_progress') AND collection_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS secret_operations_status_ix
  ON vault_mgmt.secret_operations (status, created_at DESC);

CREATE INDEX IF NOT EXISTS secret_operations_resource_ix
  ON vault_mgmt.secret_operations (collection_id, record_id, created_at DESC);

DROP TRIGGER IF EXISTS secret_operations_set_updated_at ON vault_mgmt.secret_operations;
CREATE TRIGGER secret_operations_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_operations
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- =============================================================================
-- 6. Auditoria (solo insercion)
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_audit (
  audit_id      BIGINT      GENERATED ALWAYS AS IDENTITY,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Quien: persona con sesion, maquina con AppRole, script CLI o el servicio.
  actor_kind    TEXT        NOT NULL,
  actor_user_id UUID        NULL,
  -- Instantanea del nombre (username o nombre de consumidor): sobrevive al
  -- borrado del actor.
  actor_label   TEXT        NULL,
  action        TEXT        NOT NULL,
  collection_id UUID        NULL,
  record_id     UUID        NULL,
  versions      INTEGER[]   NULL,
  outcome       TEXT        NOT NULL,
  operation_id  UUID        NULL,
  request_id    TEXT        NULL,
  -- Texto ya saneado. Nunca valores, tokens ni wrapping tokens.
  detail        TEXT        NULL,

  CONSTRAINT secret_audit_pk PRIMARY KEY (audit_id),
  CONSTRAINT secret_audit_actor_kind_ck CHECK (
    actor_kind IN ('human', 'machine', 'cli', 'service')
  ),
  CONSTRAINT secret_audit_outcome_ck CHECK (
    outcome IN ('allowed', 'denied', 'error', 'partial')
  ),
  CONSTRAINT secret_audit_actor_fk FOREIGN KEY (actor_user_id)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE vault_mgmt.secret_audit IS
  'Historial append-only de accesos y cambios. La cuenta de ejecucion no puede actualizar ni borrar filas.';

-- Orden estable del listado: (occurred_at DESC, audit_id DESC).
CREATE INDEX IF NOT EXISTS secret_audit_occurred_ix
  ON vault_mgmt.secret_audit (occurred_at DESC, audit_id DESC);

CREATE INDEX IF NOT EXISTS secret_audit_resource_ix
  ON vault_mgmt.secret_audit (collection_id, record_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS secret_audit_actor_ix
  ON vault_mgmt.secret_audit (actor_user_id, occurred_at DESC);

-- =============================================================================
-- 7. Permisos DML minimos de la cuenta de EJECUCION
-- =============================================================================
-- USAGE sin CREATE: la cuenta de ejecucion no puede crear ni alterar objetos.
-- Por tabla se concede solo lo que el servicio necesita:
--   * secret_collection_schemas y secret_audit: SELECT e INSERT. Sin UPDATE ni
--     DELETE, para que una version de esquema y una linea de auditoria no se
--     puedan reescribir desde la aplicacion.
--   * secret_collections y secret_operations: sin DELETE. Una coleccion se
--     archiva o se purga y su fila permanece como auditoria minima.
--   * el resto: SELECT/INSERT/UPDATE/DELETE.
DO $do$
DECLARE
  v_app text := current_setting('vault_mgmt.app_user', true);
BEGIN
  IF v_app IS NULL OR v_app = '' THEN
    v_app := 'vpg_app';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_app) THEN
    RAISE NOTICE 'el rol % no existe todavia: ejecuta vpg-pg-roles y repite esta migracion', v_app;
    RETURN;
  END IF;

  EXECUTE format('GRANT USAGE ON SCHEMA vault_mgmt TO %I', v_app);

  EXECUTE format(
    'GRANT SELECT, INSERT ON vault_mgmt.secret_collection_schemas TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT ON vault_mgmt.secret_audit TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON vault_mgmt.secret_collections TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE, DELETE ON vault_mgmt.secret_records TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON vault_mgmt.secret_consumers TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE, DELETE ON vault_mgmt.secret_consumer_bindings TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON vault_mgmt.secret_operations TO %I', v_app);

  -- Se revoca de forma explicita lo que no debe tener, por si una ejecucion
  -- anterior o un GRANT manual lo hubieran concedido.
  EXECUTE format(
    'REVOKE UPDATE, DELETE, TRUNCATE ON vault_mgmt.secret_collection_schemas FROM %I', v_app);
  EXECUTE format(
    'REVOKE UPDATE, DELETE, TRUNCATE ON vault_mgmt.secret_audit FROM %I', v_app);
  EXECUTE format(
    'REVOKE DELETE, TRUNCATE ON vault_mgmt.secret_collections FROM %I', v_app);
  EXECUTE format(
    'REVOKE DELETE, TRUNCATE ON vault_mgmt.secret_operations FROM %I', v_app);
  EXECUTE format(
    'REVOKE TRUNCATE ON ALL TABLES IN SCHEMA vault_mgmt FROM %I', v_app);

  RAISE NOTICE 'permisos DML minimos concedidos a % sobre vault_mgmt', v_app;
END
$do$;

COMMIT;
