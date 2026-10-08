-- =============================================================================
-- VPG Contadores - Migracion 004: aprovisionamiento de consumidores de maquina
--
-- Etapa 4.6. Amplia el catalogo de la migracion 003 para que un consumidor de
-- maquina se pueda registrar y aprovisionar DESDE LA API, con operaciones
-- persistentes que una plataforma React pueda consultar, y con la entrega de la
-- credencial mediada por un receptor configurado.
--
-- Ejecucion (cuenta ADMINISTRATIVA, no vpg_app):
--   bash scripts/vault_mgmt/apply-migrations.sh
--   # equivalente manual dentro del contenedor:
--   psql -v ON_ERROR_STOP=1 -v app_user=vpg_app -f 004_crawler_provisioning.sql
--
-- Transaccional y repetible. NO sustituye un sistema de migraciones: este
-- archivo es la migracion 004 y se aplica despues de 003_vault_mgmt.sql.
-- FastAPI nunca emite DDL.
--
-- Que anade, y por que
-- --------------------
--   1. secret_consumers gana el MODO DE ENTREGA, el estado de aprovisionamiento
--      y los ACCESSORS de Vault. Un accessor identifica una credencial para
--      poder revocarla; NO permite usarla. Los valores (role_id, secret_id,
--      tokens, wrapping tokens) no se guardan aqui en ningun caso.
--
--   2. secret_receivers es el RECEPTOR: quien puede reclamar la emision de un
--      consumidor. Guarda una REFERENCIA a su credencial (el nombre del archivo
--      de secreto), nunca la credencial. Esa referencia es lo que asocia, en el
--      servidor, una credencial concreta con un consumidor autorizado; el
--      consumer_id no sirve para eso, porque no es una contrasena.
--
--   3. secret_provisioning_deliveries es una emision concreta. Es la fila que
--      permite responder "esta emision ya se reclamo" y "ya se confirmo" sin
--      guardar lo entregado.
--
--   4. secret_operations gana alcance de consumidor, huella de la peticion para
--      la idempotencia y los campos de arrendamiento que necesita un worker
--      para reservar trabajo sin mantener una transaccion abierta durante las
--      llamadas de red.
--
-- AVISO: aqui NO se guarda ningun valor de secreto, ni su hash, ni longitudes,
-- ni fragmentos. La unica huella que se calcula (request_fingerprint) es sobre
-- parametros NO sensibles de la solicitud; nunca sobre valores de secretos,
-- donde un hash de baja entropia seria un oraculo para adivinarlos.
-- =============================================================================

\if :{?app_user}
\else
\set app_user 'vpg_app'
\endif

BEGIN;

SET LOCAL search_path = vault_mgmt, pg_catalog;
SET LOCAL vault_mgmt.app_user = :'app_user';

-- =============================================================================
-- 1. secret_consumers: modo de entrega, estado y accessors
-- =============================================================================

ALTER TABLE vault_mgmt.secret_consumers
  ADD COLUMN IF NOT EXISTS delivery_mode                TEXT        NOT NULL DEFAULT 'direct',
  ADD COLUMN IF NOT EXISTS provisioning_state           TEXT        NOT NULL DEFAULT 'unprovisioned',
  ADD COLUMN IF NOT EXISTS secret_id_accessor           TEXT        NULL,
  ADD COLUMN IF NOT EXISTS previous_secret_id_accessor  TEXT        NULL,
  ADD COLUMN IF NOT EXISTS last_token_accessor          TEXT        NULL,
  ADD COLUMN IF NOT EXISTS last_operation_id            UUID        NULL,
  ADD COLUMN IF NOT EXISTS provisioned_at               TIMESTAMPTZ NULL;

COMMENT ON COLUMN vault_mgmt.secret_consumers.delivery_mode IS
  'direct: consumidor HEREDADO de la etapa 4 (preparado por CLI). Su token lee '
  'el prefijo KV por si mismo, asi que sus bindings acotan lo que la API le '
  'entrega, NO lo que su token puede leer en Vault. '
  'mediated: consumidor de la etapa 4.6. Su politica no incluye lectura de KV: '
  'el backend autorizado lee la version permitida y se la envuelve, de modo que '
  'el binding y la version fijada si son el limite efectivo. '
  'Migrar un consumidor de direct a mediated es una decision explicita: hay que '
  'estrechar su politica en Vault.';
COMMENT ON COLUMN vault_mgmt.secret_consumers.secret_id_accessor IS
  'Accessor del SecretID vigente. Identifica la credencial para poder destruirla; '
  'NO permite autenticarse con ella. El SecretID en si no se guarda nunca.';
COMMENT ON COLUMN vault_mgmt.secret_consumers.previous_secret_id_accessor IS
  'Accessor de la credencial anterior durante una rotacion con estrategia '
  'after_ack. Se destruye cuando el receptor confirma la nueva, no antes: asi '
  'un rearranque fallido no deja al consumidor sin poder entrar.';
COMMENT ON COLUMN vault_mgmt.secret_consumers.last_token_accessor IS
  'Accessor del ultimo token que el receptor acredito en el ack. Permite revocar '
  'ESE token sin tenerlo. No es el token.';

DO $do$
BEGIN
  -- Vocabulario de estados. Se reescribe la restriccion en vez de anadir otra
  -- para que no queden dos CHECK solapados sobre la misma columna.
  ALTER TABLE vault_mgmt.secret_consumers
    DROP CONSTRAINT IF EXISTS secret_consumers_provisioning_state_ck;
  ALTER TABLE vault_mgmt.secret_consumers
    ADD CONSTRAINT secret_consumers_provisioning_state_ck CHECK (
      provisioning_state IN (
        'unprovisioned',   -- existe en el catalogo y nada mas
        'provisioning',    -- se esta preparando su identidad en Vault
        'ready',           -- el receptor acredito un token valido
        'failed',          -- el aprovisionamiento fallo y no se reintenta solo
        'revoked'
      )
    );

  ALTER TABLE vault_mgmt.secret_consumers
    DROP CONSTRAINT IF EXISTS secret_consumers_delivery_mode_ck;
  ALTER TABLE vault_mgmt.secret_consumers
    ADD CONSTRAINT secret_consumers_delivery_mode_ck CHECK (
      delivery_mode IN ('direct', 'mediated')
    );
END
$do$;

-- =============================================================================
-- 2. secret_receivers: quien puede reclamar la emision de un consumidor
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_receivers (
  receiver_id    UUID        NOT NULL DEFAULT gen_random_uuid(),
  name           TEXT        NOT NULL,
  consumer_id    UUID        NOT NULL,
  -- REFERENCIA a la credencial (nombre del archivo de secreto), no su valor.
  -- La credencial vive en secrets/, la genera 'make all' si falta y se monta
  -- solo en los componentes que participan.
  credential_ref TEXT        NOT NULL,
  state          TEXT        NOT NULL DEFAULT 'active',
  description    TEXT        NULL,
  created_by     UUID        NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_claim_at  TIMESTAMPTZ NULL,

  CONSTRAINT secret_receivers_pk PRIMARY KEY (receiver_id),
  CONSTRAINT secret_receivers_name_ck CHECK (name ~ '^[a-z0-9][a-z0-9._-]{1,62}$'),
  CONSTRAINT secret_receivers_credential_ref_ck CHECK (
    credential_ref ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{1,62}$'
  ),
  CONSTRAINT secret_receivers_state_ck CHECK (state IN ('active', 'disabled')),
  CONSTRAINT secret_receivers_consumer_fk FOREIGN KEY (consumer_id)
    REFERENCES vault_mgmt.secret_consumers (consumer_id) ON DELETE CASCADE,
  CONSTRAINT secret_receivers_created_by_fk FOREIGN KEY (created_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

-- En una base creada por una version anterior, 'name' llevaba una restriccion
-- UNIQUE total. Se retira para que la unicidad parcial de arriba sea la unica.
ALTER TABLE vault_mgmt.secret_receivers
  DROP CONSTRAINT IF EXISTS secret_receivers_name_ux;

COMMENT ON TABLE vault_mgmt.secret_receivers IS
  'Receptores que pueden reclamar emisiones. Guarda la REFERENCIA a la '
  'credencial (nombre del archivo), nunca la credencial.';

-- Un receptor sirve a UN consumidor, y un consumidor tiene UN receptor. Si dos
-- consumidores compartieran receptor, su credencial no determinaria que emision
-- reclamar, y elegir "la primera" seria entregarle a una maquina la credencial
-- de otra.
--
-- Las tres unicidades son PARCIALES, solo sobre los receptores activos, y eso
-- no es un matiz: con una unicidad total, revocar un consumidor dejaba su
-- receptor ocupado para siempre y el nombre quemado. Un receptor revocado pasa
-- a 'disabled', libera su nombre para un consumidor nuevo y conserva su fila,
-- que es a donde apuntan las entregas ya hechas.
DROP INDEX IF EXISTS vault_mgmt.secret_receivers_name_ux;
DROP INDEX IF EXISTS vault_mgmt.secret_receivers_consumer_ux;
DROP INDEX IF EXISTS vault_mgmt.secret_receivers_credential_ux;

CREATE UNIQUE INDEX IF NOT EXISTS secret_receivers_name_active_ux
  ON vault_mgmt.secret_receivers (name) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS secret_receivers_consumer_active_ux
  ON vault_mgmt.secret_receivers (consumer_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS secret_receivers_credential_active_ux
  ON vault_mgmt.secret_receivers (credential_ref) WHERE state = 'active';

CREATE INDEX IF NOT EXISTS secret_receivers_lookup_ix
  ON vault_mgmt.secret_receivers (name, state);

DROP TRIGGER IF EXISTS secret_receivers_set_updated_at ON vault_mgmt.secret_receivers;
CREATE TRIGGER secret_receivers_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_receivers
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- =============================================================================
-- 3. secret_provisioning_deliveries: una emision concreta
-- =============================================================================
-- Lo que esta tabla NO guarda, y no es un descuido:
--   * El SecretID emitido.
--   * El wrapping token entregado.
--   * El token de Vault con el que el receptor se autentico.
-- Solo sus ACCESSORS, que sirven para revocar y auditar, y los instantes y
-- recuentos necesarios para no entregar dos veces lo mismo.
CREATE TABLE IF NOT EXISTS vault_mgmt.secret_provisioning_deliveries (
  delivery_id        UUID        NOT NULL DEFAULT gen_random_uuid(),
  operation_id       UUID        NOT NULL,
  consumer_id        UUID        NOT NULL,
  receiver_id        UUID        NOT NULL,
  state              TEXT        NOT NULL DEFAULT 'reserved',
  secret_id_accessor TEXT        NULL,
  wrap_accessor      TEXT        NULL,
  token_accessor     TEXT        NULL,
  wrap_ttl_seconds   INTEGER     NULL,
  attempts           INTEGER     NOT NULL DEFAULT 1,
  claimed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Caducidad de la ENVOLTURA. Pasada esta fecha sin ack, el SecretID sigue
  -- vivo en Vault y hay que destruirlo por su accessor: eso es reconciliar.
  expires_at         TIMESTAMPTZ NULL,
  acked_at           TIMESTAMPTZ NULL,
  error              TEXT        NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT secret_provisioning_deliveries_pk PRIMARY KEY (delivery_id),
  CONSTRAINT secret_provisioning_deliveries_attempts_ck CHECK (attempts >= 1),
  CONSTRAINT secret_provisioning_deliveries_ttl_ck CHECK (
    wrap_ttl_seconds IS NULL OR wrap_ttl_seconds BETWEEN 1 AND 3600
  ),
  CONSTRAINT secret_provisioning_deliveries_acked_ck CHECK (
    state <> 'acked' OR acked_at IS NOT NULL
  ),
  CONSTRAINT secret_provisioning_deliveries_operation_fk FOREIGN KEY (operation_id)
    REFERENCES vault_mgmt.secret_operations (operation_id) ON DELETE CASCADE,
  CONSTRAINT secret_provisioning_deliveries_consumer_fk FOREIGN KEY (consumer_id)
    REFERENCES vault_mgmt.secret_consumers (consumer_id) ON DELETE CASCADE,
  CONSTRAINT secret_provisioning_deliveries_receiver_fk FOREIGN KEY (receiver_id)
    REFERENCES vault_mgmt.secret_receivers (receiver_id) ON DELETE CASCADE
);

COMMENT ON TABLE vault_mgmt.secret_provisioning_deliveries IS
  'Emisiones hacia un receptor. Guarda accessors e instantes, nunca SecretID, '
  'wrapping tokens ni tokens de Vault.';
COMMENT ON COLUMN vault_mgmt.secret_provisioning_deliveries.state IS
  'reserved: reclamada, sin emitir todavia. delivered: envoltura entregada, '
  'pendiente de ack. acked: el receptor acredito su token. expired: la envoltura '
  'caduco sin consumirse. failed: no se pudo emitir. superseded: dejo de valer '
  'porque el consumidor se revoco o se emitio otra.';

-- 'superseded' se anade al vocabulario: una revocacion invalida una entrega
-- viva, y marcarla es mas honesto que borrarla (la emision ocurrio).
ALTER TABLE vault_mgmt.secret_provisioning_deliveries
  DROP CONSTRAINT IF EXISTS secret_provisioning_deliveries_state_ck;
ALTER TABLE vault_mgmt.secret_provisioning_deliveries
  ADD CONSTRAINT secret_provisioning_deliveries_state_ck CHECK (state IN (
    'reserved', 'delivered', 'acked', 'expired', 'failed', 'superseded'
  ));

-- Como maximo UNA entrega viva por consumidor: si el receptor vuelve a
-- reclamar se le recuerda la suya, en vez de emitir otra credencial y dejar la
-- anterior huerfana en Vault.
CREATE UNIQUE INDEX IF NOT EXISTS secret_provisioning_deliveries_one_live_ux
  ON vault_mgmt.secret_provisioning_deliveries (consumer_id)
  WHERE state IN ('reserved', 'delivered');

CREATE INDEX IF NOT EXISTS secret_provisioning_deliveries_operation_ix
  ON vault_mgmt.secret_provisioning_deliveries (operation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS secret_provisioning_deliveries_expiry_ix
  ON vault_mgmt.secret_provisioning_deliveries (expires_at)
  WHERE state = 'delivered';

DROP TRIGGER IF EXISTS secret_provisioning_deliveries_set_updated_at
  ON vault_mgmt.secret_provisioning_deliveries;
CREATE TRIGGER secret_provisioning_deliveries_set_updated_at
  BEFORE UPDATE ON vault_mgmt.secret_provisioning_deliveries
  FOR EACH ROW EXECUTE FUNCTION vault_mgmt.set_updated_at();

-- =============================================================================
-- 4. secret_operations: consumidor, idempotencia y arrendamiento
-- =============================================================================

ALTER TABLE vault_mgmt.secret_operations
  ADD COLUMN IF NOT EXISTS consumer_id         UUID        NULL,
  ADD COLUMN IF NOT EXISTS request_fingerprint TEXT        NULL,
  ADD COLUMN IF NOT EXISTS lease_owner         TEXT        NULL,
  ADD COLUMN IF NOT EXISTS leased_until        TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS attempts            INTEGER     NOT NULL DEFAULT 0;

COMMENT ON COLUMN vault_mgmt.secret_operations.request_fingerprint IS
  'Huella de los parametros NO sensibles de la solicitud (nombre, receptor, '
  'bindings). Permite distinguir "misma Idempotency-Key, misma peticion" de '
  '"misma clave, otra peticion" -> 409. Nunca se calcula sobre valores de '
  'secretos: ahi un hash de baja entropia seria un oraculo.';
COMMENT ON COLUMN vault_mgmt.secret_operations.lease_owner IS
  'Worker que reservo esta operacion. El arrendamiento (leased_until) caduca '
  'solo, asi que un worker muerto no bloquea la cola para siempre.';

DO $do$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'secret_operations_consumer_fk'
       AND conrelid = 'vault_mgmt.secret_operations'::regclass
  ) THEN
    ALTER TABLE vault_mgmt.secret_operations
      ADD CONSTRAINT secret_operations_consumer_fk FOREIGN KEY (consumer_id)
        REFERENCES vault_mgmt.secret_consumers (consumer_id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'secret_operations_attempts_ck'
       AND conrelid = 'vault_mgmt.secret_operations'::regclass
  ) THEN
    ALTER TABLE vault_mgmt.secret_operations
      ADD CONSTRAINT secret_operations_attempts_ck CHECK (attempts >= 0);
  END IF;
END
$do$;

-- Tipos nuevos: alta, aprovisionamiento, rotacion y revocacion.
ALTER TABLE vault_mgmt.secret_operations
  DROP CONSTRAINT IF EXISTS secret_operations_type_ck;
ALTER TABLE vault_mgmt.secret_operations
  ADD CONSTRAINT secret_operations_type_ck CHECK (operation_type IN (
    'collection_create', 'collection_update', 'collection_schema_update',
    'collection_archive', 'collection_restore', 'collection_purge',
    'record_create', 'record_replace', 'record_patch', 'record_soft_delete',
    'versions_delete', 'versions_undelete', 'versions_destroy', 'record_purge',
    'consumer_bindings_update', 'inventory_import',
    -- etapa 4.6
    'consumer_register', 'consumer_provision', 'consumer_rotate',
    'consumer_revoke'
  ));

-- Estados nuevos:
--   waiting_receiver  solicitud guardada e identidad lista; NO se ha emitido
--                     ningun SecretID. Sin receptor real se queda aqui, que es
--                     lo correcto: emitir antes seria repartir credenciales a
--                     nadie.
--   awaiting_ack      el receptor reclamo y se le entrego la envoltura. La
--                     operacion NO esta completa hasta que acredite su token.
ALTER TABLE vault_mgmt.secret_operations
  DROP CONSTRAINT IF EXISTS secret_operations_status_ck;
ALTER TABLE vault_mgmt.secret_operations
  ADD CONSTRAINT secret_operations_status_ck CHECK (status IN (
    'pending', 'in_progress', 'waiting_receiver', 'awaiting_ack',
    'completed', 'failed', 'needs_reconciliation'
  ));

-- finished_at solo en estados terminales: los cuatro vivos no lo tienen.
ALTER TABLE vault_mgmt.secret_operations
  DROP CONSTRAINT IF EXISTS secret_operations_finished_ck;
ALTER TABLE vault_mgmt.secret_operations
  ADD CONSTRAINT secret_operations_finished_ck CHECK (
    status IN ('pending', 'in_progress', 'waiting_receiver', 'awaiting_ack')
    OR finished_at IS NOT NULL
  );

-- Como maximo UNA operacion viva por consumidor. Dos aprovisionamientos a la
-- vez sobre la misma AppRole emitirian dos SecretID y dejarian uno huerfano.
CREATE UNIQUE INDEX IF NOT EXISTS secret_operations_one_active_consumer_ux
  ON vault_mgmt.secret_operations (consumer_id)
  WHERE consumer_id IS NOT NULL
    AND status IN ('pending', 'in_progress', 'waiting_receiver', 'awaiting_ack');

-- Cola del worker: lo reclamable, lo mas antiguo primero.
CREATE INDEX IF NOT EXISTS secret_operations_queue_ix
  ON vault_mgmt.secret_operations (status, created_at)
  WHERE status IN ('pending', 'in_progress');

CREATE INDEX IF NOT EXISTS secret_operations_consumer_ix
  ON vault_mgmt.secret_operations (consumer_id, created_at DESC)
  WHERE consumer_id IS NOT NULL;

-- =============================================================================
-- 5. Permisos DML minimos de la cuenta de EJECUCION
-- =============================================================================
-- Mismo criterio que la migracion 003: solo lo que el servicio necesita.
-- Ninguna de las dos tablas lleva DELETE: una entrega se marca 'expired' o
-- 'superseded', no se borra, porque es la unica prueba de que se emitio algo.
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

  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON vault_mgmt.secret_receivers TO %I', v_app);
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON vault_mgmt.secret_provisioning_deliveries TO %I', v_app);
  EXECUTE format(
    'REVOKE DELETE, TRUNCATE ON vault_mgmt.secret_receivers FROM %I', v_app);
  EXECUTE format(
    'REVOKE DELETE, TRUNCATE ON vault_mgmt.secret_provisioning_deliveries FROM %I', v_app);

  RAISE NOTICE 'permisos DML de la etapa 4.6 concedidos a %', v_app;
END
$do$;

COMMIT;
