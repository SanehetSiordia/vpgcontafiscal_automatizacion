-- =============================================================================
-- VPG Contadores - Migracion 002: registro durable de operaciones Vault.
--
-- Motivo: una transaccion de PostgreSQL NO revierte lo que ya ocurrio en Vault.
-- Cuando una operacion toca los dos sistemas (provisionar, cambiar credenciales,
-- reset TOTP, baja, purga) hace falta dejar constancia durable de sus fases para
-- poder reconciliar a mano lo que quedo a medias.
--
-- Ejecucion (cuenta ADMINISTRATIVA, no vpg_app):
--   psql -v ON_ERROR_STOP=1 -f 002_vault_operations.sql
--
-- Transaccional y repetible. NO sustituye un sistema de migraciones: este
-- archivo es la migracion 002 y debe aplicarse explicitamente, una vez, despues
-- de 001_employees.sql.
--
-- AVISO: esta tabla NO guarda contrasenas, tokens, semillas TOTP, URIs otpauth
-- ni codigos. El campo de error se almacena ya saneado por la aplicacion.
-- =============================================================================

BEGIN;

SET LOCAL search_path = employees, pg_catalog;

CREATE TABLE IF NOT EXISTS employees.vault_operations (
  operation_id    UUID        NOT NULL DEFAULT gen_random_uuid(),
  operation_type  TEXT        NOT NULL,
  status          TEXT        NOT NULL DEFAULT 'pending',
  target_user_id  UUID        NULL,
  actor_user_id   UUID        NULL,
  -- Instantanea del nombre por si el usuario objetivo se purga despues: la
  -- auditoria minima debe sobrevivir al borrado del agregado.
  target_username TEXT        NULL,
  idempotency_key TEXT        NULL,
  -- Fases ejecutadas y su resultado, en orden. Cada elemento:
  --   {"phase": "...", "system": "vault|postgres", "state": "...", "at": "..."}
  phases          JSONB       NOT NULL DEFAULT '[]'::jsonb,
  -- Mensaje de error YA SANEADO por la aplicacion (sin secretos).
  error           TEXT        NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at     TIMESTAMPTZ NULL,

  CONSTRAINT vault_operations_pk PRIMARY KEY (operation_id),
  CONSTRAINT vault_operations_type_ck CHECK (operation_type IN (
    'vault_provision', 'vault_credentials', 'mfa_reset',
    'user_deactivate', 'user_purge'
  )),
  CONSTRAINT vault_operations_status_ck CHECK (status IN (
    'pending', 'in_progress', 'succeeded', 'failed', 'needs_reconciliation'
  )),
  -- SET NULL: la purga del empleado no borra su rastro de auditoria.
  CONSTRAINT vault_operations_target_fk FOREIGN KEY (target_user_id)
    REFERENCES employees.users (id) ON DELETE SET NULL,
  CONSTRAINT vault_operations_actor_fk FOREIGN KEY (actor_user_id)
    REFERENCES employees.users (id) ON DELETE SET NULL,
  CONSTRAINT vault_operations_finished_ck CHECK (
    status IN ('pending', 'in_progress') OR finished_at IS NOT NULL
  ),
  CONSTRAINT vault_operations_phases_ck CHECK (jsonb_typeof(phases) = 'array')
);

COMMENT ON TABLE employees.vault_operations IS
  'Registro durable de operaciones que tocan Vault y PostgreSQL a la vez.';
COMMENT ON COLUMN employees.vault_operations.phases IS
  'Fases ejecutadas en orden. Permite saber que quedo hecho en Vault si falla PostgreSQL.';
COMMENT ON COLUMN employees.vault_operations.error IS
  'Error ya saneado por la aplicacion: nunca contrasenas, tokens ni semillas.';

-- Idempotency-Key: la misma clave no puede crear dos operaciones.
CREATE UNIQUE INDEX IF NOT EXISTS vault_operations_idempotency_ux
  ON employees.vault_operations (idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- Como maximo UNA operacion viva por usuario objetivo: protege de dos
-- peticiones concurrentes sobre el mismo empleado sin mantener abierta una
-- transaccion durante las llamadas de red a Vault.
CREATE UNIQUE INDEX IF NOT EXISTS vault_operations_one_active_ux
  ON employees.vault_operations (target_user_id)
  WHERE status IN ('pending', 'in_progress') AND target_user_id IS NOT NULL;

-- Consultas de reconciliacion: "que quedo a medias".
CREATE INDEX IF NOT EXISTS vault_operations_status_ix
  ON employees.vault_operations (status, created_at DESC);

CREATE INDEX IF NOT EXISTS vault_operations_target_ix
  ON employees.vault_operations (target_user_id, created_at DESC);

DROP TRIGGER IF EXISTS vault_operations_set_updated_at ON employees.vault_operations;
CREATE TRIGGER vault_operations_set_updated_at
  BEFORE UPDATE ON employees.vault_operations
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

COMMIT;
