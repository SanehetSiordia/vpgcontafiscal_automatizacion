#!/usr/bin/env bash
# Reconciliacion de operaciones que quedaron a medias entre Vault y PostgreSQL.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/user_mgmt/reconcile-operations.sh [list|inspect <operation_id>|close <operation_id> <nota>]
#
# Por que existe: una transaccion de PostgreSQL no revierte Vault. Cuando una
# operacion falla a mitad, la API la deja en 'needs_reconciliation' con sus
# fases registradas. Este script NO deshace nada por su cuenta: muestra el
# estado real de los dos sistemas para que una persona decida.
#
# Nunca muestra contrasenas, semillas TOTP, URIs otpauth ni tokens.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);     PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER); PG_USER=${PG_USER:-vpg_admin}
USERPASS_PATH=$(env_get VAULT_USERPASS_PATH); USERPASS_PATH=${USERPASS_PATH:-userpass}

psql_q() { docker compose exec -T postgres-service \
             psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" "$@"; }

ACTION=${1:-list}

case "$ACTION" in
  list)
    echo "==> Operaciones sin cerrar o que necesitan reconciliacion"
    psql_q -c "
SELECT operation_id, operation_type, status, target_username,
       created_at, finished_at, left(coalesce(error,''), 70) AS error
  FROM employees.vault_operations
 WHERE status IN ('pending','in_progress','needs_reconciliation')
 ORDER BY created_at;"
    echo
    echo "==> Resumen por estado (ultimas 24 h)"
    psql_q -c "
SELECT status, operation_type, count(*)
  FROM employees.vault_operations
 WHERE created_at > now() - interval '24 hours'
 GROUP BY 1,2 ORDER BY 1,2;"
    ;;

  inspect)
    OP_ID=${2:?falta el operation_id}
    echo "==> Registro en PostgreSQL"
    psql_q -x -c "
SELECT operation_id, operation_type, status, target_user_id, target_username,
       actor_user_id, error, created_at, finished_at,
       jsonb_pretty(phases) AS fases
  FROM employees.vault_operations WHERE operation_id = '${OP_ID}';"

    USERNAME=$(psql_q -qtAX -c "
SELECT coalesce(vi.vault_username, o.target_username)
  FROM employees.vault_operations o
  LEFT JOIN employees.user_vault_identity vi ON vi.user_id = o.target_user_id
 WHERE o.operation_id = '${OP_ID}';" | tr -d '\r[:space:]')

    if [[ -n "$USERNAME" ]]; then
      echo
      echo "==> Estado real en Vault de '${USERNAME}' (solo existencia, sin valores)"
      docker compose exec -T vault-service sh -s "$USERPASS_PATH" "$USERNAME" <<'PROBE'
set -eu
USERPASS_PATH=$1; USERNAME=$2
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
if vault read "auth/${USERPASS_PATH}/users/${USERNAME}" >/dev/null 2>&1; then
  echo "    cuenta userpass ....: EXISTE"
  echo "    politicas ..........: $(vault read -field=token_policies "auth/${USERPASS_PATH}/users/${USERNAME}" 2>/dev/null | tr '\n' ' ')"
else
  echo "    cuenta userpass ....: no existe"
fi
ACCESSOR=$(vault read -field=accessor "sys/auth/${USERPASS_PATH}" 2>/dev/null || echo "")
if [ -n "$ACCESSOR" ]; then
  ENTITY=$(vault write -field=id identity/lookup/entity \
            alias_name="$USERNAME" alias_mount_accessor="$ACCESSOR" 2>/dev/null || echo "")
  if [ -n "$ENTITY" ]; then
    echo "    entidad ............: ${ENTITY}"
    echo "    deshabilitada ......: $(vault read -field=disabled "identity/entity/id/${ENTITY}" 2>/dev/null || echo '?')"
  else
    echo "    entidad ............: no existe"
  fi
fi
PROBE
      echo
      echo "    (la existencia de una semilla TOTP no se puede consultar en Vault"
      echo "     sin generarla; por eso no se comprueba aqui)"
    fi
    echo
    echo "==> Siguiente paso: decidir a mano. Opciones habituales:"
    echo "    - Vault provisionado y PostgreSQL sin vinculo -> insertar el vinculo"
    echo "      o borrar la cuenta en Vault y repetir el provisionamiento."
    echo "    - Vault a medias -> completar con el CLI de Vault."
    echo "    Despues, cierra el registro:"
    echo "      bash scripts/user_mgmt/reconcile-operations.sh close ${OP_ID} \"nota\""
    ;;

  close)
    OP_ID=${2:?falta el operation_id}
    NOTE=${3:?falta una nota explicando la resolucion}
    NOTE_SQL=$(printf '%s' "$NOTE" | sed "s/'/''/g")
    psql_q -v ON_ERROR_STOP=1 -c "
UPDATE employees.vault_operations
   SET status = 'succeeded',
       error = coalesce(error, '') || ' | reconciliado a mano: ${NOTE_SQL}',
       finished_at = coalesce(finished_at, now())
 WHERE operation_id = '${OP_ID}'
   AND status IN ('needs_reconciliation','in_progress','pending');"
    echo "==> Operacion ${OP_ID} marcada como reconciliada."
    ;;

  *)
    echo "ERROR: accion desconocida '${ACTION}'. Usa list | inspect | close." >&2
    exit 1
    ;;
esac
