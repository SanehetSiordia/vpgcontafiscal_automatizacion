#!/usr/bin/env bash
# Lista las operaciones de secretos que quedaron a medias y da el contexto para
# decidir que hacer con cada una.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/reconcile-operations.sh
#   bash scripts/vault_mgmt/reconcile-operations.sh --operation <operation_id>
#   bash scripts/vault_mgmt/reconcile-operations.sh --close <operation_id> \
#        --as failed --note "revisado: Vault no escribio"
#
# Este script NO arregla nada por su cuenta, y es deliberado:
#
#   * No existe transaccion distribuida entre PostgreSQL y Vault. Cuando una
#     operacion queda en 'needs_reconciliation' significa que Vault PUDO haber
#     aplicado el cambio y la respuesta se perdio. Reintentar a ciegas una
#     escritura que quizas se aplico es como se duplican versiones.
#   * La decision correcta depende de leer la metadata REAL del registro en
#     Vault y compararla con el catalogo. Eso lo hace una persona.
#   * --close solo cierra el registro de la operacion. NO toca Vault, NO toca el
#     indice de registros y NO revierte nada: sirve para dejar constancia de que
#     alguien ya la reviso.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

MODE=list
OPERATION=""
CLOSE_AS=""
NOTE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operation) MODE=detail; OPERATION=${2:-}; shift 2 ;;
    --close)     MODE=close;  OPERATION=${2:-}; shift 2 ;;
    --as)        CLOSE_AS=${2:-}; shift 2 ;;
    --note)      NOTE=${2:-}; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

if [[ "$MODE" != "list" && ! "$OPERATION" =~ ^[0-9a-fA-F-]{36}$ ]]; then
  echo "ERROR: se espera un operation_id con formato UUID." >&2
  exit 1
fi
if [[ "$MODE" == "close" ]]; then
  case "$CLOSE_AS" in
    completed|failed|needs_reconciliation) ;;
    *) echo "ERROR: --as debe ser completed, failed o needs_reconciliation." >&2; exit 1 ;;
  esac
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);     PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER); PG_USER=${PG_USER:-vpg_admin}
VM_SCHEMA=$(env_get VAULT_MGMT_POSTGRES_SCHEMA); VM_SCHEMA=${VM_SCHEMA:-vault_mgmt}
KV_MOUNT=$(env_get VAULT_MGMT_KV_MOUNT);   KV_MOUNT=${KV_MOUNT:-secret}
KV_PREFIX=$(env_get VAULT_MGMT_KV_PREFIX); KV_PREFIX=${KV_PREFIX:-vpg-managed}

run_sql() {
  docker compose exec -T postgres-service \
    psql -v ON_ERROR_STOP=1 --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "$1"
}

if [[ "$MODE" == "list" ]]; then
  echo "==> Operaciones de secretos sin cerrar"
  run_sql "
SELECT operation_id, operation_type, status, actor_username,
       collection_id, record_id, expected_version, result_version,
       created_at
  FROM ${VM_SCHEMA}.secret_operations
 WHERE status IN ('pending', 'in_progress', 'needs_reconciliation')
 ORDER BY created_at ASC, operation_id ASC
 LIMIT 100;"

  echo "==> Recuento por estado"
  run_sql "
SELECT status, count(*) AS total
  FROM ${VM_SCHEMA}.secret_operations
 GROUP BY status ORDER BY 1;"

  echo "==> Registros cuyo estado en el catalogo puede no reflejar Vault"
  echo "    (los que tienen una operacion sin cerrar encima)"
  run_sql "
SELECT r.record_id, r.collection_id, r.state, r.current_version,
       o.operation_type, o.status AS operacion
  FROM ${VM_SCHEMA}.secret_records r
  JOIN ${VM_SCHEMA}.secret_operations o ON o.record_id = r.record_id
 WHERE o.status IN ('pending', 'in_progress', 'needs_reconciliation')
 ORDER BY r.collection_id, r.record_id
 LIMIT 100;"

  cat <<NEXT

==> Como decidir, para cada una
    1. Mira las fases de la operacion:
         bash scripts/vault_mgmt/reconcile-operations.sh --operation <operation_id>
    2. Compara con la metadata REAL en Vault (sin imprimir valores):
         docker compose exec vault-service vault kv metadata get \\
           ${KV_MOUNT}/${KV_PREFIX}/<collection_id>/<record_id>
    3. Si Vault tiene la version y el catalogo no, corrige el catalogo con la
       cuenta administrativa y deja la operacion como 'completed'.
       Si Vault no la tiene, la operacion es 'failed' y se puede repetir la
       peticion de forma consciente.
    4. Deja constancia de la revision:
         bash scripts/vault_mgmt/reconcile-operations.sh --close <operation_id> \\
           --as failed --note "Vault no escribio; revisado por <quien>"

    No reintentes una escritura sin hacer el paso 2. Si la respuesta se perdio,
    Vault puede tener ya la version y un reintento crearia otra.
NEXT
  exit 0
fi

if [[ "$MODE" == "detail" ]]; then
  echo "==> Operacion ${OPERATION}"
  run_sql "
SELECT operation_id, operation_type, status, actor_username,
       collection_id, record_id, idempotency_key,
       expected_version, result_version, counters, error,
       created_at, updated_at, finished_at
  FROM ${VM_SCHEMA}.secret_operations
 WHERE operation_id = '${OPERATION}';"

  echo "==> Fases, en orden"
  run_sql "
SELECT ord AS n,
       fase->>'phase'  AS fase,
       fase->>'system' AS sistema,
       fase->>'state'  AS estado,
       fase->>'at'     AS momento,
       fase->>'detail' AS detalle
  FROM ${VM_SCHEMA}.secret_operations o,
       LATERAL jsonb_array_elements(o.phases) WITH ORDINALITY AS t(fase, ord)
 WHERE o.operation_id = '${OPERATION}'
 ORDER BY ord;"

  echo "==> Auditoria relacionada"
  run_sql "
SELECT occurred_at, actor_kind, actor_label, action, outcome, versions, detail
  FROM ${VM_SCHEMA}.secret_audit
 WHERE operation_id = '${OPERATION}'
 ORDER BY occurred_at DESC, audit_id DESC;"

  echo "==> Comando para ver la metadata REAL en Vault (no imprime valores)"
  run_sql "
SELECT 'docker compose exec vault-service vault kv metadata get '
       || c.kv_mount || '/' || c.kv_prefix || '/' || o.collection_id || '/' || o.record_id
       AS comando
  FROM ${VM_SCHEMA}.secret_operations o
  JOIN ${VM_SCHEMA}.secret_collections c ON c.collection_id = o.collection_id
 WHERE o.operation_id = '${OPERATION}' AND o.record_id IS NOT NULL;"
  exit 0
fi

# --- cierre manual con constancia -------------------------------------------
echo "==> Cerrando ${OPERATION} como '${CLOSE_AS}'"
echo "    Esto NO toca Vault ni el indice de registros: solo deja constancia."
NOTE_SQL=${NOTE//\'/\'\'}
run_sql "
UPDATE ${VM_SCHEMA}.secret_operations
   SET status = '${CLOSE_AS}',
       finished_at = coalesce(finished_at, now()),
       error = coalesce(error, '') ||
               case when '${NOTE_SQL}' = '' then '' else ' | revision CLI: ${NOTE_SQL}' end
 WHERE operation_id = '${OPERATION}'
 RETURNING operation_id, operation_type, status, finished_at;"

run_sql "
INSERT INTO ${VM_SCHEMA}.secret_audit
       (actor_kind, actor_label, action, outcome, collection_id, record_id,
        operation_id, detail)
SELECT 'cli', 'reconcile-operations', 'operation_reconciled',
       case when '${CLOSE_AS}' = 'completed' then 'allowed' else 'partial' end,
       collection_id, record_id, operation_id,
       'cerrada a mano como ${CLOSE_AS}${NOTE:+: }${NOTE_SQL}'
  FROM ${VM_SCHEMA}.secret_operations
 WHERE operation_id = '${OPERATION}';"

echo
echo "==> Hecho. Queda registrado en la auditoria quien y como la cerro."
