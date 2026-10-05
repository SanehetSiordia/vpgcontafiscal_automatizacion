#!/usr/bin/env bash
# Prepara la base de PRUEBAS con el esquema real de las etapas 2, 3 y 4.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/prepare-test-db.sh [--recreate]
#
# Es la misma base que usa la suite de la etapa 3 (vpg_contadores_test), con la
# migracion 003 anadida: las dos suites comparten PostgreSQL de pruebas y cada
# una limpia sus propias tablas.
#
# Por que una base real y no SQLite: las pruebas comprueban restricciones que
# solo existen en PostgreSQL (indices parciales con COALESCE, CHECK con regex y
# con operadores de array, ON DELETE RESTRICT entre claves compuestas, ARRAY).
# SQLite no las tiene: "pasar" alli no demostraria nada.
#
# Es una base APARTE de vpg_contadores: las pruebas no tocan datos reales, ni la
# cuenta del administrador, ni los secretos de verdad.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

RECREATE=false
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_USER=$(env_get POSTGRES_USER);    PG_USER=${PG_USER:-vpg_admin}
PG_APP=$(env_get POSTGRES_APP_USER); PG_APP=${PG_APP:-vpg_app}
PG_DB=$(env_get POSTGRES_DB);        PG_DB=${PG_DB:-vpg_contadores}
VM_SCHEMA=$(env_get VAULT_MGMT_POSTGRES_SCHEMA); VM_SCHEMA=${VM_SCHEMA:-vault_mgmt}
TEST_DB="${PG_DB}_test"

if [[ "$RECREATE" == true ]]; then
  echo "==> Recreando ${TEST_DB} con el esquema de las etapas 2 y 3"
  bash "${REPO_ROOT}/scripts/user_mgmt/prepare-test-db.sh" --recreate
else
  echo "==> Asegurando ${TEST_DB} con el esquema de las etapas 2 y 3"
  bash "${REPO_ROOT}/scripts/user_mgmt/prepare-test-db.sh"
fi

echo
echo "==> Aplicando 003_vault_mgmt.sql en ${TEST_DB}"
docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 -v app_user="$PG_APP" --no-psqlrc --quiet \
       -U "$PG_USER" -d "$TEST_DB" < "${REPO_ROOT}/sql/003_vault_mgmt.sql" \
  | grep -viE 'already exists, skipping|does not exist, skipping' || true

echo "==> Tablas de ${VM_SCHEMA} en ${TEST_DB}"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$TEST_DB" -c "
SELECT c.relname AS tabla
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${VM_SCHEMA}' AND c.relkind = 'r' ORDER BY 1;"

echo "==> Permisos de ${PG_APP} en ${TEST_DB} (los MISMOS que en produccion)"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$TEST_DB" -c "
SELECT c.relname AS tabla,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'SELECT') AS sel,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'INSERT') AS ins,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'UPDATE') AS upd,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'DELETE') AS del
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${VM_SCHEMA}' AND c.relkind = 'r' ORDER BY 1;"

echo
echo "==> Listo. Base de pruebas: ${TEST_DB} (esquemas employees y ${VM_SCHEMA})"
