#!/usr/bin/env bash
# Crea (o recrea) la base de datos de PRUEBAS con el esquema real.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/user_mgmt/prepare-test-db.sh [--recreate]
#
# Por que una base real y no SQLite: las pruebas comprueban restricciones de
# PostgreSQL (indices unicos sobre expresiones, indices parciales, CHECK con
# regex, ON DELETE RESTRICT). SQLite no las tiene, asi que "pasar" alli no
# demostraria nada.
#
# Es una base APARTE de vpg_contadores: las pruebas no tocan los datos reales
# ni la cuenta del administrador.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

RECREATE=false
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=true ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
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
TEST_DB="${PG_DB}_test"

exists=$(docker compose exec -T postgres-service \
  psql --no-psqlrc -qtAX -U "$PG_USER" -d postgres \
  -c "SELECT 1 FROM pg_database WHERE datname = '${TEST_DB}';" | tr -d '\r[:space:]')

if [[ "$exists" == "1" && "$RECREATE" == true ]]; then
  echo "==> Eliminando ${TEST_DB} (--recreate)"
  docker compose exec -T postgres-service \
    psql --no-psqlrc -qtAX -U "$PG_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE);" >/dev/null
  exists=""
fi

if [[ "$exists" != "1" ]]; then
  echo "==> Creando ${TEST_DB}"
  docker compose exec -T postgres-service \
    psql --no-psqlrc -qtAX -U "$PG_USER" -d postgres \
    -c "CREATE DATABASE ${TEST_DB} OWNER ${PG_USER};" >/dev/null
else
  echo "==> ${TEST_DB} ya existe, se reutiliza"
fi

echo "==> Aplicando el MISMO esquema que en produccion"
for file in 001_employees.sql 002_vault_operations.sql; do
  echo "    -> ${file}"
  docker compose exec -T postgres-service \
    psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet -U "$PG_USER" -d "$TEST_DB" \
    < "${REPO_ROOT}/sql/${file}" \
    | grep -viE 'already exists, skipping|does not exist, skipping' || true
done

echo "==> Permisos de ${PG_APP} sobre ${TEST_DB}"
docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet -U "$PG_USER" -d "$TEST_DB" <<SQL
GRANT CONNECT ON DATABASE ${TEST_DB} TO ${PG_APP};
GRANT USAGE ON SCHEMA employees TO ${PG_APP};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA employees TO ${PG_APP};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA employees TO ${PG_APP};
ALTER DEFAULT PRIVILEGES FOR ROLE ${PG_USER} IN SCHEMA employees
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${PG_APP};
SQL

echo
echo "==> Listo. Base de pruebas: ${TEST_DB}"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$TEST_DB" -c "
SELECT count(*) AS tablas FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'employees' AND c.relkind = 'r';"
