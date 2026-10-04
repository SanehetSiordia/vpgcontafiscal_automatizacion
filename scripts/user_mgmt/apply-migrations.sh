#!/usr/bin/env bash
# Aplica las migraciones SQL con la cuenta ADMINISTRATIVA y da permisos a la
# cuenta de ejecucion.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/user_mgmt/apply-migrations.sh
#
# FastAPI NO ejecuta DDL: no hay create_all(), ni migraciones automaticas, ni
# semillas al arrancar. Todo cambio de esquema pasa por aqui, de forma
# explicita, con el usuario propietario del esquema.
#
# Las migraciones son transaccionales y repetibles, pero eso NO sustituye un
# sistema de migraciones: cada cambio estructural necesita su propio archivo
# numerado.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);         PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER);     PG_USER=${PG_USER:-vpg_admin}
PG_APP=$(env_get POSTGRES_APP_USER);  PG_APP=${PG_APP:-vpg_app}
PG_SCHEMA=$(env_get POSTGRES_SCHEMA); PG_SCHEMA=${PG_SCHEMA:-employees}

MIGRATIONS=(001_employees.sql 002_vault_operations.sql)

echo "==> Aplicando migraciones en ${PG_DB} como ${PG_USER} (cuenta administrativa)"
for file in "${MIGRATIONS[@]}"; do
  path="${REPO_ROOT}/sql/${file}"
  [[ -r "$path" ]] || { echo "ERROR: falta ${path}" >&2; exit 1; }
  echo "    -> ${file}"
  docker compose exec -T postgres-service \
    psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet \
         --username "$PG_USER" --dbname "$PG_DB" < "$path" \
    | grep -viE 'already exists, skipping|does not exist, skipping' || true
done

echo
echo "==> Convergiendo permisos de la cuenta de ejecucion '${PG_APP}'"
docker compose exec -T postgres-service vpg-pg-roles

echo
echo "==> Comprobacion: ${PG_APP} sobre employees.vault_operations"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "
SELECT r.rolname,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.vault_operations', 'SELECT') AS select,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.vault_operations', 'INSERT') AS insert,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.vault_operations', 'UPDATE') AS update,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.vault_operations', 'TRUNCATE') AS truncate,
       has_schema_privilege(r.rolname, '${PG_SCHEMA}', 'CREATE') AS puede_ddl
  FROM pg_roles r WHERE r.rolname IN ('${PG_USER}', '${PG_APP}') ORDER BY r.rolname;"

echo
echo "==> Tablas del esquema tras migrar"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "
SELECT c.relname AS tabla
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${PG_SCHEMA}' AND c.relkind = 'r' ORDER BY 1;"
