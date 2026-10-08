#!/usr/bin/env bash
# Aplica las migraciones 003 y 004 (esquema vault_mgmt) con la cuenta
# ADMINISTRATIVA y comprueba que los permisos DML de la cuenta de ejecucion son
# los minimos.
#
#   003_vault_mgmt.sql          catalogo de colecciones, registros y consumidores
#   004_crawler_provisioning.sql aprovisionamiento automatico (etapa 4.6)
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/apply-migrations.sh
#
# Requisitos previos: las migraciones 001 y 002 ya aplicadas
# (bash scripts/user_mgmt/apply-migrations.sh) y el rol vpg_app creado
# (docker compose exec postgres-service vpg-pg-roles).
#
# FastAPI NO ejecuta DDL: no hay create_all(), ni migraciones automaticas, ni
# semillas al arrancar. Todo cambio de esquema pasa por aqui.
#
# La migracion es transaccional y repetible, pero eso NO sustituye un sistema
# de migraciones: cada cambio estructural necesita su propio archivo numerado.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);        PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER);    PG_USER=${PG_USER:-vpg_admin}
PG_APP=$(env_get POSTGRES_APP_USER); PG_APP=${PG_APP:-vpg_app}
VM_SCHEMA=$(env_get VAULT_MGMT_POSTGRES_SCHEMA); VM_SCHEMA=${VM_SCHEMA:-vault_mgmt}

echo "==> Comprobando que existen las migraciones previas"
previas=$(docker compose exec -T postgres-service \
  psql --no-psqlrc -qtAX -U "$PG_USER" -d "$PG_DB" -c "
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'employees' AND c.relname IN ('users','vault_operations');" \
  | tr -d '\r[:space:]')
if [[ "$previas" != "2" ]]; then
  echo "ERROR: faltan las migraciones 001/002 en ${PG_DB}." >&2
  echo "       Ejecuta antes: bash scripts/user_mgmt/apply-migrations.sh" >&2
  exit 1
fi
echo "    employees.users y employees.vault_operations presentes"

echo
echo "==> Aplicando 003_vault_mgmt.sql en ${PG_DB} como ${PG_USER}"
docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 -v app_user="$PG_APP" --no-psqlrc --quiet \
       --username "$PG_USER" --dbname "$PG_DB" < "${REPO_ROOT}/sql/003_vault_mgmt.sql" \
  | grep -viE 'already exists, skipping|does not exist, skipping' || true

echo
echo "==> Aplicando 004_crawler_provisioning.sql en ${PG_DB} como ${PG_USER}"
echo "    (consumer_deliveries, alcance de consumidor en secret_operations y"
echo "     los estados waiting_receiver / awaiting_ack)"
docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 -v app_user="$PG_APP" --no-psqlrc --quiet \
       --username "$PG_USER" --dbname "$PG_DB" < "${REPO_ROOT}/sql/004_crawler_provisioning.sql" \
  | grep -viE 'already exists, skipping|does not exist, skipping' || true

echo
echo "==> Tablas del esquema ${VM_SCHEMA}"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "
SELECT c.relname AS tabla
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${VM_SCHEMA}' AND c.relkind = 'r' ORDER BY 1;"

echo "==> Permisos DML de ${PG_APP}: deben ser los MINIMOS"
echo "    (esquemas y auditoria: solo SELECT e INSERT; nada con TRUNCATE;"
echo "     colecciones y operaciones: sin DELETE; ningun CREATE en el esquema)"
docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "
SELECT c.relname AS tabla,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'SELECT')   AS sel,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'INSERT')   AS ins,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'UPDATE')   AS upd,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'DELETE')   AS del,
       has_table_privilege('${PG_APP}', '${VM_SCHEMA}.' || c.relname, 'TRUNCATE') AS trunc
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${VM_SCHEMA}' AND c.relkind = 'r'
 ORDER BY 1;"

docker compose exec -T postgres-service \
  psql --no-psqlrc -U "$PG_USER" -d "$PG_DB" -c "
SELECT has_schema_privilege('${PG_APP}', '${VM_SCHEMA}', 'USAGE')  AS usage,
       has_schema_privilege('${PG_APP}', '${VM_SCHEMA}', 'CREATE') AS puede_ddl;"

echo
echo "==> Listo. Siguiente paso:"
echo "      bash scripts/vault_mgmt/vault-kv-policies.sh   # politicas KV v2"
echo "      bash scripts/vault_mgmt/prepare-internal-secret.sh"
echo "      make all                                       # genera la credencial"
echo "                                                     # de cada receptor 4.6"
