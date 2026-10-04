#!/usr/bin/env bash
# Ejecuta la suite de pytest contra PostgreSQL REAL y un doble de Vault.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/user_mgmt/run-tests.sh [argumentos de pytest]
#   bash scripts/user_mgmt/run-tests.sh -k rbac -v
#
# Que hace:
#   1. Prepara (si falta) la base vpg_contadores_test con el MISMO esquema.
#   2. Construye la etapa `user-mgmt-test`, que anade pytest al runtime.
#   3. Lanza un contenedor efimero en network-service, apuntando a esa base.
#
# Las pruebas NO tocan vpg_contadores, ni la cuenta del administrador real, ni
# el Vault real: el cliente de Vault se sustituye por un doble. El login con un
# codigo TOTP de verdad es una comprobacion MANUAL, no automatizable.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);        PG_DB=${PG_DB:-vpg_contadores}
PG_APP=$(env_get POSTGRES_APP_USER); PG_APP=${PG_APP:-vpg_app}
NETWORK=$(env_get DOCKER_NETWORK_NAME); NETWORK=${NETWORK:-network-service}
TEST_DB="${PG_DB}_test"

[[ -s "${REPO_ROOT}/secrets/postgres_app_password" ]] || {
  echo "ERROR: falta secrets/postgres_app_password." >&2
  echo "       Ejecuta bash scripts/postgres/prepare-secrets.sh" >&2
  exit 1
}

echo "==> Preparando la base de pruebas"
bash "${REPO_ROOT}/scripts/user_mgmt/prepare-test-db.sh" >/dev/null

echo "==> Construyendo la imagen de pruebas"
docker build --quiet --target user-mgmt-test -t vpg/user-mgmt-test:local . >/dev/null

echo "==> Ejecutando pytest"
echo
# El secreto se monta como archivo de solo lectura, igual que en el servicio.
MSYS_NO_PATHCONV=1 docker run --rm \
  --network "$NETWORK" \
  -v "${REPO_ROOT}/secrets/postgres_app_password:/run/secrets/postgres_app_password:ro" \
  -e USER_MGMT_POSTGRES_HOST=postgres-service \
  -e USER_MGMT_POSTGRES_DB="$TEST_DB" \
  -e USER_MGMT_POSTGRES_USER="$PG_APP" \
  -e USER_MGMT_POSTGRES_PASSWORD_FILE=/run/secrets/postgres_app_password \
  -e USER_MGMT_ENVIRONMENT=ci \
  -e USER_MGMT_LOG_LEVEL=warning \
  vpg/user-mgmt-test:local \
  python -m pytest "$@"
