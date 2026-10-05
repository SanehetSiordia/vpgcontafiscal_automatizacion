#!/usr/bin/env bash
# Ejecuta la suite de la etapa 4 contra PostgreSQL REAL y dobles explicitos de
# la pasarela y de Vault.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/run-tests.sh [argumentos de pytest]
#   bash scripts/vault_mgmt/run-tests.sh -k cas -v
#   bash scripts/vault_mgmt/run-tests.sh --all     # etapas 3 y 4 juntas
#
# Que hace:
#   1. Prepara (si falta) vpg_contadores_test con los esquemas employees y
#      vault_mgmt, con los MISMOS permisos DML que en produccion.
#   2. Construye la etapa `vault-mgmt-test`, que anade pytest al runtime.
#   3. Lanza un contenedor efimero en network-service apuntando a esa base.
#
# Con que se prueba, dicho sin adornos:
#   * PostgreSQL es REAL. Las restricciones que se comprueban (indices parciales,
#     CHECK con regex, FK compuesta con RESTRICT, ARRAY) solo existen ahi.
#   * La pasarela interna y Vault KV son DOBLES explicitos. El doble de KV
#     reproduce lo que importa: CAS, soft-delete, undelete, destroy, metadata y
#     response wrapping con un solo uso.
#   * El login con un codigo TOTP de verdad y una instancia de Vault real son
#     comprobaciones MANUALES, documentadas en el README. No se deducen de estos
#     dobles y no se presentan como si lo fueran.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

TARGET_PATH=tests/vault_mgmt
PYTEST_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --all) TARGET_PATH=tests ;;
    *) PYTEST_ARGS+=("$arg") ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);        PG_DB=${PG_DB:-vpg_contadores}
PG_APP=$(env_get POSTGRES_APP_USER); PG_APP=${PG_APP:-vpg_app}
NETWORK=$(env_get DOCKER_NETWORK_NAME); NETWORK=${NETWORK:-network-service}
VM_SCHEMA=$(env_get VAULT_MGMT_POSTGRES_SCHEMA); VM_SCHEMA=${VM_SCHEMA:-vault_mgmt}
PG_SCHEMA=$(env_get POSTGRES_SCHEMA); PG_SCHEMA=${PG_SCHEMA:-employees}
TEST_DB="${PG_DB}_test"

[[ -s "${REPO_ROOT}/secrets/postgres_app_password" ]] || {
  echo "ERROR: falta secrets/postgres_app_password." >&2
  echo "       Ejecuta bash scripts/postgres/prepare-secrets.sh" >&2
  exit 1
}

echo "==> Preparando la base de pruebas (esquemas ${PG_SCHEMA} y ${VM_SCHEMA})"
bash "${REPO_ROOT}/scripts/vault_mgmt/prepare-test-db.sh" >/dev/null

echo "==> Construyendo la imagen de pruebas"
docker build --quiet --target vault-mgmt-test -t vpg/vault-mgmt-test:local . >/dev/null

echo "==> Ejecutando pytest sobre ${TARGET_PATH}"
echo
# Los secretos se montan como archivos de solo lectura, igual que en el
# servicio. La credencial interna de las pruebas es un archivo efimero: no se
# reutiliza ninguna semilla ni el valor real de secrets/.
TMP_CRED=$(mktemp)
printf '%s' "credencial-interna-solo-para-pruebas" > "$TMP_CRED"
trap 'rm -f "$TMP_CRED"' EXIT

MSYS_NO_PATHCONV=1 docker run --rm \
  --network "$NETWORK" \
  -v "${REPO_ROOT}/secrets/postgres_app_password:/run/secrets/postgres_app_password:ro" \
  -v "${TMP_CRED}:/run/secrets/vault_mgmt_internal_token:ro" \
  -e VAULT_MGMT_POSTGRES_HOST=postgres-service \
  -e VAULT_MGMT_POSTGRES_DB="$TEST_DB" \
  -e VAULT_MGMT_POSTGRES_USER="$PG_APP" \
  -e VAULT_MGMT_POSTGRES_SCHEMA="$VM_SCHEMA" \
  -e VAULT_MGMT_POSTGRES_EMPLOYEES_SCHEMA="$PG_SCHEMA" \
  -e VAULT_MGMT_POSTGRES_PASSWORD_FILE=/run/secrets/postgres_app_password \
  -e VAULT_MGMT_INTERNAL_CREDENTIAL_FILE=/run/secrets/vault_mgmt_internal_token \
  -e VAULT_MGMT_ENVIRONMENT=ci \
  -e VAULT_MGMT_LOG_LEVEL=warning \
  -e USER_MGMT_POSTGRES_HOST=postgres-service \
  -e USER_MGMT_POSTGRES_DB="$TEST_DB" \
  -e USER_MGMT_POSTGRES_USER="$PG_APP" \
  -e USER_MGMT_POSTGRES_PASSWORD_FILE=/run/secrets/postgres_app_password \
  -e USER_MGMT_INTERNAL_CREDENTIAL_FILE=/run/secrets/vault_mgmt_internal_token \
  -e USER_MGMT_ENVIRONMENT=ci \
  -e USER_MGMT_LOG_LEVEL=warning \
  vpg/vault-mgmt-test:local \
  python -m pytest "$TARGET_PATH" "${PYTEST_ARGS[@]+"${PYTEST_ARGS[@]}"}"
