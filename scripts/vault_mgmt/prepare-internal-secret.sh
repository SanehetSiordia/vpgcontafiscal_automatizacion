#!/usr/bin/env bash
# Genera la credencial INTERNA que protege la pasarela entre
# vault-mgmt-service y user-mgmt-service.
#
#   secrets/vault_mgmt_internal_token
#     -> USER_MGMT_INTERNAL_CREDENTIAL_FILE   (quien la verifica)
#     -> VAULT_MGMT_INTERNAL_CREDENTIAL_FILE  (quien la presenta)
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/prepare-internal-secret.sh [--rotate]
#
# Por que existe esta credencial, si la red de Docker ya es interna:
#   La red NO autentica al llamante. Cualquier contenedor de network-service
#   puede resolver user-mgmt-service y llamar a /internal/v1/...; sin esta
#   credencial, el endpoint quedaria abierto a toda la red.
#
# Lo que esta credencial NO hace:
#   No sustituye al Bearer humano. La pasarela exige las DOS cosas: credencial
#   de servicio y api_session valida con sus roles y su ACL de Vault.
#
# Se compara en tiempo constante (hmac.compare_digest) en el lado que la
# verifica, y no se imprime en ningun momento.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

ROTATE=false
for arg in "$@"; do
  case "$arg" in
    --rotate) ROTATE=true ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SECRETS_DIR="${REPO_ROOT}/secrets"
mkdir -p "$SECRETS_DIR"

SECRET_PATH="${SECRETS_DIR}/vault_mgmt_internal_token"

if [[ -s "$SECRET_PATH" && "$ROTATE" == false ]]; then
  echo "==> vault_mgmt_internal_token: ya existe, se conserva (--rotate para rotarla)"
else
  if [[ -s "$SECRET_PATH" ]]; then
    echo "==> vault_mgmt_internal_token: se rota (--rotate)"
    echo "    AVISO: hay que recrear LOS DOS contenedores a la vez; si solo se"
    echo "    recrea uno, la pasarela respondera 401 hasta que el otro la lea."
  else
    echo "==> vault_mgmt_internal_token: generando"
  fi
  # 48 caracteres de [A-Za-z0-9]: ~285 bits. Sin salto de linea final; el
  # lector toma la primera linea y la recorta.
  #
  # Se leen 512 bytes de una vez y se filtran, en vez de `tr < /dev/urandom |
  # head -c 48`: ahi `head` cierra la tuberia, `tr` recibe SIGPIPE y el pipeline
  # devuelve 141, que con `set -o pipefail` aborta el script.
  value=$(head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c 1-48)
  if [[ ${#value} -lt 48 ]]; then
    echo "ERROR: no se pudieron generar 48 caracteres aleatorios." >&2
    exit 1
  fi
  printf '%s' "$value" > "$SECRET_PATH"
  unset value
  chmod 600 "$SECRET_PATH" 2>/dev/null || true
fi

echo
echo "==> Credencial en ${SECRET_PATH} (no se muestra su valor):"
printf '    %-28s %s caracteres\n' vault_mgmt_internal_token \
  "$(LC_ALL=C wc -c < "$SECRET_PATH" | tr -d ' ')"
echo
echo "    Recrea los dos servicios para que la monten:"
echo "      docker compose up -d user-mgmt-service vault-mgmt-service"
echo
echo "    Comprobacion (debe decir ready=true en los dos, con Vault desbloqueado):"
echo "      curl -s http://127.0.0.1:8000/health/ready | python -m json.tool"
echo "      curl -s http://127.0.0.1:8001/health/ready | python -m json.tool"
