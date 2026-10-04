#!/usr/bin/env bash
# Prepara la CUENTA TECNICA de user-mgmt-service en Vault (AppRole) y deja sus
# credenciales como Compose secrets.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/user_mgmt/vault-approle-bootstrap.sh [--rotate-secret-id]
#
# Que hace, de forma idempotente:
#   1. Escribe la politica 'vpg-user-mgmt' (config/policies/vpg-user-mgmt.hcl).
#   2. Habilita el metodo AppRole si falta.
#   3. Crea o actualiza el rol 'vpg-user-mgmt' con esa politica y TTL cortos.
#   4. Genera role_id y secret_id y los guarda en secrets/.
#
# Por que AppRole y no otra cosa:
#   * El Initial Root Token NO sirve como credencial habitual de un servicio.
#   * La contrasena del administrador humano TAMPOCO: sus sesiones llevan MFA y
#     son suyas, no de un proceso.
#   * El secret_id caduca y se rota sin tocar el role_id.
#
# Requiere Vault desbloqueado y un token con permisos de administracion
# (sesion 'vault login' en el contenedor, o VAULT_INITIAL_TOKEN en .env).
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

ROTATE=false
for arg in "$@"; do
  case "$arg" in
    --rotate-secret-id) ROTATE=true ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
SECRETS_DIR="${REPO_ROOT}/secrets"
mkdir -p "$SECRETS_DIR"

POLICY_NAME=vpg-user-mgmt
ROLE_NAME=vpg-user-mgmt
APPROLE_PATH=approle

echo "==> Comprobando Vault"
docker compose exec -T vault-service sh -s <<'PRECHECK'
set -eu
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
status=0; vault status >/dev/null 2>&1 || status=$?
case "$status" in
  0) ;;
  2) echo "ERROR: Vault esta sellado o sin inicializar. Desbloquealo primero." >&2; exit 1 ;;
  *) echo "ERROR: Vault no responde." >&2; exit 1 ;;
esac
vault token lookup >/dev/null 2>&1 \
  || { echo "ERROR: sin token administrativo valido en el contenedor." >&2; exit 1; }
PRECHECK

POLICY_FILE="${REPO_ROOT}/config/policies/vpg-user-mgmt.hcl"
[[ -r "$POLICY_FILE" ]] || { echo "ERROR: falta ${POLICY_FILE}" >&2; exit 1; }

echo "==> Escribiendo la politica '${POLICY_NAME}'"
# La politica viaja por stdin ('vault policy write <nombre> -') en vez de leerse
# de /vault/config/policies/. Asi el script funciona aunque la imagen de Vault
# se construyera antes de anadir este archivo, y no hace falta recrear el
# contenedor, que volveria a quedar sellado.
docker compose exec -T vault-service sh -c '
  set -eu
  if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
    VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
  fi
  vault policy write "$1" - >/dev/null
  echo "    politica escrita"
' vpg-policy-write "$POLICY_NAME" < "$POLICY_FILE"

echo "==> Habilitando AppRole y creando el rol '${ROLE_NAME}'"
docker compose exec -T vault-service sh -s "$APPROLE_PATH" "$ROLE_NAME" "$POLICY_NAME" <<'ROLE'
set -eu
APPROLE_PATH=$1; ROLE_NAME=$2; POLICY_NAME=$3
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
if ! vault auth list 2>/dev/null | grep -q "^${APPROLE_PATH}/ "; then
  vault auth enable -path="$APPROLE_PATH" \
    -description="Cuenta tecnica de user-mgmt-service" approle >/dev/null
  echo "    auth approle habilitado en ${APPROLE_PATH}/"
else
  echo "    auth approle ya estaba habilitado"
fi

# TTL cortos y renovables: el servicio renueva o reautentica solo.
# secret_id_num_uses=0 porque el contenedor reautentica tras cada reinicio.
vault write "auth/${APPROLE_PATH}/role/${ROLE_NAME}" \
  token_policies="$POLICY_NAME" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=720h \
  secret_id_num_uses=0 \
  bind_secret_id=true >/dev/null
echo "    rol ${ROLE_NAME} configurado (politica ${POLICY_NAME}, token_ttl 1h)"
ROLE

write_secret() {
  # Declaraciones por separado: con `set -u`, un `local a=$1 b="${a}"` no
  # garantiza que `a` este definida al expandir `b`.
  local name=$1
  local value=$2
  local path="${SECRETS_DIR}/${name}"
  printf '%s' "$value" > "$path"
  chmod 600 "$path" 2>/dev/null || true
}

ROLE_ID_FILE="${SECRETS_DIR}/vault_role_id"
if [[ -s "$ROLE_ID_FILE" && "$ROTATE" == false ]]; then
  echo "==> role_id: ya existe, se conserva"
else
  echo "==> Obteniendo role_id"
  ROLE_ID=$(docker compose exec -T vault-service sh -s "$APPROLE_PATH" "$ROLE_NAME" <<'RID'
set -eu
APPROLE_PATH=$1; ROLE_NAME=$2
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
vault read -field=role_id "auth/${APPROLE_PATH}/role/${ROLE_NAME}/role-id"
RID
)
  write_secret vault_role_id "$(printf '%s' "$ROLE_ID" | tr -d '\r\n')"
  unset ROLE_ID
fi

SECRET_ID_FILE="${SECRETS_DIR}/vault_secret_id"
if [[ -s "$SECRET_ID_FILE" && "$ROTATE" == false ]]; then
  echo "==> secret_id: ya existe, se conserva (--rotate-secret-id para rotarlo)"
else
  echo "==> Generando secret_id"
  SECRET_ID=$(docker compose exec -T vault-service sh -s "$APPROLE_PATH" "$ROLE_NAME" <<'SID'
set -eu
APPROLE_PATH=$1; ROLE_NAME=$2
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
vault write -f -field=secret_id "auth/${APPROLE_PATH}/role/${ROLE_NAME}/secret-id"
SID
)
  write_secret vault_secret_id "$(printf '%s' "$SECRET_ID" | tr -d '\r\n')"
  unset SECRET_ID
fi

echo
echo "==> Credenciales tecnicas en ${SECRETS_DIR} (no se muestran sus valores):"
for f in vault_role_id vault_secret_id; do
  printf '    %-18s %s caracteres\n' "$f" \
    "$(LC_ALL=C wc -c < "${SECRETS_DIR}/${f}" | tr -d ' ')"
done
echo
echo "    Recrea el contenedor para que los monte:"
echo "      docker compose up -d user-mgmt-service"
echo
echo "    Comprobacion de permisos de la cuenta tecnica (debe decir vpg-user-mgmt):"
echo "      docker compose exec user-mgmt-service python -c \\"
echo "        \"import asyncio;from app.core.config import get_settings;from app.core.vault import VaultClient;\\"
echo "         c=VaultClient(get_settings());print(asyncio.run(c.check_technical_credentials()))\""
