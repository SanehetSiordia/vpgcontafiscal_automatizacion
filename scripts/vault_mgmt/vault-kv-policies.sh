#!/usr/bin/env bash
# Prepara en Vault las politicas KV v2 limitadas al prefijo gestionado y las
# asigna a las cuentas userpass de los empleados que correspondan.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/vault-kv-policies.sh                 # solo politicas
#   bash scripts/vault_mgmt/vault-kv-policies.sh --grant-admin ada.admin
#   bash scripts/vault_mgmt/vault-kv-policies.sh --grant-reader max.manager
#   bash scripts/vault_mgmt/vault-kv-policies.sh --revoke max.manager
#   bash scripts/vault_mgmt/vault-kv-policies.sh --show ada.admin
#
# Esto implementa el mapeo que el README declaraba PENDIENTE:
#
#   vpg-secrets-admin   escribir y administrar los secretos gestionados
#   vpg-secrets-reader  leer los secretos gestionados
#
# Lo que NO se hace aqui, a proposito:
#   * NO se concede 'vpg-admin' (acceso total a Vault) a todo el personal. Esa
#     politica se asigna a mano y solo al administrador humano.
#   * NO se amplia la AppRole de user-mgmt para leer secretos. Una cuenta
#     tecnica prepara infraestructura; no suplanta permisos humanos.
#   * NO se habilita ningun montaje: KV v2 ya esta habilitado desde la etapa 1.
#
# El rol de aplicacion y la politica de Vault son cosas distintas: tener 'admin'
# en PostgreSQL no concede nada en Vault. Hay que hacer las dos cosas, y Vault
# manda sobre el rol.
#
# Requiere Vault desbloqueado y un token administrativo en el contenedor
# (sesion 'vault login', o VAULT_INITIAL_TOKEN en .env).
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

ACTION=policies
TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --grant-admin)  ACTION=grant_admin;  TARGET=${2:-}; shift 2 ;;
    --grant-reader) ACTION=grant_reader; TARGET=${2:-}; shift 2 ;;
    --revoke)       ACTION=revoke;       TARGET=${2:-}; shift 2 ;;
    --show)         ACTION=show;         TARGET=${2:-}; shift 2 ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

if [[ "$ACTION" != "policies" && -z "$TARGET" ]]; then
  echo "ERROR: falta el usuario userpass objetivo." >&2
  exit 1
fi
if [[ -n "$TARGET" && ! "$TARGET" =~ ^[a-z0-9][a-z0-9._-]{1,62}$ ]]; then
  echo "ERROR: el usuario userpass solo admite [a-z0-9._-]." >&2
  exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

KV_MOUNT=$(env_get VAULT_MGMT_KV_MOUNT);   KV_MOUNT=${KV_MOUNT:-secret}
KV_PREFIX=$(env_get VAULT_MGMT_KV_PREFIX); KV_PREFIX=${KV_PREFIX:-vpg-managed}
USERPASS=$(env_get VAULT_USERPASS_PATH);   USERPASS=${USERPASS:-userpass}

ADMIN_POLICY=vpg-secrets-admin
READER_POLICY=vpg-secrets-reader

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

# Las politicas se GENERAN a partir del montaje y del prefijo configurados, en
# vez de copiarse tal cual desde config/policies/. Asi no pueden quedar
# desparejadas con VAULT_MGMT_KV_MOUNT / VAULT_MGMT_KV_PREFIX. Los archivos de
# config/policies/ son la version legible y comentada de lo mismo.
write_policy() {
  local name=$1
  local body=$2
  docker compose exec -T vault-service sh -c '
    set -eu
    if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
      VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
    fi
    vault policy write "$1" - >/dev/null
  ' vpg-policy-write "$name" <<< "$body"
  echo "    politica ${name} escrita"
}

if [[ "$ACTION" == "policies" ]]; then
  echo "==> Escribiendo politicas limitadas a ${KV_MOUNT}/+/${KV_PREFIX}/*"

  write_policy "$ADMIN_POLICY" "$(cat <<POLICY
# Generada por scripts/vault_mgmt/vault-kv-policies.sh. Alcance: solo el
# prefijo gestionado. No es vpg-admin y no la sustituye.
path "${KV_MOUNT}/data/${KV_PREFIX}/*" {
  capabilities = ["create", "read", "update"]
}
path "${KV_MOUNT}/metadata/${KV_PREFIX}/*" {
  capabilities = ["read", "list", "delete"]
}
path "${KV_MOUNT}/delete/${KV_PREFIX}/*" {
  capabilities = ["update"]
}
path "${KV_MOUNT}/undelete/${KV_PREFIX}/*" {
  capabilities = ["update"]
}
path "${KV_MOUNT}/destroy/${KV_PREFIX}/*" {
  capabilities = ["update"]
}
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}
path "sys/wrapping/lookup" {
  capabilities = ["update"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
POLICY
)"

  write_policy "$READER_POLICY" "$(cat <<POLICY
# Generada por scripts/vault_mgmt/vault-kv-policies.sh. Solo lectura de datos:
# sin escritura, sin delete/undelete/destroy, sin metadata y sin list.
path "${KV_MOUNT}/data/${KV_PREFIX}/*" {
  capabilities = ["read"]
}
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}
path "sys/wrapping/lookup" {
  capabilities = ["update"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
POLICY
)"

  echo
  echo "==> Politicas presentes en Vault"
  docker compose exec -T vault-service sh -c '
    set -eu
    if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
      VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
    fi
    vault policy list | sed "s/^/    /"
  '
  echo
  echo "    Siguiente paso: asignarlas a quien corresponda."
  echo "      bash scripts/vault_mgmt/vault-kv-policies.sh --grant-admin  <userpass>"
  echo "      bash scripts/vault_mgmt/vault-kv-policies.sh --grant-reader <userpass>"
  echo
  echo "    AVISO: un token ya emitido NO cambia de politicas. La persona debe"
  echo "    volver a iniciar sesion (login + TOTP) para que surtan efecto."
  exit 0
fi

# --- asignacion y retirada por usuario userpass ------------------------------
# Se leen las politicas actuales, se anade o se quita la que toca y se vuelven a
# escribir. No se sobrescribe la lista a ciegas: eso borraria 'vpg-admin' o
# 'vpg-oidc-user' de quien las tuviera.
docker compose exec -T vault-service sh -s \
  "$USERPASS" "$TARGET" "$ACTION" "$ADMIN_POLICY" "$READER_POLICY" <<'GRANT'
set -eu
USERPASS=$1; TARGET=$2; ACTION=$3; ADMIN_POLICY=$4; READER_POLICY=$5
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi

if ! vault read "auth/${USERPASS}/users/${TARGET}" >/dev/null 2>&1; then
  echo "ERROR: no existe la cuenta userpass '${TARGET}'." >&2
  echo "       Provisionala antes desde user-mgmt:" >&2
  echo "       POST /user_mgmt/v1/user/{user_id}/vault/provision" >&2
  exit 1
fi

current=$(vault read -field=token_policies "auth/${USERPASS}/users/${TARGET}" 2>/dev/null || echo "")
current=$(printf '%s' "$current" | tr -d '[]' | tr ',' ' ' | tr -s ' ')

case "$ACTION" in
  show)
    echo "    politicas actuales de ${TARGET}: ${current:-(ninguna)}"
    exit 0 ;;
  grant_admin)  wanted=$ADMIN_POLICY ;;
  grant_reader) wanted=$READER_POLICY ;;
  revoke)       wanted="" ;;
esac

new=""
for p in $current; do
  # Al retirar se quitan LAS DOS politicas de secretos y se conserva el resto.
  if [ "$ACTION" = "revoke" ]; then
    case "$p" in
      "$ADMIN_POLICY"|"$READER_POLICY") continue ;;
    esac
  fi
  [ "$p" = "$wanted" ] && continue
  new="${new}${new:+,}${p}"
done
if [ -n "$wanted" ]; then
  new="${new}${new:+,}${wanted}"
fi

vault write "auth/${USERPASS}/users/${TARGET}/policies" \
  token_policies="$new" >/dev/null
echo "    politicas de ${TARGET}: ${new:-(ninguna)}"
GRANT

echo
echo "==> Hecho."
echo "    AVISO: un token ya emitido conserva sus politicas. La persona debe"
echo "    cerrar sesion y volver a entrar (login + TOTP) para que apliquen."
echo "    Comprobacion desde la API, con SU sesion:"
echo "      POST http://127.0.0.1:8001/vault_mgmt/v1/vault/access-check"
