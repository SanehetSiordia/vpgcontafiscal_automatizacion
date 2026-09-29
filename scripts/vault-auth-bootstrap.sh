#!/bin/sh
# Configura los metodos de autenticacion de Vault (idempotente):
#   1. userpass: usuario administrador inicial tomado de VAULT_ADMIN_USER_NAME
#      y VAULT_ADMIN_USER_PASS (la contrasena solo se fija al crearlo).
#   2. MFA de login TOTP obligatorio para todo inicio de sesion por userpass.
#   3. OIDC contra un proveedor externo, si VAULT_OIDC_DISCOVERY_URL,
#      VAULT_OIDC_CLIENT_ID y VAULT_OIDC_CLIENT_SECRET estan definidos.
#
# Requiere Vault inicializado y desbloqueado, y un token con permisos de
# administracion: sesion `vault login`, VAULT_TOKEN o VAULT_INITIAL_TOKEN.
#
# Uso: vpg-auth-bootstrap [--reset-totp]
#   --reset-totp  elimina y regenera el secreto TOTP del administrador.
set -eu

POLICY_DIR=/vault/config/policies
USERPASS_PATH=userpass
OIDC_PATH=oidc
MFA_METHOD_NAME=vpg-totp
MFA_ENFORCEMENT=vpg-userpass-totp
RESET_TOTP=false

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'AVISO: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

auth_enabled() { vault auth list 2>/dev/null | grep -q "^$1/ "; }

is_uuid() {
  case "$1" in
    *[!0-9a-f-]* | "") return 1 ;;
    ????????-????-????-????-????????????) return 0 ;;
    *) return 1 ;;
  esac
}

for arg in "$@"; do
  case "$arg" in
    --reset-totp) RESET_TOTP=true ;;
    -h | --help) sed -n '2,14p' "$0"; exit 0 ;;
    *) die "argumento desconocido: $arg" ;;
  esac
done

# --- Precondiciones --------------------------------------------------------
status=0
vault status >/dev/null 2>&1 || status=$?
case "$status" in
  0) ;;
  2) die "Vault no esta inicializado o esta sellado ('vault operator init' / 'vault operator unseal')." ;;
  *) die "Vault no responde en ${VAULT_ADDR}." ;;
esac

if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN
  export VAULT_TOKEN
fi
vault token lookup >/dev/null 2>&1 \
  || die "no hay un token valido: ejecuta 'vault login' o define VAULT_INITIAL_TOKEN en .env."

# userpass guarda los nombres en minusculas; el alias de la entidad debe coincidir.
ADMIN_USER=$(printf '%s' "${VAULT_ADMIN_USER_NAME:-}" | tr 'A-Z' 'a-z')
ADMIN_PASS=${VAULT_ADMIN_USER_PASS:-}
[ -n "$ADMIN_USER" ] || die "VAULT_ADMIN_USER_NAME no esta definido en .env."
[ -n "$ADMIN_PASS" ] || die "VAULT_ADMIN_USER_PASS no esta definido en .env."
case "$ADMIN_USER" in
  *[!a-z0-9._-]*) die "VAULT_ADMIN_USER_NAME solo admite letras, digitos, '.', '_' y '-'." ;;
esac
[ "${#ADMIN_PASS}" -ge 12 ] || warn "VAULT_ADMIN_USER_PASS tiene menos de 12 caracteres."

# --- Politicas -------------------------------------------------------------
log "Politicas vpg-admin y vpg-oidc-user"
vault policy write vpg-admin "${POLICY_DIR}/vpg-admin.hcl" >/dev/null
vault policy write vpg-oidc-user "${POLICY_DIR}/vpg-oidc-user.hcl" >/dev/null

# --- Userpass --------------------------------------------------------------
if ! auth_enabled "$USERPASS_PATH"; then
  log "Habilitando auth userpass en ${USERPASS_PATH}/"
  vault auth enable -path="$USERPASS_PATH" \
    -description="Administradores VPG (MFA TOTP obligatorio)" userpass >/dev/null
fi
USERPASS_ACCESSOR=$(vault read -field=accessor "sys/auth/${USERPASS_PATH}")

if vault read "auth/${USERPASS_PATH}/users/${ADMIN_USER}" >/dev/null 2>&1; then
  log "Usuario '${ADMIN_USER}' ya existe; se conserva su contrasena actual"
else
  log "Creando usuario administrador '${ADMIN_USER}'"
  printf '%s' "$ADMIN_PASS" | vault write "auth/${USERPASS_PATH}/users/${ADMIN_USER}" \
    password=- >/dev/null
fi
unset ADMIN_PASS
vault write "auth/${USERPASS_PATH}/users/${ADMIN_USER}" \
  token_policies=vpg-admin token_ttl=1h token_max_ttl=8h >/dev/null

# --- Entidad del administrador (el secreto TOTP se asocia a la entidad) -----
ENTITY_ID=$(vault write -field=id identity/lookup/entity \
  alias_name="$ADMIN_USER" alias_mount_accessor="$USERPASS_ACCESSOR" 2>/dev/null || true)
if ! is_uuid "$ENTITY_ID"; then
  log "Creando entidad y alias para '${ADMIN_USER}'"
  vault write "identity/entity/name/vpg-admin-${ADMIN_USER}" metadata=role=admin >/dev/null
  ENTITY_ID=$(vault read -field=id "identity/entity/name/vpg-admin-${ADMIN_USER}")
  vault write identity/entity-alias name="$ADMIN_USER" \
    canonical_id="$ENTITY_ID" mount_accessor="$USERPASS_ACCESSOR" >/dev/null
fi

# --- MFA TOTP --------------------------------------------------------------
MFA_METHOD_ID=""
for id in $(vault list identity/mfa/method/totp 2>/dev/null | tail -n +3); do
  # Vault recibe `method_name` al crear el metodo, pero lo devuelve como `name`.
  if [ "$(vault read -field=name "identity/mfa/method/totp/${id}" 2>/dev/null)" = "$MFA_METHOD_NAME" ]; then
    MFA_METHOD_ID=$id
    break
  fi
done
if [ -z "$MFA_METHOD_ID" ]; then
  log "Creando metodo MFA TOTP '${MFA_METHOD_NAME}'"
  # SHA1/6 digitos/30 s: compatible con Google/Microsoft Authenticator, Authy, etc.
  MFA_METHOD_ID=$(vault write -field=method_id identity/mfa/method/totp \
    method_name="$MFA_METHOD_NAME" issuer="VPG Vault" \
    period=30 key_size=20 algorithm=SHA1 digits=6 qr_size=200 \
    max_validation_attempts=5)
fi

if [ "$RESET_TOTP" = true ]; then
  log "Eliminando secreto TOTP previo de '${ADMIN_USER}'"
  vault write identity/mfa/method/totp/admin-destroy \
    method_id="$MFA_METHOD_ID" entity_id="$ENTITY_ID" >/dev/null
fi
TOTP_URL=$(vault write -field=url identity/mfa/method/totp/admin-generate \
  method_id="$MFA_METHOD_ID" entity_id="$ENTITY_ID" 2>/dev/null || true)

log "Exigiendo TOTP en todo login por ${USERPASS_PATH}/"
vault write "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" \
  mfa_method_ids="$MFA_METHOD_ID" auth_method_accessors="$USERPASS_ACCESSOR" >/dev/null

# --- OIDC ------------------------------------------------------------------
OIDC_DISCOVERY_URL=${VAULT_OIDC_DISCOVERY_URL:-}
OIDC_CLIENT_ID=${VAULT_OIDC_CLIENT_ID:-}
OIDC_CLIENT_SECRET=${VAULT_OIDC_CLIENT_SECRET:-}
UI_BASE="http://127.0.0.1:${VAULT_PORT_LOCAL:-8200},http://localhost:${VAULT_PORT_LOCAL:-8200}"

if [ -n "$OIDC_DISCOVERY_URL" ] && [ -n "$OIDC_CLIENT_ID" ] && [ -n "$OIDC_CLIENT_SECRET" ]; then
  if ! auth_enabled "$OIDC_PATH"; then
    log "Habilitando auth oidc en ${OIDC_PATH}/"
    vault auth enable -path="$OIDC_PATH" -description="SSO OIDC (${OIDC_DISCOVERY_URL})" oidc >/dev/null
  fi
  log "Configurando proveedor OIDC ${OIDC_DISCOVERY_URL}"
  printf '%s' "$OIDC_CLIENT_SECRET" | vault write "auth/${OIDC_PATH}/config" \
    oidc_discovery_url="$OIDC_DISCOVERY_URL" \
    oidc_client_id="$OIDC_CLIENT_ID" \
    oidc_client_secret=- \
    default_role=default >/dev/null
  REDIRECT_URIS=$(printf '%s' "$UI_BASE" | sed "s#\([^,]*\)#\1/ui/vault/auth/${OIDC_PATH}/oidc/callback#g")
  vault write "auth/${OIDC_PATH}/role/default" \
    role_type=oidc \
    user_claim="${VAULT_OIDC_USER_CLAIM:-email}" \
    oidc_scopes="${VAULT_OIDC_SCOPES:-profile,email}" \
    allowed_redirect_uris="$REDIRECT_URIS" \
    token_policies="${VAULT_OIDC_POLICIES:-vpg-oidc-user}" \
    token_ttl=1h token_max_ttl=8h >/dev/null
  OIDC_STATE="configurado (redirect URIs: ${REDIRECT_URIS})"
elif [ -n "${OIDC_DISCOVERY_URL}${OIDC_CLIENT_ID}${OIDC_CLIENT_SECRET}" ]; then
  warn "configuracion OIDC incompleta: se requieren VAULT_OIDC_DISCOVERY_URL, VAULT_OIDC_CLIENT_ID y VAULT_OIDC_CLIENT_SECRET."
  OIDC_STATE="omitido (configuracion incompleta)"
else
  OIDC_STATE="omitido (sin VAULT_OIDC_* en .env)"
fi
unset OIDC_CLIENT_SECRET

# --- Resumen ---------------------------------------------------------------
echo
log "Userpass: usuario '${ADMIN_USER}' con politica vpg-admin"
log "MFA:      TOTP '${MFA_METHOD_NAME}' (method_id ${MFA_METHOD_ID}) obligatorio en ${USERPASS_PATH}/"
log "OIDC:     ${OIDC_STATE}"
if [ -n "$TOTP_URL" ]; then
  echo
  echo "Registra este secreto TOTP en tu app autenticadora (se muestra UNA sola vez)."
  echo "Guardalo en tu gestor de contrasenas y limpia la pantalla con 'clear':"
  echo
  echo "  ${TOTP_URL}"
  echo
else
  log "El administrador ya tenia secreto TOTP; usa --reset-totp para regenerarlo."
fi
