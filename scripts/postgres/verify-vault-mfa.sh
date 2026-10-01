#!/usr/bin/env bash
# *** SCRIPT INTERACTIVO: pide el codigo TOTP por teclado. ***
#
# Comprueba de extremo a extremo que el empleado vinculado puede iniciar sesion
# en Vault con userpass + TOTP, y solo entonces marca el enrolamiento como
# confirmado en PostgreSQL.
#
# Uso (host, Git Bash, en una terminal real):
#   bash scripts/postgres/verify-vault-mfa.sh [--path secret/data/sat/usuarios] [--no-update]
#
# Flujo:
#   1. POST auth/userpass/login/<usuario> con la contrasena identificada por
#      VAULT_ADMIN_USER_PASS en .env. Vault responde SIN token y con un
#      mfa_request_id: el MFA no se puede omitir.
#   2. Pide el codigo TOTP por teclado (entrada oculta) y lo valida contra
#      sys/mfa/validate.
#   3. Con el token resultante consulta entity_id y politicas, y comprueba el
#      acceso a una ruta autorizada.
#   4. Si el entity_id COINCIDE con el registrado en user_vault_identity,
#      actualiza last_mfa_login_at y pasa totp_status a 'confirmed'.
#   5. Revoca el token recien emitido.
#
# Nunca se muestran ni se guardan: la contrasena, el codigo TOTP, la semilla,
# el QR, la URL otpauth ni el token. Tampoco los valores del secreto leido.
set -euo pipefail

VAULT_SECRET_PATH=secret/data/sat/usuarios
UPDATE_DB=true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) VAULT_SECRET_PATH=${2:?falta la ruta}; shift 2 ;;
    --no-update) UPDATE_DB=false; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta ${ENV_FILE}." >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

ADMIN_USER=$(env_get VAULT_ADMIN_USER_NAME | tr 'A-Z' 'a-z')
PG_DB=$(env_get POSTGRES_DB);     PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER); PG_USER=${PG_USER:-vpg_admin}

[[ -n "$ADMIN_USER" ]] || { echo "ERROR: VAULT_ADMIN_USER_NAME no esta definido en .env." >&2; exit 1; }

# La contrasena se identifica por VAULT_ADMIN_USER_PASS en .env: no se imprime,
# no se pasa como argumento visible y no se escribe en SQL ni en PostgreSQL.
ADMIN_PASS=$(env_get VAULT_ADMIN_USER_PASS)
[[ -n "$ADMIN_PASS" ]] || { echo "ERROR: VAULT_ADMIN_USER_PASS no esta definido en .env." >&2; exit 1; }

psql_q() { docker compose exec -T postgres-service \
             psql --no-psqlrc -qtAX --username "$PG_USER" --dbname "$PG_DB" "$@"; }

# --- entity_id esperado, segun PostgreSQL ------------------------------------
EXPECTED_ENTITY=$(psql_q -c \
  "SELECT vi.vault_entity_id
     FROM employees.user_vault_identity vi
     JOIN employees.users u ON u.id = vi.user_id
    WHERE lower(u.username) = lower('${ADMIN_USER}');" | tr -d '\r' | tr -d '[:space:]')

if [[ -z "$EXPECTED_ENTITY" ]]; then
  echo "ERROR: '${ADMIN_USER}' no tiene vinculo en employees.user_vault_identity." >&2
  echo "       Ejecuta antes: bash scripts/postgres/seed-initial-user.sh" >&2
  exit 1
fi
echo "==> entity_id registrado en PostgreSQL: ${EXPECTED_ENTITY}"

# --- codigo TOTP: SIEMPRE interactivo ----------------------------------------
if [[ ! -t 0 ]]; then
  echo "ERROR: este script necesita una terminal interactiva para pedir el codigo TOTP." >&2
  echo "       Ejecutalo directamente en Git Bash, no por tuberia ni en CI." >&2
  exit 1
fi
printf 'Codigo TOTP de 6 digitos para %s (entrada oculta): ' "$ADMIN_USER"
read -rs TOTP_CODE
echo
[[ "$TOTP_CODE" =~ ^[0-9]{6}$ ]] || { echo "ERROR: el codigo TOTP debe tener 6 digitos." >&2; exit 1; }

# =============================================================================
# Login + validacion MFA dentro del contenedor de Vault.
# El cuerpo (sin secretos) se pasa como argumento de `sh -c`; la contrasena y el
# codigo TOTP llegan por stdin, en dos lineas.
# =============================================================================
REMOTE_SCRIPT=$(cat <<'REMOTE_EOF'
set -eu
ADMIN_USER=$1
SECRET_PATH=$2

IFS= read -r PASSWORD
IFS= read -r CODE

# Login limpio: no se hereda el token administrativo del contenedor.
unset VAULT_TOKEN

json_field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -n 1; }

# --- paso 1: usuario + contrasena. Vault NO debe entregar token todavia ---
if ! login=$(printf '%s' "$PASSWORD" | vault write -format=json \
               "auth/userpass/login/${ADMIN_USER}" password=- 2>/dev/null); then
  echo 'MFA_LOGIN=credenciales_invalidas'
  exit 1
fi
PASSWORD=''; unset PASSWORD

REQ_ID=$(printf '%s' "$login" | json_field mfa_request_id)
TOKEN_SIN_MFA=$(printf '%s' "$login" | json_field client_token)
if [ -z "$REQ_ID" ]; then
  # Sin mfa_request_id, Vault habria entregado un token sin segundo factor.
  echo 'MFA_ENFORCED=no'
  [ -z "$TOKEN_SIN_MFA" ] || echo 'MFA_LOGIN=token_emitido_sin_mfa'
  exit 1
fi
echo 'MFA_ENFORCED=si'
echo "MFA_PASSWORD_ONLY_TOKEN=$([ -z "$TOKEN_SIN_MFA" ] && echo ninguno || echo EMITIDO)"

# El method_id viene en mfa_constraints -> any[] -> id.
METHOD_ID=$(printf '%s' "$login" | sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' | head -n 1)
printf 'MFA_METHOD_ID=%s\n' "$METHOD_ID"

# --- paso 2: validacion del codigo TOTP ---
payload=$(printf '{"mfa_request_id":"%s","mfa_payload":{"%s":["%s"]}}' \
            "$REQ_ID" "$METHOD_ID" "$CODE")
CODE=''; unset CODE

if ! validated=$(printf '%s' "$payload" | vault write -format=json sys/mfa/validate - 2>&1); then
  echo 'MFA_LOGIN=totp_rechazado'
  printf 'MFA_ERROR=%s\n' "$(printf '%s' "$validated" | grep -iE 'code:|\*' | tr '\n' ' ' | cut -c1-200)"
  exit 1
fi
payload=''; unset payload

TOKEN=$(printf '%s' "$validated" | json_field client_token)
[ -n "$TOKEN" ] || { echo 'MFA_LOGIN=sin_token'; exit 1; }
validated=''; unset validated

echo 'MFA_LOGIN=ok'
VAULT_TOKEN=$TOKEN
export VAULT_TOKEN
TOKEN=''; unset TOKEN

# --- datos NO secretos de la sesion obtenida (jamas el token) ---
printf 'ENTITY_ID=%s\n'    "$(vault token lookup -field=entity_id    2>/dev/null || true)"
printf 'POLICIES=%s\n'     "$(vault token lookup -field=policies     2>/dev/null | tr '\n' ' ' || true)"
printf 'DISPLAY_NAME=%s\n' "$(vault token lookup -field=display_name 2>/dev/null || true)"
printf 'TTL=%s\n'          "$(vault token lookup -field=ttl          2>/dev/null || true)"

# --- ruta autorizada: SOLO el resultado de autorizacion, nunca los valores ---
printf 'SECRET_PATH=%s\n' "$SECRET_PATH"
printf 'CAPABILITIES=%s\n' \
  "$(vault write -field=capabilities sys/capabilities-self path="$SECRET_PATH" 2>/dev/null | tr '\n' ' ' || echo no_consultable)"

read_rc=0
read_err=$(vault read "$SECRET_PATH" 2>&1 >/dev/null) || read_rc=$?
if [ "$read_rc" -eq 0 ]; then
  echo 'SECRET_READ=autorizada'
else
  case "$read_err" in
    *"permission denied"*|*"Code: 403"*) echo 'SECRET_READ=denegada_por_politica' ;;
    *"No value found"*|*"Code: 404"*)    echo 'SECRET_READ=autorizada_pero_sin_datos' ;;
    *) printf 'SECRET_READ=error\nSECRET_READ_DETAIL=%s\n' \
         "$(printf '%s' "$read_err" | tr '\n' ' ' | cut -c1-200)" ;;
  esac
fi

# --- el token de prueba no sobrevive al script ---
if vault token revoke -self >/dev/null 2>&1; then echo 'TOKEN_REVOKED=si'; else echo 'TOKEN_REVOKED=no'; fi
REMOTE_EOF
)

# El cuerpo del script se pasa como argumento de `sh -c`, no como archivo
# temporal: asi stdin queda libre para la contrasena y el codigo, y Git Bash no
# convierte ninguna ruta absoluta tipo /tmp/... a una ruta de Windows.
set +e
RESULT=$(printf '%s\n%s\n' "$ADMIN_PASS" "$TOTP_CODE" \
  | docker compose exec -T vault-service \
      sh -c "$REMOTE_SCRIPT" vpg-verify-mfa "$ADMIN_USER" "$VAULT_SECRET_PATH" 2>&1)
RC=$?
set -e
ADMIN_PASS=''; TOTP_CODE=''
unset ADMIN_PASS TOTP_CODE

kv() { printf '%s\n' "$RESULT" | sed -n "s/^$1=//p" | head -n 1 | tr -d '\r'; }

MFA_ENFORCED=$(kv MFA_ENFORCED)
MFA_LOGIN=$(kv MFA_LOGIN)
GOT_ENTITY=$(kv ENTITY_ID)

echo
echo "==> Resultado del login userpass + TOTP (sin token, sin contrasena, sin semilla)"
echo "    MFA exigido por Vault ....: ${MFA_ENFORCED:-?}"
echo "    Token con solo contrasena : $(kv MFA_PASSWORD_ONLY_TOKEN)"
echo "    Login MFA ................: ${MFA_LOGIN:-fallido}"

if [[ "$MFA_LOGIN" != "ok" ]]; then
  echo "    Detalle ..................: $(kv MFA_ERROR)"
  echo
  echo "ERROR: el login userpass + TOTP no se completo (codigo de salida ${RC})." >&2
  printf '%s\n' "$RESULT" | grep -vE '^(MFA_|ENTITY_|POLICIES|DISPLAY_|TTL|SECRET_|CAPAB|TOKEN_)' >&2 || true
  exit 1
fi

echo "    entity_id devuelto .......: ${GOT_ENTITY}"
echo "    politicas del token ......: $(kv POLICIES)"
echo "    display_name .............: $(kv DISPLAY_NAME)"
echo "    TTL ......................: $(kv TTL)"
echo "    token revocado al final ..: $(kv TOKEN_REVOKED)"
echo
echo "==> Consulta de una ruta Vault autorizada (solo el resultado, sin valores)"
echo "    ruta .....................: $(kv SECRET_PATH)"
echo "    capacidades de la sesion .: $(kv CAPABILITIES)"
echo "    lectura ..................: $(kv SECRET_READ) $(kv SECRET_READ_DETAIL)"

# --- confirmacion del enrolamiento: solo si el entity_id coincide ------------
echo
if [[ "$GOT_ENTITY" != "$EXPECTED_ENTITY" ]]; then
  echo "ERROR: el entity_id del login (${GOT_ENTITY}) NO coincide con el registrado" >&2
  echo "       (${EXPECTED_ENTITY}). No se confirma el enrolamiento." >&2
  exit 1
fi
echo "==> entity_id COINCIDE con el registrado en PostgreSQL."

if [[ "$UPDATE_DB" != true ]]; then
  echo "==> --no-update: no se modifica user_vault_identity."
  exit 0
fi

docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$PG_USER" --dbname "$PG_DB" <<SQL
BEGIN;
-- El filtro por vault_entity_id es lo que hace que la confirmacion dependa de
-- un login MFA real cuya entidad coincide. 'disabled' no se reactiva solo.
UPDATE employees.user_vault_identity vi
   SET last_mfa_login_at = now(),
       totp_confirmed_at = COALESCE(vi.totp_confirmed_at, now()),
       totp_status       = CASE WHEN vi.totp_status IN ('pending', 'reset_required')
                                THEN 'confirmed' ELSE vi.totp_status END
  FROM employees.users u
 WHERE u.id = vi.user_id
   AND lower(u.username)  = lower('${ADMIN_USER}')
   AND vi.vault_entity_id = '${GOT_ENTITY}'::uuid;
COMMIT;
SQL

echo
echo "==> Estado del vinculo tras el login (sin datos secretos):"
docker compose exec -T postgres-service \
  psql --no-psqlrc -x --username "$PG_USER" --dbname "$PG_DB" -c "
SELECT u.username, vi.vault_entity_id, vi.totp_status,
       vi.totp_generated_at, vi.totp_confirmed_at, vi.last_mfa_login_at
  FROM employees.user_vault_identity vi
  JOIN employees.users u ON u.id = vi.user_id
 WHERE lower(u.username) = lower('${ADMIN_USER}');"

echo
echo "RECORDATORIO: totp_status='confirmed' es solo un registro historico."
echo "Vault sigue exigiendo contrasena + TOTP en cada login; esta fila no"
echo "permite omitir el MFA."
