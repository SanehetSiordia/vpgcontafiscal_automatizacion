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
set -Eeuo pipefail

# Ninguna orden puede abortar el script sin dejar rastro: con `set -e` a secas,
# un fallo imprevisto (p. ej. un `read` que devuelve !=0) cierra la terminal sin
# imprimir nada y parece que el teclado no responde.
trap 'rc=$?; printf "
ERROR INTERNO: la linea %s termino con codigo %s.
  Orden: %s
  Si ocurre al teclear el codigo, no se intento el login.
"       "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

VAULT_SECRET_PATH=secret/data/sat/usuarios
UPDATE_DB=true
DIAGNOSE_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) VAULT_SECRET_PATH=${2:?falta la ruta}; shift 2 ;;
    --no-update) UPDATE_DB=false; shift ;;
    # --diagnose: solo comprobaciones de lectura. NO pide codigo TOTP y, por
    # tanto, NO gasta ninguno de los 5 intentos de max_validation_attempts.
    --diagnose) DIAGNOSE_ONLY=true; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

MFA_METHOD_NAME_DEFAULT=vpg-totp

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

# -----------------------------------------------------------------------------
# Lectura oculta de un codigo numerico, mostrando un '#' por digito.
#
# `read -rs` no da ninguna senal visual: si el terminal no entrega las teclas,
# la pantalla se queda igual que si el script estuviera colgado. Con eco
# enmascarado se distingue "no se registra el teclado" de "el codigo es
# incorrecto".
#
#   leer_codigo_oculto <nombre_variable> <num_digitos> <prompt>
# -----------------------------------------------------------------------------
leer_codigo_oculto() {
  local __var=$1 __max=$2 __prompt=$3
  local __code='' __ch __rc

  printf '%s' "$__prompt"
  while true; do
    __rc=0
    # -n1: una tecla; -s: sin eco propio; -t: no se cuelga indefinidamente.
    IFS= read -rsn1 -t 180 __ch || __rc=$?
    if [[ $__rc -ne 0 ]]; then
      printf '\n'
      if [[ $__rc -gt 128 ]]; then
        echo "ERROR: pasaron 180s sin recibir el codigo completo. Cancelado." >&2
        echo "       No se intento el login: no se gasto ningun intento." >&2
      else
        echo "ERROR: no se pudo leer del teclado (fin de entrada)." >&2
        echo "       Ejecuta el script directamente en la terminal, sin tuberias" >&2
        echo "       ni redirecciones. Si usas Git Bash y no responde, prueba:" >&2
        echo "         winpty bash scripts/postgres/verify-vault-mfa.sh" >&2
      fi
      return 1
    fi

    case "$__ch" in
      '')                                      # Enter: termina aunque falten digitos
        break ;;
      $'\177' | $'\b')                         # Retroceso / Supr
        if [[ -n "$__code" ]]; then
          __code=${__code%?}
          printf '\b \b'
        fi ;;
      [0-9])
        if [[ ${#__code} -lt $__max ]]; then
          __code+=$__ch
          printf '#'
          [[ ${#__code} -eq $__max ]] && break  # autoenvio al completar
        fi ;;
      *)                                        # cualquier otra tecla se ignora
        : ;;
    esac
  done

  printf '  [%d/%d digitos]\n' "${#__code}" "$__max"
  printf -v "$__var" '%s' "$__code"
  return 0
}

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

# =============================================================================
# Diagnostico previo (solo lectura, no gasta intentos de TOTP)
# =============================================================================
MFA_METHOD_NAME=$(env_get VAULT_MFA_METHOD_NAME); MFA_METHOD_NAME=${MFA_METHOD_NAME:-$MFA_METHOD_NAME_DEFAULT}

# El method_id guardado en PostgreSQL por seed-initial-user.sh.
DB_METHOD_ID=$(psql_q -c \
  "SELECT c.totp_method_id
     FROM employees.vault_auth_config c
     JOIN employees.user_vault_identity vi ON vi.vault_auth_config_id = c.id
     JOIN employees.users u ON u.id = vi.user_id
    WHERE lower(u.username) = lower('${ADMIN_USER}');" | tr -d '\r' | tr -d '[:space:]')

# Configuracion real del metodo, leida de Vault.
METHOD_CFG=$(docker compose exec -T vault-service sh -c '
  for id in $(vault list identity/mfa/method/totp 2>/dev/null | tail -n +3); do
    if [ "$(vault read -field=name "identity/mfa/method/totp/${id}" 2>/dev/null)" = "'"$MFA_METHOD_NAME"'" ]; then
      printf "METHOD_ID=%s\n" "$id"
      for f in algorithm digits period skew issuer key_size max_validation_attempts; do
        printf "%s=%s\n" "$f" "$(vault read -field="$f" "identity/mfa/method/totp/${id}" 2>/dev/null)"
      done
      exit 0
    fi
  done
  echo "METHOD_ID="
' 2>/dev/null || true)

mcfg() { printf '%s\n' "$METHOD_CFG" | sed -n "s/^$1=//p" | head -n 1 | tr -d '\r'; }
VAULT_METHOD_ID=$(mcfg METHOD_ID)

# Relojes: un desfase mayor que period*skew invalida TODOS los codigos.
HOST_EPOCH=$(date -u +%s)
VAULT_EPOCH=$(docker compose exec -T vault-service date -u +%s 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
SKEW_SEG=$(( HOST_EPOCH - ${VAULT_EPOCH:-$HOST_EPOCH} ))
PERIOD_SEG=$(mcfg period | tr -d 's'); PERIOD_SEG=${PERIOD_SEG:-30}
SKEW_PASOS=$(mcfg skew);              SKEW_PASOS=${SKEW_PASOS:-1}
TOLERANCIA=$(( PERIOD_SEG * (SKEW_PASOS + 1) ))

echo
echo "==> Diagnostico (solo lectura, no gasta intentos de TOTP)"
echo "    usuario userpass .........: ${ADMIN_USER}"
echo "    metodo TOTP ..............: ${MFA_METHOD_NAME}"
echo "    method_id en Vault .......: ${VAULT_METHOD_ID:-NO ENCONTRADO}"
echo "    method_id en PostgreSQL ..: ${DB_METHOD_ID:-<sin registro>}"
if [[ -n "$VAULT_METHOD_ID" && -n "$DB_METHOD_ID" && "$VAULT_METHOD_ID" != "$DB_METHOD_ID" ]]; then
  echo "    >> AVISO: el method_id de Vault NO coincide con el registrado."
  echo "       El metodo TOTP se recreo despues de la vinculacion. Vuelve a"
  echo "       ejecutar: bash scripts/postgres/seed-initial-user.sh"
fi
echo "    algoritmo / digitos ......: $(mcfg algorithm) / $(mcfg digits)"
echo "    periodo / skew ...........: ${PERIOD_SEG}s / ${SKEW_PASOS} pasos (tolerancia +-${TOLERANCIA}s)"
echo "    issuer en la app .........: $(mcfg issuer)"
echo "    intentos maximos .........: $(mcfg max_validation_attempts) fallos consecutivos"
echo "    reloj host (UTC) .........: $(date -u -d "@${HOST_EPOCH}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u '+%Y-%m-%d %H:%M:%S')"
echo "    reloj contenedor (UTC) ...: $(docker compose exec -T vault-service date -u '+%Y-%m-%d %H:%M:%S' 2>/dev/null | tr -d '\r')"
if [[ ${SKEW_PASOS} -ge 0 ]] && [[ ${SKEW_SEG#-} -gt $TOLERANCIA ]]; then
  echo "    >> PROBLEMA: host y contenedor difieren ${SKEW_SEG#-}s (> ${TOLERANCIA}s)."
  echo "       Reinicia Docker Desktop o ejecuta en PowerShell como admin:"
  echo "       wsl --shutdown    (y vuelve a arrancar Docker Desktop)"
else
  echo "    desfase host/contenedor ..: ${SKEW_SEG#-}s (dentro de la tolerancia)"
fi

if [[ "$DIAGNOSE_ONLY" == true ]]; then
  echo
  echo "==> --diagnose: no se ha pedido ningun codigo TOTP ni se ha intentado el login."
  exit 0
fi

# --- codigo TOTP: SIEMPRE interactivo ----------------------------------------
if [[ ! -t 0 ]]; then
  echo "ERROR: este script necesita una terminal interactiva para pedir el codigo TOTP." >&2
  echo "       Ejecutalo directamente en Git Bash, no por tuberia ni en CI." >&2
  exit 1
fi

# Si la ventana actual esta a punto de expirar, espera: evita gastar un intento
# con un codigo que caduca mientras se teclea.
RESTAN=$(( PERIOD_SEG - (HOST_EPOCH % PERIOD_SEG) ))
echo
echo "==> Ventana TOTP actual: quedan ${RESTAN}s de ${PERIOD_SEG}s"
if [[ $RESTAN -lt 8 ]]; then
  echo "    Esperando ${RESTAN}s para que empiece una ventana nueva..."
  sleep "$RESTAN"
  echo "    Ventana nueva. Lee el codigo AHORA y escribelo."
fi

echo
echo "    Escribe los 6 digitos. Veras un '#' por cada uno, para confirmar que"
echo "    el teclado se esta registrando. Borrar: retroceso. Cancelar: Ctrl+C."
echo "    Al llegar al sexto digito se envia solo (no hace falta pulsar Enter)."
echo

leer_codigo_oculto TOTP_CODE 6 "Codigo TOTP para ${ADMIN_USER}: "
PROMPT_EPOCH=$(date -u +%s)
TECLEO_SEG=$(( PROMPT_EPOCH - HOST_EPOCH ))

if [[ ! "$TOTP_CODE" =~ ^[0-9]{6}$ ]]; then
  echo "ERROR: el codigo TOTP debe tener exactamente 6 digitos (sin espacios)." >&2
  echo "       Recibidos ${#TOTP_CODE} caracteres. No se ha intentado el login:" >&2
  echo "       no se ha gastado ningun intento." >&2
  exit 1
fi

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
  if [ -n "$TOKEN_SIN_MFA" ]; then
    echo 'MFA_LOGIN=token_emitido_sin_mfa'
  else
    echo 'MFA_LOGIN=sin_mfa_requirement'
  fi
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
  # Clasificacion del fallo: cada caso tiene una causa y un remedio distintos.
  case "$validated" in
    *"maximum TOTP validation attempts"*|*"exceeded the allowed attempts"*|*"try again in"*)
      echo 'MFA_LOGIN=totp_bloqueado' ;;
    *"failed to validate TOTP passcode"*)
      echo 'MFA_LOGIN=totp_incorrecto' ;;
    *"no TOTP secret"*|*"no entry for entity"*|*"secret not found"*)
      echo 'MFA_LOGIN=sin_semilla_totp' ;;
    *"MFA request ID"*|*"not found"*|*"expired"*)
      echo 'MFA_LOGIN=peticion_mfa_caducada' ;;
    *"permission denied"*|*"Code: 403. Errors:"*)
      echo 'MFA_LOGIN=totp_incorrecto' ;;
    *)
      echo 'MFA_LOGIN=error_desconocido' ;;
  esac
  # Error COMPLETO de Vault, en una linea por mensaje y sin recortar: es la
  # unica forma de ver por que lo rechazo.
  printf '%s' "$validated" \
    | grep -ivE '^[[:space:]]*$|^(Error writing data|URL:|Code:)' \
    | sed 's/^[[:space:]*]*//' \
    | while IFS= read -r l; do [ -n "$l" ] && printf 'MFA_ERROR_LINE=%s\n' "$l"; done
  printf 'MFA_ERROR_CODE=%s\n' \
    "$(printf '%s' "$validated" | sed -n 's/.*\(Code: [0-9]*\).*/\1/p' | head -n 1)"
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
# OJO: en esta version `vault token lookup` NO admite -field ("flag provided but
# not defined: -field"). Hay que leer el endpoint con `vault read`, que si lo
# admite.
lookup_self() { vault read -field="$1" auth/token/lookup-self 2>&1; }

lk_rc=0
ENTITY=$(lookup_self entity_id) || lk_rc=$?
if [ "$lk_rc" -ne 0 ] || [ -z "$ENTITY" ]; then
  # Sin entity_id no hay con que comparar. Decirlo explicitamente, en vez de
  # mandar un valor vacio que luego parece una discrepancia de identidad.
  echo 'ENTITY_LOOKUP=fallido'
  printf 'ENTITY_LOOKUP_ERROR=%s\n' "$(printf '%s' "$ENTITY" | tr '\n' ' ' | cut -c1-200)"
else
  echo 'ENTITY_LOOKUP=ok'
  printf 'ENTITY_ID=%s\n' "$ENTITY"
fi
printf 'POLICIES=%s\n'     "$(lookup_self policies | tr '\n' ' ')"
printf 'DISPLAY_NAME=%s\n' "$(lookup_self display_name)"
printf 'TTL=%s\n'          "$(lookup_self ttl)"

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
echo "==> Validando con Vault (userpass + TOTP)..."
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
  echo "    Segundos tecleando .......: ${TECLEO_SEG}s (tolerancia +-${TOLERANCIA}s)"
  echo
  echo "=========================================================================="
  case "$MFA_LOGIN" in
    totp_incorrecto)
      echo " ESTADO: TOTP INCORRECTO -- Vault rechazo el codigo de 6 digitos."
      echo "=========================================================================="
      echo
      echo " La contrasena SI era correcta (Vault llego a pedir el segundo factor)."
      echo " Lo que fallo es el codigo. Causas por orden de probabilidad:"
      echo
      echo " 1. ENTRADA OBSOLETA EN LA APP. Si el secreto se regenero alguna vez"
      echo "    (vpg-auth-bootstrap --reset-totp) o el volumen de Vault se recreo,"
      echo "    las entradas antiguas '$(mcfg issuer)' dan codigos invalidos."
      echo "    Solo vale la ULTIMA. Borra las demas de la app."
      echo
      echo " 2. HORA DEL TELEFONO. Activa la hora automatica de red."
      echo "    Host y contenedor estan a ${SKEW_SEG#-}s, asi que el desfase, si"
      echo "    existe, esta en el telefono."
      if [[ $TECLEO_SEG -gt $TOLERANCIA ]]; then
      echo
      echo " 3. TARDASTE ${TECLEO_SEG}s EN TECLEAR, mas que la tolerancia de"
      echo "    ${TOLERANCIA}s. El codigo caduco mientras lo escribias."
      echo "    Vuelve a intentarlo con el codigo recien generado."
      else
      echo
      echo " 3. El tiempo de tecleo (${TECLEO_SEG}s) estaba dentro de la tolerancia,"
      echo "    asi que el codigo no caduco por lentitud."
      fi
      echo
      echo " 4. ENTRADA MAL REGISTRADA. En Google Authenticator la clave se teclea"
      echo "    en '+ -> Ingresar una clave de configuracion', tipo 'Basada en"
      echo "    tiempo', sin espacios. Solo letras A-Z y digitos 2-7: la 'O' es"
      echo "    letra, nunca cero; la 'I' es letra, nunca uno."
      echo
      echo " SOLUCION DEFINITIVA si nada de lo anterior encaja: regenerar la"
      echo " semilla. Es una accion MANUAL y destructiva (invalida la entrada"
      echo " actual de la app); este script nunca la ejecuta por su cuenta:"
      echo
      echo "   docker compose exec vault-service vpg-auth-bootstrap --reset-totp"
      echo
      echo " Despues BORRA las entradas '$(mcfg issuer)' viejas de la app, registra"
      echo " el nuevo otpauth:// que imprime el script, limpia la pantalla (clear)"
      echo " y vuelve a ejecutar esta verificacion."
      ;;
    totp_bloqueado)
      echo " ESTADO: TOTP BLOQUEADO -- demasiados intentos fallidos seguidos."
      echo "=========================================================================="
      echo
      echo " Se agotaron los $(mcfg max_validation_attempts) intentos consecutivos"
      echo " (max_validation_attempts) del metodo '${MFA_METHOD_NAME}'."
      echo " Vault bloquea la validacion de esta entidad durante un tiempo."
      echo
      echo " QUE HACER: espera lo que indique el mensaje de Vault de abajo y"
      echo " vuelve a intentarlo UNA sola vez con un codigo recien generado."
      echo " El contador se reinicia tras una validacion correcta."
      echo
      echo " Mientras esperas, usa --diagnose (no gasta intentos):"
      echo "   bash scripts/postgres/verify-vault-mfa.sh --diagnose"
      ;;
    sin_semilla_totp)
      echo " ESTADO: SIN SEMILLA TOTP -- la entidad no tiene secreto generado."
      echo "=========================================================================="
      echo
      echo " La entidad ${EXPECTED_ENTITY} no tiene semilla TOTP asociada, asi que"
      echo " ningun codigo puede ser valido. Generala (accion MANUAL):"
      echo
      echo "   docker compose exec vault-service vpg-auth-bootstrap"
      echo
      echo " y registra el otpauth:// que imprime (se muestra una sola vez)."
      ;;
    peticion_mfa_caducada)
      echo " ESTADO: PETICION MFA CADUCADA -- el mfa_request_id ya no es valido."
      echo "=========================================================================="
      echo
      echo " Pasaron demasiados segundos entre el login y la validacion."
      echo " Vuelve a ejecutar el script y teclea el codigo sin pausas."
      ;;
    credenciales_invalidas)
      echo " ESTADO: CONTRASENA INCORRECTA -- no se llego a pedir el TOTP."
      echo "=========================================================================="
      echo
      echo " Vault rechazo el usuario o la contrasena, antes del segundo factor."
      echo " El TOTP NO es el problema y NO se gasto ningun intento de TOTP."
      echo
      echo " Revisa VAULT_ADMIN_USER_PASS en .env: tiene que ser la contrasena"
      echo " ACTUAL de '${ADMIN_USER}' en auth/userpass. Si la cambiaste despues"
      echo " del bootstrap, .env quedo desactualizado (el bootstrap no sobrescribe"
      echo " la contrasena de un usuario que ya existe)."
      echo
      echo " Para fijar una contrasena nueva (se lee oculta, por stdin):"
      echo "   docker compose exec -T vault-service \\"
      echo "     vault write auth/userpass/users/${ADMIN_USER} password=-"
      ;;
    token_emitido_sin_mfa)
      echo " ESTADO: FALLO DE SEGURIDAD -- Vault emitio un token SIN pedir MFA."
      echo "=========================================================================="
      echo
      echo " El enforcement '$(env_get VAULT_MFA_ENFORCEMENT)' no esta cubriendo"
      echo " el montaje userpass. Revisalo y vuelve a ejecutar el bootstrap:"
      echo "   docker compose exec vault-service vault read \\"
      echo "     identity/mfa/login-enforcement/$(env_get VAULT_MFA_ENFORCEMENT)"
      ;;
    *)
      echo " ESTADO: ERROR NO CLASIFICADO al validar el TOTP."
      echo "=========================================================================="
      echo
      echo " Revisa el mensaje literal de Vault de abajo."
      ;;
  esac

  VAULT_CODE=$(kv MFA_ERROR_CODE)
  echo
  echo "--------------------------------------------------------------------------"
  echo " Respuesta literal de Vault${VAULT_CODE:+ (${VAULT_CODE})}:"
  if printf '%s\n' "$RESULT" | grep -q '^MFA_ERROR_LINE='; then
    printf '%s\n' "$RESULT" | sed -n 's/^MFA_ERROR_LINE=/   /p'
  else
    printf '%s\n' "$RESULT" | grep -vE '^(MFA_LOGIN|MFA_ENFORCED|MFA_METHOD_ID|MFA_PASSWORD_ONLY_TOKEN|ENTITY_ID|POLICIES|DISPLAY_NAME|TTL|SECRET_|CAPABILITIES|TOKEN_REVOKED)=' \
      | sed 's/^/   /'
  fi
  echo "--------------------------------------------------------------------------"
  echo
  echo " El vinculo en PostgreSQL NO se ha modificado: totp_status sigue como"
  echo " estaba. Solo un login MFA correcto con entity_id coincidente lo cambia."
  echo "=========================================================================="
  [[ "${RC:-1}" -ne 0 ]] && exit "$RC"
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
if [[ "$(kv ENTITY_LOOKUP)" != "ok" || -z "$GOT_ENTITY" ]]; then
  echo "ERROR: el login userpass + TOTP fue CORRECTO, pero no se pudo leer el" >&2
  echo "       entity_id de la sesion. Sin el no hay con que comparar, asi que" >&2
  echo "       no se confirma el enrolamiento." >&2
  echo "       Detalle de Vault: $(kv ENTITY_LOOKUP_ERROR)" >&2
  echo "       Comprueba a mano:" >&2
  echo "         docker compose exec vault-service \\" >&2
  echo "           vault read -field=entity_id auth/token/lookup-self" >&2
  exit 1
fi
if [[ "$GOT_ENTITY" != "$EXPECTED_ENTITY" ]]; then
  echo "ERROR: el entity_id del login (${GOT_ENTITY}) NO coincide con el registrado" >&2
  echo "       (${EXPECTED_ENTITY}). No se confirma el enrolamiento." >&2
  echo "       Significa que la entidad de Vault se recreo despues de la" >&2
  echo "       vinculacion. Revisa employees.user_vault_identity antes de tocar" >&2
  echo "       nada: seed-initial-user.sh no sobrescribe un vinculo divergente." >&2
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
