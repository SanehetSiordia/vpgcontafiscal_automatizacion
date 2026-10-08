#!/usr/bin/env bash
# *** SCRIPT INTERACTIVO: pide un codigo TOTP por teclado. ***
#
# Recorrido de extremo a extremo del aprovisionamiento de un consumidor de
# maquina (etapa 4.6), con datos FICTICIOS y contra el sistema real.
#
# Uso (host, Git Bash, en una terminal real):
#   bash scripts/vault_mgmt/provisioning-walkthrough.sh [--keep] [--receiver local]
#     --keep              no revoca el consumidor de prueba al final
#     --receiver <nombre>  receptor configurado a usar (por omision: local)
#
# Demuestra, en este orden:
#   1. Salud de las dos APIs y la capacidad de aprovisionamiento en readiness.
#   2. El canal interno exige la credencial del receptor: sin ella, 401.
#   3. Sesion en user-mgmt (login + TOTP). El alta exige rol admin.
#   4. Alta del consumidor: 202 con tres campos, y 'pending' NO es entregado.
#   5. Idempotencia: misma clave y parametros devuelve los mismos IDs; misma
#      clave con otros parametros, 409.
#   6. El worker deja la identidad lista y la operacion en waiting_receiver,
#      SIN emitir ninguna credencial (no hay receptor que la recoja todavia).
#   7. El receptor reclama: recibe role_id y una envoltura de un solo uso.
#   8. Desenvuelve en Vault, entra con AppRole y confirma. Solo entonces la
#      operacion llega a completed y el consumidor a ready.
#   9. Un segundo claim no emite otra credencial encima.
#  10. Rotacion after_ack: la anterior sigue viva hasta que se confirma la nueva.
#  11. Revocacion, y el claim siguiente rechazado.
#
# CUANTOS CODIGOS TOTP HACEN FALTA: uno. Esta subetapa no pide reautenticacion
# por accion para las operaciones de consumidores; basta sesion valida y rol
# admin. Las reglas de MFA de 'destroy' y 'purge' de registros no cambian.
#
# El usuario administrador y su contrasena salen de VAULT_ADMIN_USER_NAME y
# VAULT_ADMIN_USER_PASS del .env, igual que en los demas recorridos: no hay
# ningun usuario escrito en el codigo. La contrasena viaja por stdin.
#
# Lo que NO se imprime nunca: la credencial del receptor, el secret_id
# desenvuelto, el wrapping token completo y el token de Vault. De esos se
# muestran sus accessors y sus TTL, que es lo que sirve para auditar.
#
# UNA REGLA DE ESTE SCRIPT, APRENDIDA A GOLPES: las cabeceras que llevan una
# credencial o una clave de idempotencia son de UN SOLO USO. api() las consume,
# y cada llamada que necesite una la pone justo antes. Mantenerlas puestas entre
# peticiones dio dos fallos reales:
#
#   * La clave del alta se la quedaba la revocacion de la limpieza, y el
#     reintento respondia 409 'idempotency_key_reused'.
#   * La credencial del receptor sobrevivia a 'R="" ... api' (bash restaura la
#     asignacion de prefijo al volver de una funcion) y acababa viajando a Vault
#     en el login de AppRole, que no tiene nada que ver con ella.
#
# El Bearer humano (A) si persiste: es la sesion y la usan casi todas las
# llamadas.
#
# Esto NO es el crawler: es su contrato. Que el recorrido pase demuestra que el
# aprovisionamiento funciona, no que exista un crawler.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

KEEP=false
RECEPTOR=local
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=true ;;
    --receiver) shift; RECEPTOR=${1:-}; [[ -n "$RECEPTOR" ]] || {
      echo "ERROR: --receiver necesita un nombre." >&2; exit 1; } ;;
    -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $1" >&2; exit 1 ;;
  esac
  shift
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

UM_BIND=$(env_get USER_MGMT_HOST_BIND);     UM_BIND=${UM_BIND:-127.0.0.1}
UM_PORT=$(env_get USER_MGMT_PORT_LOCAL);    UM_PORT=${UM_PORT:-8000}
UM_PREFIX=$(env_get USER_MGMT_API_PREFIX);  UM_PREFIX=${UM_PREFIX:-/user_mgmt/v1}
VM_BIND=$(env_get VAULT_MGMT_HOST_BIND);    VM_BIND=${VM_BIND:-127.0.0.1}
VM_PORT=$(env_get VAULT_MGMT_PORT_LOCAL);   VM_PORT=${VM_PORT:-8001}
VM_PREFIX=$(env_get VAULT_MGMT_API_PREFIX); VM_PREFIX=${VM_PREFIX:-/vault_mgmt/v1}
VAULT_BIND=$(env_get VAULT_HOST_BIND);      VAULT_BIND=${VAULT_BIND:-127.0.0.1}
VAULT_PORT=$(env_get VAULT_PORT_LOCAL);     VAULT_PORT=${VAULT_PORT:-8200}

UM_BASE="http://${UM_BIND}:${UM_PORT}"
VM_BASE="http://${VM_BIND}:${VM_PORT}"
UM="${UM_BASE}${UM_PREFIX}"
VM="${VM_BASE}${VM_PREFIX}"
VAULT_BASE="http://${VAULT_BIND}:${VAULT_PORT}"
INTERNO="${VM_BASE}/internal/v1/crawler/provisioning"
ADMIN_USER=$(env_get VAULT_ADMIN_USER_NAME | tr 'A-Z' 'a-z')

SUFIJO=$(date +%H%M%S)
CONSUMIDOR="crawler-demo-${SUFIJO}"

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
paso()   { printf '  %-58s ' "$*"; }
ok()     { printf 'HTTP %s  %s\n' "$1" "${2:-}"; }
nota()   { printf '    %s\n' "$*"; }

jget() { python -c "
import json,sys
crudo = sys.stdin.read()
if not crudo.strip():
    print(''); sys.exit(0)
try:
    d = json.loads(crudo)
except json.JSONDecodeError:
    print(''); sys.exit(0)
for k in sys.argv[1].split('.'):
    if d is None: break
    d = d[int(k)] if k.isdigit() and isinstance(d, list) else (
        d.get(k) if isinstance(d, dict) else None)
print(d if d is not None else '')" "$1"; }

# api <METODO> <URL> [CUERPO]
#
# Fija ESTADO y RESP como variables GLOBALES. Se llama SIN sustitucion de
# comandos a proposito: en un subshell, el ESTADO que fijara dentro no llegaria
# aqui y las comprobaciones leerian el de la llamada anterior.
RESP=""
ESTADO=""
api() {
  local metodo=$1 url=$2 cuerpo=${3-}
  local -a opciones=(-sS -X "$metodo" "$url" -H 'Content-Type: application/json')
  # El Bearer humano SI persiste: es la sesion, y la usan casi todas las
  # llamadas a las dos APIs. Se pone una vez tras el login.
  [[ -n "${A:-}" ]] && opciones+=(-H "$A")

  # Las tres cabeceras siguientes son de UN SOLO USO: se consumen en la
  # peticion que las lleva. Cada una por un motivo concreto, y los tres
  # ocurrieron de verdad en este script:
  #
  #   R    credencial del receptor. Si persistiera, acabaria enviandose a Vault
  #        en el login de AppRole, que no tiene nada que ver con ella. Pasaba.
  #   IDEM clave de idempotencia. Pertenece a una peticion, no a la sesion: al
  #        quedarse puesta, la revocacion de la limpieza se quedo con la clave
  #        del alta y el reintento respondia 409.
  #   VT   token de Vault (envoltura o maquina). Nunca debe viajar a otra ruta
  #        que la que lo necesita.
  if [[ -n "${R:-}" ]]; then
    opciones+=(-H "$R"); R=""
  fi
  if [[ -n "${IDEM:-}" ]]; then
    opciones+=(-H "Idempotency-Key: $IDEM"); IDEM=""
  fi
  if [[ -n "${VT:-}" ]]; then
    opciones+=(-H "X-Vault-Token: $VT"); VT=""
  fi
  [[ -n "$cuerpo" ]] && opciones+=(--data-binary "$cuerpo")

  local respuesta
  respuesta=$(curl -w $'\n%{http_code}' "${opciones[@]}" 2>&1) || true
  ESTADO=${respuesta##*$'\n'}
  RESP=${respuesta%$'\n'*}
  [[ "$ESTADO" =~ ^[0-9]{3}$ ]] || { RESP=$respuesta; ESTADO="000"; }
}

exigir() {
  local esperado=$1 descripcion=$2
  if [[ "$ESTADO" != "$esperado" ]]; then
    printf 'FALLO\n'
    printf '\n  Se esperaba HTTP %s en: %s\n' "$esperado" "$descripcion"
    printf '  Se recibio HTTP %s con este cuerpo:\n\n' "${ESTADO:-sin respuesta}"
    printf '%s\n' "$RESP" | python -m json.tool 2>/dev/null || printf '%s\n' "$RESP"
    printf '\n'
    exit 1
  fi
}

campo() { printf '%s' "$RESP" | jget "$1"; }
resumen() { local v=$1; [[ -z "$v" ]] && { printf '(vacio)'; return; }
  printf '%s...(+%s caracteres)' "${v:0:8}" "$(( ${#v} - 8 ))"; }

leer_totp() {
  local motivo=$1
  if [[ ! -t 0 ]]; then
    echo "ERROR: hace falta una terminal interactiva para el codigo TOTP." >&2
    exit 1
  fi
  echo
  echo "  Escribe los 6 digitos del autenticador. Veras un '#' por cada uno."
  printf '  Codigo TOTP de %s (%s): ' "$ADMIN_USER" "$motivo"
  CODIGO=''
  local rc ch
  while true; do
    rc=0; IFS= read -rsn1 -t 180 ch || rc=$?
    [[ $rc -ne 0 ]] && { echo; echo "ERROR: sin codigo TOTP." >&2; exit 1; }
    case "$ch" in
      '') break ;;
      $'\177'|$'\b') [[ -n "$CODIGO" ]] && { CODIGO=${CODIGO%?}; printf '\b \b'; } ;;
      [0-9]) CODIGO+=$ch; printf '#'; [[ ${#CODIGO} -eq 6 ]] && break ;;
    esac
  done
  echo
}

# =============================================================================
titulo "1. Salud y capacidad de aprovisionamiento"
# =============================================================================
for par in "user-mgmt:${UM_BASE}" "vault-mgmt:${VM_BASE}"; do
  nombre=${par%%:*}; base=${par#*:}
  paso "${nombre} /health/ready"
  api GET "${base}/health/ready"
  ok "$ESTADO" "ready=$(campo ready)"
  if [[ "$ESTADO" != "200" ]]; then
    echo; echo "  ${nombre} no esta listo. Detalle:"; nota "$(campo detail)"
    echo; echo "  Si Vault esta sellado, desbloquealo (paso MANUAL) y repite:"
    echo "    docker compose exec vault-service vault operator unseal"
    exit 1
  fi
done

paso "capacidad consumer_provisioning"
api GET "${VM_BASE}/health/ready"
PROV=$(campo capabilities.consumer_provisioning)
ok "$ESTADO" "consumer_provisioning=${PROV}"
if [[ "$PROV" != "True" && "$PROV" != "true" ]]; then
  nota "El aprovisionamiento esta desactivado: falta el token del aprovisionador."
  nota "Detalle: $(campo detail)"
  nota "En local lo deja 'make all'. Sin el, las altas se quedan en 'pending'."
  exit 1
fi
nota "Son capacidades, no comprobaciones: si faltan, el CRUD sigue atendiendo."

# =============================================================================
titulo "2. El canal interno exige la credencial del receptor"
# =============================================================================
CRED_FILE="${REPO_ROOT}/secrets/crawler_receiver_${RECEPTOR}"
[[ -s "$CRED_FILE" ]] || {
  echo "ERROR: no existe ${CRED_FILE#"$REPO_ROOT/"}." >&2
  echo "       La genera 'make all'. Revisa VAULT_MGMT_RECEIVERS en .env." >&2
  exit 1; }
CRED=$(head -n 1 "$CRED_FILE")

paso "POST claim SIN credencial"
R="" api POST "${INTERNO}/claim" '{}'
ok "$ESTADO" "<- 401 esperado ($(campo code))"
exigir 401 "claim sin la credencial del receptor"

paso "POST claim con credencial incorrecta"
R="X-VPG-Receiver-Credential: no-es-la-buena" api POST "${INTERNO}/claim" '{}'
ok "$ESTADO" "<- 401 esperado ($(campo code))"
exigir 401 "claim con una credencial que no es de nadie"
nota "Oculto en Swagger NO es lo que lo protege: lo protege la credencial."
nota "Comparte el puerto de la API y responde igual si se acierta la ruta."

# =============================================================================
titulo "3. Sesion en user-mgmt (el alta exige rol admin)"
# =============================================================================
paso "GET ${VM_PREFIX}/vault/consumers sin sesion"
api GET "${VM}/vault/consumers"
ok "$ESTADO" "<- 401 esperado"
exigir 401 "listado de consumidores sin sesion"

[[ -n "$ADMIN_USER" ]] || { echo "ERROR: falta VAULT_ADMIN_USER_NAME en .env" >&2; exit 1; }
PASS=$(env_get VAULT_ADMIN_USER_PASS)
[[ -n "$PASS" ]] || { echo "ERROR: falta VAULT_ADMIN_USER_PASS en .env" >&2; exit 1; }

paso "POST ${UM_PREFIX}/auth/login (solo contrasena)"
CUERPO=$(python -c "
import json,sys
print(json.dumps({'username': sys.argv[1], 'password': sys.argv[2]}))" \
  "$ADMIN_USER" "$PASS")
PASS=''; unset PASS
api POST "${UM}/auth/login" "$CUERPO"
CUERPO=''; unset CUERPO
exigir 200 "login con la contrasena de ${ADMIN_USER}"
CHALLENGE=$(campo challenge_id)
ok 200 "desafio recibido, SIN sesion"

leer_totp "para iniciar sesion"
paso "POST ${UM_PREFIX}/auth/mfa/verify"
api POST "${UM}/auth/mfa/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
  "$CHALLENGE" "$CODIGO")"
CODIGO=''; unset CODIGO
exigir 200 "validacion del codigo TOTP"
SESION=$(campo api_session)
A="Authorization: Bearer ${SESION}"
ok 200 "sesion establecida  roles=$(campo role_codes)"

# =============================================================================
titulo "4. Alta del consumidor: 202 y tres campos"
# =============================================================================
# Clave de idempotencia del alta. Se vuelve a poner antes de CADA peticion que
# deba llevarla, porque api() la consume.
IDEM_ALTA="demo-${SUFIJO}"
ALTA=$(python -c "
import json,sys
print(json.dumps({'name': sys.argv[1], 'receiver': sys.argv[2],
                  'description': 'consumidor de prueba del recorrido 4.6',
                  'bindings': []}))" "$CONSUMIDOR" "$RECEPTOR")

# Un recorrido que solo se puede ejecutar una vez no es reproducible. El
# receptor sirve a UN consumidor, asi que si quedo ocupado por una ejecucion
# anterior de ESTE script, se revoca primero. Solo las suyas: un consumidor con
# otro nombre es de alguien y se para, diciendo que hacer.
paso "receptor '${RECEPTOR}' disponible"
IDEM="$IDEM_ALTA"
api POST "${VM}/vault/consumers" "$ALTA"
if [[ "$ESTADO" == "409" && "$(campo code)" == "receiver_taken" ]]; then
  ANTERIOR=$(printf '%s' "$RESP" | python -c "
import json,re,sys
m = re.search(r\"al consumidor '([^']+)'\", json.load(sys.stdin).get('message',''))
print(m.group(1) if m else '')")
  ok 409 "ocupado por '${ANTERIOR}'"
  if [[ "$ANTERIOR" != crawler-demo-* ]]; then
    printf '
  El receptor %s sirve al consumidor %s, que NO es un residuo de
'       "$RECEPTOR" "$ANTERIOR"
    printf '  este recorrido, asi que no se toca. Revocalo tu si procede:
'
    printf '    POST %s/vault/consumers/{consumer_id}/revoke
' "$VM_PREFIX"
    printf '    cuerpo: {"confirm": "%s"}
' "$ANTERIOR"
    printf '  O usa otro receptor configurado:  --receiver <nombre>

'
    exit 1
  fi
  nota "es un residuo de una ejecucion anterior de este recorrido: se revoca"
  api GET "${VM}/vault/consumers?limit=100"
  exigir 200 "listado para localizar el consumidor anterior"
  VIEJO_ID=$(printf '%s' "$RESP" | python -c "
import json,sys
objetivo = sys.argv[1]
for item in json.load(sys.stdin)['items']:
    if item['name'] == objetivo:
        print(item['consumer_id']); break" "$ANTERIOR")
  [[ -n "$VIEJO_ID" ]] || { echo "  no se pudo localizar '${ANTERIOR}'"; exit 1; }
  paso "revocando el consumidor anterior"
  api POST "${VM}/vault/consumers/${VIEJO_ID}/revoke" "$(python -c "
import json,sys
print(json.dumps({'confirm': sys.argv[1], 'reason': 'residuo de un recorrido anterior'}))"     "$ANTERIOR")"
  exigir 202 "revocacion del consumidor anterior"
  VIEJA_OP=$(campo operation_id)
  for _ in $(seq 1 30); do
    api GET "${VM}/vault/operations/${VIEJA_OP}"
    [[ "$(campo status)" =~ ^(completed|failed|needs_reconciliation)$ ]] && break
    sleep 2
  done
  ok "$ESTADO" "status=$(campo status); receptor liberado"
  # El reintento vuelve a llevar la clave del alta: la limpieza de por medio no
  # la ha gastado, porque esas peticiones no llevan ninguna.
  paso "POST ${VM_PREFIX}/vault/consumers (reintento)"
  IDEM="$IDEM_ALTA"
  api POST "${VM}/vault/consumers" "$ALTA"
fi
ok "$ESTADO" "status=$(campo status)"
exigir 202 "alta del consumidor ${CONSUMIDOR}"
CONSUMER_ID=$(campo consumer_id)
OPERACION=$(campo operation_id)
CAMPOS=$(printf '%s' "$RESP" | python -c "
import json,sys
print(','.join(sorted(json.load(sys.stdin))))")
nota "campos devueltos: ${CAMPOS}"
nota "consumer_id=${CONSUMER_ID}"
nota "operation_id=${OPERACION}"
nota "'pending' significa SOLICITUD GUARDADA, no entrega completada."

paso "la respuesta no trae credenciales"
if printf '%s' "$RESP" | grep -qiE '"(role_id|secret_id|wrap_token|vault_token)"'; then
  printf 'FALLO\n'; echo "  la respuesta contiene una credencial"; exit 1
fi
ok 202 "sin role_id, secret_id, wrap_token ni vault_token"

# =============================================================================
titulo "5. Idempotencia"
# =============================================================================
paso "misma Idempotency-Key y mismos parametros"
IDEM="$IDEM_ALTA"
api POST "${VM}/vault/consumers" "$ALTA"
exigir 202 "repetir el alta con la misma clave"
if [[ "$(campo consumer_id)" == "$CONSUMER_ID" && "$(campo operation_id)" == "$OPERACION" ]]; then
  ok 202 "mismos consumer_id y operation_id"
else
  printf 'FALLO\n'; echo "  deberia devolver los mismos identificadores"; exit 1
fi

paso "misma clave con OTROS parametros"
IDEM="$IDEM_ALTA"
api POST "${VM}/vault/consumers" "$(python -c "
import json,sys
print(json.dumps({'name': sys.argv[1], 'receiver': sys.argv[2], 'bindings': []}))" \
  "otro-${CONSUMIDOR}" "$RECEPTOR")"
ok "$ESTADO" "<- 409 esperado ($(campo code))"
exigir 409 "reutilizar una Idempotency-Key para otra peticion"

# =============================================================================
titulo "6. El worker prepara la identidad y NO emite credencial"
# =============================================================================
paso "esperando a que el worker la procese"
ESTADO_OP=""
for _ in $(seq 1 30); do
  api GET "${VM}/vault/operations/${OPERACION}"
  ESTADO_OP=$(campo status)
  [[ "$ESTADO_OP" == "waiting_receiver" || "$ESTADO_OP" == "failed" ]] && break
  sleep 2
done
ok "$ESTADO" "status=${ESTADO_OP}"
if [[ "$ESTADO_OP" != "waiting_receiver" ]]; then
  echo; echo "  La operacion no llego a waiting_receiver."
  nota "error: $(campo error)"
  nota "Revisa el worker:  docker compose logs --tail=40 vault-mgmt-worker"
  exit 1
fi
nota "AppRole, politica y rol listos. CERO SecretID emitidos: sin receptor que"
nota "los recoja, emitir seria repartir credenciales a nadie."

paso "GET ${VM_PREFIX}/vault/consumers/{id}"
api GET "${VM}/vault/consumers/${CONSUMER_ID}"
exigir 200 "detalle del consumidor"
ok 200 "provisioning_state=$(campo consumer.provisioning_state)  delivery_mode=$(campo consumer.delivery_mode)"

# =============================================================================
titulo "7. El receptor reclama su emision"
# =============================================================================
R="X-VPG-Receiver-Credential: ${CRED}"
paso "POST claim con la credencial correcta"
api POST "${INTERNO}/claim" "$(python -c "
import json,sys
print(json.dumps({'instance': 'provisioning-walkthrough'}))")"
exigir 200 "claim del receptor ${RECEPTOR}"
ok 200 "status=$(campo status)"
DELIVERY=$(campo delivery_id)
ROLE_ID=$(campo role_id)
WRAP=$(campo wrap_token)
LOGIN_PATH=$(campo login_path)
nota "delivery_id=${DELIVERY}"
nota "role_id=$(resumen "$ROLE_ID")"
nota "wrap_token=$(resumen "$WRAP")  ttl=$(campo wrap_ttl_seconds)s"
nota "login_path=${LOGIN_PATH}"

paso "la operacion NO esta completa todavia"
R="" api GET "${VM}/vault/operations/${OPERACION}"
ok "$ESTADO" "status=$(campo status)  <- awaiting_ack esperado"
exigir 200 "estado de la operacion tras el claim"

# =============================================================================
titulo "8. Desenvolver, entrar y confirmar"
# =============================================================================
paso "POST sys/wrapping/unwrap (UN SOLO USO)"
A="" R="" VT="$WRAP" api POST "${VAULT_BASE}/v1/sys/wrapping/unwrap" '{}'
exigir 200 "desenvolver la entrega en Vault"
SECRET_ID=$(campo data.secret_id)
VT=""; unset VT
[[ -n "$SECRET_ID" ]] || { echo "  la envoltura no traia secret_id"; exit 1; }
ok 200 "secret_id obtenido: $(resumen "$SECRET_ID")  (no se guarda en disco)"

paso "POST ${LOGIN_PATH} (AppRole)"
api POST "${VAULT_BASE}/v1/${LOGIN_PATH}" "$(python -c "
import json,sys
print(json.dumps({'role_id': sys.argv[1], 'secret_id': sys.argv[2]}))" \
  "$ROLE_ID" "$SECRET_ID")"
exigir 200 "login AppRole del consumidor"
TOKEN=$(campo auth.client_token)
SECRET_ID=''; unset SECRET_ID
ok 200 "token=$(resumen "$TOKEN")  accessor=$(campo auth.accessor)"
nota "politicas=$(campo auth.token_policies)  ttl=$(campo auth.lease_duration)s"
nota "El token se queda aqui, en memoria. No vuelve a la API para guardarse."

paso "POST ack (el servidor comprueba el token con lookup)"
R="X-VPG-Receiver-Credential: ${CRED}"
api POST "${INTERNO}/ack" "$(python -c "
import json,sys
print(json.dumps({'delivery_id': sys.argv[1], 'vault_token': sys.argv[2],
                  'instance': 'provisioning-walkthrough'}))" "$DELIVERY" "$TOKEN")"
exigir 200 "confirmacion del receptor"
ok 200 "status=$(campo status)  provisioning_state=$(campo provisioning_state)"
nota "token_accessor=$(campo token_accessor)  ttl=$(campo token_ttl_seconds)s"
nota "Se devuelve el ACCESSOR, que sirve para revocar, no para usar."

paso "estado final de la operacion"
A="Authorization: Bearer ${SESION}" R="" api GET "${VM}/vault/operations/${OPERACION}"
ok "$ESTADO" "status=$(campo status)  <- completed esperado"

# =============================================================================
titulo "9. Un segundo claim no emite otra credencial"
# =============================================================================
paso "POST claim de nuevo"
A="" R="X-VPG-Receiver-Credential: ${CRED}" api POST "${INTERNO}/claim" '{}'
ok "$ESTADO" "status=$(campo status)"
nota "$(campo detail)"
nota "Emitir encima dejaria la credencial anterior huerfana en Vault."

# =============================================================================
titulo "10. Rotacion after_ack: la anterior vive hasta la confirmacion"
# =============================================================================
A="Authorization: Bearer ${SESION}"; R=""
paso "POST ${VM_PREFIX}/vault/consumers/{id}/rotate"
IDEM="rotate-${SUFIJO}"
api POST "${VM}/vault/consumers/${CONSUMER_ID}/rotate" \
  '{"strategy":"after_ack","note":"recorrido 4.6"}'
exigir 202 "solicitud de rotacion"
ROTACION=$(campo operation_id)
ok 202 "operation_id=${ROTACION}  status=$(campo status)"

paso "esperando a que el worker la prepare"
for _ in $(seq 1 30); do
  api GET "${VM}/vault/operations/${ROTACION}"
  [[ "$(campo status)" == "waiting_receiver" ]] && break
  sleep 2
done
ok "$ESTADO" "status=$(campo status)"

paso "el receptor recoge la credencial nueva"
A="" R="X-VPG-Receiver-Credential: ${CRED}" api POST "${INTERNO}/claim" '{}'
exigir 200 "claim de la rotacion"
DELIVERY2=$(campo delivery_id)
WRAP2=$(campo wrap_token)
ROLE_ID2=$(campo role_id)
LOGIN2=$(campo login_path)
ok 200 "delivery_id=${DELIVERY2}"
nota "Hasta el ack, el TOKEN anterior sigue vivo (su SecretID ya se consumio"
nota "al entrar). Eso es lo que compra after_ack: si el rearranque falla, el"
nota "crawler que ya estaba dentro no se queda fuera."

paso "desenvolver, entrar y confirmar la nueva"
R="" VT="$WRAP2" api POST "${VAULT_BASE}/v1/sys/wrapping/unwrap" '{}'
exigir 200 "desenvolver la rotacion"
SECRET2=$(campo data.secret_id); VT=""; unset VT
api POST "${VAULT_BASE}/v1/${LOGIN2}" "$(python -c "
import json,sys
print(json.dumps({'role_id': sys.argv[1], 'secret_id': sys.argv[2]}))" \
  "$ROLE_ID2" "$SECRET2")"
exigir 200 "login con la credencial rotada"
TOKEN2=$(campo auth.client_token); SECRET2=''; unset SECRET2
R="X-VPG-Receiver-Credential: ${CRED}"
api POST "${INTERNO}/ack" "$(python -c "
import json,sys
print(json.dumps({'delivery_id': sys.argv[1], 'vault_token': sys.argv[2]}))" \
  "$DELIVERY2" "$TOKEN2")"
exigir 200 "ack de la rotacion"
ok 200 "retired_previous=$(campo retired_previous)"
nota "La credencial anterior se ha retirado AHORA, al confirmarse la nueva."
nota "Los TOKENS que salieron de ella siguen vivos hasta su TTL."

# =============================================================================
if [[ "$KEEP" == true ]]; then
titulo "11. Limpieza OMITIDA (--keep)"
  nota "El consumidor ${CONSUMIDOR} queda activo."
  nota "Para revocarlo despues:"
  nota "  POST ${VM_PREFIX}/vault/consumers/${CONSUMER_ID}/revoke"
  nota "  cuerpo: {\"confirm\": \"${CONSUMIDOR}\"}"
else
titulo "11. Revocacion del consumidor de prueba"
  A="Authorization: Bearer ${SESION}"; R=""
  paso "POST ${VM_PREFIX}/vault/consumers/{id}/revoke"
  IDEM="revoke-${SUFIJO}"
  api POST "${VM}/vault/consumers/${CONSUMER_ID}/revoke" "$(python -c "
import json,sys
print(json.dumps({'confirm': sys.argv[1], 'reason': 'fin del recorrido'}))" \
    "$CONSUMIDOR")"
  exigir 202 "solicitud de revocacion"
  REVOCACION=$(campo operation_id)
  ok 202 "operation_id=${REVOCACION}"

  paso "esperando a que el worker la ejecute"
  for _ in $(seq 1 30); do
    api GET "${VM}/vault/operations/${REVOCACION}"
    [[ "$(campo status)" =~ ^(completed|failed|needs_reconciliation)$ ]] && break
    sleep 2
  done
  ok "$ESTADO" "status=$(campo status)"

  paso "el claim siguiente se rechaza"
  A="" R="X-VPG-Receiver-Credential: ${CRED}" api POST "${INTERNO}/claim" '{}'
  ok "$ESTADO" "<- 403 esperado ($(campo code))"
  nota "Revocar impide entregas FUTURAS. No caduca un wrapping token ya"
  nota "entregado, y los tokens vivos duran hasta su TTL."
fi

CRED=''; unset CRED
TOKEN=''; unset TOKEN
TOKEN2=''; unset TOKEN2

titulo "Recorrido completado"
cat <<RESUMEN
  consumidor : ${CONSUMIDOR}
  consumer_id: ${CONSUMER_ID}
  receptor   : ${RECEPTOR}

  Lo que este recorrido demuestra: el contrato de aprovisionamiento funciona
  de punta a punta contra Vault real, y ninguna respuesta humana lleva
  credenciales.

  Lo que NO demuestra: que exista un crawler. Esta etapa entrega su contrato
  de consumo; el receptor de este recorrido es una pieza de prueba aislada
  (scripts/vault_mgmt/test_receiver.py hace lo mismo sin pedir TOTP, una vez
  que el consumidor ya esta dado de alta).
RESUMEN
