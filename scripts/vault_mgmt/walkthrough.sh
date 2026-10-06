#!/usr/bin/env bash
# *** SCRIPT INTERACTIVO: pide codigos TOTP por teclado. ***
#
# Recorrido de extremo a extremo por vault-mgmt-service con datos FICTICIOS.
#
# Uso (host, Git Bash, en una terminal real):
#   bash scripts/vault_mgmt/walkthrough.sh [--keep]
#     --keep   no purga la coleccion de prueba al final
#
# Demuestra, en este orden:
#   1. Salud de las dos APIs y la cadena de dependencias.
#   2. Sesion en user-mgmt (login + TOTP) y su uso en vault-mgmt.
#   3. Coleccion con esquema tipado, que NO crea nada en Vault.
#   4. Dos registros INDEPENDIENTES: dos claves de Vault, no una sobrescrita.
#   5. CAS: la segunda escritura con la misma version pierde y no sobrescribe.
#   6. PATCH: omitido conserva, null elimina; null sobre obligatorio no escribe.
#   7. Entrega envuelta (un solo uso) y entrega plana por eleccion explicita.
#   8. Renombrado que conserva UUID, path fisico e historial.
#   9. Esquema compatible (crea version) e incompatible (409, sin crear nada).
#  10. Capacidad efectiva: rol de aplicacion Y ACL de Vault.
#  11. Metadata nativa con los tres estados: activa, borrada y destruida.
#  12. Purga con reautenticacion MFA, y la misma prueba rechazada al reusarla.
#  13. Auditoria sin valores, y limpieza de los fixtures.
#
# CUANTOS CODIGOS TOTP HACEN FALTA: tres distintos (dos con --keep). Uno para
# el login y uno por cada operacion irreversible, porque la prueba de MFA es de
# un solo uso y Vault no admite reutilizar un codigo. Esperale al siguiente si
# el autenticador aun muestra el mismo.
#
# El usuario administrador y su contrasena salen de VAULT_ADMIN_USER_NAME y
# VAULT_ADMIN_USER_PASS del .env, igual que en scripts/user_mgmt/smoke-api.sh:
# no hay ningun usuario escrito en el codigo. La contrasena viaja por stdin,
# nunca como argumento visible ni en el historial.
#
# Ningun valor de secreto, token de sesion o wrapping token se imprime: de las
# entregas se muestran los NOMBRES de los campos y el tamano del token.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

KEEP=false
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

UM_BIND=$(env_get USER_MGMT_HOST_BIND);   UM_BIND=${UM_BIND:-127.0.0.1}
UM_PORT=$(env_get USER_MGMT_PORT_LOCAL);  UM_PORT=${UM_PORT:-8000}
UM_PREFIX=$(env_get USER_MGMT_API_PREFIX); UM_PREFIX=${UM_PREFIX:-/user_mgmt/v1}
VM_BIND=$(env_get VAULT_MGMT_HOST_BIND);  VM_BIND=${VM_BIND:-127.0.0.1}
VM_PORT=$(env_get VAULT_MGMT_PORT_LOCAL); VM_PORT=${VM_PORT:-8001}
VM_PREFIX=$(env_get VAULT_MGMT_API_PREFIX); VM_PREFIX=${VM_PREFIX:-/vault_mgmt/v1}
KV_MOUNT=$(env_get VAULT_MGMT_KV_MOUNT);  KV_MOUNT=${KV_MOUNT:-secret}

UM_BASE="http://${UM_BIND}:${UM_PORT}"
VM_BASE="http://${VM_BIND}:${VM_PORT}"
UM="${UM_BASE}${UM_PREFIX}"
VM="${VM_BASE}${VM_PREFIX}"
ADMIN_USER=$(env_get VAULT_ADMIN_USER_NAME | tr 'A-Z' 'a-z')

SUFIJO=$(date +%H%M%S)
COLECCION="sat/demo-${SUFIJO}"

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
paso()   { printf '  %-58s ' "$*"; }
ok()     { printf 'HTTP %s  %s\n' "$1" "${2:-}"; }
nota()   { printf '    %s\n' "$*"; }

# --- ayudantes ---------------------------------------------------------------
# jget "a.b.0.c" sobre stdin. Devuelve vacio si falta la clave, en vez de una
# traza de Python: asi el fallo se lee en el mensaje del paso, no en el stack.
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

# api <METODO> <URL> [CUERPO] -> cuerpo en stdout y estado en la variable ESTADO.
# Nunca aborta: cada paso decide si el estado que recibio es el que esperaba,
# porque varios pasos de este recorrido esperan 409 o 422 a proposito.
ESTADO=""
api() {
  local metodo=$1 url=$2 cuerpo=${3-}
  local -a opciones=(-sS -X "$metodo" "$url" -H 'Content-Type: application/json')
  [[ -n "${A:-}" ]] && opciones+=(-H "$A")
  [[ -n "${P:-}" ]] && opciones+=(-H "X-VPG-MFA-Proof: $P")
  [[ -n "$cuerpo" ]] && opciones+=(--data-binary "$cuerpo")

  local respuesta
  respuesta=$(curl -w $'\n%{http_code}' "${opciones[@]}" 2>&1) || true
  ESTADO=${respuesta##*$'\n'}
  printf '%s' "${respuesta%$'\n'*}"
}

# exigir <esperado> <cuerpo> <descripcion>: si el estado no es el esperado,
# imprime el cuerpo real y para. Es la diferencia entre "no funciona" y saber
# por que.
exigir() {
  local esperado=$1 cuerpo=$2 descripcion=$3
  if [[ "$ESTADO" != "$esperado" ]]; then
    printf 'FALLO\n'
    printf '\n  Se esperaba HTTP %s en: %s\n' "$esperado" "$descripcion"
    printf '  Se recibio HTTP %s con este cuerpo:\n\n' "${ESTADO:-sin respuesta}"
    printf '%s\n\n' "$cuerpo" | python -m json.tool 2>/dev/null \
      || printf '%s\n\n' "$cuerpo"
    exit 1
  fi
}

# Lee un codigo TOTP con eco enmascarado. Nunca queda en el historial.
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

json() { python -c "
import json,sys
print(json.dumps(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}))" "$1"; }

# =============================================================================
titulo "1. Salud de las dos APIs"
# =============================================================================
for par in "user-mgmt:${UM_BASE}" "vault-mgmt:${VM_BASE}"; do
  nombre=${par%%:*}; base=${par#*:}
  paso "${nombre} /health/live"
  ok "$(curl -s -o /dev/null -w '%{http_code}' "${base}/health/live")"

  paso "${nombre} /health/ready"
  cuerpo=$(curl -s -w $'\n%{http_code}' "${base}/health/ready" 2>&1) || true
  estado=${cuerpo##*$'\n'}; cuerpo=${cuerpo%$'\n'*}
  ok "$estado" "ready=$(printf '%s' "$cuerpo" | jget ready)"
  if [[ "$estado" != "200" ]]; then
    echo
    echo "  ${nombre} no esta listo. Detalle:"
    printf '    %s\n' "$(printf '%s' "$cuerpo" | jget detail)"
    echo
    echo "  Si Vault esta sellado, desbloquealo (paso MANUAL) y repite:"
    echo "    docker compose exec vault-service vault operator unseal"
    exit 1
  fi
done

# =============================================================================
titulo "2. Sesion en user-mgmt (el login no vive en vault-mgmt)"
# =============================================================================
paso "GET ${VM_PREFIX}/vault/collections sin sesion"
api GET "${VM}/vault/collections" >/dev/null
ok "$ESTADO" "<- 401 esperado"
[[ "$ESTADO" == "401" ]] || { echo "FALLO: se esperaba 401 sin sesion"; exit 1; }

[[ -n "$ADMIN_USER" ]] || {
  echo "ERROR: falta VAULT_ADMIN_USER_NAME en .env" >&2; exit 1; }
PASS=$(env_get VAULT_ADMIN_USER_PASS)
[[ -n "$PASS" ]] || {
  echo "ERROR: falta VAULT_ADMIN_USER_PASS en .env" >&2; exit 1; }

paso "POST ${UM_PREFIX}/auth/login (solo contrasena)"
LOGIN=$(python -c "
import json,sys
print(json.dumps({'username': sys.argv[1], 'password': sys.argv[2]}))" \
  "$ADMIN_USER" "$PASS" \
  | curl -sS -w $'\n%{http_code}' -X POST -H 'Content-Type: application/json' \
         --data-binary @- "${UM}/auth/login" 2>&1) || true
PASS=''; unset PASS
ESTADO=${LOGIN##*$'\n'}; LOGIN=${LOGIN%$'\n'*}
exigir 200 "$LOGIN" "login con la contrasena de ${ADMIN_USER}"
CHALLENGE=$(printf '%s' "$LOGIN" | jget challenge_id)
ok 200 "desafio recibido, SIN sesion"
nota "contiene api_session: $(printf '%s' "$LOGIN" \
  | python -c 'import json,sys;print("api_session" in json.load(sys.stdin))')"

leer_totp "para iniciar sesion"
paso "POST ${UM_PREFIX}/auth/mfa/verify"
VERIFY=$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
  "$CHALLENGE" "$CODIGO" \
  | curl -sS -w $'\n%{http_code}' -X POST -H 'Content-Type: application/json' \
         --data-binary @- "${UM}/auth/mfa/verify" 2>&1) || true
CODIGO=''; unset CODIGO
ESTADO=${VERIFY##*$'\n'}; VERIFY=${VERIFY%$'\n'*}
exigir 200 "$VERIFY" "validacion del codigo TOTP"
SESION=$(printf '%s' "$VERIFY" | jget api_session)
A="Authorization: Bearer ${SESION}"
ok 200 "sesion establecida"
nota "usuario=$(printf '%s' "$VERIFY" | jget username)  roles=$(printf '%s' "$VERIFY" | jget role_codes)"

# =============================================================================
titulo "3. Coleccion con esquema tipado (no crea nada en Vault)"
# =============================================================================
paso "POST ${VM_PREFIX}/vault/collections"
CUERPO=$(python -c "
import json,sys
print(json.dumps({
  'logical_name': sys.argv[1],
  'description': 'Credenciales del portal del SAT (datos ficticios)',
  'reader_role_codes': ['admin', 'manager'],
  'fields': [
    {'name': 'usuario',  'type': 'string', 'required': True,  'max_length': 64},
    {'name': 'password', 'type': 'string', 'required': True,
     'sensitive': True, 'max_length': 256},
    {'name': 'rfc',      'type': 'string', 'required': False, 'max_length': 13},
  ],
}))" "$COLECCION")
RESP=$(api POST "${VM}/vault/collections" "$CUERPO")
exigir 201 "$RESP" "creacion de la coleccion ${COLECCION}"
C=$(printf '%s' "$RESP" | jget collection_id)
PREFIJO=$(printf '%s' "$RESP" | jget physical_prefix)
ok 201 "collection_id=${C}"
nota "nombre logico : $(printf '%s' "$RESP" | jget logical_name)"
nota "path fisico   : ${PREFIJO}"
nota "el path sale del UUID, no del nombre: renombrar no movera nada"

paso "LIST ${KV_MOUNT}/${PREFIJO} en Vault"
CLAVES=$(docker compose exec -T vault-service \
  vault kv list "${KV_MOUNT}/${PREFIJO}" 2>&1 || true)
if printf '%s' "$CLAVES" | grep -qi "no value found"; then
  ok "--" "el prefijo NO existe todavia"
  nota "KV v2 no tiene carpetas: un prefijo sin claves no existe"
else
  ok "--" "ATENCION: ya hay claves bajo el prefijo"
  printf '%s\n' "$CLAVES" | sed 's/^/      /'
fi

# =============================================================================
titulo "4. Dos registros INDEPENDIENTES: dos secretos, no uno sobrescrito"
# =============================================================================
crear_registro() {
  local etiqueta=$1 usuario=$2 clave=$3
  local cuerpo
  cuerpo=$(python -c "
import json,sys
print(json.dumps({'label': sys.argv[1],
                  'values': {'usuario': sys.argv[2], 'password': sys.argv[3]}}))" \
    "$etiqueta" "$usuario" "$clave")
  api POST "${VM}/vault/collections/${C}/records" "$cuerpo"
}

paso "POST .../records (primero)"
RESP=$(crear_registro "contribuyente-uno-${SUFIJO}" "demo-uno" "valor-ficticio-1")
exigir 201 "$RESP" "creacion del primer registro"
R1=$(printf '%s' "$RESP" | jget record_id)
V1=$(printf '%s' "$RESP" | jget version)
ok 201 "record_id=${R1}  version=${V1}"

paso "POST .../records (segundo)"
RESP=$(crear_registro "contribuyente-dos-${SUFIJO}" "demo-dos" "valor-ficticio-2")
exigir 201 "$RESP" "creacion del segundo registro"
R2=$(printf '%s' "$RESP" | jget record_id)
ok 201 "record_id=${R2}  version=$(printf '%s' "$RESP" | jget version)"

paso "LIST ${KV_MOUNT}/${PREFIJO} en Vault"
CLAVES=$(docker compose exec -T vault-service \
  vault kv list -format=json "${KV_MOUNT}/${PREFIJO}" 2>/dev/null || echo '[]')
CUANTAS=$(printf '%s' "$CLAVES" | python -c 'import json,sys;print(len(json.load(sys.stdin)))')
ok "--" "${CUANTAS} claves distintas"
[[ "$CUANTAS" == "2" ]] || { echo "FALLO: se esperaban 2 claves en Vault"; exit 1; }
nota "dos registros = dos secretos, cada uno con su propio historial"

paso "GET .../records (listado del catalogo)"
RESP=$(api GET "${VM}/vault/collections/${C}/records")
exigir 200 "$RESP" "listado de registros"
ok 200 "total=$(printf '%s' "$RESP" | jget page.total)"
if printf '%s' "$RESP" | grep -q "valor-ficticio"; then
  echo "FALLO: el listado del catalogo contiene valores"; exit 1
fi
nota "el listado NO contiene ningun valor"

# =============================================================================
titulo "5. CAS: la escritura con una version caducada no sobrescribe"
# =============================================================================
paso "PUT .../records/{id} con expected_version=${V1}"
CUERPO=$(json '{"expected_version": 1, "values": {"usuario": "demo-uno", "password": "v2-ficticio"}}')
RESP=$(api PUT "${VM}/vault/collections/${C}/records/${R1}" "$CUERPO")
exigir 200 "$RESP" "reemplazo con el CAS correcto"
V2=$(printf '%s' "$RESP" | jget version)
ok 200 "version=${V2}"

paso "PUT .../records/{id} con expected_version=1 otra vez"
RESP=$(api PUT "${VM}/vault/collections/${C}/records/${R1}" "$CUERPO")
exigir 409 "$RESP" "conflicto de CAS"
ok 409 "code=$(printf '%s' "$RESP" | jget code)"
nota "el cambio ajeno NO se sobrescribio"

# =============================================================================
titulo "6. PATCH: omitido conserva, null elimina"
# =============================================================================
paso "PUT .../records/{id} anadiendo rfc"
CUERPO=$(json '{"expected_version": 2, "values": {"usuario": "demo-uno", "password": "v3-ficticio", "rfc": "XAXX010101000"}}')
RESP=$(api PUT "${VM}/vault/collections/${C}/records/${R1}" "$CUERPO")
exigir 200 "$RESP" "escritura con los tres campos"
V3=$(printf '%s' "$RESP" | jget version)
ok 200 "version=${V3}"

paso "PATCH .../records/{id} con rfc=null"
CUERPO=$(python -c "
import json,sys
print(json.dumps({'expected_version': int(sys.argv[1]),
                  'patch': {'password': 'v4-ficticio', 'rfc': None}}))" "$V3")
RESP=$(api PATCH "${VM}/vault/collections/${C}/records/${R1}" "$CUERPO")
exigir 200 "$RESP" "merge patch"
V4=$(printf '%s' "$RESP" | jget version)
ok 200 "version=${V4}"

paso "POST .../read (plain) para ver los campos resultantes"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R1}/read" \
  "$(json '{"delivery": "plain", "reason": "recorrido del README"}')")
exigir 200 "$RESP" "entrega plana"
CAMPOS=$(printf '%s' "$RESP" | python -c '
import json,sys
print(",".join(sorted(json.load(sys.stdin)["delivery"]["values"])))')
ok 200 "campos=${CAMPOS}"
nota "usuario se omitio en el patch y se conserva; rfc llevaba null y ya no esta"
[[ "$CAMPOS" == "password,usuario" ]] || {
  echo "FALLO: se esperaban exactamente password,usuario"; exit 1; }

paso "PATCH .../records/{id} con password=null (obligatorio)"
CUERPO=$(python -c "
import json,sys
print(json.dumps({'expected_version': int(sys.argv[1]), 'patch': {'password': None}}))" "$V4")
RESP=$(api PATCH "${VM}/vault/collections/${C}/records/${R1}" "$CUERPO")
exigir 422 "$RESP" "patch que dejaria la tupla invalida"
ok 422 "campo=$(printf '%s' "$RESP" | jget context.fields.0.field)"
nota "422 y NO se escribio nada"

# =============================================================================
titulo "7. Entrega: envuelta por defecto, de un solo uso"
# =============================================================================
paso "POST .../read (sin delivery: envuelta)"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R1}/read" "$(json '{}')")
exigir 200 "$RESP" "entrega envuelta"
WRAP=$(printf '%s' "$RESP" | jget delivery.wrap_token)
ok 200 "modo=$(printf '%s' "$RESP" | jget delivery.mode)  ttl=$(printf '%s' "$RESP" | jget delivery.ttl_seconds)s"
nota "token de ${#WRAP} caracteres; no se imprime ni se guarda"
if printf '%s' "$RESP" | grep -q "valor-ficticio\|v4-ficticio"; then
  echo "FALLO: la entrega envuelta contiene valores"; exit 1
fi

paso "vault unwrap (primera vez)"
UNWRAP=$(docker compose exec -T vault-service \
  sh -c "VAULT_TOKEN='' vault unwrap -format=json '${WRAP}'" 2>&1 || true)
CAMPOS=$(printf '%s' "$UNWRAP" | python -c '
import json,sys
try:
    d = json.load(sys.stdin)["data"]["data"]
    print(",".join(sorted(d["values"])), "schema_version=" + str(d["schema_version"]))
except Exception:
    print("")' 2>/dev/null || echo "")
if [[ -n "$CAMPOS" ]]; then
  ok "--" "campos=${CAMPOS}"
  nota "solo los NOMBRES: ningun valor se imprime"
else
  ok "--" "no se pudo desenvolver"
  printf '%s\n' "$UNWRAP" | tail -2 | sed 's/^/      /'
fi

paso "vault unwrap (segunda vez)"
UNWRAP2=$(docker compose exec -T vault-service \
  sh -c "VAULT_TOKEN='' vault unwrap '${WRAP}'" 2>&1 || true)
if printf '%s' "$UNWRAP2" | grep -qiE "wrapping token is not valid|does not exist|invalid"; then
  ok "--" "rechazado: es de UN SOLO USO"
else
  ok "--" "ATENCION: se pudo desenvolver dos veces"
  printf '%s\n' "$UNWRAP2" | tail -2 | sed 's/^/      /'
fi
WRAP=''; unset WRAP

# =============================================================================
titulo "8. Renombrar conserva UUID, path fisico e historial"
# =============================================================================
paso "PATCH .../collections/{id} con otro nombre logico"
NUEVO="sat/datos-${SUFIJO}"
RESP=$(api PATCH "${VM}/vault/collections/${C}" \
  "$(python -c "import json,sys;print(json.dumps({'logical_name': sys.argv[1]}))" "$NUEVO")")
exigir 200 "$RESP" "renombrado de la coleccion"
ok 200 "nombre=$(printf '%s' "$RESP" | jget logical_name)"
[[ "$(printf '%s' "$RESP" | jget collection_id)" == "$C" ]] || {
  echo "FALLO: el collection_id cambio"; exit 1; }
[[ "$(printf '%s' "$RESP" | jget physical_prefix)" == "$PREFIJO" ]] || {
  echo "FALLO: el path fisico cambio"; exit 1; }
nota "mismo collection_id y mismo path fisico"

paso "GET .../records/{id}/metadata (historial)"
RESP=$(api GET "${VM}/vault/collections/${C}/records/${R1}/metadata")
exigir 200 "$RESP" "metadata del registro"
VERSIONES=$(printf '%s' "$RESP" | python -c '
import json,sys
print(",".join(str(v["version"]) for v in json.load(sys.stdin)["versions"]))')
ok 200 "versiones=${VERSIONES}"
nota "el historial sobrevive al renombrado"

# =============================================================================
titulo "9. Esquema: compatible crea version, incompatible responde 409"
# =============================================================================
paso "PUT .../schema anadiendo un campo opcional"
RESP=$(api PUT "${VM}/vault/collections/${C}/schema" "$(json '{
  "fields": [
    {"name": "usuario",  "type": "string", "required": true,  "max_length": 64},
    {"name": "password", "type": "string", "required": true, "sensitive": true, "max_length": 256},
    {"name": "rfc",      "type": "string", "required": false, "max_length": 13},
    {"name": "notas",    "type": "string", "required": false, "max_length": 500}
  ],
  "note": "se anade notas opcional"
}')")
exigir 200 "$RESP" "nueva version de esquema compatible"
ok 200 "version=$(printf '%s' "$RESP" | jget current_schema_version)  compatible=$(printf '%s' "$RESP" | jget compatibility.compatible)"

paso "PUT .../schema quitando un campo"
RESP=$(api PUT "${VM}/vault/collections/${C}/schema" "$(json '{
  "fields": [{"name": "usuario", "type": "string", "required": true, "max_length": 64}]
}')")
exigir 409 "$RESP" "esquema incompatible"
ok 409 "code=$(printf '%s' "$RESP" | jget code)"
nota "motivo: $(printf '%s' "$RESP" | jget context.breaking_changes.0.reason)"
nota "registros afectados: $(printf '%s' "$RESP" | jget context.records_affected)"
if printf '%s' "$RESP" | grep -q "ficticio"; then
  echo "FALLO: el diagnostico contiene valores"; exit 1
fi
nota "el diagnostico habla de campos, nunca de valores"

# =============================================================================
titulo "10. Capacidad efectiva: rol de aplicacion Y ACL de Vault"
# =============================================================================
paso "POST ${VM_PREFIX}/vault/access-check"
RESP=$(api POST "${VM}/vault/access-check" "$(python -c "
import json,sys
print(json.dumps({'collection_id': sys.argv[1], 'record_id': sys.argv[2],
                  'operations': ['record_read','record_replace','record_purge']}))" \
  "$C" "$R1")")
exigir 200 "$RESP" "comprobacion de capacidad"
ok 200 "roles=$(printf '%s' "$RESP" | jget your_roles)"
printf '%s' "$RESP" | python -c '
import json,sys
d = json.load(sys.stdin)
for o in d["operations"]:
    print(f"      {o[\"operation\"]:18} rol={o[\"allowed_by_application_role\"]}"
          + (f"  ({o[\"reason\"]})" if o.get("reason") else ""))
for ruta, caps in d["vault_capabilities"].items():
    print(f"      vault: {ruta} -> {caps}")'

# =============================================================================
titulo "11. Los tres estados de una version"
# =============================================================================
paso "POST .../versions/delete (soft-delete de la version 1)"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R1}/versions/delete" \
  "$(json '{"versions": [1]}')")
exigir 204 "$RESP" "soft-delete de una version historica"
ok 204 "reversible con undelete"

paso "GET .../records/{id} (el registro sigue activo)"
RESP=$(api GET "${VM}/vault/collections/${C}/records/${R1}")
exigir 200 "$RESP" "resumen del registro"
ok 200 "state=$(printf '%s' "$RESP" | jget state)"
nota "borrar una version historica NO deja el registro borrado"

# =============================================================================
titulo "12. Purga: admin + confirmacion + MFA reciente"
# =============================================================================
paso "POST .../records/{id}/purge SIN prueba de MFA"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R2}/purge" \
  "$(json '{"confirm": "PURGE"}')")
exigir 403 "$RESP" "purga sin prueba de MFA"
ok 403 "code=$(printf '%s' "$RESP" | jget code)"

echo
echo "  Para purgar hace falta reautenticarse. Necesitas un codigo TOTP NUEVO:"
echo "  si el autenticador aun muestra el anterior, espera a que cambie."
PASS=$(env_get VAULT_ADMIN_USER_PASS)
paso "POST ${UM_PREFIX}/auth/mfa/step-up"
CUERPO=$(python -c "
import json,sys
print(json.dumps({'password': sys.argv[1], 'operation': 'record_purge',
                  'collection_id': sys.argv[2], 'resource_ids': [sys.argv[3]]}))" \
  "$PASS" "$C" "$R2")
PASS=''; unset PASS
RESP=$(api POST "${UM}/auth/mfa/step-up" "$CUERPO")
exigir 200 "$RESP" "paso 1 de la reautenticacion"
SCH=$(printf '%s' "$RESP" | jget challenge_id)
ok 200 "desafio recibido, SIN prueba todavia"

leer_totp "para autorizar la purga"
paso "POST ${UM_PREFIX}/auth/mfa/step-up/verify"
RESP=$(api POST "${UM}/auth/mfa/step-up/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
  "$SCH" "$CODIGO")")
CODIGO=''; unset CODIGO
exigir 200 "$RESP" "paso 2 de la reautenticacion"
P=$(printf '%s' "$RESP" | jget mfa_proof)
ok 200 "prueba emitida (un solo uso)"
nota "operacion=$(printf '%s' "$RESP" | jget operation)  recursos=1"

paso "POST .../records/{id}/purge CON la prueba"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R2}/purge" \
  "$(json '{"confirm": "PURGE", "reason": "recorrido del README"}')")
exigir 204 "$RESP" "purga del segundo registro"
ok 204 "datos y metadata destruidos"

paso "POST .../records/{id}/purge reusando la MISMA prueba"
RESP=$(api POST "${VM}/vault/collections/${C}/records/${R1}/purge" \
  "$(json '{"confirm": "PURGE"}')")
exigir 403 "$RESP" "reutilizacion de la prueba"
ok 403 "code=$(printf '%s' "$RESP" | jget code)"
nota "la prueba era de un solo uso y ya se consumio"
P=''; unset P

paso "vault kv metadata get del registro purgado"
SALIDA=$(docker compose exec -T vault-service \
  vault kv metadata get "${KV_MOUNT}/${PREFIJO}/${R2}" 2>&1 || true)
if printf '%s' "$SALIDA" | grep -qi "no value found"; then
  ok "--" "en Vault ya no existe"
else
  ok "--" "ATENCION: sigue habiendo metadata"
fi

paso "GET .../records/{id} del registro purgado"
RESP=$(api GET "${VM}/vault/collections/${C}/records/${R2}")
exigir 200 "$RESP" "resumen del registro purgado"
ok 200 "state=$(printf '%s' "$RESP" | jget state)"
nota "en el catalogo queda como 'destroyed': distingue destruido de inexistente"

# =============================================================================
titulo "13. Auditoria y limpieza"
# =============================================================================
paso "GET ${VM_PREFIX}/vault/audit"
RESP=$(api GET "${VM}/vault/audit?collection_id=${C}&limit=100")
exigir 200 "$RESP" "historial de auditoria"
ok 200 "lineas=$(printf '%s' "$RESP" | jget page.total)"
printf '%s' "$RESP" | python -c '
import json,sys
for i in json.load(sys.stdin)["items"][:8]:
    print(f"      {i[\"occurred_at\"][11:19]}  {i[\"actor_kind\"]:7} {i[\"action\"]:26} {i[\"outcome\"]}")'
if printf '%s' "$RESP" | grep -q "ficticio"; then
  echo "FALLO: la auditoria contiene valores"; exit 1
fi
nota "la auditoria no contiene ningun valor ni wrapping token"

if [[ "$KEEP" == true ]]; then
  echo
  echo "  --keep: la coleccion ${NUEVO} se conserva."
  echo "  Para purgarla luego hacen falta un step-up con"
  echo "  operation=collection_purge_batch y resource_ids=[${R1}]."
else
  echo
  echo "  Limpieza de fixtures: se purgara la coleccion de prueba."
  echo "  Necesitas un TERCER codigo TOTP, nuevo."
  PASS=$(env_get VAULT_ADMIN_USER_PASS)
  paso "POST ${UM_PREFIX}/auth/mfa/step-up (purga de coleccion)"
  CUERPO=$(python -c "
import json,sys
print(json.dumps({'password': sys.argv[1], 'operation': 'collection_purge_batch',
                  'collection_id': sys.argv[2], 'resource_ids': [sys.argv[3]]}))" \
    "$PASS" "$C" "$R1")
  PASS=''; unset PASS
  RESP=$(api POST "${UM}/auth/mfa/step-up" "$CUERPO")
  exigir 200 "$RESP" "paso 1 de la reautenticacion de limpieza"
  SCH=$(printf '%s' "$RESP" | jget challenge_id)
  ok 200 "desafio recibido"

  leer_totp "para purgar la coleccion"
  paso "POST ${UM_PREFIX}/auth/mfa/step-up/verify"
  RESP=$(api POST "${UM}/auth/mfa/step-up/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
    "$SCH" "$CODIGO")")
  CODIGO=''; unset CODIGO
  exigir 200 "$RESP" "paso 2 de la reautenticacion de limpieza"
  P=$(printf '%s' "$RESP" | jget mfa_proof)
  ok 200 "prueba emitida"

  paso "POST .../collections/{id}/purge"
  RESP=$(api POST "${VM}/vault/collections/${C}/purge" \
    "$(json '{"confirm": "PURGE", "reason": "limpieza del recorrido"}')")
  exigir 204 "$RESP" "purga de la coleccion"
  ok 204 "coleccion purgada"
  P=''; unset P

  paso "GET .../collections/{id}"
  RESP=$(api GET "${VM}/vault/collections/${C}")
  exigir 200 "$RESP" "estado final de la coleccion"
  ok 200 "state=$(printf '%s' "$RESP" | jget state)"
  nota "la fila permanece como auditoria minima"
fi

paso "POST ${UM_PREFIX}/auth/logout"
api POST "${UM}/auth/logout" >/dev/null
ok "$ESTADO" "sesion cerrada y token de Vault revocado"
A=''; unset A

titulo "Recorrido completado"
cat <<FIN
  Lo que se ha demostrado, con datos ficticios:
    - crear una coleccion no escribe nada en Vault;
    - dos registros son dos secretos independientes;
    - el CAS impide sobrescribir el cambio ajeno;
    - un patch con null elimina un campo y no toca sus hermanos;
    - un null sobre un campo obligatorio no escribe nada;
    - la entrega envuelta es de un solo uso;
    - renombrar conserva UUID, path e historial;
    - un esquema incompatible no crea version;
    - la purga exige confirmacion y una prueba de MFA de un solo uso;
    - ni los listados, ni el diagnostico, ni la auditoria llevan valores.

  Lo que este recorrido NO cubre:
    - el contrato de maquina del crawler, que necesita role_id y secret_id:
        bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
        python scripts/vault_mgmt/crawler_client.py --help
    - el fallo parcial y su reconciliacion:
        bash scripts/vault_mgmt/reconcile-operations.sh
FIN
