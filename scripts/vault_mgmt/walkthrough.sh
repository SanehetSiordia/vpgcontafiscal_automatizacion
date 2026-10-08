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
#  11. Los tres estados de una version.
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
#
# Al terminar imprime los UUID de la coleccion y de los registros, listos para
# exportar, porque las comprobaciones manuales del README (seccion 7) los
# necesitan y un script no puede dejar variables en el shell que lo invoca.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

KEEP=false
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    -h|--help) sed -n '2,41p' "$0"; exit 0 ;;
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

# api <METODO> <URL> [CUERPO]
#
# Fija dos variables GLOBALES: ESTADO con el codigo HTTP y RESP con el cuerpo.
#
# Se llama SIN sustitucion de comandos, y eso no es un detalle de estilo:
# `RESP=$(api ...)` ejecutaria api en un subshell y el ESTADO que fijara dentro
# NO llegaria aqui, asi que las comprobaciones leerian el estado de la llamada
# anterior. Esa fue exactamente la causa de que este recorrido fallara con
# "se esperaba 201, se recibio 200" cuando la coleccion si se habia creado.
RESP=""
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
  RESP=${respuesta%$'\n'*}
  # Un fallo de transporte deja el estado en 000 y el motivo en el cuerpo.
  [[ "$ESTADO" =~ ^[0-9]{3}$ ]] || { RESP=$respuesta; ESTADO="000"; }
}

# exigir <esperado> <descripcion>: si el estado de la ULTIMA llamada no es el
# esperado, imprime el cuerpo real y para. Es la diferencia entre "no funciona"
# y saber por que.
exigir() {
  local esperado=$1 descripcion=$2
  if [[ "$ESTADO" != "$esperado" ]]; then
    printf 'FALLO\n'
    printf '\n  Se esperaba HTTP %s en: %s\n' "$esperado" "$descripcion"
    printf '  Se recibio HTTP %s con este cuerpo:\n\n' "${ESTADO:-sin respuesta}"
    printf '%s\n' "$RESP" | python -m json.tool 2>/dev/null \
      || printf '%s\n' "$RESP"
    printf '\n'
    exit 1
  fi
}

# campo "a.b" -> extrae del cuerpo de la ultima respuesta.
campo() { printf '%s' "$RESP" | jget "$1"; }

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
print(json.dumps(json.loads(sys.argv[1])))" "$1"; }

# =============================================================================
titulo "1. Salud de las dos APIs"
# =============================================================================
for par in "user-mgmt:${UM_BASE}" "vault-mgmt:${VM_BASE}"; do
  nombre=${par%%:*}; base=${par#*:}
  paso "${nombre} /health/live"
  ok "$(curl -s -o /dev/null -w '%{http_code}' "${base}/health/live")"

  paso "${nombre} /health/ready"
  api GET "${base}/health/ready"
  ok "$ESTADO" "ready=$(campo ready)"
  if [[ "$ESTADO" != "200" ]]; then
    echo
    echo "  ${nombre} no esta listo. Detalle:"
    nota "$(campo detail)"
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
api GET "${VM}/vault/collections"
ok "$ESTADO" "<- 401 esperado"
exigir 401 "peticion de negocio sin sesion"

[[ -n "$ADMIN_USER" ]] || {
  echo "ERROR: falta VAULT_ADMIN_USER_NAME en .env" >&2; exit 1; }
PASS=$(env_get VAULT_ADMIN_USER_PASS)
[[ -n "$PASS" ]] || {
  echo "ERROR: falta VAULT_ADMIN_USER_PASS en .env" >&2; exit 1; }

paso "POST ${UM_PREFIX}/auth/login (solo contrasena)"
# La contrasena se construye en Python y viaja por --data-binary: no aparece en
# la linea de ordenes ni en el historial.
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
nota "contiene api_session: $(printf '%s' "$RESP" \
  | python -c 'import json,sys;print("api_session" in json.load(sys.stdin))')"

leer_totp "para iniciar sesion"
paso "POST ${UM_PREFIX}/auth/mfa/verify"
api POST "${UM}/auth/mfa/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
  "$CHALLENGE" "$CODIGO")"
CODIGO=''; unset CODIGO
exigir 200 "validacion del codigo TOTP"
SESION=$(campo api_session)
USUARIO=$(campo username)
ROLES=$(campo role_codes)
A="Authorization: Bearer ${SESION}"
ok 200 "sesion establecida"
nota "usuario=${USUARIO}  roles=${ROLES}"

# =============================================================================
titulo "3. Coleccion con esquema tipado (no crea nada en Vault)"
# =============================================================================
paso "POST ${VM_PREFIX}/vault/collections"
api POST "${VM}/vault/collections" "$(python -c "
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
}))" "$COLECCION")"
exigir 201 "creacion de la coleccion ${COLECCION}"
C=$(campo collection_id)
PREFIJO=$(campo physical_prefix)
ok 201 "collection_id=${C}"
nota "nombre logico : $(campo logical_name)"
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
  api POST "${VM}/vault/collections/${C}/records" "$(python -c "
import json,sys
print(json.dumps({'label': sys.argv[1],
                  'values': {'usuario': sys.argv[2], 'password': sys.argv[3]}}))" \
    "$1" "$2" "$3")"
}

paso "POST .../records (primero)"
crear_registro "contribuyente-uno-${SUFIJO}" "demo-uno" "valor-ficticio-1"
exigir 201 "creacion del primer registro"
R1=$(campo record_id)
ok 201 "record_id=${R1}  version=$(campo version)"

paso "POST .../records (segundo)"
crear_registro "contribuyente-dos-${SUFIJO}" "demo-dos" "valor-ficticio-2"
exigir 201 "creacion del segundo registro"
R2=$(campo record_id)
ok 201 "record_id=${R2}  version=$(campo version)"

paso "LIST ${KV_MOUNT}/${PREFIJO} en Vault"
CUANTAS=$(docker compose exec -T vault-service \
  vault kv list -format=json "${KV_MOUNT}/${PREFIJO}" 2>/dev/null \
  | python -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')
ok "--" "${CUANTAS} claves distintas"
[[ "$CUANTAS" == "2" ]] || { echo "FALLO: se esperaban 2 claves en Vault"; exit 1; }
nota "dos registros = dos secretos, cada uno con su propio historial"

paso "GET .../records (listado del catalogo)"
api GET "${VM}/vault/collections/${C}/records"
exigir 200 "listado de registros"
ok 200 "total=$(campo page.total)"
if printf '%s' "$RESP" | grep -q "valor-ficticio"; then
  echo "FALLO: el listado del catalogo contiene valores"; exit 1
fi
nota "el listado NO contiene ningun valor"

# =============================================================================
titulo "5. CAS: la escritura con una version caducada no sobrescribe"
# =============================================================================
CAS_V1='{"expected_version": 1, "values": {"usuario": "demo-uno", "password": "v2-ficticio"}}'

paso "PUT .../records/{id} con expected_version=1"
api PUT "${VM}/vault/collections/${C}/records/${R1}" "$(json "$CAS_V1")"
exigir 200 "reemplazo con el CAS correcto"
ok 200 "version=$(campo version)"

paso "PUT .../records/{id} con expected_version=1 otra vez"
api PUT "${VM}/vault/collections/${C}/records/${R1}" "$(json "$CAS_V1")"
exigir 409 "conflicto de CAS"
ok 409 "code=$(campo code)"
nota "el cambio ajeno NO se sobrescribio"

# =============================================================================
titulo "6. PATCH: omitido conserva, null elimina"
# =============================================================================
paso "PUT .../records/{id} anadiendo rfc"
api PUT "${VM}/vault/collections/${C}/records/${R1}" "$(json '{"expected_version": 2, "values": {"usuario": "demo-uno", "password": "v3-ficticio", "rfc": "XAXX010101000"}}')"
exigir 200 "escritura con los tres campos"
V3=$(campo version)
ok 200 "version=${V3}"

paso "PATCH .../records/{id} con rfc=null"
api PATCH "${VM}/vault/collections/${C}/records/${R1}" "$(python -c "
import json,sys
print(json.dumps({'expected_version': int(sys.argv[1]),
                  'patch': {'password': 'v4-ficticio', 'rfc': None}}))" "$V3")"
exigir 200 "merge patch"
V4=$(campo version)
ok 200 "version=${V4}"

paso "POST .../read (plain) para ver los campos resultantes"
api POST "${VM}/vault/collections/${C}/records/${R1}/read" \
  "$(json '{"delivery": "plain", "reason": "recorrido del README"}')"
exigir 200 "entrega plana"
CAMPOS=$(printf '%s' "$RESP" | python -c '
import json,sys
print(",".join(sorted(json.load(sys.stdin)["delivery"]["values"])))')
ok 200 "campos=${CAMPOS}"
nota "usuario se omitio en el patch y se conserva; rfc llevaba null y ya no esta"
[[ "$CAMPOS" == "password,usuario" ]] || {
  echo "FALLO: se esperaban exactamente password,usuario"; exit 1; }

paso "PATCH .../records/{id} con password=null (obligatorio)"
api PATCH "${VM}/vault/collections/${C}/records/${R1}" "$(python -c "
import json,sys
print(json.dumps({'expected_version': int(sys.argv[1]), 'patch': {'password': None}}))" "$V4")"
exigir 422 "patch que dejaria la tupla invalida"
ok 422 "campo=$(campo context.fields.0.field)"
nota "422 y NO se escribio nada"

# =============================================================================
titulo "7. Entrega: envuelta por defecto, de un solo uso"
# =============================================================================
paso "POST .../read (sin delivery: envuelta)"
api POST "${VM}/vault/collections/${C}/records/${R1}/read" "$(json '{}')"
exigir 200 "entrega envuelta"
WRAP=$(campo delivery.wrap_token)
ok 200 "modo=$(campo delivery.mode)  ttl=$(campo delivery.ttl_seconds)s"
nota "token de ${#WRAP} caracteres; no se imprime ni se guarda"
if printf '%s' "$RESP" | grep -qE "valor-ficticio|v4-ficticio"; then
  echo "FALLO: la entrega envuelta contiene valores"; exit 1
fi

paso "vault unwrap (primera vez)"
CAMPOS=$(docker compose exec -T -e VAULT_TOKEN= vault-service \
  vault unwrap -format=json "$WRAP" 2>/dev/null \
  | python -c '
import json,sys
try:
    d = json.load(sys.stdin)["data"]["data"]
    print(",".join(sorted(d["values"])) + "  esquema=v" + str(d["schema_version"]))
except Exception:
    print("")' || true)
if [[ -n "$CAMPOS" ]]; then
  ok "--" "campos=${CAMPOS}"
  nota "solo los NOMBRES: ningun valor se imprime"
else
  ok "--" "no se pudo desenvolver (revisalo a mano)"
fi

paso "vault unwrap (segunda vez)"
SEGUNDO=$(docker compose exec -T -e VAULT_TOKEN= vault-service \
  vault unwrap "$WRAP" 2>&1 || true)
if printf '%s' "$SEGUNDO" | grep -qiE "wrapping token is not valid|does not exist|invalid|expired"; then
  ok "--" "rechazado: es de UN SOLO USO"
else
  ok "--" "ATENCION: se pudo desenvolver dos veces"
  printf '%s\n' "$SEGUNDO" | tail -2 | sed 's/^/      /'
fi
WRAP=''; unset WRAP

# =============================================================================
titulo "8. Renombrar conserva UUID, path fisico e historial"
# =============================================================================
NUEVO="sat/datos-${SUFIJO}"
paso "PATCH .../collections/{id} con otro nombre logico"
api PATCH "${VM}/vault/collections/${C}" "$(python -c "
import json,sys
print(json.dumps({'logical_name': sys.argv[1]}))" "$NUEVO")"
exigir 200 "renombrado de la coleccion"
ok 200 "nombre=$(campo logical_name)"
[[ "$(campo collection_id)" == "$C" ]] || {
  echo "FALLO: el collection_id cambio"; exit 1; }
[[ "$(campo physical_prefix)" == "$PREFIJO" ]] || {
  echo "FALLO: el path fisico cambio"; exit 1; }
nota "mismo collection_id y mismo path fisico"

paso "GET .../records/{id}/metadata (historial)"
api GET "${VM}/vault/collections/${C}/records/${R1}/metadata"
exigir 200 "metadata del registro"
VERSIONES=$(printf '%s' "$RESP" | python -c '
import json,sys
print(",".join(str(v["version"]) for v in json.load(sys.stdin)["versions"]))')
ok 200 "versiones=${VERSIONES}"
nota "el historial sobrevive al renombrado"

# =============================================================================
titulo "9. Esquema: compatible crea version, incompatible responde 409"
# =============================================================================
paso "PUT .../schema anadiendo un campo opcional"
api PUT "${VM}/vault/collections/${C}/schema" "$(json '{
  "fields": [
    {"name": "usuario",  "type": "string", "required": true,  "max_length": 64},
    {"name": "password", "type": "string", "required": true, "sensitive": true, "max_length": 256},
    {"name": "rfc",      "type": "string", "required": false, "max_length": 13},
    {"name": "notas",    "type": "string", "required": false, "max_length": 500}
  ],
  "note": "se anade notas opcional"
}')"
exigir 200 "nueva version de esquema compatible"
ok 200 "version=$(campo current_schema_version)  compatible=$(campo compatibility.compatible)"

paso "PUT .../schema quitando un campo"
api PUT "${VM}/vault/collections/${C}/schema" "$(json '{
  "fields": [{"name": "usuario", "type": "string", "required": true, "max_length": 64}]
}')"
exigir 409 "esquema incompatible"
ok 409 "code=$(campo code)"
nota "motivo: $(campo context.breaking_changes.0.reason)"
nota "registros afectados: $(campo context.records_affected)"
if printf '%s' "$RESP" | grep -q "ficticio"; then
  echo "FALLO: el diagnostico contiene valores"; exit 1
fi
nota "el diagnostico habla de campos, nunca de valores"

# =============================================================================
titulo "10. Capacidad efectiva: rol de aplicacion Y ACL de Vault"
# =============================================================================
paso "POST ${VM_PREFIX}/vault/access-check"
api POST "${VM}/vault/access-check" "$(python -c "
import json,sys
print(json.dumps({'collection_id': sys.argv[1], 'record_id': sys.argv[2],
                  'operations': ['record_read','record_replace','record_purge']}))" \
  "$C" "$R1")"
exigir 200 "comprobacion de capacidad"
ok 200 "roles=$(campo your_roles)"
printf '%s' "$RESP" | python -c '
import json,sys
d = json.load(sys.stdin)
for o in d["operations"]:
    linea = "      {:18} rol={}".format(o["operation"], o["allowed_by_application_role"])
    if o.get("reason"):
        linea += "  ({})".format(o["reason"])
    print(linea)
for ruta, caps in d["vault_capabilities"].items():
    print("      vault: {} -> {}".format(ruta, caps))'

# =============================================================================
titulo "11. Los tres estados de una version"
# =============================================================================
paso "POST .../versions/delete (soft-delete de la version 1)"
api POST "${VM}/vault/collections/${C}/records/${R1}/versions/delete" \
  "$(json '{"versions": [1]}')"
exigir 204 "soft-delete de una version historica"
ok 204 "reversible con undelete"

paso "GET .../records/{id} (el registro sigue activo)"
api GET "${VM}/vault/collections/${C}/records/${R1}"
exigir 200 "resumen del registro"
ok 200 "state=$(campo state)"
nota "borrar una version historica NO deja el registro borrado"

paso "GET .../records/{id}/metadata (estados por version)"
api GET "${VM}/vault/collections/${C}/records/${R1}/metadata"
exigir 200 "metadata con los estados"
printf '%s' "$RESP" | python -c '
import json,sys
for v in json.load(sys.stdin)["versions"]:
    print("      version {:<3} {}".format(v["version"], v["state"]))'

# =============================================================================
titulo "12. Purga: admin + confirmacion + MFA reciente"
# =============================================================================
paso "POST .../records/{id}/purge SIN prueba de MFA"
api POST "${VM}/vault/collections/${C}/records/${R2}/purge" \
  "$(json '{"confirm": "PURGE"}')"
exigir 403 "purga sin prueba de MFA"
ok 403 "code=$(campo code)"

pedir_prueba() {
  local operacion=$1 recurso=$2 motivo=$3
  local pass cuerpo
  pass=$(env_get VAULT_ADMIN_USER_PASS)
  paso "POST ${UM_PREFIX}/auth/mfa/step-up"
  cuerpo=$(python -c "
import json,sys
print(json.dumps({'password': sys.argv[1], 'operation': sys.argv[2],
                  'collection_id': sys.argv[3], 'resource_ids': [sys.argv[4]]}))" \
    "$pass" "$operacion" "$C" "$recurso")
  pass=''; unset pass
  api POST "${UM}/auth/mfa/step-up" "$cuerpo"
  cuerpo=''; unset cuerpo
  exigir 200 "paso 1 de la reautenticacion (${operacion})"
  local desafio
  desafio=$(campo challenge_id)
  ok 200 "desafio recibido, SIN prueba todavia"

  leer_totp "$motivo"
  paso "POST ${UM_PREFIX}/auth/mfa/step-up/verify"
  api POST "${UM}/auth/mfa/step-up/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" \
    "$desafio" "$CODIGO")"
  CODIGO=''; unset CODIGO
  exigir 200 "paso 2 de la reautenticacion (${operacion})"
  P=$(campo mfa_proof)
  ok 200 "prueba emitida (un solo uso)"
  nota "operacion=$(campo operation)  recursos=1"
}

echo
echo "  Para purgar hace falta reautenticarse. Necesitas un codigo TOTP NUEVO:"
echo "  si el autenticador aun muestra el anterior, espera a que cambie."
pedir_prueba record_purge "$R2" "para autorizar la purga del registro"

paso "POST .../records/{id}/purge CON la prueba"
api POST "${VM}/vault/collections/${C}/records/${R2}/purge" \
  "$(json '{"confirm": "PURGE", "reason": "recorrido del README"}')"
exigir 204 "purga del segundo registro"
ok 204 "datos y metadata destruidos"

paso "POST .../records/{id}/purge reusando la MISMA prueba"
api POST "${VM}/vault/collections/${C}/records/${R1}/purge" \
  "$(json '{"confirm": "PURGE"}')"
exigir 403 "reutilizacion de la prueba"
ok 403 "code=$(campo code)"
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
api GET "${VM}/vault/collections/${C}/records/${R2}"
exigir 200 "resumen del registro purgado"
ok 200 "state=$(campo state)"
nota "en el catalogo queda como 'destroyed': distingue destruido de inexistente"

# =============================================================================
titulo "13. Auditoria y limpieza"
# =============================================================================
paso "GET ${VM_PREFIX}/vault/audit"
api GET "${VM}/vault/audit?collection_id=${C}&limit=100"
exigir 200 "historial de auditoria"
ok 200 "lineas=$(campo page.total)"
printf '%s' "$RESP" | python -c '
import json,sys
for i in json.load(sys.stdin)["items"][:8]:
    print("      {}  {:7} {:26} {}".format(
        i["occurred_at"][11:19], i["actor_kind"], i["action"], i["outcome"]))'
if printf '%s' "$RESP" | grep -q "ficticio"; then
  echo "FALLO: la auditoria contiene valores"; exit 1
fi
nota "la auditoria no contiene ningun valor ni wrapping token"

if [[ "$KEEP" == true ]]; then
  echo
  echo "  --keep: la coleccion se conserva."
else
  echo
  echo "  Limpieza de fixtures: se purgara la coleccion de prueba."
  echo "  Necesitas un TERCER codigo TOTP, nuevo."
  pedir_prueba collection_purge_batch "$R1" "para purgar la coleccion"

  paso "POST .../collections/{id}/purge"
  api POST "${VM}/vault/collections/${C}/purge" \
    "$(json '{"confirm": "PURGE", "reason": "limpieza del recorrido"}')"
  exigir 204 "purga de la coleccion"
  ok 204 "coleccion purgada"
  P=''; unset P

  paso "GET .../collections/{id}"
  api GET "${VM}/vault/collections/${C}"
  exigir 200 "estado final de la coleccion"
  ok 200 "state=$(campo state)"
  nota "la fila permanece como auditoria minima"
fi

paso "POST ${UM_PREFIX}/auth/logout"
api POST "${UM}/auth/logout"
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
FIN

if [[ "$KEEP" == true ]]; then
  cat <<FIN

  La coleccion sigue viva. Un script no puede dejar variables en tu shell, asi
  que para las comprobaciones manuales del README (seccion 7) copia esto:

    C=${C}
    R1=${R1}
    PREFIJO=${PREFIJO}

  Y para purgarla cuando acabes hace falta un step-up con
  operation=collection_purge_batch y resource_ids=[${R1}].
FIN
else
  cat <<FIN

  Fixtures limpiados: la coleccion ${NUEVO} esta purgada y su fila permanece
  como auditoria minima. Para repetir el recorrido con una coleccion nueva,
  vuelve a lanzar el script.
FIN
fi

cat <<'FIN'

  Lo que este recorrido NO cubre:
    - el contrato de maquina del crawler, que necesita role_id y secret_id:
        bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
        python scripts/vault_mgmt/crawler_client.py --help
    - el fallo parcial y su reconciliacion:
        bash scripts/vault_mgmt/reconcile-operations.sh
FIN
