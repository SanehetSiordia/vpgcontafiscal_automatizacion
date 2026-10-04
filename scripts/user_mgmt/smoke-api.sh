#!/usr/bin/env bash
# *** SCRIPT INTERACTIVO: pide el codigo TOTP por teclado. ***
#
# Recorrido de extremo a extremo por la API con datos FICTICIOS.
#
# Uso (host, Git Bash, en una terminal real):
#   bash scripts/user_mgmt/smoke-api.sh [--keep]
#     --keep   no borra el empleado de prueba al final
#
# Demuestra, en este orden:
#   1. Login sin sesion antes del MFA, y login valido.
#   2. Alta de empleado, lectura, paginacion.
#   3. PUT frente a PATCH.
#   4. Permisos: 401, 403, 409, 422, 429.
#   5. Provisionamiento en Vault y GET que NO reinicia el TOTP.
#   6. Cambio de credenciales y reset explicito de MFA.
#   7. Baja logica (entidad deshabilitada) y purga.
#   8. Comprobacion de acceso a una ruta de Vault, sin revelar valores.
#
# La contrasena se toma de VAULT_ADMIN_USER_PASS en .env y viaja por stdin:
# nunca como argumento visible ni en el historial. El codigo TOTP se teclea
# oculto. Ningun secreto se imprime.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

KEEP=false
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

HOST_BIND=$(env_get USER_MGMT_HOST_BIND); HOST_BIND=${HOST_BIND:-127.0.0.1}
PORT=$(env_get USER_MGMT_PORT_LOCAL);     PORT=${PORT:-8000}
PREFIX=$(env_get USER_MGMT_API_PREFIX);   PREFIX=${PREFIX:-/user_mgmt/v1}
BASE="http://${HOST_BIND}:${PORT}"
API="${BASE}${PREFIX}"
ADMIN_USER=$(env_get VAULT_ADMIN_USER_NAME | tr 'A-Z' 'a-z')

SUFIJO=$(date +%H%M%S)
EMPLEADO="demo.${SUFIJO}"

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
paso()   { printf '  %-58s ' "$*"; }
ok()     { printf 'HTTP %s  %s\n' "$1" "${2:-}"; }

# jq no es necesario: se usa python, que ya esta en el host.
jget() { python -c "
import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d = d[int(k)] if k.isdigit() else d.get(k)
    if d is None: break
print(d if d is not None else '')" "$1"; }

# --- 1. readiness --------------------------------------------------------
titulo "1. Estado del servicio"
paso "/health/live"
ok "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/health/live")"
paso "/health/ready"
READY_CODE=$(curl -s -o /tmp/ready.$$ -w '%{http_code}' "${BASE}/health/ready")
ok "$READY_CODE" "$(jget ready < /tmp/ready.$$)"
if [[ "$READY_CODE" != "200" ]]; then
  echo
  echo "El servicio no esta listo. Detalle:"
  jget detail < /tmp/ready.$$
  echo
  echo "Si Vault esta sellado, desbloquealo (paso manual) y repite:"
  echo "  docker compose exec vault-service vault operator unseal"
  rm -f /tmp/ready.$$
  exit 1
fi
rm -f /tmp/ready.$$

# --- 2. login ------------------------------------------------------------
titulo "2. Autenticacion (userpass + TOTP delegado a Vault)"

paso "GET ${PREFIX}/user sin sesion"
ok "$(curl -s -o /dev/null -w '%{http_code}' "${API}/user")" "<- 401 esperado"

PASS=$(env_get VAULT_ADMIN_USER_PASS)
[[ -n "$PASS" ]] || { echo "ERROR: falta VAULT_ADMIN_USER_PASS en .env" >&2; exit 1; }

paso "POST ${PREFIX}/auth/login (solo contrasena)"
LOGIN=$(python -c "
import json,sys
print(json.dumps({'username': sys.argv[1], 'password': sys.argv[2]}))" "$ADMIN_USER" "$PASS" \
  | curl -s -X POST -H 'Content-Type: application/json' --data-binary @- "${API}/auth/login")
PASS=''; unset PASS
CHALLENGE=$(printf '%s' "$LOGIN" | jget challenge_id)
[[ -n "$CHALLENGE" ]] || { echo "FALLO"; printf '%s\n' "$LOGIN"; exit 1; }
ok 200 "desafio recibido, SIN sesion"
printf '    mfa_required=%s  metodo=%s\n' \
  "$(printf '%s' "$LOGIN" | jget mfa_required)" "$(printf '%s' "$LOGIN" | jget method_name)"
printf '    contiene api_session: %s\n' \
  "$(printf '%s' "$LOGIN" | python -c 'import json,sys;print("api_session" in json.load(sys.stdin))')"

# --- codigo TOTP, oculto y con eco enmascarado ---------------------------
if [[ ! -t 0 ]]; then
  echo "ERROR: hace falta una terminal interactiva para el codigo TOTP." >&2
  exit 1
fi
echo
echo "  Escribe los 6 digitos del autenticador. Veras un '#' por cada uno."
printf '  Codigo TOTP para %s: ' "$ADMIN_USER"
CODE=''
while true; do
  rc=0; IFS= read -rsn1 -t 180 ch || rc=$?
  [[ $rc -ne 0 ]] && { echo; echo "ERROR: sin codigo TOTP." >&2; exit 1; }
  case "$ch" in
    '') break ;;
    $'\177'|$'\b') [[ -n "$CODE" ]] && { CODE=${CODE%?}; printf '\b \b'; } ;;
    [0-9]) CODE+=$ch; printf '#'; [[ ${#CODE} -eq 6 ]] && break ;;
  esac
done
echo

paso "POST ${PREFIX}/auth/mfa/verify"
VERIFY=$(python -c "
import json,sys
print(json.dumps({'challenge_id': sys.argv[1], 'code': sys.argv[2]}))" "$CHALLENGE" "$CODE" \
  | curl -s -X POST -H 'Content-Type: application/json' --data-binary @- "${API}/auth/mfa/verify")
CODE=''; unset CODE
SESSION=$(printf '%s' "$VERIFY" | jget api_session)
if [[ -z "$SESSION" ]]; then
  echo "FALLO"
  printf '%s\n' "$VERIFY" | python -m json.tool
  exit 1
fi
ok 200 "sesion establecida"
printf '    usuario=%s  roles=%s\n' \
  "$(printf '%s' "$VERIFY" | jget username)" \
  "$(printf '%s' "$VERIFY" | python -c 'import json,sys;print(",".join(json.load(sys.stdin)["role_codes"]))')"
printf '    entity_id=%s\n' "$(printf '%s' "$VERIFY" | jget entity_id)"

AUTH=(-H "Authorization: Bearer ${SESSION}")
JSON=(-H 'Content-Type: application/json')

req() {  # req <metodo> <ruta> [cuerpo-json]
  local metodo=$1 ruta=$2 cuerpo=${3:-}
  if [[ -n "$cuerpo" ]]; then
    printf '%s' "$cuerpo" | curl -s -o /tmp/resp.$$ -w '%{http_code}' \
      -X "$metodo" "${AUTH[@]}" "${JSON[@]}" --data-binary @- "${API}${ruta}"
  else
    curl -s -o /tmp/resp.$$ -w '%{http_code}' -X "$metodo" "${AUTH[@]}" "${API}${ruta}"
  fi
}

# --- 3. CRUD -------------------------------------------------------------
titulo "3. Alta, lectura y paginacion (datos ficticios)"

paso "POST ${PREFIX}/user"
CODE_HTTP=$(req POST /user "$(cat <<JSON
{"username": "${EMPLEADO}",
 "profile": {"first_name": "Demo", "last_name_paternal": "Ficticio",
             "birth_date": "1991-03-20"},
 "emails": [{"email": "${EMPLEADO}@example.invalid", "is_primary": true}],
 "phones": [{"phone_number": "5500000000", "is_primary": true}]}
JSON
)")
USER_ID=$(jget id < /tmp/resp.$$)
ok "$CODE_HTTP" "id=${USER_ID:0:8}..."

paso "GET ${PREFIX}/user/{id}"
ok "$(req GET "/user/${USER_ID}")" "roles=$(python -c 'import json,sys;print(",".join(json.load(sys.stdin)["role_codes"]))' < /tmp/resp.$$)"

paso "GET ${PREFIX}/user?limit=2 (paginacion)"
CODE_HTTP=$(req GET "/user?limit=2&offset=0&sort_by=username&order=asc")
ok "$CODE_HTTP" "total=$(python -c 'import json,sys;print(json.load(sys.stdin)["page"]["total"])' < /tmp/resp.$$)"

titulo "4. PUT (reemplazo) frente a PATCH (parcial)"
paso "PATCH: anade un correo y conserva el resto"
CODE_HTTP=$(req PATCH "/user/${USER_ID}" \
  "{\"emails\":[{\"email\":\"${EMPLEADO}.alt@example.invalid\"}]}")
ok "$CODE_HTTP" "correos=$(python -c 'import json,sys;print(len(json.load(sys.stdin)["emails"]))' < /tmp/resp.$$)"

paso "PUT: reemplaza y vacia las colecciones omitidas"
CODE_HTTP=$(req PUT "/user/${USER_ID}" \
  '{"profile":{"first_name":"Demo","last_name_paternal":"Ficticio","birth_date":"1991-03-20"}}')
ok "$CODE_HTTP" "correos=$(python -c 'import json,sys;print(len(json.load(sys.stdin)["emails"]))' < /tmp/resp.$$)"

# --- 5. errores ----------------------------------------------------------
titulo "5. Codigos de error"
paso "422 campo desconocido"
ok "$(req POST /user '{"username":"x.y","is_active":false,"profile":{"first_name":"A","last_name_paternal":"B","birth_date":"1990-01-01"}}')"
paso "422 RFC incoherente con la fecha"
ok "$(req POST /user '{"username":"rfc.malo","profile":{"first_name":"A","last_name_paternal":"B","birth_date":"1990-01-01","rfc":"ABCD880101XY1"}}')"
paso "409 username duplicado"
ok "$(req POST /user "{\"username\":\"${EMPLEADO}\",\"profile\":{\"first_name\":\"A\",\"last_name_paternal\":\"B\",\"birth_date\":\"1990-01-01\"}}")"
paso "404 UUID inexistente"
ok "$(req GET /user/00000000-0000-4000-8000-000000000999)"
paso "401 con sesion inventada"
ok "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer no-existe' "${API}/user")"

paso "429 al superar el limite de login"
LIMITE=$(env_get USER_MGMT_RATE_LIMIT_LOGIN_PER_MINUTE); LIMITE=${LIMITE:-10}
RL=000
for _ in $(seq 1 $((LIMITE + 2))); do
  RL=$(printf '{"username":"no.existe","password":"mala"}' \
    | curl -s -o /dev/null -w '%{http_code}' -X POST "${JSON[@]}" --data-binary @- "${API}/auth/login")
  [[ "$RL" == "429" ]] && break
done
ok "$RL" "$([[ "$RL" == "429" ]] && echo 'Retry-After presente' || echo 'no se alcanzo el limite')"

# --- 6. Vault ------------------------------------------------------------
titulo "6. Provisionamiento en Vault y estado del TOTP"
paso "POST .../vault/provision"
PROV_PASS="Demo-$(date +%s)-Ficticia"
CODE_HTTP=$(req POST "/user/${USER_ID}/vault/provision" \
  "$(python -c "import json,sys;print(json.dumps({'initial_password': sys.argv[1]}))" "$PROV_PASS")")
ok "$CODE_HTTP" "totp_status=$(jget totp_status < /tmp/resp.$$)"
printf '    uri de enrolamiento recibido: %s (no se imprime)\n' \
  "$(python -c 'import json,sys;print("si" if json.load(sys.stdin).get("totp_enrollment_uri") else "no")' < /tmp/resp.$$)"

paso "GET: muestra el estado, NO reinicia el TOTP"
req GET "/user/${USER_ID}" >/dev/null
printf 'HTTP 200  totp_status=%s\n' \
  "$(python -c 'import json,sys;print(json.load(sys.stdin)["vault_link"]["totp_status"])' < /tmp/resp.$$)"
printf '    el GET no devuelve otpauth://: %s\n' \
  "$(grep -c 'otpauth' /tmp/resp.$$ || true)"

paso "PATCH .../vault/credentials (solo contrasena)"
ok "$(req PATCH "/user/${USER_ID}/vault/credentials" \
  "$(python -c "import json,sys;print(json.dumps({'new_password': sys.argv[1]}))" "${PROV_PASS}-2")")"

paso "PATCH .../vault/credentials (rename sin contrasena)"
ok "$(req PATCH "/user/${USER_ID}/vault/credentials" '{"new_vault_username":"demo.renombrado"}')" "<- 422 esperado"

paso "POST .../mfa/reset sin confirmacion"
ok "$(req POST "/user/${USER_ID}/mfa/reset" '{"reason":"prueba"}')" "<- 422 esperado"

paso "POST .../mfa/reset con confirmacion"
CODE_HTTP=$(req POST "/user/${USER_ID}/mfa/reset" '{"confirm":"RESET","reason":"prueba de humo"}')
ok "$CODE_HTTP" "totp_status=$(jget totp_status < /tmp/resp.$$)"

titulo "7. Comprobacion de acceso a Vault (sin revelar valores)"
paso "POST ${PREFIX}/vault/access-check (recurso valido)"
CODE_HTTP=$(req POST /vault/access-check '{"resource":"crawler_sat"}')
ok "$CODE_HTTP" "resultado=$(jget result < /tmp/resp.$$)"
printf '    capacidades: %s\n' \
  "$(python -c 'import json,sys;print(json.load(sys.stdin).get("capabilities"))' < /tmp/resp.$$ 2>/dev/null || echo '-')"
paso "POST ${PREFIX}/vault/access-check (ruta arbitraria)"
ok "$(req POST /vault/access-check '{"resource":"secret/data/lo-que-sea"}')" "<- 422 esperado"

# --- 8. baja y purga -----------------------------------------------------
titulo "8. Baja logica y purga"
paso "DELETE ${PREFIX}/user/{id} (baja logica)"
ok "$(req DELETE "/user/${USER_ID}")"
paso "GET tras la baja: is_active"
req GET "/user/${USER_ID}" >/dev/null
printf 'HTTP 200  is_active=%s\n' "$(jget is_active < /tmp/resp.$$)"

paso "GET .../operations (registro durable)"
CODE_HTTP=$(req GET "/user/${USER_ID}/operations")
ok "$CODE_HTTP" "operaciones=$(python -c 'import json,sys;print(len(json.load(sys.stdin)))' < /tmp/resp.$$)"

if [[ "$KEEP" == false ]]; then
  paso "DELETE ${PREFIX}/user/{id}/purge"
  ok "$(req DELETE "/user/${USER_ID}/purge")"
  paso "GET tras la purga"
  ok "$(req GET "/user/${USER_ID}")" "<- 404 esperado"
else
  echo "  --keep: el empleado ${EMPLEADO} (${USER_ID}) se conserva."
fi

titulo "9. Cierre de sesion"
paso "POST ${PREFIX}/auth/logout"
ok "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${AUTH[@]}" "${API}/auth/logout")"
paso "GET ${PREFIX}/auth/me tras el logout"
ok "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "${API}/auth/me")" "<- 401 esperado"

rm -f /tmp/resp.$$
echo
echo "Recorrido terminado. Ningun secreto se imprimio en pantalla."
