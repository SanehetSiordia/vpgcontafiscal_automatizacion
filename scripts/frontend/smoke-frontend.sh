#!/usr/bin/env bash
# Recorrido NO interactivo del frontend ya publicado.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/smoke-frontend.sh
#   bash scripts/frontend/smoke-frontend.sh --cacert "$(mkcert -CAROOT)/rootCA.pem"
#
# No pide contrasenas, no pide TOTP y no provisiona nada: comprueba lo que se
# puede comprobar sin credenciales. El login real con un codigo de verdad es la
# comprobacion MANUAL que describe readme/etapa-5-1-frontend.md.
#
# Distingue dos cosas que suelen confundirse:
#   * el frontend sirve y reenvia bien  (esto es lo que se prueba aqui);
#   * user-mgmt esta listo              (depende de Vault desbloqueado).
# Con Vault sellado, el backend responde 503 y eso NO es un fallo del frontend:
# el guion lo dice con esas palabras.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta .env" >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

CACERT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cacert) CACERT="${2:?falta la ruta del CA}"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "ERROR: opcion desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

HTTPS=$(env_get FRONTEND_HTTPS_ENABLED); HTTPS=${HTTPS:-false}
ALCANCE=$(env_get FRONTEND_ACCESS_SCOPE); ALCANCE=${ALCANCE:-local}
HOST=$(env_get FRONTEND_PUBLIC_HOST);     HOST=${HOST:-localhost}
P_HTTP=$(env_get FRONTEND_HTTP_PORT);     P_HTTP=${P_HTTP:-8080}
P_HTTPS=$(env_get FRONTEND_HTTPS_PORT);   P_HTTPS=${P_HTTPS:-8443}
NETWORK=$(env_get DOCKER_NETWORK_NAME);   NETWORK=${NETWORK:-network-service}
CONTENEDOR=$(env_get FRONTEND_CONTAINER_NAME); CONTENEDOR=${CONTENEDOR:-vpg-frontend}

CURL=(curl --silent --show-error --max-time 10)
if [[ "$HTTPS" == true ]]; then
  BASE="https://${HOST}:${P_HTTPS}"
  [[ -n "$CACERT" ]] && CURL+=(--cacert "$CACERT")
else
  BASE="http://${HOST}:${P_HTTP}"
fi

FALLOS=0
ok()    { printf '   OK     %s\n' "$1"; }
nota()  { printf '   ...    %s\n' "$1"; }
falla() { printf '   FALLO  %s\n' "$1" >&2; FALLOS=$((FALLOS + 1)); }

codigo() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || printf '000'; }
cuerpo() { "${CURL[@]}" "$@" 2>/dev/null || true; }

echo "== Recorrido del frontend en ${BASE}  (alcance ${ALCANCE}, HTTPS ${HTTPS})"
echo

# --- 1. contenedor ----------------------------------------------------------
echo "-- 1. Contenedor"
estado=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}sin-healthcheck{{end}}' \
         "$CONTENEDOR" 2>/dev/null | tr -d '\r' || true)
case "$estado" in
  healthy) ok "$CONTENEDOR healthy segun su propio healthcheck" ;;
  starting) nota "$CONTENEDOR todavia arrancando" ;;
  "") falla "no existe el contenedor $CONTENEDOR: ejecuta 'make all'" ;;
  *) falla "$CONTENEDOR en estado '$estado'. Log: docker compose logs frontend-service" ;;
esac

# --- 2. salud propia --------------------------------------------------------
echo
echo "-- 2. Salud del frontend (no finge la del backend)"
salud=$(cuerpo "${BASE}/healthz")
if grep -q '"service":"frontend-service"' <<< "$salud"; then
  ok "/healthz responde y se identifica como el frontend"
else
  falla "/healthz no responde lo esperado: ${salud:0:120}"
fi
grep -q 'user_mgmt\|backend' <<< "$salud" &&
  falla "/healthz habla del backend: no debe fingir su salud" ||
  ok "/healthz no afirma nada sobre user-mgmt"

# --- 3. documento y rutas profundas -----------------------------------------
echo
echo "-- 3. Documento y fallback de la SPA"
for ruta in / /login /mfa /inicio /configuracion-totp /ruta/que/no/existe; do
  c=$(codigo "${BASE}${ruta}")
  if [[ "$c" == 200 ]]; then ok "GET ${ruta} -> 200 (lo resuelve React Router)"
  else falla "GET ${ruta} -> ${c}, se esperaba 200 por el fallback"; fi
done
doc=$(cuerpo "${BASE}/configuracion-totp")
grep -q 'id="raiz"' <<< "$doc" && ok "la ruta profunda devuelve el documento de la SPA" ||
  falla "la ruta profunda no devuelve index.html"

# --- 4. el prefijo del proxy no se duplica ni se pierde ---------------------
echo
echo "-- 4. Reescritura del prefijo /api/user_mgmt/v1 -> /user_mgmt/v1"
me=$(cuerpo -o - -w '' "${BASE}/api/user_mgmt/v1/auth/me")
if grep -q '"request_id"' <<< "$me"; then
  ok "GET /auth/me llega a la API (responde su ErrorDetail con request_id)"
else
  falla "GET /auth/me no llego a la API: ${me:0:160}"
fi
c=$(codigo "${BASE}/api/user_mgmt/v1/auth/me")
case "$c" in
  401) ok "sin Bearer responde 401: el prefijo es exacto y la ruta existe" ;;
  404) falla "404: el prefijo se esta duplicando o perdiendo en la reescritura" ;;
  503) nota "503: la API esta viva pero no lista (Vault sellado). El prefijo es correcto" ;;
  *)   falla "respuesta inesperada ($c) en /auth/me" ;;
esac
# Una ruta que NO existe en el backend debe dar el 404 del BACKEND (con su
# cuerpo), no el 404 del frontend ni index.html.
inv=$(cuerpo "${BASE}/api/user_mgmt/v1/esta-ruta-no-existe")
grep -q 'id="raiz"' <<< "$inv" &&
  falla "una ruta de API inexistente devuelve index.html" ||
  ok "una ruta de API inexistente no devuelve index.html"

# --- 5. lo que no se reenvia -------------------------------------------------
echo
echo "-- 5. Lo que el proxy NO reenvia"
for ruta in /api/internal/v1/crawler/provisioning/claim \
            /api/vault_mgmt/v1/collections \
            /api/health/ready \
            /api/user_mgmt/v1/../internal/v1/vault-mgmt/session; do
  c=$(codigo "${BASE}${ruta}")
  if [[ "$c" == 404 ]]; then ok "${ruta} -> 404 del frontend"
  else falla "${ruta} -> ${c}: deberia quedar fuera del proxy"; fi
done
tipo=$("${CURL[@]}" -o /dev/null -w '%{content_type}' "${BASE}/api/internal/v1/x" 2>/dev/null || true)
grep -q json <<< "$tipo" && ok "ese 404 es JSON, no una pagina HTML" ||
  falla "el 404 de API no es JSON (tipo: $tipo)"

# --- 6. sin contenido mixto -------------------------------------------------
echo
echo "-- 6. Origen unico: ni contenido mixto ni llamadas a terceros"
assets=$(cuerpo "${BASE}/" | grep -o '/assets/[^"]*' | sort -u)
mezcla=0
for a in $assets; do
  if cuerpo "${BASE}${a}" | grep -qE 'https?://(?!localhost)[a-z0-9.-]+' 2>/dev/null; then
    # grep sin PCRE en algunos entornos: se repite la busqueda simple.
    if cuerpo "${BASE}${a}" | grep -oE 'http://[a-z0-9.-]+' | grep -vq 'localhost\|127.0.0.1'; then
      falla "el asset ${a} referencia un origen http:// externo"
      mezcla=1
    fi
  fi
done
[[ "$mezcla" == 0 ]] && ok "los assets no referencian ningun origen http:// externo"
cuerpo "${BASE}/" | grep -q 'src="/assets/' && ok "el documento carga sus scripts por ruta relativa" ||
  falla "el documento no carga los scripts por ruta relativa"

# --- 7. DNS interno del upstream --------------------------------------------
echo
echo "-- 7. Resolucion del upstream dentro de la red ${NETWORK}"
ip=$(docker run --rm --network "$NETWORK" busybox:1.37 nslookup user-mgmt-service 2>/dev/null |
     sed -n 's/^Address: *//p' | tail -n 1 | tr -d '\r')
if [[ -n "$ip" ]]; then
  ok "user-mgmt-service resuelve por DNS interno ($ip)"
  nota "Nginx lo resuelve EN CADA peticion (resolver 127.0.0.11): si se recrea"
  nota "el contenedor y cambia de IP, el proxy no se queda con la vieja."
else
  nota "no se pudo comprobar el DNS interno (busybox no disponible); se omite"
fi

# --- 8. redireccion en modo HTTPS -------------------------------------------
if [[ "$HTTPS" == true ]]; then
  echo
  echo "-- 8. Listener HTTP en modo HTTPS: solo redirige"
  destino=$(curl --silent --max-time 10 -o /dev/null -w '%{redirect_url}' \
            "http://${HOST}:${P_HTTP}/inicio" || true)
  [[ "$destino" == "https://${HOST}:${P_HTTPS}/inicio" ]] &&
    ok "redirige conservando la ruta: $destino" ||
    falla "la redireccion no conserva ruta o puerto: '$destino'"
fi

echo
if [[ "$FALLOS" -gt 0 ]]; then
  echo "== $FALLOS comprobacion(es) en rojo." >&2
  exit 1
fi
echo "== Recorrido completado sin fallos."
echo
echo "   Lo que esto NO demuestra, y sigue siendo manual:"
echo "     * que un codigo TOTP real abra sesion;"
echo "     * que Google Authenticator acepte el QR de inscripcion;"
echo "     * que la CSP no se viole en el navegador (consola abierta)."
echo "   Esta en readme/etapa-5-1-frontend.md."
