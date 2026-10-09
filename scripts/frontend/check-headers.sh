#!/usr/bin/env bash
# Comprueba con curl las cabeceras que exige la etapa 5.1, incluidas las de las
# respuestas de ERROR del proxy, que es donde mas se olvidan.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/check-headers.sh
#   bash scripts/frontend/check-headers.sh --cacert "$(mkcert -CAROOT)/rootCA.pem"
#
# El modo (HTTP o HTTPS), el puerto y el nombre publico se leen de .env, para
# comprobar lo que de verdad esta publicado y no una suposicion.
#
# En HTTPS se valida el certificado de verdad. Con --cacert se usa esa CA; sin
# ella se usa el almacen del sistema. NO se usa 'curl -k' en ningun caso: pasar
# con -k no acredita que el navegador vaya a aceptar nada.
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
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "ERROR: opcion desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

HTTPS=$(env_get FRONTEND_HTTPS_ENABLED); HTTPS=${HTTPS:-false}
HOST=$(env_get FRONTEND_PUBLIC_HOST);    HOST=${HOST:-localhost}
PUERTO_HTTP=$(env_get FRONTEND_HTTP_PORT);   PUERTO_HTTP=${PUERTO_HTTP:-8080}
PUERTO_HTTPS=$(env_get FRONTEND_HTTPS_PORT); PUERTO_HTTPS=${PUERTO_HTTPS:-8443}
PREFIJO=$(env_get USER_MGMT_API_PREFIX);     PREFIJO=${PREFIJO:-/user_mgmt/v1}

CURL=(curl --silent --show-error --max-time 10)
if [[ "$HTTPS" == true ]]; then
  BASE="https://${HOST}:${PUERTO_HTTPS}"
  [[ -n "$CACERT" ]] && CURL+=(--cacert "$CACERT")
else
  BASE="http://${HOST}:${PUERTO_HTTP}"
fi

echo "== Cabeceras de ${BASE}  (modo HTTPS: ${HTTPS})"
[[ "$HTTPS" == true && -z "$CACERT" ]] &&
  echo "   (sin --cacert: se valida contra el almacen del sistema; mkcert lo instala)"
echo

FALLOS=0
cabeceras() { "${CURL[@]}" -D- -o /dev/null "$@" | tr -d '\r'; }

exigir() {
  local titulo="$1" cabecera="$2" patron="$3" texto="$4"
  if grep -iE "^${cabecera}:" <<< "$texto" | grep -qiE "$patron"; then
    printf '   OK     %-46s %s\n' "$titulo" "$cabecera"
  else
    printf '   FALLO  %-46s %s (esperado: %s)\n' "$titulo" "$cabecera" "$patron" >&2
    FALLOS=$((FALLOS + 1))
  fi
}

# La linea de estado no es una cabecera ("HTTP/1.1 200 OK" no lleva ':'), asi
# que se comprueba aparte en vez de forzarla dentro de exigir().
exigir_estado() {
  local titulo="$1" patron="$2" texto="$3" linea
  linea=$(grep -m1 -E '^HTTP/' <<< "$texto" || true)
  if grep -qE "^HTTP/[0-9.]+ ${patron}" <<< "$linea"; then
    printf '   OK     %-46s %s
' "$titulo" "$linea"
  else
    printf '   FALLO  %-46s %s (esperado %s)
' "$titulo" "${linea:-sin respuesta}" "$patron" >&2
    FALLOS=$((FALLOS + 1))
  fi
}

prohibir() {
  local titulo="$1" cabecera="$2" texto="$3"
  if grep -iqE "^${cabecera}:" <<< "$texto"; then
    printf '   FALLO  %-46s %s no deberia estar\n' "$titulo" "$cabecera" >&2
    FALLOS=$((FALLOS + 1))
  else
    printf '   OK     %-46s sin %s\n' "$titulo" "$cabecera"
  fi
}

una_sola_vez() {
  local titulo="$1" cabecera="$2" texto="$3" cuantas
  cuantas=$(grep -icE "^${cabecera}:" <<< "$texto" || true)
  if [[ "$cuantas" == 1 ]]; then
    printf '   OK     %-46s %s una sola vez\n' "$titulo" "$cabecera"
  else
    printf '   FALLO  %-46s %s aparece %s veces (upstream duplicado)\n' \
      "$titulo" "$cabecera" "$cuantas" >&2
    FALLOS=$((FALLOS + 1))
  fi
}

# --- 1. documento -----------------------------------------------------------
echo "-- 1. Documento (/)"
DOC=$(cabeceras "${BASE}/")
exigir "documento" "Content-Security-Policy" "default-src 'self'" "$DOC"
exigir "documento" "Content-Security-Policy" "object-src 'none'" "$DOC"
exigir "documento" "Content-Security-Policy" "frame-ancestors 'none'" "$DOC"
exigir "documento" "X-Content-Type-Options" "nosniff" "$DOC"
exigir "documento" "Referrer-Policy" "no-referrer" "$DOC"
exigir "documento" "Permissions-Policy" "camera=\(\)" "$DOC"
exigir "documento revalida" "Cache-Control" "no-cache" "$DOC"
prohibir "sin HSTS en esta fase" "Strict-Transport-Security" "$DOC"

# --- 2. ruta profunda de la SPA ---------------------------------------------
echo
echo "-- 2. Ruta profunda (/configuracion-totp)"
PROF=$(cabeceras "${BASE}/configuracion-totp")
exigir_estado "ruta profunda" "200" "$PROF"
exigir "ruta profunda" "Content-Type" "text/html" "$PROF"
exigir "ruta profunda" "Content-Security-Policy" "default-src 'self'" "$PROF"

# --- 3. estatico con hash ---------------------------------------------------
echo
echo "-- 3. Estatico con hash (cache larga, que no debe perderse)"
ASSET=$("${CURL[@]}" "${BASE}/" | grep -o '/assets/index-[^"]*\.js' | head -n 1)
if [[ -n "$ASSET" ]]; then
  EST=$(cabeceras "${BASE}${ASSET}")
  exigir "asset $ASSET" "Cache-Control" "max-age=31536000" "$EST"
  exigir "asset $ASSET" "Cache-Control" "immutable" "$EST"
else
  echo "   FALLO  no se encontro ningun asset con hash en el documento" >&2
  FALLOS=$((FALLOS + 1))
fi

# --- 4. error del frontend (404 de API no proxiada) -------------------------
echo
echo "-- 4. Error propio del frontend (/api/internal/v1 no se reenvia)"
ERR=$(cabeceras "${BASE}/api/internal/v1/crawler/provisioning/claim")
exigir_estado "no se proxia /internal" "404" "$ERR"
exigir "error con cabeceras" "X-Content-Type-Options" "nosniff" "$ERR"
exigir "error sin cache" "Cache-Control" "no-store" "$ERR"
exigir "un error de API no es index.html" "Content-Type" "application/json" "$ERR"

# --- 5. autenticacion a traves del proxy ------------------------------------
echo
echo "-- 5. Autenticacion por el proxy (incluida su respuesta de error)"
LOGIN=$("${CURL[@]}" -D- -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario.inexistente","password":"no-importa"}' \
  "${BASE}/api/user_mgmt/v1/auth/login" | tr -d '\r')
exigir "login: sin cache ni en el error" "Cache-Control" "no-store" "$LOGIN"
una_sola_vez "login: no se duplica la del upstream" "Cache-Control" "$LOGIN"
exigir "login: el request_id se conserva" "x-request-id" "[0-9a-f]" "$LOGIN"
exigir "login: nosniff" "X-Content-Type-Options" "nosniff" "$LOGIN"

echo
echo "-- 6. Inscripcion propia por el proxy (sin autorizacion valida)"
INS=$("${CURL[@]}" -D- -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -d '{"enrollment_id":"autorizacion-inexistente"}' \
  "${BASE}/api/user_mgmt/v1/auth/enrollment/totp" | tr -d '\r')
exigir "inscripcion: sin cache" "Cache-Control" "no-store" "$INS"
una_sola_vez "inscripcion: sin duplicar" "Cache-Control" "$INS"

# --- 7. redireccion en modo HTTPS -------------------------------------------
if [[ "$HTTPS" == true ]]; then
  echo
  echo "-- 7. Listener HTTP: solo redirige, no sirve la aplicacion"
  RED=$(curl --silent --show-error --max-time 10 -D- -o /dev/null \
        "http://${HOST}:${PUERTO_HTTP}/configuracion-totp" | tr -d '\r')
  exigir_estado "redireccion permanente" "30[18]" "$RED"
  exigir "al origen HTTPS configurado" "Location" "https://${HOST}:${PUERTO_HTTPS}/configuracion-totp" "$RED"
  CUERPO=$(curl --silent --max-time 10 "http://${HOST}:${PUERTO_HTTP}/" || true)
  if grep -qi "<div id=\"raiz\"" <<< "$CUERPO"; then
    echo "   FALLO  el listener HTTP esta sirviendo la aplicacion" >&2
    FALLOS=$((FALLOS + 1))
  else
    echo "   OK     el listener HTTP no sirve el login"
  fi
  echo
  echo "-- 8. TLS: version del protocolo"
  for version in --tlsv1.2 --tlsv1.3; do
    if "${CURL[@]}" "$version" -o /dev/null "${BASE}/healthz" 2>/dev/null; then
      echo "   OK     ${version#--} aceptado"
    else
      echo "   ...    ${version#--} no negociado (puede ser normal segun el cliente)"
    fi
  done
fi

echo
if [[ "$FALLOS" -gt 0 ]]; then
  echo "== $FALLOS comprobacion(es) en rojo." >&2
  exit 1
fi
echo "== Todas las cabeceras comprobadas."
echo "   La CSP tambien se prueba en el navegador: abre $BASE, mira la consola"
echo "   y comprueba que no hay violaciones al cargar React ni al pintar el QR."
