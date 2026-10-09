#!/usr/bin/env bash
# Comprobaciones del frontend, TODAS dentro de Docker.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/run-tests.sh                 # tipos + lint + pruebas
#   bash scripts/frontend/run-tests.sh --solo-pruebas
#   bash scripts/frontend/run-tests.sh -- -t "segundo factor"   # a vitest
#
# No hace falta Node ni npm instalados en Windows: se construye la etapa
# `frontend-test` del Dockerfile, que parte del builder y ya tiene las
# dependencias de desarrollo del lockfile.
#
# Que demuestran estas pruebas: el comportamiento del cliente contra dobles
# HTTP explicitos y contra el OpenAPI REAL capturado del servicio
# (frontend/src/test/openapi.user-mgmt.json). Que NO demuestran: que el
# servicio en marcha se comporte como su documento, ni que Google Authenticator
# acepte un URI. Eso es el recorrido manual del README y smoke-frontend.sh.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

SOLO_PRUEBAS=false
ARGS_VITEST=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --solo-pruebas) SOLO_PRUEBAS=true ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    --) shift; ARGS_VITEST=("$@"); break ;;
    *) echo "ERROR: opcion desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: falta docker en el PATH. Arranca Docker Desktop." >&2
  exit 1
}

echo "==> Construyendo la imagen de pruebas del frontend (etapa frontend-test)"
docker build --quiet --target frontend-test -t vpg/frontend-test:local . >/dev/null

ejecutar() {
  local titulo="$1"; shift
  echo
  echo "==> $titulo"
  docker run --rm vpg/frontend-test:local "$@"
}

if [[ "$SOLO_PRUEBAS" != true ]]; then
  # La comprobacion de tipos ya ocurre dentro del build de la imagen; se repite
  # aqui para que el fallo salga con su mensaje y no mezclado con el de Docker.
  ejecutar "Tipos (tsc --noEmit, strict)" npm run typecheck
  ejecutar "Lint (eslint)" npm run lint
fi

echo
echo "==> Pruebas (vitest + Testing Library, jsdom)"
if [[ ${#ARGS_VITEST[@]} -gt 0 ]]; then
  docker run --rm vpg/frontend-test:local npx vitest run "${ARGS_VITEST[@]}"
else
  docker run --rm vpg/frontend-test:local npm test
fi

echo
echo "==> Todo en verde."
echo "    Para el recorrido contra el servicio real:  bash scripts/frontend/smoke-frontend.sh"
