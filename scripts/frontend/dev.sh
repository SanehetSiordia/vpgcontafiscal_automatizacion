#!/usr/bin/env bash
# Arranca el perfil de DESARROLLO del frontend (Vite con recarga en caliente).
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/dev.sh            # arranca y sigue el log
#   bash scripts/frontend/dev.sh --parar
#
# Es un perfil aparte del runtime de 'make all', y la diferencia no es
# cosmetica: Vite sirve con scripts en linea y una conexion de HMR que la CSP
# del runtime prohibe. Aqui no hay CSP y eso solo vale para desarrollar; la
# imagen que se publica es Nginx con la politica estricta y sin Vite dentro.
#
# Necesita user-mgmt-service en marcha (el proxy de Vite le reenvia /api) y
# node_modules instalado la primera vez:
#   bash scripts/frontend/npm.sh ci
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta .env" >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

DC=(docker compose --project-directory "$REPO_ROOT" --env-file "$ENV_FILE"
    -f "${REPO_ROOT}/compose.yaml" --profile dev)
PUERTO=$(env_get FRONTEND_DEV_PORT); PUERTO=${PUERTO:-5173}

if [[ "${1:-}" == "--parar" ]]; then
  echo "==> Deteniendo el perfil de desarrollo"
  "${DC[@]}" stop frontend-dev
  "${DC[@]}" rm -f frontend-dev
  exit 0
fi

[[ -d "${REPO_ROOT}/frontend/node_modules" ]] || {
  echo "ERROR: falta frontend/node_modules." >&2
  echo "       Ejecuta primero:  bash scripts/frontend/npm.sh ci" >&2
  exit 1
}

echo "==> Arrancando frontend-dev (perfil 'dev', no forma parte de 'make all')"
"${DC[@]}" up -d frontend-dev
echo
echo "   Desarrollo:  http://127.0.0.1:${PUERTO}"
echo "   El runtime de make all sigue en su puerto, sin tocar y con su CSP."
echo "   Parar:  bash scripts/frontend/dev.sh --parar"
echo
"${DC[@]}" logs -f frontend-dev
