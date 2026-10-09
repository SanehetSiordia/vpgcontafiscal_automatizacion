#!/usr/bin/env bash
# Ejecuta npm sobre frontend/ DENTRO de un contenedor.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/npm.sh install --save-exact react-router-dom@6.28.0
#   bash scripts/frontend/npm.sh ci
#   bash scripts/frontend/npm.sh run build
#
# Para que existe: en Windows no hace falta Node ni npm instalados, pero si hay
# que poder regenerar package-lock.json o anadir una dependencia sin salirse de
# Docker. La version de Node es la MISMA que usa el build de la imagen
# (NODE_VERSION de .env), para que el lockfile no se genere con otra.
#
# Monta frontend/ para que el lockfile y node_modules queden en el repositorio.
# node_modules y dist estan excluidos de Git y del contexto de build.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta .env" >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

NODE_VERSION=$(env_get NODE_VERSION); NODE_VERSION=${NODE_VERSION:-22-alpine}
[[ $# -gt 0 ]] || { sed -n '2,18p' "$0"; exit 2; }

echo "==> node:${NODE_VERSION}  npm $*"
# Sin --user: npm necesita escribir en /app y en su cache. El contenedor es
# efimero y solo ve frontend/, nunca secrets/ ni el resto del repositorio.
MSYS_NO_PATHCONV=1 exec docker run --rm -it \
  -v "${REPO_ROOT}/frontend:/app" \
  -w /app \
  "node:${NODE_VERSION}" \
  npm "$@"
