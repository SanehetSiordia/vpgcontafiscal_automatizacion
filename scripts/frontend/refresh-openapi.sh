#!/usr/bin/env bash
# Vuelve a capturar el OpenAPI de user-mgmt-service para las pruebas de
# contrato del frontend.
#
# Uso (host, Git Bash, con user-mgmt-service en marcha):
#   bash scripts/frontend/refresh-openapi.sh
#
# El documento se guarda en frontend/src/test/openapi.user-mgmt.json y es lo que
# lee src/test/contract.test.ts. Se captura, NO se escribe a mano: un contrato
# copiado a mano documenta lo que alguien creia, no lo que el servicio publica.
#
# Si el servicio cambia de contrato, esta captura y las pruebas de contrato son
# lo que hace que el frontend se entere rompiendose aqui, y no en el navegador.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta .env" >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

BIND=$(env_get USER_MGMT_HOST_BIND); BIND=${BIND:-127.0.0.1}
PORT=$(env_get USER_MGMT_PORT_LOCAL); PORT=${PORT:-8000}
DESTINO="${REPO_ROOT}/frontend/src/test/openapi.user-mgmt.json"
TEMPORAL="${DESTINO}.nuevo"

URL="http://${BIND}:${PORT}/openapi.json"
echo "==> Capturando ${URL}"
curl --silent --show-error --fail --max-time 15 -o "$TEMPORAL" "$URL" || {
  rm -f "$TEMPORAL"
  echo "ERROR: no se pudo leer el OpenAPI en ${URL}." >&2
  echo "       user-mgmt-service tiene que estar en marcha: make all" >&2
  exit 1
}

# Comprobacion minima de que es lo que parece antes de sustituir el anterior.
grep -q '"openapi"' "$TEMPORAL" || {
  rm -f "$TEMPORAL"
  echo "ERROR: la respuesta no parece un documento OpenAPI." >&2
  exit 1
}
grep -q '/auth/login' "$TEMPORAL" || {
  rm -f "$TEMPORAL"
  echo "ERROR: el documento no declara /auth/login: no es el de user-mgmt." >&2
  exit 1
}

if [[ -f "$DESTINO" ]] && cmp -s "$TEMPORAL" "$DESTINO"; then
  rm -f "$TEMPORAL"
  echo "==> Sin cambios: el contrato capturado ya era el actual."
  exit 0
fi

mv -f "$TEMPORAL" "$DESTINO"
echo "==> Actualizado: frontend/src/test/openapi.user-mgmt.json"
echo "    Revisa el diff y ejecuta  bash scripts/frontend/run-tests.sh"
