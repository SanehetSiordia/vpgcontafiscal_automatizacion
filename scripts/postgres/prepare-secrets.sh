#!/usr/bin/env bash
# Prepara los archivos de Compose secrets que necesita postgres-service.
#
#   secrets/postgres_password      -> POSTGRES_PASSWORD_FILE      (cuenta admin)
#   secrets/postgres_app_password  -> POSTGRES_APP_PASSWORD_FILE  (cuenta de ejecucion)
#
# Se ejecuta en el host, desde la raiz del repositorio (Git Bash):
#   bash scripts/postgres/prepare-secrets.sh
#
# - No sobrescribe un secreto existente salvo --force (recrear el contenedor con
#   un POSTGRES_PASSWORD distinto NO cambia la contrasena ya guardada en el
#   volumen: initdb solo la fija la primera vez).
# - El directorio secrets/ esta en .gitignore y en .dockerignore: los archivos no
#   entran al repositorio ni al contexto de build.
# - No imprime ningun valor.
set -euo pipefail

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SECRETS_DIR="${REPO_ROOT}/secrets"
mkdir -p "$SECRETS_DIR"

# Solo [A-Za-z0-9]: evita problemas de escapado en psql, en las URL de conexion
# y en los .pgpass.
random_password() {
  LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
}

write_secret() {
  local name=$1 path="${SECRETS_DIR}/$1"

  if [[ -s "$path" && "$FORCE" == false ]]; then
    echo "==> ${name}: ya existe, se conserva (usa --force para regenerarlo)"
    return
  fi
  if [[ -s "$path" ]]; then
    echo "==> ${name}: se regenera (--force)"
  else
    echo "==> ${name}: generando"
  fi

  # Sin salto de linea final: el entrypoint oficial de PostgreSQL usa el
  # contenido del archivo tal cual.
  printf '%s' "$(random_password)" > "$path"
  chmod 600 "$path" 2>/dev/null || true
}

write_secret postgres_password
write_secret postgres_app_password

echo
echo "==> Secretos en ${SECRETS_DIR} (no se muestran sus valores):"
for f in postgres_password postgres_app_password; do
  printf '    %-24s %s caracteres\n' "$f" "$(LC_ALL=C wc -c < "${SECRETS_DIR}/${f}" | tr -d ' ')"
done
echo
echo "    Guardalos en tu gestor de contrasenas si vas a conectar desde el host."
echo "    Para leer uno puntualmente:  cat secrets/postgres_password; echo"
