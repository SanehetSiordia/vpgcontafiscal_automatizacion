#!/bin/sh
# Aplica el DDL del esquema de empleados con psql, en una sola transaccion.
#
# Se instala en la imagen como /usr/local/bin/vpg-pg-schema y ademas se enlaza
# en /docker-entrypoint-initdb.d/10-schema.sh, de modo que el entrypoint OFICIAL
# de PostgreSQL lo ejecuta solo durante la inicializacion de un volumen VACIO.
# Para cualquier otro caso se invoca a mano:
#
#   docker compose exec postgres-service vpg-pg-schema
#
# Es repetible: el DDL usa IF NOT EXISTS / CREATE OR REPLACE y no borra datos.
set -eu

SQL_FILE=${VPG_SQL_FILE:-/opt/vpg/sql/001_employees.sql}
DB_NAME=${POSTGRES_DB:-postgres}
DB_USER=${POSTGRES_USER:-postgres}

[ -r "$SQL_FILE" ] || { echo "ERROR: no se puede leer ${SQL_FILE}" >&2; exit 1; }

echo "==> Aplicando ${SQL_FILE} en ${DB_NAME} como ${DB_USER}"

# ON_ERROR_STOP=1 + BEGIN/COMMIT dentro del archivo: o se aplica todo o nada.
psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet \
     --username "$DB_USER" --dbname "$DB_NAME" \
     -f "$SQL_FILE"

echo "==> Esquema 'employees' aplicado."
