#!/bin/sh
# Crea (o converge) la cuenta de EJECUCION con permisos minimos que usara el
# futuro backend, separada de la cuenta administrativa POSTGRES_USER, que es
# superusuario y propietaria del esquema.
#
# La contrasena se lee del secreto montado por Compose
# (POSTGRES_APP_PASSWORD_FILE) y se envia a psql por stdin: nunca aparece en
# los argumentos del proceso, ni en el historial, ni en los archivos SQL.
#
# Se instala como /usr/local/bin/vpg-pg-roles y se enlaza en
# /docker-entrypoint-initdb.d/20-app-role.sh (solo corre automaticamente con un
# volumen VACIO). Ejecucion manual e idempotente:
#
#   docker compose exec postgres-service vpg-pg-roles
#
# Orden recomendado: vpg-pg-schema primero, vpg-pg-roles despues.
set -eu

DB_NAME=${POSTGRES_DB:-postgres}
DB_USER=${POSTGRES_USER:-postgres}
APP_USER=${POSTGRES_APP_USER:-vpg_app}
APP_SCHEMA=${POSTGRES_SCHEMA:-employees}
PASS_FILE=${POSTGRES_APP_PASSWORD_FILE:-/run/secrets/postgres_app_password}

case "$APP_USER" in
  *[!a-z0-9_]*) echo "ERROR: POSTGRES_APP_USER solo admite [a-z0-9_]." >&2; exit 1 ;;
esac

[ -r "$PASS_FILE" ] || {
  echo "ERROR: no se puede leer el secreto ${PASS_FILE}." >&2
  echo "       Ejecuta scripts/postgres/prepare-secrets.sh y recrea el contenedor." >&2
  exit 1
}

# Primera linea del secreto, sin salto final.
APP_PASS=$(head -n 1 "$PASS_FILE" | tr -d '\r\n')
[ -n "$APP_PASS" ] || { echo "ERROR: ${PASS_FILE} esta vacio." >&2; exit 1; }
[ "${#APP_PASS}" -ge 16 ] || { echo "ERROR: la contrasena de ${APP_USER} debe tener 16+ caracteres." >&2; exit 1; }

# Escapado para literal SQL (standard_conforming_strings = on: solo ').
APP_PASS_SQL=$(printf '%s' "$APP_PASS" | sed "s/'/''/g")
unset APP_PASS

echo "==> Convergiendo el rol de ejecucion '${APP_USER}' en ${DB_NAME}"

# El SQL viaja por stdin: la contrasena no aparece en los argumentos del
# proceso. Va embebida en el cuerpo del bloque DO y NUNCA en una sentencia que
# devuelva valores (un SELECT set_config(...) imprimiria el secreto en stdout y,
# con `docker compose up`, acabaria en el log del contenedor).
# SET LOCAL log_statement='none' evita ademas el log del servidor si alguien lo
# activa.
psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet \
     --username "$DB_USER" --dbname "$DB_NAME" <<SQL
BEGIN;
SET LOCAL log_statement = 'none';
SET LOCAL log_min_duration_statement = -1;

DO \$do\$
DECLARE
  v_app    text := '${APP_USER}';
  v_schema text := '${APP_SCHEMA}';
  v_owner  text := '${DB_USER}';
  v_pass   text := '${APP_PASS_SQL}';
BEGIN
  -- 1. Rol de login sin privilegios de administracion.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_app) THEN
    EXECUTE format(
      'ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
      v_app, v_pass);
    RAISE NOTICE 'rol % ya existia: contrasena y atributos convergidos', v_app;
  ELSE
    EXECUTE format(
      'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
      v_app, v_pass);
    RAISE NOTICE 'rol % creado', v_app;
  END IF;

  EXECUTE format('ALTER ROLE %I SET search_path = %I', v_app, v_schema);
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), v_app);

  -- 2. Nada en el esquema public (PG15+ ya lo deja cerrado; se reitera).
  EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', v_app);

  -- 3. Permisos minimos sobre el esquema de la aplicacion. USAGE sin CREATE:
  --    la cuenta de ejecucion NO puede crear ni alterar objetos (eso es DDL,
  --    tarea de la cuenta administrativa / de las migraciones).
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = v_schema) THEN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', v_schema, v_app);
    EXECUTE format(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I',
      v_schema, v_app);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I',
      v_schema, v_app);
    -- Y lo mismo para las tablas que cree despues el propietario.
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
      v_owner, v_schema, v_app);
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO %I',
      v_owner, v_schema, v_app);
  ELSE
    RAISE NOTICE 'el esquema % todavia no existe: ejecuta vpg-pg-schema y repite este script', v_schema;
  END IF;
END
\$do\$;

COMMIT;
SQL

unset APP_PASS_SQL

echo "==> Rol '${APP_USER}' listo (login, sin DDL, sin superusuario)."
