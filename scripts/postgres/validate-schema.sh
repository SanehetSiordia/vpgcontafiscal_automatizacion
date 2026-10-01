#!/usr/bin/env bash
# Comprobaciones de solo lectura sobre el esquema de empleados, y pruebas de
# restricciones que SE REVIERTEN siempre (cada una va en su propia transaccion
# con ROLLBACK, por lo que no deja datos).
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/postgres/validate-schema.sh [tablas|constraints|indices|datos|restricciones|todo]
#
# Nunca muestra contrasenas, semillas TOTP ni tokens: solo metadatos del
# modelo y los datos no secretos del empleado.
set -euo pipefail

SECTION=${1:-todo}

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

PG_DB=$(env_get POSTGRES_DB);     PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER); PG_USER=${PG_USER:-vpg_admin}
PG_SCHEMA=$(env_get POSTGRES_SCHEMA); PG_SCHEMA=${PG_SCHEMA:-employees}
PG_APP=$(env_get POSTGRES_APP_USER);  PG_APP=${PG_APP:-vpg_app}

q() { docker compose exec -T postgres-service psql --no-psqlrc -v ON_ERROR_STOP=1 \
        --username "$PG_USER" --dbname "$PG_DB" "$@"; }

banner() { printf '\n========== %s ==========\n' "$1"; }

# -----------------------------------------------------------------------------
if [[ "$SECTION" == "tablas" || "$SECTION" == "todo" ]]; then
  banner "Tablas del esquema ${PG_SCHEMA} y numero de filas"
  q -c "
SELECT c.relname AS tabla,
       c.reltuples::bigint AS filas_estimadas,
       (SELECT count(*) FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS columnas,
       obj_description(c.oid, 'pg_class') AS comentario
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${PG_SCHEMA}' AND c.relkind = 'r'
 ORDER BY c.relname;"
fi

# -----------------------------------------------------------------------------
if [[ "$SECTION" == "constraints" || "$SECTION" == "todo" ]]; then
  banner "Restricciones (PK / FK / UNIQUE / CHECK) y politicas ON DELETE"
  q -c "
SELECT con.conrelid::regclass AS tabla,
       con.conname            AS restriccion,
       CASE con.contype WHEN 'p' THEN 'PRIMARY KEY'
                        WHEN 'f' THEN 'FOREIGN KEY'
                        WHEN 'u' THEN 'UNIQUE'
                        WHEN 'c' THEN 'CHECK' END AS tipo,
       CASE con.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
                            WHEN 'c' THEN 'CASCADE'   WHEN 'n' THEN 'SET NULL'
                            WHEN 'd' THEN 'SET DEFAULT' END AS on_delete,
       pg_get_constraintdef(con.oid) AS definicion
  FROM pg_catalog.pg_constraint con
  JOIN pg_catalog.pg_class     c ON c.oid = con.conrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = '${PG_SCHEMA}'
 ORDER BY con.conrelid::regclass::text,
          CASE con.contype WHEN 'p' THEN 1 WHEN 'f' THEN 2 WHEN 'u' THEN 3 ELSE 4 END,
          con.conname;"

  banner "Columnas NOT NULL por tabla"
  q -c "
SELECT table_name AS tabla,
       string_agg(column_name, ', ' ORDER BY ordinal_position) AS columnas_not_null
  FROM information_schema.columns
 WHERE table_schema = '${PG_SCHEMA}' AND is_nullable = 'NO'
 GROUP BY table_name ORDER BY table_name;"

  banner "Triggers de updated_at"
  q -c "
SELECT c.relname AS tabla, t.tgname AS trigger, p.proname AS funcion
  FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class     c ON c.oid = t.tgrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_proc      p ON p.oid = t.tgfoid
 WHERE n.nspname = '${PG_SCHEMA}' AND NOT t.tgisinternal
 ORDER BY c.relname;"
fi

# -----------------------------------------------------------------------------
if [[ "$SECTION" == "indices" || "$SECTION" == "todo" ]]; then
  banner "Indices (los de PK/UNIQUE los crea la restriccion; no se duplican)"
  q -c "
SELECT tablename AS tabla, indexname AS indice, indexdef AS definicion
  FROM pg_catalog.pg_indexes
 WHERE schemaname = '${PG_SCHEMA}'
 ORDER BY tablename, indexname;"

  banner "Indices redundantes (misma tabla y mismas columnas/expresion)"
  q -c "
WITH ix AS (
  SELECT i.indrelid::regclass AS tabla,
         i.indexrelid::regclass AS indice,
         pg_get_expr(i.indexprs, i.indrelid) AS expresion,
         i.indkey::text AS columnas,
         pg_get_expr(i.indpred, i.indrelid) AS parcial
    FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = '${PG_SCHEMA}'
)
SELECT tabla, columnas, coalesce(expresion,'-') AS expresion,
       coalesce(parcial,'-') AS parcial,
       count(*) AS repeticiones, string_agg(indice::text, ', ') AS indices
  FROM ix
 GROUP BY tabla, columnas, expresion, parcial
HAVING count(*) > 1;"
fi

# -----------------------------------------------------------------------------
if [[ "$SECTION" == "datos" || "$SECTION" == "todo" ]]; then
  banner "Roles de aplicacion sembrados"
  q -c "SELECT code, name, description FROM ${PG_SCHEMA}.roles ORDER BY code;"

  banner "Recuento por tabla (deteccion de duplicados al repetir los scripts)"
  q -c "
SELECT 'users' AS tabla, count(*) FROM ${PG_SCHEMA}.users
UNION ALL SELECT 'roles',               count(*) FROM ${PG_SCHEMA}.roles
UNION ALL SELECT 'user_roles',          count(*) FROM ${PG_SCHEMA}.user_roles
UNION ALL SELECT 'user_profiles',       count(*) FROM ${PG_SCHEMA}.user_profiles
UNION ALL SELECT 'user_phones',         count(*) FROM ${PG_SCHEMA}.user_phones
UNION ALL SELECT 'user_addresses',      count(*) FROM ${PG_SCHEMA}.user_addresses
UNION ALL SELECT 'user_emails',         count(*) FROM ${PG_SCHEMA}.user_emails
UNION ALL SELECT 'vault_auth_config',   count(*) FROM ${PG_SCHEMA}.vault_auth_config
UNION ALL SELECT 'user_vault_identity', count(*) FROM ${PG_SCHEMA}.user_vault_identity
ORDER BY 1;"

  banner "Privilegios del rol de ejecucion ${PG_APP} (debe ser DML, sin DDL)"
  q -c "
SELECT r.rolname, r.rolsuper AS superusuario, r.rolcreatedb, r.rolcreaterole,
       has_schema_privilege(r.rolname, '${PG_SCHEMA}', 'USAGE')  AS schema_usage,
       has_schema_privilege(r.rolname, '${PG_SCHEMA}', 'CREATE') AS schema_create,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.users', 'SELECT') AS users_select,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.users', 'INSERT') AS users_insert,
       has_table_privilege(r.rolname, '${PG_SCHEMA}.users', 'TRUNCATE') AS users_truncate
  FROM pg_catalog.pg_roles r WHERE r.rolname IN ('${PG_USER}', '${PG_APP}') ORDER BY r.rolname;"
fi

# -----------------------------------------------------------------------------
if [[ "$SECTION" == "restricciones" || "$SECTION" == "todo" ]]; then
  banner "Pruebas de restricciones (TODAS terminan en ROLLBACK)"

  # Cada prueba corre aislada: si la restriccion funciona, psql devuelve error y
  # se informa OK. El ROLLBACK final garantiza que nada queda escrito.
  probe() {
    local titulo=$1 sql=$2 out rc=0
    out=$(docker compose exec -T postgres-service psql --no-psqlrc --quiet \
            --username "$PG_USER" --dbname "$PG_DB" 2>&1 <<EOSQL
BEGIN;
${sql}
ROLLBACK;
EOSQL
    ) || rc=$?
    if printf '%s' "$out" | grep -qiE 'ERROR:|FATAL:'; then
      printf '  [OK rechazado] %-46s %s\n' "$titulo" \
        "$(printf '%s' "$out" | grep -iE 'ERROR:' | head -n 1 | cut -c1-110)"
    else
      printf '  [!! ACEPTADO ] %-46s la restriccion NO actuo\n' "$titulo"
    fi
  }

  UID_SQL="(SELECT id FROM ${PG_SCHEMA}.users ORDER BY created_at LIMIT 1)"

  probe "username duplicado con otras mayusculas" \
    "INSERT INTO ${PG_SCHEMA}.users (username) SELECT upper(username) FROM ${PG_SCHEMA}.users LIMIT 1;"

  probe "auth_provider fuera del CHECK" \
    "INSERT INTO ${PG_SCHEMA}.users (username, auth_provider) VALUES ('probe.user', 'ldap');"

  probe "password_hash con autenticacion delegada a Vault" \
    "INSERT INTO ${PG_SCHEMA}.users (username, auth_provider, password_hash) VALUES ('probe.user', 'vault', '\$argon2id\$v=19\$m=65536,t=3,p=4\$abc\$def');"

  probe "password_hash local que no es Argon2id" \
    "INSERT INTO ${PG_SCHEMA}.users (username, auth_provider, password_hash) VALUES ('probe.user', 'local', '\$2b\$12\$bcryptnoadmitido');"

  probe "asignacion de rol duplicada" \
    "INSERT INTO ${PG_SCHEMA}.user_roles (user_id, role_id) SELECT user_id, role_id FROM ${PG_SCHEMA}.user_roles LIMIT 1;"

  probe "borrar un rol todavia asignado (ON DELETE RESTRICT)" \
    "DELETE FROM ${PG_SCHEMA}.roles WHERE code = 'admin';"

  probe "segundo perfil para el mismo usuario" \
    "INSERT INTO ${PG_SCHEMA}.user_profiles (user_id, first_name, last_name_paternal, birth_date) VALUES (${UID_SQL}, 'otro', 'perfil', DATE '1990-01-01');"

  probe "CURP cuya fecha no coincide con birth_date" \
    "UPDATE ${PG_SCHEMA}.user_profiles SET birth_date = DATE '1991-04-25' WHERE user_id = ${UID_SQL};"

  # Fecha correcta (920425) pero longitud invalida: falla el CHECK de formato,
  # no el de coherencia con birth_date.
  probe "RFC con formato invalido" \
    "UPDATE ${PG_SCHEMA}.user_profiles SET rfc = 'SIMS920425IY' WHERE user_id = ${UID_SQL};"

  probe "segundo correo principal para el mismo usuario" \
    "INSERT INTO ${PG_SCHEMA}.user_emails (user_id, email, is_primary) VALUES (${UID_SQL}, 'otro.correo@example.com', TRUE);"

  probe "correo repetido cambiando mayusculas" \
    "INSERT INTO ${PG_SCHEMA}.user_emails (user_id, email) SELECT user_id, upper(email) FROM ${PG_SCHEMA}.user_emails LIMIT 1;"

  probe "correo con formato invalido" \
    "INSERT INTO ${PG_SCHEMA}.user_emails (user_id, email) VALUES (${UID_SQL}, 'sin-arroba.example.com');"

  probe "telefono con letras" \
    "INSERT INTO ${PG_SCHEMA}.user_phones (user_id, phone_number) VALUES (${UID_SQL}, '667ABC2628');"

  probe "codigo postal de 4 digitos" \
    "INSERT INTO ${PG_SCHEMA}.user_addresses (user_id, street, exterior_number, postal_code) VALUES (${UID_SQL}, 'Calle', '1', '8018');"

  probe "totp_status fuera del CHECK" \
    "UPDATE ${PG_SCHEMA}.user_vault_identity SET totp_status = 'enrolled' WHERE user_id = ${UID_SQL};"

  probe "totp_status=confirmed sin totp_confirmed_at" \
    "UPDATE ${PG_SCHEMA}.user_vault_identity SET totp_status = 'confirmed', totp_confirmed_at = NULL WHERE user_id = ${UID_SQL};"

  probe "vault_username con mayusculas" \
    "UPDATE ${PG_SCHEMA}.user_vault_identity SET vault_username = 'SinhueSiordia' WHERE user_id = ${UID_SQL};"

  probe "segunda identidad de Vault para el mismo usuario" \
    "INSERT INTO ${PG_SCHEMA}.user_vault_identity (user_id, vault_auth_config_id, vault_username, vault_entity_id) SELECT user_id, vault_auth_config_id, 'otro.alias', gen_random_uuid() FROM ${PG_SCHEMA}.user_vault_identity LIMIT 1;"

  probe "borrar la config de auth con vinculos vivos (RESTRICT)" \
    "DELETE FROM ${PG_SCHEMA}.vault_auth_config;"

  banner "Pruebas que DEBEN pasar (y tambien se revierten)"
  probe_ok() {
    local titulo=$1 sql=$2 out rc=0
    out=$(docker compose exec -T postgres-service psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
            --username "$PG_USER" --dbname "$PG_DB" 2>&1 <<EOSQL
BEGIN;
${sql}
ROLLBACK;
EOSQL
    ) || rc=$?
    if [[ $rc -eq 0 ]] && ! printf '%s' "$out" | grep -qiE 'ERROR:|FATAL:'; then
      printf '  [OK aceptado ] %-46s %s\n' "$titulo" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-90)"
    else
      printf '  [!! RECHAZADO] %-46s %s\n' "$titulo" \
        "$(printf '%s' "$out" | grep -iE 'ERROR:' | head -n 1 | cut -c1-110)"
    fi
  }

  probe_ok "un metodo TOTP compartido por dos empleados" \
    "INSERT INTO ${PG_SCHEMA}.users (username) VALUES ('probe.segundo');
     INSERT INTO ${PG_SCHEMA}.user_vault_identity (user_id, vault_auth_config_id, vault_username, vault_entity_id)
       SELECT (SELECT id FROM ${PG_SCHEMA}.users WHERE username='probe.segundo'),
              (SELECT id FROM ${PG_SCHEMA}.vault_auth_config LIMIT 1),
              'probe.segundo', gen_random_uuid();
     SELECT count(DISTINCT user_id) AS empleados, count(DISTINCT c.totp_method_id) AS metodos_totp
       FROM ${PG_SCHEMA}.user_vault_identity vi
       JOIN ${PG_SCHEMA}.vault_auth_config c ON c.id = vi.vault_auth_config_id;"

  probe_ok "updated_at se actualiza solo (trigger)" \
    "UPDATE ${PG_SCHEMA}.users SET is_active = is_active, updated_at = TIMESTAMPTZ '2000-01-01'
       WHERE id = ${UID_SQL};
     SELECT (updated_at > created_at) AS updated_at_recalculado FROM ${PG_SCHEMA}.users WHERE id = ${UID_SQL};"

  echo
  echo "  Comprobacion final: nada quedo escrito por las pruebas."
  q -c "SELECT count(*) AS usuarios_probe FROM ${PG_SCHEMA}.users WHERE username LIKE 'probe%' OR username ~ '[A-Z]';"
fi
