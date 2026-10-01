#!/usr/bin/env bash
# Inserta (o reconcilia) el empleado inicial y su vinculo con la identidad que
# YA existe en Vault. Transaccional e idempotente: repetirlo no duplica usuario,
# perfil, telefono, direccion, correo, asignacion de rol ni vinculo.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/postgres/seed-initial-user.sh [--dry-run]
#
# Que hace:
#   1. Lee de .env los parametros NO sensibles (VAULT_ADMIN_USER_NAME, POSTGRES_*).
#   2. Pregunta a Vault, dentro del contenedor vault-service, el accessor de
#      userpass, el entity_id del alias, el method_id del metodo TOTP y el
#      enforcement MFA. No inventa identificadores y distingue los errores de
#      permisos o conectividad de la inexistencia del recurso.
#   3. Ejecuta un unico BEGIN/COMMIT en postgres-service.
#
# Que NO hace:
#   - No genera ni regenera secretos TOTP, ni cambia politicas de Vault.
#   - No guarda en PostgreSQL contrasenas, semillas TOTP, QR, URLs otpauth
#     ni tokens.
#   - No marca el TOTP como 'confirmed': eso solo lo hace
#     scripts/postgres/verify-vault-mfa.sh tras un login MFA real.
set -euo pipefail

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta ${ENV_FILE} (cp .env.example .env)." >&2; exit 1; }

# Lee una clave de .env sin exportar el resto del archivo (en particular, sin
# arrastrar VAULT_ADMIN_USER_PASS a este proceso).
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

VAULT_ADMIN_USER_NAME=$(env_get VAULT_ADMIN_USER_NAME)
PG_DB=$(env_get POSTGRES_DB);       PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER);   PG_USER=${PG_USER:-vpg_admin}
USERPASS_PATH=$(env_get VAULT_USERPASS_PATH);  USERPASS_PATH=${USERPASS_PATH:-userpass}
MFA_METHOD_NAME=$(env_get VAULT_MFA_METHOD_NAME); MFA_METHOD_NAME=${MFA_METHOD_NAME:-vpg-totp}
MFA_ENFORCEMENT=$(env_get VAULT_MFA_ENFORCEMENT); MFA_ENFORCEMENT=${MFA_ENFORCEMENT:-vpg-userpass-totp}

[[ -n "$VAULT_ADMIN_USER_NAME" ]] || { echo "ERROR: VAULT_ADMIN_USER_NAME no esta definido en .env." >&2; exit 1; }

# userpass guarda los nombres en minusculas: el vinculo debe coincidir.
ADMIN_USER=$(printf '%s' "$VAULT_ADMIN_USER_NAME" | tr 'A-Z' 'a-z')

# --- Datos del empleado inicial ----------------------------------------------
SEED_ROLE_CODE=admin
SEED_FIRST_NAME=sinhue
SEED_LAST_NAME=siordia
SEED_BIRTH_DATE=1992-04-25
SEED_RFC=SIMS920425IY8
SEED_CURP=SIMS920425HSLRLN06
SEED_PHONE_CC=52
SEED_PHONE=6671302628
SEED_NEIGHBORHOOD=Belcantto
SEED_STREET='Priv. Parremo'
SEED_EXTERIOR=6505
SEED_INTERIOR=13B
SEED_POSTAL_CODE=80184
SEED_EMAIL=carpediem.sinhue@gmail.com

# =============================================================================
# 1. Resolver la identidad en Vault (dentro de vault-service)
# =============================================================================
echo "==> Consultando Vault (contenedor vault-service)"

VAULT_PROBE=$(cat <<'PROBE'
set -eu
USERPASS_PATH=$1
ADMIN_USER=$2
MFA_METHOD_NAME=$3
MFA_ENFORCEMENT=$4

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Un fallo de permisos o de red NO significa que el recurso no exista.
classify() {
  case "$2" in
    *"permission denied"*|*"Code: 403"*)
      die "permiso denegado al acceder a $1. El recurso puede existir: usa un token con permisos suficientes (vault login / VAULT_INITIAL_TOKEN). No se asume su inexistencia." ;;
    *"connection refused"*|*"no such host"*|*"EOF"*|*"timeout"*|*"Code: 50"*)
      die "problema de conectividad con Vault al acceder a $1: $2" ;;
  esac
}

if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN
  export VAULT_TOKEN
fi

status=0
vault status >/dev/null 2>&1 || status=$?
case "$status" in
  0) ;;
  2) die "Vault esta sellado o sin inicializar. Ejecuta 'vault operator unseal' y repite." ;;
  *) die "Vault no responde en ${VAULT_ADDR:-<sin VAULT_ADDR>} (conectividad), no se concluye nada sobre sus recursos." ;;
esac
vault token lookup >/dev/null 2>&1 \
  || die "no hay un token valido en el contenedor: 'vault login' o VAULT_INITIAL_TOKEN en .env."

# --- accessor del montaje userpass ---
if ! out=$(vault read -field=accessor "sys/auth/${USERPASS_PATH}" 2>&1); then
  classify "sys/auth/${USERPASS_PATH}" "$out"
  die "el montaje userpass '${USERPASS_PATH}' no responde: ${out}. Ejecuta 'vpg-auth-bootstrap'."
fi
ACCESSOR=$out

# --- entidad asociada al alias userpass ---
if ! out=$(vault write -field=id identity/lookup/entity \
            alias_name="$ADMIN_USER" alias_mount_accessor="$ACCESSOR" 2>&1); then
  classify "identity/lookup/entity" "$out"
  die "no hay entidad para el alias '${ADMIN_USER}' en ${USERPASS_PATH}/ (${out}). Ejecuta 'vpg-auth-bootstrap'."
fi
ENTITY_ID=$out

# --- metodo MFA TOTP por nombre ---
if ! listing=$(vault list -format=json identity/mfa/method/totp 2>&1); then
  classify "identity/mfa/method/totp" "$listing"
  die "no se pudieron listar los metodos MFA TOTP: ${listing}. Ejecuta 'vpg-auth-bootstrap'."
fi
METHOD_ID=""
for id in $(vault list identity/mfa/method/totp 2>/dev/null | tail -n +3); do
  # Vault recibe method_name al crear el metodo y lo devuelve como name.
  if [ "$(vault read -field=name "identity/mfa/method/totp/${id}" 2>/dev/null)" = "$MFA_METHOD_NAME" ]; then
    METHOD_ID=$id
    break
  fi
done
[ -n "$METHOD_ID" ] || die "no existe un metodo MFA TOTP llamado '${MFA_METHOD_NAME}'. Ejecuta 'vpg-auth-bootstrap'."

# --- enforcement: debe cubrir TODO el montaje userpass ---
if ! accessors=$(vault read -field=auth_method_accessors \
                  "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" 2>&1); then
  classify "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" "$accessors"
  die "no existe el enforcement MFA '${MFA_ENFORCEMENT}' (${accessors}). Ejecuta 'vpg-auth-bootstrap'."
fi
methods=$(vault read -field=mfa_method_ids "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" 2>/dev/null || echo '[]')
entities=$(vault read -field=identity_entity_ids "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" 2>/dev/null || echo '[]')
groups=$(vault read -field=identity_group_ids "identity/mfa/login-enforcement/${MFA_ENFORCEMENT}" 2>/dev/null || echo '[]')

ENF_COVERS_MOUNT=no
ENF_SCOPE=mount-wide
case "$accessors" in *"$ACCESSOR"*) ENF_COVERS_MOUNT=yes ;; esac
case "$methods"   in *"$METHOD_ID"*) ;; *) ENF_COVERS_MOUNT=no ;; esac
# Si el enforcement se limita a entidades o grupos concretos, NO cubre todo
# userpass con independencia del rol.
case "${entities}${groups}" in
  "[][]"|"[] []"|"") ;;
  *) ENF_SCOPE=restringido ;;
esac

printf 'USERPASS_PATH=%s\n'     "$USERPASS_PATH"
printf 'VAULT_USERNAME=%s\n'    "$ADMIN_USER"
printf 'USERPASS_ACCESSOR=%s\n' "$ACCESSOR"
printf 'ENTITY_ID=%s\n'         "$ENTITY_ID"
printf 'TOTP_METHOD_ID=%s\n'    "$METHOD_ID"
printf 'MFA_ENFORCEMENT=%s\n'   "$MFA_ENFORCEMENT"
printf 'ENF_COVERS_MOUNT=%s\n'  "$ENF_COVERS_MOUNT"
printf 'ENF_SCOPE=%s\n'         "$ENF_SCOPE"
PROBE
)

PROBE_OUT=$(printf '%s' "$VAULT_PROBE" | docker compose exec -T vault-service \
  sh -s "$USERPASS_PATH" "$ADMIN_USER" "$MFA_METHOD_NAME" "$MFA_ENFORCEMENT")

get_kv() { printf '%s\n' "$PROBE_OUT" | sed -n "s/^$1=//p" | head -n 1 | tr -d '\r'; }

VAULT_USERNAME=$(get_kv VAULT_USERNAME)
USERPASS_ACCESSOR=$(get_kv USERPASS_ACCESSOR)
ENTITY_ID=$(get_kv ENTITY_ID)
TOTP_METHOD_ID=$(get_kv TOTP_METHOD_ID)
ENF_COVERS_MOUNT=$(get_kv ENF_COVERS_MOUNT)
ENF_SCOPE=$(get_kv ENF_SCOPE)

for v in VAULT_USERNAME USERPASS_ACCESSOR ENTITY_ID TOTP_METHOD_ID; do
  [[ -n "${!v}" ]] || { echo "ERROR: Vault no devolvio ${v}." >&2; exit 1; }
done

echo "    userpass path .....: ${USERPASS_PATH}"
echo "    userpass accessor .: ${USERPASS_ACCESSOR}"
echo "    vault_username ....: ${VAULT_USERNAME}"
echo "    vault_entity_id ...: ${ENTITY_ID}"
echo "    totp method_id ....: ${TOTP_METHOD_ID} (${MFA_METHOD_NAME}, compartible entre empleados)"
echo "    mfa enforcement ...: ${MFA_ENFORCEMENT} (cubre el montaje: ${ENF_COVERS_MOUNT}, alcance: ${ENF_SCOPE})"

if [[ "$ENF_COVERS_MOUNT" != "yes" || "$ENF_SCOPE" != "mount-wide" ]]; then
  echo "AVISO: el enforcement '${MFA_ENFORCEMENT}' no cubre todo el montaje ${USERPASS_PATH}/." >&2
  echo "       Revisa 'vault read identity/mfa/login-enforcement/${MFA_ENFORCEMENT}'." >&2
  echo "       Se continua: el vinculo se registra igual, pero el MFA podria no exigirse a todos." >&2
fi

if [[ "$DRY_RUN" == true ]]; then
  echo
  echo "==> --dry-run: no se escribio nada en PostgreSQL."
  exit 0
fi

# =============================================================================
# 2. Insercion transaccional e idempotente en PostgreSQL
# =============================================================================
sql_lit() { printf '%s' "$1" | sed "s/'/''/g"; }

echo
echo "==> Insertando en ${PG_DB} (una sola transaccion)"

docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$PG_USER" --dbname "$PG_DB" <<SQL
BEGIN;

-- Los valores viajan como ajustes de sesion locales a la transaccion: psql no
-- interpola variables dentro de los bloques \$\$ ... \$\$.
SELECT set_config('vpg.username',         '$(sql_lit "$VAULT_USERNAME")',    true),
       set_config('vpg.role_code',        '$(sql_lit "$SEED_ROLE_CODE")',    true),
       set_config('vpg.first_name',       '$(sql_lit "$SEED_FIRST_NAME")',   true),
       set_config('vpg.last_name',        '$(sql_lit "$SEED_LAST_NAME")',    true),
       set_config('vpg.birth_date',       '$(sql_lit "$SEED_BIRTH_DATE")',   true),
       set_config('vpg.rfc',              '$(sql_lit "$SEED_RFC")',          true),
       set_config('vpg.curp',             '$(sql_lit "$SEED_CURP")',         true),
       set_config('vpg.phone_cc',         '$(sql_lit "$SEED_PHONE_CC")',     true),
       set_config('vpg.phone',            '$(sql_lit "$SEED_PHONE")',        true),
       set_config('vpg.neighborhood',     '$(sql_lit "$SEED_NEIGHBORHOOD")', true),
       set_config('vpg.street',           '$(sql_lit "$SEED_STREET")',       true),
       set_config('vpg.exterior',         '$(sql_lit "$SEED_EXTERIOR")',     true),
       set_config('vpg.interior',         '$(sql_lit "$SEED_INTERIOR")',     true),
       set_config('vpg.postal_code',      '$(sql_lit "$SEED_POSTAL_CODE")',  true),
       set_config('vpg.email',            '$(sql_lit "$SEED_EMAIL")',        true),
       set_config('vpg.userpass_path',    '$(sql_lit "$USERPASS_PATH")',     true),
       set_config('vpg.userpass_accessor','$(sql_lit "$USERPASS_ACCESSOR")', true),
       set_config('vpg.entity_id',        '$(sql_lit "$ENTITY_ID")',         true),
       set_config('vpg.totp_method_id',   '$(sql_lit "$TOTP_METHOD_ID")',    true),
       set_config('vpg.mfa_enforcement',  '$(sql_lit "$MFA_ENFORCEMENT")',   true)
\g /dev/null

DO \$seed\$
DECLARE
  v_username text := lower(current_setting('vpg.username'));
  v_path     text := current_setting('vpg.userpass_path');
  v_accessor text := current_setting('vpg.userpass_accessor');
  v_method   uuid := current_setting('vpg.totp_method_id')::uuid;
  v_enf      text := current_setting('vpg.mfa_enforcement');
  v_entity   uuid := current_setting('vpg.entity_id')::uuid;
  v_email    text := lower(current_setting('vpg.email'));
  v_cfg_id   uuid;
  v_user_id  uuid;
  v_role_id  uuid;
  v_owner    uuid;
  v_linked   uuid;
BEGIN
  ---------------------------------------------------------------- 1. config
  INSERT INTO employees.vault_auth_config
         (userpass_path, userpass_accessor, totp_method_id, mfa_enforcement_name)
  VALUES (v_path, v_accessor, v_method, v_enf)
  ON CONFLICT (userpass_path) DO UPDATE
     SET userpass_accessor    = EXCLUDED.userpass_accessor,
         totp_method_id       = EXCLUDED.totp_method_id,
         mfa_enforcement_name = EXCLUDED.mfa_enforcement_name
   WHERE vault_auth_config.userpass_accessor    IS DISTINCT FROM EXCLUDED.userpass_accessor
      OR vault_auth_config.totp_method_id       IS DISTINCT FROM EXCLUDED.totp_method_id
      OR vault_auth_config.mfa_enforcement_name IS DISTINCT FROM EXCLUDED.mfa_enforcement_name
  RETURNING id INTO v_cfg_id;

  IF v_cfg_id IS NULL THEN   -- no hubo cambios: ya estaba al dia
    SELECT id INTO v_cfg_id FROM employees.vault_auth_config WHERE userpass_path = v_path;
    RAISE NOTICE 'vault_auth_config: sin cambios (%)', v_cfg_id;
  ELSE
    RAISE NOTICE 'vault_auth_config: escrita (%)', v_cfg_id;
  END IF;

  ---------------------------------------------------------------- 2. usuario
  SELECT id INTO v_user_id FROM employees.users WHERE lower(username) = v_username;
  IF v_user_id IS NULL THEN
    INSERT INTO employees.users (username, auth_provider, password_hash, is_active)
    VALUES (v_username, 'vault', NULL, TRUE)
    RETURNING id INTO v_user_id;
    RAISE NOTICE 'users: creado % (%)', v_username, v_user_id;
  ELSE
    RAISE NOTICE 'users: ya existia % (%)', v_username, v_user_id;
  END IF;

  ---------------------------------------------------------------- 3. perfil
  IF EXISTS (SELECT 1 FROM employees.user_profiles WHERE user_id = v_user_id) THEN
    RAISE NOTICE 'user_profiles: ya existia';
  ELSE
    INSERT INTO employees.user_profiles
           (user_id, first_name, last_name_paternal, birth_date, rfc, curp)
    VALUES (v_user_id,
            current_setting('vpg.first_name'),
            current_setting('vpg.last_name'),
            current_setting('vpg.birth_date')::date,
            upper(current_setting('vpg.rfc')),
            upper(current_setting('vpg.curp')));
    RAISE NOTICE 'user_profiles: creado';
  END IF;

  ---------------------------------------------------------------- 4. rol
  SELECT id INTO v_role_id FROM employees.roles WHERE code = current_setting('vpg.role_code');
  IF v_role_id IS NULL THEN
    RAISE EXCEPTION 'el rol % no existe: aplica sql/001_employees.sql (vpg-pg-schema)',
      current_setting('vpg.role_code');
  END IF;
  INSERT INTO employees.user_roles (user_id, role_id)
  VALUES (v_user_id, v_role_id)
  ON CONFLICT (user_id, role_id) DO NOTHING;
  RAISE NOTICE 'user_roles: % <- %', v_username, current_setting('vpg.role_code');

  ---------------------------------------------------------------- 5. telefono
  IF EXISTS (SELECT 1 FROM employees.user_phones
              WHERE user_id = v_user_id
                AND country_code = current_setting('vpg.phone_cc')::smallint
                AND phone_number = current_setting('vpg.phone')) THEN
    RAISE NOTICE 'user_phones: ya existia';
  ELSE
    INSERT INTO employees.user_phones
           (user_id, country_code, phone_number, phone_type, is_primary)
    VALUES (v_user_id,
            current_setting('vpg.phone_cc')::smallint,
            current_setting('vpg.phone'),
            'mobile',
            NOT EXISTS (SELECT 1 FROM employees.user_phones
                         WHERE user_id = v_user_id AND is_primary));
    RAISE NOTICE 'user_phones: creado';
  END IF;

  ---------------------------------------------------------------- 6. direccion
  IF EXISTS (SELECT 1 FROM employees.user_addresses
              WHERE user_id = v_user_id
                AND street          = current_setting('vpg.street')
                AND exterior_number = current_setting('vpg.exterior')
                AND postal_code     = current_setting('vpg.postal_code')
                AND interior_number IS NOT DISTINCT FROM current_setting('vpg.interior')) THEN
    RAISE NOTICE 'user_addresses: ya existia';
  ELSE
    INSERT INTO employees.user_addresses
           (user_id, neighborhood, street, exterior_number, interior_number,
            postal_code, country_code, address_type, is_primary)
    VALUES (v_user_id,
            current_setting('vpg.neighborhood'),
            current_setting('vpg.street'),
            current_setting('vpg.exterior'),
            current_setting('vpg.interior'),
            current_setting('vpg.postal_code'),
            'MX', 'home',
            NOT EXISTS (SELECT 1 FROM employees.user_addresses
                         WHERE user_id = v_user_id AND is_primary));
    RAISE NOTICE 'user_addresses: creada';
  END IF;

  ---------------------------------------------------------------- 7. correo
  SELECT user_id INTO v_owner FROM employees.user_emails WHERE lower(email) = v_email;
  IF v_owner IS NULL THEN
    INSERT INTO employees.user_emails (user_id, email, is_primary)
    VALUES (v_user_id, v_email,
            NOT EXISTS (SELECT 1 FROM employees.user_emails
                         WHERE user_id = v_user_id AND is_primary));
    RAISE NOTICE 'user_emails: creado';
  ELSIF v_owner = v_user_id THEN
    RAISE NOTICE 'user_emails: ya existia';
  ELSE
    RAISE EXCEPTION 'el correo % ya pertenece a otro empleado (%)', v_email, v_owner;
  END IF;

  ---------------------------------------------- 8. vinculo con Vault
  SELECT vault_entity_id INTO v_linked
    FROM employees.user_vault_identity WHERE user_id = v_user_id;

  IF v_linked IS NULL THEN
    -- 'pending': el vinculo queda registrado, pero este proyecto no ha visto
    -- todavia un login MFA correcto. totp_generated_at se deja NULL porque la
    -- semilla la genero el bootstrap de Vault y aqui no se inventa la fecha.
    INSERT INTO employees.user_vault_identity
           (user_id, vault_auth_config_id, vault_username, vault_entity_id, totp_status)
    VALUES (v_user_id, v_cfg_id, v_username, v_entity, 'pending');
    RAISE NOTICE 'user_vault_identity: vinculado a la entidad % (totp_status=pending)', v_entity;
  ELSIF v_linked <> v_entity THEN
    RAISE EXCEPTION
      'el usuario % ya esta vinculado a la entidad % pero Vault reporta %. No se sobrescribe: revisalo manualmente.',
      v_username, v_linked, v_entity;
  ELSE
    UPDATE employees.user_vault_identity
       SET vault_auth_config_id = v_cfg_id
     WHERE user_id = v_user_id
       AND vault_auth_config_id IS DISTINCT FROM v_cfg_id;
    RAISE NOTICE 'user_vault_identity: ya vinculado a % (estado sin tocar)', v_entity;
  END IF;
END
\$seed\$;

COMMIT;
SQL

echo
echo "==> Hecho. Resumen (sin datos secretos):"
docker compose exec -T postgres-service \
  psql --no-psqlrc --username "$PG_USER" --dbname "$PG_DB" -x -c "
SELECT u.username,
       u.auth_provider,
       (u.password_hash IS NULL) AS password_hash_es_null,
       u.is_active,
       p.first_name, p.last_name_paternal, p.birth_date, p.rfc, p.curp,
       string_agg(DISTINCT r.code, ',') AS roles,
       vi.vault_username, vi.vault_entity_id, vi.totp_status,
       vi.last_mfa_login_at,
       c.userpass_path, c.userpass_accessor, c.mfa_enforcement_name
  FROM employees.users u
  LEFT JOIN employees.user_profiles p       ON p.user_id = u.id
  LEFT JOIN employees.user_roles ur         ON ur.user_id = u.id
  LEFT JOIN employees.roles r               ON r.id = ur.role_id
  LEFT JOIN employees.user_vault_identity vi ON vi.user_id = u.id
  LEFT JOIN employees.vault_auth_config c    ON c.id = vi.vault_auth_config_id
 WHERE lower(u.username) = lower('$(sql_lit "$VAULT_USERNAME")')
 GROUP BY u.username, u.auth_provider, u.password_hash, u.is_active,
          p.first_name, p.last_name_paternal, p.birth_date, p.rfc, p.curp,
          vi.vault_username, vi.vault_entity_id, vi.totp_status, vi.last_mfa_login_at,
          c.userpass_path, c.userpass_accessor, c.mfa_enforcement_name;"
