-- =============================================================================
-- VPG Contadores - Etapa 2 (local): registro de empleados, roles y vinculacion
-- con identidades existentes en HashiCorp Vault.
--
-- Ejecucion:  psql -v ON_ERROR_STOP=1 -f 001_employees.sql
-- Propiedades: transaccional (BEGIN/COMMIT) y repetible sobre el mismo esquema
--              sin borrar datos ni duplicar objetos.
--
-- AVISO: la repetibilidad NO sustituye un sistema de migraciones. "IF NOT
-- EXISTS" conserva los objetos ya creados: si una tabla existe con una
-- definicion anterior, este archivo no la altera. Todo cambio estructural
-- posterior necesita su propio script de migracion versionado.
--
-- AVISO: este archivo NO contiene secretos. Nunca se guardan aqui (ni en
-- PostgreSQL) contrasenas de Vault, semillas TOTP, codigos QR, URLs otpauth
-- ni tokens.
-- =============================================================================

BEGIN;

-- Esquema dedicado: separa el modelo de aplicacion de "public".
CREATE SCHEMA IF NOT EXISTS employees;

COMMENT ON SCHEMA employees IS
  'Empleados, roles de aplicacion y vinculacion con identidades de Vault.';

SET LOCAL search_path = employees, pg_catalog;

-- -----------------------------------------------------------------------------
-- updated_at automatico. Una sola funcion reutilizada por todos los triggers.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION employees.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;

COMMENT ON FUNCTION employees.set_updated_at() IS
  'Trigger BEFORE UPDATE: fija updated_at = now() ignorando el valor enviado.';

-- =============================================================================
-- 1. Usuarios (empleados)
-- =============================================================================
-- auth_provider delega la verificacion de credenciales:
--   'vault' -> Vault valida contrasena + TOTP (password_hash DEBE ser NULL)
--   'oidc'  -> el proveedor externo valida  (password_hash DEBE ser NULL)
--   'local' -> reservado para una futura autenticacion local con Argon2id
CREATE TABLE IF NOT EXISTS employees.users (
  id            UUID        NOT NULL DEFAULT gen_random_uuid(),
  username      TEXT        NOT NULL,
  is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
  auth_provider TEXT        NOT NULL DEFAULT 'vault',
  password_hash TEXT        NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT users_pk PRIMARY KEY (id),
  -- Longitud y juego de caracteres compatibles con los nombres que acepta
  -- el metodo userpass de Vault.
  CONSTRAINT users_username_format_ck CHECK (username ~ '^[A-Za-z0-9._-]{3,64}$'),
  CONSTRAINT users_auth_provider_ck   CHECK (auth_provider IN ('vault', 'oidc', 'local')),
  -- Si la autenticacion esta delegada, no puede haber hash local almacenado.
  CONSTRAINT users_delegated_no_hash_ck CHECK (
    auth_provider = 'local' OR password_hash IS NULL
  ),
  -- Cuando exista autenticacion local, solo se admite Argon2id en formato PHC.
  CONSTRAINT users_password_hash_argon2id_ck CHECK (
    password_hash IS NULL OR password_hash LIKE '$argon2id$%'
  )
);

COMMENT ON TABLE  employees.users IS 'Empleados con acceso al sistema.';
COMMENT ON COLUMN employees.users.is_active IS
  'Baja logica de la aplicacion. NO bloquea por si sola el acceso directo a Vault.';
COMMENT ON COLUMN employees.users.password_hash IS
  'Reservado para autenticacion local con Argon2id. NULL cuando se delega a Vault u OIDC.';

-- Login unico sin distincion de mayusculas/minusculas.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_ux
  ON employees.users (lower(username));

-- Listados del futuro backend: "empleados activos".
CREATE INDEX IF NOT EXISTS users_active_ix
  ON employees.users (is_active)
  WHERE is_active;

DROP TRIGGER IF EXISTS users_set_updated_at ON employees.users;
CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON employees.users
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

-- =============================================================================
-- 2. Roles de aplicacion y asignacion muchos a muchos
-- =============================================================================
-- NOTA: son roles de APLICACION, no roles ni superusuarios de PostgreSQL. Estas
-- tablas almacenan la intencion; quien la hace cumplir sera el futuro backend
-- (y, para los secretos, las politicas de Vault).
CREATE TABLE IF NOT EXISTS employees.roles (
  id          UUID        NOT NULL DEFAULT gen_random_uuid(),
  code        TEXT        NOT NULL,
  name        TEXT        NOT NULL,
  description TEXT        NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT roles_pk      PRIMARY KEY (id),
  CONSTRAINT roles_code_uq UNIQUE (code),
  CONSTRAINT roles_code_ck CHECK (code ~ '^[a-z][a-z0-9_]{2,31}$'),
  CONSTRAINT roles_name_ck CHECK (btrim(name) <> '')
);

COMMENT ON TABLE employees.roles IS
  'Roles de aplicacion (admin, manager, employee). No son roles de PostgreSQL.';

DROP TRIGGER IF EXISTS roles_set_updated_at ON employees.roles;
CREATE TRIGGER roles_set_updated_at
  BEFORE UPDATE ON employees.roles
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

CREATE TABLE IF NOT EXISTS employees.user_roles (
  user_id     UUID        NOT NULL,
  role_id     UUID        NOT NULL,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  assigned_by UUID        NULL,

  -- La PK compuesta impide duplicar la misma pareja usuario/rol.
  CONSTRAINT user_roles_pk PRIMARY KEY (user_id, role_id),
  -- CASCADE: al borrar un empleado desaparecen sus asignaciones.
  CONSTRAINT user_roles_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,
  -- RESTRICT: un rol en uso no se borra por accidente.
  CONSTRAINT user_roles_role_fk FOREIGN KEY (role_id)
    REFERENCES employees.roles (id) ON DELETE RESTRICT,
  -- SET NULL: se conserva la asignacion aunque se borre quien la hizo.
  CONSTRAINT user_roles_assigned_by_fk FOREIGN KEY (assigned_by)
    REFERENCES employees.users (id) ON DELETE SET NULL
);

COMMENT ON TABLE employees.user_roles IS
  'Asignacion muchos a muchos usuario <-> rol; la PK compuesta evita duplicados.';

-- La PK (user_id, role_id) ya cubre las busquedas por user_id (prefijo).
-- Solo falta el sentido inverso: "quien tiene el rol X".
CREATE INDEX IF NOT EXISTS user_roles_role_ix
  ON employees.user_roles (role_id);

-- =============================================================================
-- 3. Perfil: exactamente uno por usuario (user_id es la PK)
-- =============================================================================
CREATE TABLE IF NOT EXISTS employees.user_profiles (
  user_id            UUID        NOT NULL,
  first_name         TEXT        NOT NULL,
  last_name_paternal TEXT        NOT NULL,
  last_name_maternal TEXT        NULL,   -- puede faltar legitimamente
  birth_date         DATE        NOT NULL,
  rfc                TEXT        NULL,
  curp               TEXT        NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- PK = FK: garantiza perfil unico por usuario sin indice adicional.
  CONSTRAINT user_profiles_pk PRIMARY KEY (user_id),
  CONSTRAINT user_profiles_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,

  CONSTRAINT user_profiles_first_name_ck CHECK (btrim(first_name) <> ''),
  CONSTRAINT user_profiles_last_name_ck  CHECK (btrim(last_name_paternal) <> ''),
  -- Rango razonable: ni fechas futuras ni anteriores a 1900.
  CONSTRAINT user_profiles_birth_date_ck CHECK (
    birth_date >= DATE '1900-01-01' AND birth_date <= CURRENT_DATE
  ),
  -- RFC de persona fisica: 4 letras + AAMMDD + homoclave de 3.
  CONSTRAINT user_profiles_rfc_format_ck CHECK (
    rfc IS NULL OR rfc ~ '^[A-Z&N]{4}[0-9]{6}[A-Z0-9]{3}$'
  ),
  -- CURP: 4 letras + AAMMDD + sexo + entidad + 3 consonantes + homoclave + digito.
  CONSTRAINT user_profiles_curp_format_ck CHECK (
    curp IS NULL OR curp ~ '^[A-Z]{4}[0-9]{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9][0-9]$'
  ),
  -- Posiciones 5-10 de RFC/CURP codifican la fecha de nacimiento: debe cuadrar.
  CONSTRAINT user_profiles_rfc_birth_date_ck CHECK (
    rfc IS NULL OR substring(rfc FROM 5 FOR 6) = to_char(birth_date, 'YYMMDD')
  ),
  CONSTRAINT user_profiles_curp_birth_date_ck CHECK (
    curp IS NULL OR substring(curp FROM 5 FOR 6) = to_char(birth_date, 'YYMMDD')
  ),
  -- Identificadores fiscales irrepetibles entre empleados.
  CONSTRAINT user_profiles_rfc_uq  UNIQUE (rfc),
  CONSTRAINT user_profiles_curp_uq UNIQUE (curp)
);

COMMENT ON TABLE employees.user_profiles IS
  'Datos personales. Uno por usuario (PK = FK a users).';

DROP TRIGGER IF EXISTS user_profiles_set_updated_at ON employees.user_profiles;
CREATE TRIGGER user_profiles_set_updated_at
  BEFORE UPDATE ON employees.user_profiles
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

-- =============================================================================
-- 4. Contacto: telefonos, direcciones y correos (uno a muchos)
-- =============================================================================
CREATE TABLE IF NOT EXISTS employees.user_phones (
  id           UUID        NOT NULL DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL,
  country_code SMALLINT    NOT NULL DEFAULT 52,   -- Mexico
  phone_number TEXT        NOT NULL,
  phone_type   TEXT        NOT NULL DEFAULT 'mobile',
  extension    TEXT        NULL,
  is_primary   BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT user_phones_pk PRIMARY KEY (id),
  CONSTRAINT user_phones_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,
  -- Solo digitos: el formato de presentacion es cosa de la capa superior.
  CONSTRAINT user_phones_number_ck    CHECK (phone_number ~ '^[0-9]{7,15}$'),
  CONSTRAINT user_phones_country_ck   CHECK (country_code >= 1 AND country_code <= 999),
  CONSTRAINT user_phones_type_ck      CHECK (phone_type IN ('mobile', 'home', 'work', 'other')),
  CONSTRAINT user_phones_extension_ck CHECK (extension IS NULL OR extension ~ '^[0-9]{1,8}$'),
  -- El mismo numero no se repite dentro del mismo empleado.
  CONSTRAINT user_phones_unique_per_user_uq UNIQUE (user_id, country_code, phone_number)
);

COMMENT ON TABLE employees.user_phones IS 'Telefonos del empleado (uno a muchos).';

CREATE INDEX IF NOT EXISTS user_phones_user_ix
  ON employees.user_phones (user_id);

-- Como maximo un telefono principal por empleado.
CREATE UNIQUE INDEX IF NOT EXISTS user_phones_one_primary_ux
  ON employees.user_phones (user_id)
  WHERE is_primary;

DROP TRIGGER IF EXISTS user_phones_set_updated_at ON employees.user_phones;
CREATE TRIGGER user_phones_set_updated_at
  BEFORE UPDATE ON employees.user_phones
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();


CREATE TABLE IF NOT EXISTS employees.user_addresses (
  id              UUID        NOT NULL DEFAULT gen_random_uuid(),
  user_id         UUID        NOT NULL,
  neighborhood    TEXT        NULL,   -- colonia / fraccionamiento
  street          TEXT        NOT NULL,
  exterior_number TEXT        NOT NULL,
  interior_number TEXT        NULL,
  postal_code     TEXT        NOT NULL,
  city            TEXT        NULL,
  state_code      TEXT        NULL,   -- clave de entidad federativa (SIN, JAL...)
  country_code    TEXT        NOT NULL DEFAULT 'MX',
  address_type    TEXT        NOT NULL DEFAULT 'home',
  is_primary      BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT user_addresses_pk PRIMARY KEY (id),
  CONSTRAINT user_addresses_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,
  CONSTRAINT user_addresses_street_ck      CHECK (btrim(street) <> ''),
  CONSTRAINT user_addresses_exterior_ck    CHECK (btrim(exterior_number) <> ''),
  CONSTRAINT user_addresses_postal_code_ck CHECK (postal_code ~ '^[0-9]{5}$'),
  CONSTRAINT user_addresses_country_ck     CHECK (country_code ~ '^[A-Z]{2}$'),
  CONSTRAINT user_addresses_state_ck       CHECK (state_code IS NULL OR state_code ~ '^[A-Z]{2,4}$'),
  CONSTRAINT user_addresses_type_ck        CHECK (address_type IN ('home', 'work', 'fiscal', 'other'))
);

COMMENT ON TABLE employees.user_addresses IS 'Direcciones del empleado (uno a muchos).';

CREATE INDEX IF NOT EXISTS user_addresses_user_ix
  ON employees.user_addresses (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS user_addresses_one_primary_ux
  ON employees.user_addresses (user_id)
  WHERE is_primary;

DROP TRIGGER IF EXISTS user_addresses_set_updated_at ON employees.user_addresses;
CREATE TRIGGER user_addresses_set_updated_at
  BEFORE UPDATE ON employees.user_addresses
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();


CREATE TABLE IF NOT EXISTS employees.user_emails (
  id          UUID        NOT NULL DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL,
  email       TEXT        NOT NULL,
  is_primary  BOOLEAN     NOT NULL DEFAULT FALSE,
  is_verified BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT user_emails_pk PRIMARY KEY (id),
  CONSTRAINT user_emails_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,
  CONSTRAINT user_emails_format_ck CHECK (
    email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[A-Za-z]{2,}$'
  ),
  CONSTRAINT user_emails_length_ck CHECK (char_length(email) <= 254)
);

COMMENT ON TABLE employees.user_emails IS
  'Correos del empleado (uno a muchos). Unicos globalmente sin distinguir mayusculas.';

-- Un correo pertenece a un unico empleado, sin distincion de mayusculas.
CREATE UNIQUE INDEX IF NOT EXISTS user_emails_email_lower_ux
  ON employees.user_emails (lower(email));

-- El indice parcial de "principal" no sirve para listar todos los correos
-- de un empleado; este si.
CREATE INDEX IF NOT EXISTS user_emails_user_ix
  ON employees.user_emails (user_id);

-- Como maximo un correo principal por empleado.
CREATE UNIQUE INDEX IF NOT EXISTS user_emails_one_primary_ux
  ON employees.user_emails (user_id)
  WHERE is_primary;

DROP TRIGGER IF EXISTS user_emails_set_updated_at ON employees.user_emails;
CREATE TRIGGER user_emails_set_updated_at
  BEFORE UPDATE ON employees.user_emails
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

-- =============================================================================
-- 5. Configuracion compartida de autenticacion en Vault
-- =============================================================================
-- Un registro por montaje userpass. El metodo TOTP se comparte entre empleados
-- (cada entidad de Vault tiene su propia semilla individual), por eso
-- totp_method_id NO lleva UNIQUE.
CREATE TABLE IF NOT EXISTS employees.vault_auth_config (
  id                   UUID        NOT NULL DEFAULT gen_random_uuid(),
  userpass_path        TEXT        NOT NULL,
  -- TEXT, no UUID: los accessors de Vault tienen forma "auth_userpass_1a2b3c4d".
  userpass_accessor    TEXT        NOT NULL,
  totp_method_id       UUID        NOT NULL,
  mfa_enforcement_name TEXT        NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT vault_auth_config_pk PRIMARY KEY (id),
  CONSTRAINT vault_auth_config_path_uq     UNIQUE (userpass_path),
  CONSTRAINT vault_auth_config_accessor_uq UNIQUE (userpass_accessor),
  CONSTRAINT vault_auth_config_path_ck     CHECK (userpass_path ~ '^[a-z0-9._-]{1,64}$'),
  CONSTRAINT vault_auth_config_accessor_ck CHECK (btrim(userpass_accessor) <> ''),
  CONSTRAINT vault_auth_config_enforcement_ck CHECK (btrim(mfa_enforcement_name) <> '')
);

COMMENT ON TABLE employees.vault_auth_config IS
  'Ruta userpass, su accessor (TEXT), el method_id TOTP y el nombre del enforcement MFA.';
COMMENT ON COLUMN employees.vault_auth_config.userpass_accessor IS
  'Accessor del montaje (p. ej. auth_userpass_1a2b3c4d): es TEXT, no un UUID.';
COMMENT ON COLUMN employees.vault_auth_config.totp_method_id IS
  'Sin UNIQUE a proposito: un mismo metodo TOTP se comparte entre empleados.';

DROP TRIGGER IF EXISTS vault_auth_config_set_updated_at ON employees.vault_auth_config;
CREATE TRIGGER vault_auth_config_set_updated_at
  BEFORE UPDATE ON employees.vault_auth_config
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

-- =============================================================================
-- 6. Vinculacion individual usuario <-> identidad de Vault
-- =============================================================================
-- PostgreSQL guarda el VINCULO y su historia. Vault es quien verifica
-- contrasena y TOTP en cada login: una fila con totp_status='confirmed'
-- documenta un enrolamiento pasado, NO autoriza omitir el MFA.
CREATE TABLE IF NOT EXISTS employees.user_vault_identity (
  user_id              UUID        NOT NULL,
  vault_auth_config_id UUID        NOT NULL,
  vault_username       TEXT        NOT NULL,
  vault_entity_id      UUID        NOT NULL,
  totp_status          TEXT        NOT NULL DEFAULT 'pending',
  totp_generated_at    TIMESTAMPTZ NULL,
  totp_confirmed_at    TIMESTAMPTZ NULL,
  last_mfa_login_at    TIMESTAMPTZ NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Relacion individual: PK = FK al usuario (como maximo una identidad).
  CONSTRAINT user_vault_identity_pk PRIMARY KEY (user_id),
  CONSTRAINT user_vault_identity_user_fk FOREIGN KEY (user_id)
    REFERENCES employees.users (id) ON DELETE CASCADE,
  -- RESTRICT: no se borra una configuracion de auth con vinculos vivos.
  CONSTRAINT user_vault_identity_config_fk FOREIGN KEY (vault_auth_config_id)
    REFERENCES employees.vault_auth_config (id) ON DELETE RESTRICT,

  CONSTRAINT user_vault_identity_username_uq UNIQUE (vault_username),
  CONSTRAINT user_vault_identity_entity_uq   UNIQUE (vault_entity_id),
  -- userpass normaliza a minusculas; el alias debe coincidir exactamente.
  CONSTRAINT user_vault_identity_username_lower_ck CHECK (
    vault_username = lower(vault_username)
  ),
  CONSTRAINT user_vault_identity_username_format_ck CHECK (
    vault_username ~ '^[a-z0-9._-]{3,64}$'
  ),
  CONSTRAINT user_vault_identity_totp_status_ck CHECK (
    totp_status IN ('pending', 'confirmed', 'reset_required', 'disabled')
  ),
  -- 'confirmed' exige constancia de cuando se confirmo.
  CONSTRAINT user_vault_identity_confirmed_ck CHECK (
    totp_status <> 'confirmed' OR totp_confirmed_at IS NOT NULL
  ),
  CONSTRAINT user_vault_identity_timeline_ck CHECK (
    totp_generated_at IS NULL
    OR totp_confirmed_at IS NULL
    OR totp_confirmed_at >= totp_generated_at
  )
);

COMMENT ON TABLE employees.user_vault_identity IS
  'Vinculo 1:1 con la entidad de Vault y estado historico de su enrolamiento TOTP.';
COMMENT ON COLUMN employees.user_vault_identity.totp_status IS
  'pending | confirmed | reset_required | disabled. Informativo: no sustituye al MFA de Vault.';
COMMENT ON COLUMN employees.user_vault_identity.last_mfa_login_at IS
  'Ultimo login userpass+TOTP verificado por este proyecto (entity_id coincidente).';

CREATE INDEX IF NOT EXISTS user_vault_identity_config_ix
  ON employees.user_vault_identity (vault_auth_config_id);

-- Consultas operativas: "quien falta por confirmar TOTP".
CREATE INDEX IF NOT EXISTS user_vault_identity_totp_status_ix
  ON employees.user_vault_identity (totp_status);

DROP TRIGGER IF EXISTS user_vault_identity_set_updated_at ON employees.user_vault_identity;
CREATE TRIGGER user_vault_identity_set_updated_at
  BEFORE UPDATE ON employees.user_vault_identity
  FOR EACH ROW EXECUTE FUNCTION employees.set_updated_at();

-- =============================================================================
-- 7. Siembra idempotente de los roles de aplicacion
-- =============================================================================
INSERT INTO employees.roles (code, name, description) VALUES
  ('admin',    'Administrador',
   'Administra empleados y asignaciones de roles.'),
  ('manager',  'Gestor',
   'CRUD operativo de empleados; no administra roles ni credenciales ajenas.'),
  ('employee', 'Empleado',
   'Consulta su propio perfil y modifica sus datos de contacto.')
ON CONFLICT (code) DO UPDATE
  SET name        = EXCLUDED.name,
      description = EXCLUDED.description
  WHERE roles.name        IS DISTINCT FROM EXCLUDED.name
     OR roles.description IS DISTINCT FROM EXCLUDED.description;

COMMIT;
