# Componente 2: PostgreSQL 17 (empleados, roles y vínculo con Vault)

[← Índice del proyecto](../README.md)

Etapas: [1. HashiCorp Vault](etapa-1-vault.md) · **2. PostgreSQL 17** · [3. user-mgmt-service](etapa-3-user-mgmt-service.md) · [4. vault-mgmt-service](etapa-4-vault-mgmt-service.md)

---

Etapa 2 **local**: `postgres:17-alpine` en la misma red `network-service` que
Vault, con el modelo de empleados, roles de aplicación y la tabla que vincula
cada empleado con la identidad que **ya existe** en Vault.

> **Alcance de esta etapa.** Aquí termina en PostgreSQL + modelo + vínculo con
> Vault + verificaciones por CLI. **No hay FastAPI, frontend, endpoints,
> servicios HTTP ni ORM**, y no se añaden en esta etapa. La «futura API» se
> menciona solo para justificar la forma del modelo y el reparto de permisos.

### Archivos de este componente

| Archivo | Propósito |
|---|---|
| `Dockerfile` | Etapas `postgres-assets` (normaliza CRLF y permisos) → `postgres-server`. **Conserva el entrypoint oficial** de PostgreSQL |
| `compose.yaml` | Servicio `postgres-service` en `network-service`, volumen `postgres-data`, healthcheck y Compose secrets |
| `sql/001_employees.sql` | DDL del esquema `employees` (transaccional y repetible) + siembra de roles |
| `scripts/postgres/pg-schema.sh` | Aplica el DDL con `psql`. En la imagen: `vpg-pg-schema` |
| `scripts/postgres/pg-app-role.sh` | Crea/converge la cuenta de ejecución `vpg_app`. En la imagen: `vpg-pg-roles` |
| `scripts/postgres/prepare-secrets.sh` | Genera `secrets/postgres_password` y `secrets/postgres_app_password` |
| `scripts/postgres/seed-initial-user.sh` | Inserción transaccional e idempotente del empleado inicial + vínculo con Vault |
| `scripts/postgres/validate-schema.sh` | Inspección del modelo y pruebas de restricciones que **siempre** terminan en `ROLLBACK` |
| `scripts/postgres/verify-vault-mfa.sh` | **Interactivo.** Login userpass + TOTP real y confirmación del enrolamiento |
| `requirements/postgres.txt` | **Sin paquetes**: en el contenedor de la base de datos no se instala Python ni dependencias |
| `.env` / `.env.example` | Parámetros **no sensibles** `POSTGRES_*` y nombres de los recursos de Vault |

Las contraseñas de PostgreSQL **no están en `.env`**: se suministran por
Compose secrets y se leen con `POSTGRES_PASSWORD_FILE` /
`POSTGRES_APP_PASSWORD_FILE`. El directorio `secrets/` está excluido del
repositorio (`.gitignore`) y del contexto de build (`.dockerignore`).

`postgres-service` **no usa `env_file: .env`** a propósito: así las variables
`VAULT_*` (incluida `VAULT_ADMIN_USER_PASS`) nunca entran en el entorno del
contenedor de la base de datos.

### Dos cuentas de PostgreSQL con responsabilidades separadas

| Cuenta | Origen | Para qué | Privilegios |
|---|---|---|---|
| `vpg_admin` (`POSTGRES_USER`) | la crea `initdb` | Administración y **propiedad del esquema**: DDL y migraciones | superusuario |
| `vpg_app` (`POSTGRES_APP_USER`) | `vpg-pg-roles` | Cuenta de **ejecución** del futuro backend | `LOGIN`, `CONNECT`, `USAGE` en `employees` (**sin `CREATE`**), `SELECT/INSERT/UPDATE/DELETE`. Sin `SUPERUSER`, `CREATEDB`, `CREATEROLE`, `TRUNCATE` ni nada en `public` |

`ALTER DEFAULT PRIVILEGES` hace que las tablas que cree después `vpg_admin`
hereden los mismos permisos para `vpg_app`.

### Modelo de datos (esquema `employees`)

Nombres en `snake_case`, claves primarias `UUID` con `gen_random_uuid()`
(nativo en PostgreSQL 17, sin extensiones), `created_at`/`updated_at` en
`TIMESTAMPTZ` y un único trigger `employees.set_updated_at()` por tabla.

| Tabla | Cardinalidad | Notas |
|---|---|---|
| `users` | — | Login único **sin distinción de mayúsculas** (`UNIQUE (lower(username))`), `is_active`, `auth_provider` ∈ {`vault`,`oidc`,`local`} |
| `roles` | — | `code` único (`admin`, `manager`, `employee`) |
| `user_roles` | N:M | `PRIMARY KEY (user_id, role_id)`: imposible duplicar la pareja |
| `user_profiles` | 1:1 | `PK = FK` a `users`: perfil único por usuario. Nombre, apellidos, fecha de nacimiento, RFC y CURP |
| `user_phones` | 1:N | `UNIQUE (user_id, country_code, phone_number)`, máximo un principal |
| `user_addresses` | 1:N | Colonia, calle, exterior, interior, CP, máximo una principal |
| `user_emails` | 1:N | `UNIQUE (lower(email))` global, máximo un principal por usuario |
| `vault_auth_config` | — | Configuración **compartida**: ruta userpass, su accessor, el `method_id` TOTP y el nombre del enforcement |
| `user_vault_identity` | 1:1 | Vínculo con la entidad de Vault y estado histórico del enrolamiento TOTP |

#### `password_hash`: reservado, y NULL cuando se delega

`users.password_hash` es **nullable** y está reservado para una futura
autenticación local con **Argon2id**. Dos `CHECK` lo garantizan:

- `users_delegated_no_hash_ck`: si `auth_provider <> 'local'` (es decir, cuando
  la autenticación está delegada a Vault o a OIDC), `password_hash` **debe ser
  NULL**.
- `users_password_hash_argon2id_ck`: si hay hash, tiene que empezar por
  `$argon2id$` (formato PHC). No se admiten bcrypt ni otros.

#### Justificación de las políticas `ON DELETE`

| Relación | Política | Por qué |
|---|---|---|
| `user_roles.user_id → users` | `CASCADE` | Al borrar un empleado sus asignaciones dejan de tener sentido |
| `user_roles.role_id → roles` | `RESTRICT` | Un rol en uso no se borra por accidente |
| `user_roles.assigned_by → users` | `SET NULL` | Se conserva la asignación aunque desaparezca quien la hizo |
| `user_profiles`, `user_phones`, `user_addresses`, `user_emails`, `user_vault_identity` → `users` | `CASCADE` | Son datos **dependientes** del empleado |
| `user_vault_identity.vault_auth_config_id → vault_auth_config` | `RESTRICT` | No se borra una configuración de autenticación con vínculos vivos |

#### `CHECK` que vale la pena conocer

- RFC: `^[A-Z&N]{4}[0-9]{6}[A-Z0-9]{3}$`; CURP:
  `^[A-Z]{4}[0-9]{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9][0-9]$`.
- Las posiciones 5-10 de RFC **y** CURP codifican la fecha de nacimiento, y hay
  un `CHECK` que exige que coincidan con `birth_date`.
- `vault_username` tiene que estar en minúsculas (`= lower(vault_username)`),
  porque el método userpass de Vault normaliza así los nombres.
- `totp_status = 'confirmed'` exige `totp_confirmed_at IS NOT NULL`.

#### Índices

29 índices, sin redundancias (`validate-schema.sh indices` lo comprueba). Los
de `PRIMARY KEY` y `UNIQUE` los crea la propia restricción y **no se duplican**
con un `CREATE INDEX`. Los añadidos explícitamente cubren lo que las
restricciones no:

- `users_username_lower_ux` (único, `lower(username)`) y `users_active_ix`
  (parcial, `WHERE is_active`).
- `user_emails_email_lower_ux` (único, `lower(email)`) y `user_emails_user_ix`
  — el índice parcial de «principal» no sirve para listar todos los correos de
  un empleado.
- `user_phones_user_ix`, `user_addresses_user_ix`,
  `user_vault_identity_config_ix`, `user_vault_identity_totp_status_ix`.
- `user_roles_role_ix`: el sentido inverso de la `PK (user_id, role_id)`, cuyo
  prefijo ya cubre las búsquedas por `user_id`.

### RBAC: matriz de permisos

Son **roles de aplicación**, no roles ni superusuarios de PostgreSQL. La
siembra es idempotente (`ON CONFLICT (code)`).

| Capacidad | `admin` | `manager` | `employee` |
|---|---|---|---|
| Crear / editar / dar de baja empleados | ✅ | ✅ | ❌ |
| Consultar cualquier empleado | ✅ | ✅ | ❌ |
| Consultar su propio perfil | ✅ | ✅ | ✅ |
| Modificar sus propios datos de contacto | ✅ | ✅ | ✅ |
| Modificar el contacto de otros | ✅ | ✅ | ❌ |
| Asignar o quitar roles | ✅ | ❌ | ❌ |
| Administrar credenciales ajenas (vínculo Vault, reset TOTP) | ✅ | ❌ | ❌ |

> **Estas tablas NO hacen cumplir los permisos por sí solas.** `roles` y
> `user_roles` almacenan la *intención*; quien la aplique será el futuro
> backend. PostgreSQL solo garantiza la integridad del dato (sin duplicados,
> sin roles inexistentes). Y para los **secretos**, quien autoriza es Vault con
> sus políticas, no estas tablas.

#### Correspondencia *futura* con políticas de Vault

Hoy solo existen las políticas `vpg-admin` y `vpg-oidc-user` del componente 1.
`vpg-admin` está asignada **únicamente** al administrador inicial: **no se
asigna a todos los empleados**. Este es el mapeo previsto, todavía **no
implementado**:

| Rol de aplicación | Política de Vault prevista | Alcance previsto |
|---|---|---|
| `admin` | `vpg-admin` (existe) | Administración de Vault |
| `manager` | `vpg-operator` (**pendiente**) | Lectura/escritura de `secret/sat/*` |
| `employee` | `vpg-employee-self` (**pendiente**) | Sin acceso a `secret/*`, o solo a su propia ruta |

### Vinculación con Vault y MFA TOTP: quién hace qué

| | PostgreSQL | Vault |
|---|---|---|
| Vínculo empleado ↔ identidad | **sí** (`user_vault_identity`) | — |
| Estado histórico del enrolamiento | **sí** (`totp_status`, fechas) | — |
| Verificar contraseña | no | **sí** (`auth/userpass`) |
| Verificar código TOTP | no | **sí** (`identity/mfa/*`) |
| Guardar semilla TOTP / QR / otpauth | **nunca** | sí |

> **Una fila con `totp_status = 'confirmed'` NO permite omitir el MFA.** Es un
> registro histórico. Vault exige contraseña + TOTP en **cada** login, y el
> enforcement `vpg-userpass-totp` cubre **todo** el montaje `userpass`
> independientemente del rol. Los permisos para consultar secretos siguen
> dependiendo de las políticas de Vault, no de estas tablas.

`vault_auth_config.userpass_accessor` es **TEXT**, no `UUID`: los accessors de
Vault tienen la forma `auth_userpass_32a80de2`.

`vault_auth_config.totp_method_id` **no lleva `UNIQUE`** a propósito: un mismo
método TOTP se comparte entre empleados, aunque cada entidad tenga su propia
semilla individual.

**Qué no se almacena nunca en PostgreSQL, en los archivos SQL ni en los logs:**
contraseñas de Vault, semillas TOTP, códigos QR, URLs `otpauth://` y tokens.

> **Desactivar un empleado en PostgreSQL (`users.is_active = FALSE`) NO bloquea
> por sí solo su acceso directo a Vault.** Mientras exista su usuario en
> `auth/userpass` y conserve su política, podrá seguir iniciando sesión en Vault
> y leer los secretos que esa política le permita. Para cortar el acceso real
> hay que actuar **también** en Vault: quitarle las políticas
> (`vault write auth/userpass/users/<u> token_policies=""`), borrar el usuario
> (`vault delete auth/userpass/users/<u>`) y revocar sus tokens vivos
> (`vault lease revoke -prefix auth/userpass/`). `is_active` es una baja lógica
> de la aplicación.

---

## Comprobaciones reproducibles (Git Bash)

Todas se ejecutan desde la raíz del repositorio. Las marcadas
**🖐 INTERACTIVO** piden algo por teclado y necesitan una terminal real.

> **Git Bash:** si un comando interactivo muestra
> `the input device is not a TTY`, antepón `winpty`. Los argumentos que empiezan
> con `/` se convierten en rutas de Windows; por eso algunos comandos llevan
> `MSYS_NO_PATHCONV=1`.

> **Puerto 5432.** El valor por defecto es `POSTGRES_PORT_LOCAL=5432`. Si el
> equipo ya tiene una instalación nativa de PostgreSQL escuchando ahí,
> `docker compose up` falla con
> `ports are not available: ... bind: An attempt was made to access a socket in a way forbidden by its access permissions`.
> Compruébalo con `netstat -ano | grep 5432` y cambia `POSTGRES_PORT_LOCAL` en
> `.env` (p. ej. a `5434`). Las comprobaciones de abajo se ejecutaron con
> `5434` por esa razón.

### 1. Preparar secretos, validar la configuración y arrancar

```bash
cp .env.example .env                        # solo parámetros no sensibles
bash scripts/postgres/prepare-secrets.sh    # genera secrets/ (no muestra valores)
docker compose config --quiet && echo "config OK"
docker compose build
docker compose up -d
```

`prepare-secrets.sh` no sobrescribe un secreto existente salvo `--force`.

> **Importante:** recrear el contenedor con un `POSTGRES_PASSWORD` distinto
> **no** cambia la contraseña ya guardada en el volumen: `initdb` solo la fija
> la primera vez. La contraseña de `vpg_app` sí converge, porque `vpg-pg-roles`
> hace `ALTER ROLE ... PASSWORD` en cada ejecución.

**Resultado esperado**

```
==> postgres_password: generando
==> postgres_app_password: generando
    postgres_password        32 caracteres
    postgres_app_password    32 caracteres
config OK
 Image vpg/postgres-server:17-alpine Built
 Container vpg-postgres Started
```

### 2. Estado, logs y redes

```bash
docker compose ps
docker compose logs postgres-service | tail -20
docker network ls --filter name=network-service
docker network inspect network-service --format '{{.Name}} driver={{.Driver}} subnet={{range .IPAM.Config}}{{.Subnet}}{{end}}
contenedores:{{range .Containers}}
  {{.Name}} -> {{.IPv4Address}}{{end}}'
```

**Resultado real**

```
NAME           SERVICE            STATUS                   PORTS
vpg-postgres   postgres-service   Up (healthy)             127.0.0.1:5434->5432/tcp
vpg-vault      vault-service      Up (healthy)             0.0.0.0:8200->8200/tcp

network-service driver=bridge subnet=172.18.0.0/16
contenedores:
  vpg-vault -> 172.18.0.2/16
  vpg-postgres -> 172.18.0.3/16
```

El healthcheck (`pg_isready`, `interval=15s`, `timeout=5s`, `retries=5`,
`start_period=40s`) está declarado en `compose.yaml`.

### 3. Resolver `postgres-service` desde otro contenedor de la red

```bash
docker compose exec vault-service sh -c 'nslookup postgres-service | tail -5; nc -z -w 3 postgres-service 5432 && echo "TCP 5432 alcanzable"'
```

**Resultado real**

```
Non-authoritative answer:
Name:	postgres-service
Address: 172.18.0.3
TCP 5432 alcanzable
```

### 4. `pg_isready` y una conexión autenticada con `SELECT 1`

```bash
# a) healthcheck manual
docker compose exec postgres-service pg_isready --username=vpg_admin --dbname=vpg_contadores

# b) conexión autenticada por TCP como la cuenta de ejecución (scram-sha-256).
#    La contraseña se pasa por el entorno del exec, no como argumento del comando.
APPPW=$(cat secrets/postgres_app_password)
docker compose exec -T -e PGPASSWORD="$APPPW" postgres-service \
  psql --host=127.0.0.1 --username=vpg_app --dbname=vpg_contadores -qtAX \
       -c "SELECT 1 AS ok, current_user, current_setting('search_path');"
unset APPPW

# c) desde el host, por el puerto publicado
PORT=$(sed -n 's/^POSTGRES_PORT_LOCAL=//p' .env | tr -d '\r')
APPPW=$(cat secrets/postgres_app_password)
docker run --rm --network host -e PGPASSWORD="$APPPW" postgres:17-alpine \
  psql --host=127.0.0.1 --port="$PORT" --username=vpg_app --dbname=vpg_contadores \
       -qtAX -c "SELECT 1 AS ok, inet_server_addr();"
unset APPPW
```

**Resultado real**

```
/var/run/postgresql:5432 - accepting connections
1|vpg_app|employees
1|172.18.0.3
```

Desde PowerShell, `Test-NetConnection -ComputerName 127.0.0.1 -Port 5434 -InformationLevel Quiet`
devolvió `True`.

### 5. Inspeccionar tablas, restricciones e índices

```bash
bash scripts/postgres/validate-schema.sh tablas
bash scripts/postgres/validate-schema.sh constraints
bash scripts/postgres/validate-schema.sh indices
```

**Resultado real (resumen)**

```
9 tablas: roles, user_addresses, user_emails, user_phones, user_profiles,
          user_roles, user_vault_identity, users, vault_auth_config

restricciones:  33 CHECK | 9 FOREIGN KEY | 9 PRIMARY KEY | 8 UNIQUE
índices:        29
índices redundantes (misma tabla y mismas columnas/expresión): (0 rows)
triggers de updated_at: 8 (uno por tabla con updated_at)
```

### 6. Insertar y consultar al empleado `sinhue`

Requiere **Vault desbloqueado** y con los recursos del componente 1 ya
configurados (`vpg-auth-bootstrap`). El script resuelve la identidad en Vault
por *username* + *accessor*: **no inventa identificadores**, y distingue un
error de permisos o de conectividad de la inexistencia del recurso.

```bash
bash scripts/postgres/seed-initial-user.sh --dry-run   # solo consulta Vault
bash scripts/postgres/seed-initial-user.sh             # inserta en una transacción
```

**Resultado real**

```
==> Consultando Vault (contenedor vault-service)
    userpass path .....: userpass
    userpass accessor .: auth_userpass_32a80de2
    vault_username ....: sinhuesiordia
    vault_entity_id ...: cdaf589c-3da0-c00f-a7ad-3c30a216cff8
    totp method_id ....: 4b2ddbcb-fe31-b4fb-d430-12c4e6d86515 (vpg-totp, compartible entre empleados)
    mfa enforcement ...: vpg-userpass-totp (cubre el montaje: yes, alcance: mount-wide)

==> Insertando en vpg_contadores (una sola transaccion)
BEGIN
NOTICE:  vault_auth_config: escrita (c6c48468-7b79-4357-80e9-b0e8dbf7798e)
NOTICE:  users: creado sinhuesiordia (03572c00-c8ad-4d62-a723-8b8ab1da786a)
NOTICE:  user_profiles: creado
NOTICE:  user_roles: sinhuesiordia <- admin
NOTICE:  user_phones: creado
NOTICE:  user_addresses: creada
NOTICE:  user_emails: creado
NOTICE:  user_vault_identity: vinculado a la entidad cdaf589c-... (totp_status=pending)
DO
COMMIT

-[ RECORD 1 ]---------+-------------------------------------
username              | sinhuesiordia
auth_provider         | vault
password_hash_es_null | t
is_active             | t
first_name            | sinhue
last_name_paternal    | siordia
birth_date            | 1992-04-25
rfc                   | SIMS920425IY8
curp                  | SIMS920425HSLRLN06
roles                 | admin
vault_username        | sinhuesiordia
vault_entity_id       | cdaf589c-3da0-c00f-a7ad-3c30a216cff8
totp_status           | pending
last_mfa_login_at     |
userpass_path         | userpass
userpass_accessor     | auth_userpass_32a80de2
mfa_enforcement_name  | vpg-userpass-totp
```

El resumen **excluye datos secretos** por construcción: no hay contraseña, ni
semilla TOTP, ni token. `password_hash` es `NULL` porque `auth_provider` es
`vault`.

Consulta equivalente a mano:

```bash
docker compose exec postgres-service psql -U vpg_admin -d vpg_contadores -x -c "
SELECT u.username, u.auth_provider, (u.password_hash IS NULL) AS hash_null,
       p.first_name, p.last_name_paternal, p.rfc, p.curp,
       e.email, ph.phone_number, a.neighborhood, a.street, a.postal_code,
       r.code AS rol, vi.vault_entity_id, vi.totp_status
  FROM employees.users u
  JOIN employees.user_profiles p        ON p.user_id = u.id
  JOIN employees.user_emails e          ON e.user_id = u.id
  JOIN employees.user_phones ph         ON ph.user_id = u.id
  JOIN employees.user_addresses a       ON a.user_id = u.id
  JOIN employees.user_roles ur          ON ur.user_id = u.id
  JOIN employees.roles r                ON r.id = ur.role_id
  JOIN employees.user_vault_identity vi ON vi.user_id = u.id
 WHERE lower(u.username) = 'sinhuesiordia';"
```

### 7. Repetir DDL e inserción: no hay duplicados

El DDL se aplica **con `psql`**, es transaccional (`BEGIN`/`COMMIT` dentro del
archivo) y repetible sobre el mismo esquema sin borrar datos ni duplicar
objetos.

```bash
docker compose exec postgres-service vpg-pg-schema     # repite el DDL
docker compose exec postgres-service vpg-pg-roles      # repite los permisos
bash scripts/postgres/seed-initial-user.sh             # repite la inserción
bash scripts/postgres/validate-schema.sh datos
```

**Resultado real**

```
recuentos ANTES:   users=1 roles=3 user_roles=1 user_profiles=1 user_phones=1
                   user_addresses=1 user_emails=1 vault_auth_config=1 user_vault_identity=1

NOTICE:  relation "users" already exists, skipping
...
==> Esquema 'employees' aplicado.
NOTICE:  rol vpg_app ya existia: contrasena y atributos convergidos

NOTICE:  vault_auth_config: sin cambios (c6c48468-...)
NOTICE:  users: ya existia sinhuesiordia (03572c00-...)
NOTICE:  user_profiles: ya existia
NOTICE:  user_phones: ya existia
NOTICE:  user_addresses: ya existia
NOTICE:  user_emails: ya existia
NOTICE:  user_vault_identity: ya vinculado a cdaf589c-... (estado sin tocar)

recuentos DESPUES: users=1 roles=3 user_roles=1 user_profiles=1 user_phones=1
                   user_addresses=1 user_emails=1 vault_auth_config=1 user_vault_identity=1
```

> **La idempotencia no sustituye a las migraciones.** `IF NOT EXISTS` conserva
> los objetos existentes: si una tabla ya existe con una definición anterior,
> el archivo **no la altera** y no avisa de la diferencia. Cualquier cambio
> estructural (añadir una columna, cambiar un `CHECK`) necesita su propio
> script de migración versionado (`sql/002_*.sql`, …).

> **`/docker-entrypoint-initdb.d` solo se ejecuta automáticamente con un volumen
> vacío.** Los enlaces `10-schema.sh` y `20-app-role.sh` los corre el entrypoint
> oficial **únicamente** en la primera inicialización de `vpg-postgres-data`.
> Con el volumen ya inicializado, el entrypoint imprime
> `PostgreSQL Database directory appears to contain a database; Skipping initialization`
> y hay que invocar `vpg-pg-schema` / `vpg-pg-roles` a mano.

### 8. Probar restricciones con operaciones que se revierten

Cada prueba corre en su **propia transacción con `ROLLBACK`**: no deja datos.

```bash
bash scripts/postgres/validate-schema.sh restricciones
```

**Resultado real**

```
========== Pruebas de restricciones (TODAS terminan en ROLLBACK) ==========
  [OK rechazado] username duplicado con otras mayusculas        users_username_lower_ux
  [OK rechazado] auth_provider fuera del CHECK                  users_auth_provider_ck
  [OK rechazado] password_hash con autenticacion delegada a Vault users_delegated_no_hash_ck
  [OK rechazado] password_hash local que no es Argon2id         users_password_hash_argon2id_ck
  [OK rechazado] asignacion de rol duplicada                    user_roles_pk
  [OK rechazado] borrar un rol todavia asignado (RESTRICT)      user_roles_role_fk
  [OK rechazado] segundo perfil para el mismo usuario           user_profiles_pk
  [OK rechazado] CURP cuya fecha no coincide con birth_date     user_profiles_curp_birth_date_ck
  [OK rechazado] RFC con formato invalido                       user_profiles_rfc_format_ck
  [OK rechazado] segundo correo principal para el mismo usuario user_emails_one_primary_ux
  [OK rechazado] correo repetido cambiando mayusculas           user_emails_email_lower_ux
  [OK rechazado] correo con formato invalido                    user_emails_format_ck
  [OK rechazado] telefono con letras                            user_phones_number_ck
  [OK rechazado] codigo postal de 4 digitos                     user_addresses_postal_code_ck
  [OK rechazado] totp_status fuera del CHECK                    user_vault_identity_totp_status_ck
  [OK rechazado] totp_status=confirmed sin totp_confirmed_at    user_vault_identity_confirmed_ck
  [OK rechazado] vault_username con mayusculas                  user_vault_identity_username_format_ck
  [OK rechazado] segunda identidad de Vault para el mismo usuario user_vault_identity_pk
  [OK rechazado] borrar la config de auth con vinculos vivos    user_vault_identity_config_fk

========== Pruebas que DEBEN pasar (y tambien se revierten) ==========
  [OK aceptado ] un metodo TOTP compartido por dos empleados     empleados=2 | metodos_totp=1
  [OK aceptado ] updated_at se actualiza solo (trigger)          updated_at_recalculado = t

  Comprobacion final: nada quedo escrito por las pruebas.
 usuarios_probe
----------------
              0
```

### 9. Recrear el contenedor sin borrar el volumen

```bash
docker compose down            # SIN -v: conserva los volúmenes
docker volume ls --filter name=vpg-postgres-data
docker compose up -d
docker compose logs postgres-service | grep -E "Skipping initialization|ready to accept"
docker compose exec postgres-service psql -U vpg_admin -d vpg_contadores -x -c "
SELECT u.id, u.username, p.rfc, vi.vault_entity_id, vi.totp_status
  FROM employees.users u
  JOIN employees.user_profiles p ON p.user_id = u.id
  JOIN employees.user_vault_identity vi ON vi.user_id = u.id;"
```

**Resultado real**

```
contenedor antes: f7d6f35c7ff8   →   contenedor después: 9a9ed581dbb3  (distinto)
volumen vpg-postgres-data: conservado

PostgreSQL Database directory appears to contain a database; Skipping initialization
database system is ready to accept connections
0 ejecuciones de /docker-entrypoint-initdb.d

-[ RECORD 1 ]---+-------------------------------------
id              | 03572c00-c8ad-4d62-a723-8b8ab1da786a   <- el mismo UUID de antes
username        | sinhuesiordia
rfc             | SIMS920425IY8
vault_entity_id | cdaf589c-3da0-c00f-a7ad-3c30a216cff8
totp_status     | pending
```

**Nunca** uses `docker compose down -v`: borra `vpg-postgres-data` **y**
`vpg-vault-data`.

> Tras recrear el contenedor, **Vault arranca sellado**: hay que volver a
> desbloquearlo (`docker compose exec vault-service vault operator unseal`)
> antes de ejecutar los pasos 6, 10 y 11.

### 10. 🖐 INTERACTIVO — Verificar userpass + TOTP

Usa la contraseña **existente** identificada por `VAULT_ADMIN_USER_PASS` en
`.env`: no se muestra, no se copia al SQL, no se pasa como argumento visible y
no se guarda en PostgreSQL. El código TOTP **se pide por teclado** (entrada
oculta) y hay que leerlo de la app autenticadora.

```bash
# a) diagnóstico de solo lectura: relojes, método TOTP, enforcement y vínculo.
#    NO pide código y NO gasta ninguno de los 5 intentos.
bash scripts/postgres/verify-vault-mfa.sh --diagnose

# b) verificación completa (pide el código por teclado)
bash scripts/postgres/verify-vault-mfa.sh
```

Antes de pedir el código, el script espera si a la ventana TOTP actual le quedan
menos de 8 s, y después informa de cuántos segundos tardaste en teclear: así se
descarta que el código caducara mientras lo escribías.

**El prompt muestra un `#` por cada dígito tecleado.** `read -rs` a secas no da
ninguna señal visual y es imposible distinguir «el teclado no responde» de «el
script está colgado»:

```
    Escribe los 6 digitos. Veras un '#' por cada uno, para confirmar que
    el teclado se esta registrando. Borrar: retroceso. Cancelar: Ctrl+C.
    Al llegar al sexto digito se envia solo (no hace falta pulsar Enter).

Codigo TOTP para sinhuesiordia: ######  [6/6 digitos]
==> Validando con Vault (userpass + TOTP)...
```

- **Autoenvío al sexto dígito**: no hay que pulsar Enter. En consecuencia, el
  retroceso solo corrige **antes** de completar los 6.
- Las teclas no numéricas se ignoran; el retroceso (`DEL` o `^H`) borra el
  último dígito.
- Si pulsas Enter con menos de 6 dígitos, el script lo rechaza **sin intentar el
  login**: no gasta ningún intento.
- Hay un límite de 180 s; si expira, se cancela sin consumir intentos.
- El script corre con `set -Eeuo pipefail` y un `trap ... ERR` que imprime línea,
  código de salida y orden fallida: **ningún fallo lo cierra en silencio**.

Si aun así el prompt no reacciona a las teclas, es cosa del terminal; prueba:

```bash
winpty bash scripts/postgres/verify-vault-mfa.sh
```

Flujo: (1) `auth/userpass/login/<usuario>` solo con contraseña — Vault responde
**sin token** y con un `mfa_request_id`; (2) se pide el TOTP y se valida contra
`sys/mfa/validate`; (3) con el token resultante se consultan `entity_id` y
políticas; (4) **solo si el `entity_id` coincide** con el registrado se
actualizan `last_mfa_login_at` y `totp_status`; (5) el token se revoca.

**Resultado esperado** (nunca se imprime el token):

```
==> entity_id registrado en PostgreSQL: cdaf589c-3da0-c00f-a7ad-3c30a216cff8
Codigo TOTP de 6 digitos para sinhuesiordia (entrada oculta):

==> Resultado del login userpass + TOTP
    MFA exigido por Vault ....: si
    Token con solo contrasena : ninguno
    Login MFA ................: ok
    entity_id devuelto .......: cdaf589c-3da0-c00f-a7ad-3c30a216cff8
    politicas del token ......: [default vpg-admin]
    token revocado al final ..: si

==> entity_id COINCIDE con el registrado en PostgreSQL.

username          | sinhuesiordia
totp_status       | confirmed
totp_confirmed_at | <fecha del login>
last_mfa_login_at | <fecha del login>
```

**Estado de esta comprobación: VERIFICADA, salvo la escritura en PostgreSQL.**

Rechazos, comprobados contra la instancia en ejecución:

```
MFA_ENFORCED=si
MFA_PASSWORD_ONLY_TOKEN=ninguno        <- con solo contraseña Vault NO emite token
MFA_METHOD_ID=4b2ddbcb-fe31-b4fb-d430-12c4e6d86515   <- coincide con vault_auth_config
MFA_LOGIN=totp_incorrecto  (con un código 000000 deliberadamente inválido)
   failed to satisfy enforcement vpg-userpass-totp. error: 2 errors occurred:
   failed to validate TOTP passcode
   login MFA validation failed for methodID: [4b2ddbcb-...]

(con contraseña incorrecta) MFA_LOGIN=credenciales_invalidas   <- no llega al TOTP
```

Login correcto, con un código TOTP real tecleado por el titular (2026-10-02):

```
Codigo TOTP para sinhuesiordia: ######  [6/6 digitos]
==> Validando con Vault (userpass + TOTP)...

    MFA exigido por Vault ....: si
    Token con solo contrasena : ninguno
    Login MFA ................: ok           <- userpass + TOTP aceptado
    token revocado al final ..: si
```

**Pendiente:** el paso de `totp_status` a `confirmed`. En esa misma ejecución el
script no pudo leer el `entity_id` de la sesión por un fallo propio —usaba
`vault token lookup -field=...`, que esta versión de Vault rechaza con
`flag provided but not defined: -field`— y, al no tener con qué comparar, **no
confirmó nada**. Ya está corregido (`vault read -field=entity_id
auth/token/lookup-self`, comprobado: devuelve `cdaf589c-…`). El valor en la base
de datos sigue siendo `totp_status = pending`, `last_mfa_login_at = NULL`:
**no se ha inventado ningún resultado**. Basta repetir el paso 10.

> ⚠️ El método TOTP tiene `max_validation_attempts=5`. Varios intentos
> fallidos seguidos bloquean la validación de esa entidad durante un rato. Usa
> `--diagnose` mientras esperas: no consume intentos.

#### Si el código TOTP es rechazado

El script distingue los casos y los imprime en un bloque `ESTADO: ...` con la
respuesta **literal** de Vault debajo. No se oculta ningún error y el vínculo en
PostgreSQL **no se modifica** en ninguno de ellos.

| `ESTADO` | Qué significa | Qué hacer |
|---|---|---|
| `TOTP INCORRECTO` | La contraseña era correcta (Vault llegó a pedir el segundo factor) pero el código no coincide | Entrada obsoleta en la app, hora del teléfono, o código caducado al teclear. Ver abajo |
| `TOTP BLOQUEADO` | Se agotaron los 5 intentos consecutivos | Esperar lo que indique Vault y reintentar **una** vez con un código recién generado |
| `SIN SEMILLA TOTP` | La entidad no tiene secreto generado | `docker compose exec vault-service vpg-auth-bootstrap` |
| `PETICIÓN MFA CADUCADA` | Expiró el `mfa_request_id` entre el login y la validación | Repetir sin pausas |
| `CONTRASEÑA INCORRECTA` | Falló antes del segundo factor; **no** se gastó ningún intento de TOTP | `VAULT_ADMIN_USER_PASS` en `.env` no es la contraseña actual de userpass |
| `FALLO DE SEGURIDAD` | Vault emitió token **sin** pedir MFA | Revisar el enforcement y repetir `vpg-auth-bootstrap` |

Diagnóstico real del 2026-10-02 sobre esta instancia:

```
    method_id en Vault .......: 4b2ddbcb-fe31-b4fb-d430-12c4e6d86515
    method_id en PostgreSQL ..: 4b2ddbcb-fe31-b4fb-d430-12c4e6d86515   <- coinciden
    algoritmo / digitos ......: SHA1 / 6
    periodo / skew ...........: 30s / 1 pasos (tolerancia +-60s)
    issuer en la app .........: VPG Vault
    desfase host/contenedor ..: 1s (dentro de la tolerancia)

Respuesta literal de Vault (Code: 403):
   failed to satisfy enforcement vpg-userpass-totp. error: 2 errors occurred:
   failed to validate TOTP passcode
   login MFA validation failed for methodID: [4b2ddbcb-...]
```

Es decir: contraseña correcta, relojes del servidor correctos, método bien
configurado y **sin** bloqueo por intentos. El mensaje `failed to validate TOTP
passcode` significa que **la semilla que tiene la app no es la que tiene Vault**.

Causas, por orden de probabilidad:

1. **Entrada obsoleta en la app.** La semilla va asociada a la *entidad*, no al
   método. Si alguna vez se ejecutó `--reset-totp`, o se recreó el volumen de
   Vault, las entradas `VPG Vault` anteriores generan códigos inválidos. **Solo
   vale la última**: borra las demás.
2. **Hora del teléfono.** Activa la hora automática de red. El desfase
   host/contenedor ya está comprobado (1 s), así que si hay desfase está en el
   teléfono.
3. **Código caducado al teclear.** El script ahora informa de los segundos de
   tecleo y los compara con la tolerancia.
4. **Clave mal transcrita.** En Google Authenticator:
   **+ → Ingresar una clave de configuración**, tipo **Basada en tiempo**, sin
   espacios. Solo letras A-Z y dígitos 2-7: la `O` es letra (nunca cero) y la
   `I` es letra (nunca uno).

**Solución definitiva.** Vault no permite volver a leer una semilla ya
generada (es lo correcto), así que la única forma de salir de la duda es
regenerarla. Es **destructivo** (invalida la entrada actual de la app) y por eso
el script **nunca** lo hace por su cuenta — hay que ejecutarlo a mano:

```bash
# 1. regenera la semilla y muestra el otpauth:// UNA sola vez
docker compose exec vault-service vpg-auth-bootstrap --reset-totp

# 2. borra las entradas "VPG Vault" viejas de la app y registra la nueva,
#    guárdala en el gestor de contraseñas y limpia la pantalla
clear

# 3. (opcional) deja constancia del reset en el modelo
docker compose exec postgres-service psql -U vpg_admin -d vpg_contadores -c   "UPDATE employees.user_vault_identity vi
      SET totp_status = 'reset_required', totp_generated_at = now()
     FROM employees.users u
    WHERE u.id = vi.user_id AND lower(u.username) = 'sinhuesiordia';"

# 4. verifica
bash scripts/postgres/verify-vault-mfa.sh
```

`--reset-totp` **no cambia el `entity_id`** (la entidad ya existe), así que el
vínculo de PostgreSQL sigue siendo válido y **no hay que repetir**
`seed-initial-user.sh`. Un login correcto lleva `reset_required` → `confirmed`.

### 11. Consultar una ruta Vault autorizada

Lo hace el mismo script del paso 10, con el token recién obtenido por MFA, y
muestra **solo el resultado de autorización**, nunca los valores del secreto:

```bash
bash scripts/postgres/verify-vault-mfa.sh --path secret/data/sat/usuarios
```

**Resultado esperado**

```
==> Consulta de una ruta Vault autorizada (solo el resultado, sin valores)
    ruta .....................: secret/data/sat/usuarios
    capacidades de la sesion .: [create delete list patch read sudo update]
    lectura ..................: autorizada
```

Los tres estados posibles son `autorizada`,
`autorizada_pero_sin_datos` (la política permite leer, la ruta no tiene datos)
y `denegada_por_politica`. En ningún caso se imprime el contenido del secreto.

**Estado: VERIFICADA** en la ejecución del 2026-10-02, con el token emitido tras
un login userpass + TOTP real:

```
==> Consulta de una ruta Vault autorizada (solo el resultado, sin valores)
    ruta .....................: secret/data/sat/usuarios
    capacidades de la sesion .: [create delete list patch read sudo update]
    lectura ..................: autorizada
```

Las capacidades son las de la política `vpg-admin`. No se imprimió ningún valor
del secreto, ni el token.

Equivalente a mano, con una sesión ya abierta en el contenedor:

```bash
docker compose exec vault-service vault write -field=capabilities \
  sys/capabilities-self path=secret/data/sat/usuarios
docker compose exec vault-service sh -c \
  'vault read secret/data/sat/usuarios >/dev/null 2>&1 && echo "lectura autorizada" || echo "lectura NO autorizada"'
```

---

## Seguridad

### Escaneo de la imagen

**No se afirma que la imagen no tenga vulnerabilidades.** Se evaluó con Docker
Scout y el resultado real del 2026-10-01 fue:

```bash
docker scout cves vpg/postgres-server:17-alpine
docker scout cves --only-severity critical,high vpg/postgres-server:17-alpine
docker scout recommendations vpg/postgres-server:17-alpine
docker scout cves vpg/vault-server:2.1.1
```

```
Target: vpg/postgres-server:17-alpine
  66 paquetes indexados
  2 paquetes vulnerables, 24 vulnerabilidades:  2 CRITICAL | 22 HIGH | 0 MEDIUM | 0 LOW
  Origen: biblioteca estándar de Go 1.24.6 enlazada estáticamente en `gosu 1.19`
          (p. ej. CVE-2025-68121, CVE-2026-39821)
  Los paquetes apk (musl, openssl, postgresql 17.11, zlib…) salen con 0C/0H.
```

Son vulnerabilidades **heredadas de la imagen oficial `postgres:17-alpine`**,
no introducidas por este `Dockerfile`. Mitigación: reconstruir con
`docker compose build --pull` cuando la imagen base publique un `gosu`
recompilado, y repetir el escaneo. En este entorno local el puerto solo escucha
en `127.0.0.1`.

### Decisiones de este componente

- El contenedor de la base de datos **no lleva Python ni dependencias
  adicionales** (`requirements/postgres.txt` está vacío de paquetes): menos
  superficie de ataque.
- `security_opt: no-new-privileges:true`; el proceso corre como el usuario
  `postgres` de la imagen oficial.
- Las contraseñas llegan **solo** por archivo de secreto. `vpg-pg-roles` las
  envía a `psql` por **stdin** y embebidas en el cuerpo de un bloque `DO`, nunca
  en un `SELECT` que las devuelva: un `SELECT set_config(...)` imprimiría el
  secreto en stdout y acabaría en `docker compose logs`.
- `.env.example` **no contiene ningún secreto** nuevo.
- `secrets/` está en `.gitignore` y en `.dockerignore`.
- Autenticación TCP por `scram-sha-256` (valor por defecto de la imagen); por
  socket Unix dentro del contenedor es `trust`, también por defecto.

### Límites conocidos de esta etapa

- El modelo almacena roles y vínculos; **no los hace cumplir**. Eso le toca al
  futuro backend y, para los secretos, a las políticas de Vault.
- `totp_generated_at` queda `NULL`: la semilla la generó el bootstrap de Vault y
  aquí no se inventa una fecha.
- No hay sistema de migraciones (ver el aviso del paso 7).
- No hay TLS entre el cliente y PostgreSQL: solo es aceptable porque el puerto
  se publica en `127.0.0.1`.
