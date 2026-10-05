# vpgcontafiscal_automatizacion
Automatizacion Inteligente para contabilidad fiscal VPG

| Componente | Estado | Servicio |
|---|---|---|
| [1. HashiCorp Vault](#componente-1-hashicorp-vault-credenciales) | listo | `vault-service` |
| [2. PostgreSQL 17](#componente-2-postgresql-17-empleados-roles-y-vínculo-con-vault) | listo | `postgres-service` |
| [3. user-mgmt-service (FastAPI)](#componente-3-user-mgmt-service-fastapi--sqlalchemy) | listo | `user-mgmt-service` |
| 4. Frontend | **no implementado**: esta etapa termina en el backend | — |

## Componente 1: HashiCorp Vault (credenciales del servicio)

Vault 2.1.1 en modo servidor (no dev), almacenamiento integrado Raft en un
volumen Docker y motor de secretos KV v2. El puerto 8200 se publica solo en
`127.0.0.1`.

| Archivo | Propósito |
|---|---|
| `Dockerfile` | Multistage: `vault-assets` (normaliza CRLF y permisos) → `vault-server` |
| `compose.yaml` | Servicio `vault-service`, red `network-service`, volumen persistente |
| `config/vault.hcl` | Configuración del servidor |
| `docker-entrypoint.sh` | Ejecuta `vault server` con la configuración del proyecto |
| `scripts/vault-auth-bootstrap.sh` | Configura userpass + MFA TOTP y OIDC (comando `vpg-auth-bootstrap` en la imagen) |
| `config/policies/*.hcl` | Políticas `vpg-admin` (administrador) y `vpg-oidc-user` (usuarios OIDC) |
| `.env.example` | Parámetros no sensibles `VAULT_*` (copiar a `.env`) |
| `requirements/vault.txt` | Sin dependencias Python |

### Requisitos previos

- Windows con Docker Desktop (backend WSL 2) en ejecución.
- Git for Windows (Git Bash).
- Comprobar: `docker version` y `docker compose version`.

> **Git Bash:** si un comando interactivo muestra `the input device is not a TTY`,
> antepón `winpty` (p. ej. `winpty docker compose exec vault-service vault operator unseal`).
> Los argumentos que empiezan con `/` se convierten en rutas de Windows; por eso
> esos comandos llevan `MSYS_NO_PATHCONV=1`.

### 1. Preparar y construir

```bash
cp .env.example .env          # solo parámetros no sensibles
docker compose config         # valida la configuración resultante
docker compose build
```

### 2. Iniciar y consultar estado

```bash
docker compose up -d
docker compose ps
docker compose exec vault-service vault status   # Sealed: true hasta desbloquear
```

`vault status` devuelve código 2 mientras esté sellado; es normal.

### 3. Inicializar (solo una vez por volumen)

```bash
docker compose exec vault-service vault operator init -key-shares=1 -key-threshold=1
```

La salida muestra la **Unseal Key** y el **Initial Root Token** una sola vez.
Guárdalos de inmediato en un gestor de contraseñas y limpia la pantalla (`clear`).
No los redirijas a archivos del proyecto ni los pegues en comandos.
Para un esquema más robusto usa, por ejemplo, `-key-shares=3 -key-threshold=2`
y reparte las claves.

### 4. Desbloquear e iniciar sesión

Los comandos piden el valor de forma oculta; nada queda en el historial.

```bash
docker compose exec vault-service vault operator unseal   # pega la Unseal Key
docker compose exec vault-service vault login -no-print   # pega el token
```

El token queda en `~/.vault-token` **dentro del contenedor** (no en el proyecto
ni en el volumen) y se pierde si el contenedor se recrea.

### 5. Habilitar KV v2 (solo una vez)

```bash
docker compose exec vault-service vault secrets enable -path=secret -version=2 kv
docker compose exec vault-service vault secrets list
```

### 5.1 Autenticación: Userpass + MFA (TOTP) y OIDC (solo una vez)

Con Vault desbloqueado y la sesión root activa (paso 4, o `VAULT_INITIAL_TOKEN`
en `.env`), ejecuta el script idempotente incluido en la imagen:

```bash
docker compose exec vault-service vpg-auth-bootstrap
```

Qué configura:

| Elemento | Detalle |
|---|---|
| Políticas | `vpg-admin` (acceso total) y `vpg-oidc-user` (lectura de `secret/sat/*`) |
| `auth/userpass` | Usuario `VAULT_ADMIN_USER_NAME` (en minúsculas) con contraseña inicial `VAULT_ADMIN_USER_PASS` y política `vpg-admin`. Si el usuario ya existe **no** se sobrescribe la contraseña |
| MFA de login | Método TOTP `vpg-totp` (SHA1, 6 dígitos, 30 s) **obligatorio** en todo login por userpass |
| `auth/oidc` | Solo si `.env` define `VAULT_OIDC_DISCOVERY_URL`, `VAULT_OIDC_CLIENT_ID` y `VAULT_OIDC_CLIENT_SECRET`; rol `default` con `VAULT_OIDC_USER_CLAIM`, `VAULT_OIDC_SCOPES` y `VAULT_OIDC_POLICIES` |

En la primera ejecución el script muestra **una sola vez** un URI `otpauth://`
con el secreto TOTP del administrador. Regístralo en tu app autenticadora
(Google/Microsoft Authenticator, Authy, 1Password…), guárdalo en el gestor de
contraseñas y limpia la pantalla (`clear`).

En Google Authenticator: **+ → Ingresar una clave de configuración**, escribe la
clave (el valor tras `secret=`, sin espacios; solo letras A-Z y dígitos 2-7, la
`O` es letra, no cero) y elige **Basada en tiempo**. Si el código es rechazado,
borra entradas "VPG Vault" antiguas de regeneraciones previas: solo vale la
última. El teléfono debe tener la hora automática activada.

Para regenerarlo:

```bash
docker compose exec vault-service vpg-auth-bootstrap --reset-totp
```

Iniciar sesión como administrador (pide contraseña y después el código TOTP):

```bash
docker compose exec vault-service vault login -method=userpass -no-print username=usuarioadmin
```

En la UI: método **Username**, y después el código de 6 dígitos.

Cambiar la contraseña inicial tras el primer login (recomendado):

```bash
docker compose exec vault-service vault write auth/userpass/users/usuarioadmin password=-
```
Verificar Codigo MFA esperado para ingresar con username

```bash
python -c "import base64,hmac,hashlib,struct,time;k=base64.b32decode('SECRET_GENERADO');h=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();o=h[-1]&15;print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))"
```

**OIDC:** registra en tu proveedor (Entra ID, Google, Keycloak, Okta…) una
aplicación web con redirect URI
`http://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback` (y la variante
`localhost`), completa las variables `VAULT_OIDC_*` en `.env`, recrea el
contenedor (`docker compose up -d`) para que las reciba, desbloquea y vuelve a
ejecutar `vpg-auth-bootstrap`. El login se hace desde la UI (método **OIDC**,
rol `default`); el MFA de los usuarios OIDC lo aplica el proveedor.

Una vez comprobado el acceso como administrador, revoca el root token
(`vault token revoke -self`) y quita `VAULT_INITIAL_TOKEN` de `.env`; si lo
necesitas de nuevo, genera uno con `vault operator generate-root`.

### 6. Guardar credenciales de ejemplo

Valores de ejemplo: usuario `__Fulanito__`, password `__MyS3cret0__`; sustitúyelos
por los reales. La contraseña se lee oculta y se envía por stdin (`password=-`),
así no aparece en el historial ni en los argumentos del comando.

```bash
read -rsp 'Password: ' VPG_PASS; echo
printf '%s' "$VPG_PASS" | docker compose exec -T vault-service \
  vault kv put -mount=secret sat/usuarios usuario=__Fulanito__ password=-
unset VPG_PASS
```

### 7. Recuperar cada valor

```bash
docker compose exec vault-service vault kv get -mount=secret -field=usuario sat/usuarios
docker compose exec vault-service vault kv get -mount=secret -field=password sat/usuarios
docker compose exec vault-service vault kv metadata get -mount=secret sat/usuarios   # versiones
```

### 8. Logs, reinicio y parada

```bash
docker compose logs -f vault-service       # Ctrl+C para salir
docker compose restart vault-service       # reinicia el mismo contenedor
docker compose stop                        # detiene sin borrar nada
docker compose down                        # elimina contenedor y red; conserva el volumen
```

**Nunca** uses `docker compose down -v` salvo que quieras borrar todos los
secretos: elimina el volumen `vpg-vault-data`.

Para cerrar la sesión en el contenedor al terminar:

```bash
MSYS_NO_PATHCONV=1 docker compose exec vault-service rm -f /home/vault/.vault-token
```

### Qué se repite tras reiniciar

| Evento | Desbloquear (unseal) | Iniciar sesión (login) | Init / habilitar KV |
|---|---|---|---|
| `restart`, `stop`/`start`, reinicio de Docker Desktop o Windows | Sí | No (el token sigue en el contenedor) | No |
| `down` + `up -d` o `build` + `up -d` (contenedor recreado) | Sí | Sí | No |
| `down -v` (volumen borrado) | — | — | Sí, todo desde el paso 3 |

Vault siempre arranca sellado: el desbloqueo es manual a propósito; no se
guardan claves en el proyecto para automatizarlo.

### Verificar que el volumen conserva los secretos

```bash
docker volume inspect vpg-vault-data
docker compose down
docker compose up -d
docker compose exec vault-service vault operator unseal
docker compose exec vault-service vault login -no-print
docker compose exec vault-service vault kv get -mount=secret -field=usuario sat/usuarios
MSYS_NO_PATHCONV=1 docker compose exec vault-service ls -la /vault/data
```

Si el valor aparece tras recrear el contenedor, el volumen persiste los datos.

### Interfaz web

<http://127.0.0.1:8200/ui> (solo accesible desde este equipo).

### Notas de seguridad

- `tls_disable = true` solo es aceptable porque el puerto se publica en
  `127.0.0.1`. Para cualquier despliegue compartido habilita TLS.
- `disable_mlock = true` es lo recomendado con Raft; implica que la memoria de
  Vault podría ir a swap. En WSL 2 el swap vive en un archivo del host; si te
  preocupa, desactívalo en `.wslconfig` (`swap=0`).
- Revisa vulnerabilidades de la imagen construida con
  `docker scout cves vpg/vault-server:2.1.1`.

---

## Componente 2: PostgreSQL 17 (empleados, roles y vínculo con Vault)

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

---

## Componente 3: user-mgmt-service (FastAPI + SQLAlchemy)

Backend REST **local** para el CRUD de empleados y la administración controlada
de su vínculo con Vault. FastAPI 0.142, SQLAlchemy 2.1 asíncrono y Psycopg 3
sobre los servicios de las etapas 1 y 2.

> **Alcance de esta etapa.** Termina en backend, ORM, sincronización controlada
> y comprobaciones. **No hay frontend, React ni páginas propias**, y no hay
> despliegue VPS/Kubernetes/Terraform. Swagger UI y ReDoc sí forman parte de la
> entrega. Tampoco hay crawling, gestión de archivos ni autenticación OIDC o
> local: `password_hash` sigue reservado y NULL.

### Requisitos previos

Esta etapa **no se sostiene sola**: depende de que las dos anteriores estén
terminadas. El propio servicio lo comprueba al arrancar y se niega a continuar
si falta lo esencial.

| Requisito | De dónde viene | Cómo comprobarlo |
|---|---|---|
| Docker Desktop (WSL 2) y Git Bash | — | `docker compose version` |
| Puerto `8000` libre en `127.0.0.1` | — | `netstat -ano \| grep 8000` |
| Vault **inicializado** | Etapa 1, paso 3 | `docker compose exec vault-service vault status` |
| Vault **desbloqueado** (paso manual) | Etapa 1, paso 4 | `Sealed false` |
| `auth/userpass`, método TOTP `vpg-totp` y enforcement `vpg-userpass-totp` | Etapa 1, paso 5.1 | `vpg-auth-bootstrap` |
| Esquema `employees` aplicado | Etapa 2, pasos 1 y 7 | `validate-schema.sh tablas` |
| Cuenta `vpg_app` con permisos DML y **sin** DDL | Etapa 2 | `validate-schema.sh datos` |
| **Al menos un admin activo vinculado a Vault** | Etapa 2, paso 6 | `seed-initial-user.sh` |
| Migración `002_vault_operations.sql` aplicada | Etapa 3, paso 1 | `apply-migrations.sh` |
| Cuenta técnica AppRole con su política | Etapa 3, paso 1 | `vault-approle-bootstrap.sh` |

Si falta el administrador vinculado, **el proceso aborta el arranque** con un
mensaje que nombra los scripts a ejecutar. Si lo que falla es Vault (sellado o
inaccesible), el proceso **sí arranca** pero responde 503 en readiness y en todo
endpoint de negocio.

### Archivos de este componente

| Archivo | Propósito |
|---|---|
| `app/core/config.py` | Ajustes `USER_MGMT_*` validados al arrancar; secretos leídos de archivo |
| `app/core/database.py` | Motor asíncrono, pool limitado, `pool_pre_ping`. **Sin `create_all()`** |
| `app/core/vault.py` | Cliente HTTP de Vault: login, MFA, identidades, TOTP, revocación |
| `app/core/security.py` | Sesiones API y desafíos MFA, solo en memoria, con TTL y tope |
| `app/core/readiness.py` | Precondición de arranque y estado de readiness |
| `app/core/logging.py` | Logs JSON, `X-Request-ID` y saneado de secretos |
| `app/core/rate_limit.py` | Ventana deslizante en memoria |
| `app/core/errors.py` | Errores de dominio y su traducción a HTTP |
| `app/models/employees.py` | ORM mapeado al esquema **existente** |
| `app/schemas/` | DTO separados para crear, reemplazar, modificar y responder |
| `app/repositories/` | Consultas de empleados y del registro de operaciones |
| `app/services/` | `users.py`, `auth.py`, `vault_sync.py`, `rbac.py` |
| `app/routers/` | `health.py`, `auth.py`, `users.py`, `vault_ops.py` |
| `app/deps.py` | Dependencias de FastAPI: sesión, principal, compuertas |
| `app/main.py` | `lifespan`, middleware, manejadores de error, montaje de routers |
| `sql/002_vault_operations.sql` | Migración: registro durable de operaciones Vault |
| `config/policies/vpg-user-mgmt.hcl` | Política de la cuenta técnica (AppRole) |
| `scripts/user_mgmt/*.sh` | AppRole, migraciones, base de pruebas, tests, reconciliación, recorrido curl |
| `requirements/user_mgmt.txt` | Dependencias de ejecución, fijadas |
| `requirements/user_mgmt-dev.txt` | Dependencias **solo** de pruebas |
| `tests/` | 91 pruebas pytest |
| `postman/` | Colección y environment de Postman: 44 peticiones, 19 variables |

### Requerimientos: dependencias y por qué cada una

`requirements/user_mgmt.txt`, todas con versión **fijada** para que una
reconstrucción dé la misma imagen:

| Paquete | Versión | Para qué |
|---|---|---|
| `fastapi` | 0.142.2 | Framework, inyección por `Depends`, OpenAPI |
| `starlette` | 1.7.0 | Base ASGI. **Fijada de forma explícita** aunque llegue como dependencia: ahí estaban las vulnerabilidades del primer escaneo |
| `uvicorn` | 0.54.0 | Servidor ASGI, un worker, sin reload |
| `uvloop` | 0.23.0 | Bucle de eventos. Declarado aparte en vez de usar `uvicorn[standard]` |
| `httptools` | 0.8.0 | Parser HTTP. Mismo motivo |
| `sqlalchemy[asyncio]` | 2.1.3 | ORM y sesiones asíncronas |
| `psycopg[c,pool]` | 3.2.13 | Driver PostgreSQL asíncrono, variante C |
| `pydantic` | 2.13.5 | Validación de DTO |
| `pydantic-settings` | 2.15.0 | Configuración validada al arrancar |
| `httpx` | 0.28.1 | Cliente HTTP asíncrono hacia Vault, con timeouts |

`requirements/user_mgmt-dev.txt` (**no** entra en la imagen de ejecución):
`pytest` 8.4.2, `pytest-asyncio` 1.3.0, `anyio` 4.15.1.

**Por qué no `uvicorn[standard]`:** arrastra `watchfiles`, que exige cadena de
compilación de Rust y solo sirve para `--reload`, que este servicio no usa.

**Por qué no `email-validator`:** rechaza los dominios de uso reservado
(`.invalid`, `.test`, `example.com`), que son justo los que deben aparecer en
ejemplos y pruebas según el RFC 2606. El tipo de correo es propio y usa **el
mismo patrón** que el `CHECK user_emails_format_ck` de la base, para que la API
y PostgreSQL no discrepen.

### Arquitectura por capas

```
routers/        HTTP, códigos de estado, OpenAPI
   ↓ Depends
services/       reglas de negocio, RBAC, orquestación Vault+PostgreSQL
   ↓
repositories/   consultas SQLAlchemy parametrizadas
   ↓
models/         ORM del esquema employees que ya existe
```

`core/` aporta configuración, motor de base de datos, cliente Vault, sesiones,
logging, rate limiting y readiness. No hay repositorios genéricos ni interfaces
abstractas sin uso concreto.

**Acceso a datos.** Una `AsyncSession` por petición, nunca compartida entre
tareas. Pool limitado (5 + 5), `pool_pre_ping`, `statement_timeout` de 15 s.
Las relaciones se cargan con `selectinload` explícito y los `relationship` están
en `lazy="raise"`, de modo que una carga perezosa accidental **falla en las
pruebas** en vez de provocar N+1 silencioso en producción. `updated_at` lo
mantiene el trigger de PostgreSQL; el ORM no lo escribe.

### Clases creadas y los avisos que llevan dentro

Cada clase documenta en su docstring la regla que la justifica. Estas son las
que conviene leer antes de tocar el código, con el aviso que contienen:

#### `app/core/vault.py`

| Clase | Aviso que documenta |
|---|---|
| `VaultClient` | Habla con Vault **por su API HTTP**. No ejecuta `docker exec`, ni un shell, ni `vpg-auth-bootstrap` por petición |
| `VaultPermissionDenied` | «403: el token carece de permisos. **NO significa que el recurso no exista**» — distinguirlos es lo que evita borrar o recrear algo que sí estaba |
| `VaultNotFound` | 404 con cuerpo vacío: eso **sí** es inexistencia |
| `VaultSealed` / `VaultUnavailable` | Separan «Vault está sellado» de «Vault no responde»: la primera se arregla con un unseal manual, la segunda no |
| `VaultSession` | «Token humano emitido tras completar el MFA. **Solo vive en memoria**». Define `__str__` para que un log accidental no imprima el token |
| `MFAChallenge` | Lleva `token_issued_without_mfa`: si Vault entregara token con solo la contraseña, sería un fallo de configuración del enforcement y se trata como tal |

#### `app/core/security.py`

| Clase | Aviso que documenta |
|---|---|
| `ApiSession` | «Guarda el token de Vault, que **jamás** se devuelve». El identificador que ve el cliente es opaco y sin relación con él |
| `PendingChallenge` | Un login con contraseña correcta **no es una sesión**: es un desafío con TTL que se consume una sola vez |
| `SessionStore` | Documenta la limitación: reiniciar el worker invalida todas las sesiones, y varios workers exigirían otro diseño. También que `drop_sessions_for_user` **quita de memoria pero no revoca**: devolver las víctimas permite revocarlas en Vault aparte |

#### `app/core/readiness.py`

| Clase | Aviso que documenta |
|---|---|
| `StartupPreconditionError` | «Impide arrancar: falta provisionamiento previo por CLI». Es el único fallo que aborta el proceso |
| `AdminAnchor` | El administrador de referencia verificado al arrancar: `entity_id`, accessor, `method_id` y enforcement, comparados contra Vault |
| `ReadinessState` | Separa las cinco comprobaciones para que el 503 diga **qué** falta, no solo que falta algo |

#### `app/models/employees.py`

| Clase | Aviso que documenta |
|---|---|
| `Base` | «Se usa **SOLO para mapear, nunca para emitir DDL**» |
| `User` | `password_hash` reservado para Argon2id; debe ser NULL con autenticación delegada (lo impone `users_delegated_no_hash_ck` en la base) |
| `UserVaultIdentity` | PostgreSQL guarda el **vínculo y su historia**; Vault verifica contraseña y TOTP. Una fila `confirmed` **no autoriza omitir el MFA** |
| `VaultAuthConfig` | `userpass_accessor` es TEXT, no UUID. `totp_method_id` **sin UNIQUE a propósito**: el método se comparte entre empleados |
| `VaultOperation` | «Registro durable de operaciones que tocan Vault y PostgreSQL»: existe porque una transacción de PostgreSQL no revierte Vault |

#### `app/schemas/`

| Clase | Aviso que documenta |
|---|---|
| `UserCreate` | Crea `users` + `user_profiles` + `user_roles` en **una** transacción |
| `UserReplace` | **PUT**: reemplaza *todos* los campos editables; lo omitido se vacía |
| `UserPatch` | **PATCH**: un campo omitido se deja como está, **nunca** se interpreta como borrado |
| `UserSearch` | Va por POST para que los datos personales no viajen en la URL ni queden en logs de acceso |
| `EnrollmentOut` | Contiene el **único** envío del URI `otpauth://`. Si se pierde, hace falta un reset explícito: no se regenera en silencio |
| `VaultLinkOut` | «**Nunca** incluye semillas, QR ni tokens». Añade un `notice` que explica qué significa cada `totp_status` |
| `SessionOut` | «El token de Vault **no** aparece aquí ni en ningún sitio» |
| `AccessCheckOut` | «**Nunca** incluye los valores del secreto» |

#### `app/services/` y `app/core/errors.py`

| Clase | Aviso que documenta |
|---|---|
| `Principal` | Los roles se **releen de PostgreSQL** en cada petición, no se confían al momento del login |
| `VaultSyncService` | Ninguna transacción de base de datos permanece abierta durante una llamada de red; cada fase se escribe antes de seguir; nada se reintenta solo |
| `AuthService` | La contraseña se envía y se descarta; el desafío se consume una sola vez |
| `PartialOperationError` | «Vault ya cambió pero PostgreSQL no pudo reflejarlo»: por eso **no** se devuelve 201/204 |
| `NotReadyError` | 503 mientras la precondición no esté verificada |

---

## Endpoints

Prefijo `/user_mgmt/v1`. Conserva `/user` del contrato original. UUID en las
rutas; **contraseñas y códigos TOTP solo en cuerpos**. Swagger en
<http://127.0.0.1:8000/docs>.

### Salud (sin autenticación)

| Método | Ruta | Códigos | Qué hace |
|---|---|---|---|
| GET | `/health/live` | 200 | El proceso responde. No toca PostgreSQL ni Vault |
| GET | `/health/ready` | 200 / 503 | `SELECT 1` autenticado, Vault inicializado y desbloqueado, credencial técnica válida y admin vinculado |

### Autenticación

| Método | Ruta | Sesión | Códigos | Qué hace |
|---|---|---|---|---|
| POST | `/auth/login` | no | 200, 401, 403, 422, 429, 503 | Paso 1. Devuelve un **desafío MFA**, no una sesión |
| POST | `/auth/mfa/verify` | no | 200, 401, 403, 422, 429, 503 | Paso 2. Valida el TOTP y entrega la sesión API |
| POST | `/auth/logout` | sí | 204, 401 | Cierra la sesión y revoca el token en Vault |
| GET | `/auth/me` | sí | 200, 401 | Datos de la sesión actual (útil en Swagger) |

`POST /auth/login` responde **403** si Vault llegara a emitir token con solo la
contraseña: significaría que el enforcement MFA no está cubriendo el montaje.

### Empleados

| Método | Ruta | Rol mínimo | Códigos | Notas |
|---|---|---|---|---|
| POST | `/user` | `manager` | 201, 403, 409, 422 | Una sola transacción. Un `manager` no puede elegir roles |
| GET | `/user` | `employee` | 200, 422 | Paginado y con orden estable. Un `employee` solo se ve a sí mismo |
| POST | `/user/search` | `manager` | 200, 403, 422 | Búsqueda por correo, RFC o CURP **con cuerpo**, no en la URL |
| GET | `/user/{user_id}` | `employee` (propio) | 200, 403, 404 | **Nunca** genera, destruye ni reinicia TOTP |
| PUT | `/user/{user_id}` | `manager` | 200, 403, 404, 409, 422 | Reemplazo: las colecciones omitidas se vacían |
| PATCH | `/user/{user_id}` | `employee` (propio) | 200, 403, 404, 409, 422 | Parcial. Un `employee` toca sus contactos, no su perfil fiscal |
| PUT | `/user/{user_id}/roles` | `admin` | 200, 403, 404, 409, 422 | Protege la última cuenta admin activa |
| DELETE | `/user/{user_id}` | `manager` | 204, 403, 404, **409** | Baja lógica + entidad de Vault deshabilitada. 409 si la baja queda incompleta |
| DELETE | `/user/{user_id}/purge` | `admin` + MFA reciente | 204, 403, 404, 409, 503 | Solo sobre un usuario ya desactivado, nunca a uno mismo |
| GET | `/user/{user_id}/operations` | `admin` | 200, 403 | Historial del registro durable |

### Vault

| Método | Ruta | Rol mínimo | Códigos | Notas |
|---|---|---|---|---|
| POST | `/user/{user_id}/vault/provision` | `admin` | 201, 403, 409, 422, 503 | Entrega el URI `otpauth://` **una sola vez**, con `Cache-Control: no-store` |
| PATCH | `/user/{user_id}/vault/credentials` | `admin` | 200, 403, 409, **422**, 503 | Cambiar el username **exige** enviar también `new_password` |
| POST | `/user/{user_id}/mfa/reset` | `admin` + MFA reciente | 200, 403, 409, 422, 503 | Exige `confirm: "RESET"`. Solo la semilla de esa entidad |
| POST | `/vault/access-check` | `employee` | 200, 401, 422, 503 | Evalúa con el **token humano**. Allowlist de rutas lógicas |
| GET | `/vault/operations/{operation_id}` | `admin` | 200, 403, 404 | Estado y fases de una operación |

**Cabecera `Idempotency-Key`** (opcional) en provisionamiento, cambio de
credenciales, reset y purga: repetir la petición con la misma clave devuelve la
operación original en vez de ejecutarla dos veces. No se almacena el cuerpo.

### Diferencias de semántica que conviene no confundir

| | PUT `/user/{id}` | PATCH `/user/{id}` |
|---|---|---|
| Qué describe el cuerpo | El **estado final** | Solo **los cambios** |
| Colección omitida | Se **vacía** | Se **conserva** |
| Modificar un contacto | Se envía la lista completa | Se envía su `id` |
| Borrar un contacto | Omitirlo de la lista | `remove_*_ids` explícito |
| Perfil fiscal | Obligatorio y completo | Opcional y parcial |

---

## Autenticación: cómo encajan Vault y PostgreSQL

Es la parte que más se presta a malentendidos, así que conviene tenerla clara:
**los dos sistemas hacen cosas distintas y ninguno sustituye al otro**.

### Reparto de responsabilidades

| | Vault | PostgreSQL |
|---|---|---|
| Verificar la contraseña | **sí** (`auth/userpass`) | no |
| Verificar el código TOTP | **sí** (`sys/mfa/validate`) | no |
| Guardar la semilla TOTP / QR / `otpauth://` | sí | **nunca** |
| Guardar el vínculo empleado ↔ identidad | no | **sí** (`user_vault_identity`) |
| Guardar el estado histórico del enrolamiento | no | **sí** (`totp_status`, fechas) |
| Decidir qué roles de aplicación tiene alguien | no | **sí** (`user_roles`) |
| Decidir qué secretos puede leer alguien | **sí** (políticas) | no |

### El `entity_id` es la junta entre ambos

El `entity_id` de Vault es lo único que permite afirmar que «la persona que
acaba de superar el MFA» y «esta fila de `employees.users`» son la misma. Por
eso:

- `user_vault_identity.vault_entity_id` es **UNIQUE** y se obtiene de Vault, no
  se inventa.
- Tras validar el TOTP, el servicio **compara** el `entity_id` que devuelve
  Vault con el registrado. Si no coincide, **revoca el token recién emitido** y
  responde 403 `entity_mismatch`, en vez de entregar una sesión.
- La confirmación del enrolamiento (`pending → confirmed`) se escribe con un
  `UPDATE ... WHERE vault_entity_id = <el devuelto>`: es el filtro lo que
  garantiza que solo un login real con la entidad correcta puede confirmarlo.

### Flujo completo de un login

```
1. POST /auth/login {username, password}
      └─> Vault: auth/userpass/login/{username}
          Vault responde SIN token y con mfa_request_id          <- el MFA no se puede omitir
      └─> API: guarda un desafío en memoria, con TTL. No hay sesión.

2. POST /auth/mfa/verify {challenge_id, code}
      └─> Vault: sys/mfa/validate  -> client_token + entity_id
      └─> PostgreSQL: ¿existe el empleado? ¿está activo?
                      ¿su vault_entity_id coincide?               <- si no, se revoca el token
      └─> PostgreSQL: last_mfa_login_at = now()
                      pending|reset_required -> confirmed
      └─> API: devuelve un identificador OPACO de sesión.
               El token de Vault se queda en memoria del proceso.

3. Cada petición autenticada
      └─> Vault: auth/token/lookup-self   <- una entidad deshabilitada
                                             o un token revocado invalidan la sesión
      └─> PostgreSQL: ¿sigue activo? ¿qué roles tiene AHORA?
```

### Qué significa (y qué no) cada `totp_status`

| Estado | Significa | **No** significa |
|---|---|---|
| `pending` | Este sistema no ha visto todavía un login MFA correcto | Que la persona no haya registrado su autenticador. **No justifica reiniciar el TOTP** |
| `confirmed` | Hubo un login MFA correcto con la entidad registrada | Que se pueda **omitir** el MFA. Vault lo sigue exigiendo en cada login |
| `reset_required` | Se destruyó la semilla anterior y aún no hay login con la nueva | Que la cuenta esté bloqueada |
| `disabled` | El acceso MFA de esa identidad está deshabilitado | Que la cuenta esté borrada |

### Dos credenciales distintas, deliberadamente separadas

| | Sesión humana | Cuenta técnica (AppRole) |
|---|---|---|
| Cómo se obtiene | userpass + TOTP | `role_id` + `secret_id` de archivo |
| Para qué sirve | Lo que hace **esa persona**: `/vault/access-check` | Provisionar cuentas, entidades y TOTP |
| Dónde vive | Memoria del proceso, con TTL | Memoria, renovada o reautenticada sola |
| Política | La del usuario en Vault | `vpg-user-mgmt`, estrecha |
| Qué **no** es | — | **Nunca** el Initial Root Token ni la contraseña del administrador |

**La credencial técnica no suple los permisos del usuario.**
`/vault/access-check` usa siempre el token humano: si esa persona no puede leer
una ruta, el endpoint dice que no puede, no la lee «por detrás».

### Autenticación contra PostgreSQL

La API se conecta **solo** como `vpg_app`, por TCP y con `scram-sha-256`, con la
contraseña leída de `/run/secrets/postgres_app_password`. Esa cuenta tiene
`SELECT/INSERT/UPDATE/DELETE` y `USAGE` sobre el esquema, pero **no** `CREATE`
ni `TRUNCATE`: el DDL es de la cuenta administrativa y solo se aplica por CLI.

### Lo que nunca se almacena ni se registra

Contraseñas de Vault, semillas TOTP, códigos QR, URIs `otpauth://`, códigos de 6
dígitos y tokens. Ni en PostgreSQL, ni en los archivos SQL, ni en los logs. El
formateador de logs redacta por **nombre de clave** y por **patrón** en texto
libre.

> **Desactivar un empleado en PostgreSQL no basta.** `is_active=false` es una
> baja de la aplicación. Lo que bloquea su acceso real a Vault, incluidos los
> tokens ya emitidos, es **deshabilitar su entidad**, y por eso `DELETE /user/{id}`
> lo hace y devuelve 409 si no pudo.

---

### RBAC y autorización por objeto

| Capacidad | `admin` | `manager` | `employee` |
|---|---|---|---|
| Crear empleados | ✅ | ✅ (siempre como `employee`) | ❌ |
| Elegir roles al crear | ✅ | ❌ (403) | ❌ |
| Leer cualquier empleado | ✅ | ✅ | solo a sí mismo |
| Modificar contactos ajenos | ✅ | ✅ | ❌ |
| Modificar sus propios contactos | ✅ | ✅ | ✅ |
| Modificar perfil fiscal | ✅ | ✅ | ❌ |
| Asignar roles | ✅ | ❌ | ❌ |
| Provisionar o cambiar credenciales | ✅ | ❌ | ❌ |
| Reset de MFA ajeno | ✅ (+ MFA reciente) | ❌ | ❌ |
| Purgar | ✅ (+ MFA reciente, nunca a sí mismo) | ❌ | ❌ |

**Autorización por objeto**: conocer el UUID de otro empleado no permite leerlo
ni modificarlo. Se devuelve **403**, no un 404 cosmético: enmascarar no es
autorizar.

Un `manager` puede crear fichas pendientes sin acceso a Vault; el
provisionamiento posterior lo hace un `admin`. La **última cuenta admin activa**
está protegida frente a quitarle el rol y frente a la baja, y la autopurga está
bloqueada.

Los roles de aplicación, los roles de PostgreSQL y las políticas de Vault son
cosas distintas. El servicio **no asigna `vpg-admin` por tener el rol `admin`**,
y la configuración **rechaza al arrancar** que `vpg-admin` figure en la lista de
políticas asignables.

### Operaciones Vault y consistencia

**Una transacción de PostgreSQL no revierte Vault.** De ahí el diseño:

- Ninguna transacción de base de datos permanece abierta durante una llamada de
  red. Cada operación abre transacciones cortas: validar y registrar, llamar a
  Vault, registrar el resultado.
- Cada fase se escribe en `employees.vault_operations` (migración 002) antes de
  seguir. El registro guarda `operation_id`, tipo, usuario objetivo, fases,
  estado y error **ya saneado**; nunca contraseñas, tokens ni semillas.
- Dos invariantes los impone la base, no el código: una `Idempotency-Key` no
  crea dos operaciones, y **como máximo una operación viva por usuario
  objetivo**, lo que serializa peticiones concurrentes sin mantener abierta una
  transacción.
- **Nada se reintenta solo.** Login, TOTP y generación de semillas no son
  idempotentes.
- Si Vault ya cambió y PostgreSQL no puede reflejarlo, la respuesta **no es
  201/204**: es **409** con el `operation_id`, y la operación queda en
  `needs_reconciliation`.

| Operación | Comportamiento |
|---|---|
| **Provisionar** | Crea cuenta userpass, entidad y alias con el **accessor existente**, y genera la semilla TOTP de esa entidad con el método compartido. El URI `otpauth://` se entrega **una sola vez**, con `Cache-Control: no-store`, nunca se registra y ningún GET lo devuelve. Si falla a mitad, compensa **solo lo que creó esa operación** |
| **Leer** | Muestra el estado histórico y su aviso. **El GET nunca genera, destruye ni reinicia TOTP, y no cambia credenciales** |
| **Credenciales** | La contraseña se envía directamente a Vault y no se persiste. Vault **no ofrece rename de userpass**: la secuencia real es crear la cuenta nueva, repuntar el alias a la **misma entidad** (lo que conserva `entity_id` y la semilla ya registrada) y solo entonces borrar la anterior. Por eso cambiar el username **exige** enviar también `new_password`: si falta, se rechaza con 422 y no se toca nada, en vez de inventar la contraseña anterior |
| **Reset TOTP** | Exige admin, confirmación explícita (`confirm: "RESET"`) y **MFA reciente**. Destruye y regenera solo la semilla de la entidad objetivo; método, enforcement y demás personas quedan intactos. Invalida las sesiones del objetivo, limpia la confirmación vigente y deja `reset_required` |
| **Baja lógica** | `is_active=false`, invalida sesiones y **deshabilita la entidad en Vault**. Deshabilitar **no** equivale a revocar; la revocación es solo del objetivo, nunca global del montaje. Si la entidad no se pudo deshabilitar, **no se devuelve 204** |
| **Purga** | Solo admin, sobre un usuario ya desactivado, nunca a uno mismo. Borra únicamente **sus** cuenta, alias, entidad y enrolamiento. Si la entidad tiene alias de otros montajes o nombres, la purga **se detiene con 409** y lo explica. El registro de la operación sobrevive como auditoría mínima |

**Reconciliación**: `bash scripts/user_mgmt/reconcile-operations.sh list |
inspect <id> | close <id> "nota"`. No deshace nada por su cuenta: muestra el
estado real de los dos sistemas para que una persona decida.

### Protección y auditoría

Logs **JSON** con `X-Request-ID` validado o generado (un valor del cliente con
saltos de línea no puede inyectar líneas en el log), actor, UUID objetivo,
operación, estado y duración.

**Nunca se registran**: cuerpos de login o enrolamiento, `Authorization`,
tokens, contraseñas, códigos TOTP, URIs `otpauth://`, QR ni valores de secretos.
El `access log` de uvicorn está desactivado y SQLAlchemy no imprime sentencias
ni parámetros. La respuesta de validación muestra campo y motivo, **nunca el
valor enviado**: el cuerpo puede llevar una contraseña o un código.

**Rate limiting** en memoria por ventana deslizante: login, MFA, por sesión en
CRUD y global, con `Retry-After` en los 429.

> **Límite documentado.** Los contadores viven en el proceso: con varios workers
> el límite efectivo se multiplicaría. Y esto **no es una defensa contra IDOR**:
> la autorización por objeto se comprueba en cada endpoint. Tampoco hay
> aislamiento multi-inquilino, porque no existe ese dominio en el proyecto.

---

## Comprobaciones reproducibles (etapa 3)

Desde la raíz del repositorio, en Git Bash. Las marcadas **🖐 INTERACTIVO**
piden algo por teclado.

### 1. Preparar secretos, política de servicio y migraciones

```bash
# Secretos de PostgreSQL (etapa 2; no sobrescribe si ya existen)
bash scripts/postgres/prepare-secrets.sh

# Vault debe estar desbloqueado (paso MANUAL de la etapa 1)
docker compose exec vault-service vault operator unseal

# Política vpg-user-mgmt + AppRole + secrets/vault_role_id y vault_secret_id
bash scripts/user_mgmt/vault-approle-bootstrap.sh

# Migraciones 001 y 002 con la cuenta ADMINISTRATIVA, y permisos para vpg_app
bash scripts/user_mgmt/apply-migrations.sh
```

**Resultado real**

```
==> Escribiendo la politica 'vpg-user-mgmt'
    politica escrita
    auth approle habilitado en approle/
    rol vpg-user-mgmt configurado (politica vpg-user-mgmt, token_ttl 1h)
    vault_role_id      36 caracteres
    vault_secret_id    36 caracteres

  rolname  | select | insert | update | truncate | puede_ddl
-----------+--------+--------+--------+----------+-----------
 vpg_admin | t      | t      | t      | t        | t
 vpg_app   | t      | t      | t      | f        | f      <- sin DDL ni TRUNCATE

10 tablas (las 9 de la etapa 2 + vault_operations)
```

### 2. Construir, validar y arrancar

```bash
docker compose config --quiet && echo "config OK"
docker compose build
docker compose up -d
docker compose ps
```

El `healthcheck` del servicio usa `/health/live`, no `/health/ready`: el
contenedor está sano aunque Vault siga sellado. `interval=15s`, `timeout=5s`,
`retries=5`, `start_period=20s`.

`postgres-service` es dependencia `service_healthy`. `vault-service` es
`service_started` **a propósito**: arranca sellado y la API debe poder
levantarse igualmente.

### 3. Readiness con Vault sellado: 503

```bash
docker compose restart vault-service     # vuelve a quedar sellado
curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:8000/health/ready
curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:8000/user_mgmt/v1/user
```

**Resultado real**

```
HTTP 503
{
  "ready": false,
  "checks": {
    "postgres_select_1": true,
    "vault_initialized": true,
    "vault_unsealed": false,
    "vault_technical_credential": false,
    "admin_linked_in_postgres_and_vault": false
  },
  "detail": "vault: sellado ('vault operator unseal', paso manual); vault: pendiente de comprobar el vinculo del administrador"
}

HTTP 503
{"code":"not_ready","message":"el servicio todavia no esta listo: vault: sellado ...","request_id":"843d2ff7..."}
```

Tras desbloquear Vault, el refresco periódico lo detecta solo (sin reiniciar la
API):

```
HTTP 200
{"ready": true, "checks": {"postgres_select_1": true, "vault_initialized": true,
 "vault_unsealed": true, "vault_technical_credential": true,
 "admin_linked_in_postgres_and_vault": true}, "detail": null}
```

### 4. Salud, DNS y conexiones internas

```bash
curl -s http://127.0.0.1:8000/health/live
docker compose exec user-mgmt-service python -c "
import socket
for h in ('postgres-service','vault-service'): print(h, socket.gethostbyname(h))"
```

**Resultado real**

```
{"status":"alive"}
postgres-service 172.18.0.3
vault-service    172.18.0.2
```

### 5. Swagger, ReDoc y OpenAPI

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/docs
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/redoc
curl -s http://127.0.0.1:8000/openapi.json | python -c "
import json,sys
d=json.load(sys.stdin)
print(sum(1 for p in d['paths'] for m in d['paths'][p] if m in ('get','post','put','patch','delete')), 'operaciones')"
```

**Resultado real**: `200`, `200`, `21 operaciones`. En el navegador,
<http://127.0.0.1:8000/docs>: **Authorize** acepta el `api_session`.

### 6. 🖐 INTERACTIVO — Recorrido completo por curl

```bash
bash scripts/user_mgmt/smoke-api.sh
```

Pide el código TOTP con eco enmascarado (`#` por dígito). La contraseña sale de
`VAULT_ADMIN_USER_PASS` y viaja por stdin: nunca como argumento visible ni en el
historial. Demuestra, con **datos ficticios**: login sin sesión antes del MFA,
login válido, alta, lectura y paginación, PUT frente a PATCH, 401/403/409/422/429,
provisionamiento, GET que no reinicia el TOTP, cambio de credenciales, reset
explícito, baja lógica, purga y `access-check`.

Con `--keep` conserva el empleado de prueba; por defecto lo purga al terminar.

### 7. Fallo parcial y reconciliación

Las pruebas lo ejercitan (`test_fallo_en_vault_compensa_lo_creado`): cuando falla
la generación de la semilla tras crear cuenta y entidad, la operación queda en
`failed`, las fases registradas son
`userpass_user_created → compensate_userpass`, y en Vault no queda nada de esa
operación. Para inspeccionar en vivo:

```bash
bash scripts/user_mgmt/reconcile-operations.sh list
bash scripts/user_mgmt/reconcile-operations.sh inspect <operation_id>
bash scripts/user_mgmt/reconcile-operations.sh close <operation_id> "resuelto a mano"
```

### 8. Persistencia al recrear solo la API

```bash
docker compose rm -sf user-mgmt-service
docker compose up -d user-mgmt-service
docker compose exec postgres-service psql -U vpg_admin -d vpg_contadores -c "
SELECT u.username, vi.totp_status FROM employees.users u
  JOIN employees.user_vault_identity vi ON vi.user_id = u.id;"
docker volume ls --filter name=vpg-
```

**Resultado real**

```
antes:   03572c00-...|sinhuesiordia|confirmed
despues: 03572c00-...|sinhuesiordia|confirmed     <- idéntico
vpg-postgres-data, vpg-vault-data                  <- intactos
```

Las **sesiones en memoria sí se pierden** al reiniciar el worker: es el límite
documentado del diseño de un solo worker.

---

## Colección de Postman

Dos archivos en `postman/`, generados a partir del **OpenAPI real** de
`http://127.0.0.1:8000/openapi.json`:

| Archivo | Contenido |
|---|---|
| `vpg-user-mgmt.postman_collection.json` | 4 carpetas, **44 peticiones**, 119 aserciones `pm.test` |
| `vpg-user-mgmt.postman_environment.json` | **19 variables** de entorno |

Cada uno de los **21 endpoints** tiene dos peticiones: una **· Ejemplo**
(camino feliz) y una **· Prueba** (validación, permiso o error esperado). Las
tres excepciones añaden una tercera: `PATCH /user/{id}` lleva una prueba extra
de «modificar por id, no recrear», y `DELETE /user/{id}` una verificación del
estado tras la baja.

### Importar

En Postman: **Import** → arrastra los dos archivos → selecciona el environment
**«VPG user-mgmt (local)»** en el desplegable de la esquina superior derecha.

### Dónde va el `Authorization: Bearer <api_session>`

Si una petición devuelve esto:

```json
{
  "code": "unauthenticated",
  "message": "falta la cabecera Authorization: Bearer <api_session>",
  "request_id": "46a9ccc332934975bc438062dd58ac38",
  "context": {}
}
```

es que salió sin la cabecera. **No hay que escribirla a mano en ninguna
petición.** Está configurada una sola vez, en tres piezas:

| Dónde | Qué poner |
|---|---|
| **Colección → pestaña `Authorization`** | Type: **Bearer Token** · Token: `{{api_session}}` |
| **Cada petición → pestaña `Authorization`** | **Inherit auth from parent** (es el valor por defecto; no hay que tocar nada) |
| **Environment → `api_session`** | Se rellena **sola**: la escribe el script de `POST /auth/mfa/verify` |

Las únicas peticiones con **No Auth** son las 4 de salud, el login y la
verificación MFA —en ese momento aún no existe sesión—, y
`GET /auth/me · Prueba (401 sin Authorization)`, que lleva No Auth **a
propósito** para reproducir ese error.

### Puesta en marcha

1. Rellena `admin_username` y `admin_password` (los de `VAULT_ADMIN_USER_NAME`
   y `VAULT_ADMIN_USER_PASS` en `.env`).
2. Lanza `00 · Salud → GET /health/ready`. Si da **503**, desbloquea Vault:
   `docker compose exec vault-service vault operator unseal`.
3. Lanza `01 → POST /auth/login · Ejemplo`. Guarda `challenge_id`; todavía **no
   hay sesión**.
4. Pon el código de 6 dígitos del autenticador en **`totp_code`** y lanza
   `01 → POST /auth/mfa/verify · Ejemplo` **enseguida**: el código dura 30 s y
   el desafío 180 s.
5. A partir de ahí, las carpetas 02 y 03 funcionan solas.

> El `api_session` caduca (1 h) y **se pierde al reiniciar el contenedor**,
> porque las sesiones viven en memoria del único worker. Si empiezan los 401,
> repite los pasos 3-4.

### Variables del environment

| Variable | Tipo | Origen | Para qué |
|---|---|---|---|
| `base_url` | fija | `http://127.0.0.1:8000` | Ajústala si cambiaste `USER_MGMT_PORT_LOCAL` |
| `api_prefix` | fija | `/user_mgmt/v1` | Debe coincidir con `USER_MGMT_API_PREFIX` |
| `admin_username` | **rellenar** | — | Usuario userpass, en minúsculas |
| `admin_password` | **rellenar**, secret | — | Contraseña de Vault |
| `totp_code` | **rellenar**, secret | — | Código de 6 dígitos, justo antes del paso 4 |
| `challenge_id` | automática, secret | `/auth/login` | Desafío MFA, TTL 180 s |
| `api_session` | automática, secret | `/auth/mfa/verify` | **Lo que se manda como Bearer** |
| `mi_user_id` | automática | `/auth/mfa/verify` | Tu propio UUID (autopurga, último admin) |
| `user_id` | automática | `POST /user` | Empleado de prueba |
| `operation_id` | automática | operaciones Vault | Para consultar fases |
| `phone_id` | automática | `PATCH /user/{id}` | Para modificar un contacto por su id |
| `demo_username`, `demo_email` | automáticas | `POST /user` | Se regeneran con sufijo de tiempo, para poder repetir el alta |
| `demo_birth_date` | fija | `1991-03-20` | Formato `YYYY-MM-DD` |
| `provision_password`, `provision_password_nueva` | fijas, secret | ficticias | Provisionamiento y cambio de credenciales |
| `vault_resource` | fija | `crawler_sat` | Nombre **lógico** de la allowlist, no una ruta |
| `page_limit` | fija | `20` | Elementos por página |
| `uuid_inexistente` | fija | `00000000-…-999` | Para las pruebas de 404 |

Las marcadas `secret` las oculta Postman en la interfaz y no viajan en los
exports compartidos.

### Ejecutar la colección entera

Orden: `00` → `01` → `02` → `03`. Avisos antes de darle al Runner:

- `01 → mfa/verify · Prueba` **gasta uno de los 5 intentos** de
  `max_validation_attempts` del método TOTP.
- `01 → logout · Ejemplo` invalida la sesión: déjalo para el final.
- `02 → PUT …/roles · Prueba` intenta quitarte el rol admin. Devuelve 409 si
  eres el último admin activo; si hay más de uno, **lo conseguirá**.
- `02 → DELETE …/purge · Ejemplo` borra de verdad al empleado de prueba, en
  Vault y en PostgreSQL. Es un usuario ficticio que crea la propia colección.
- `03` necesita que `02 → POST /user · Ejemplo` haya corrido antes y que la
  purga **no**.

También se puede lanzar sin interfaz, con Newman en Docker:

```bash
MSYS_NO_PATHCONV=1 docker run --rm --network network-service \
  -v "$(pwd -W)/postman:/etc/newman:ro" \
  postman/newman:alpine run /etc/newman/vpg-user-mgmt.postman_collection.json \
  -e /etc/newman/vpg-user-mgmt.postman_environment.json \
  --env-var base_url=http://user-mgmt-service:8000 \
  --folder "00 · Salud (sin Authorization)"
```

Dentro de la red se usa `http://user-mgmt-service:8000`, no el puerto publicado
en el host.

**Resultado real** de esa carpeta:

```
↳ GET /health/ready · Ejemplo
  GET http://user-mgmt-service:8000/health/ready [200 OK, 409B, 9ms]
  ✓  Respuesta con X-Request-ID
  ✓  Responde 200 o 503
  ✓  Informa las cinco comprobaciones

  requests 4 | test-scripts 8 | assertions 14 | failed 0
```

Y la petición que reproduce el 401 del principio:

```
↳ GET /auth/me · Prueba (401 sin Authorization)
  GET .../user_mgmt/v1/auth/me [401 Unauthorized, 337B, 69ms]
  ✓  Responde 401
  ✓  code = unauthenticated
  ✓  El error trae request_id
  ✓  El mensaje indica como arreglarlo
```

### Lo que la colección nunca guarda

El URI `otpauth://` que devuelve el provisionamiento **no** se escribe en
ninguna variable de entorno, a propósito: es un secreto de un solo uso que se
entrega una vez y no vuelve a aparecer en ningún GET. El token de Vault tampoco,
porque no sale del servidor.

---

## Pruebas unitarias

### Cómo ejecutarlas

```bash
# Base de pruebas APARTE, con el mismo esquema (una sola vez)
bash scripts/user_mgmt/prepare-test-db.sh

# Suite completa, en un contenedor efímero sobre network-service
bash scripts/user_mgmt/run-tests.sh

# Un subconjunto, con detalle
bash scripts/user_mgmt/run-tests.sh -k rbac -v
bash scripts/user_mgmt/run-tests.sh tests/test_vault_sync.py -v

# Volver a empezar con la base limpia
bash scripts/user_mgmt/prepare-test-db.sh --recreate
```

**Resultado real**

```
91 passed in 42.46s
```

### Con qué se prueban

| | Decisión | Por qué |
|---|---|---|
| Base de datos | **PostgreSQL real**, en `vpg_contadores_test` | Se comprueban restricciones que **solo** existen en PostgreSQL: índices únicos sobre expresiones (`lower(username)`), índices parciales (`WHERE is_primary`), `CHECK` con regex y `ON DELETE RESTRICT`. Con SQLite «pasarían» sin demostrar nada |
| Vault | **Doble controlado** (`FakeVault`) | Las pruebas no pueden depender de un código TOTP ni destruir la semilla del administrador real |
| Cuenta de base de datos | `vpg_app`, la misma que usa el servicio | La limpieza entre pruebas usa `DELETE` y no `TRUNCATE` justamente porque `vpg_app` **no tiene** ese privilegio |
| Imagen | Etapa `user-mgmt-test` | Parte del runtime y le añade solo pytest. La imagen que se publica **no** lleva dependencias de prueba |

El doble reproduce el comportamiento que importa: el login con contraseña **no**
entrega token, hace falta validar el TOTP, y las operaciones de identidad fallan
como falla Vault.

> **El MFA con un código real del titular es una comprobación MANUAL**
> (paso 6 de esta etapa y paso 10 de la etapa 2). **No se deduce de los
> dobles** y no se da por buena sin ejecutarla.

### Qué comprueba cada módulo

#### `tests/test_auth_and_rbac.py` — 25 pruebas

Login, sesiones y matriz de permisos.

| Grupo | Pruebas |
|---|---|
| Login en dos pasos | `login_devuelve_desafio_y_no_sesion`, `login_con_contrasena_incorrecta`, `usuario_inexistente_no_se_distingue`, `codigo_totp_incorrecto`, `desafio_no_se_reutiliza` |
| Vínculo con PostgreSQL | `pending_pasa_a_confirmed_tras_login_valido`, `entity_id_distinto_rechaza_la_sesion` |
| Sesión | `sesion_no_expone_token_de_vault`, `logout_revoca_el_token_en_vault`, `sin_cabecera_authorization`, `sesion_inventada` |
| RBAC | `employee_no_crea_empleados`, `manager_no_elige_roles`, `manager_crea_siempre_employee`, `admin_elige_roles_existentes`, `rol_inexistente_no_se_crea`, `manager_no_asigna_roles`, `ultimo_admin_protegido` |
| Aislamiento por objeto (IDOR) | `employee_no_lee_a_otro_aunque_sepa_su_uuid`, `employee_lee_su_propia_ficha`, `employee_no_modifica_a_otro`, `employee_modifica_sus_contactos`, `employee_no_modifica_su_perfil_fiscal`, `employee_solo_se_ve_a_si_mismo_en_el_listado`, `employee_no_busca_a_otros` |

#### `tests/test_users_crud.py` — 22 pruebas (24 casos)

CRUD, validación, paginación y compatibilidad del ORM.

| Grupo | Pruebas |
|---|---|
| Alta transaccional | `alta_completa_en_una_transaccion`, `alta_revierte_entera_si_falla_una_parte`, `username_duplicado_sin_distinguir_mayusculas` |
| Asignación masiva | `rechaza_campos_desconocidos`, `no_admite_asignacion_masiva_de_id_ni_auditoria` (prueba `id`, `created_at`, `auth_provider`, `password_hash` y `vault_link`) |
| Validación de dominio | `validacion_de_perfil` (3 casos), `rfc_debe_cuadrar_con_la_fecha`, `un_solo_correo_principal`, `telefono_se_normaliza_a_digitos` |
| PUT frente a PATCH | `put_reemplaza_y_vacia_colecciones`, `patch_no_borra_lo_omitido`, `patch_modifica_por_id_y_borra_explicitamente`, `patch_con_id_ajeno` |
| Paginación | `paginacion_y_orden_estable`, `orden_fuera_de_la_allowlist`, `limite_de_pagina`, `filtro_por_rol`, `busqueda_por_cuerpo_no_por_url` |
| Errores | `404_con_uuid_inexistente`, `uuid_mal_formado` |
| **ORM contra el esquema real** | `orm_coincide_con_las_columnas_reales` (cada columna mapeada existe en la base con el mismo nombre), `trigger_de_updated_at_lo_mantiene_la_base` (escribir una fecha absurda se ignora: la pone el trigger) |

#### `tests/test_vault_sync.py` — 26 pruebas

Sincronización con Vault y consistencia.

| Grupo | Pruebas |
|---|---|
| Provisionamiento | `provision_crea_cuenta_entidad_y_semilla`, `manager_no_provisiona`, `politica_fuera_de_la_allowlist`, `no_se_provisiona_dos_veces` |
| Secretos que no se filtran | `el_uri_de_enrolamiento_no_aparece_en_get`, `get_no_genera_ni_destruye_totp` |
| Idempotencia y fallos parciales | `idempotency_key_no_repite_la_operacion`, `fallo_en_vault_compensa_lo_creado`, `vault_caido_devuelve_503` |
| Credenciales | `cambio_de_password`, `rename_sin_password_se_bloquea`, `rename_conserva_entidad_y_bloquea_el_nombre_viejo` |
| Reset de MFA | `reset_exige_confirmacion_explicita`, `reset_solo_toca_la_entidad_objetivo`, `reset_invalida_las_sesiones_del_objetivo` |
| Baja lógica | `baja_deshabilita_la_entidad_en_vault`, `baja_incompleta_no_devuelve_204`, `un_token_previo_deja_de_valer_tras_la_baja` |
| Purga | `no_se_puede_purgar_a_un_activo`, `autopurga_bloqueada`, `manager_no_purga`, `purga_borra_solo_lo_suyo`, `purga_se_detiene_con_alias_ajenos` |
| `access-check` | `access_check_usa_la_allowlist`, `access_check_no_revela_valores`, `access_check_denegado` |

#### `tests/test_security_surface.py` — 16 pruebas

Readiness, rate limiting, saneado de logs y contrato OpenAPI.

| Grupo | Pruebas |
|---|---|
| Readiness | `live_responde_siempre`, `ready_en_verde`, `ready_devuelve_503_si_falta_algo`, `negocio_bloqueado_con_vault_sellado`, `ready_no_expone_secretos` |
| Rate limiting | `rate_limit_en_login_con_retry_after` |
| Saneado de logs | `scrub_elimina_campos_sensibles`, `scrub_elimina_patrones_en_texto_libre`, `formateador_json_sanea_los_extras`, `la_validacion_no_devuelve_el_valor_enviado` |
| `X-Request-ID` | `request_id_del_cliente_se_valida`, `cabecera_request_id_vuelve_en_la_respuesta`, `error_incluye_request_id` |
| OpenAPI | `openapi_documenta_errores_y_esquemas`, `openapi_no_contiene_datos_reales`, `openapi_describe_el_esquema_bearer` |

### Qué NO cubren

- El login con un **código TOTP real**: solo el recorrido manual del paso 6.
- El Vault real: las pruebas usan el doble. Que la política `vpg-user-mgmt`
  tenga los permisos correctos se comprueba en el arranque
  (`vault_technical_credential` en `/health/ready`), no aquí.
- Concurrencia real entre procesos: el índice único de operaciones vivas la
  impone en la base, pero no se simulan dos clientes simultáneos.

---

## Seguridad (etapa 3)

### Escaneo de la imagen

**No se afirma que la imagen esté libre de vulnerabilidades.** Se evaluó y este
es el resultado real del 2026-10-04:

```bash
docker scout cves vpg/user-mgmt-server:0.3.0
docker scout cves --only-severity critical,high vpg/user-mgmt-server:0.3.0
```

```
Target: vpg/user-mgmt-server:0.3.0
  82 paquetes indexados
  0 CRITICAL | 0 HIGH | 5 MEDIUM | 1 LOW
```

Comparación con la etapa 2, sin cambios: `vpg/postgres-server:17-alpine` sigue
con 2 CRITICAL y 22 HIGH heredadas de `gosu` en la imagen oficial.

### Observaciones corregidas tras implementar el backend

Lo que se descubrió **durante** esta etapa y obligó a cambiar algo:

| # | Observación | Corrección |
|---|---|---|
| 1 | El `compose.yaml` publicaba Vault con `"${VAULT_PORT_LOCAL}:${VAULT_PORT_REMOTE}"`, es decir en **0.0.0.0**, mientras el texto del README prometía `127.0.0.1` | Las tres publicaciones llevan ahora bind explícito (`VAULT_HOST_BIND`, `POSTGRES_HOST_BIND`, `USER_MGMT_HOST_BIND`). Sin él, Docker publica en todas las interfaces |
| 2 | El primer escaneo encontró **3 HIGH en `starlette 0.41.3`** (CVE-2026-54283, CVE-2026-48818, CVE-2025-62727), que arrastraba `fastapi==0.115.6` | FastAPI 0.142.2 y Starlette 1.7.0, fijada de forma explícita. Reescaneado: 0 HIGH. Las 91 pruebas siguen pasando |
| 3 | `psycopg[c]==3.2.3` **no compila** con el gcc 15 de Alpine 3.22: `numutils.c` declara `UINT64CONST(10000000000000000000)` | Fijado a **3.2.13**, que sí compila, en la etapa builder |
| 4 | La implementación **pura de Python de psycopg tampoco sirve** en musl: resuelve libpq con `ctypes.util.find_library("pq")`, que devuelve `None` por no haber `ldconfig` ni `ld`, y aborta con `libpq library not found` | Se usa la variante C y el runtime solo lleva `apk add libpq`. Meter `binutils` en el runtime habría sido peor |
| 5 | `sys/auth/*` es una ruta **protegida por root** en Vault: leerla exige `sudo` además de `read`. Sin él, `403 permission denied` aunque el montaje exista | La política `vpg-user-mgmt` lo documenta y lo acota a ese único montaje y solo en lectura |
| 6 | Tras mutar un empleado, el objeto recargado conservaba las **colecciones del identity map**: los borrados de PUT/PATCH y las altas de PATCH no se reflejaban en la respuesta | `repo.get_by_id(..., refresh=True)` fuerza `populate_existing`. **Lo detectaron las pruebas**, no una revisión a ojo |
| 7 | El formateador de logs redactaba por patrón pero **no por nombre de clave**: un `extra` llamado `password` con un valor sin patrón reconocible se habría escrito entero | `JsonFormatter` comprueba ahora la clave además del valor. **También lo detectó una prueba** |
| 8 | `vpg_app` **no tiene `TRUNCATE`** (correcto por diseño), y la limpieza entre pruebas lo usaba | Las pruebas limpian con `DELETE`, respetando el orden de las FK: las mismas operaciones que puede hacer el servicio en producción |
| 9 | `email-validator` rechaza los dominios de uso reservado (`.invalid`, `example.com`), que son los que deben aparecer en ejemplos y pruebas | Tipo de correo propio, con **el mismo patrón** que el `CHECK` de la base |
| 10 | Una `IntegrityError` podía escapar sin traducirse a 409, porque `replace_roles` dispara su propio `flush` antes del `try` final | El alta completa va dentro de **un único** `try/except IntegrityError` |

### Otras decisiones

- `security_opt: no-new-privileges:true`; Uvicorn corre como `vpg` (uid 100).
- Runtime sin compiladores: comprobado en el contenedor en marcha
  (`gcc`, `cc`, `make` y `ld` ausentes; `/wheels` eliminado).
- La API no carga el `.env` del proyecto: `VAULT_ADMIN_USER_PASS`,
  `VAULT_INITIAL_TOKEN` y `VAULT_UNSEAL_KEY` no entran en su entorno.
- Se montan **tres archivos de secreto concretos**, no el directorio `secrets/`.
- Sin TLS entre cliente y API: aceptable solo porque el puerto se publica en
  `127.0.0.1`.

### Límites conocidos de esta etapa

- Sesiones y rate limiting **en memoria**: un solo worker. Varios workers o
  réplicas exigen otro diseño; no se añade Redis en esta etapa.
- `password_hash` sigue **reservado y NULL**: no hay autenticación local ni OIDC
  en la API todavía.
- `/vault/access-check` evalúa una **allowlist de rutas lógicas**, no rutas
  arbitrarias.
- La correspondencia rol de aplicación ↔ política de Vault para `manager` y
  `employee` sigue **pendiente**: hoy solo existen `vpg-admin`, `vpg-oidc-user`
  y la nueva `vpg-user-mgmt`.
- No hay sistema de migraciones automático: `apply-migrations.sh` aplica
  archivos numerados de forma explícita. La idempotencia **no** lo sustituye.
- El desbloqueo de Vault sigue siendo **manual**. Para despliegues desatendidos
  habría que configurar auto-unseal, que no es parte de esta etapa.
