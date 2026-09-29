# vpgcontafiscal_automatizacion
Automatizacion Inteligente para contabilidad fiscal VPG

## Componente 1: HashiCorp Vault (credenciales del crawler)

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
| Políticas | `vpg-admin` (acceso total) y `vpg-oidc-user` (lectura de `secret/crawler/*`) |
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


Verificar Codigo MFA esperado para ingresar con username

```bash
python -c "import base64,hmac,hashlib,struct,time;k=base64.b32decode('SECRET_GENERADO');h=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();o=h[-1]&15;print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))"
```

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
