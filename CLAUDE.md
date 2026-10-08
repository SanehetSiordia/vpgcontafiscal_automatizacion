# CLAUDE.md

## 1. Resumen y lectura inicial

Backend local de **VPG Contadores**: cuatro servicios en Docker Compose sobre la
red `network-service`. Frontend y crawler **no existen**: la etapa 4 entrega el
*contrato de consumo* del crawler.

| Servicio | Qué es | Dónde |
|---|---|---|
| `vault-service` | Vault sin modo dev, Raft, KV v2, `userpass` + MFA TOTP | [config/vault.hcl](config/vault.hcl) |
| `postgres-service` | PostgreSQL 17, esquemas `employees` y `vault_mgmt` | [sql/](sql/) |
| `user-mgmt-service` | FastAPI: login de dos pasos, CRUD de empleados, pasarela interna | [app/main.py](app/main.py) |
| `vault-mgmt-service` | FastAPI: CRUD dinámico de secretos en KV v2 | [app/vault_mgmt/main.py](app/vault_mgmt/main.py) |

Lee primero este mapa y después solo los archivos de la tarea, comprobando su
vigencia: el código manda sobre la documentación.

| Para cambiar... | Consulta |
|---|---|
| Login, TOTP, sesiones | [app/services/auth.py](app/services/auth.py), [app/core/security.py](app/core/security.py), [app/routers/auth.py](app/routers/auth.py) |
| Permisos de aplicación | [app/services/rbac.py](app/services/rbac.py), [app/vault_mgmt/core/principal.py](app/vault_mgmt/core/principal.py) |
| Autorización entre servicios | [app/routers/internal.py](app/routers/internal.py), [app/services/vault_gateway.py](app/services/vault_gateway.py), [app/vault_mgmt/core/gateway_client.py](app/vault_mgmt/core/gateway_client.py) |
| Colecciones, esquemas, registros | [app/vault_mgmt/services/](app/vault_mgmt/services/), [app/core/secret_schema.py](app/core/secret_schema.py), [app/core/vault_kv.py](app/core/vault_kv.py), [app/core/vault.py](app/core/vault.py) |
| Contrato de máquina (crawler) | [app/vault_mgmt/core/machine_auth.py](app/vault_mgmt/core/machine_auth.py), [app/vault_mgmt/services/consumers.py](app/vault_mgmt/services/consumers.py) |
| Base de datos y orquestación | [sql/](sql/), [Makefile](Makefile), [compose.yaml](compose.yaml), [Dockerfile](Dockerfile) |

La documentación por etapas está en [readme/](readme/), una por componente, con
[README.md](README.md) como índice: son extensos, se leen bajo demanda.

## 2. Directorios y puntos de entrada

| Ruta | Responsabilidad | Entrypoint |
|---|---|---|
| `app/` (raíz) | user-mgmt: routers, services, repositories, models, schemas | `app.main:app` (8000) |
| `app/core/` | Módulos **compartidos**: config, database, errors, logging, rate_limit, vault, vault_kv, secret_schema | — |
| `app/vault_mgmt/` | vault-mgmt, con su propio `core/` y `deps.py` | `app.vault_mgmt.main:app` (8001) |
| `sql/` | Migraciones numeradas 001, 002 y 003 | — |
| `scripts/postgres/`, `scripts/user_mgmt/`, `scripts/vault_mgmt/` | Preparación por CLI, pruebas, smoke y recorridos | `*.sh` en Git Bash |
| `config/policies/` | Políticas de Vault; versión legible de las que genera `vault-kv-policies.sh` | — |
| `tests/`, `tests/vault_mgmt/` | Suites de las etapas 3 y 4 | [pytest.ini](pytest.ini) |
| `secrets/` | Compose secrets. Fuera de Git y del build. **No abrir** | — |

## 3. Stack y comandos

Fijado en [requirements/](requirements/), [.env.example](.env.example) y
[Dockerfile](Dockerfile): Vault 2.1.1, PostgreSQL 17-alpine, Python 3.12-alpine,
FastAPI 0.142.2, Starlette 1.7.0, Uvicorn 0.54.0, SQLAlchemy 2.1.3, Pydantic
2.13.5, httpx 0.28.1, pytest 8.4.2 y `psycopg[c,pool]` 3.2.13, que en musl se
compila en la etapa builder: no sirve `[binary]` ni la pura.

Primera instalación, una vez por volumen, tras `cp .env.example .env`:

```bash
bash scripts/postgres/prepare-secrets.sh
make config          # inicializa Vault y guarda sus credenciales en secrets/
docker compose exec vault-service vault secrets enable -path=secret -version=2 kv
docker compose exec vault-service vpg-auth-bootstrap
bash scripts/postgres/seed-initial-user.sh
bash scripts/user_mgmt/apply-migrations.sh      # migraciones 001 y 002
bash scripts/vault_mgmt/apply-migrations.sh     # migración 003
bash scripts/vault_mgmt/prepare-internal-secret.sh
bash scripts/vault_mgmt/vault-kv-policies.sh    # requiere Vault desbloqueado
bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
```

En reinicios basta `make all`: arranca, desbloquea con `secrets/VAULT_UNSEAL_KEY`,
aplica lo que falte y levanta las dos APIs. Los `.paso-NN-*` son internos.

```bash
bash scripts/user_mgmt/run-tests.sh      # etapa 3
bash scripts/vault_mgmt/run-tests.sh     # etapa 4 (--all: ambas)
bash scripts/vault_mgmt/smoke-api.sh     # no interactivo
bash scripts/vault_mgmt/walkthrough.sh   # INTERACTIVO: pide TOTP
```

Destructivos, documentados sin ejecutarlos: `make down` elimina contenedores y
red conservando volúmenes, imágenes, secretos e inicialización de Vault.
`make purge` **borra** los volúmenes de Vault y PostgreSQL, las imágenes propias
y las credenciales de `secrets/` huérfanas; exige confirmación, que sin terminal
es `make purge PURGE_CONFIRM=vpg-contadores`, y obliga a repetir la etapa 1.

## 4. Flujos clave

- **Login de dos pasos.** `POST /user_mgmt/v1/auth/login` da `challenge_id`;
  `POST /auth/mfa/verify` con el TOTP da una `api_session` opaca. Autoriza Vault
  (`userpass` + MFA) y los roles salen de `employees.user_roles`. El token de
  Vault vive en memoria del worker ([app/core/security.py](app/core/security.py)),
  no se devuelve al cliente ni se persiste.
- **Empleados y provisionamiento.** [app/routers/users.py](app/routers/users.py) y
  [app/routers/vault_ops.py](app/routers/vault_ops.py) sobre `employees.*`;
  `VaultSyncService` registra cada operación en `employees.vault_operations`.
- **CRUD de secretos.** vault-mgmt **no tiene login**: reenvía el Bearer y su
  credencial de servicio a `POST /internal/v1/vault-mgmt/{session,execute}` de
  user-mgmt, que valida sesión, empleado, roles y ACL y ejecuta con el **token
  humano**. El catálogo vive en `vault_mgmt.*`, los valores solo en KV v2 bajo
  `secret/data/vpg-managed/` con CAS y versionado, y la entrega es por response
  wrapping de un solo uso (`plain` solo por elección explícita).
- **Consumo de máquina.** `POST /vault_mgmt/v1/integrations/crawler/resolve`
  autentica un **token de Vault** de AppRole propia (`lookup-self`, path,
  `role_name`, política, TTL) y resuelve el consumidor desde esa identidad, no
  del cuerpo; si falla, no hay vuelta a la cuenta técnica.

## 5. Reglas y convenciones

- **Ninguna aplicación emite DDL.** No hay `create_all()`: el esquema lo crean
  las migraciones numeradas de `sql/`, aplicadas por scripts explícitos.
- **El unseal es manual.** Una dependencia ausente no aborta el arranque:
  `/health/ready` y los endpoints de negocio responden 503 con el detalle. Lo
  único que sí aborta es la falta de un administrador con rol `admin` en
  PostgreSQL ([app/core/readiness.py](app/core/readiness.py)).
- **Credenciales por archivo** (`/run/secrets/...`), nunca como variable de
  entorno con su valor. Solo `vault-service` lleva `env_file`.
- Rol de aplicación y política de Vault son distintos: `admin` →
  `vpg-secrets-admin`, `manager` y `employee` → `vpg-secrets-reader`, máquina →
  `vpg-crawler`. Hacen falta las dos y Vault manda. La autorización es **por
  objeto**: conocer un UUID no da derecho a nada. `destroy` y `purge` exigen
  además `admin`, confirmación en el cuerpo y una prueba de MFA reciente, de un
  solo uso, en `X-VPG-MFA-Proof`.
- Errores: `AppError` con `code`, `message`, `request_id` y `context`
  ([app/core/errors.py](app/core/errors.py)). No se registran cuerpos ni valores;
  la validación informa campo y motivo, no el valor enviado.
- Local, no producción: HTTP sin TLS, puertos solo en loopback, sesiones y rate
  limiting en memoria, un worker sin `--reload`. `.env.example` propone 5432; si
  el host ocupa ese puerto, cambia `POSTGRES_PORT_LOCAL`.

## 6. Limitaciones y referencia Git

- `make config` guarda la Unseal Key y el token inicial en `secrets/`: quien los
  tenga tiene todos los secretos y el sellado deja de proteger. El propio
  [Makefile](Makefile) lo advierte; bórralos para volver al manual.
- Estados incoherentes: [sql/002_vault_operations.sql:49](sql/002_vault_operations.sql:49)
  usa `succeeded` y [sql/003_vault_mgmt.sql:356](sql/003_vault_mgmt.sql:356)
  `completed`. No los unifiques sin revisar los dos repositorios de operaciones.
- Sin transacción distribuida entre PostgreSQL y Vault: un fallo parcial devuelve
  409 con `operation_id` y queda en `needs_reconciliation`, que resuelven los
  `reconcile-operations.sh` de cada etapa.
- La validación de esquema es un subconjunto cerrado propio
  ([app/core/secret_schema.py](app/core/secret_schema.py)): sin `$ref` ni
  resolución de URI, para no depender de `jsonschema` en musl.
- `README.md` lista `postman/`, pero `.gitignore` excluye `postman/*`: la colección
  la genera [scripts/vault_mgmt/build_postman.py](scripts/vault_mgmt/build_postman.py).
- `pytest.ini` fija `testpaths = tests`, así que `python -m pytest` corre ambas
  suites; la imagen `vault-mgmt-test` limita su CMD a `tests/vault_mgmt`. Se
  prueba con PostgreSQL real y dobles de Vault y de la pasarela: el login con un
  TOTP real es comprobación manual.

Commit base inspeccionado: `b56aa38a243ffc11a848f4809677d4a4ca14a6b5`, rama
`feature_fastapi_vault`, árbol limpio; ese hash no incluye este documento. Para
su última actualización, los cambios posteriores a la base y los no confirmados:

```bash
git log -1 --format="%H %s" -- CLAUDE.md
git diff b56aa38a243ffc11a848f4809677d4a4ca14a6b5 HEAD -- . ":(exclude)CLAUDE.md"
git status --short
```

Actualiza este mapa cuando cambien la arquitectura, los comandos o los
invariantes; no lo reescribas ni crees un commit por cada lectura.
