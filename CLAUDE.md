# CLAUDE.md

## 1. Resumen y lectura inicial

Backend local de **VPG Contadores**: cinco servicios en Docker Compose sobre la
red `network-service`. Frontend y crawler **no existen**: las etapas 4 y 4.6
entregan el *contrato de consumo* del crawler, no el crawler.

| Servicio | Qué es | Dónde |
|---|---|---|
| `vault-service` | Vault sin modo dev, Raft, KV v2, `userpass` + MFA TOTP | [config/vault.hcl](config/vault.hcl) |
| `postgres-service` | PostgreSQL 17, esquemas `employees` y `vault_mgmt` | [sql/](sql/) |
| `user-mgmt-service` | FastAPI: login de dos pasos, CRUD de empleados, pasarela interna | [app/main.py](app/main.py) |
| `vault-mgmt-service` | FastAPI: CRUD dinámico de secretos en KV v2 | [app/vault_mgmt/main.py](app/vault_mgmt/main.py) |
| `vault-mgmt-worker` | Misma imagen, otro comando: procesa la cola de operaciones | [app/vault_mgmt/worker.py](app/vault_mgmt/worker.py) |

Lee primero este mapa y después solo los archivos de la tarea, comprobando su
vigencia: el código manda sobre la documentación.

| Para cambiar... | Consulta |
|---|---|
| Login, TOTP, sesiones | [app/services/auth.py](app/services/auth.py), [app/core/security.py](app/core/security.py), [app/routers/auth.py](app/routers/auth.py) |
| Permisos de aplicación | [app/services/rbac.py](app/services/rbac.py), [app/vault_mgmt/core/principal.py](app/vault_mgmt/core/principal.py) |
| Autorización entre servicios | [app/routers/internal.py](app/routers/internal.py), [app/services/vault_gateway.py](app/services/vault_gateway.py), [app/vault_mgmt/core/gateway_client.py](app/vault_mgmt/core/gateway_client.py) |
| Colecciones, esquemas, registros | [app/vault_mgmt/services/](app/vault_mgmt/services/), [app/core/secret_schema.py](app/core/secret_schema.py), [app/core/vault_kv.py](app/core/vault_kv.py), [app/core/vault.py](app/core/vault.py) |
| Contrato de máquina y entrega | [app/vault_mgmt/core/machine_auth.py](app/vault_mgmt/core/machine_auth.py), [app/vault_mgmt/services/consumers.py](app/vault_mgmt/services/consumers.py) |
| Aprovisionamiento (4.6) | [app/vault_mgmt/services/provisioning.py](app/vault_mgmt/services/provisioning.py), [app/vault_mgmt/routers/consumers.py](app/vault_mgmt/routers/consumers.py), [app/vault_mgmt/routers/provisioning_internal.py](app/vault_mgmt/routers/provisioning_internal.py) |
| Credenciales de Vault del aprovisionador | [app/vault_mgmt/core/vault_auth.py](app/vault_mgmt/core/vault_auth.py), [app/vault_mgmt/core/approle_admin.py](app/vault_mgmt/core/approle_admin.py) |
| Base de datos y orquestación | [sql/](sql/), [Makefile](Makefile), [compose.yaml](compose.yaml), [Dockerfile](Dockerfile) |

La documentación por etapas está en [readme/](readme/), con
[README.md](README.md) como índice: son extensos, se leen bajo demanda.

## 2. Directorios y puntos de entrada

| Ruta | Responsabilidad | Entrypoint |
|---|---|---|
| `app/` (raíz) | user-mgmt: routers, services, repositories, models, schemas | `app.main:app` (8000) |
| `app/core/` | Módulos **compartidos**: config, database, errors, logging, rate_limit, vault, vault_kv, secret_schema | — |
| `app/vault_mgmt/` | vault-mgmt, con su propio `core/` y `deps.py` | `app.vault_mgmt.main:app` (8001) |
| `sql/` | Migraciones numeradas 001, 002, 003 y 004 | — |
| `scripts/postgres/`, `scripts/user_mgmt/`, `scripts/vault_mgmt/` | Preparación por CLI, pruebas, smoke y recorridos | `*.sh` en Git Bash |
| `config/policies/` | Políticas de Vault; versión legible de las que genera `vault-kv-policies.sh` | — |
| `tests/`, `tests/vault_mgmt/` | Suites de las etapas 3, 4 y 4.6 | [pytest.ini](pytest.ini) |
| `secrets/` | Compose secrets. Fuera de Git y del build. **No abrir** | — |

## 3. Stack y comandos

Fijado en [requirements/](requirements/), [.env.example](.env.example) y
[Dockerfile](Dockerfile): Vault 2.1.1, PostgreSQL 17-alpine, Python 3.12-alpine,
FastAPI 0.142.2, SQLAlchemy 2.1.3, Pydantic 2.13.5, httpx 0.28.1, pytest 8.4.2 y
`psycopg[c,pool]` 3.2.13, que en musl se compila en la etapa builder: no sirve
`[binary]` ni la pura.

Primera instalación, una vez por volumen, tras `cp .env.example .env`:

```bash
bash scripts/postgres/prepare-secrets.sh
make config          # inicializa Vault y guarda sus credenciales en secrets/
docker compose exec vault-service vault secrets enable -path=secret -version=2 kv
docker compose exec vault-service vpg-auth-bootstrap
bash scripts/postgres/seed-initial-user.sh
bash scripts/user_mgmt/apply-migrations.sh      # migraciones 001 y 002
bash scripts/vault_mgmt/apply-migrations.sh     # migraciones 003 y 004
bash scripts/vault_mgmt/prepare-internal-secret.sh
bash scripts/vault_mgmt/vault-kv-policies.sh    # requiere Vault desbloqueado
bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
```

Desde la etapa 4.6, `make all` hace también la **primera inicialización** de un
volumen nuevo (`make config` queda como alias), genera la credencial de cada
receptor si falta y levanta el worker. Nunca reinicializa un volumen con datos y
nunca rota una credencial que ya vale. `make help` resume los objetivos; los
`.paso-NN-*` son internos.

`/health/ready` separa dos cosas: `checks` condiciona `ready` (si algo es false,
503), y `capabilities` **no bloquea** — si falta el token del aprovisionador, el
CRUD sigue atendiendo y las altas de consumidores se guardan en `pending`.

```bash
bash scripts/user_mgmt/run-tests.sh      # etapa 3
bash scripts/vault_mgmt/run-tests.sh     # etapa 4 y 4.6 (--all: todas)
bash scripts/vault_mgmt/smoke-api.sh     # no interactivo
bash scripts/vault_mgmt/walkthrough.sh   # INTERACTIVO: pide TOTP
bash scripts/vault_mgmt/provisioning-walkthrough.sh   # INTERACTIVO (etapa 4.6)
python scripts/vault_mgmt/test_receiver.py            # receptor de pruebas
```

Destructivos: `make down` elimina contenedores y red conservando volúmenes,
imágenes y secretos. `make purge` **borra** los volúmenes, las imágenes propias
y las credenciales huérfanas de `secrets/`; exige confirmación (sin terminal,
`make purge PURGE_CONFIRM=vpg-contadores`) y obliga a repetir la etapa 1.

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
  humano**. El catálogo vive en `vault_mgmt.*` y los valores solo en KV v2 bajo
  `secret/data/vpg-managed/`, con CAS y versionado; la entrega es por response
  wrapping de un solo uso.
- **Aprovisionamiento de una máquina (4.6).** `POST /vault/consumers` valida,
  guarda y devuelve **202**; la petición no habla con Vault. El worker prepara la
  AppRole y para en `waiting_receiver` **sin emitir credencial**. El receptor
  reclama en `/internal/v1/crawler/provisioning/claim` con su credencial, recibe
  el SecretID **envuelto**, entra con AppRole y confirma en `/ack`, donde el
  servidor comprueba con `lookup` que el token es de esa identidad **y de esa
  entrega** (por el `delivery_id` que el claim dejó en sus metadatos). Solo
  entonces hay `completed`.
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
- **Credenciales por archivo** (`/run/secrets/...`), nunca por variable de
  entorno. Solo `vault-service` lleva `env_file`.
- Rol de aplicación y política de Vault son distintos: `admin` →
  `vpg-secrets-admin`, `manager` y `employee` → `vpg-secrets-reader`, máquina →
  `vpg-crawler`. Hacen falta las dos y Vault manda. La autorización es **por
  objeto**: conocer un UUID no da derecho a nada. `destroy` y `purge` exigen
  además `admin`, confirmación en el cuerpo y una prueba de MFA reciente, de un
  solo uso, en `X-VPG-MFA-Proof`.
- **Ninguna respuesta humana lleva credenciales**: de Vault solo salen
  *accessors*. La única que cruza es el SecretID del `claim` interno, envuelto.
- **El rol AppRole se deriva del nombre del consumidor**, nunca se recibe:
  [approle_admin.py](app/vault_mgmt/core/approle_admin.py) rechaza lo que esté
  fuera de `VAULT_MGMT_MANAGED_ROLE_PREFIX` y genera el HCL él mismo.
- `delivery_mode` marca el límite real: un consumidor `direct` (heredado) lee
  todo el prefijo KV con su token, así que sus bindings acotan lo que la API le
  entrega, **no** lo que puede leer. Uno `mediated` no puede leer KV.
- La unicidad del nombre de un receptor es **parcial** (solo activos): revocar
  un consumidor libera su receptor poniéndolo en `disabled`, y la fila se
  conserva porque las entregas apuntan a ella. Con unicidad total, el nombre
  quedaba quemado y la función era de un solo uso por receptor.
- Una revocación **supersede** la operación viva del consumidor en vez de
  chocar con ella: si no, un consumidor atascado no se podría revocar nunca.
- **Un doble no valida a quien reemplaza.** `FakeAppRole` sustituye al cliente
  de Vault entero, así que no puede detectar un fallo del propio cliente. Eso ya
  ocurrió: `metadata` iba como objeto donde Vault exige una cadena JSON, las 38
  pruebas seguían verdes y el recorrido real devolvía 503. El formato de hilo se
  prueba aparte, contra el cliente de verdad y un transporte falso
  ([tests/vault_mgmt/test_approle_admin_wire.py](tests/vault_mgmt/test_approle_admin_wire.py)).
  Si tocas `approle_admin.py`, afirma sobre el cuerpo que sale por el cable.
- Tres cosas de la API de Vault que no son obvias y ya costaron una depuración:
  el `lookup` de un token **no** expone el accessor de su SecretID (solo los
  metadatos que se le pusieron, más `role_name`); al envolver, el accessor que
  devuelve es el del *wrapping token*, no el del SecretID; y con
  `secret_id_num_uses=1` lo que sobrevive a una rotación es el **token**, que se
  retira por su accessor, no el SecretID, que ya se consumió.
- Errores: `AppError` con `code`, `message`, `request_id` y `context`
  ([app/core/errors.py](app/core/errors.py)). No se registran cuerpos ni valores;
  la validación informa campo y motivo, no el valor enviado.
- Local, no producción: HTTP sin TLS, puertos solo en loopback, sesiones y rate
  limiting en memoria. `.env.example` propone 5432; si el host ocupa ese puerto,
  cambia `POSTGRES_PORT_LOCAL`.

## 6. Limitaciones y referencia Git

- `make all` guarda la Unseal Key y el token inicial en `secrets/`: quien los
  tenga tiene todos los secretos y el sellado deja de proteger. Además, ese
  token es el que usa el aprovisionador (montado en solo lectura en vault-mgmt
  y su worker): lo acota el **código**, no la ACL. Bórralos para volver al
  manual; el [Makefile](Makefile) y la etapa 4.6 lo advierten.
- Estados incoherentes: [sql/002_vault_operations.sql:49](sql/002_vault_operations.sql:49)
  usa `succeeded`; `vault_mgmt.secret_operations` usa `completed`. No los
  unifiques sin revisar los dos repositorios de operaciones.
- Un consumidor `direct` no está acotado por sus bindings (ver §5), y migrarlo a
  `mediated` exige estrechar su política en Vault a mano.
- El SecretID es de un solo uso: un receptor que lo pierda al reiniciar necesita
  reaprovisionarse. No se promete *exactamente una vez*: token, SecretID y
  envoltura tienen TTL distintos.
- `make purge` conserva la credencial de un receptor mientras exista el volumen
  de PostgreSQL, porque el consumidor al que sirve sigue en el catálogo.
- Sin transacción distribuida entre PostgreSQL y Vault: un fallo parcial deja
  `needs_reconciliation` con su `operation_id`, que resuelven los
  `reconcile-operations.sh`.
- La validación de esquema es un subconjunto cerrado propio
  ([app/core/secret_schema.py](app/core/secret_schema.py)): sin `$ref`, para no
  depender de `jsonschema` en musl.
- `.gitignore` excluye `postman/*`: las colecciones las genera
  [scripts/vault_mgmt/build_postman.py](scripts/vault_mgmt/build_postman.py).
- Se prueba con PostgreSQL real y dobles de Vault y de la pasarela: el login con
  un TOTP real y el aprovisionamiento contra Vault son comprobación manual.

Commit base inspeccionado: `45273f142f5ad4732523583b1d2456d7dac0f951`, rama
`feature_fastapi_vault`. Ese hash es el estado **anterior** a la etapa 4.6, así
que el `git diff` de abajo es justo lo que esa etapa añadió. No se anota aquí el
hash del commit que contiene este documento: sería una referencia circular.

```bash
git log -1 --format="%H %s" -- CLAUDE.md
git diff 45273f142f5ad4732523583b1d2456d7dac0f951 HEAD -- . ":(exclude)CLAUDE.md"
git status --short
```

Actualiza este mapa cuando cambien la arquitectura, los comandos o los
invariantes; no lo reescribas ni crees un commit por cada lectura.
