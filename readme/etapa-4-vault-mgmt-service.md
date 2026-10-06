# Componente 4: vault-mgmt-service (CRUD dinámico de secretos)

[← Índice del proyecto](../README.md)

Etapas: [1. HashiCorp Vault](etapa-1-vault.md) · [2. PostgreSQL 17](etapa-2-postgresql.md) · [3. user-mgmt-service](etapa-3-user-mgmt-service.md) · **4. vault-mgmt-service**

---

API REST local para **definir colecciones de secretos con campos tipados** y
gestionar sus **registros completos** en HashiCorp Vault KV v2. Se publica en
`127.0.0.1:8001` y se apoya en los tres componentes anteriores: PostgreSQL para
el catálogo y la auditoría, Vault para los valores, y `user-mgmt-service` para
autenticar a las personas.

### Lo que esta etapa NO incluye

No hay frontend, ni crawling, ni subida de archivos binarios, ni OIDC o login
local en esta API, ni despliegue en VPS, Kubernetes o Terraform. Swagger y ReDoc
sí están. Los campos `file_reference` son **referencias a archivos externos**:
KV nunca guarda el contenido ni su base64. Esta etapa entrega backend, pruebas,
documentación y Postman; **no ejecuta ningún proceso de crawling** y no hace
peticiones a sitios externos.

### Archivos de este componente

| Archivo | Para qué |
|---|---|
| `sql/003_vault_mgmt.sql` | Migración 003: esquema `vault_mgmt` con catálogo, esquemas versionados, índice de registros, consumidores, operaciones y auditoría. Incluye los **permisos DML mínimos** |
| `app/vault_mgmt/` | La aplicación: `main.py`, `deps.py`, `core/`, `models/`, `repositories/`, `routers/`, `schemas/`, `services/` |
| `app/core/secret_schema.py` | Esquema tipado: definición, documento JSON Schema y validación. **Compartido** con la pasarela de user-mgmt |
| `app/core/vault_kv.py` | Cliente de KV v2: datos, versiones, metadata y response wrapping. **Compartido** |
| `app/routers/internal.py` | Pasarela interna **en user-mgmt**. Fuera del OpenAPI público |
| `app/services/vault_gateway.py` | Donde se autoriza de verdad y se ejecuta KV con el **token humano** |
| `requirements/vault_mgmt.txt`, `requirements/vault_mgmt-dev.txt` | Dependencias de ejecución y de pruebas |
| `config/policies/vpg-secrets-admin.hcl` | Política KV v2 de administración, acotada al prefijo gestionado |
| `config/policies/vpg-secrets-reader.hcl` | Política KV v2 de solo lectura |
| `config/policies/vpg-crawler.hcl` | Política de la máquina: solo lectura |
| `scripts/vault_mgmt/*` | Preparación por CLI (migraciones, políticas, credencial interna, consumidor), inventario, reconciliación, pruebas, humo y el **recorrido interactivo** `walkthrough.sh` |
| `tests/vault_mgmt/*` | 155 pruebas: catálogo, registros, CAS, MFA, entrega, ciclo de vida, crawler y superficie de seguridad |
| `postman/vpg-vault-mgmt.postman_collection.json` | Colección v2.1, **derivada del OpenAPI** |

### Por qué un esquema de PostgreSQL propio y no `employees`

`scripts/postgres/pg-app-role.sh` concede a `vpg_app`
`SELECT/INSERT/UPDATE/DELETE` sobre **todas** las tablas de `employees`, y deja
privilegios por defecto para las futuras. Meter aquí el catálogo le daría
permiso de `UPDATE` y `DELETE` sobre la auditoría y sobre los esquemas
versionados, que deben ser **de solo inserción**. El esquema `vault_mgmt` tiene
sus propios `GRANT`, uno por tabla:

| Tabla | SELECT | INSERT | UPDATE | DELETE | Por qué |
|---|:--:|:--:|:--:|:--:|---|
| `secret_audit` | sí | sí | **no** | **no** | Append-only: una línea escrita no se reescribe desde la aplicación |
| `secret_collection_schemas` | sí | sí | **no** | **no** | Una versión de esquema es inmutable |
| `secret_collections` | sí | sí | sí | **no** | Una colección se archiva o se purga; su fila permanece como auditoría mínima |
| `secret_operations` | sí | sí | sí | **no** | El rastro de una operación no se borra |
| `secret_records` | sí | sí | sí | sí | El índice sí se mantiene |
| `secret_consumers` | sí | sí | sí | **no** | Un consumidor se revoca, no se borra |
| `secret_consumer_bindings` | sí | sí | sí | sí | El `PUT` de asignaciones es un reemplazo completo |

Ninguna tabla tiene `TRUNCATE` y el esquema no concede `CREATE`: la cuenta de
ejecución no puede emitir DDL. **Consecuencia real y buscada:** la suite de
pruebas *no puede* vaciar la auditoría ni los esquemas. Por eso cada prueba usa
nombres y UUID propios; para empezar de cero se recrea la base de pruebas.

Tampoco se reutiliza `employees.vault_operations`: su clave es el empleado
objetivo (FK a `employees.users` e índice de «una operación viva por usuario»).
Una operación sobre un registro de secretos no tiene empleado objetivo, y su
exclusión debe ser por colección o por registro. Es una tabla nueva, no un
encaje forzado.

### Modelo: colección, esquema y registro

Una **colección** tiene UUID, nombre lógico único (`sat/usuarios`), descripción,
versión de esquema, estado y roles lectores. Su **esquema** declara campos con
nombre, tipo, `required` y clasificación `sensitive`, y admite `string`,
`number`, `integer`, `boolean`, `object`, `array` y `file_reference`, con topes
de tamaño, profundidad y número de campos.

Un **registro** tiene UUID estable y guarda **un objeto completo** de campos
relacionados:

```json
{ "usuario": "demo", "password": "valor-ficticio" }
```

**N registros son N secretos de Vault**, cada uno con su propio path y su propio
historial de versiones. No son N escrituras que sobrescriben el mismo
`sat/usuarios`. Borrar un registro elimina su tupla completa; eliminar un campo
es otra operación (un `PATCH` con `null`) y no borra sus campos hermanos.

El reparto es estricto:

- **PostgreSQL** guarda catálogo, esquemas versionados, índice de registros,
  asignaciones de consumidores, auditoría y operaciones. **Nunca** valores
  secretos, ni sus hashes.
- **Vault** guarda los valores y sus versiones, en
  `secret/vpg-managed/{collection_id}/{record_id}`. Los segmentos
  `data`/`metadata`/`delete`/`undelete`/`destroy` son detalles del cliente KV v2,
  no carpetas del secreto.

Cada versión de Vault guarda una **envoltura**:

```json
{ "schema_version": 1, "values": { "usuario": "demo", "password": "valor-ficticio" } }
```

Así cada versión conserva el esquema que la validó. `custom_metadata` de KV v2 es
**por clave, no por versión**: no se usa para afirmar qué esquema tenía una
versión histórica, y la respuesta de `/metadata` lo dice de forma explícita.

**Renombrar** `sat/usuarios` a `sat/datos` cambia el nombre lógico del catálogo
y conserva UUID, path físico, historial y las referencias del crawler, porque el
path se deriva del `collection_id`. KV v2 **no tiene rename nativo** y aquí no se
simula con copy + delete: eso perdería el historial y dejaría una copia del
secreto en otro path.

**Crear una colección no crea nada en Vault.** KV v2 no tiene carpetas y un
prefijo sin claves simplemente no existe. `LIST` enumera hijos de un prefijo: no
devuelve documentos, no aplica filtrado de políticas elemento a elemento y **no
tiene paginación nativa**. El `limit`/`offset` de la API es del catálogo en
PostgreSQL.

### Validación de esquema: la decisión y su límite

El esquema se publica como documento **JSON Schema (Draft 2020-12)**,
autocontenido, sin `$ref` ni `$defs`, y se guarda junto a la versión. La
validación la hace un validador **propio** (`app/core/secret_schema.py`) sobre el
subconjunto cerrado que este servicio genera: `type`, `enum`, `required`,
`properties`, `additionalProperties: false`, `items`, `minItems`/`maxItems`,
`minLength`/`maxLength`, `minimum`/`maximum`. Sin resolución de URI y sin
ejecución de código.

**Por qué no la librería `jsonschema`:** arrastra `rpds-py`, que es una
extensión compilada en Rust. En `python:3.12-alpine` (musl) eso significa, o
depender de que exista una rueda `musllinux` para cada versión futura, o meter la
cadena de compilación de Rust en la etapa builder. Este proyecto ya pagó ese
peaje con `psycopg` y está documentado.

**El límite, dicho sin adornos:** ese validador cubre *solo* el subconjunto que
se genera aquí, no JSON Schema completo. Para compensarlo, el documento que
publica `GET .../schema` es estándar, de modo que cualquier validador externo
puede comprobar los mismos valores y debe llegar al mismo veredicto.

**`sensitive` controla presentación y registro, no seguridad.** Un campo
sensible no se muestra en mensajes de error ni se escribe en logs. No convierte
el valor en seguro: lo que lo protege es Vault y los permisos de entrega.

### Autenticación entre procesos: la pasarela interna

Las sesiones y los tokens de Vault viven **en memoria del único worker de
user-mgmt**, y la `api_session` es un identificador **opaco**: no es un JWT ni un
token de Vault. Copiar `SessionStore` a otro contenedor daría un diccionario
vacío en otro proceso, no acceso a las sesiones existentes.

Por eso vault-mgmt **no valida sesiones**. Recibe el Bearer humano y envía la
operación tipada a una pasarela interna de user-mgmt, que autoriza y ejecuta:

```
cliente ──Bearer api_session──▶ vault-mgmt:8001
                                      │
                    Bearer + credencial interna + operación tipada
                                      ▼
                        user-mgmt:8000  /internal/v1/vault-mgmt/execute
                                      │ valida sesión, empleado, roles, MFA
                                      │ resuelve el path desde el catálogo
                                      ▼
                        Vault KV v2, con el TOKEN HUMANO
```

El contrato interno es mínimo:

| Endpoint | Qué hace |
|---|---|
| `POST /internal/v1/vault-mgmt/session` | Valida las dos credenciales y devuelve **únicamente** principal, roles vigentes y antigüedad del MFA |
| `POST /internal/v1/vault-mgmt/execute` | Recibe `operation` de una allowlist, `collection_id`, `record_id`, CAS y parámetros tipados; **vuelve a autorizar** y ejecuta KV |

Qué se comprueba en cada ejecución, en este orden:

1. **Credencial interna de servicio**, con comparación en tiempo constante
   (`secrets.compare_digest`). Viene de un archivo de Compose secret, nunca de
   una variable de entorno con su valor.
2. **Bearer humano**: sesión viva, token de Vault vigente, empleado activo y
   roles **releídos de PostgreSQL**. La credencial interna **no sustituye** nada
   de esto: las dos son obligatorias.
3. **Catálogo compartido**: la colección y el registro existen, el estado lo
   permite y el path físico se deriva del catálogo, nunca del cuerpo.
4. **Permisos de aplicación**: `admin` para escribir; rol lector autorizado para
   leer.
5. **Prueba de MFA reciente** para lo irreversible, ligada a sesión, actor,
   operación y conjunto cerrado de recursos.
6. **ACL de Vault**: la operación se ejecuta con el token de la persona. Si su
   política no cubre el path, Vault responde 403 aunque el rol de aplicación lo
   permitiera. **Vault manda.**

Lo que la pasarela **no** hace: no devuelve el token de Vault ni su accessor; no
acepta URL, montaje, path, cabecera ni endpoint de Vault del llamante (el DTO es
`extra="forbid"`, así que un campo de más es 422); no ejecuta un shell ni habla
con el socket de Docker; no usa la cuenta técnica (AppRole) para leer secretos; y
no escribe en el catálogo, solo lo consulta.

**La red de Docker no autentica a nadie.** Cualquier contenedor de
`network-service` puede resolver `user-mgmt-service`; de ahí la credencial de
servicio. Los endpoints se registran con `include_in_schema=False`, así que no
aparecen en `/openapi.json`, ni en Swagger, ni en ReDoc, ni en Postman — pero eso
**no es su protección**: la protección son las dos credenciales.

### Reautenticación MFA para lo irreversible

`destroy` y `purge` exigen tres cosas **a la vez**: rol `admin`, confirmación
explícita en el cuerpo y una **prueba breve de MFA reciente**.

La prueba se pide en user-mgmt con un **login completo** del titular:

| Paso | Endpoint | Qué devuelve |
|---|---|---|
| 1 | `POST /user_mgmt/v1/auth/mfa/step-up` | `challenge_id`. Aquí se fijan `operation` y `resource_ids`: **todavía no hay prueba** |
| 2 | `POST /user_mgmt/v1/auth/mfa/step-up/verify` | `mfa_proof`, que se envía en `X-VPG-MFA-Proof` |

El usuario sale de la **sesión**, no del cuerpo: no se puede reautenticar a
nombre de otra persona. El código se valida contra `sys/mfa/validate` de Vault —
aquí no se comparan dígitos ni se consultan semillas en PostgreSQL, y **no se
acepta un booleano enviado por el cliente**. El token que Vault emite al validar
se revoca de inmediato: la sesión ya tiene el suyo.

La prueba es de **un solo uso**, caduca pronto, no sobrevive al cierre de su
sesión y está ligada a sesión, actor, operación y **conjunto cerrado** de
recursos. Para un lote destructivo autoriza esa operación registrada sobre ese
conjunto, no acciones ilimitadas: por eso un lote de colección es **una sola
llamada** a la pasarela, con una sola prueba.

### Permisos y mapeo rol ↔ política de Vault

Esta etapa implementa el mapeo que la etapa 3 declaraba **pendiente**:

| Rol de aplicación | Política de Vault | Alcance |
|---|---|---|
| `admin` | `vpg-secrets-admin` | `create/read/update` en `secret/data/vpg-managed/*`; `read/list/delete` en metadata; `update` en delete/undelete/destroy |
| `manager`, `employee` | `vpg-secrets-reader` | Solo `read` en `secret/data/vpg-managed/*`. Sin escritura, sin borrado, sin metadata y sin `list` |
| Máquina (crawler) | `vpg-crawler` | Solo `read` en `secret/data/vpg-managed/*`, más wrapping |

Lo que **no** se hace, a propósito: no se concede `vpg-admin` (acceso total a
Vault) a todo el personal; no se amplía la AppRole de user-mgmt para leer
secretos (una cuenta técnica prepara infraestructura, **no suplanta permisos
humanos**); y el rol de aplicación no concede nada en Vault por sí solo. Hay que
hacer las dos cosas, y Vault manda sobre el rol.

`scripts/vault_mgmt/vault-kv-policies.sh` **genera** las políticas a partir de
`VAULT_MGMT_KV_MOUNT` y `VAULT_MGMT_KV_PREFIX`, en vez de copiar los `.hcl` tal
cual, para que no puedan quedar desparejados con la configuración. Los archivos
de `config/policies/` son la versión legible y comentada de lo mismo.

### Entrega de secretos

`POST .../records/{record_id}/read` entrega por defecto **response wrapping de
Vault**: un token de un solo uso, con TTL corto configurable (60 s por omisión),
la versión y la referencia. El consumidor lo desenvuelve en Vault.

Tres cosas que el wrapping **no** es: no es un JSON cifrado; no impide que el
receptor autorizado vea los valores al desenvolverlo; y no es lo mismo que la
`api_session` ni que el token de autenticación de Vault. Es una capacidad
sensible y una **excepción explícita** de entrega: nunca se registra en logs ni
se persiste, tampoco en la auditoría.

La alternativa `plain` devuelve JSON **solo por elección explícita** del lector
autorizado, con `Cache-Control: no-store`.

> **SHA-256 es un hash, no cifrado reversible.** Esta API no devuelve hashes como
> sustituto de las credenciales que un consumidor necesita usar. Vault protege el
> **almacenamiento**; HTTPS protegería el **transporte**. **HTTP en loopback o en
> la red local de pruebas no proporciona cifrado en tránsito**, y en este entorno
> no se usa TLS: es un límite real, no un detalle.

### KV v2, concurrencia y operaciones destructivas

- **CAS obligatorio** en escrituras: `0` para crear, `current_version` esperado
  para `PUT` y `PATCH`. Un conflicto responde 409 y **no sobrescribe el cambio
  ajeno**.
- Antes de un `PATCH` se valida el **objeto resultante completo**. Si un `null`
  borraría un campo `required`, la respuesta es 422 y **no se escribe nada**.
- `PUT` y `PATCH` crean versión **nueva**; las anteriores no se mutan.
- Soft-delete admite `undelete`. `destroy` y el borrado de metadata son
  **irreversibles**.
- **Restaurar una versión antigua no cambia por sí solo cuál es `latest`**:
  `latest` sigue siendo la mayor no destruida. La respuesta de `/metadata` lo
  dice.
- Una colección `archived` bloquea el acceso de la API y las entregas futuras.
  **No** revoca secretos ya entregados, **no** caduca un wrapping token que ya
  viaja y **no** impide a un administrador leer Vault directamente: eso lo decide
  la ACL de Vault.
- Los lotes están **acotados** por configuración. Si la colección tiene más
  registros que el tope, la operación se rechaza **antes** de tocar nada, en vez
  de dejar la mitad hecha.
- Mientras una transición está abierta, el índice parcial de operaciones y la
  comprobación previa **serializan** las escrituras de esta API sobre esa
  colección. Eso cubre a esta API, **no a Vault**: alguien con permisos puede
  escribir directamente, y por eso antes de cerrar se **compara el inventario** y
  se reportan las claves que el catálogo no conoce. No se borran ni se adoptan en
  silencio. No se promete una exclusión global que el motor no ofrece.

**No hay transacción distribuida.** De ahí: fases durables, `Idempotency-Key` en
mutaciones, CAS, estados `pending`/`in_progress`/`completed`/`failed`/
`needs_reconciliation`, y reconciliación por CLI. No se almacenan cuerpos, ni
valores, ni hashes de contraseñas para comparar reintentos — un hash de baja
entropía en la base sería un oráculo. **No se reintenta a ciegas** cuando Vault
pudo escribir y se perdió la respuesta: la operación queda en
`needs_reconciliation` y la respuesta es 409 con el `operation_id`.

Y mientras siga sin reconciliar, **ese recurso no acepta escrituras**: dejar
escribir encima convertiría una incoherencia conocida en varias. Se libera cuando
una persona la revisa y la cierra con
`scripts/vault_mgmt/reconcile-operations.sh --close`.

Ninguna transacción de base de datos permanece abierta durante una llamada HTTP.
`202` no se usa: no hay procesamiento pendiente durable, y no se añaden colas ni
Redis.

### Contrato del futuro crawler: una máquina independiente

No se presta la `api_session` de ningún empleado. El consumidor presenta en
`Authorization` un **token de Vault** obtenido antes con su propia AppRole de
solo lectura, en un montaje **separado** (`approle-crawler/`) del de la cuenta
técnica de user-mgmt, para poder revocar la máquina sin tocar la otra.

Qué se valida: `lookup-self` con ese token; que su `path` sea el login de la
AppRole esperada; que su `role_name` coincida; que lleve la política mínima
registrada; que siga vigente; y que el consumidor tenga **binding** para cada
registro pedido. El `consumer_id` **no se acepta del cliente**: se resuelve desde
la identidad del token, y por eso `(montaje, rol)` es único en la base — si dos
consumidores compartieran rol, un token no determinaría qué alcance le
corresponde y elegir «el primero» sería darle a una máquina los permisos de otra.
**Si la autenticación falla, no hay vuelta a la cuenta técnica del servicio.**

Se resuelve por **UUID de registro y versión explícita**; nunca por usuario y
contraseña, ni por path libre, ni por URL arbitraria. Se devuelven wrapping
tokens emitidos con los permisos de **esa** máquina, no de un empleado ni del
bootstrap. **No se emiten tokens de autenticación nuevos.**

| Tema | Comportamiento |
|---|---|
| Revocar un binding | Impide **entregas futuras**. No caduca un wrapping token ya entregado, no revoca su token AppRole y no borra lo que ya leyó |
| Revocar el consumidor | `--revoke` borra el rol en Vault y lo marca revocado. Los **tokens ya emitidos** viven hasta su TTL (20 min): por eso el TTL es corto |
| Versión fijada vs `latest` | `pinned_version` fija la versión y no cambia aunque se escriba otra. Ausente significa `latest` |
| Expiración y un solo uso | El wrapping token caduca y se consume una vez. Si caduca, **se pide otra entrega sin repetir la tarea** |
| Cambio de esquema | La envoltura lleva `schema_version`: el consumidor sabe con qué esquema se validó lo que recibe |

Nunca se incluyen secretos en URL, en payloads de trabajo, en archivos
exportados de Postman ni en errores.

### Contrato REST

Prefijo `/vault_mgmt/v1`, con `/vault` como raíz del dominio. UUID en los paths;
nombres lógicos, valores y códigos TOTP **solo en el cuerpo**. Salud no requiere
sesión; la integración de máquinas tiene autenticación propia.

| Método | Ruta relativa | Permiso | Resultado |
|---|---|---|---|
| GET | `/health/live` | público | 200, proceso vivo |
| GET | `/health/ready` | público | 200/503, dependencias y pasarela |
| POST | `/vault/collections` | admin | 201, catálogo y esquema inicial |
| GET | `/vault/collections` | lector autorizado | 200, colecciones visibles, sin valores |
| GET | `/vault/collections/{id}` | lector autorizado | 200, definición y estado |
| PATCH | `/vault/collections/{id}` | admin | 200, nombre/descr./lectores |
| GET | `/vault/collections/{id}/schema` | lector autorizado | 200, campos, tipos y versión |
| PUT | `/vault/collections/{id}/schema` | admin | 200, versión nueva compatible; 409 si no |
| DELETE | `/vault/collections/{id}` | admin + MFA reciente | 204, archivo y soft-delete; 409 parcial |
| POST | `/vault/collections/{id}/restore` | admin + MFA reciente | 200, versiones recuperables |
| POST | `/vault/collections/{id}/purge` | admin + MFA reciente | 204, destrucción; auditoría conservada |
| POST | `/vault/collections/{id}/records` | admin | 201, registro completo con CAS=0 |
| GET | `/vault/collections/{id}/records` | lector autorizado | 200, IDs/estado/versiones, sin valores |
| GET | `/vault/collections/{id}/records/{rid}` | lector autorizado | 200, resumen, sin valores |
| POST | `/vault/collections/{id}/records/{rid}/read` | lector autorizado | 200, entrega wrapped o plain |
| PUT | `/vault/collections/{id}/records/{rid}` | admin | 200, reemplazo completo con CAS |
| PATCH | `/vault/collections/{id}/records/{rid}` | admin | 200, merge patch con CAS |
| DELETE | `/vault/collections/{id}/records/{rid}` | admin | 204, soft-delete de la versión actual |
| GET | `/vault/collections/{id}/records/{rid}/metadata` | admin | 200, metadata nativa, sin valores |
| POST | `.../records/{rid}/versions/delete` | admin | 204, soft-delete de versiones explícitas |
| POST | `.../records/{rid}/versions/undelete` | admin | 204, recuperar no destruidas |
| POST | `.../records/{rid}/versions/destroy` | admin + MFA reciente | 204, irreversible |
| POST | `.../records/{rid}/purge` | admin + MFA reciente | 204, datos y metadata |
| POST | `/vault/access-check` | lector autorizado | 200, capacidad efectiva, sin valores |
| GET | `/vault/operations/{id}` | admin | 200, estado, fases y error saneado |
| GET | `/vault/audit` | admin | 200, historial paginado sin valores |
| PUT | `/vault/consumers/{id}/bindings` | admin | 200, registros y versiones autorizados |
| GET | `/vault/consumers/{id}/bindings` | admin | 200, referencias y alcance, sin credenciales |
| POST | `/integrations/crawler/resolve` | máquina autorizada | 200, entrega wrapped; no inicia crawling |

**Listados:** `limit=20` (1–100), `offset>=0`, orden estable con una clave única
como último criterio, allowlist de filtros y de orden, y total del catálogo
**visible** — decir cuántas colecciones hay en total a quien solo puede ver tres
ya sería filtrar.

**Errores uniformes:** 401 sesión ausente o expirada, 403 sin permiso, 404
recurso o versión inexistente, 409 CAS/conflicto/fallo parcial, 422 cuerpo
inválido, 429 con `Retry-After`, 503 dependencia no disponible. Se distinguen
**soft-deleted**, **destroyed** y **ausencia**, sin filtrar valores. `204` sin
cuerpo solo tras completar todas las fases.

**Nota sobre 403 frente a 404:** cuando alguien pide un recurso que existe pero
no le corresponde se devuelve **403**, no un 404 cosmético. Enmascarar no es
autorizar: lo que no se revela es el contenido, no la existencia de un recurso
cuyo UUID ya tenía. La excepción es un registro que no pertenece a la colección
indicada: ahí se responde 404 sin distinguir «no existe» de «existe en otra
colección», porque confirmar lo segundo sí filtraría el catálogo.

---

## Comprobaciones reproducibles (etapa 4)

Todo en Git Bash, desde la raíz del repositorio. Los puertos salen del `.env`:
este equipo publica PostgreSQL en **5434** porque el 5432 lo ocupa un PostgreSQL
nativo.

### 1. Preparación por CLI

```bash
# Secretos de PostgreSQL (etapa 2; no sobrescribe si ya existen)
bash scripts/postgres/prepare-secrets.sh

# Migraciones 001 y 002 y permisos de vpg_app (etapa 3)
bash scripts/user_mgmt/apply-migrations.sh

# Migración 003 y permisos DML MÍNIMOS del catálogo
bash scripts/vault_mgmt/apply-migrations.sh

# Credencial interna de la pasarela (la leen los DOS servicios)
bash scripts/vault_mgmt/prepare-internal-secret.sh
```

Resultado esperado de la migración 003: las siete tablas y esta tabla de
permisos, que es la comprobación que importa.

```
           tabla           | sel | ins | upd | del | trunc
---------------------------+-----+-----+-----+-----+-------
 secret_audit              | t   | t   | f   | f   | f
 secret_collection_schemas | t   | t   | f   | f   | f
 secret_collections        | t   | t   | t   | f   | f
 secret_consumer_bindings  | t   | t   | t   | t   | f
 secret_consumers          | t   | t   | t   | f   | f
 secret_operations         | t   | t   | t   | f   | f
 secret_records            | t   | t   | t   | t   | f

 usage | puede_ddl
-------+-----------
 t     | f
```

Resultado real obtenido: exactamente esa tabla.

Las políticas de Vault y el consumidor necesitan Vault **desbloqueado**, así que
van después del paso 4:

```bash
# Políticas KV v2 acotadas al prefijo gestionado
bash scripts/vault_mgmt/vault-kv-policies.sh

# Asignarlas a quien corresponda, una persona por invocación. Usa los
# usuarios REALES de employees.user_vault_identity, no los de las pruebas:
#   docker compose exec postgres-service psql -U vpg_admin -d vpg_contadores -c "
#   SELECT u.username, string_agg(r.code, ',') AS roles, i.vault_username
#     FROM employees.users u
#     JOIN employees.user_roles ur ON ur.user_id = u.id
#     JOIN employees.roles r ON r.id = ur.role_id
#     LEFT JOIN employees.user_vault_identity i ON i.user_id = u.id
#    WHERE u.is_active GROUP BY 1, 3 ORDER BY 1;"
bash scripts/vault_mgmt/vault-kv-policies.sh --grant-admin  '<usuario-admin>'
bash scripts/vault_mgmt/vault-kv-policies.sh --grant-reader '<usuario-manager>'
bash scripts/vault_mgmt/vault-kv-policies.sh --show         '<usuario-manager>'

# Identidad de máquina del futuro crawler (AppRole dedicada, solo lectura)
bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
```

> Un token **ya emitido** no cambia de políticas. Tras conceder o retirar una,
> la persona debe cerrar sesión y volver a entrar (login + TOTP) para que apliquen.
> El script lo avisa.

### 2. Construir y validar la configuración

```bash
docker compose config >/dev/null && echo "compose: OK"
docker compose build vault-mgmt-service
docker compose images vault-mgmt-service
```

Resultado real: `compose: OK` y la imagen `vpg/vault-mgmt-server:0.4.0`
construida. La etapa builder compila las ruedas para musl (`psycopg-c`, `uvloop`,
`httptools`, `pydantic-core`) y el runtime solo instala las ruedas ya construidas
sobre `libpq`, sin compiladores ni caché de pip.

### 3. Arrancar

```bash
docker compose up -d
docker compose ps --format "table {{.Service}}\t{{.Status}}"
```

Resultado real:

```
SERVICE              STATUS
postgres-service     Up (healthy)
user-mgmt-service    Up (healthy)
vault-service        Up (healthy)
vault-mgmt-service   Up (healthy)
```

El contenedor está **healthy** aunque Vault siga sellado, porque su healthcheck
usa `/health/live`, no `/health/ready`. Son dos cosas distintas.

### 4. Vault arranca sellado: el desbloqueo es MANUAL

```bash
curl -s http://127.0.0.1:8001/health/ready | python -m json.tool
```

Resultado real con Vault sellado (**HTTP 503**):

```json
{
    "ready": false,
    "checks": {
        "postgres_select_1": true,
        "catalog_schema_present": true,
        "vault_initialized": true,
        "vault_unsealed": false,
        "user_mgmt_ready": false,
        "internal_gateway_authenticated": false
    },
    "detail": "vault: sellado ('vault operator unseal', paso manual); user-mgmt: /health/ready no responde 200 (puede estar esperando el unseal manual de Vault); pasarela: no se puede confirmar todavía porque la pasarela responde 503: ..."
}
```

Nótese la cadena: Vault sellado deja a user-mgmt no listo, y eso deja la pasarela
sin poder confirmarse. El diagnóstico dice la causa raíz primero. La API **no
hace unseal**:

```bash
docker compose exec vault-service vault operator unseal   # pide la clave
curl -s http://127.0.0.1:8001/health/ready | python -m json.tool   # ahora 200
```

### 5. Salud, DNS y documentación

```bash
bash scripts/vault_mgmt/smoke-api.sh
```

Resultado real: las 7 secciones pasan. Comprueba salud, Swagger/ReDoc/OpenAPI
(20 rutas, dos esquemas de seguridad), que la pasarela interna **no** está en
ningún OpenAPI público, que exige sus dos credenciales **probándola desde otro
contenedor de la red**, DNS entre servicios por nombre, publicación solo en
loopback y que los endpoints de negocio exigen sesión.

Las dos APIs documentan por separado:

| URL | Qué |
|---|---|
| http://127.0.0.1:8000/docs | Swagger de user-mgmt (sesiones, empleados, MFA) |
| http://127.0.0.1:8001/docs | Swagger de vault-mgmt (colecciones, registros, crawler) |
| http://127.0.0.1:8001/redoc | ReDoc de vault-mgmt |
| http://127.0.0.1:8001/openapi.json | Contrato, sin rutas `/internal` |

La protección de la pasarela, comprobada desde `vault-mgmt-service` hacia
`user-mgmt-service` por la red interna:

```
sin credencial ni Bearer       : HTTP 401 code=internal_credential_invalid
credencial inventada           : HTTP 401 code=internal_credential_invalid
credencial correcta, sin Bearer: HTTP 401 (o 503 si Vault sigue sellado)
```

### 6. 🖐 INTERACTIVO — Recorrido CRUD completo

Necesita códigos TOTP de una persona, así que no se automatiza. La forma
recomendada es el script, igual que en la etapa 3:

```bash
bash scripts/vault_mgmt/walkthrough.sh
bash scripts/vault_mgmt/walkthrough.sh --keep   # conserva la colección de prueba
```

El usuario administrador y su contraseña salen de `VAULT_ADMIN_USER_NAME` y
`VAULT_ADMIN_USER_PASS` del `.env`: **no hay ningún usuario escrito en el
código**, y la contraseña viaja por stdin, nunca como argumento visible ni en el
historial. El código TOTP se teclea oculto, con un `#` por dígito.

> **Harán falta tres códigos TOTP distintos** (dos con `--keep`): uno para el
> login y uno por cada operación irreversible, porque la prueba de MFA es de un
> solo uso y Vault no admite reutilizar un código. Si el autenticador sigue
> mostrando el anterior, espera a que cambie.

Demuestra, en este orden y con datos ficticios: que crear una colección no
escribe nada en Vault; dos registros que son dos secretos independientes; el CAS
que impide sobrescribir el cambio ajeno; un `PATCH` donde lo omitido se conserva
y `null` elimina; un `null` sobre un campo obligatorio que responde 422 sin
escribir; la entrega envuelta y su consumo único; el renombrado que conserva
UUID, path e historial; un esquema incompatible que no crea versión; la
capacidad efectiva; los tres estados de una versión; la purga con
reautenticación y el rechazo al reutilizar la prueba; y la auditoría sin
valores.

Al final cierra la sesión y purga los fixtures, salvo con `--keep`.

#### El mismo recorrido a mano

Si prefieres ir paso a paso, esto es lo mismo con `curl`. **El paso 0 no es
opcional:** sin él, `curl` recibe una URL vacía, no imprime nada y el `python`
siguiente falla con un `JSONDecodeError` que no dice nada del problema real.

```bash
# --- paso 0: variables y comprobación previa -------------------------------
UM=http://127.0.0.1:8000/user_mgmt/v1
VM=http://127.0.0.1:8001/vault_mgmt/v1
# Tu administrador real, el de employees.users. NO uses 'ada.admin': ese es el
# fixture de las pruebas y solo existe en la base de pruebas.
ADMIN=$(sed -n 's/^[[:space:]]*VAULT_ADMIN_USER_NAME=//p' .env | head -1 | tr -d '\r')

# Si alguna falta, para aquí en vez de fallar tres comandos más adelante.
: "${UM:?define UM}" "${VM:?define VM}" "${ADMIN:?falta VAULT_ADMIN_USER_NAME en .env}"
curl -fsS http://127.0.0.1:8000/health/ready >/dev/null && echo "user-mgmt listo"
curl -fsS http://127.0.0.1:8001/health/ready >/dev/null && echo "vault-mgmt listo"
echo "administrador: $ADMIN"
```

Si una de las dos comprobaciones falla, mira su `detail`: lo habitual es que
Vault siga sellado y el desbloqueo sea manual.

```bash
# --- paso 0b: ayudantes que fallan hablando --------------------------------
# api <MÉTODO> <URL> [CUERPO] -> cuerpo en stdout, estado en $ESTADO.
# Sustituye a `curl -s | python -c`, que ante cualquier error deja una traza
# ilegible en vez del 401 o el 503 que de verdad ocurrió.
api() {
  local metodo=$1 url=$2 cuerpo=${3-}
  local -a opciones=(-sS -X "$metodo" "$url" -H 'Content-Type: application/json')
  [[ -n "${A:-}" ]] && opciones+=(-H "$A")
  [[ -n "${P:-}" ]] && opciones+=(-H "X-VPG-MFA-Proof: $P")
  [[ -n "$cuerpo" ]] && opciones+=(--data-binary "$cuerpo")
  local respuesta
  respuesta=$(curl -w $'\n%{http_code}' "${opciones[@]}" 2>&1) || true
  ESTADO=${respuesta##*$'\n'}
  respuesta=${respuesta%$'\n'*}
  if [[ ! "$ESTADO" =~ ^2[0-9][0-9]$ ]]; then
    printf 'ERROR: %s %s -> %s\n' "$metodo" "$url" "${ESTADO:-sin respuesta}" >&2
    printf '%s\n' "$respuesta" >&2
    return 1
  fi
  printf '%s' "$respuesta"
}

# jget "a.b.0.c" sobre stdin. Devuelve vacío si falta la clave.
jget() { python -c "
import json,sys
crudo = sys.stdin.read()
if not crudo.strip(): print(''); sys.exit(0)
try: d = json.loads(crudo)
except json.JSONDecodeError: print(''); sys.exit(0)
for k in sys.argv[1].split('.'):
    if d is None: break
    d = d[int(k)] if k.isdigit() and isinstance(d, list) else (
        d.get(k) if isinstance(d, dict) else None)
print(d if d is not None else '')" "$1"; }
```

```bash
# --- 1. sesión (etapa 3) ---------------------------------------------------
read -rsp "Contraseña de $ADMIN: " PASS; echo
CH=$(api POST "$UM/auth/login" \
     "$(python -c "import json,sys;print(json.dumps({'username':sys.argv[1],'password':sys.argv[2]}))" \
        "$ADMIN" "$PASS")" | jget challenge_id)
unset PASS
[[ -n "$CH" ]] || { echo "sin challenge_id: mira el error de arriba"; }

read -rp "Código TOTP: " CODE
S=$(api POST "$UM/auth/mfa/verify" \
    "$(python -c "import json,sys;print(json.dumps({'challenge_id':sys.argv[1],'code':sys.argv[2]}))" \
       "$CH" "$CODE")" | jget api_session)
unset CODE
A="Authorization: Bearer $S"
[[ -n "$S" ]] && echo "sesión establecida"
```

```bash
# --- 2. crear la colección y su esquema ------------------------------------
C=$(api POST "$VM/vault/collections" '{
  "logical_name": "sat/usuarios-demo",
  "description": "Credenciales del portal del SAT (datos ficticios)",
  "reader_role_codes": ["admin", "manager"],
  "fields": [
    {"name": "usuario",  "type": "string", "required": true,  "max_length": 64},
    {"name": "password", "type": "string", "required": true,  "sensitive": true, "max_length": 256},
    {"name": "rfc",      "type": "string", "required": false, "max_length": 13}
  ]
}' | jget collection_id)
echo "collection_id=$C"

# Crear la colección NO ha escrito nada en Vault: KV v2 no tiene carpetas
docker compose exec vault-service vault kv list "secret/vpg-managed/$C"
# "No value found": correcto, el prefijo todavía no existe
```

```bash
# --- 3. dos registros INDEPENDIENTES ---------------------------------------
R1=$(api POST "$VM/vault/collections/$C/records" '{
       "label": "contribuyente-uno",
       "values": {"usuario": "demo-uno", "password": "valor-ficticio-1"}
     }' | jget record_id)
R2=$(api POST "$VM/vault/collections/$C/records" '{
       "label": "contribuyente-dos",
       "values": {"usuario": "demo-dos", "password": "valor-ficticio-2"}
     }' | jget record_id)
echo "R1=$R1"; echo "R2=$R2"

# Dos claves distintas en Vault, no una sobrescrita dos veces
docker compose exec vault-service vault kv list "secret/vpg-managed/$C"
```

```bash
# --- 4. CAS: la segunda escritura con la misma versión PIERDE --------------
api PUT "$VM/vault/collections/$C/records/$R1" \
  '{"expected_version":1,"values":{"usuario":"demo-uno","password":"v2-ficticio"}}' \
  | python -m json.tool          # 200, version 2

api PUT "$VM/vault/collections/$C/records/$R1" \
  '{"expected_version":1,"values":{"usuario":"demo-uno","password":"no-se-escribe"}}'
# ERROR: PUT ... -> 409  con code=cas_conflict. El cambio ajeno sigue intacto.
```

```bash
# --- 5. PATCH: omitido conserva, null elimina ------------------------------
api PUT "$VM/vault/collections/$C/records/$R1" \
  '{"expected_version":2,"values":{"usuario":"demo-uno","password":"v3","rfc":"XAXX010101000"}}' \
  >/dev/null
api PATCH "$VM/vault/collections/$C/records/$R1" \
  '{"expected_version":3,"patch":{"password":"v4-ficticio","rfc":null}}' \
  | python -m json.tool          # 200, version 4

# 'usuario' se omitió y se conserva; 'rfc' llevaba null y ya no está
api POST "$VM/vault/collections/$C/records/$R1/read" \
  '{"delivery":"plain","reason":"recorrido del README"}' \
  | python -c 'import json,sys; print(sorted(json.load(sys.stdin)["delivery"]["values"]))'
# ['password', 'usuario']

# null sobre un campo OBLIGATORIO: 422 y NO se escribe nada
api PATCH "$VM/vault/collections/$C/records/$R1" \
  '{"expected_version":4,"patch":{"password":null}}'
# ERROR: PATCH ... -> 422  con el campo y el motivo
```

```bash
# --- 6. entrega envuelta (por defecto) -------------------------------------
W=$(api POST "$VM/vault/collections/$C/records/$R1/read" '{}' | jget delivery.wrap_token)
echo "wrap token de ${#W} caracteres (un solo uso, TTL 60 s)"
docker compose exec -T vault-service vault unwrap -format=json "$W" \
  | python -c 'import json,sys; d=json.load(sys.stdin)["data"]["data"]; print("esquema v%s, campos: %s" % (d["schema_version"], sorted(d["values"])))'
docker compose exec -T vault-service vault unwrap "$W" 2>&1 | tail -1
# el segundo intento falla: es de un solo uso
unset W
```

```bash
# --- 7. renombrar: el historial NO se pierde -------------------------------
api PATCH "$VM/vault/collections/$C" '{"logical_name":"sat/datos-demo"}' \
  | python -c 'import json,sys; d=json.load(sys.stdin); print(d["logical_name"], d["collection_id"], d["physical_prefix"])'
api GET "$VM/vault/collections/$C/records/$R1/metadata" \
  | python -c 'import json,sys; print([v["version"] for v in json.load(sys.stdin)["versions"]])'
# mismo collection_id, mismo physical_prefix, versiones 1..4 intactas
```

```bash
# --- 8. esquema compatible (crea v2) e incompatible (409) -----------------
api PUT "$VM/vault/collections/$C/schema" '{
  "fields": [
    {"name":"usuario","type":"string","required":true,"max_length":64},
    {"name":"password","type":"string","required":true,"sensitive":true,"max_length":256},
    {"name":"rfc","type":"string","required":false,"max_length":13},
    {"name":"notas","type":"string","required":false,"max_length":500}
  ], "note": "se añade notas opcional"
}' | python -m json.tool          # 200, applied=true, versión 2

api PUT "$VM/vault/collections/$C/schema" \
  '{"fields":[{"name":"usuario","type":"string","required":true,"max_length":64}]}'
# ERROR: PUT ... -> 409  con code=schema_incompatible y el detalle por campo
```

```bash
# --- 9. capacidad efectiva -------------------------------------------------
api POST "$VM/vault/access-check" "$(python -c "
import json,sys
print(json.dumps({'collection_id':sys.argv[1],'record_id':sys.argv[2],
                  'operations':['record_read','record_replace','record_purge']}))" \
  "$C" "$R1")" | python -m json.tool
```

```bash
# --- 10. destructivo: hace falta step-up de MFA ----------------------------
api POST "$VM/vault/collections/$C/records/$R2/purge" '{"confirm":"PURGE"}'
# ERROR: POST ... -> 403  con code=mfa_proof_required

read -rsp "Contraseña de $ADMIN (reautenticación): " PASS; echo
SCH=$(api POST "$UM/auth/mfa/step-up" "$(python -c "
import json,sys
print(json.dumps({'password':sys.argv[1],'operation':'record_purge',
                  'collection_id':sys.argv[2],'resource_ids':[sys.argv[3]]}))" \
      "$PASS" "$C" "$R2")" | jget challenge_id)
unset PASS

# Un código TOTP NUEVO: el anterior ya se usó y Vault no admite repetirlo
read -rp "Código TOTP nuevo: " CODE2
P=$(api POST "$UM/auth/mfa/step-up/verify" "$(python -c "
import json,sys
print(json.dumps({'challenge_id':sys.argv[1],'code':sys.argv[2]}))" \
    "$SCH" "$CODE2")" | jget mfa_proof)
unset CODE2

api POST "$VM/vault/collections/$C/records/$R2/purge" \
  '{"confirm":"PURGE","reason":"limpieza de fixtures"}' && echo "purgado (204)"

# La prueba es de UN SOLO USO: repetirla falla
api POST "$VM/vault/collections/$C/records/$R1/purge" '{"confirm":"PURGE"}'
# ERROR: POST ... -> 403  con code=mfa_proof_invalid
unset P
```

```bash
# --- 11. auditoría: quién, qué y con qué resultado, sin valores ------------
api GET "$VM/vault/audit?collection_id=$C&limit=10" | python -m json.tool
```

### 7. Comprobar los datos **directamente en Vault**, sin imprimir valores

Lo importante es ver la estructura, las versiones y los estados, no el
contenido. Estos comandos no imprimen ningún valor:

```bash
# Las claves del prefijo gestionado: un hijo por colección, y uno por registro
docker compose exec vault-service vault kv list secret/vpg-managed
docker compose exec vault-service vault kv list "secret/vpg-managed/$C"

# Metadata nativa: versiones, estados e irreversibilidades. NO imprime datos
docker compose exec vault-service vault kv metadata get "secret/vpg-managed/$C/$R1"

# Solo los NOMBRES de los campos de la versión actual, nunca sus valores
docker compose exec vault-service sh -c \
  "vault kv get -format=json secret/vpg-managed/$C/$R1" \
  | python -c 'import json,sys; d=json.load(sys.stdin)["data"]["data"]; \
print("schema_version:", d["schema_version"]); print("campos:", sorted(d["values"]))'

# Confirmar que un registro purgado ya no existe en Vault
docker compose exec vault-service vault kv metadata get "secret/vpg-managed/$C/$R2" \
  2>&1 | tail -1          # "No value found"
```

Y que PostgreSQL **no** guarda ningún valor, recorriendo toda columna de texto y
JSON del catálogo:

```bash
docker compose exec -T postgres-service psql --no-psqlrc -U vpg_admin -d vpg_contadores -c "
SELECT c.table_name, c.column_name
  FROM information_schema.columns c
 WHERE c.table_schema = 'vault_mgmt'
   AND c.data_type IN ('text','character varying','jsonb','json')
 ORDER BY 1, 2;" | head -30
```

La prueba automatizada `test_ningun_valor_llega_a_postgresql` hace exactamente
eso: genera el recorrido completo (crear, leer en claro y parchear) y busca el
valor en **cada** columna de texto y JSON del esquema. Resultado: cero.

### 8. Persistencia al recrear las APIs

```bash
docker compose rm -sf vault-mgmt-service user-mgmt-service
docker compose up -d user-mgmt-service vault-mgmt-service
docker compose exec vault-service vault operator unseal      # si se recreó Vault

# El catálogo y los secretos siguen ahí; la SESIÓN no
curl -s -o /dev/null -w 'sesión anterior -> HTTP %{http_code}\n' \
  "$VM/vault/collections" -H "$A"
# sesión anterior -> HTTP 401
```

Las colecciones, los registros, las versiones, las asignaciones y la auditoría
**persisten**: viven en los volúmenes de PostgreSQL y de Vault. Lo que no
sobrevive es la **sesión**, porque vive en memoria del worker de user-mgmt, y con
ella sus pruebas de MFA. Hay que volver a iniciar sesión. Está documentado como
límite, no es un fallo.

### 9. Fallo parcial y reconciliación

```bash
bash scripts/vault_mgmt/reconcile-operations.sh
bash scripts/vault_mgmt/reconcile-operations.sh --operation '<operation_id>'
bash scripts/vault_mgmt/reconcile-operations.sh --close '<operation_id>' \
     --as failed --note "revisado: Vault no escribió"
```

El script **no arregla nada por su cuenta**, y es deliberado: cuando una
operación queda en `needs_reconciliation`, Vault **pudo** haber aplicado el
cambio y la respuesta se perdió. Reintentar a ciegas una escritura que quizás se
aplicó es como se duplican versiones. El script muestra las fases, el comando
para ver la metadata real en Vault, y solo cierra el registro cuando una persona
ya lo revisó. `--close` no toca Vault ni el índice de registros.

Para contrastar el prefijo gestionado con el catálogo:

```bash
export VAULT_TOKEN='<token administrativo>'     # no se guarda en ningún archivo
python scripts/vault_mgmt/inventory_import.py audit
```

### 10. Inventario e importación de secretos **anteriores**

Los secretos que ya existían, como `secret/sat/usuarios`, **se conservan**. La
importación es explícita, no destructiva y con CAS:

```bash
export VAULT_TOKEN='<token administrativo>'

# 1. qué hay, sin tocar nada
python scripts/vault_mgmt/inventory_import.py list --path sat

# 2. qué pasaría (dry-run; NO escribe). Muestra los NOMBRES de los campos
#    para poder compararlos con el esquema, nunca su contenido
python scripts/vault_mgmt/inventory_import.py plan \
    --source sat/usuarios --collection "$C"

# 3. importar de verdad (hay que escribirlo)
python scripts/vault_mgmt/inventory_import.py apply \
    --source sat/usuarios --collection "$C"
```

No borra ni mueve el origen: es una **copia** al prefijo gestionado, y
`secret/sat/usuarios` sigue existiendo con su historial. Escribe con `cas=0`: si
el destino ya tiene datos, esa entrada falla y el resto continúa. No imprime
valores en ningún modo.

### 11. 🖐 INTERACTIVO — Consumo por el cliente CLI de la máquina

```bash
# El bootstrap muestra role_id y secret_id UNA vez y registra el consumer_id
bash scripts/vault_mgmt/crawler-approle-bootstrap.sh

# Asignarle registros (solo admin, con su api_session)
curl -s -X PUT "$VM/vault/consumers/'<consumer_id>'/bindings" -H "$A" \
  -H 'Content-Type: application/json' \
  -d "{\"bindings\":[{\"collection_id\":\"$C\",\"record_id\":\"$R1\",\"pinned_version\":null}]}" \
  | python -m json.tool

# Consumo con datos ficticios. No imprime valores: nombres y tamaños
python scripts/vault_mgmt/crawler_client.py \
  --role-id '<role_id>' --secret-id '<secret_id>' \
  --record "$C:$R1" --double-unwrap
```

El cliente hace exactamente lo que hará el crawler: login AppRole en Vault,
`resolve` presentando **ese** token, y desenvuelve en Vault. `--double-unwrap`
comprueba que el wrapping token es de un solo uso. **No hace ninguna petición a
un sitio externo: aquí no hay crawling.**

### 12. Limpieza de **fixtures** solamente

```bash
# Purgar la colección de demostración (admin + MFA reciente)
# operation = collection_purge_batch
curl -s -o /dev/null -w 'purga de colección -> HTTP %{http_code}\n' \
  -X POST "$VM/vault/collections/$C/purge" -H "$A" \
  -H "X-VPG-MFA-Proof: '<prueba nueva>'" -H 'Content-Type: application/json' \
  -d '{"confirm":"PURGE","reason":"limpieza de fixtures de demostración"}'

# Revocar el consumidor de prueba
bash scripts/vault_mgmt/crawler-approle-bootstrap.sh --revoke

# Base de pruebas desde cero (la única forma de vaciar la auditoría:
# la cuenta de ejecución no puede borrarla, por diseño)
bash scripts/vault_mgmt/prepare-test-db.sh --recreate
```

Se purga **solo** lo creado por estos ejemplos. `secret/sat/usuarios` y los demás
secretos anteriores no se tocan, y los volúmenes no se borran.

---

## Pruebas unitarias (etapa 4)

```bash
# Base de pruebas con los esquemas employees y vault_mgmt (una vez)
bash scripts/vault_mgmt/prepare-test-db.sh

# Suite de la etapa 4
bash scripts/vault_mgmt/run-tests.sh

# Un subconjunto, con detalle
bash scripts/vault_mgmt/run-tests.sh -k cas -v

# Las dos etapas juntas
bash scripts/vault_mgmt/run-tests.sh --all

# Volver a empezar con la base limpia
bash scripts/vault_mgmt/prepare-test-db.sh --recreate
```

### Con qué se prueba, y qué demuestra cada cosa

| Pieza | Cómo | Qué demuestra y qué no |
|---|---|---|
| PostgreSQL | **Real**, en `vpg_contadores_test`, con los esquemas `employees` y `vault_mgmt` y **los mismos permisos DML que en producción** | Demuestra índices parciales con `COALESCE`, `CHECK` con regex y con operadores de array, FK compuesta con `RESTRICT`, `ARRAY` y los `GRANT`/`REVOKE`. Con SQLite «pasarían» sin demostrar nada |
| Pasarela interna | **Real y en el proceso de pruebas**: la app de user-mgmt se monta de verdad y el cliente de vault-mgmt le habla por `ASGITransport` | Demuestra credencial interna, Bearer obligatorio, roles releídos, pruebas de MFA ligadas a operación y recurso, y la traducción de errores entre los dos servicios. **No es un mock de la autorización: es la autorización** |
| Vault KV v2 | **Doble explícito** (`FakeKv`) | Reproduce CAS, soft-delete, undelete, destroy, metadata nativa, los tres estados (ausente/borrado/destruido) y el wrapping de un solo uso. **No** demuestra el comportamiento exacto de las políticas HCL ni de una instancia real |
| Login con TOTP | **Doble** (`FakeVault`, código fijo) | Permite probar el flujo de dos pasos sin gastar códigos reales. **El login con un código de verdad es una comprobación manual**, documentada arriba, y no se deduce de estos dobles |

### Qué comprueba cada módulo

| Módulo | Pruebas | Qué cubre |
|---|--:|---|
| `test_catalog.py` | 15 | Creación sin tocar Vault, nombre único y validado, visibilidad por rol, renombrado que conserva historial, esquema compatible e incompatible, límites de campos y profundidad |
| `test_records.py` | 18 | N registros independientes, validación de la tupla, CAS (incluida una carrera real con dos peticiones en vuelo), PUT/PATCH, soft-delete, undelete, destroy, purga, los tres estados, idempotencia |
| `test_gateway_auth.py` | 14 | Sesión inventada y revocada, empleado desactivado, roles retirados, **Vault deniega aunque el rol permita**, credencial interna sin Bearer y al revés, intento de path/montaje/URL libre, operación fuera de la allowlist, revalidación independiente |
| `test_mfa_and_delivery.py` | 13 | Step-up completo, prueba de un solo uso, ligada a operación/recurso/sesión, que no sobrevive al logout, entrega envuelta y plana, wrapping reutilizado y vuelto a pedir |
| `test_lifecycle.py` | 12 | Archivar, restaurar omitiendo lo destruido, purgar, lote acotado, fallo parcial con 409, respuesta perdida → `needs_reconciliation`, bloqueo hasta reconciliar, detección de escrituras externas |
| `test_crawler.py` | 18 | Identidad AppRole única, los dos contratos que no se cruzan, token válido con identidad no registrada, sin política mínima, otro montaje, sin binding, versión fijada vs `latest`, revocación, Vault deniega a la máquina |
| `test_security_surface.py` | 19 | Cero valores y cero hashes en PostgreSQL (recorriendo **cada** columna de texto y JSON), logs sin valores ni tokens, auditoría append-only y esquemas inmutables **comprobados contra la base**, sin DDL, sin `create_all`, OpenAPI sin rutas internas, 503 por dependencia, paginación estable |
| `test_schema_spec.py` | 46 | Unitarias puras del esquema: definición, documento Draft 2020-12 sin `$ref`, validación, `file_reference` como referencia, JSON Merge Patch (RFC 7386) y compatibilidad entre versiones |

**Resultado real: 155 pruebas de la etapa 4 pasan.** Con `--all`, **246**
(las 91 de la etapa 3 siguen pasando sin cambios en sus expectativas).

### Qué NO cubren

- Una instancia de **Vault real**: el cliente KV se sustituye por un doble.
- El **login con un código TOTP real** y el **consumo del crawler con
  credenciales reales**: necesitan una persona y están arriba como
  comprobaciones manuales.
- El comportamiento exacto de las **políticas HCL** en Vault.
- Red, TLS, DNS externo y rendimiento.

---

## Seguridad (etapa 4)

### Lo que se descubrió **durante** esta etapa y obligó a cambiar algo

Todo esto lo encontraron las pruebas o el arranque real, no una revisión a ojo:

| # | Observación | Corrección |
|---|---|---|
| 1 | El ORM declaraba la FK de `created_by`/`actor_user_id` a `employees.users`, que **no está en sus metadatos**: SQLAlchemy abortaba al ordenar las escrituras con `NoReferencedTableError` | Esas columnas se mapean sin FK declarada. La integridad la impone **PostgreSQL** (la migración la crea con `ON DELETE SET NULL`), que es donde debe estar. Compartir una declarativa entre los dos servicios habría resuelto la resolución a cambio de acoplar los mapeos |
| 2 | `find_consumer_by_identity` podía encontrar **varios** consumidores con la misma identidad AppRole y fallaba con `MultipleResultsFound` | `secret_consumers_identity_ux` hace único `(montaje, rol)`. No es comodidad: el servicio no acepta un `consumer_id` del cliente, así que si dos consumidores compartieran rol, elegir «el primero» sería darle a una máquina los permisos de otra |
| 3 | Un `VaultError` construido fuera del cliente KV llegaba **sin sanear** a la respuesta, con lo que un mensaje con un token podía salir al cliente | Se sanea también en la frontera de la pasarela y al reenviar mensajes entre procesos. La prueba que lo detectó inyecta un error con un token dentro |
| 4 | Una operación en `needs_reconciliation` **liberaba el recurso**: se podía escribir encima de una incoherencia conocida | Ese estado ya no libera. Se libera cuando una persona la revisa y la cierra con el script de reconciliación, con código de error propio (`reconciliation_pending`) y el comando en el mensaje |
| 5 | `max_length: 0` se convertía **en silencio** en el tope por defecto, porque `int(raw.get(k) or default)` trata el cero como ausencia | `_int_or` distingue ausente de cero. Un cero enviado a propósito llega a la comprobación de rango y se rechaza |
| 6 | Las peticiones de la colección de Postman que van a **user-mgmt** usaban `{{api_prefix}}`, el de vault-mgmt: habrían construido URL inexistentes | Variable propia `api_prefix_user_mgmt`. **Lo detectó el comprobador de cobertura** del generador, no una lectura del JSON |
| 7 | El generador de la credencial interna abortaba con código 141: `tr < /dev/urandom \| head -c 48` hace que `head` cierre la tubería y `tr` reciba `SIGPIPE`, y con `pipefail` eso tumba el script | Se leen 512 bytes de una vez y se filtran, sin tubería que se cierre a mitad |
| 8 | El primer borrador del script de importación invocaba `python3` **dentro de la imagen de Vault**, que no lo tiene | Reescrito como CLI de Python en el host, con biblioteca estándar: habla con Vault por HTTP y con el catálogo por `psql` |
| 9 | `.dockerignore` excluía `requirements/vault_mgmt*.txt`: el build fallaba al copiarlos | Añadidos a la allowlist del contexto |

### Decisiones y sus límites

- **Un worker y sin reload**, igual que user-mgmt. Las sesiones viven en memoria
  de *user-mgmt*, no de este servicio; aquí lo que vive en memoria es el rate
  limiting.
- **Código en la imagen**, sin volumen persistente de código. Usuario no root
  (`vpg`), `no-new-privileges:true`, runtime sin compiladores.
- **Sin `env_file`**: este proceso no ve `VAULT_UNSEAL_KEY`,
  `VAULT_INITIAL_TOKEN` ni `VAULT_ADMIN_USER_PASS`. Se montan **dos** archivos de
  secreto concretos, no el directorio `secrets/`.
- **El servicio no se autoconcede nada al arrancar**: no habilita montajes KV, no
  escribe políticas, no habilita autenticadores y no siembra datos. Todo eso son
  scripts CLI idempotentes. Un servicio que se autoconcede permisos al arrancar
  es un servicio al que no se le pueden recortar.
- **`depends_on` con `service_started`** para Vault y user-mgmt, no
  `service_healthy`: Vault arranca sellado y user-mgmt puede estar vivo sin estar
  listo. Exigir salud crearía un arranque en cadena imposible de diagnosticar.
- **CORS** con lista explícita y `allow_credentials`. La configuración **rechaza
  al arrancar** un `*` en los orígenes: con credenciales no es compatible, y
  aceptarlo invita a desactivar la comprobación.
- **Sin TLS** entre cliente y API. Aceptable solo porque el puerto se publica en
  `127.0.0.1`, y dicho con claridad: en red local sin HTTPS no hay cifrado en
  tránsito.

### Límites conocidos de esta etapa

- **No hay transacción distribuida** entre PostgreSQL y Vault. Hay fases
  durables, CAS, idempotencia y reconciliación por CLI. No hay colas ni Redis, y
  `202` no se usa porque no hay procesamiento pendiente durable.
- La **serialización de escrituras** durante una transición de colección cubre
  esta API, no Vault. Alguien con permisos puede escribir directamente; se
  detecta comparando el inventario, no se impide.
- **Revocar no revoca lo entregado.** Quitar un binding o archivar una colección
  impide entregas futuras; un wrapping token que ya viaja sigue siendo válido
  hasta su TTL, y lo que el consumidor ya leyó, leído está.
- El **validador de esquema** cubre el subconjunto que este servicio genera, no
  JSON Schema completo. El documento publicado es estándar para poder
  contrastarlo con un validador externo.
- Las **sesiones y las pruebas de MFA** viven en memoria del worker de
  user-mgmt: reiniciarlo las invalida todas.
- El **rate limiting** es en memoria y por proceso. No es una defensa contra
  IDOR: la autorización por objeto se comprueba en cada operación.
- El **desbloqueo de Vault sigue siendo manual**.
- Los **cambios de esquema incompatibles** exigen una migración explícita y
  revisada. Este servicio no reescribe registros en masa, y no se añade un
  migrador automático de valores.
- Esta etapa **no implementa el crawler**: solo su contrato de consumo y un
  cliente CLI de ejemplo con datos ficticios.
