# Etapa 4.6 · Aprovisionamiento automático de consumidores de máquina

Amplía la etapa 4 para que un consumidor de máquina se **registre y aprovisione
desde la API**, con operaciones persistentes que una futura plataforma React +
TypeScript pueda consultar, y con la credencial entregada a un **receptor
configurado** en vez de copiada a mano.

Servicio nuevo: `vault-mgmt-worker`, el mismo contenedor que la API con otro
comando.

> **Lo que esta etapa NO implementa, y no es un olvido.** No hay crawler, ni
> frontend, ni descargas, ni GCP/Kubernetes/Terraform. Se entrega el backend y
> el *contrato* de integración. La entrega se valida con un receptor de pruebas
> aislado (`scripts/vault_mgmt/test_receiver.py`), que demuestra que el contrato
> funciona, **no** que exista un crawler. Por eso `make all` no arranca ningún
> receptor: sin él, la operación se queda en `waiting_receiver`, que es el
> comportamiento correcto.

---

## La solicitud administrativa: 202 y tres campos

```json
{
  "consumer_id": "9f1a77f0-c2a9-4e50-b1d0-e7a45c334c0e",
  "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
  "status": "pending"
}
```

`pending` significa **solicitud guardada**, no entrega completada. En ese momento
no existe ninguna credencial emitida y no hay nada que el receptor pueda usar.

La petición humana **no habla con Vault**: valida, guarda y devuelve 202 con un
`Location`. El trabajo con Vault lo hace el worker leyendo esa misma fila de
PostgreSQL. Dos consecuencias buscadas: un reinicio no pierde nada, y React solo
necesita *solicitar* y *consultar*, sin esperar a Vault en una petición HTTP ni
guardar credenciales.

---

## El ciclo de una emisión

```
pending ──▶ in_progress ──▶ waiting_receiver ──▶ awaiting_ack ──▶ completed
   │            │                  │                  │
   │            │                  │                  └─ el receptor acreditó
   │            │                  │                     su token (lookup real)
   │            │                  └─ identidad lista en Vault.
   │            │                     CERO SecretID emitidos.
   │            └─ el worker prepara montaje, política y rol
   └─ solicitud guardada

cualquiera ──▶ failed | needs_reconciliation
```

**Por qué se para en `waiting_receiver`.** Sin receptor que recoja la credencial,
emitir un SecretID es dejar una credencial viva esperando a un proceso que puede
no existir. Se emite en el `claim`, cuando hay alguien al otro lado.

**Por qué `awaiting_ack` no es `completed`.** Haber entregado la envoltura no
prueba que el receptor pudiera usarla. La operación se cierra cuando acredita el
token que obtuvo, y el servidor lo **comprueba** con `auth/token/lookup` contra
Vault: un `success: true` del cliente no probaría nada.

---

## Contrato público

Prefijo `/vault_mgmt/v1`. **Todas las rutas exigen sesión válida y rol `admin`.**
`Idempotency-Key` opcional en los POST de mutación.

| Método | Ruta | Resultado |
|---|---|---|
| POST | `/vault/consumers` | 202; registra consumidor, receptor, bindings iniciales y operación |
| GET | `/vault/consumers` | 200; lista paginada, sin credenciales |
| GET | `/vault/consumers/{consumer_id}` | 200; estado, última operación y última entrega |
| POST | `/vault/consumers/{consumer_id}/provision` | 202; prepara emisión pendiente |
| PUT | `/vault/consumers/{consumer_id}/bindings` | 200; reemplazo completo del alcance |
| GET | `/vault/consumers/{consumer_id}/bindings` | 200; referencias y versiones autorizadas |
| POST | `/vault/consumers/{consumer_id}/rotate` | 202; rotación controlada |
| POST | `/vault/consumers/{consumer_id}/revoke` | 202; bloqueo de entregas y revocación técnica |
| GET | `/vault/operations/{operation_id}` | 200; estado, fases y error saneado |

Errores: 401, 403, 404, 409, 422, 429 y 503, con el cuerpo uniforme de
`ErrorDetail`.

### Lo que el cuerpo del alta NO acepta

HCL, rutas de Vault, nombre de montaje o de rol, root token y URL del receptor.
El montaje sale de la configuración del servicio y el rol se **deriva** del
nombre del consumidor (`VAULT_MGMT_MANAGED_ROLE_PREFIX` + nombre), así que una
petición no puede apuntar a una identidad ajena. Un campo de más es 422.

### Ninguna respuesta humana lleva credenciales

No hay `role_id`, `secret_id`, token de Vault ni wrapping token en **ningún**
endpoint de este contrato. Lo único que se devuelve de Vault son *accessors*, y
solo en el detalle de una entrega: un accessor identifica una credencial para
poder revocarla y auditarla, **no para usarla**.

React solo solicita y consulta. No guarda credenciales de máquina en
`localStorage` ni en variables `VITE_`.

---

## Entrega al futuro crawler: claim y ack

Dos endpoints internos, fuera del OpenAPI público y protegidos por la credencial
del receptor:

```
POST /internal/v1/crawler/provisioning/claim
POST /internal/v1/crawler/provisioning/ack
```

1. **claim.** El receptor presenta su credencial. El servidor resuelve **desde
   ella** qué consumidor le corresponde, comprueba estado y reserva la
   operación. Si hay emisión esperando, pide a Vault el SecretID con
   **response wrapping** de TTL corto y devuelve `role_id`, el wrapping token,
   su TTL, `consumer_id`, `operation_id` y `delivery_id`. La operación pasa a
   `awaiting_ack`.
2. **El crawler desenvuelve** en Vault (`sys/wrapping/unwrap`, un solo uso) y
   hace `login` con su AppRole. El token se queda en memoria de su runtime y
   nunca llega a React.
3. **ack.** Confirma el `delivery_id` presentando el token obtenido y su
   credencial interna. El servidor hace `lookup` y verifica montaje, rol,
   política **y que el token venga de esa misma entrega**, antes de marcar
   `completed` / `ready`. Después descarta el token: lo que guarda es su
   accessor.

> **Cómo se comprueba que el token es de *esa* entrega.** El `claim` etiqueta el
> SecretID con `consumer_id`, `operation_id`, `delivery_id` y `receiver`, y Vault
> copia esos metadatos al token que sale del login. Sin esa comprobación, un
> token obtenido con la credencial de **otra** entrega del mismo consumidor
> pasaría la verificación de identidad —mismo montaje, mismo rol, misma
> política— y confirmaría una entrega que no es la suya. Esos metadatos son
> además lo que permite reconciliar con precisión: ver más abajo.

### Qué protege a estos endpoints, sin medias verdades

* Lo que los protege es **la credencial del receptor**, comparada en tiempo
  constante y nunca registrada.
* `consumer_id` **no** es una contraseña: es un identificador que aparece en
  respuestas administrativas y en la auditoría. El claim no lo acepta del
  cliente.
* Estar fuera del OpenAPI (`include_in_schema=False`) **no** los vuelve
  inaccesibles: comparten el puerto de la API y responden igual si alguien
  acierta la ruta. Ocultarlos en Swagger es higiene de documentación, no un
  control de acceso.
* No se publican al host en `compose.yaml` y no se llega a ellos con una URL que
  suministre un cliente.
* El transporte es **HTTP** dentro de la red de Docker. La credencial autentica;
  **no cifra**. Para eso haría falta TLS, y en este entorno local no se usa.

### Sin receptor real

La operación se queda en `waiting_receiver` y **no se emite ningún SecretID**.
Un receptor simulado demuestra el contrato en pruebas; no demuestra la
disponibilidad del futuro crawler.

---

## Entrega mediada y consumidores heredados

`secret_consumers.delivery_mode` distingue dos cosas que no son equivalentes:

| Modo | Quién lee KV | Qué acotan los bindings |
|---|---|---|
| `direct` (etapa 4, por CLI) | el token de **la máquina** | lo que **esta API** le entrega |
| `mediated` (etapa 4.6, por API) | el **backend autorizado**, por cuenta de la máquina | lo que la máquina puede obtener, de verdad |

**Para un consumidor `direct`, los bindings y `pinned_version` no son el límite
real.** Su política cubre `secret/data/vpg-managed/*` completo, así que su token
puede leer cualquier registro del prefijo por su cuenta. Decir lo contrario
sería falso.

Para un consumidor `mediated` la política **no incluye lectura de KV**
(`vpg-crawler-managed`: solo `sys/wrapping/unwrap`, `lookup-self` y
`renew-self`). El backend lee la versión que autoriza el binding y la envuelve
para él. Ahí sí el binding es el límite efectivo.

**Migrar un consumidor heredado es una decisión explícita**, no algo que ocurra
solo: hay que estrechar su política en Vault y cambiar su `delivery_mode`. La
API se niega a aprovisionar un consumidor `direct` (409 `legacy_consumer`), y se
niega a tocar un rol fuera del espacio de nombres gestionado (409
`role_not_managed`).

`/integrations/crawler/resolve` sigue funcionando para los dos, autenticado por
token de máquina y bindings, y la respuesta marca con `mediated` cómo se leyó
cada entrega.

---

## Identidades y credenciales

| Credencial | Quién la tiene | Dónde vive | Rota |
|---|---|---|---|
| `api_session` | la persona | memoria del worker de user-mgmt | al caducar o cerrar sesión |
| Credencial de la pasarela | user-mgmt y vault-mgmt | `secrets/vault_mgmt_internal_token` | a mano |
| Credencial del receptor | vault-mgmt y el receptor | `secrets/crawler_receiver_<nombre>` | a mano; `make all` no la rota |
| RoleID | estable por consumidor | solo en Vault | no |
| SecretID | el receptor, un solo uso | solo en Vault; viaja envuelto | `POST .../rotate` |
| Token del aprovisionador | vault-mgmt y su worker | `secrets/VAULT_INITIAL_TOKEN`, solo lectura | fuera de esta etapa |

La persona usa su `api_session` y el MFA que ya existe en el login. Esta
subetapa **no** añade reautenticación por acción para las operaciones de
consumidores: basta sesión válida y rol `admin`. Las reglas de MFA de `destroy`
y `purge` de registros **no cambian**.

### El token del aprovisionador, dicho sin adornos

El aprovisionador necesita un token administrativo de Vault para crear la
AppRole del consumidor y emitir su SecretID. En el **perfil local** se le monta
en solo lectura `secrets/VAULT_INITIAL_TOKEN`.

Ese token puede hacer cualquier cosa en Vault. Lo que lo acota aquí **no es la
ACL, es el código**: `app/vault_mgmt/core/approle_admin.py` construye cada path
a partir del montaje gestionado y de un rol derivado del consumidor, y rechaza
cualquier otro. Esto es una simplificación aceptada de desarrollo y **no** una
configuración de producción.

Lo que sí se mantiene:

* Se monta **solo** en `vault-mgmt-service` y su worker. Ni user-mgmt ni
  PostgreSQL lo reciben, y la clave de unseal no la recibe ningún servicio.
* No se copia a ninguna imagen, no viaja como argumento de ningún proceso, no se
  registra y no se devuelve en ninguna respuesta.
* Si falta, el aprovisionamiento queda **desactivado**, se dice en readiness y
  las solicitudes se quedan en `pending`. El resto del servicio sigue operando.

El proveedor está separado en `app/vault_mgmt/core/vault_auth.py` justamente
para poder sustituirlo por una identidad técnica propia sin tocar ningún
endpoint.

### El SecretID y el script de la etapa 4

`scripts/vault_mgmt/crawler-approle-bootstrap.sh` tenía dos afirmaciones falsas,
corregidas en esta etapa:

* Emitía un SecretID **nuevo en cada ejecución**, también sin
  `--rotate-secret-id`. Llamarlo en cada arranque iba acumulando credenciales
  válidas que nadie controlaba. Ahora, sin argumentos, **no emite ninguno**.
* `--rotate-secret-id` **no invalidaba** los anteriores: solo añadía otro.
  Invalidar exige otra llamada, por su accessor. Ahora lo dice, y
  `--destroy-previous` lo hace.

`make all` **no invoca** ese script: emitir credenciales no es parte de un
arranque.

---

## Rotación y revocación

**Rotación** (`POST .../rotate`), con estrategia explícita en el cuerpo:

* `after_ack` (por omisión): se emite la nueva y la anterior se retira **solo
  cuando el receptor confirma**. Lo que se retira es el **token** anterior, por
  su accessor: su SecretID ya se consumió al entrar, porque es de un solo uso.
  Durante la ventana ese token sigue vivo, y eso evita dejar fuera al crawler
  que ya estaba dentro si el rearranque falla.
* `immediate`: se destruye la anterior al emitir la nueva. Más estricto, con
  ventana de corte.

**Revocación** (`POST .../revoke`, con `confirm` = nombre exacto): destruye los
SecretID del rol, revoca por accessor el token acreditado y borra el rol AppRole.
Además hace dos cosas que no son evidentes y que conviene saber:

* **Supersede cualquier operación viva** del consumidor en vez de chocar con
  ella. Lo contrario convertía un consumidor atascado —por ejemplo, esperando
  para siempre a un receptor que ya no existe— en un consumidor **imposible de
  revocar**, que es justo cuando más falta hace poder hacerlo.
* **Libera su receptor**, que pasa a `disabled`. La unicidad del nombre de un
  receptor es *parcial*, solo sobre los activos: con una unicidad total,
  revocar dejaba el nombre ocupado para siempre y la función era de un solo uso
  por receptor. La fila no se borra, porque las entregas ya hechas apuntan a
  ella y son la única prueba de que se emitió algo.

Después de revocar, la credencial de ese receptor deja de resolver a ningún
consumidor: el `claim` responde 403 `receiver_not_bound`, no `consumer_revoked`.

Dos cosas que conviene no confundir, en los dos casos:

* Destruir un SecretID **no** revoca los tokens que ya salieron de él: viven
  hasta su TTL y se cortan por su accessor.
* Borrar un rol AppRole **no** elimina los tokens ya emitidos ni los secretos
  que el consumidor ya leyó.

Si Vault no está disponible durante una revocación, el consumidor queda
bloqueado en el catálogo y la operación en `needs_reconciliation`, diciendo que
su AppRole sigue viva.

---

## Persistencia y worker

Migración **004** (`sql/004_crawler_provisioning.sql`), sobre el esquema
`vault_mgmt` de la 003:

| Objeto | Para qué |
|---|---|
| `secret_consumers` (+columnas) | `delivery_mode`, `provisioning_state` y los accessors |
| `secret_receivers` | receptor → consumidor, con la **referencia** a su credencial |
| `secret_provisioning_deliveries` | una emisión concreta: estado, accessors e instantes |
| `secret_operations` (+columnas) | `consumer_id`, `request_fingerprint`, `lease_owner`, `leased_until`, `attempts` |

**No se almacenan** SecretID, wrapping tokens, tokens de Vault ni valores de
secretos. Solo accessors, estados, expiraciones e intentos.

Invariantes que impone PostgreSQL, no el código:

* Una sola operación viva por consumidor (`secret_operations_one_active_consumer_ux`).
  Dos aprovisionamientos a la vez emitirían dos SecretID y dejarían uno huérfano.
* Una sola entrega viva por consumidor (`..._one_live_ux`).
* Un receptor por consumidor y un nombre de receptor por consumidor.
* `finished_at` solo en estados terminales.

### El worker

```bash
docker compose logs -f vault-mgmt-worker
```

Un proceso aparte, con la **misma imagen** que la API y el comando
`python -m app.vault_mgmt.worker`. Sin Redis ni Celery: la cola es una tabla.

Reserva trabajo con `SELECT ... FOR UPDATE SKIP LOCKED` y un `leased_until`, y
**cierra la transacción antes de llamar a Vault**. Tres propiedades buscadas:

* Varios workers pueden compartir la cola sin memoria compartida: el que llega
  segundo salta las filas bloqueadas en vez de esperar. Se arranca con uno, pero
  el diseño no obliga a quedarse ahí.
* Un worker que muera no bloquea la cola: su arrendamiento caduca y otro la toma.
* Ninguna conexión de PostgreSQL queda retenida durante un timeout de Vault.

Las sesiones humanas de user-mgmt siguen con su límite de **un worker**: eso es
otra cosa (viven en memoria de *ese* proceso) y esta etapa no lo cambia.

### Idempotencia y reanudación

Misma `Idempotency-Key` con los mismos parámetros devuelve los mismos
identificadores; con parámetros distintos es **409**. La comparación usa una
huella de los parámetros **no sensibles** (nombre, receptor, bindings): nunca de
valores de secretos, donde un hash de baja entropía sería un oráculo.

Ante reinicio se retoman las solicitudes guardadas. Ante respuesta incierta de
Vault **no se repiten escrituras a ciegas**: la envoltura caducada sin consumir
se reconcilia antes de emitir otra cosa.

**Cómo se identifica un SecretID huérfano.** Al envolver, Vault devuelve el
accessor del *wrapping token*, no el del SecretID: ese viaja dentro de la
envoltura y el servicio **no lo ve nunca**. Así que no se puede destruir «por su
accessor» sin más. Se identifica por sus **metadatos**: se listan los accessors
vivos del rol, se consulta cada uno y se destruye el que lleva el `delivery_id`
de la entrega caducada. Si alguno no lleva etiqueta, no se toca: pudo emitirlo
otra cosa, y destruir a ciegas una credencial ajena es peor que dejar una
huérfana.

### Tres cosas que sólo se vieron ejecutándolo contra Vault

Las pruebas de esta etapa pasaban y el recorrido contra Vault real falló. Las
tres causas eran suposiciones sobre la API de Vault que el doble no contradecía,
y conviene dejarlas escritas porque son fáciles de repetir:

1. **`metadata` es un *string*, no un objeto.** El campo de
   `auth/<montaje>/role/<rol>/secret-id` espera un JSON ya serializado.
   Enviarle un mapa responde `400 … expected type 'string', got unconvertible
   type 'map[string]interface {}'`, y el `claim` devolvía 503. La serialización
   vive ahora en el cliente, y hay una prueba del **cuerpo que sale por el
   cable** en `tests/vault_mgmt/test_approle_admin_wire.py`.
2. **El `lookup` de un token no expone el accessor de su SecretID.** `meta` trae
   lo que se le puso (`consumer_id`, `delivery_id`, `operation_id`, `receiver`)
   más `role_name`, y nada más. El catálogo ya no intenta registrarlo, y en
   cambio usa el `delivery_id` para la comprobación del punto 3 de arriba.
3. **En una rotación, lo que sobrevive es el *token*, no el SecretID.** Con
   `secret_id_num_uses=1` el SecretID queda consumido en el login, así que
   «retirar la credencial anterior» significa **revocar el token anterior por su
   accessor**. Destruir un SecretID ya consumido no hace nada.

De ahí la regla general de esta etapa: **un doble no valida a quien reemplaza.**
`FakeAppRole` prueba muy bien la máquina de estados y no prueba el formato de
hilo; para eso está la prueba contra el cliente real y un transporte falso, y
para lo demás el recorrido contra Vault.

**No se promete *exactamente una vez*.** Token, SecretID y envoltura tienen TTL
distintos. El SecretID es de un solo uso (`VAULT_MGMT_CRAWLER_SECRET_ID_NUM_USES=1`):
un receptor que lo pierda al reiniciar necesita **reaprovisionarse**, no
reutilizarlo, y el token que ya obtuvo se renueva hasta su `token_max_ttl`.

---

## Arranque con `make all`

```bash
make help      # resumen de los objetivos
make all       # arranque completo, incluida la primera inicialización
```

Desde esta etapa, `make all` **inicializa Vault si el volumen es nuevo**. El
límite no se ha relajado, se ha hecho explícito:

* Se inicializa **solo** cuando Vault dice que no está inicializado y en
  `secrets/` no hay credenciales a medias.
* Un volumen **ya inicializado no se reinicializa nunca**: sería destructivo y
  no recuperaría la Unseal Key, que Vault no vuelve a mostrar.
* Si está inicializado y falta su Unseal Key, la pide una vez, la **prueba**
  desbloqueando y solo entonces la guarda. Sin terminal interactiva, dice cómo
  suministrarla a mano.

`make config` sigue existiendo como **alias compatible**: hace exactamente esa
preparación de Vault, sin arrancar el resto.

Secuencia: validar herramientas → resolver imágenes → arrancar PostgreSQL y
Vault → inicializar solo si hace falta → desbloquear con el archivo → aplicar
migraciones pendientes → verificar administrador → **generar la credencial de
cada receptor si falta** → arrancar las dos APIs y el worker → comprobar salud.

Lo que `make all` **no** hace: no rota credenciales que ya valen (ni el SecretID
de la AppRole de user-mgmt, ni la de la pasarela, ni la de un receptor, ni la
del crawler), no crea el administrador, no siembra datos y no reconstruye
imágenes sin cambios. **Reiniciar infraestructura no es rotar nada.**

`make down` conserva volúmenes y secretos. `make purge` elimina solo recursos
del proyecto y las credenciales generadas vinculadas a los volúmenes que
desaparecen, con confirmación; las credenciales de receptor se conservan
mientras exista el volumen de PostgreSQL, porque el consumidor al que sirven
sigue en el catálogo.

### Si falta el administrador

La precondición de la etapa 3 se mantiene: `make all` prepara lo que puede y
**aborta antes de iniciar las APIs** señalando el alta pendiente, con los
scripts exactos. No inventa cuentas ni contraseñas. El arranque completo con un
comando aplica **una vez satisfecha esa preparación**, no antes.

Clonar el repositorio **no** transmite los secretos: `secrets/` está fuera de
Git y del contexto de build. Lo que falta hay que generarlo o suministrarlo.

---

## Comprobaciones reproducibles (etapa 4.6)

### 1. Arranque y salud

```bash
make all
curl -s http://127.0.0.1:8001/health/ready | python -m json.tool
```

`checks` son las comprobaciones que **condicionan** `ready`. `capabilities` es
distinto y está separado a propósito: `consumer_provisioning` y
`receivers_configured` **no bloquean**. Si falta el token del aprovisionador, el
CRUD de secretos sigue atendiendo y las altas se guardan en `pending`.

### 2. No interactivas

```bash
bash scripts/vault_mgmt/smoke-api.sh
```

Comprueba, entre otras cosas, que el OpenAPI público publica 25 rutas y 35
operaciones, que no hay rutas `/internal` en él, que el canal de
aprovisionamiento exige la credencial del receptor (401 sin ella y con una
inválida) y que el worker está en marcha. **No reclama ninguna emisión**:
hacerlo emitiría una credencial de verdad, y un smoke no debe tener ese efecto.

### 3. 🖐 INTERACTIVO — Recorrido completo

```bash
bash scripts/vault_mgmt/provisioning-walkthrough.sh
```

**Es reejecutable.** Un receptor sirve a un solo consumidor, así que si quedó
ocupado por una ejecución anterior de este mismo recorrido (nombres
`crawler-demo-*`), lo revoca primero y lo dice. Si lo ocupa un consumidor que
**no** es un residuo suyo, se para y explica qué hacer: no toca lo que no ha
creado. Con `--receiver <nombre>` se usa otro receptor configurado.

> Dos detalles del propio script que costaron una ejecución cada uno, por si se
> toca: las cabeceras con credencial y la `Idempotency-Key` son de **un solo
> uso**. Dejarlas puestas entre peticiones hacía que la revocación de la
> limpieza se quedara con la clave del alta (409 `idempotency_key_reused` en el
> reintento), y que la credencial del receptor acabara viajando a Vault en el
> login de AppRole —porque bash restaura la asignación de prefijo
> (`R="" … api`) al volver de una función—. El Bearer humano sí persiste: es la
> sesión.

Pide **un** código TOTP. Recorre salud y capacidades, los 401 del canal interno,
login, alta (202 y tres campos), idempotencia (misma clave igual → mismos IDs;
misma clave distinta → 409), el paso del worker a `waiting_receiver` sin emitir
nada, claim, unwrap, login AppRole, ack hasta `completed`, segundo claim que no
emite otra credencial, rotación `after_ack` y revocación. Con `--keep` no revoca
al final.

Resultado real obtenido: el recorrido completo pasa contra Vault real, incluidas
la rotación y la revocación, y el 403 `receiver_not_bound` del claim posterior.

### 4. Receptor de pruebas sin TOTP

Una vez que el consumidor existe y tiene una emisión pendiente:

```bash
python scripts/vault_mgmt/test_receiver.py
python scripts/vault_mgmt/test_receiver.py --no-ack   # deja awaiting_ack
```

Hace lo que hará el crawler en su arranque, y nada más. Con `--no-ack` se
comprueba que sin confirmación la operación **no** llega a `completed`.

### 5. Segundo `make all` sin cambios

```bash
make all
```

Resultado esperado, verificado: omite las migraciones (9 tablas ya existen), el
AppRole de user-mgmt, la credencial de la pasarela y la del receptor («no se
rota una credencial valida»), y no reconstruye las imágenes («huella de entradas
e id de imagen coinciden»).

### 6. Persistencia tras reinicio

```bash
docker compose restart vault-mgmt-worker vault-mgmt-service
curl -s -H "Authorization: Bearer <api_session>" \
  http://127.0.0.1:8001/vault_mgmt/v1/vault/operations/<operation_id> \
  | python -m json.tool
```

La operación sigue donde estaba: vive en PostgreSQL, no en memoria.

### 7. Pruebas unitarias

```bash
bash scripts/vault_mgmt/run-tests.sh tests/vault_mgmt/test_provisioning.py
bash scripts/vault_mgmt/run-tests.sh tests/vault_mgmt/test_approle_admin_wire.py
bash scripts/vault_mgmt/run-tests.sh --all
```

Resultado real obtenido: **56 pruebas** en las dos suites de esta etapa (41 del
aprovisionamiento y 15 del cliente de AppRole contra un transporte falso) y
**302** en total (etapas 3, 4 y 4.6), todas en verde.

Qué demuestran, y qué no:

* **PostgreSQL es real.** Los invariantes de esta etapa son índices parciales y
  CHECK; en un doble no existen.
* **La autorización es real.** La pasarela interna de user-mgmt corre en el
  proceso de pruebas y el rol `admin` se relee de PostgreSQL en cada petición.
* **Vault es un doble explícito** (`tests/vault_mgmt/fakes_provisioning.py`),
  con el comportamiento del que dependen las garantías: la envoltura es de un
  solo uso, el SecretID solo sale envuelto, el accessor que Vault devuelve al
  envolver es el del *wrapping token* y no el del SecretID, el SecretID se
  consume en el login, destruirlo no revoca tokens ya emitidos, y la guarda de
  alcance rechaza un rol ajeno.
* **El cliente de AppRole se prueba aparte**, contra un `httpx.MockTransport`
  (`tests/vault_mgmt/test_approle_admin_wire.py`), afirmando sobre el cuerpo que
  sale por el cable. Es el único sitio donde se comprueba el formato de hilo:
  un doble del cliente no puede validar al cliente.
* **El worker se invoca en línea**: se prueba la máquina de estados, no el bucle
  de sondeo.

Lo que **no** demuestran: Vault de verdad, los TTL reales, el efecto de las
políticas HCL y un crawler real. Para eso están los recorridos de arriba.

Escenarios cubiertos: idempotencia (clave igual y clave reutilizada), receptor
ausente y desconocido, credencial interna ausente e inválida, `consumer_id` como
credencial rechazado, `api_session` rechazada en el canal interno, identidad de
Vault incorrecta en el `ack`, envoltura caducada y reconciliada, claim repetido,
rotación en sus dos estrategias, revocación, reserva por dos workers, y ausencia
de credenciales en respuestas humanas.

---

## Evolución a GCP, fuera de esta etapa

El sellado migrará a **GCP Cloud KMS** para auto-unseal. **No se implementa
ahora**, y conviene no confundir qué resuelve:

* Auto-unseal **sustituye el desbloqueo con clave Shamir local**. Nada más.
* **No** proporciona ni recupera `VAULT_INITIAL_TOKEN`, y **no** autentica
  servicios. La autenticación en ejecución se migrará por separado a identidades
  técnicas, sustituyendo el proveedor de
  `app/vault_mgmt/core/vault_auth.py` sin tocar endpoints.
* Las **recovery keys** de un Vault con auto-unseal **no son** unseal keys ni
  tokens: sirven para operaciones de recuperación, no para desbloquear ni para
  autenticarse.

---

## Seguridad (etapa 4.6)

### Decisiones y sus límites

| Decisión | Qué cuesta |
|---|---|
| Token administrativo por archivo para el aprovisionador | Puede todo en Vault; lo acota el código, no la ACL. Perfil local únicamente |
| Credencial de receptor por archivo, sin mTLS | Autentica, no cifra. HTTP interno en Docker |
| Endpoints internos en el puerto público | Protegidos por credencial; ocultarlos en Swagger no es un control |
| SecretID de un solo uso | Un receptor que lo pierda necesita reaprovisionarse |
| `after_ack` por omisión en la rotación | Ventana con dos credenciales válidas, a cambio de no dejar al crawler fuera |
| Entrega mediada para los nuevos | El backend lee por cuenta de la máquina: es él quien debe estar bien acotado |

### Límites conocidos

* **HTTP en loopback y en la red de Docker no cifra el tránsito.** Vault
  protege el almacenamiento; HTTPS protegería el transporte, y aquí no se usa.
* El rate limiting del canal interno es en memoria y por proceso.
* No hay transacción distribuida entre PostgreSQL y Vault. Un fallo parcial deja
  la operación en `needs_reconciliation` con su `operation_id`.
* Un consumidor `direct` puede leer todo el prefijo gestionado con su propio
  token. Sus bindings no son el límite real, y migrarlo es manual.
* `make config`/`make all` guardan la Unseal Key y el token inicial en
  `secrets/`: quien tenga esos archivos tiene todos los secretos, y el sellado
  deja de proteger en este equipo. Bórralos para volver al desbloqueo manual.
