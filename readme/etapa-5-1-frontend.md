# Etapa 5.1 · Frontend de autenticación (React + TypeScript)

El primer frontend de VPG Contadores: **solo acceso**. Login de dos pasos
delegado a Vault, verificación TOTP, sesión actual, cierre de sesión y la
inscripción del segundo factor. Servido por Nginx desde la misma imagen que lo
construye, dentro de `network-service`, en el mismo origen que la API.

| | |
|---|---|
| Servicio | `frontend-service` (contenedor `vpg-frontend`) |
| Imagen | `vpg/frontend-server:0.5.1`, etapa `frontend-server` del [Dockerfile](../Dockerfile) |
| URL por omisión | `http://localhost:8080` (loopback) |
| Backend que consume | `user-mgmt-service`, prefijo `/user_mgmt/v1` |
| Código | [`frontend/`](../frontend) |
| Runtime de Nginx | [`docker/frontend/`](../docker/frontend) |

## Qué entrega esta etapa, y qué no

**Entrega**: las cuatro operaciones de autenticación de user-mgmt
(`login`, `mfa/verify`, `logout`, `me`), el aviso del estado del segundo factor,
la **inscripción inicial del TOTP propio** y una pantalla administrativa mínima
para inscribir o reiniciar el TOTP de otra persona.

**No entrega**, y no lo insinúa en ninguna pantalla: CRUD de empleados, secretos,
colecciones, consumidores, crawler, OIDC, autenticación local, Kubernetes,
Terraform ni GCP. La pantalla de inicio es una bienvenida con la identidad y el
estado de la sesión, no un panel de módulos futuros.

Los endpoints internos de máquina (`/internal/...`) **no se exponen** por el
proxy: están fuera del único prefijo que se reenvía, y una petición a ellos
recibe un 404 del propio frontend.

---

## 1. Requisitos y arranque

Los mismos que el resto del proyecto, sin añadir nada al equipo:

* Windows con **Docker Desktop** (backend WSL 2) en ejecución.
* **Git Bash** (Bash 4+ y coreutils) y GNU Make 4.0 o posterior.
* **No hace falta Node ni npm instalados.** El build, la comprobación de tipos,
  el lint y las pruebas se ejecutan en contenedores. Si hace falta tocar
  dependencias, `scripts/frontend/npm.sh` ejecuta npm en la misma versión de
  Node que usa la imagen.

```bash
make all
```

El frontend es el **paso 10 de 11**: va después de las dos APIs y del worker,
porque un frontend sin nada a lo que reenviar no aporta diagnóstico. El paso
valida alcance, bind, puertos y material TLS **antes** de publicar nada,
construye la imagen solo si cambiaron sus entradas, levanta el servicio, espera
a que su propio `/healthz` responda y comprueba que resuelve `user-mgmt-service`
por DNS interno.

Salida real de ese paso en un arranque en modo HTTP local:

```text
-- 10/11 Frontend: alcance, TLS, publicacion y salud
   OK        frontend: alcance 'local', HTTPS false, bind 127.0.0.1 y puertos 8080/8443 son una combinacion admitida
   OMITIR    frontend-service: vpg/frontend-server:0.5.1 al dia (huella de entradas e id de imagen coinciden)
   EJECUTAR  docker compose up -d --no-build frontend-service
   OK        frontend-service healthy: su escucha interna de salud responde, y no finge la de user-mgmt
   OK        frontend publicado en http://127.0.0.1:8080 (/healthz responde 200)
   OK        frontend-service resuelve por DNS interno: user-mgmt-service
```

Una segunda ejecución de `make all` **no reconstruye** la imagen (la huella de
entradas y el id de imagen coinciden), **no rota** ningún certificado y **no
toca** MFA ni datos.

### Comprobaciones sueltas

```bash
docker compose config --quiet                       # la configuracion es valida
docker compose ps
docker compose logs --tail 30 frontend-service      # incluye el modo elegido
curl -s http://127.0.0.1:8080/healthz
```

El `/healthz` del frontend comprueba **el frontend**: que Nginx responde con su
configuración cargada. No consulta a user-mgmt a propósito: fingir aquí la salud
del backend solo serviría para que un backend caído pareciera sano. Para eso
está `/health/ready` de cada API.

---

## 2. El contrato con user-mgmt

Rutas relativas al prefijo `/user_mgmt/v1`. El navegador llama al **mismo
origen** con `/api` delante, y Nginx reescribe ese prefijo.

| Método | Ruta | Sesión | Qué devuelve |
|---|---|---|---|
| POST | `/auth/login` | no | Desafío MFA. 200, 401, 403, 422, 429, 503 |
| POST | `/auth/mfa/verify` | no | Sesión API tras un TOTP válido. 200, 401, 403, 422, 429, 503 |
| POST | `/auth/enrollment/totp` | no | URI `otpauth` propio (ampliación 5.1). 200, 401, 403, 409, 422, 429, 503 |
| POST | `/auth/logout` | sí | 204 sin cuerpo, o 401 |
| GET | `/auth/me` | sí | Principal actual. 200 o 401 |
| GET | `/user/{user_id}` | sí (admin) | Detalle del empleado, con `vault_link` |
| POST | `/user/{user_id}/vault/provision` | sí (admin) | `EnrollmentOut`, URI una sola vez |
| POST | `/user/{user_id}/mfa/reset` | sí (admin + MFA reciente) | `EnrollmentOut`, URI una sola vez |

### Correspondencia DTO backend ↔ tipos TypeScript

| Esquema Pydantic | Tipo TypeScript | Notas |
|---|---|---|
| `LoginRequest` | `LoginRequest` | `{username, password}`. El `username` se normaliza a minúsculas en los dos lados |
| `LoginChallenge` | `LoginChallenge` | `totp_status` y `enrollment_id` son opcionales (ampliación 5.1) |
| `MfaVerifyRequest` | `MfaVerifyRequest` | `code` es **string**: un número perdería los ceros iniciales |
| `SessionOut` | `SessionOut` | `api_session` es opaco; no es JWT y no se descodifica |
| `SelfEnrollmentRequest` | `SelfEnrollmentRequest` | solo `enrollment_id` |
| `SelfEnrollmentOut` | `SelfEnrollmentOut` | `totp_enrollment_uri` siempre presente si hay 200 |
| `EnrollmentOut` | `EnrollmentOut` | `totp_enrollment_uri` **puede venir nulo**: el tipo lo admite y la pantalla no inventa un QR |
| `VaultLinkOut` | `VaultLink` | estado histórico y fechas; nunca semillas |
| `UserOut` | `UserDetail` | recortado a lo que se muestra: esta etapa no hace CRUD |
| `VaultProvisionRequest` | `ProvisionRequest` | solo `initial_password` es obligatorio |
| `MfaResetRequest` | `MfaResetRequest` | `confirm: "RESET"` y `reason` |
| `ErrorDetail` | `ApiErrorBody` / `ApiError` | `{code, message, request_id, context}` |
| `GET /auth/me` | `Principal` | **ver abajo** |

**Contradicción detectada y declarada**: `GET /auth/me` está implementado con
`response_model=dict`, así que su OpenAPI no describe ningún campo. El tipo
`Principal` se escribió leyendo [app/routers/auth.py](../app/routers/auth.py),
no el esquema, y por eso `toPrincipal()` valida cada campo antes de usarlo.
[`src/test/contract.test.ts`](../frontend/src/test/contract.test.ts) fija esa
limitación: si algún día se tipa la respuesta, esa prueba falla y avisa de que
hay que sustituir el tipo escrito a mano por el esquema real.

Las pruebas de contrato no comparan contra un contrato copiado a mano: leen el
OpenAPI **capturado del servicio en marcha**
(`frontend/src/test/openapi.user-mgmt.json`, que regenera
`scripts/frontend/refresh-openapi.sh`).

### La ampliación aditiva de esta etapa

El enunciado pide el aviso de `pending` **antes** del MFA, y los cuatro
endpoints de auth no exponían el estado. La ampliación es la mínima posible y
no cambia nada de lo anterior:

1. **`LoginChallenge` gana dos campos opcionales**, resueltos *después* de que
   Vault acepte la contraseña y de comprobar el vínculo en PostgreSQL:
   * `totp_status`: el estado **histórico** del enrolamiento. Nulo si el
     empleado no tiene vínculo registrado.
   * `enrollment_id`: una autorización de **un solo uso** para inscribir el
     TOTP propio. Solo aparece si el estado es `pending` o `reset_required`.
2. **`POST /auth/enrollment/totp`**: consume ese `enrollment_id` y devuelve el
   URI `otpauth` de **su propia** entidad, con `Cache-Control: no-store`.

Lo que **no** cambia: sigue sin haber sesión en el paso 1, el MFA se sigue
exigiendo, los códigos de error son los mismos y no hay ninguna consulta pública
por `username` que exponga el estado sin contraseña.

Un cliente que ignore los dos campos nuevos se comporta exactamente como antes.

---

## 3. Inscripción inicial del TOTP del administrador

El caso que esto resuelve: una persona ya registrada en PostgreSQL y en Vault
que **todavía no tiene su autenticador**, y que por tanto no puede completar el
MFA ni, en consecuencia, abrir ninguna pantalla donde pedir su inscripción.

### Contrato

`POST /user_mgmt/v1/auth/enrollment/totp` → `{"enrollment_id": "<autorización>"}`

Validaciones, en este orden
([app/services/auth.py](../app/services/auth.py)):

| Comprobación | Si falla |
|---|---|
| La autorización existe, no se ha usado y no ha caducado | 401 `enrollment_expired` |
| El empleado sigue existiendo y activo | 403 `inactive_user` |
| Sigue teniendo vínculo con Vault registrado | 403 `not_linked` |
| La entidad del vínculo es la misma de la autorización | 403 `entity_mismatch` |
| El estado sigue siendo `pending` o `reset_required` | 409 `enrollment_not_allowed` |
| Vault genera una semilla nueva para esa entidad | 409 `totp_already_enrolled` |
| Vault está accesible y desbloqueado | 503 |

Tres propiedades que conviene leer juntas:

* **La autorización no es una sesión.** No lleva token de Vault, no vale como
  `Authorization: Bearer` y no habilita ninguna operación administrativa. Hay
  pruebas que lo comprueban enviándola como Bearer a `/auth/me` y a
  `/user/{id}/vault/provision`: las dos responden 401.
* **`totp_status != confirmed` no autoriza generar ni reemplazar la semilla.**
  El estado solo sirve para no ofrecer esto a quien ya tiene un login MFA
  confirmado. Quien decide si se puede generar es **Vault**, que rechaza un
  `admin-generate` sobre una entidad que ya tiene semilla; eso se traduce en
  409 y **nunca** en una destrucción. El flujo no llama a `admin-destroy`
  jamás.
* **La sesión API se entrega solo en `/auth/mfa/verify`**, con el código
  validado contra Vault. Inscribirse no abre sesión: hay una prueba que
  inscribe y después comprueba que un código incorrecto sigue dando 401.

### Qué pasa en el primer arranque de verdad

`vpg-auth-bootstrap` (etapa 1) **ya genera** la semilla del administrador
inicial y la imprime una sola vez en la terminal. Consecuencia práctica, dicha
sin rodeos:

* Si esa inscripción se escaneó, el administrador entra por el flujo normal y
  esta pantalla no le hace falta.
* Si **se perdió**, el flujo de inscripción propia responde **409**: la entidad
  ya tiene semilla y aquí no se regenera en silencio. La salida documentada es
  el reset explícito:

  ```bash
  docker compose exec vault-service vpg-auth-bootstrap --reset-totp
  ```

  Esa alternativa por CLI se conserva a propósito, y la pantalla lo dice con
  esas palabras en vez de ofrecer un botón que no podría funcionar.
* Donde la inscripción propia **sí** funciona es cuando la entidad existe sin
  semilla: un empleado dado de alta y vinculado sin pasar por `provision`, o una
  entidad cuya semilla se destruyó. En esos casos devuelve el URI una vez.

La semilla no se regenera automáticamente al iniciar el sistema, ni al abrir la
pantalla, ni al repetir `make all`: ninguno de esos caminos llama a
`admin-generate`. Lo único que lo llama es `provision`, `mfa/reset` y este
endpoint, y los tres exigen una acción explícita.

---

## 4. Pantallas, estado y lo que cada una promete

### Máquina de estados

Está escrita aparte, sin React, en
[`frontend/src/features/auth/state/reducer.ts`](../frontend/src/features/auth/state/reducer.ts):

```text
anonymous ──login()──▶ logging_in ──desafío──▶ mfa_required ──código──▶ verifying_mfa
     ▲                      │                      ▲                        │
     └──── error ───────────┘                      └──── código inválido ───┤
     ▲                                                                      │
     └──── logout / sesión perdida ◀── logging_out ◀── authenticated ◀───────┘
```

Dos invariantes los hace cumplir el reducer, no las pantallas:

* **no hay sesión antes de `authenticated`**: un desafío válido no es una
  sesión, y validar la contraseña no autentica a nadie;
* **una operación en curso no se repite**: `LOGIN_START` en `logging_in` y
  `MFA_START` en `verifying_mfa` se ignoran, así que ni un doble clic ni el
  doble efecto de `StrictMode` lanzan dos peticiones.

Además, **ninguna** de las operaciones sale de un `useEffect`: todas vienen de
un envío explícito. `StrictMode` queda activado precisamente para que, si
alguien mueve una a un efecto, se vea duplicada en las pruebas.

### `/login`

Usuario y contraseña, envío explícito, errores por campo, mostrar u ocultar la
contraseña, estado de carga. Con un desafío válido se descarta la contraseña del
formulario y se navega a `/mfa`. No se declara a nadie autenticado.

Un **403 con código `mfa_not_enforced`** (Vault emitió token solo con la
contraseña) se trata como lo que es: un fallo de configuración del
*enforcement*. Se muestra un error de configuración, **se bloquea el formulario**
y ese token no se interpreta como sesión en ningún punto.

### `/mfa`

Código de seis dígitos en **un solo campo**, como `string` para conservar los
ceros iniciales, con `inputMode="numeric"` y `autocomplete="one-time-code"` (el
móvil ofrece el código del portapapeles), pegado tolerante a espacios y envío
único con el botón bloqueado mientras valida.

Ni se genera el TOTP en React, ni se envía dígito a dígito. El plazo se presenta
como **aproximado**: el contrato expone `expires_in_seconds`, un plazo relativo,
y no publica la hora del servidor; inventar precisión sería peor que no darla.

### `/inicio`

Bienvenida, identidad, roles, políticas de Vault, caducidad de la sesión,
antigüedad del MFA y cerrar sesión. El principal viene de `/auth/me`, no de la
respuesta del login.

El cierre llama al backend y borra el estado local de inmediato. Distingue tres
desenlaces, y no promete lo que no sabe:

| Respuesta | Lo que se dice |
|---|---|
| 204 | «el servidor la eliminó y revocó su token de Vault» |
| 401 | «la sesión ya no existía en el servidor» (sin parsear cuerpo) |
| red caída | «se ha borrado la sesión en este navegador, pero no se ha podido confirmar la revocación: el token de Vault seguirá vivo hasta su TTL» |

### Sesión en memoria

La sesión y el desafío viven **solo en memoria**. Recargar la página exige un
login nuevo, y eso es correcto aquí: las sesiones de user-mgmt viven en la
memoria de un único worker y reiniciarlo las invalida de todas formas. No hay
`localStorage`, ni `sessionStorage`, ni IndexedDB, ni cookie de sesión, ni
refresh token, ni Redis, ni BFF para disimularlo. Hay una regla de ESLint que
prohíbe esos accesos y una comprobación en las pruebas que falla si algo escribe
en el almacenamiento del navegador.

Las rutas protegidas mejoran la navegación (evitan aterrizar en una pantalla sin
sesión) y nada más: **autoriza el backend**, que vuelve a comprobar sesión, rol
y permiso por objeto en cada petición.

---

## 5. El aviso de `pending` y el QR

Los cuatro estados, tal como los documenta la etapa 3, con el texto que se
muestra:

| Estado | Qué se muestra |
|---|---|
| `pending` | El aviso completo del enunciado: *«Tu autenticación TOTP está pendiente de confirmación. Si aún no la configuraste, abre Google Authenticator en tu celular y escanea el código QR de inscripción que te proporcione el responsable. Si ya la configuraste, introduce el código de seis dígitos de la aplicación.»* El campo del código sigue disponible |
| `confirmed` | Ningún aviso de pendiente. El MFA se sigue exigiendo |
| `reset_required` | Hay una semilla nueva sin confirmar; la anterior ya no sirve |
| `disabled` | No se permite continuar como si el MFA estuviera activo |
| sin estado | Instrucción general y se **declara la limitación**: «el servicio no ha informado el estado de tu inscripción en esta respuesta» |

El QR se muestra **solo cuando existe un URI `otpauth` autorizado entregado por
el backend**. Si no hay URI:

> El QR de inscripción no está disponible. Solicita al administrador la
> configuración de tu autenticador.

…junto con la opción de introducir el código si la inscripción ya existe. **No**
se dibuja un QR ficticio, ni se sustituye por `challenge_id`, `username`, un
UUID o la URL del sitio: si lo recibido no empieza por `otpauth://totp/`, el
componente dice que la respuesta no es utilizable y no dibuja nada.

El QR se renderiza con `QRCodeSVG` de `qrcode.react`, **local**, sin ningún
servicio externo de imágenes. Se dibuja la cadena **exacta** del backend, así
que issuer, algoritmo, dígitos y periodo son los que generó Vault; al lado se
muestran esos parámetros como texto, leídos del propio URI sin recomponerlo.

El URI y su QR viven **solo en la memoria del componente**: llegan por props,
no se guardan en estado global, ni en el almacenamiento del navegador, ni en la
URL, ni en el historial, ni en ningún log. Se eliminan al cerrar, al cambiar de
usuario, al desmontar y al vencer el tiempo local de visualización (180 s). Ese
tiempo **oculta la pantalla y nada más**: no caduca la semilla en Vault, y el
texto lo dice así. No hay descarga, ni exportación, ni copia automática; la
configuración manual existe como revelación explícita, dentro de un
`<details>` cerrado, con la misma protección.

---

## 6. `/configuracion-totp`: la herramienta administrativa

Protegida para `admin`. Recibe el **UUID** del empleado objetivo; esta etapa no
implementa búsqueda de empleados, y una caja de búsqueda inventada llamaría a
rutas que no existen.

| Acción | Endpoint real | Exigencias |
|---|---|---|
| Consultar estado | `GET /user/{id}` | Solo lectura: no genera, no devuelve y no reinicia semillas |
| Aprovisionar e inscribir | `POST /user/{id}/vault/provision` | Rol admin y contraseña inicial. Entrega el URI **una vez** |
| Reiniciar el segundo factor | `POST /user/{id}/mfa/reset` | Rol admin, **MFA reciente** y escribir `RESET` a mano |

Nada se dispara al abrir la pantalla, al recibir `pending` ni al fallar un
código: las tres salen de un envío explícito. `pending` **no autoriza un reset**
por sí mismo, y el texto de la pantalla lo dice.

Errores que la pantalla distingue de verdad: 401 (devuelve al acceso), 403
`stale_mfa` (explica que hace falta volver a entrar), 404, **409
`partial_operation`** (muestra el `operation_id` y cómo reconciliarlo, sin
emitir otra semilla), 422 con campo y motivo, 429 con `Retry-After` y 503.

Un empleado o un manager **no** entran, aunque conozcan la ruta: el servidor
rechazaría igualmente estas operaciones, y aquí solo se evita el viaje. Hay
pruebas para los tres roles.

El administrador presenta el QR a su titular por el procedimiento local
documentado (pantalla a pantalla, en persona). Un usuario todavía sin MFA **no**
accede a esta pantalla solo por estar `pending`: hace falta sesión y rol admin.
El administrador inicial se inscribe por el flujo restringido de la sección 3, y
la vía por CLI (`vpg-auth-bootstrap --reset-totp`) se conserva documentada.

El QR no se puede volver a pedir con un GET ni reconstruir si se perdió el URI.
Si la persona ya fue provisionada y no tiene la inscripción, hace falta un reset
administrativo explícito. **No se promete recuperación de la semilla.**

---

## 7. Cabeceras de seguridad y CSP

Las sirve Nginx, con `always` para que salgan **también en las respuestas de
error**:

| Cabecera | Valor |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Cache-Control` | `no-store` en todo `/api` (incluidos sus errores); `no-cache` en `index.html` y rutas de interfaz; `public, max-age=31536000, immutable` en `/assets/` |

Tres detalles que costaron una decisión cada uno:

1. **La CSP no lleva `unsafe-inline` en ningún directiva**, y eso obliga a dos
   cosas en el código: Vite se construye con `modulePreload.polyfill: false`
   (con el valor por omisión inyecta un script **inline** en `index.html`), y en
   el código TSX no hay ni un `style={{ ... }}`, porque `style-src` también
   cubre los atributos `style`. El QR es un SVG en línea generado por la
   librería local, así que tampoco hace falta `data:` en `img-src`.
2. **Las cabeceras se incluyen dentro de cada `location`**, no una vez en el
   `server`. En Nginx, un `add_header` en una `location` **reemplaza** las
   heredadas en vez de sumarse: con una sola `location` que añada algo propio se
   perderían todas las de arriba.
3. **La `Cache-Control` del upstream se oculta antes de añadir la propia**
   (`proxy_hide_header`), para no acabar con dos cabeceras: la API ya manda
   `no-store` en login, MFA, inscripción y reset. Hay una comprobación que
   cuenta las apariciones y falla si aparece dos veces.

**HSTS está deshabilitado** en esta fase, también en modo HTTPS, y
`upgrade-insecure-requests` no se activa en ningún modo. Es una política que el
navegador recuerda durante meses: activarla es una decisión aparte, con su
propio nombre de dominio y su propio plazo.

Sin service worker, así que no hay nada que pueda cachear una respuesta
sensible por su cuenta.

### Comprobarlas

```bash
bash scripts/frontend/check-headers.sh
bash scripts/frontend/check-headers.sh --cacert "$(mkcert -CAROOT)/rootCA.pem"
```

El guion lee el modo real de `.env` y comprueba el documento, una ruta profunda,
un asset con hash, el 404 propio del frontend, el login **y su respuesta de
error**, la inscripción, la ausencia de HSTS y, en modo HTTPS, la redirección y
la versión de TLS negociada. Resultado real en modo HTTP local:

```text
== Cabeceras de http://localhost:8080  (modo HTTPS: false)
-- 1. Documento (/)
   OK     documento      Content-Security-Policy
   OK     documento      X-Content-Type-Options
   OK     documento      Referrer-Policy
   OK     documento      Permissions-Policy
   OK     documento revalida    Cache-Control
   OK     sin HSTS en esta fase sin Strict-Transport-Security
-- 4. Error propio del frontend (/api/internal/v1 no se reenvia)
   OK     no se proxia /internal   HTTP/1.1 404 Not Found
   OK     un error de API no es index.html   Content-Type
-- 5. Autenticacion por el proxy (incluida su respuesta de error)
   OK     login: sin cache ni en el error    Cache-Control
   OK     login: no se duplica la del upstream   Cache-Control una sola vez
   OK     login: el request_id se conserva   x-request-id
== Todas las cabeceras comprobadas.
```

La CSP **en el navegador** es comprobación manual: abrir la URL con la consola
abierta y confirmar que no hay violaciones al cargar React, al hacer `fetch` ni
al pintar el QR. `curl` no ejecuta la política.

---

## 8. HTTP local y HTTPS: modos, matriz y certificados

TLS se controla con variables **no sensibles** de `.env`, consumidas por Compose
y por la configuración de ejecución de Nginx. Ninguna es `VITE_*`: cambiar de
modo **no** obliga a reconstruir la imagen.

```dotenv
FRONTEND_HTTPS_ENABLED=false
FRONTEND_ACCESS_SCOPE=local
FRONTEND_HOST_BIND=127.0.0.1
FRONTEND_HTTP_PORT=8080
FRONTEND_HTTPS_PORT=8443
FRONTEND_HEALTH_PORT=8081
FRONTEND_PUBLIC_HOST=localhost
FRONTEND_TLS_CERT_FILE=./secrets/frontend-tls/tls.crt
FRONTEND_TLS_KEY_FILE=./secrets/frontend-tls/tls.key
```

### Matriz de combinaciones

| Alcance | HTTPS | Bind | Resultado |
|---|---|---|---|
| `local` | `false` | loopback | **Admitido**. `http://localhost:8080`. El 8443 queda publicado sin nada escuchando |
| `local` | `true` | loopback | **Admitido**. `https://localhost:8443`; el 8080 solo redirige |
| `lan` | `true` | `0.0.0.0` o la IP | **Admitido**. `https://<nombre o IP>:8443` |
| `lan` | `false` | cualquiera | **Rechazado** antes de publicar: compartirlo en claro expondría la contraseña y el TOTP |
| `local` | `false` | fuera de loopback | **Rechazado**: cambiar solo el bind no elude el requisito de HTTPS |
| cualquiera | `true` | sin certificado válido | **Rechazado** con la causa concreta. **No** se vuelve a HTTP por su cuenta |

Las dos últimas filas son el punto importante: la validación está **duplicada a
propósito** en el paso del Makefile (para leerla antes de publicar) y en el
entrypoint del contenedor (para quien arranque el contenedor sin pasar por
`make`). Puertos privilegiados, puertos repetidos, un `FRONTEND_PUBLIC_HOST` con
esquema o ruta y valores que no sean `true`/`false` o `local`/`lan` también se
rechazan.

### Qué se valida del certificado antes de publicar

Presencia, legibilidad, que no esté vacío, que sea PEM X.509, **vigencia**
(`-checkend 0`, con aviso si caduca en menos de 7 días), **correspondencia
certificado/clave** (comparando la clave pública) y que los **SAN cubran
`FRONTEND_PUBLIC_HOST`**. Si falta cualquiera de esas cosas, el contenedor no
arranca y el log dice cuál.

### Preparar el certificado

```bash
bash scripts/frontend/prepare-tls.sh                       # usa FRONTEND_PUBLIC_HOST
bash scripts/frontend/prepare-tls.sh despacho.local 192.168.1.50
bash scripts/frontend/prepare-tls.sh --force               # reemplaza el actual
```

Con **mkcert** instalado (recomendado) genera el par y además instala la
confianza de su CA en **este** equipo, así que el navegador local no avisa. Sin
mkcert usa `openssl` —el del host, que Git for Windows trae, o uno en un
contenedor— y genera un autofirmado con los SAN pedidos; en ese caso el
navegador avisará hasta que se confíe en el certificado a mano.

El guion **conserva** un certificado que ya sirve: si está vigente, su clave
corresponde y cubre los nombres pedidos, no rota nada y lo dice. Repetir
`make all` tampoco lo toca.

**Confianza en los demás equipos del despacho.** Hay que instalarla a mano, en
cada equipo, y ningún script de este repositorio puede hacerlo: no toca otras
máquinas y no lo promete. Con mkcert, el archivo que hay que distribuir e
instalar como CA de confianza es `rootCA.pem` del directorio que imprime
`mkcert -CAROOT`. Con un autofirmado, se instala el propio certificado. Los SAN
deben cubrir exactamente los nombres o las IP con que cada equipo abra la
aplicación.

### Cambiar de modo sin reconstruir

```bash
bash scripts/frontend/prepare-tls.sh despacho.local
# en .env: FRONTEND_HTTPS_ENABLED=true, FRONTEND_ACCESS_SCOPE=lan,
#          FRONTEND_HOST_BIND=0.0.0.0, FRONTEND_PUBLIC_HOST=despacho.local
make all
```

La imagen **no se reconstruye**: su huella de entradas no ha cambiado. Lo único
que cambia es la configuración que el entrypoint genera al arrancar. Volver a
HTTP local es el camino inverso, igual de barato.

En modo HTTPS la aplicación y la API se sirven **únicamente** por HTTPS. El
listener de texto claro que queda **solo redirige** (308, conservando ruta y
puerto, al origen HTTPS configurado) y no sirve el login ni reenvía la API: una
redirección no protege unas credenciales que ya viajaron en claro, así que por
ahí no hay nada que enviar. El destino se construye con el valor **validado**
del arranque, nunca con el `Host` de la petición.

El backend y Vault **no** se publican en la LAN para resolver el acceso del
frontend: el navegador llama al mismo origen HTTPS y el proxy conserva HTTP solo
dentro de `network-service`. Tampoco hay contenido mixto: todas las peticiones
son relativas.

HTTPS no cambia nada del resto: la sesión sigue en memoria, el MFA se sigue
exigiendo y el desbloqueo de Vault sigue siendo lo que era.

---

## 9. Docker, proxy y el perfil de desarrollo

### La imagen

Build multietapa: `frontend-builder` (Node, `npm ci` desde el lockfile,
`typecheck` y `vite build`) y `frontend-server` (Nginx con el paquete ya
construido). La imagen que se publica **no** lleva Node, ni npm, ni
`node_modules`, ni el código fuente. Corre con el usuario `nginx` (no root), con
el pid y los temporales en `/tmp`, y escucha en puertos no privilegiados.

```text
dist/index.html                          0.83 kB
dist/assets/index-*.css                  6.90 kB
dist/assets/TotpAdminPage-*.js           8.56 kB   (fragmento aparte)
dist/assets/index-*.js                 210.63 kB   (69.25 kB comprimido)
```

La herramienta administrativa se carga aparte con `React.lazy`: no hace falta
para iniciar sesión, que es lo que hace todo el mundo. El resto cabe en un solo
paquete, así que no se parte por partirlo.

No hay volumen persistente para el paquete estático: el código va **en** la
imagen, y si cambia el código cambia la imagen.

### El proxy

```text
navegador                       Nginx                         red interna
/api/user_mgmt/v1/auth/login -> reescribe -> http://user-mgmt-service:8000/user_mgmt/v1/auth/login
```

* **Un solo prefijo se reenvía**, escrito con una expresión regular que captura
  el resto de la ruta, de modo que la reescritura es explícita y no se duplica
  ni se come el prefijo. Hay pruebas de las dos cosas.
* **El `Authorization` se conserva** tal cual; sin él la API no autoriza. Se
  reenvían también `X-Request-ID` y `X-VPG-MFA-Proof`.
* **Nada más se reenvía**: ni `/internal`, ni vault-mgmt, ni Vault, ni
  PostgreSQL, ni los endpoints de máquina. Una ruta bajo `/api/` que no encaje
  recibe un **404 JSON del frontend**, no `index.html`.
* **Un error de API no sirve `index.html`.** El fallback de la SPA es solo para
  rutas de interfaz.
* **DNS y recreación del upstream**: el nombre del upstream va en una variable
  con `resolver 127.0.0.11 valid=10s`, así que Nginx lo resuelve en cada
  petición. Con un `proxy_pass` de nombre literal, Nginx fija la IP al arrancar
  y un `docker compose up -d user-mgmt-service` que cambie de IP dejaría el
  proxy apuntando a la vieja hasta reiniciarlo. Así no.
* **Sin reintentos** (`proxy_next_upstream off`): el login, el MFA y la
  inscripción no son idempotentes.
* **Sin caché de proxy**: no se declara ningún `proxy_cache_path`.

### Perfil de desarrollo (opcional)

Separado del runtime de `make all`, con `profiles: [dev]`, así que no lo levanta
ni `docker compose up` ni `make all`:

```bash
bash scripts/frontend/npm.sh ci      # la primera vez
bash scripts/frontend/dev.sh         # http://127.0.0.1:5173
bash scripts/frontend/dev.sh --parar
```

Vite sirve con scripts en línea y una conexión de HMR que la CSP del runtime
prohíbe. Esos permisos **no llegan** al runtime: el de `make all` es Nginx con
la política estricta y sin Vite dentro.

### `down` y `purge`

`make down` elimina el contenedor y la red, y conserva volúmenes, imágenes,
secretos y el material TLS. `make purge` borra los volúmenes de Vault y
PostgreSQL, las imágenes propias (incluida la del frontend) y las credenciales
huérfanas de `secrets/`; **conserva `secrets/frontend-tls/`**, que no depende de
ningún volumen y cuya pérdida obligaría a volver a instalar la confianza en cada
equipo.

---

## 10. Pruebas y qué demuestra cada una

### Frontend (contenerizadas)

```bash
bash scripts/frontend/run-tests.sh                        # tipos + lint + pruebas
bash scripts/frontend/run-tests.sh --solo-pruebas
bash scripts/frontend/run-tests.sh -- -t "segundo factor"
```

Resultado real: **96 pruebas en 7 archivos, todas en verde**, más `tsc --noEmit`
en modo estricto y ESLint sin avisos.

| Archivo (pruebas) | Qué cubre |
|---|---|
| `state/reducer.test.ts` (10) | La máquina de estados: que un desafío no es una sesión, que no se repite una operación en curso, que la autorización de inscripción se retira al usarse |
| `shared/api/http.test.ts` (10) | Bearer solo donde toca, 204 sin parsear, 401 del logout, `ErrorDetail` real, `Retry-After`, ausencia de reintentos, red caída distinguida del 503 |
| `pages/LoginPage.test.tsx` (13) | Login sin sesión, validación local, 401, 403 `mfa_not_enforced` **bloqueante**, 403 `not_provisioned`, 422 con campos y sin valores, 429 con espera visible, 503, red caída, ruta protegida sin sesión |
| `pages/MfaPage.test.tsx` (14) | Código válido, ceros iniciales, pegado con espacios, nada se envía al teclear, código incompleto, código incorrecto, desafío caducado, 429, doble clic, recarga sin desafío, logout 204/401/red |
| `totp/SelfEnrollmentPanel.test.tsx` (11) | Los cinco estados del aviso, QR desde un URI real, un solo uso, 409 con el camino del reset, `pending` sin URI, cadena que no es `otpauth`, descarte al volver |
| `totp/pages/TotpAdminPage.test.tsx` (15) | Denegación a employee y manager, GET sin efectos, `pending` que no provisiona ni reinicia, provisión con QR, respuesta sin URI, 409 parcial con `operation_id`, reset con confirmación, 403 `stale_mfa`, 401, cambio de objetivo |
| `test/contract.test.ts` (23) | Rutas, campos y ejemplos contra el **OpenAPI capturado** del servicio, incluida la limitación de `/auth/me` |

Los dobles HTTP son explícitos: cada ruta se declara con su cuerpo y su estado
reales, y una petición que no coincida con ninguna **falla la prueba** en vez de
devolver un 200 vacío. Así una llamada de más (un efecto repetido, un reintento)
se ve en cuanto aparece. Ninguna prueba usa una semilla TOTP real ni genera
códigos del administrador.

### Backend

```bash
bash scripts/user_mgmt/run-tests.sh
bash scripts/user_mgmt/run-tests.sh tests/test_totp_enrollment.py
```

La suite completa queda en **318 pruebas en verde** (PostgreSQL real y doble de
Vault). La de la etapa 3 sigue intacta y se añade
[`tests/test_totp_enrollment.py`](../tests/test_totp_enrollment.py), **16
pruebas**: estado histórico y autorización solo con contraseña correcta,
`confirmed` y `disabled` sin autorización, un solo uso, 409 que **no destruye**
la semilla existente, la autorización que no vale como sesión ni abre la
pantalla administrativa, 503 con Vault sellado y la inscripción que no sustituye
al MFA.

### Recorrido no interactivo del servicio real

```bash
bash scripts/frontend/smoke-frontend.sh
bash scripts/frontend/smoke-frontend.sh --cacert "$(mkcert -CAROOT)/rootCA.pem"
```

Comprueba el contenedor, `/healthz`, el documento y **las rutas profundas**
(`/login`, `/mfa`, `/inicio`, `/configuracion-totp` y una inexistente), que el
prefijo del proxy no se duplica ni se pierde, que `/internal`, vault-mgmt y
`/health` quedan fuera, que un 404 de API es JSON y no `index.html`, que no hay
contenido mixto, el DNS interno del upstream y, en modo HTTPS, que la
redirección conserva ruta y puerto.

Distingue dos cosas que se confunden: *el frontend sirve y reenvía bien* y
*user-mgmt está listo*. Con Vault sellado el backend responde 503 y el guion lo
dice con esas palabras, en vez de apuntarlo como fallo del frontend.

### Comprobado en un navegador real

Además de las suites, esta etapa se recorrió en un navegador de verdad contra
los servicios en marcha. Lo comprobado:

* `http://localhost:8080/login` carga React **sin una sola violación de CSP**:
  la consola solo trae el 401 esperado de la petición de prueba. Con las
  banderas de la v7 activadas en el router, tampoco quedan avisos de React
  Router.
* Un login con credenciales inexistentes viaja por el proxy
  (`POST /api/user_mgmt/v1/auth/login` → 401) y la pantalla muestra «Usuario o
  contraseña incorrectos» con la referencia del log del servicio. Que la
  petición salga quiere decir que `connect-src 'self'` no la bloquea.
* Abrir `http://localhost:8080/configuracion-totp` **directamente** carga la
  aplicación (no un 404 de Nginx) y, sin sesión, vuelve al acceso con el aviso
  de que hace falta iniciar sesión.
* A 375 px de ancho el formulario sigue siendo legible y usable: etiquetas,
  ayuda, el botón de mostrar contraseña y el aviso caben sin desbordes.

**No se usan pruebas de navegador contenerizadas** (un Playwright o similar en
Docker): las suites cubren el comportamiento con jsdom y los guiones cubren el
servicio real, y añadir un navegador automatizado habría duplicado eso sin
cubrir lo único que de verdad falta, que es un teléfono con Google
Authenticator. Queda anotado como decisión, no como olvido.

### Lo que sigue siendo manual, y por qué

No es pereza: no se puede automatizar sin falsificar lo que se quiere probar.

| Comprobación | Por qué es manual |
|---|---|
| Login con un código TOTP **real** | Haría falta la semilla de una persona real; generar códigos en la prueba demostraría que la prueba sabe sumar, no que el sistema autentica |
| Que **Google Authenticator** acepte el QR | Hace falta un teléfono |
| Que la **CSP** no se viole en el navegador | `curl` no ejecuta la política |
| Confianza de la CA en los equipos del despacho | Cada equipo es una máquina distinta |

### Tres niveles, dichos por su nombre

* **Simulación**: las pruebas del frontend (dobles HTTP) y las del backend
  (doble de Vault). Demuestran comportamiento del código, no de Vault.
* **Integración real**: `make all`, `check-headers.sh` y `smoke-frontend.sh`
  contra los servicios en marcha, con el contrato capturado del OpenAPI real.
* **Pendiente de comprobación manual**: lo de la tabla de arriba.

---

## 11. Recorrido manual (necesita un teléfono)

Con `make all` terminado y un usuario de pruebas autorizado —no el
administrador, si se puede evitar—:

1. **Abrir** `http://localhost:8080` con la consola del navegador abierta.
   Comprobar que no hay violaciones de CSP ni peticiones a ningún origen que no
   sea el propio.
2. **Paso 1.** Escribir `"<usuario>"` y su contraseña, y pulsar *Continuar al
   segundo factor*. La cabecera debe pasar a «pendiente del segundo factor», y
   la pantalla debe decir que **todavía no hay sesión**.
3. **El aviso.** Si el estado histórico es `pending`, debe aparecer el aviso
   completo. Si es `confirmed`, no debe aparecer ninguno.
4. **La inscripción.** Si esa identidad no tiene semilla, pulsar *Mostrar mi
   código QR de inscripción*: aparece el QR, los pasos de Google Authenticator y
   los parámetros del URI. Escanearlo desde *Añadir cuenta → Escanear código QR*.
   Si ya tiene semilla, debe salir el 409 con el camino del reset, y **no** un
   QR.
5. **Paso 2.** Escribir el código de seis dígitos de la aplicación y pulsar
   *Validar y entrar*. Solo aquí aparece `/inicio`.
6. **La sesión.** Comprobar identidad, roles, políticas de Vault, caducidad y
   antigüedad del MFA. Recargar la página (F5): debe volver al acceso diciendo
   que hace falta iniciar sesión, porque la sesión vive en memoria.
7. **Rutas profundas.** Abrir `http://localhost:8080/configuracion-totp`
   directamente: debe cargar la aplicación (no un 404 de Nginx) y, sin sesión,
   volver al acceso.
8. **La herramienta administrativa.** Con una sesión de `admin`, abrirla, pegar
   el UUID de un empleado y pulsar *Consultar estado*. Aprovisionar solo si de
   verdad hace falta: entrega el URI **una sola vez**.
9. **El cierre.** Pulsar *Cerrar sesión* y leer el mensaje: con 204 debe decir
   que el servidor revocó el token.
10. **Reinicio del backend.** `docker compose restart user-mgmt-service` con una
    sesión abierta: la siguiente operación autenticada devuelve al acceso. Es lo
    esperado, porque las sesiones viven en la memoria de ese worker.

---

## 12. Seguridad y limitaciones conocidas (etapa 5.1)

* **No es una configuración de producción validada.** Es el entorno local del
  despacho: HTTP en loopback o HTTPS con un certificado propio, sesiones y
  limitación de peticiones en memoria de un solo worker.
* **La sesión vive en memoria del navegador y del worker.** Recargar obliga a
  entrar otra vez, y reiniciar user-mgmt invalida todas las sesiones. No se
  disimula con cookies, refresh tokens ni un BFF.
* **Un solo worker de user-mgmt.** Con varias réplicas, una sesión solo valdría
  en el proceso que la creó. Escalar ese backend no es parte de esta etapa.
* **No se registra nada sensible.** Ni `Authorization`, ni contraseñas, ni
  códigos, ni `challenge_id`, ni `api_session`, ni URI `otpauth`, ni el QR. El
  log de Nginx registra la ruta **normalizada** y el estado, sin cadena de
  consulta y sin cabeceras. ESLint prohíbe `console` en el código de la
  aplicación y `dangerouslySetInnerHTML` por nombre.
* **El frontend no monta `secrets/` completo**, ni el token inicial de Vault, ni
  la clave de unseal, ni credenciales internas. En modo HTTPS recibe exactamente
  dos archivos de solo lectura.
* **Las variables `VITE_*` son públicas** y se incorporan al paquete; no sirven
  para secretos y añadirlas al contenedor estático no cambia nada. La
  configuración de ejecución (modo, puertos, TLS, alcance) es de Nginx, no del
  paquete.
* **El puerto HTTPS se publica también en modo HTTP**, sin nada escuchando
  detrás, porque Compose no admite mapeos condicionales. Si estorba, se cambia
  en `.env`.
* **El tiempo de visualización del QR oculta la pantalla, no caduca la
  semilla.** La semilla sigue siendo válida en Vault.
* **Perder el URI no se arregla aquí.** Hace falta un reset administrativo
  explícito, y para el administrador inicial la vía documentada es
  `vpg-auth-bootstrap --reset-totp`.
* **La confianza de la CA es manual en cada equipo.** `make all` no puede
  instalarla en otras máquinas y no lo promete.
* **HSTS deshabilitado** a propósito en esta fase.
* **El QR depende de una librería local** (`qrcode.react`). Si se cambiara por
  una que use `canvas` y `toDataURL`, haría falta `data:` en `img-src`: la
  variante SVG se eligió justamente para no tocar la política.
