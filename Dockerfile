ARG VAULT_VERSION=2.1.1
ARG POSTGRES_VERSION=17-alpine
ARG PYTHON_VERSION=3.12-alpine
ARG NODE_VERSION=22-alpine
ARG NGINX_VERSION=1.27-alpine

# =============================================================================
# Componente 1: HashiCorp Vault
# =============================================================================

# Etapa 1: prepara los archivos del proyecto.
# Normaliza finales de linea (Git en Windows puede convertirlos a CRLF)
# y deja permisos correctos antes de copiarlos a la imagen final.
FROM hashicorp/vault:${VAULT_VERSION} AS vault-assets
USER root
COPY config/vault.hcl /staging/vault/config/vault.hcl
COPY config/policies/ /staging/vault/config/policies/
COPY docker-entrypoint.sh /staging/usr/local/bin/vpg-entrypoint.sh
COPY scripts/vault-auth-bootstrap.sh /staging/usr/local/bin/vpg-auth-bootstrap
RUN sed -i 's/\r$//' /staging/vault/config/vault.hcl /staging/vault/config/policies/*.hcl \
      /staging/usr/local/bin/vpg-entrypoint.sh /staging/usr/local/bin/vpg-auth-bootstrap \
 && chmod 0640 /staging/vault/config/vault.hcl /staging/vault/config/policies/*.hcl \
 && chmod 0755 /staging/usr/local/bin/vpg-entrypoint.sh /staging/usr/local/bin/vpg-auth-bootstrap \
 && mkdir -p /staging/vault/data \
 && chmod 0700 /staging/vault/data

# Etapa final: servidor Vault (sin modo dev), usuario no root.
FROM hashicorp/vault:${VAULT_VERSION} AS vault-server
COPY --from=vault-assets --chown=vault:vault /staging/vault/ /vault/
COPY --from=vault-assets /staging/usr/local/bin/ /usr/local/bin/
ENV VAULT_ADDR=http://127.0.0.1:8200
USER vault
EXPOSE 8200
VOLUME ["/vault/data"]
# `vault status` devuelve 0 (desbloqueado), 2 (sellado) o 1 (error).
# El contenedor se considera sano si el proceso responde, aunque esté sellado.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD vault status >/dev/null 2>&1; [ $? -ne 1 ]
ENTRYPOINT ["/usr/local/bin/vpg-entrypoint.sh"]

# =============================================================================
# Componente 2: PostgreSQL 17 (empleados, roles y vinculo con Vault)
# =============================================================================

# Etapa 1: normaliza CRLF y permisos del DDL y de los scripts, igual que en
# Vault. No se instala Python ni ninguna dependencia adicional.
FROM postgres:${POSTGRES_VERSION} AS postgres-assets
USER root
COPY sql/001_employees.sql            /staging/opt/vpg/sql/001_employees.sql
COPY scripts/postgres/pg-schema.sh    /staging/usr/local/bin/vpg-pg-schema
COPY scripts/postgres/pg-app-role.sh  /staging/usr/local/bin/vpg-pg-roles
RUN sed -i 's/\r$//' /staging/opt/vpg/sql/001_employees.sql \
      /staging/usr/local/bin/vpg-pg-schema /staging/usr/local/bin/vpg-pg-roles \
 && chmod 0644 /staging/opt/vpg/sql/001_employees.sql \
 && chmod 0755 /staging/usr/local/bin/vpg-pg-schema /staging/usr/local/bin/vpg-pg-roles

# Etapa final: se CONSERVA el entrypoint y el CMD oficiales de postgres
# (no se declaran ENTRYPOINT ni CMD aqui).
FROM postgres:${POSTGRES_VERSION} AS postgres-server
COPY --from=postgres-assets /staging/opt/vpg/       /opt/vpg/
COPY --from=postgres-assets /staging/usr/local/bin/ /usr/local/bin/
# Los enlaces en /docker-entrypoint-initdb.d solo los ejecuta el entrypoint
# oficial cuando el volumen de datos esta VACIO. Los mismos scripts se pueden
# invocar a mano en cualquier momento (vpg-pg-schema / vpg-pg-roles).
RUN ln -sf /usr/local/bin/vpg-pg-schema /docker-entrypoint-initdb.d/10-schema.sh \
 && ln -sf /usr/local/bin/vpg-pg-roles  /docker-entrypoint-initdb.d/20-app-role.sh
EXPOSE 5432
VOLUME ["/var/lib/postgresql/data"]

# =============================================================================
# Componente 3: user-mgmt-service (FastAPI)
# =============================================================================

# Etapa builder: aqui viven gcc y las cabeceras. Varias dependencias no publican
# rueda para musl (psycopg-c, uvloop, httptools, pydantic-core) y se compilan.
FROM python:${PYTHON_VERSION} AS user-mgmt-builder
RUN apk add --no-cache build-base musl-dev postgresql-dev libffi-dev
COPY requirements/user_mgmt.txt /tmp/user_mgmt.txt
RUN python -m pip install --no-cache-dir --upgrade pip wheel \
 && python -m pip wheel --no-cache-dir --wheel-dir /wheels -r /tmp/user_mgmt.txt

# Etapa final: solo la biblioteca de cliente de PostgreSQL en tiempo de
# ejecucion. Sin compiladores, sin cabeceras, sin cache de pip.
FROM python:${PYTHON_VERSION} AS user-mgmt-server
RUN apk add --no-cache libpq \
 && addgroup -S vpg && adduser -S -G vpg -h /app vpg
COPY --from=user-mgmt-builder /wheels /wheels
COPY requirements/user_mgmt.txt /tmp/user_mgmt.txt
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels \
      -r /tmp/user_mgmt.txt \
 && rm -rf /wheels /tmp/user_mgmt.txt /root/.cache

WORKDIR /app
# El codigo va EN la imagen: no hace falta volumen persistente para /app.
COPY --chown=vpg:vpg app/ /app/app/
# Normaliza CRLF por si Git los convirtio en Windows.
RUN find /app/app -name '*.py' -exec sed -i 's/\r$//' {} + \
 && python -m compileall -q /app/app \
 && chown -R vpg:vpg /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app
USER vpg
EXPOSE 8000
# Un worker y sin reload: las sesiones viven en memoria del proceso.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--no-access-log", "--proxy-headers"]

# Etapa de PRUEBAS: parte del runtime y le anade solo las dependencias de test.
# No forma parte de la imagen que se publica; se construye a demanda con
# `--target user-mgmt-test`.
FROM user-mgmt-server AS user-mgmt-test
USER root
COPY requirements/user_mgmt-dev.txt /tmp/dev.txt
RUN python -m pip install --no-cache-dir -r /tmp/dev.txt && rm -f /tmp/dev.txt
COPY --chown=vpg:vpg tests/ /app/tests/
COPY --chown=vpg:vpg pytest.ini /app/pytest.ini
RUN find /app/tests -name '*.py' -exec sed -i 's/\r$//' {} +
USER vpg
CMD ["python", "-m", "pytest"]

# =============================================================================
# Componente 4: vault-mgmt-service (FastAPI) - CRUD dinamico de secretos
# =============================================================================

# Etapa builder: igual que la de user-mgmt y por el mismo motivo. En musl varias
# dependencias no publican rueda (psycopg-c, uvloop, httptools, pydantic-core) y
# hay que compilarlas aqui, no en el runtime.
FROM python:${PYTHON_VERSION} AS vault-mgmt-builder
RUN apk add --no-cache build-base musl-dev postgresql-dev libffi-dev
COPY requirements/vault_mgmt.txt /tmp/vault_mgmt.txt
RUN python -m pip install --no-cache-dir --upgrade pip wheel \
 && python -m pip wheel --no-cache-dir --wheel-dir /wheels -r /tmp/vault_mgmt.txt

# Etapa final: solo la biblioteca de cliente de PostgreSQL en tiempo de
# ejecucion. Sin compiladores, sin cabeceras, sin cache de pip, usuario no root.
FROM python:${PYTHON_VERSION} AS vault-mgmt-server
RUN apk add --no-cache libpq \
 && addgroup -S vpg && adduser -S -G vpg -h /app vpg
COPY --from=vault-mgmt-builder /wheels /wheels
COPY requirements/vault_mgmt.txt /tmp/vault_mgmt.txt
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels \
      -r /tmp/vault_mgmt.txt \
 && rm -rf /wheels /tmp/vault_mgmt.txt /root/.cache

WORKDIR /app
# El codigo va EN la imagen: no hay volumen persistente de codigo.
# Se copia el arbol `app/` completo porque vault_mgmt reutiliza modulos de la
# etapa 3 (app/core/errors.py, logging.py, rate_limit.py, vault.py, vault_kv.py
# y secret_schema.py). Lo que NO se hace es importar app.main: cada servicio
# tiene el suyo y no comparten estado en memoria.
COPY --chown=vpg:vpg app/ /app/app/
# Normaliza CRLF por si Git los convirtio en Windows.
RUN find /app/app -name '*.py' -exec sed -i 's/\r$//' {} + \
 && python -m compileall -q /app/app \
 && chown -R vpg:vpg /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app
USER vpg
EXPOSE 8001
# Un worker y sin reload, igual que user-mgmt.
CMD ["uvicorn", "app.vault_mgmt.main:app", \
     "--host", "0.0.0.0", "--port", "8001", \
     "--workers", "1", "--no-access-log", "--proxy-headers"]

# Etapa de PRUEBAS de la etapa 4. No se publica; se construye a demanda con
# `--target vault-mgmt-test`.
FROM vault-mgmt-server AS vault-mgmt-test
USER root
COPY requirements/vault_mgmt-dev.txt /tmp/dev.txt
RUN python -m pip install --no-cache-dir -r /tmp/dev.txt && rm -f /tmp/dev.txt
COPY --chown=vpg:vpg tests/ /app/tests/
COPY --chown=vpg:vpg pytest.ini /app/pytest.ini
RUN find /app/tests -name '*.py' -exec sed -i 's/\r$//' {} +
USER vpg
CMD ["python", "-m", "pytest", "tests/vault_mgmt"]

# =============================================================================
# Componente 5: frontend-service (React + TypeScript servido por Nginx)
#
# Build en dos etapas con proposito distinto:
#   * `frontend-builder` tiene Node y TODAS las dependencias de desarrollo. Ahi
#     se comprueban los tipos y se construye el paquete estatico.
#   * `frontend-server` es Nginx con los estaticos ya construidos. NO lleva
#     Node, ni npm, ni node_modules, ni el codigo fuente: lo que se publica es
#     el resultado del build, no las herramientas que lo hicieron.
# =============================================================================

FROM node:${NODE_VERSION} AS frontend-builder
WORKDIR /build
# Primero el manifiesto y el lockfile: asi la capa de dependencias se reutiliza
# mientras no cambien, aunque cambie el codigo.
COPY frontend/package.json frontend/package-lock.json ./
# `npm ci` y no `npm install`: instala EXACTAMENTE el lockfile y falla si el
# manifiesto y el lockfile no concuerdan.
RUN npm ci --no-audit --no-fund
COPY frontend/tsconfig.json frontend/vite.config.ts frontend/eslint.config.js \
     frontend/index.html ./
COPY frontend/src ./src
COPY frontend/public ./public
# Los tipos se comprueban DENTRO del build: un error de tipos no debe llegar a
# una imagen publicable.
RUN npm run typecheck && npm run build

# Etapa de PRUEBAS del frontend. No se publica; se construye a demanda con
# `--target frontend-test` (scripts/frontend/run-tests.sh).
FROM frontend-builder AS frontend-test
ENV CI=true
CMD ["npm", "test"]

# Etapa final: Nginx con usuario no root, puertos no privilegiados y la
# configuracion generada en el arranque segun el modo (HTTP o HTTPS).
FROM nginx:${NGINX_VERSION} AS frontend-server
# openssl para comprobar de verdad el par certificado/clave antes de publicar
# TLS; gettext para `envsubst`, que rellena la plantilla del servidor.
RUN apk add --no-cache openssl gettext

COPY docker/frontend/nginx.conf            /etc/nginx/nginx.conf
COPY docker/frontend/snippets/             /etc/nginx/vpg/snippets/
COPY docker/frontend/templates/            /etc/nginx/vpg/templates/
COPY docker/frontend/entrypoint.sh         /usr/local/bin/vpg-frontend-entrypoint.sh
COPY --from=frontend-builder /build/dist/  /usr/share/nginx/html/

# Normaliza CRLF (Git en Windows), fija permisos y deja escribible lo que el
# arranque necesita: el directorio donde se genera server.conf y /tmp/nginx.
# Tambien se retiran el entrypoint oficial y conf.d: la configuracion la
# genera el nuestro, y dejarlos solo invita a anadir ahi otro servidor.
RUN sed -i 's/\r$//' /usr/local/bin/vpg-frontend-entrypoint.sh /etc/nginx/nginx.conf \
      /etc/nginx/vpg/snippets/*.conf /etc/nginx/vpg/templates/*.template \
 && chmod 0755 /usr/local/bin/vpg-frontend-entrypoint.sh \
 && chmod 0644 /etc/nginx/nginx.conf /etc/nginx/vpg/snippets/*.conf \
      /etc/nginx/vpg/templates/*.template \
 && mkdir -p /tmp/nginx \
 && chown -R nginx:nginx /etc/nginx/vpg /tmp/nginx \
 && rm -rf /docker-entrypoint.d /etc/nginx/conf.d /docker-entrypoint.sh

USER nginx
# Puertos NO privilegiados: 8080 (HTTP o redireccion), 8443 (TLS). El 8081 es
# la escucha interna de salud y no se publica.
EXPOSE 8080 8443
# Forma de shell para que FRONTEND_HEALTH_PORT se expanda en ejecucion. Va
# siempre por HTTP contra la escucha interna: asi un fallo de TLS se ve como un
# contenedor que no arranca, en vez de taparse con una comprobacion insegura.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD wget --quiet --spider "http://127.0.0.1:${FRONTEND_HEALTH_PORT:-8081}/healthz" || exit 1
ENTRYPOINT ["/usr/local/bin/vpg-frontend-entrypoint.sh"]
