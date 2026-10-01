ARG VAULT_VERSION=2.1.1
ARG POSTGRES_VERSION=17-alpine

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
