ARG VAULT_VERSION=2.1.1

# Etapa 1: prepara los archivos del proyecto.
# Normaliza finales de linea (Git en Windows puede convertirlos a CRLF)
# y deja permisos correctos antes de copiarlos a la imagen final.
FROM hashicorp/vault:${VAULT_VERSION} AS vault-assets
USER root
COPY config/vault.hcl /staging/vault/config/vault.hcl
COPY docker-entrypoint.sh /staging/usr/local/bin/vpg-entrypoint.sh
RUN sed -i 's/\r$//' /staging/vault/config/vault.hcl /staging/usr/local/bin/vpg-entrypoint.sh \
 && chmod 0640 /staging/vault/config/vault.hcl \
 && chmod 0755 /staging/usr/local/bin/vpg-entrypoint.sh \
 && mkdir -p /staging/vault/data \
 && chmod 0700 /staging/vault/data

# Etapa final: servidor Vault (sin modo dev), usuario no root.
FROM hashicorp/vault:${VAULT_VERSION} AS vault-server
COPY --from=vault-assets --chown=vault:vault /staging/vault/ /vault/
COPY --from=vault-assets /staging/usr/local/bin/vpg-entrypoint.sh /usr/local/bin/vpg-entrypoint.sh
ENV VAULT_ADDR=http://127.0.0.1:8200
USER vault
EXPOSE 8200
VOLUME ["/vault/data"]
# `vault status` devuelve 0 (desbloqueado), 2 (sellado) o 1 (error).
# El contenedor se considera sano si el proceso responde, aunque esté sellado.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD vault status >/dev/null 2>&1; [ $? -ne 1 ]
ENTRYPOINT ["/usr/local/bin/vpg-entrypoint.sh"]
