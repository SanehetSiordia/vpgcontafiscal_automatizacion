#!/usr/bin/dumb-init /bin/sh
# Arranca Vault en modo servidor con la configuración del proyecto.
# Sustituye al entrypoint oficial para no inyectar opciones -dev-*.
set -e
exec vault server -config=/vault/config/vault.hcl
