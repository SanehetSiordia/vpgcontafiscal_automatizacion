# Politica por defecto para identidades que inician sesion por OIDC.
# Solo lectura de las credenciales del crawler en KV v2 (mount "secret").

path "secret/data/crawler/*" {
  capabilities = ["read"]
}

path "secret/metadata/crawler/*" {
  capabilities = ["read", "list"]
}
