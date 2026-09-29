# Politica de administracion de Vault para el usuario administrador
# (userpass + MFA TOTP). Equivale a acceso total; sustituye al uso
# cotidiano del root token, que debe revocarse o guardarse offline.

path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
