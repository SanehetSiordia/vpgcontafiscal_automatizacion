// Politica de ADMINISTRACION de los secretos gestionados por vault-mgmt.
//
// Se asigna a las personas con rol de aplicacion 'admin'. Implementa el mapeo
// que el README declaraba pendiente, y lo hace de forma ESTRECHA: solo el
// prefijo gestionado. No es 'vpg-admin' (acceso total a Vault) y no la
// sustituye: una cosa es administrar estos secretos y otra administrar Vault.
//
// El prefijo esta fijado a secret/+/vpg-managed/*. Si se cambia el montaje
// (VAULT_MGMT_KV_MOUNT) o el prefijo (VAULT_MGMT_KV_PREFIX), hay que reescribir
// esta politica: scripts/vault_mgmt/vault-kv-policies.sh la genera a partir de
// esos valores, precisamente para que no se queden desparejados.
//
// Los segmentos data / metadata / delete / undelete / destroy son del cliente
// KV v2, no carpetas del secreto: por eso hay una ruta por cada uno.

// --- Datos: leer y escribir versiones nuevas ---
path "secret/data/vpg-managed/*" {
  capabilities = ["create", "read", "update"]
}

// --- Metadata: historial, y su borrado (que destruye TODO el historial) ---
path "secret/metadata/vpg-managed/*" {
  capabilities = ["read", "list", "delete"]
}

// --- Soft-delete y recuperacion de versiones concretas ---
path "secret/delete/vpg-managed/*" {
  capabilities = ["update"]
}

path "secret/undelete/vpg-managed/*" {
  capabilities = ["update"]
}

// --- Destruccion irreversible de versiones concretas ---
path "secret/destroy/vpg-managed/*" {
  capabilities = ["update"]
}

// --- Response wrapping y consulta de capacidades ---
// La politica 'default' ya las concede a todo token; se declaran aqui para que
// el alcance de esta politica se lea entero en un sitio.
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}

path "sys/wrapping/lookup" {
  capabilities = ["update"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
