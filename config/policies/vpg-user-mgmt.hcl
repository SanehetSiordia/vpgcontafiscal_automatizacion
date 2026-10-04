// Politica de la CUENTA TECNICA de user-mgmt-service (AppRole).
//
// Es deliberadamente estrecha: provisiona cuentas, entidades y enrolamientos
// TOTP, y nada mas. No sustituye los permisos de nadie.
//
// NO incluye, a proposito:
//   * secret/*            -> el servicio no lee secretos del SAT ni del crawler.
//                            /vault/access-check usa el token HUMANO, no este.
//   * sys/policies/*      -> no puede crear ni modificar politicas.
//   * sys/auth/*          -> no puede montar ni desmontar metodos de auth.
//   * create/delete sobre identity/mfa/method/totp/<id>
//                         -> el metodo TOTP es COMPARTIDO entre empleados:
//                            esta cuenta solo toca la semilla de una entidad.
//   * identity/mfa/login-enforcement (escritura)
//                         -> el enforcement cubre todo userpass y no se cambia
//                            desde la API.
//   * sys/leases/revoke-prefix y similares
//                         -> nunca una revocacion global del montaje userpass.

// --- Montaje userpass: solo lectura de su configuracion (accessor) ---
// `sys/auth/*` es una ruta PROTEGIDA POR ROOT en Vault: leerla exige `sudo`
// ademas de `read`. Sin el, la respuesta es 403 "permission denied" aunque el
// montaje exista (comprobado en este proyecto). El alcance sigue siendo
// minimo: solo este montaje y solo lectura; no permite crear ni borrar
// metodos de autenticacion, porque no hay `create`, `update` ni `delete`.
path "sys/auth/userpass" {
  capabilities = ["read", "sudo"]
}

// --- Cuentas userpass de empleados ---
path "auth/userpass/users" {
  capabilities = ["list"]
}

path "auth/userpass/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}

// --- Entidades y alias de identidad ---
path "identity/entity" {
  capabilities = ["create", "update"]
}

path "identity/entity/id/*" {
  capabilities = ["read", "update", "delete"]
}

path "identity/entity/name/*" {
  capabilities = ["read"]
}

path "identity/entity-alias" {
  capabilities = ["create", "update"]
}

path "identity/entity-alias/id/*" {
  capabilities = ["read", "update", "delete"]
}

path "identity/lookup/entity" {
  capabilities = ["create", "update"]
}

// --- MFA TOTP: leer el metodo compartido y operar SOLO sobre una entidad ---
path "identity/mfa/method/totp" {
  capabilities = ["list"]
}

path "identity/mfa/method/totp/*" {
  capabilities = ["read"]
}

// Las rutas exactas ganan al glob anterior: aqui si hay escritura, y solo aqui.
path "identity/mfa/method/totp/admin-generate" {
  capabilities = ["create", "update"]
}

path "identity/mfa/method/totp/admin-destroy" {
  capabilities = ["create", "update"]
}

// --- Enforcement MFA: solo lectura, para verificar que cubre userpass ---
path "identity/mfa/login-enforcement/*" {
  capabilities = ["read"]
}

// --- Gestion del propio token tecnico ---
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

// Revocacion de UN token concreto por su accessor (el de un empleado dado de
// baja). Requiere sudo en Vault. No permite revocar por prefijo.
path "auth/token/revoke-accessor" {
  capabilities = ["update", "sudo"]
}
