// Politica de la MAQUINA (crawler): solo lectura, y solo del prefijo gestionado.
//
// Se asigna a la AppRole dedicada del consumidor, que crea
// scripts/vault_mgmt/crawler-approle-bootstrap.sh con TTL cortos.
//
// Esta politica es el limite exterior. El limite interior lo ponen los
// bindings del catalogo: aunque la politica cubra todo el prefijo, el endpoint
// /integrations/crawler/resolve solo prepara entrega de los registros que el
// consumidor tiene asignados. Las dos capas son necesarias; ninguna sustituye
// a la otra.
//
// NO incluye escritura, ni borrado, ni metadata, ni list: el consumidor
// resuelve por UUID de registro, no explora el arbol.

path "secret/data/vpg-managed/*" {
  capabilities = ["read"]
}

// Necesarias para que el servicio pueda preparar la entrega envuelta CON LOS
// PERMISOS DE ESTA MAQUINA, y para que ella desenvuelva despues.
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}

path "sys/wrapping/unwrap" {
  capabilities = ["update"]
}

path "sys/wrapping/lookup" {
  capabilities = ["update"]
}

// Validacion de la propia identidad: la usa el servicio al recibir el token.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
