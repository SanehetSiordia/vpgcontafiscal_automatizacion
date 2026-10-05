// Politica de LECTURA de los secretos gestionados por vault-mgmt.
//
// Se asigna a las personas con rol de aplicacion 'manager' o 'employee' que
// deban leer colecciones compartidas. Que la coleccion las declare lectoras es
// condicion necesaria pero NO suficiente: ademas hace falta esta politica, y
// Vault manda sobre el rol de aplicacion.
//
// Deliberadamente NO incluye:
//   * escritura de datos      -> escribir es cosa de un administrador;
//   * delete/undelete/destroy -> borrar versiones tampoco;
//   * list sobre metadata     -> enumerar el prefijo entero no hace falta para
//                                leer un registro concreto, y LIST no aplica
//                                filtrado por politica elemento a elemento;
//   * read sobre metadata     -> el historial de versiones es informacion de
//                                administracion.
//
// Tampoco se amplia la AppRole de empleados para leer secretos: una cuenta
// tecnica prepara infraestructura, no suplanta permisos humanos.

path "secret/data/vpg-managed/*" {
  capabilities = ["read"]
}

// Response wrapping: es como se entregan los valores por defecto.
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}

path "sys/wrapping/lookup" {
  capabilities = ["update"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
