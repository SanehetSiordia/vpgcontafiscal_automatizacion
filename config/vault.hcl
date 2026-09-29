# Configuracion de Vault para el entorno local de VPG Contadores.
# Almacenamiento integrado (Raft) persistido en el volumen /vault/data.

ui            = true
disable_mlock = true   # recomendado con Raft; ver README (swap del host)

storage "raft" {
  path    = "/vault/data"
  node_id = "vpg-vault-1"
}

# El contenedor escucha en todas sus interfaces; compose publica el
# puerto unicamente en 127.0.0.1 del host.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # solo aceptable para uso local; en produccion usar TLS
}

api_addr     = "http://127.0.0.1:8200"
cluster_addr = "https://vault-service:8201"
