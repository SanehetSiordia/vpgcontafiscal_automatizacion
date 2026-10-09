#!/bin/sh
# =============================================================================
# Arranque de frontend-service (etapa 5.1).
#
# Decide el modo (HTTP o HTTPS) con variables NO sensibles del entorno, valida
# lo que hace falta ANTES de publicar nada y solo entonces arranca Nginx.
#
# Dos reglas que este script hace cumplir y que no se pueden eludir cambiando
# solo el bind del puerto:
#
#   * alcance 'lan' EXIGE HTTPS. Si no esta habilitado, no arranca.
#   * alcance 'local' solo admite HTTP; y el HTTP solo se publica en loopback,
#     lo cual decide Compose con FRONTEND_HOST_BIND. Si ese bind sale del
#     loopback con HTTPS deshabilitado, el arranque se rechaza igualmente: el
#     valor llega aqui para poder comprobarlo.
#
# Si algo de TLS falta o no cuadra, el proceso FALLA con la causa concreta. No
# hay vuelta automatica a HTTP: eso convertiria un error de configuracion en una
# pagina de login servida en claro.
#
# No se imprime ninguna clave, ningun certificado y ningun valor de secreto.
# =============================================================================
set -eu

CERT=/run/secrets/frontend_tls_cert
KEY=/run/secrets/frontend_tls_key
DESTINO=/etc/nginx/vpg/server.conf
PLANTILLAS=/etc/nginx/vpg/templates

log()   { printf '[frontend] %s\n' "$1"; }
fallo() { printf '[frontend] ERROR: %s\n' "$1" >&2; exit 1; }

# --- parametros, con los mismos valores por omision que .env.example --------
ALCANCE=${FRONTEND_ACCESS_SCOPE:-local}
HTTPS=${FRONTEND_HTTPS_ENABLED:-false}
PUERTO_HTTP=${FRONTEND_HTTP_PORT:-8080}
PUERTO_HTTPS=${FRONTEND_HTTPS_PORT:-8443}
PUERTO_SALUD=${FRONTEND_HEALTH_PORT:-8081}
HOST_PUBLICO=${FRONTEND_PUBLIC_HOST:-localhost}
BIND=${FRONTEND_HOST_BIND:-127.0.0.1}

# --- validacion de valores ---------------------------------------------------
case "$ALCANCE" in
  local|lan) ;;
  *) fallo "FRONTEND_ACCESS_SCOPE debe valer 'local' o 'lan' (recibido: '$ALCANCE')" ;;
esac

case "$HTTPS" in
  true|false) ;;
  *) fallo "FRONTEND_HTTPS_ENABLED debe valer 'true' o 'false' (recibido: '$HTTPS')" ;;
esac

puerto_valido() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}

for par in "FRONTEND_HTTP_PORT=$PUERTO_HTTP" "FRONTEND_HTTPS_PORT=$PUERTO_HTTPS" \
           "FRONTEND_HEALTH_PORT=$PUERTO_SALUD"; do
  nombre=${par%%=*}
  valor=${par#*=}
  puerto_valido "$valor" ||
    fallo "$nombre debe ser un puerto no privilegiado entre 1024 y 65535 (recibido: '$valor')"
done

if [ "$PUERTO_HTTP" = "$PUERTO_HTTPS" ] || [ "$PUERTO_HTTP" = "$PUERTO_SALUD" ] ||
   [ "$PUERTO_HTTPS" = "$PUERTO_SALUD" ]; then
  fallo "los puertos HTTP ($PUERTO_HTTP), HTTPS ($PUERTO_HTTPS) y de salud ($PUERTO_SALUD) deben ser distintos"
fi

# Nombre publico: solo un host o una IP. Sin esquema, sin ruta y sin espacios,
# porque de aqui sale el destino de la redireccion y el server_name.
case "$HOST_PUBLICO" in
  ''|*://*|*/*|*\ *|*:*)
    fallo "FRONTEND_PUBLIC_HOST debe ser solo un nombre o una IP, sin esquema, sin puerto y sin ruta (recibido: '$HOST_PUBLICO')" ;;
esac
printf '%s' "$HOST_PUBLICO" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' ||
  fallo "FRONTEND_PUBLIC_HOST no parece un nombre ni una IP validos: '$HOST_PUBLICO'"

es_loopback() {
  case "$1" in
    127.0.0.1|::1|localhost) return 0 ;;
    *) return 1 ;;
  esac
}

# --- combinaciones admitidas -------------------------------------------------
if [ "$ALCANCE" = lan ] && [ "$HTTPS" != true ]; then
  fallo "alcance 'lan' exige FRONTEND_HTTPS_ENABLED=true. Compartir el frontend en la red del despacho en texto claro expondria la contrasena y el codigo TOTP de cada persona. Prepara el certificado (scripts/frontend/prepare-tls.sh) y vuelve a intentarlo"
fi

if [ "$ALCANCE" = local ] && [ "$HTTPS" != true ] && ! es_loopback "$BIND"; then
  fallo "alcance 'local' con HTTPS deshabilitado solo admite publicacion en loopback, y FRONTEND_HOST_BIND vale '$BIND'. Cambiar solo el bind no es una forma de saltarse el requisito de HTTPS: pon FRONTEND_ACCESS_SCOPE=lan y habilita TLS"
fi

# --- TLS: se comprueba de verdad antes de publicar --------------------------
if [ "$HTTPS" = true ]; then
  command -v openssl >/dev/null 2>&1 ||
    fallo "falta openssl en la imagen: sin el no se puede comprobar el certificado, y no se publica TLS sin comprobarlo"

  [ -f "$CERT" ] || fallo "no existe el certificado montado en $CERT. Prepara secrets/frontend-tls/ (scripts/frontend/prepare-tls.sh)"
  [ -f "$KEY" ]  || fallo "no existe la clave montada en $KEY"
  [ -r "$CERT" ] || fallo "el certificado $CERT no es legible por el usuario del contenedor"
  [ -r "$KEY" ]  || fallo "la clave $KEY no es legible por el usuario del contenedor"
  [ -s "$CERT" ] || fallo "el certificado $CERT esta vacio: el archivo existe pero no hay material TLS. Genera el par con scripts/frontend/prepare-tls.sh"
  [ -s "$KEY" ]  || fallo "la clave $KEY esta vacia"

  openssl x509 -in "$CERT" -noout >/dev/null 2>&1 ||
    fallo "el certificado $CERT no es un PEM X.509 valido"
  openssl pkey -in "$KEY" -noout >/dev/null 2>&1 ||
    fallo "la clave $KEY no es una clave privada PEM valida"

  openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1 ||
    fallo "el certificado $CERT esta caducado o todavia no es valido. Renuevalo: no se sirve TLS con un certificado invalido"
  if ! openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null 2>&1; then
    log "AVISO: el certificado caduca en menos de 7 dias"
  fi

  huella_cert=$(openssl x509 -in "$CERT" -noout -pubkey 2>/dev/null | openssl sha256 | awk '{print $NF}')
  huella_clave=$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}')
  [ -n "$huella_cert" ] && [ "$huella_cert" = "$huella_clave" ] ||
    fallo "el certificado y la clave no se corresponden (su clave publica no coincide). Comprueba que FRONTEND_TLS_CERT_FILE y FRONTEND_TLS_KEY_FILE apuntan al mismo par"

  # Nombres que cubre el certificado: SAN si los hay, y si no el CN.
  nombres=$(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null |
            tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p; s/^[[:space:]]*IP Address://p' |
            tr -d ' ')
  if [ -z "$nombres" ]; then
    nombres=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null |
              sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p' | tr -d ' ')
    [ -n "$nombres" ] && log "AVISO: el certificado no tiene subjectAltName; se usa su CN, que los navegadores modernos ignoran"
  fi
  cubierto=no
  for nombre in $nombres; do
    [ "$nombre" = "$HOST_PUBLICO" ] && cubierto=si && break
    case "$nombre" in
      \*.*)
        sufijo=${nombre#\*}
        case "$HOST_PUBLICO" in
          *"$sufijo") cubierto=si ;;
        esac
        ;;
    esac
    [ "$cubierto" = si ] && break
  done
  [ "$cubierto" = si ] ||
    fallo "el certificado no cubre '$HOST_PUBLICO' (cubre: ${nombres:-ninguno}). Reemitelo con ese nombre o IP en los SAN: el navegador lo rechazaria"

  log "TLS comprobado: PEM valido, vigente, clave coincidente y nombre '$HOST_PUBLICO' cubierto"
fi

# --- render de la configuracion ---------------------------------------------
mkdir -p /tmp/nginx/client /tmp/nginx/proxy /tmp/nginx/fastcgi /tmp/nginx/uwsgi /tmp/nginx/scgi

if [ "$HTTPS" = true ]; then
  if [ "$PUERTO_HTTPS" = 443 ]; then
    VPG_HTTPS_BASE="https://$HOST_PUBLICO"
  else
    VPG_HTTPS_BASE="https://$HOST_PUBLICO:$PUERTO_HTTPS"
  fi
  PLANTILLA="$PLANTILLAS/server-https.conf.template"
else
  VPG_HTTPS_BASE=""
  PLANTILLA="$PLANTILLAS/server-http.conf.template"
fi

export FRONTEND_HTTP_PORT="$PUERTO_HTTP"
export FRONTEND_HTTPS_PORT="$PUERTO_HTTPS"
export FRONTEND_HEALTH_PORT="$PUERTO_SALUD"
export FRONTEND_PUBLIC_HOST="$HOST_PUBLICO"
export VPG_HTTPS_BASE

# La lista de variables NO es opcional: sin ella, envsubst se comeria tambien
# las variables de Nginx ($uri, $request_uri, $http_authorization...).
envsubst '${FRONTEND_HTTP_PORT} ${FRONTEND_HTTPS_PORT} ${FRONTEND_HEALTH_PORT} ${FRONTEND_PUBLIC_HOST} ${VPG_HTTPS_BASE}' \
  < "$PLANTILLA" > "$DESTINO" ||
  fallo "no se pudo escribir $DESTINO (comprueba los permisos del directorio /etc/nginx/vpg)"

if [ "$HTTPS" = true ]; then
  log "modo HTTPS: aplicacion y API solo por $VPG_HTTPS_BASE; el puerto $PUERTO_HTTP solo redirige"
else
  log "modo HTTP (alcance local, loopback): http://$HOST_PUBLICO:$PUERTO_HTTP"
fi
log "salud interna del contenedor: http://127.0.0.1:$PUERTO_SALUD/healthz"

nginx -t -c /etc/nginx/nginx.conf ||
  fallo "la configuracion generada no es valida para Nginx"

exec nginx -c /etc/nginx/nginx.conf -g 'daemon off;'
