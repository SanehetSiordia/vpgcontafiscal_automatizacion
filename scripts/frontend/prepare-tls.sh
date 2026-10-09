#!/usr/bin/env bash
# Prepara el par TLS del frontend en secrets/frontend-tls/.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/frontend/prepare-tls.sh                    # usa FRONTEND_PUBLIC_HOST
#   bash scripts/frontend/prepare-tls.sh despacho.local 192.168.1.50
#   bash scripts/frontend/prepare-tls.sh --force            # reemplaza el actual
#
# Lo que hace, por orden de preferencia:
#   1. mkcert, si esta instalado. Es la unica via que ademas INSTALA la
#      confianza de su CA en ESTE equipo, asi que el navegador local no avisa.
#   2. openssl del host (Git for Windows lo trae).
#   3. openssl dentro de un contenedor, si el host no lo tiene.
#
# Lo que NO hace:
#   * no sobrescribe un certificado que ya sirve (vigente, con clave que
#     corresponde y que cubre los nombres pedidos). Repetir 'make all' no rota
#     nada: hace falta --force;
#   * no instala confianza en OTROS equipos. Cada equipo del despacho tiene que
#     confiar en la CA a mano, y el README dice como. Prometer lo contrario
#     seria falso: ningun script de este repositorio toca otro equipo;
#   * no imprime la clave privada ni su contenido en ningun momento.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
[[ -r "$ENV_FILE" ]] || { echo "ERROR: falta .env (cp .env.example .env)" >&2; exit 1; }
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

FORCE=false
NOMBRES=()
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    -*) echo "ERROR: opcion desconocida: $arg" >&2; exit 2 ;;
    *) NOMBRES+=("$arg") ;;
  esac
done

PUBLIC_HOST=$(env_get FRONTEND_PUBLIC_HOST); PUBLIC_HOST=${PUBLIC_HOST:-localhost}
CERT_REL=$(env_get FRONTEND_TLS_CERT_FILE); CERT_REL=${CERT_REL:-./secrets/frontend-tls/tls.crt}
# OJO: esta ruta NO se lee con el cargador del Makefile, que salta las claves
# con "KEY" en el nombre por si son secretas. Aqui es una RUTA, no un secreto.
KEY_REL=$(env_get FRONTEND_TLS_KEY_FILE); KEY_REL=${KEY_REL:-./secrets/frontend-tls/tls.key}

CERT="${REPO_ROOT}/${CERT_REL#./}"
KEY="${REPO_ROOT}/${KEY_REL#./}"

if [[ ${#NOMBRES[@]} -eq 0 ]]; then
  NOMBRES=("$PUBLIC_HOST")
  [[ "$PUBLIC_HOST" != localhost ]] && NOMBRES+=(localhost)
  NOMBRES+=(127.0.0.1)
fi

echo "==> Nombres que cubrira el certificado: ${NOMBRES[*]}"

cubre_nombres() {
  local san
  san=$(openssl_cmd x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null |
        tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p; s/^[[:space:]]*IP Address://p' | tr -d ' ')
  local nombre
  for nombre in "${NOMBRES[@]}"; do
    grep -Fxq "$nombre" <<< "$san" || return 1
  done
  return 0
}

# --- herramienta disponible --------------------------------------------------
OPENSSL_MODO=""
if command -v openssl >/dev/null 2>&1; then
  OPENSSL_MODO=host
else
  command -v docker >/dev/null 2>&1 || {
    echo "ERROR: no hay openssl en el PATH ni docker para suplirlo." >&2
    exit 1
  }
  OPENSSL_MODO=docker
  echo "    (sin openssl en el host: se usara openssl dentro de un contenedor)"
fi

# Dos arreglos propios de Git Bash en Windows, los dos imprescindibles:
#
#   1. OPENSSL_CONF. En este tipo de equipos suele apuntar al openssl.cnf de
#      otra instalacion (p. ej. la de PostgreSQL) que ni existe, y entonces
#      'openssl req' falla con "Can't open ... openssl.cnf". Se usa un archivo
#      minimo propio: para un autofirmado con -addext no hace falta nada mas.
#   2. MSYS2_ARG_CONV_EXCL. Sin el, MSYS convierte el argumento "/CN=..." en una
#      ruta de Windows y openssl rechaza el subject. Se excluye SOLO ese prefijo
#      y no toda la conversion (MSYS_NO_PATHCONV=1), porque entonces las rutas
#      absolutas de los demas argumentos llegarian en formato MSYS y el openssl
#      nativo de Windows no sabria abrirlas.
#
# El archivo minimo se escribe con ruta RELATIVA dentro de secrets/frontend-tls/
# (que ya esta fuera de Git) y se pasa asi: con MSYS_NO_PATHCONV activo, una
# ruta absoluta estilo MSYS (/c/Users/...) llegaria sin convertir y el openssl
# nativo de Windows no sabria abrirla.
CNF_MINIMO=""
preparar_cnf() {
  [[ -n "$CNF_MINIMO" ]] && return 0
  local dir
  dir=$(dirname "$CERT_REL")
  mkdir -p "$dir"
  CNF_MINIMO="${dir}/openssl-minimo.cnf"
  printf '[req]
distinguished_name = dn
[dn]
' > "$CNF_MINIMO"
  trap 'rm -f "$CNF_MINIMO"' EXIT
}

openssl_cmd() {
  if [[ "$OPENSSL_MODO" == host ]]; then
    preparar_cnf
    MSYS2_ARG_CONV_EXCL='/CN=;/O=;/C=' OPENSSL_CONF="$CNF_MINIMO" openssl "$@"
  else
    MSYS_NO_PATHCONV=1 docker run --rm -i \
      -v "${REPO_ROOT}/secrets/frontend-tls:/tls" -w /tls \
      alpine:3.21 sh -c 'apk add --no-cache openssl >/dev/null 2>&1; exec openssl "$@"' sh "$@"
  fi
}

# --- conservar lo que ya sirve ----------------------------------------------
if [[ -s "$CERT" && -s "$KEY" && "$FORCE" != true ]]; then
  if openssl_cmd x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1 && cubre_nombres; then
    huella_cert=$(openssl_cmd x509 -in "$CERT" -noout -pubkey 2>/dev/null | openssl_cmd sha256 | awk '{print $NF}')
    huella_clave=$(openssl_cmd pkey -in "$KEY" -pubout 2>/dev/null | openssl_cmd sha256 | awk '{print $NF}')
    if [[ -n "$huella_cert" && "$huella_cert" == "$huella_clave" ]]; then
      echo "==> El certificado actual ya sirve: vigente, con su clave y cubriendo esos nombres."
      openssl_cmd x509 -in "$CERT" -noout -subject -enddate | sed 's/^/    /'
      echo "    No se rota nada. Para reemplazarlo: --force"
      exit 0
    fi
  fi
  echo "    El certificado actual no sirve para estos nombres o esta caducado: se genera otro."
fi

mkdir -p "$(dirname "$CERT")" "$(dirname "$KEY")"
chmod 700 "$(dirname "$CERT")" 2>/dev/null || true

# --- generacion --------------------------------------------------------------
if command -v mkcert >/dev/null 2>&1 && [[ "${VPG_TLS_SIN_MKCERT:-}" != 1 ]]; then
  echo "==> Generando con mkcert (instala la confianza de su CA en ESTE equipo)"
  mkcert -cert-file "$CERT_REL" -key-file "$KEY_REL" "${NOMBRES[@]}"
  echo "    CA de mkcert: $(mkcert -CAROOT)"
  echo "    En los DEMAS equipos del despacho hay que confiar en esa CA a mano:"
  echo "      copia rootCA.pem de ese directorio e instalalo como CA de confianza."
else
  echo "==> Generando un certificado autofirmado con openssl"
  echo "    No hay confianza instalada: el navegador avisara hasta que se"
  echo "    confie en el certificado a mano en cada equipo. mkcert evita eso."
  san=""
  for nombre in "${NOMBRES[@]}"; do
    if [[ "$nombre" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      san+="IP:${nombre},"
    else
      san+="DNS:${nombre},"
    fi
  done
  san=${san%,}
  openssl_cmd req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout "$(basename "$KEY")" -out "$(basename "$CERT")" \
    -subj "/CN=${NOMBRES[0]}/O=VPG Contadores (local)" \
    -addext "subjectAltName=${san}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>"${TMPDIR:-/tmp}/vpg-openssl.err" ||
    {
      echo "ERROR: openssl no pudo generar el par:" >&2
      tail -n 5 "${TMPDIR:-/tmp}/vpg-openssl.err" >&2 || true
      rm -f "${TMPDIR:-/tmp}/vpg-openssl.err"
      exit 1
    }
  rm -f "${TMPDIR:-/tmp}/vpg-openssl.err"
  # Con el modo contenedor los archivos se escriben en el directorio montado;
  # con el modo host hay que moverlos si no estamos ya ahi.
  if [[ "$OPENSSL_MODO" == host ]]; then
    [[ -f "$(basename "$CERT")" ]] && mv -f "$(basename "$CERT")" "$CERT"
    [[ -f "$(basename "$KEY")" ]] && mv -f "$(basename "$KEY")" "$KEY"
  fi
fi

[[ -s "$CERT" && -s "$KEY" ]] || { echo "ERROR: no se genero el par TLS." >&2; exit 1; }
chmod 600 "$CERT" "$KEY" 2>/dev/null || true

echo
echo "==> Par TLS listo (la clave no se imprime):"
openssl_cmd x509 -in "$CERT" -noout -subject -enddate -ext subjectAltName 2>/dev/null | sed 's/^/    /'
echo
echo "Siguiente paso: pon FRONTEND_HTTPS_ENABLED=true en .env y ejecuta 'make all'."
echo "Para compartirlo en el despacho ademas: FRONTEND_ACCESS_SCOPE=lan,"
echo "FRONTEND_HOST_BIND con la interfaz y FRONTEND_PUBLIC_HOST con el nombre o IP."
