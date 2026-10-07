# =============================================================================
# VPG Contadores - infraestructura local (etapas 1-4)
#
# Prepara, arranca, verifica y detiene lo que YA existe en este repositorio:
# vault-service, postgres-service, user-mgmt-service y vault-mgmt-service sobre
# la red network-service. No implementa nada nuevo: solo orquesta compose.yaml,
# las migraciones de sql/ y los scripts de scripts/.
#
# Requisitos: Windows con Docker Desktop (backend WSL 2) en ejecucion, Git Bash
# (Bash 4+ y coreutils), GNU Make 4.0 o posterior y Docker Compose v2. Nada se
# instala automaticamente: si falta algo, se dice que es y como obtenerlo.
#
# -----------------------------------------------------------------------------
# USO (Git Bash). Funciona desde cualquier directorio: el Makefile fija su raiz.
#
#   make            Igual que 'make all' (objetivo predeterminado).
#   make config     PASO PREVIO, una sola vez por volumen de Vault: deja las
#                   credenciales de Vault en archivos del proyecto para que el
#                   arranque no necesite a nadie delante.
#                     secrets/VAULT_UNSEAL_KEY     clave de desbloqueo
#                     secrets/VAULT_INITIAL_TOKEN  token inicial (root)
#                   Si Vault esta SIN inicializar, lo inicializa y guarda las dos
#                   credenciales. Si YA estaba inicializado y los archivos no
#                   existen, Vault no permite releer esa clave: la pide por
#                   teclado (entrada oculta), la PRUEBA y solo entonces la
#                   guarda. No sobrescribe archivos que ya existan.
#   make all        Valida herramientas, resuelve imagenes, arranca PostgreSQL
#                   y Vault, DESBLOQUEA Vault con secrets/VAULT_UNSEAL_KEY y
#                   abre sesion con secrets/VAULT_INITIAL_TOKEN, aplica lo que
#                   falte de migraciones y credenciales tecnicas, comprueba el
#                   administrador y levanta las dos APIs en orden. Sin esos
#                   archivos vuelve al desbloqueo manual y lo dice.
#   make down       Detiene y elimina contenedores y red. CONSERVA volumenes,
#                   imagenes, cache de build, secretos y la inicializacion de
#                   Vault. Funciona con los servicios ya detenidos.
#   make purge      DESTRUCTIVO: borra los datos persistentes del proyecto
#                   (volumenes de Vault y PostgreSQL) y el resto de recursos
#                   exclusivos. Inventaria, muestra lo que borrara y exige
#                   confirmacion escribiendo el nombre del proyecto.
#                   Sin terminal interactiva:
#                     make purge PURGE_CONFIRM=vpg-contadores
#
# Solo esos cuatro objetivos son publicos. Los '.paso-NN-*' son el desglose
# interno de 'make all' y no se invocan a mano.
#
# -----------------------------------------------------------------------------
# LO QUE CUESTA EL ARRANQUE DESATENDIDO
#
# Guardar la Unseal Key y el token inicial en secrets/ es una decision
# deliberada de este entorno local, y conviene saber lo que implica: quien tenga
# esos dos archivos tiene todos los secretos de Vault, y el sellado deja de
# proteger nada mientras existan. Lo que si se mantiene:
#
#   * Los dos archivos viven en secrets/, excluido de Git (.gitignore) y del
#     contexto de build (.dockerignore), con permisos restrictivos.
#   * Sus valores NO se imprimen nunca, no se pasan como argumentos de ningun
#     proceso (viajan por stdin) y no se copian a .env ni a ninguna imagen.
#   * 'make purge' los borra cuando desaparece el volumen de Vault, porque
#     dejan de valer para nada.
#   * Para un entorno compartido, borra los dos archivos y vuelve al desbloqueo
#     manual: 'make all' lo admite y te dice el comando.
#
# Tiempos maximos, en segundos, sobreescribibles en la linea de ordenes
# (p. ej. make all PG_TIMEOUT=300):
#   PG_TIMEOUT PULL_TIMEOUT BUILD_TIMEOUT VAULT_TIMEOUT UNSEAL_TIMEOUT API_TIMEOUT
# y LOCK_STALE, los segundos sin latido tras los que un bloqueo se da por
# abandonado. Ninguna espera es indefinida: todas terminan diciendo que falta.
#
# -----------------------------------------------------------------------------
# LO QUE ESTE MAKEFILE NO HACE, A PROPOSITO
#
#   * No inicializa Vault por su cuenta en 'make all': eso solo lo hace
#     'make config', de forma explicita y una vez por volumen. 'make all'
#     desbloquea con el archivo si existe, y si no, pide el paso manual.
#   * No crea el administrador, ni siembra datos, ni resetea TOTP, ni sincroniza
#     contrasenas. Si falta el administrador, aborta ANTES de iniciar las APIs e
#     indica los scripts exactos.
#   * No ejecuta DDL por su cuenta ni usa create_all(): las migraciones las
#     aplican los scripts del repositorio, y solo si faltan sus objetos.
#   * No imprime .env, tokens, contrasenas, claves de unseal ni semillas TOTP.
#     No carga .env con source ni eval: lo recorre linea a linea y SALTA las
#     claves que puedan ser sensibles, que nunca entran en memoria.
#   * No hace login humano ni CRUD destructivo como prueba de arranque. Para eso
#     estan scripts/vault_mgmt/walkthrough.sh y los smoke-api.sh de cada etapa.
#   * No ejecuta limpieza global de Docker (system prune, builder prune sobre
#     builders compartidos, borrado de todos los volumenes) ni toca recursos de
#     otros proyectos.
#
# -----------------------------------------------------------------------------
# DOS DECISIONES DE FORMA QUE IMPONE WINDOWS
#
# 1. Make lanza cada receta pasandola por la linea de ordenes, que aqui no
#    admite mas de ~8 KB (si se pasa, el shell recibe el guion truncado y falla
#    con 'unexpected EOF'). Por eso 'make all' esta partido en pasos y las
#    funciones comunes se materializan una sola vez en
#    .cache/vpg-make/comun.sh, que cada receta carga con '.'. Ese archivo se
#    reescribe desde este Makefile en cada invocacion real, asi que no puede
#    quedar desfasado, y NO se escribe en un 'make -n'.
# 2. Make no resuelve rutas estilo MSYS (/usr/bin/bash) y acaba usando su sh,
#    que es el mismo bash de Git Bash arrancado como sh. Por eso SHELL se
#    resuelve a una ruta de Windows y las recetas no usan nada que ese modo no
#    admita.
#
# Estado en ejecucion: .cache/vpg-make/ (ya excluido por .gitignore). Contiene
# comun.sh, huellas de build, el bloqueo, el resumen de la ejecucion y cuerpos
# de respuesta temporales. Nunca secretos. 'make purge' lo invalida.
# =============================================================================

ifeq ($(filter 4.% 5.% 6.%,$(MAKE_VERSION)),)
$(error Se necesita GNU Make 4.0 o posterior (hay $(MAKE_VERSION)); Git Bash / winget traen una version valida)
endif

# Detectado ANTES de tocar MAKEFLAGS: con 'make -n' no se escribe nada.
MODO_SECO := $(strip $(findstring n,$(firstword $(MAKEFLAGS))) \
                     $(filter --dry-run --just-print --recon,$(MAKEFLAGS)))

.SHELLFLAGS := -o errexit -o nounset -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := all
# Secuencial incluso con make -j, y sin ruido de directorios.
.NOTPARALLEL:
MAKEFLAGS += --no-print-directory
.SUFFIXES:

# Raiz del proyecto: la del propio Makefile, no la del directorio de invocacion.
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ESTADO := $(ROOT)/.cache/vpg-make
COMUN := $(ESTADO)/comun.sh

# Identificador de ESTA invocacion de make. Lo comparten todos sus pasos, asi
# que el bloqueo se reentra sin abrir ventanas entre pasos.
RUN_ID := $(shell date +%s%N)

PG_TIMEOUT     ?= 240
VAULT_TIMEOUT  ?= 90
UNSEAL_TIMEOUT ?= 900
API_TIMEOUT    ?= 240
PULL_TIMEOUT   ?= 1800
BUILD_TIMEOUT  ?= 3600

# Segundos sin latido tras los cuales un bloqueo se considera abandonado. Cada
# paso late cada 20 s mientras trabaja, asi que este margen solo se agota si el
# proceso murio de malas maneras.
LOCK_STALE ?= 180

# Confirmacion no interactiva de purge: debe valer exactamente el nombre del
# proyecto declarado en compose.yaml.
PURGE_CONFIRM ?=

# -----------------------------------------------------------------------------
# Funciones comunes. Se escriben en $(COMUN) y cada receta hace:
#     TARGET_NAME='<objetivo>'; . "$(COMUN)"
# Aqui no hay ninguna referencia a variables automaticas de Make ($@ y
# companeras) porque esto se expande fuera de contexto de receta.
# -----------------------------------------------------------------------------
define COMUN_SH
# Generado por el Makefile de VPG Contadores. No editar: se reescribe solo.
set +x +v
umask 077

ROOT='$(ROOT)'
ENV_FILE="$$ROOT/.env"
COMPOSE_FILE="$$ROOT/compose.yaml"
STATE_DIR='$(ESTADO)'
LOCK_DIR="$$STATE_DIR/lock"
RESUMEN="$$STATE_DIR/resumen.txt"
ARCHIVO_UNSEAL="$$ROOT/secrets/VAULT_UNSEAL_KEY"
ARCHIVO_TOKEN="$$ROOT/secrets/VAULT_INITIAL_TOKEN"
LOCK_OWNED=0
LIBERAR_AL_SALIR=0
LATIDO_PID=""
CURRENT_STEP="inicio"
BODY_FILE=""
FALLOS=""
BUILD_LIST=""
cd "$$ROOT" || { printf 'ERROR: no se puede entrar en %s\n' "$$ROOT" >&2; exit 1; }

OBJETIVO_PUBLICO=all
case "$${TARGET_NAME:-all}" in
  config) OBJETIVO_PUBLICO=config ;;
  down)   OBJETIVO_PUBLICO=down ;;
  purge)  OBJETIVO_PUBLICO=purge ;;
esac

# ---- mensajes: un estado por paso, siempre saneado -------------------------
sanitize() { printf '%s' "$$*" | tr -d '\000-\010\013\014\016-\037' | tr '\r\n' '  ' | cut -c1-500; }
step() { CURRENT_STEP="$$1"; printf '\n-- %s\n' "$$1"; }
act()  { printf '   EJECUTAR  %s\n' "$$(sanitize "$$*")"; }
skip() { printf '   OMITIR    %s\n' "$$(sanitize "$$*")"; }
info() { printf '   ...       %s\n' "$$(sanitize "$$*")"; }
warn() { printf '   AVISO     %s\n' "$$(sanitize "$$*")" >&2; }
die()  { printf '   ERROR     %s\n' "$$(sanitize "$$*")" >&2; exit 1; }
ok() {
  local texto
  texto=$$(sanitize "$$*")
  printf '   OK        %s\n' "$$texto"
  printf '%s\n' "$$texto" >> "$$RESUMEN" 2>/dev/null || true
}
anotar_fallo() { FALLOS="$$FALLOS$$1"$$'\n'; warn "$$1"; }

# ---- .env: recorrido linea a linea, sin source ni eval ---------------------
# Las claves que puedan ser sensibles (contrasenas, tokens, claves de unseal)
# se SALTAN: no llegan a la memoria de este proceso.
declare -A ENVCACHE
cargar_env() {
  local linea clave valor
  [ -r "$$ENV_FILE" ] || die "falta .env en $$ROOT (copia la plantilla: cp .env.example .env)"
  while IFS= read -r linea || [ -n "$$linea" ]; do
    case "$$linea" in ''|'#'*) continue ;; *=*) ;; *) continue ;; esac
    clave=$${linea%%=*}
    valor=$${linea#*=}
    case "$$clave" in *PASS*|*PASSWORD*|*TOKEN*|*SECRET*|*UNSEAL*|*KEY*) continue ;; esac
    ENVCACHE["$$clave"]=$${valor%$$'\r'}
  done < "$$ENV_FILE"
}
env_get() { printf '%s' "$${ENVCACHE[$$1]:-}"; }
env_req() {
  local valor
  valor=$$(env_get "$$1")
  [ -n "$$valor" ] || die "falta $$1 en .env, o este Makefile lo considera sensible y no lo lee (plantilla: .env.example)"
  printf '%s' "$$valor"
}

# ---- herramientas, archivos y Docker ---------------------------------------
need_tool() { command -v "$$1" >/dev/null 2>&1 || die "falta '$$1' en el PATH. $$2"; }
require_file() { [ -r "$$ROOT/$$1" ] || die "falta el archivo del repositorio: $$1$${2:+ - $$2}"; }
docker_vivo() {
  need_tool docker "Instala Docker Desktop con backend WSL 2 y vuelve a abrir Git Bash."
  docker version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
    die "el daemon de Docker no responde. Arranca Docker Desktop y espera a que indique 'Engine running'"
}
dc() { docker compose "$${DC_ARGS[@]}" "$$@"; }

# ---- bloqueo local, exclusivo de este proyecto -----------------------------
soltar_bloqueo() {
  parar_latido
  if [ "$$LOCK_OWNED" = "1" ]; then
    rm -f "$$LOCK_DIR/run" 2>/dev/null || true
    rmdir "$$LOCK_DIR" 2>/dev/null || true
    LOCK_OWNED=0
  fi
}
limpieza() {
  local rc=$$?
  parar_latido
  rm -f "$$STATE_DIR"/ready-*.json "$$STATE_DIR"/init.*.json "$$STATE_DIR"/init.*.json.err 2>/dev/null || true
  if [ -n "$$BODY_FILE" ] && [ -f "$$BODY_FILE" ]; then rm -f "$$BODY_FILE"; fi
  if [ "$$rc" -ne 0 ]; then
    printf '\n   ERROR     el paso "%s" no termino (codigo %s).\n' "$$CURRENT_STEP" "$$rc" >&2
    printf '             No se ha detenido ningun servicio sano ni se han borrado datos.\n' >&2
    printf '             Corrige lo indicado y reejecuta: make %s\n' "$$OBJETIVO_PUBLICO" >&2
    soltar_bloqueo
  elif [ "$$LIBERAR_AL_SALIR" = "1" ]; then
    soltar_bloqueo
  fi
  return $$rc
}
latir() { if [ "$$LOCK_OWNED" = "1" ]; then touch "$$LOCK_DIR/run" 2>/dev/null || true; fi; }
arrancar_latido() {
  ( while sleep 20; do
      [ -d "$$LOCK_DIR" ] || break
      touch "$$LOCK_DIR/run" 2>/dev/null || break
    done ) >/dev/null 2>&1 &
  LATIDO_PID=$$!
}
parar_latido() {
  if [ -n "$$LATIDO_PID" ]; then kill "$$LATIDO_PID" 2>/dev/null || true; LATIDO_PID=""; fi
}
tomar_bloqueo() {
  local propietario ahora edad limite
  limite=$(LOCK_STALE)
  mkdir -p "$$STATE_DIR" || die "no se puede crear el directorio de estado $$STATE_DIR"
  chmod 700 "$$STATE_DIR" 2>/dev/null || true
  if mkdir "$$LOCK_DIR" 2>/dev/null; then
    printf '%s' "$$RUN_ID" > "$$LOCK_DIR/run"
  else
    propietario=$$(cat "$$LOCK_DIR/run" 2>/dev/null || true)
    if [ "$$propietario" != "$$RUN_ID" ]; then
      ahora=$$(date +%s)
      edad=$$(( ahora - $$(stat -c %Y "$$LOCK_DIR/run" 2>/dev/null || echo 0) ))
      if [ "$$edad" -lt "$$limite" ]; then
        printf '             Si estas seguro de que ese proceso ya no existe, elimina el bloqueo\n' >&2
        printf '             a mano:  rmdir .cache/vpg-make/lock\n' >&2
        die "ya hay un 'make' de este proyecto en curso (ejecucion $$propietario, ultima actividad hace $${edad}s). No se toca un bloqueo que puede estar activo"
      fi
      warn "bloqueo abandonado (ejecucion $$propietario sin latido desde hace $${edad}s, por encima de LOCK_STALE=$${limite}s): se reutiliza"
      printf '%s' "$$RUN_ID" > "$$LOCK_DIR/run"
    fi
  fi
  LOCK_OWNED=1
  latir
  arrancar_latido
  trap 'limpieza' EXIT
  trap 'printf "\n   ERROR     interrumpido por senal\n" >&2; exit 130' INT TERM HUP
}

# ---- identidad del proyecto y parametros NO sensibles de .env --------------
cargar_env
PROJECT_NAME=$$(sed -n 's/^name:[[:space:]]*//p' "$$COMPOSE_FILE" 2>/dev/null | head -n 1 | tr -d '\r')
[ -n "$$PROJECT_NAME" ] || die "compose.yaml no declara \"name:\" o no es legible ($$COMPOSE_FILE)"
case "$$PROJECT_NAME" in [a-z0-9]*) ;; *) die "nombre de proyecto inesperado en compose.yaml: $$PROJECT_NAME" ;; esac
ETIQUETA_PROYECTO="com.docker.compose.project=$$PROJECT_NAME"
DC_ARGS=(--project-directory "$$ROOT" --env-file "$$ENV_FILE" -f "$$COMPOSE_FILE" -p "$$PROJECT_NAME")

VAULT_VERSION=$$(env_req VAULT_VERSION)
POSTGRES_VERSION=$$(env_req POSTGRES_VERSION)
PYTHON_VERSION=$$(env_req PYTHON_VERSION)
USER_MGMT_VERSION=$$(env_req USER_MGMT_VERSION)
VAULT_MGMT_VERSION=$$(env_req VAULT_MGMT_VERSION)
IMG_VAULT="vpg/vault-server:$$VAULT_VERSION"
IMG_PG="vpg/postgres-server:$$POSTGRES_VERSION"
IMG_UM="vpg/user-mgmt-server:$$USER_MGMT_VERSION"
IMG_VM="vpg/vault-mgmt-server:$$VAULT_MGMT_VERSION"
BASE_VAULT="hashicorp/vault:$$VAULT_VERSION"
BASE_PG="postgres:$$POSTGRES_VERSION"
BASE_PY="python:$$PYTHON_VERSION"
PG_DB=$$(env_req POSTGRES_DB)
PG_USER=$$(env_req POSTGRES_USER)
PG_APP=$$(env_req POSTGRES_APP_USER)
PG_SCHEMA=$$(env_req POSTGRES_SCHEMA)
VM_SCHEMA=$$(env_req VAULT_MGMT_POSTGRES_SCHEMA)
NET=$$(env_req DOCKER_NETWORK_NAME)
VOL_VAULT=$$(env_req VAULT_VOLUME_NAME)
VOL_PG=$$(env_req POSTGRES_VOLUME_NAME)
VAULT_BIND=$$(env_req VAULT_HOST_BIND)
VAULT_PORT=$$(env_req VAULT_PORT_LOCAL)
PG_BIND=$$(env_req POSTGRES_HOST_BIND)
PG_PORT=$$(env_req POSTGRES_PORT_LOCAL)
UM_BIND=$$(env_req USER_MGMT_HOST_BIND)
UM_PORT=$$(env_req USER_MGMT_PORT_LOCAL)
VM_BIND=$$(env_req VAULT_MGMT_HOST_BIND)
VM_PORT=$$(env_req VAULT_MGMT_PORT_LOCAL)
UM_URL="http://$$UM_BIND:$$UM_PORT"
VM_URL="http://$$VM_BIND:$$VM_PORT"
TABLAS_EMPLEADOS="users roles user_roles user_profiles user_phones user_addresses user_emails vault_auth_config user_vault_identity vault_operations"
TABLAS_CATALOGO="secret_collections secret_collection_schemas secret_records secret_consumers secret_consumer_bindings secret_operations secret_audit"

# ---- puertos: colision con otro proyecto o con un proceso del host ---------
puerto_libre() {
  local bind="$$1" puerto="$$2" etiqueta="$$3" mio ajeno
  mio=$$(docker ps -a --filter "label=$$ETIQUETA_PROYECTO" --filter "publish=$$puerto" --format '{{.Names}}' 2>/dev/null | head -n 1 | tr -d '\r')
  if [ -n "$$mio" ]; then
    info "puerto $$puerto ($$etiqueta): ya lo reserva $$mio, de este proyecto"
    return 0
  fi
  ajeno=$$(docker ps --filter "publish=$$puerto" --format '{{.Names}} [proyecto: {{.Label "com.docker.compose.project"}}]' 2>/dev/null | head -n 3 | tr '\n' ' ' | tr -d '\r')
  if [ -n "$$ajeno" ]; then
    die "el puerto $$puerto ($$etiqueta) lo publica otro contenedor: $$ajeno. No se eliminan recursos ajenos: libera ese contenedor o cambia el puerto en .env"
  fi
  if command -v netstat >/dev/null 2>&1; then
    if netstat -ano 2>/dev/null | tr -d '\r' | grep -Eq "TCP[[:space:]]+(0\.0\.0\.0|127\.0\.0\.1|\[::\]|\[::1\]|$$bind):$$puerto[[:space:]]+.*LISTENING"; then
      die "el puerto $$puerto ($$etiqueta) ya esta escuchando en este equipo y no es de un contenedor de Docker. Compruebalo con: netstat -ano | grep $$puerto   y cambia el puerto en .env"
    fi
  else
    info "sin netstat: no se comprueba si un proceso del host ocupa el puerto $$puerto"
  fi
}

# ---- imagenes: huella de las entradas reales del build ---------------------
svc_img() {
  case "$$1" in
    vault-service)      printf '%s' "$$IMG_VAULT" ;;
    postgres-service)   printf '%s' "$$IMG_PG" ;;
    user-mgmt-service)  printf '%s' "$$IMG_UM" ;;
    vault-mgmt-service) printf '%s' "$$IMG_VM" ;;
  esac
}
svc_base() {
  case "$$1" in
    vault-service)      printf '%s' "$$BASE_VAULT" ;;
    postgres-service)   printf '%s' "$$BASE_PG" ;;
    user-mgmt-service|vault-mgmt-service) printf '%s' "$$BASE_PY" ;;
  esac
}
svc_target() {
  case "$$1" in
    vault-service)      printf 'vault-server' ;;
    postgres-service)   printf 'postgres-server' ;;
    user-mgmt-service)  printf 'user-mgmt-server' ;;
    vault-mgmt-service) printf 'vault-mgmt-server' ;;
  esac
}
svc_args() {
  case "$$1" in
    vault-service)      printf 'VAULT_VERSION=%s' "$$VAULT_VERSION" ;;
    postgres-service)   printf 'POSTGRES_VERSION=%s' "$$POSTGRES_VERSION" ;;
    user-mgmt-service|vault-mgmt-service) printf 'PYTHON_VERSION=%s' "$$PYTHON_VERSION" ;;
  esac
}
svc_files() {
  case "$$1" in
    vault-service)      printf '%s' "config/vault.hcl docker-entrypoint.sh scripts/vault-auth-bootstrap.sh" ;;
    postgres-service)   printf '%s' "sql/001_employees.sql scripts/postgres/pg-schema.sh scripts/postgres/pg-app-role.sh" ;;
    user-mgmt-service)  printf '%s' "requirements/user_mgmt.txt" ;;
    vault-mgmt-service) printf '%s' "requirements/vault_mgmt.txt" ;;
  esac
}
svc_arbol() {
  case "$$1" in
    vault-service)      printf '%s' "config/policies:*.hcl" ;;
    postgres-service)   printf '%s' "" ;;
    user-mgmt-service|vault-mgmt-service) printf '%s' "app:*.py" ;;
  esac
}
huella_arbol() {
  find "$$ROOT/$$1" -type f -name "$$2" -print0 2>/dev/null | sort -z |
    while IFS= read -r -d '' ruta; do
      printf '%s %s\n' "$${ruta#$$ROOT/}" "$$(sha256sum < "$$ruta" | cut -d' ' -f1)"
    done
}
huella() {
  local svc="$$1" archivo arbol dir patron
  {
    printf 'servicio=%s\n' "$$svc"
    printf 'imagen=%s\n'   "$$(svc_img "$$svc")"
    printf 'target=%s\n'   "$$(svc_target "$$svc")"
    printf 'args=%s\n'     "$$(svc_args "$$svc")"
    for archivo in Dockerfile .dockerignore $$(svc_files "$$svc"); do
      printf '%s %s\n' "$$archivo" "$$(sha256sum < "$$ROOT/$$archivo" | cut -d' ' -f1)"
    done
    for arbol in $$(svc_arbol "$$svc"); do
      dir=$${arbol%%:*}; patron=$${arbol#*:}
      huella_arbol "$$dir" "$$patron"
    done
  } | sha256sum | cut -d' ' -f1
}
decidir_build() {
  local svc="$$1" img fp img_id marcador fp_guardada id_guardada
  img=$$(svc_img "$$svc")
  fp=$$(huella "$$svc")
  marcador="$$STATE_DIR/build-$$svc.fp"
  img_id=$$(docker image inspect --format '{{.Id}}' "$$img" 2>/dev/null | tr -d '\r' || true)
  if [ -z "$$img_id" ]; then
    info "$$svc: $$img no existe localmente; se construye"
    BUILD_LIST="$$BUILD_LIST $$svc"; return 0
  fi
  if [ ! -s "$$marcador" ]; then
    info "$$svc: $$img existe, pero no hay huella registrada; una etiqueta no demuestra que la imagen corresponda a las entradas actuales, asi que se construye"
    BUILD_LIST="$$BUILD_LIST $$svc"; return 0
  fi
  fp_guardada=$$(sed -n '1p' "$$marcador" | tr -d '\r')
  id_guardada=$$(sed -n '2p' "$$marcador" | tr -d '\r')
  if [ "$$id_guardada" != "$$img_id" ]; then
    info "$$svc: la imagen local no es la que registro la ultima construccion; se construye"
    BUILD_LIST="$$BUILD_LIST $$svc"; return 0
  fi
  if [ "$$fp_guardada" != "$$fp" ]; then
    info "$$svc: cambiaron entradas del build (Dockerfile, .dockerignore, contexto efectivo, codigo, requisitos o argumentos); se construye"
    BUILD_LIST="$$BUILD_LIST $$svc"; return 0
  fi
  skip "$$svc: $$img al dia (huella de entradas e id de imagen coinciden)"
}
registrar_huella() {
  local svc="$$1" img img_id
  img=$$(svc_img "$$svc")
  img_id=$$(docker image inspect --format '{{.Id}}' "$$img" 2>/dev/null | tr -d '\r' || true)
  [ -n "$$img_id" ] || die "$$svc: el build termino pero no existe la imagen $$img"
  printf '%s\n%s\n' "$$(huella "$$svc")" "$$img_id" > "$$STATE_DIR/build-$$svc.fp"
  chmod 600 "$$STATE_DIR/build-$$svc.fp" 2>/dev/null || true
}
resolver_imagenes() {
  local svc base bases=""
  BUILD_LIST=""
  for svc in "$$@"; do decidir_build "$$svc"; done
  if [ -z "$$BUILD_LIST" ]; then
    skip "ninguna imagen del proyecto necesita construirse"
    return 0
  fi
  for svc in $$BUILD_LIST; do
    base=$$(svc_base "$$svc")
    case " $$bases " in *" $$base "*) : ;; *) bases="$$bases $$base" ;; esac
  done
  for base in $$bases; do
    if docker image inspect "$$base" >/dev/null 2>&1; then
      skip "imagen base $$base: ya esta en local"
    else
      act "docker pull $$base  (solo porque falta en local)"
      latir
      timeout $(PULL_TIMEOUT) docker pull "$$base" ||
        die "no se pudo descargar la imagen base $$base (limite $(PULL_TIMEOUT)s)"
      ok "imagen base $$base descargada"
    fi
  done
  for svc in $$BUILD_LIST; do
    act "docker compose build $$svc  (sin --no-cache y sin pull forzado)"
    latir
    timeout $(BUILD_TIMEOUT) docker compose "$${DC_ARGS[@]}" build "$$svc" ||
      die "fallo la construccion de $$svc (limite $(BUILD_TIMEOUT)s)"
    registrar_huella "$$svc"
    ok "imagen de $$svc construida y huella de entradas registrada"
  done
}

# ---- PostgreSQL: consultas con la cuenta propietaria, nunca DDL ------------
psql_admin() { dc exec -T postgres-service psql --no-psqlrc -qtAX -U "$$PG_USER" -d "$$PG_DB" "$$@"; }
sql1() { psql_admin -c "$$1" 2>/dev/null | head -n 1 | tr -d '\r' | tr -d '[:space:]'; }
tablas_faltantes() {
  local esquema="$$1" esperadas="$$2" presentes tabla falta=""
  presentes=$$(psql_admin -c "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '$$esquema' AND c.relkind = 'r';" 2>/dev/null | tr -d '\r' || true)
  for tabla in $$esperadas; do
    printf '%s\n' "$$presentes" | grep -Fxq "$$tabla" || falta="$$falta $$tabla"
  done
  printf '%s' "$${falta# }"
}
invariante_permisos() {
  local esq="$$1" remedio="$$2" usage create
  usage=$$(sql1 "SELECT has_schema_privilege('$$PG_APP', '$$esq', 'USAGE');")
  if [ "$$usage" != "t" ]; then
    act "bash $$remedio  (la cuenta de ejecucion $$PG_APP no tiene USAGE en $$esq)"
    bash "$$remedio" || die "$$remedio fallo"
    usage=$$(sql1 "SELECT has_schema_privilege('$$PG_APP', '$$esq', 'USAGE');")
    [ "$$usage" = "t" ] || die "$$PG_APP sigue sin USAGE en $$esq"
  fi
  create=$$(sql1 "SELECT has_schema_privilege('$$PG_APP', '$$esq', 'CREATE');")
  if [ "$$create" = "t" ]; then
    warn "$$PG_APP tiene CREATE en $$esq y el diseno lo prohibe (ninguna aplicacion emite DDL). Ningun script del repositorio lo revoca; hazlo a mano: REVOKE CREATE ON SCHEMA $$esq FROM $$PG_APP;"
  fi
}

# ---- Vault: estados, credenciales en archivo y sesion administrativa -------
# Ningun valor se imprime ni se pasa como argumento: la clave y el token viajan
# siempre por stdin, con el mismo mecanismo que usan los scripts del proyecto
# ('vault write ... key=-' y 'vault login -'). Ojo: 'vault operator unseal -' NO
# sirve, porque manda un guion literal como clave.
VAULT_JSON=""
vault_estado() {
  VAULT_JSON=$$(dc exec -T vault-service vault status -format=json 2>/dev/null | tr -d '\r' || true)
  case "$$VAULT_JSON" in *'"initialized"'*) return 0 ;; esac
  return 1
}
esperar_vault_accesible() {
  local secs="$$1" deadline
  deadline=$$(( $$(date +%s) + secs ))
  while :; do
    if vault_estado; then return 0; fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      die "Vault no responde a 'vault status' en $${secs}s: esta INACCESIBLE, que no es lo mismo que sellado. Revisa: docker compose logs vault-service"
    fi
    latir
    sleep 3
  done
}
vault_campo_falso() { printf '%s' "$$VAULT_JSON" | grep -Eq "\"$$1\"[[:space:]]*:[[:space:]]*false"; }
vault_campo_cierto() { printf '%s' "$$VAULT_JSON" | grep -Eq "\"$$1\"[[:space:]]*:[[:space:]]*true"; }
vault_umbral() {
  local t
  t=$$(printf '%s' "$$VAULT_JSON" | sed -n 's/.*"t"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -n 1)
  printf '%s' "$${t:-1}"
}
guardar_credencial_vault() {
  local ruta="$$1" valor="$$2"
  mkdir -p "$$(dirname "$$ruta")" 2>/dev/null || true
  chmod 700 "$$(dirname "$$ruta")" 2>/dev/null || true
  printf '%s' "$$valor" > "$$ruta" || return 1
  chmod 600 "$$ruta" 2>/dev/null || true
  return 0
}
leer_oculto() {
  local __var="$$1" __prompt="$$2" __valor=""
  printf '%s' "$$__prompt"
  IFS= read -rs -t 300 __valor || true
  printf '\n'
  printf -v "$$__var" '%s' "$$__valor"
}
desbloquear_con_archivo() {
  local umbral
  [ -s "$$ARCHIVO_UNSEAL" ] || return 1
  umbral=$$(vault_umbral)
  if [ "$$umbral" -gt 1 ] 2>/dev/null; then
    warn "Vault exige $$umbral claves para desbloquear y secrets/VAULT_UNSEAL_KEY solo guarda una: el desbloqueo no puede completarse desde aqui"
    return 1
  fi
  act "desbloquear Vault con secrets/VAULT_UNSEAL_KEY (la clave viaja por stdin; no se imprime)"
  dc exec -T vault-service vault write -format=json sys/unseal key=- < "$$ARCHIVO_UNSEAL" >/dev/null 2>&1 || true
  vault_estado || return 1
  if vault_campo_falso sealed; then
    warn "Vault desbloqueado automaticamente: la Unseal Key vive en secrets/VAULT_UNSEAL_KEY, asi que el sellado ya no protege estos datos en este equipo"
    return 0
  fi
  warn "la clave de secrets/VAULT_UNSEAL_KEY no desbloqueo Vault (puede ser de otro volumen)"
  return 1
}
capturar_credenciales_existentes() {
  local clave="" token=""
  info "Vault YA estaba inicializado y Vault no vuelve a mostrar su Unseal Key: hay que suministrarla una vez (la tienes en tu gestor de contrasenas)"
  if [ ! -t 0 ]; then
    printf '             Sin terminal interactiva, escribe los dos archivos a mano. Asi los valores\n' >&2
    printf '             no quedan en el historial ni en los argumentos de ningun proceso:\n' >&2
    printf '               read -rsp "Unseal Key: " K; printf %%s "$$K" > secrets/VAULT_UNSEAL_KEY; unset K\n' >&2
    printf '               read -rsp "Root token: " T; printf %%s "$$T" > secrets/VAULT_INITIAL_TOKEN; unset T\n' >&2
    printf '             O empieza de cero, lo que BORRA los datos:  make purge  y despues  make config\n' >&2
    die "no se pueden capturar credenciales ya existentes sin terminal interactiva"
  fi
  if [ ! -s "$$ARCHIVO_UNSEAL" ]; then
    leer_oculto clave "   Unseal Key de este volumen (entrada oculta, no se imprime): "
    [ -n "$$clave" ] || die "no se escribio ninguna clave: no se ha guardado nada"
    if vault_campo_cierto sealed; then
      printf '%s' "$$clave" | dc exec -T vault-service vault write -format=json sys/unseal key=- >/dev/null 2>&1 || true
      vault_estado || true
      if vault_campo_cierto sealed; then
        clave=""
        die "esa clave NO desbloqueo Vault: no se guarda nada. Comprueba que es la de este volumen"
      fi
      guardar_credencial_vault "$$ARCHIVO_UNSEAL" "$$clave" ||
        die "la clave desbloquea Vault, pero no se pudo escribir en secrets/VAULT_UNSEAL_KEY: comprueba permisos y repite"
      ok "clave probada contra Vault (desbloqueo correcto) y guardada en secrets/VAULT_UNSEAL_KEY"
    else
      guardar_credencial_vault "$$ARCHIVO_UNSEAL" "$$clave" ||
        die "no se pudo escribir en secrets/VAULT_UNSEAL_KEY: comprueba permisos y repite"
      ok "clave guardada en secrets/VAULT_UNSEAL_KEY"
      info "Vault ya estaba desbloqueado, asi que la clave no se ha podido probar ahora: el proximo arranque con Vault sellado lo dira"
    fi
    clave=""
  fi
  if [ ! -s "$$ARCHIVO_TOKEN" ]; then
    leer_oculto token "   Token administrativo de Vault, root o equivalente (Enter para omitirlo): "
    if [ -z "$$token" ]; then
      info "sin token: 'make all' podra desbloquear Vault, pero el bootstrap de AppRole y la consulta de identidad del administrador necesitaran una sesion abierta a mano (docker compose exec vault-service vault login)"
    else
      printf '%s' "$$token" | dc exec -T vault-service vault login -no-print - >/dev/null 2>&1 || true
      if dc exec -T vault-service vault token lookup >/dev/null 2>&1; then
        guardar_credencial_vault "$$ARCHIVO_TOKEN" "$$token" ||
          die "el token es valido, pero no se pudo escribir en secrets/VAULT_INITIAL_TOKEN"
        ok "token probado (abre sesion administrativa) y guardado en secrets/VAULT_INITIAL_TOKEN"
      else
        warn "ese token no abre sesion administrativa en Vault: NO se guarda"
      fi
      token=""
    fi
  fi
}
configurar_credenciales_vault() {
  local tmp clave token
  if [ -s "$$ARCHIVO_UNSEAL" ] && [ -s "$$ARCHIVO_TOKEN" ]; then
    skip "secrets/VAULT_UNSEAL_KEY y secrets/VAULT_INITIAL_TOKEN ya existen: no se sobrescriben (borralos a mano si quieres regenerarlos)"
    return 0
  fi
  if vault_campo_falso initialized; then
    if [ -e "$$ARCHIVO_UNSEAL" ] || [ -e "$$ARCHIVO_TOKEN" ]; then
      printf '             Borra lo que haya quedado y repite:\n' >&2
      printf '               rm -f secrets/VAULT_UNSEAL_KEY secrets/VAULT_INITIAL_TOKEN && make config\n' >&2
      die "Vault esta sin inicializar y en secrets/ hay credenciales de Vault a medias: serian de otro volumen y no se sobrescriben solas"
    fi
    mkdir -p "$$ROOT/secrets" || die "no se puede crear $$ROOT/secrets"
    chmod 700 "$$ROOT/secrets" 2>/dev/null || true
    act "docker compose exec vault-service vault operator init -key-shares=1 -key-threshold=1  (una sola vez por volumen)"
    tmp="$$STATE_DIR/init.$$RUN_ID.json"
    if ! dc exec -T vault-service vault operator init -key-shares=1 -key-threshold=1 -format=json > "$$tmp" 2>"$$tmp.err"; then
      if [ -s "$$tmp.err" ]; then printf '   ...       %s\n' "$$(sanitize "$$(head -c 300 "$$tmp.err")")" >&2; fi
      rm -f "$$tmp" "$$tmp.err"
      die "'vault operator init' fallo: Vault sigue sin inicializar"
    fi
    chmod 600 "$$tmp" 2>/dev/null || true
    clave=$$(tr -d ' \n\r' < "$$tmp" | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')
    token=$$(tr -d ' \n\r' < "$$tmp" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
    if [ -z "$$clave" ] || [ -z "$$token" ]; then
      clave=""; token=""
      mv -f "$$tmp" "$$STATE_DIR/init-RESCATE.json" 2>/dev/null || true
      rm -f "$$tmp.err"
      die "Vault quedo INICIALIZADO pero no se pudieron leer la clave y el token de su salida. NO reinicialices: la salida completa esta en .cache/vpg-make/init-RESCATE.json; saca de ahi los valores, dejalos en secrets/VAULT_UNSEAL_KEY y secrets/VAULT_INITIAL_TOKEN y borra ese archivo"
    fi
    if ! guardar_credencial_vault "$$ARCHIVO_UNSEAL" "$$clave" ||
       ! guardar_credencial_vault "$$ARCHIVO_TOKEN" "$$token"; then
      clave=""; token=""
      mv -f "$$tmp" "$$STATE_DIR/init-RESCATE.json" 2>/dev/null || true
      rm -f "$$tmp.err"
      die "Vault quedo INICIALIZADO pero no se pudo escribir en secrets/. NO reinicialices: la salida completa esta en .cache/vpg-make/init-RESCATE.json; copia de ahi la clave y el token a secrets/VAULT_UNSEAL_KEY y secrets/VAULT_INITIAL_TOKEN, y borra ese archivo"
    fi
    clave=""; token=""
    rm -f "$$tmp" "$$tmp.err"
    ok "Vault inicializado; clave de desbloqueo y token inicial guardados en secrets/ sin imprimirlos"
    warn "COPIA los dos archivos en tu gestor de contrasenas: Vault no vuelve a mostrar esa clave y sin ella los datos del volumen son irrecuperables"
    return 0
  fi
  capturar_credenciales_existentes
}
iniciar_sesion_vault() {
  if [ -s "$$ARCHIVO_TOKEN" ]; then
    dc exec -T vault-service vault login -no-print - < "$$ARCHIVO_TOKEN" >/dev/null 2>&1 || true
    if dc exec -T vault-service vault token lookup >/dev/null 2>&1; then
      ok "sesion administrativa abierta en vault-service con secrets/VAULT_INITIAL_TOKEN (el token viaja por stdin)"
      return 0
    fi
    warn "secrets/VAULT_INITIAL_TOKEN no sirve como token administrativo (revocado, caducado o de otro volumen)"
  fi
  if dc exec -T vault-service vault token lookup >/dev/null 2>&1; then
    skip "sesion administrativa: el contenedor ya tenia una abierta"
    return 0
  fi
  info "sin token administrativo en vault-service: los pasos que preparan AppRole o consultan la identidad del administrador lo diran si lo necesitan ('make config', o 'docker compose exec vault-service vault login')"
  return 1
}

# ---- PostgreSQL: listo de verdad, no solo 'healthy' ------------------------
# Con un volumen vacio, el entrypoint oficial levanta un servidor TEMPORAL para
# ejecutar initdb y lo para antes de arrancar el definitivo. El healthcheck
# puede marcar 'healthy' justo antes de esa parada, asi que pg_isready y el
# SELECT 1 se reintentan hasta el limite en vez de fallar a la primera.
esperar_pg() {
  local secs="$$1" cid estado resultado deadline
  deadline=$$(( $$(date +%s) + secs ))
  cid=$$(dc ps -q postgres-service 2>/dev/null | tr -d '\r' | head -n 1)
  [ -n "$$cid" ] || die "no hay contenedor de postgres-service tras el arranque"
  while :; do
    estado=$$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}sin-healthcheck{{end}}' "$$cid" 2>/dev/null | tr -d '\r' || true)
    if [ "$$estado" = healthy ]; then break; fi
    if [ "$$estado" = unhealthy ]; then
      die "postgres-service esta unhealthy. Revisa: docker compose logs postgres-service"
    fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      die "PostgreSQL no llego a 'healthy' en $${secs}s (ultimo estado: $${estado:-desconocido}). Revisa: docker compose logs postgres-service"
    fi
    latir
    sleep 3
  done
  ok "postgres-service healthy segun su propio healthcheck"
  while :; do
    if dc exec -T postgres-service pg_isready --quiet --username="$$PG_USER" --dbname="$$PG_DB" >/dev/null 2>&1; then break; fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      die "pg_isready no acepta conexiones dentro del contenedor tras $${secs}s. Revisa: docker compose logs postgres-service"
    fi
    info "pg_isready todavia no acepta conexiones (initdb puede estar reiniciando el servidor); se reintenta"
    latir
    sleep 3
  done
  ok "pg_isready acepta conexiones para $$PG_USER/$$PG_DB"
  while :; do
    resultado=$$(dc exec -T postgres-service sh -c 'PGPASSWORD=$$(cat /run/secrets/postgres_app_password) psql --no-psqlrc -qtAX --host=127.0.0.1 --username="$$1" --dbname="$$2" -c "SELECT 1"' sh "$$PG_APP" "$$PG_DB" 2>&1 | tr -d '\r' | tr -d '[:space:]' || true)
    if [ "$$resultado" = "1" ]; then break; fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      die "el SELECT 1 autenticado como $$PG_APP por TCP no devolvio 1 tras $${secs}s. Ultima respuesta: $$resultado"
    fi
    latir
    sleep 3
  done
  ok "SELECT 1 autenticado como $$PG_APP por TCP (la contrasena se lee del archivo de secreto dentro del contenedor)"
}

# ---- APIs: vivo no es listo ------------------------------------------------
detalle_ready() { sed -n 's/.*"detail":"\([^"]*\)".*/\1/p' "$$BODY_FILE" 2>/dev/null | head -n 1; }
checks_falsos() { tr ',' '\n' < "$$BODY_FILE" 2>/dev/null | sed -n 's/.*"\([a-z_]*\)"[[:space:]]*:[[:space:]]*false.*/\1/p' | tr '\n' ' '; }
check_true() { grep -Eq "\"$$1\"[[:space:]]*:[[:space:]]*true" "$$BODY_FILE" 2>/dev/null; }
contenedor_vivo() {
  local cid
  cid=$$(dc ps -q "$$1" 2>/dev/null | tr -d '\r' | head -n 1)
  [ -n "$$cid" ] || return 1
  [ "$$(docker inspect --format '{{.State.Running}}' "$$cid" 2>/dev/null | tr -d '\r')" = "true" ]
}
pistas_ready() {
  local falsos="$$1"
  case "$$falsos" in *vault_unsealed*) printf '             Vault sellado:  docker compose exec vault-service vault operator unseal\n' >&2 ;; esac
  case "$$falsos" in *vault_technical_credential*) printf '             AppRole invalida (p. ej. volumen de Vault sustituido):  bash scripts/user_mgmt/vault-approle-bootstrap.sh --rotate-secret-id\n' >&2 ;; esac
  case "$$falsos" in *admin_linked*) printf '             Vinculo del administrador:  docker compose exec vault-service vpg-auth-bootstrap  y  bash scripts/postgres/seed-initial-user.sh\n' >&2 ;; esac
  case "$$falsos" in *catalog_schema_present*) printf '             Catalogo sin migrar:  bash scripts/vault_mgmt/apply-migrations.sh\n' >&2 ;; esac
  case "$$falsos" in *internal_gateway_authenticated*) printf '             Credencial interna desincronizada:  bash scripts/vault_mgmt/prepare-internal-secret.sh --rotate  y despues  docker compose up -d user-mgmt-service vault-mgmt-service\n' >&2 ;; esac
}
esperar_api() {
  local svc="$$1" base="$$2" secs="$$3" deadline code detalle falsos
  BODY_FILE="$$STATE_DIR/ready-$$svc.json"
  deadline=$$(( $$(date +%s) + secs ))
  while :; do
    code=$$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "$$base/health/live" 2>/dev/null || printf '000')
    if [ "$$code" = "200" ]; then break; fi
    if ! contenedor_vivo "$$svc"; then
      printf '   ...       ultimas lineas de %s:\n' "$$svc" >&2
      dc logs --tail 15 "$$svc" 2>&1 | cut -c1-200 | sed 's/^/             /' >&2 || true
      die "el contenedor de $$svc no esta en marcha: su arranque termino. Si fue la precondicion del administrador, el log lo dice literalmente"
    fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      die "$$svc no responde /health/live en $${secs}s en $$base"
    fi
    latir
    sleep 3
  done
  ok "$$svc responde /health/live (proceso vivo, que todavia no es servicio preparado)"
  while :; do
    code=$$(curl -s --max-time 10 -o "$$BODY_FILE" -w '%{http_code}' "$$base/health/ready" 2>/dev/null || printf '000')
    if [ "$$code" = "200" ]; then break; fi
    if [ "$$(date +%s)" -ge "$$deadline" ]; then
      falsos=$$(checks_falsos)
      detalle=$$(detalle_ready)
      if [ -n "$$falsos" ]; then printf '   ...       comprobaciones en rojo: %s\n' "$$falsos" >&2; fi
      if [ -n "$$detalle" ]; then printf '   ...       diagnostico del servicio: %s\n' "$$(sanitize "$$detalle")" >&2; fi
      pistas_ready "$$falsos"
      die "$$svc sigue respondiendo $$code en /health/ready tras $${secs}s. No se ha detenido nada: corrige lo anterior y reejecuta 'make all'"
    fi
    latir
    sleep 4
  done
}
verificar_checks() {
  local svc="$$1" c
  shift
  for c in "$$@"; do
    check_true "$$c" || die "$$svc responde 200 en /health/ready pero la comprobacion $$c no esta en verde"
  done
}
dns_interno() {
  local svc="$$1" nombres="$$2" salida cuantos esperados
  salida=$$(dc exec -T "$$svc" python -c 'import socket,sys
[print(h, socket.gethostbyname(h)) for h in sys.argv[1:]]' $$nombres 2>&1 | tr -d '\r' || true)
  cuantos=$$(printf '%s\n' "$$salida" | grep -c '^[a-z-]* [0-9]' || true)
  esperados=$$(printf '%s\n' $$nombres | wc -l | tr -d ' ')
  if [ "$$cuantos" != "$$esperados" ]; then
    printf '   ...       %s\n' "$$(sanitize "$$salida")" >&2
    die "$$svc no resuelve por DNS interno todos los nombres de la red $$NET: $$nombres"
  fi
  ok "$$svc resuelve por DNS interno: $$nombres"
}

# ---- purge: inventario y borrado acreditado --------------------------------
inventariar() {
  local linea ref cid
  INV_CONT=$$(docker ps -a --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}}  {{.Names}}  ({{.Status}})' 2>/dev/null | tr -d '\r')
  INV_RED=$$(docker network ls --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}}  {{.Name}}' 2>/dev/null | tr -d '\r')
  INV_VOL=$$(docker volume ls --filter "label=$$ETIQUETA_PROYECTO" --format '{{.Name}}' 2>/dev/null | tr -d '\r')
  DECLARADAS=$$(dc config --images 2>/dev/null | tr -d '\r')
  INV_IMG=""
  while IFS= read -r linea; do
    [ -n "$$linea" ] || continue
    ref=$${linea##*  }
    if printf '%s\n' "$$DECLARADAS" | grep -Fxq "$$ref"; then
      INV_IMG="$$INV_IMG$$linea"$$'\n'
    else
      info "imagen conservada (etiquetada, pero no declarada en compose.yaml: puede ser de otro uso): $$ref"
    fi
  done <<< "$$(docker images --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}}  {{.Repository}}:{{.Tag}}' 2>/dev/null | tr -d '\r')"
  INV_BIND=$$(docker ps -a --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}}' 2>/dev/null | while IFS= read -r cid; do
    if [ -n "$$cid" ]; then docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{println .Source}}{{end}}{{end}}' "$$cid" 2>/dev/null; fi
  done | sed '/^$$/d' | sort -u | tr -d '\r')
}
listar() {
  printf '   %s\n' "$$1"
  if [ -n "$$2" ]; then printf '%s\n' "$$2" | sed 's/^/     /'; else printf '     (ninguno)\n'; fi
}
imprimir_inventario() {
  listar "Contenedores:" "$$INV_CONT"
  listar "Redes:" "$$INV_RED"
  listar "Volumenes (SE BORRAN SUS DATOS):" "$$INV_VOL"
  listar "Imagenes construidas por este proyecto:" "$$INV_IMG"
  listar "Rutas del host montadas como bind por estos contenedores:" "$$INV_BIND"
  printf '     De ellas solo se borraran, por nombre exacto, las credenciales que generan los\n'
  printf '     scripts del proyecto en secrets/. Ninguna otra ruta se toca.\n'
  printf '   Estado local a invalidar: %s\n' "$$STATE_DIR"
  printf '   SE CONSERVAN: codigo, .env, configuracion, imagenes base compartidas, cache de\n'
  printf '     build compartida y los recursos de otros proyectos.\n'
}
confirmar_purga() {
  local confirmacion="$$1" respuesta
  if [ -n "$$confirmacion" ]; then
    [ "$$confirmacion" = "$$PROJECT_NAME" ] ||
      die "PURGE_CONFIRM='$$confirmacion' no coincide con el nombre del proyecto ('$$PROJECT_NAME'). No se ha borrado nada"
    info "confirmacion no interactiva aceptada mediante PURGE_CONFIRM"
  elif [ -t 0 ]; then
    printf '\n   Escribe el nombre del proyecto para CONFIRMAR el borrado (%s): ' "$$PROJECT_NAME"
    IFS= read -r respuesta || respuesta=""
    [ "$$respuesta" = "$$PROJECT_NAME" ] || die "confirmacion incorrecta: no se ha borrado nada"
  else
    die "make purge necesita confirmacion explicita y no hay terminal interactiva. Usa:  make purge PURGE_CONFIRM=$$PROJECT_NAME"
  fi
  ok "borrado confirmado para el proyecto $$PROJECT_NAME"
}
retirar_contenedores_redes_volumenes() {
  local resto vol
  act "docker compose down --volumes --remove-orphans"
  dc down --volumes --remove-orphans ||
    anotar_fallo "'docker compose down --volumes --remove-orphans' devolvio error; se continua con el inventario"
  resto=$$(docker ps -a --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}} {{.Names}}' 2>/dev/null | tr -d '\r')
  if [ -n "$$resto" ]; then
    printf '%s\n' "$$resto" | while IFS=' ' read -r cid cname; do
      if [ -n "$$cid" ]; then
        printf '   EJECUTAR  docker rm -f %s\n' "$$cname"
        docker rm -f "$$cid" >/dev/null 2>&1 || printf '   AVISO     no se pudo eliminar el contenedor %s\n' "$$cname" >&2
      fi
    done
  fi
  for vol in $$INV_VOL; do
    if docker volume inspect "$$vol" >/dev/null 2>&1; then
      act "docker volume rm $$vol"
      docker volume rm "$$vol" >/dev/null 2>&1 || anotar_fallo "no se pudo eliminar el volumen $$vol (puede estar en uso)"
    fi
    docker volume inspect "$$vol" >/dev/null 2>&1 || ok "volumen eliminado: $$vol"
  done
  resto=$$(docker network ls --filter "label=$$ETIQUETA_PROYECTO" --format '{{.ID}} {{.Name}}' 2>/dev/null | tr -d '\r')
  if [ -n "$$resto" ]; then
    printf '%s\n' "$$resto" | while IFS=' ' read -r nid nname; do
      if [ -n "$$nid" ]; then
        printf '   EJECUTAR  docker network rm %s\n' "$$nname"
        docker network rm "$$nid" >/dev/null 2>&1 || printf '   AVISO     no se pudo eliminar la red %s\n' "$$nname" >&2
      fi
    done
  fi
  ok "contenedores, huerfanos y red del proyecto retirados"
}
retirar_imagenes_propias() {
  local linea iid ref usuarios
  if [ -z "$$INV_IMG" ]; then
    skip "no hay imagenes propias que eliminar"
  else
    while IFS= read -r linea; do
      [ -n "$$linea" ] || continue
      iid=$${linea%%  *}; ref=$${linea##*  }
      usuarios=$$(docker ps -a --filter "ancestor=$$iid" --format '{{.Names}}' 2>/dev/null | tr '\n' ' ' | tr -d '\r')
      if [ -n "$$usuarios" ]; then
        info "imagen conservada, la usa otro contenedor: $$ref ($$usuarios)"
        continue
      fi
      act "docker image rm $$ref"
      if docker image rm "$$ref" >/dev/null 2>&1; then
        ok "imagen eliminada: $$ref"
      else
        info "imagen conservada: $$ref (otra imagen o proyecto depende de ella)"
      fi
    done <<< "$$INV_IMG"
  fi
  info "imagenes base compartidas conservadas: la etiqueta de este proyecto no las cubre y otros proyectos pueden usarlas"
}
retirar_cache_build() {
  if docker buildx ls --format '{{.Name}}' 2>/dev/null | tr -d '\r' | grep -Fxq "$$PROJECT_NAME"; then
    act "docker buildx prune --builder $$PROJECT_NAME --force  (builder dedicado al proyecto)"
    docker buildx prune --builder "$$PROJECT_NAME" --force >/dev/null 2>&1 ||
      anotar_fallo "no se pudo limpiar la cache del builder $$PROJECT_NAME"
  else
    skip "cache de build: la compartida NO se toca, y no se crea un builder nuevo solo para poder borrarla. Limitacion asumida: ese espacio no se recupera aqui"
  fi
}
borrar_secreto_generado() {
  local nombre="$$1" ruta="$$ROOT/secrets/$$1"
  if [ ! -e "$$ruta" ]; then info "secrets/$$nombre: no existe"; return 0; fi
  if [ -L "$$ruta" ]; then warn "secrets/$$nombre es un enlace simbolico: no se sigue ni se borra"; return 0; fi
  if [ ! -f "$$ruta" ]; then warn "secrets/$$nombre no es un archivo regular: no se toca"; return 0; fi
  if rm -f "$$ruta"; then ok "credencial generada eliminada: secrets/$$nombre"; else anotar_fallo "no se pudo borrar secrets/$$nombre"; fi
}
retirar_credenciales_desechables() {
  local nombre
  for nombre in postgres_password postgres_app_password vault_role_id vault_secret_id vault_mgmt_internal_token VAULT_UNSEAL_KEY VAULT_INITIAL_TOKEN; do
    case "$$nombre" in
      postgres_password|postgres_app_password)
        if docker volume inspect "$$VOL_PG" >/dev/null 2>&1; then
          info "secrets/$$nombre se conserva: el volumen de PostgreSQL sigue existiendo y esa contrasena todavia vale"
          continue
        fi ;;
      vault_role_id|vault_secret_id)
        if docker volume inspect "$$VOL_VAULT" >/dev/null 2>&1; then
          info "secrets/$$nombre se conserva: el volumen de Vault sigue existiendo y la AppRole todavia vale"
          continue
        fi ;;
      VAULT_UNSEAL_KEY|VAULT_INITIAL_TOKEN)
        if docker volume inspect "$$VOL_VAULT" >/dev/null 2>&1; then
          info "secrets/$$nombre se conserva: el volumen de Vault sigue existiendo y esa credencial todavia lo abre"
          continue
        fi ;;
    esac
    borrar_secreto_generado "$$nombre"
  done
  info "se conservan .env, el codigo, la configuracion y cualquier otro archivo de secrets/ que no genere este proyecto"
}
invalidar_estado_local() {
  if [ -d "$$STATE_DIR" ] && [ ! -L "$$STATE_DIR" ] && [ "$$STATE_DIR" = "$$ROOT/.cache/vpg-make" ]; then
    act "eliminar el estado local $$STATE_DIR"
    LOCK_OWNED=0
    rm -rf "$$STATE_DIR" || anotar_fallo "no se pudo eliminar $$STATE_DIR"
    [ -d "$$STATE_DIR" ] || printf '   OK        estado local invalidado: no quedan huellas que puedan omitir preparacion\n'
  fi
}
verificar_purga() {
  local q_cont q_red q_vol=0 q_img=0 vol linea ref
  q_cont=$$(docker ps -a --filter "label=$$ETIQUETA_PROYECTO" -q 2>/dev/null | sed '/^$$/d' | wc -l | tr -d ' ')
  q_red=$$(docker network ls --filter "label=$$ETIQUETA_PROYECTO" -q 2>/dev/null | sed '/^$$/d' | wc -l | tr -d ' ')
  for vol in $$INV_VOL; do
    if docker volume inspect "$$vol" >/dev/null 2>&1; then q_vol=$$(( q_vol + 1 )); fi
  done
  while IFS= read -r linea; do
    [ -n "$$linea" ] || continue
    ref=$${linea##*  }
    if docker image inspect "$$ref" >/dev/null 2>&1; then q_img=$$(( q_img + 1 )); fi
  done <<< "$$INV_IMG"
  printf '   De los recursos inventariados como exclusivos quedan: %s contenedores, %s redes, %s volumenes, %s imagenes\n' "$$q_cont" "$$q_red" "$$q_vol" "$$q_img"
  printf '   Espacio: Docker libera lo que ocupaban estos recursos en SU almacen. Detener\n'
  printf '     contenedores libera su CPU y su memoria de ejecucion, pero esto no limpia cache\n'
  printf '     del sistema operativo, ni RAM, ni swap, ni compacta el disco virtual de Docker\n'
  printf '     Desktop: lo que Docker recupera no es, sin mas, espacio devuelto al equipo.\n'
  printf '     Tampoco se promete borrado seguro de los datos.\n'
  if [ -n "$$FALLOS" ]; then
    printf '\n'
    die "la limpieza NO esta completa: hubo errores o quedan recursos cuya propiedad no se pudo acreditar. Revisa los AVISO anteriores"
  fi
  if [ "$$q_cont$$q_red$$q_vol$$q_img" = "0000" ]; then
    printf '   OK        no quedan recursos exclusivos de %s\n' "$$PROJECT_NAME"
  else
    die "siguen existiendo recursos inventariados como exclusivos: no se afirma limpieza completa"
  fi
}
endef

# Materializacion de las funciones comunes. Solo en ejecucion real: con
# 'make -n' no se escribe ni se crea nada.
#
# Se escribe primero en un temporal propio de esta invocacion y solo se sustituye
# el archivo definitivo si su contenido cambia, con un mv (renombrado atomico):
# asi otra invocacion simultanea nunca puede leerlo a medio escribir. El RUN_ID
# NO vive aqui, sino en cada receta, para que dos ejecuciones a la vez no se
# pisen la identidad y el bloqueo siga distinguiendolas.
ifeq ($(MODO_SECO),)
$(shell mkdir -p "$(ESTADO)" 2>/dev/null; chmod 700 "$(ESTADO)" 2>/dev/null)
$(file >$(COMUN).$(RUN_ID).tmp,$(COMUN_SH))
$(shell if cmp -s "$(COMUN).$(RUN_ID).tmp" "$(COMUN)" 2>/dev/null; then rm -f "$(COMUN).$(RUN_ID).tmp"; else mv -f "$(COMUN).$(RUN_ID).tmp" "$(COMUN)"; fi; chmod 600 "$(COMUN)" 2>/dev/null)
endif

CARGA = TARGET_NAME='$@'; RUN_ID='$(RUN_ID)'; . "$(COMUN)"

PASOS := .paso-01-validar .paso-02-imagenes .paso-03-arranque .paso-04-postgres \
         .paso-05-vault .paso-06-migraciones .paso-07-administrador \
         .paso-08-credenciales .paso-09-apis .paso-10-resumen

.PHONY: all config down purge $(PASOS)

# =============================================================================
# make config - paso previo: credenciales de Vault en archivos del proyecto
#
# Deja secrets/VAULT_UNSEAL_KEY y secrets/VAULT_INITIAL_TOKEN para que 'make all'
# arranque sin nadie delante. Dos caminos, segun el estado real de Vault:
#
#   * Sin inicializar: 'vault operator init -key-shares=1 -key-threshold=1' y
#     guarda la clave y el token. Es la unica vez que Vault los muestra.
#   * Ya inicializado: Vault no permite releer la clave, asi que la pide por
#     teclado con entrada oculta, la PRUEBA desbloqueando y solo entonces la
#     guarda. El token se prueba igual, abriendo sesion.
#
# Nunca sobrescribe un archivo que ya exista, nunca imprime un valor y nunca
# pasa uno como argumento de un proceso: todo viaja por stdin.
# =============================================================================
config:
	@$(CARGA)
	tomar_bloqueo
	LIBERAR_AL_SALIR=1
	printf '== VPG Contadores: make config (proyecto %s)\n' "$$PROJECT_NAME"
	step "1/3 Requisitos y arranque de Vault"
	docker_vivo
	errores="$$STATE_DIR/compose-config.err"
	if ! dc config --quiet 2>"$$errores"; then
	  if [ -s "$$errores" ]; then printf '   ...       %s\n' "$$(sanitize "$$(head -c 500 "$$errores")")" >&2; fi
	  rm -f "$$errores"
	  die "'docker compose config' rechaza la configuracion. Revisa .env y compose.yaml"
	fi
	rm -f "$$errores"
	ok "compose.yaml valido"
	resolver_imagenes vault-service
	act "docker compose up -d --no-build vault-service"
	dc up -d --no-build vault-service || die "Compose no pudo arrancar vault-service"
	esperar_vault_accesible $(VAULT_TIMEOUT)
	ok "vault-service responde a 'vault status'"
	step "2/3 Credenciales de Vault en secrets/"
	configurar_credenciales_vault
	step "3/3 Comprobacion"
	if vault_campo_cierto sealed; then
	  desbloquear_con_archivo || die "las credenciales guardadas no desbloquean este Vault"
	fi
	iniciar_sesion_vault || true
	vault_estado || true
	if vault_campo_falso sealed; then
	  ok "Vault inicializado y desbloqueado con las credenciales del proyecto"
	else
	  die "Vault sigue sellado: revisa secrets/VAULT_UNSEAL_KEY"
	fi
	printf '\n   Siguiente paso:  make all   (ya no pedira el desbloqueo)\n'
	printf '   Si este volumen de Vault es nuevo, antes hace falta la preparacion de la etapa 1\n'
	printf '   y el alta del administrador, que siguen siendo tuyas porque enrolan un TOTP:\n'
	printf '     docker compose exec vault-service vault secrets enable -path=secret -version=2 kv\n'
	printf '     docker compose exec vault-service vpg-auth-bootstrap\n'
	printf '     bash scripts/postgres/seed-initial-user.sh\n'

# =============================================================================
# make all - arranque ordenado, repetible y sin pasos manuales ocultos
#
# Idempotencia: ningun paso se decide solo por un marcador. Se consulta el
# estado real (imagen e id, tablas y permisos, filas del administrador, archivos
# de secreto, salud y readiness); las huellas de build son un apoyo atado al id
# de la imagen, y las comprobaciones de salud se repiten siempre.
#
# Si un paso falla, los servicios que ya estaban sanos se quedan como estan: no
# hay rollback ni borrado de datos. Se informa del paso y se reanuda con
# 'make all'.
# =============================================================================
all: $(PASOS)
	@printf '\n== make all completado\n'

# --- 1. Herramientas, Docker, archivos, secretos y puertos -------------------
.paso-01-validar:
	@$(CARGA)
	tomar_bloqueo
	: > "$$RESUMEN"
	printf '== VPG Contadores: make all (proyecto %s)\n' "$$PROJECT_NAME"
	step "1/10 Herramientas, conexion con Docker, archivos, secretos y puertos"
	[ "$${BASH_VERSINFO[0]:-0}" -ge 4 ] || die "se necesita Bash 4 o posterior (Git Bash / MSYS2 lo trae)"
	for util in sed grep awk tr cut sort find head tail wc date sleep stat touch mkdir rmdir rm cat sha256sum curl timeout; do
	  need_tool "$$util" "Lo aportan Git for Windows / MSYS2 (coreutils). No se instala nada automaticamente."
	done
	docker_vivo
	cv=$$(docker compose version --short 2>/dev/null | tr -d '\r' || true)
	[ -n "$$cv" ] || die "no hay Compose v2 ('docker compose'). Actualiza Docker Desktop: el 'docker-compose' v1 no sirve"
	mayor=$${cv%%.*}
	case "$$mayor" in ''|*[!0-9]*) die "no se entiende la version de Compose: $$cv" ;; esac
	[ "$$mayor" -ge 2 ] || die "Compose $$cv es v1; se necesita v2 o posterior"
	ok "docker CLI y Compose v$$cv con el daemon accesible"
	for f in compose.yaml Dockerfile .dockerignore config/vault.hcl docker-entrypoint.sh \
	         scripts/vault-auth-bootstrap.sh sql/001_employees.sql sql/002_vault_operations.sql \
	         sql/003_vault_mgmt.sql scripts/postgres/prepare-secrets.sh scripts/postgres/pg-schema.sh \
	         scripts/postgres/pg-app-role.sh scripts/postgres/seed-initial-user.sh \
	         scripts/user_mgmt/apply-migrations.sh scripts/user_mgmt/vault-approle-bootstrap.sh \
	         scripts/vault_mgmt/apply-migrations.sh scripts/vault_mgmt/prepare-internal-secret.sh \
	         requirements/user_mgmt.txt requirements/vault_mgmt.txt; do
	  require_file "$$f"
	done
	[ -d "$$ROOT/config/policies" ] || die "falta el directorio config/policies"
	[ -n "$$(find "$$ROOT/config/policies" -name '*.hcl' -print -quit)" ] || die "config/policies no contiene politicas .hcl"
	[ -d "$$ROOT/app" ] || die "falta el arbol de aplicacion app/"
	ok "archivos, migraciones, politicas y scripts referenciados presentes"
	errores="$$STATE_DIR/compose-config.err"
	if ! dc config --quiet 2>"$$errores"; then
	  if [ -s "$$errores" ]; then printf '   ...       %s\n' "$$(sanitize "$$(head -c 500 "$$errores")")" >&2; fi
	  rm -f "$$errores"
	  die "'docker compose config' rechaza la configuracion. Revisa .env y compose.yaml"
	fi
	rm -f "$$errores"
	ok "compose.yaml valido (validado sin volcar la configuracion expandida)"
	declaradas=$$(dc config --images 2>/dev/null | tr -d '\r')
	for img in "$$IMG_VAULT" "$$IMG_PG" "$$IMG_UM" "$$IMG_VM"; do
	  printf '%s\n' "$$declaradas" | grep -Fxq "$$img" ||
	    die "compose.yaml no declara la imagen $$img; comprueba las versiones de .env"
	done
	ok "las cuatro imagenes del proyecto coinciden con lo declarado en compose.yaml"
	if [ ! -s secrets/postgres_password ]; then
	  if docker volume inspect "$$VOL_PG" >/dev/null 2>&1; then
	    die "falta secrets/postgres_password y el volumen $$VOL_PG ya existe: initdb fijo esa contrasena en la primera inicializacion y generar otra NO la cambia. Recupera el archivo de tu gestor de contrasenas, o empieza de cero con 'make purge' (borra los datos)"
	  fi
	  act "bash scripts/postgres/prepare-secrets.sh  (genera lo que falte; no sobrescribe ni imprime valores)"
	  bash scripts/postgres/prepare-secrets.sh || die "prepare-secrets.sh fallo"
	elif [ ! -s secrets/postgres_app_password ]; then
	  act "bash scripts/postgres/prepare-secrets.sh  (falta el secreto de la cuenta de ejecucion; vpg-pg-roles lo converge)"
	  bash scripts/postgres/prepare-secrets.sh || die "prepare-secrets.sh fallo"
	else
	  skip "secretos de PostgreSQL: los dos archivos ya existen"
	fi
	[ -s secrets/postgres_password ] && [ -s secrets/postgres_app_password ] ||
	  die "siguen faltando los secretos de PostgreSQL en secrets/"
	ok "secretos de PostgreSQL montables como Compose secrets"
	puerto_libre "$$VAULT_BIND" "$$VAULT_PORT" vault-service
	puerto_libre "$$PG_BIND"    "$$PG_PORT"    postgres-service
	puerto_libre "$$UM_BIND"    "$$UM_PORT"    user-mgmt-service
	puerto_libre "$$VM_BIND"    "$$VM_PORT"    vault-mgmt-service
	ok "puertos $$VAULT_PORT, $$PG_PORT, $$UM_PORT y $$VM_PORT sin colisiones"

# --- 2. Imagenes: base solo si falta, build solo si cambian las entradas ------
.paso-02-imagenes:
	@$(CARGA)
	tomar_bloqueo
	step "2/10 Imagenes: base solo si falta, build solo si cambiaron sus entradas"
	docker_vivo
	resolver_imagenes vault-service postgres-service user-mgmt-service vault-mgmt-service

# --- 3. PostgreSQL y Vault, sin levantar todavia las APIs --------------------
.paso-03-arranque:
	@$(CARGA)
	tomar_bloqueo
	step "3/10 PostgreSQL y Vault (todavia sin las APIs)"
	docker_vivo
	act "docker compose up -d --no-build postgres-service vault-service"
	dc up -d --no-build postgres-service vault-service ||
	  die "Compose no pudo arrancar postgres-service y vault-service"
	ok "contenedores de PostgreSQL y Vault en marcha, reutilizando los existentes y conservando los volumenes"
	estampa="$$(docker volume inspect --format '{{.CreatedAt}}' "$$VOL_PG" 2>/dev/null || printf 'sin-volumen')|$$(docker volume inspect --format '{{.CreatedAt}}' "$$VOL_VAULT" 2>/dev/null || printf 'sin-volumen')"
	previa=$$(cat "$$STATE_DIR/instancia" 2>/dev/null || true)
	if [ -n "$$previa" ] && [ "$$previa" != "$$estampa" ]; then
	  info "los volumenes persistentes no son los de la ultima ejecucion: el estado local queda invalidado y ningun paso se omitira por marcadores de la instancia anterior"
	  rm -f "$$STATE_DIR"/instancia-*.done 2>/dev/null || true
	fi
	printf '%s' "$$estampa" > "$$STATE_DIR/instancia"

# --- 4. PostgreSQL listo de verdad ------------------------------------------
.paso-04-postgres:
	@$(CARGA)
	tomar_bloqueo
	step "4/10 PostgreSQL listo: healthy, pg_isready y SELECT 1 autenticado"
	esperar_pg $(PG_TIMEOUT)

# --- 5. Vault: estados distinguidos y unseal manual --------------------------
.paso-05-vault:
	@$(CARGA)
	tomar_bloqueo
	step "5/10 Vault: accesible, inicializado y desbloqueado"
	esperar_vault_accesible $(VAULT_TIMEOUT)
	if vault_campo_falso initialized; then
	  if [ -s "$$ARCHIVO_UNSEAL" ] || [ -s "$$ARCHIVO_TOKEN" ]; then
	    printf '             Si esas credenciales ya no valen, borralas y vuelve a empezar:\n' >&2
	    printf '               rm -f secrets/VAULT_UNSEAL_KEY secrets/VAULT_INITIAL_TOKEN && make config\n' >&2
	    die "Vault esta SIN inicializar pero en secrets/ ya hay credenciales de Vault: son de otro volumen. No se sobrescriben solas ni se inicializa encima"
	  fi
	  printf '             Ejecuta el paso previo, que lo inicializa y guarda sus credenciales:\n' >&2
	  printf '               make config\n' >&2
	  die "Vault esta SIN inicializar. 'make all' no inicializa Vault: eso es trabajo de 'make config', una sola vez por volumen"
	fi
	if vault_campo_cierto sealed; then
	  if [ -s "$$ARCHIVO_UNSEAL" ]; then
	    desbloquear_con_archivo ||
	      die "no se pudo desbloquear Vault con secrets/VAULT_UNSEAL_KEY. Comprueba que ese archivo es la clave de este volumen, o desbloquealo a mano: docker compose exec vault-service vault operator unseal"
	  elif [ -t 0 ] && [ -t 1 ]; then
	    printf '   ...       Vault esta SELLADO y no hay secrets/VAULT_UNSEAL_KEY.\n'
	    printf '             Para que no vuelva a hacer falta nadie delante:  make config\n'
	    printf '             Ahora mismo, desbloquealo a mano en OTRA terminal de Git Bash:\n'
	    printf '                 docker compose exec vault-service vault operator unseal\n'
	    printf '             Esperando la comprobacion, hasta $(UNSEAL_TIMEOUT)s...\n'
	    deadline=$$(( $$(date +%s) + $(UNSEAL_TIMEOUT) ))
	    while :; do
	      latir
	      sleep 5
	      vault_estado || true
	      if vault_campo_falso sealed; then break; fi
	      if [ "$$(date +%s)" -ge "$$deadline" ]; then
	        die "Vault sigue SELLADO tras $(UNSEAL_TIMEOUT)s. Desbloquealo y reejecuta 'make all'"
	      fi
	    done
	  else
	    printf '             Deja el arranque desatendido con:  make config\n' >&2
	    printf '             O desbloquealo ahora a mano y reejecuta make all:\n' >&2
	    printf '               docker compose exec vault-service vault operator unseal\n' >&2
	    die "Vault esta SELLADO, no hay secrets/VAULT_UNSEAL_KEY y no hay terminal interactiva"
	  fi
	fi
	ok "Vault inicializado y DESBLOQUEADO"
	iniciar_sesion_vault || true

# --- 6. Migraciones pendientes y permisos -----------------------------------
.paso-06-migraciones:
	@$(CARGA)
	tomar_bloqueo
	step "6/10 Migraciones pendientes, permisos y objetos del catalogo"
	info "este proyecto no tiene tabla de historial ni checksums de migraciones (lo dice su README): no se puede saber por historial que se aplico, asi que se comprueban OBJETOS e INVARIANTES y solo se actua si falta algo. No se emite DDL en cada arranque ni se usa create_all"
	faltan=$$(tablas_faltantes "$$PG_SCHEMA" "$$TABLAS_EMPLEADOS")
	rol_app=$$(sql1 "SELECT count(*) FROM pg_roles WHERE rolname = '$$PG_APP';")
	if [ -n "$$faltan" ] || [ "$$rol_app" != "1" ]; then
	  if [ -n "$$faltan" ]; then info "faltan en $$PG_SCHEMA: $$faltan"; fi
	  if [ "$$rol_app" != "1" ]; then info "no existe el rol de ejecucion $$PG_APP"; fi
	  act "bash scripts/user_mgmt/apply-migrations.sh  (001, 002 y convergencia de permisos)"
	  bash scripts/user_mgmt/apply-migrations.sh || die "apply-migrations.sh de user_mgmt fallo"
	  faltan=$$(tablas_faltantes "$$PG_SCHEMA" "$$TABLAS_EMPLEADOS")
	  [ -z "$$faltan" ] || die "tras aplicar 001 y 002 siguen faltando tablas en $$PG_SCHEMA: $$faltan"
	  ok "migraciones 001 y 002 aplicadas"
	else
	  skip "migraciones 001 y 002: sus 10 tablas y el rol $$PG_APP ya existen"
	fi
	faltan=$$(tablas_faltantes "$$VM_SCHEMA" "$$TABLAS_CATALOGO")
	if [ -n "$$faltan" ]; then
	  info "faltan en $$VM_SCHEMA: $$faltan"
	  act "bash scripts/vault_mgmt/apply-migrations.sh  (003 y permisos DML minimos del catalogo)"
	  bash scripts/vault_mgmt/apply-migrations.sh || die "apply-migrations.sh de vault_mgmt fallo"
	  faltan=$$(tablas_faltantes "$$VM_SCHEMA" "$$TABLAS_CATALOGO")
	  [ -z "$$faltan" ] || die "tras aplicar 003 siguen faltando tablas en $$VM_SCHEMA: $$faltan"
	  ok "migracion 003 aplicada"
	else
	  skip "migracion 003: las 7 tablas de $$VM_SCHEMA ya existen"
	fi
	invariante_permisos "$$PG_SCHEMA" scripts/user_mgmt/apply-migrations.sh
	invariante_permisos "$$VM_SCHEMA" scripts/vault_mgmt/apply-migrations.sh
	ok "permisos de $$PG_APP comprobados: USAGE en $$PG_SCHEMA y en $$VM_SCHEMA"

# --- 7. Administrador en los dos sistemas, antes de las APIs -----------------
.paso-07-administrador:
	@$(CARGA)
	tomar_bloqueo
	step "7/10 Administrador en PostgreSQL y en Vault, antes de iniciar las APIs"
	JOIN="FROM $$PG_SCHEMA.users u JOIN $$PG_SCHEMA.user_roles ur ON ur.user_id = u.id JOIN $$PG_SCHEMA.roles r ON r.id = ur.role_id AND r.code = 'admin' JOIN $$PG_SCHEMA.user_vault_identity vi ON vi.user_id = u.id JOIN $$PG_SCHEMA.vault_auth_config c ON c.id = vi.vault_auth_config_id WHERE u.is_active"
	cuantos=$$(sql1 "SELECT count(*) $$JOIN;")
	case "$${cuantos:-}" in
	  ''|*[!0-9]*) die "no se pudo consultar el administrador en PostgreSQL (respuesta: $${cuantos:-vacia}); no se concluye que falte" ;;
	esac
	if [ "$$cuantos" = "0" ]; then
	  printf '             Procedimientos existentes, en este orden:\n' >&2
	  printf '               docker compose exec vault-service vpg-auth-bootstrap\n' >&2
	  printf '               bash scripts/postgres/seed-initial-user.sh\n' >&2
	  die "no hay ningun administrador activo con rol 'admin' y vinculo en $$PG_SCHEMA.user_vault_identity. Make no crea administradores ni siembra cuentas: registralo y reejecuta 'make all' (user-mgmt-service aborta su arranque sin esta precondicion)"
	fi
	fila=$$(psql_admin -c "SELECT u.username, vi.vault_username, vi.vault_entity_id, vi.totp_status, c.userpass_path, c.totp_method_id, c.mfa_enforcement_name $$JOIN ORDER BY u.created_at LIMIT 1;" 2>/dev/null | head -n 1 | tr -d '\r')
	IFS='|' read -r ADM_USER ADM_ALIAS ADM_ENT ADM_TOTP ADM_PATH ADM_METHOD ADM_ENF <<< "$$fila"
	[ -n "$${ADM_ENT:-}" ] || die "no se pudo leer el vinculo del administrador en PostgreSQL"
	ok "PostgreSQL: '$$ADM_USER' activo con rol admin, alias userpass '$$ADM_ALIAS' en $$ADM_PATH/, entidad $$ADM_ENT, enforcement $$ADM_ENF, totp_status=$$ADM_TOTP"
	info "totp_status es estado historico: 'pending' no es un fallo y no justifica tocar nada"
	act "bash scripts/postgres/seed-initial-user.sh --dry-run  (consulta de SOLO LECTURA a Vault; no escribe en PostgreSQL)"
	rc=0
	salida=$$(bash scripts/postgres/seed-initial-user.sh --dry-run 2>&1) || rc=$$?
	if [ "$$rc" -eq 0 ]; then
	  v_ent=$$(printf '%s\n' "$$salida" | sed -n 's/^[[:space:]]*vault_entity_id[[:space:].]*:[[:space:]]*//p' | head -n 1 | awk '{print $$1}')
	  v_met=$$(printf '%s\n' "$$salida" | sed -n 's/^[[:space:]]*totp method_id[[:space:].]*:[[:space:]]*//p' | head -n 1 | awk '{print $$1}')
	  v_enf=$$(printf '%s\n' "$$salida" | sed -n 's/^[[:space:]]*mfa enforcement[[:space:].]*:[[:space:]]*//p' | head -n 1)
	  [ -n "$$v_ent" ] || die "la consulta a Vault no devolvio entity_id; no se concluye nada"
	  [ "$$v_ent" = "$$ADM_ENT" ] ||
	    die "el entity_id del alias '$$ADM_ALIAS' en Vault ($$v_ent) no coincide con el registrado en PostgreSQL ($$ADM_ENT): la entidad se recreo. Revisa $$PG_SCHEMA.user_vault_identity antes de tocar nada; para reconciliar, bash scripts/postgres/seed-initial-user.sh"
	  if [ -n "$$v_met" ] && [ "$$v_met" != "$$ADM_METHOD" ]; then
	    die "el method_id del metodo TOTP en Vault ($$v_met) no coincide con el registrado ($$ADM_METHOD): el metodo se recreo. Reconcilia con bash scripts/postgres/seed-initial-user.sh"
	  fi
	  case "$$v_enf" in
	    *"cubre el montaje: yes"*) : ;;
	    *) warn "el enforcement MFA no cubre todo el montaje userpass: $$v_enf" ;;
	  esac
	  ok "Vault: usuario userpass '$$ADM_ALIAS' con entidad $$v_ent, metodo TOTP y enforcement coincidentes con lo registrado"
	else
	  case "$$salida" in
	    *"no hay entidad para el alias"*|*"no existe un metodo MFA TOTP"*|*"no existe el enforcement"*|*"el montaje userpass"*)
	      printf '   ...       %s\n' "$$(sanitize "$$(printf '%s\n' "$$salida" | tail -n 2)")" >&2
	      printf '             Procedimiento existente:\n' >&2
	      printf '               docker compose exec vault-service vpg-auth-bootstrap\n' >&2
	      die "falta la configuracion del administrador en Vault. Make no la crea: ejecutala y reejecuta 'make all'" ;;
	    *"no hay un token valido"*|*"permiso denegado"*|*"conectividad"*|*"sellado"*)
	      warn "el lado Vault no se puede confirmar desde aqui: $$(sanitize "$$(printf '%s\n' "$$salida" | tail -n 1)")"
	      info "un error de token, de permisos o de conectividad NO es ausencia. Lo confirmara la comprobacion admin_linked_in_postgres_and_vault de /health/ready, que usa la cuenta tecnica (AppRole) con permisos de inspeccion legitimos" ;;
	    *)
	      warn "la consulta de solo lectura a Vault no se pudo clasificar: $$(sanitize "$$(printf '%s\n' "$$salida" | tail -n 1)")"
	      info "no se interpreta como ausencia; queda en manos de admin_linked_in_postgres_and_vault en /health/ready" ;;
	  esac
	fi
	info "la inscripcion TOTP individual no se comprueba aqui: Vault no permite releer una semilla ya generada y no se genera ninguna nueva. Que existan el metodo o el enforcement no prueba la inscripcion de una persona; eso lo demuestra un login real con bash scripts/postgres/verify-vault-mfa.sh"

# --- 8. Credenciales tecnicas que el arranque necesita de verdad -------------
.paso-08-credenciales:
	@$(CARGA)
	tomar_bloqueo
	step "8/10 Configuracion tecnica: AppRole de user-mgmt y credencial de la pasarela"
	if [ -s secrets/vault_role_id ] && [ -s secrets/vault_secret_id ]; then
	  skip "AppRole de user-mgmt: role_id y secret_id ya presentes (no se regenera un SecretID valido)"
	else
	  act "bash scripts/user_mgmt/vault-approle-bootstrap.sh  (politica vpg-user-mgmt + AppRole)"
	  bash scripts/user_mgmt/vault-approle-bootstrap.sh ||
	    die "vault-approle-bootstrap.sh fallo. Necesita Vault desbloqueado y un token administrativo en el contenedor ('vault login' en vault-service, o VAULT_INITIAL_TOKEN en .env)"
	  [ -s secrets/vault_role_id ] && [ -s secrets/vault_secret_id ] ||
	    die "el bootstrap de AppRole no dejo role_id y secret_id en secrets/"
	  ok "AppRole de user-mgmt preparada"
	fi
	if [ -s secrets/vault_mgmt_internal_token ]; then
	  skip "credencial interna de la pasarela: ya existe (no se rota una credencial valida)"
	else
	  act "bash scripts/vault_mgmt/prepare-internal-secret.sh  (credencial que leen los DOS servicios)"
	  bash scripts/vault_mgmt/prepare-internal-secret.sh || die "prepare-internal-secret.sh fallo"
	  [ -s secrets/vault_mgmt_internal_token ] || die "no se genero secrets/vault_mgmt_internal_token"
	  ok "credencial interna de la pasarela preparada"
	fi
	skip "politicas KV v2 (scripts/vault_mgmt/vault-kv-policies.sh) y AppRole del crawler (scripts/vault_mgmt/crawler-approle-bootstrap.sh): no son requisito del arranque, readiness no las exige. Se ejecutan a mano cuando haga falta operar el CRUD humano o activar el consumidor"

# --- 9. Las dos APIs, en orden y con readiness real -------------------------
.paso-09-apis:
	@$(CARGA)
	tomar_bloqueo
	step "9/10 APIs en orden: primero user-mgmt-service, despues vault-mgmt-service"
	docker_vivo
	act "docker compose up -d --no-build user-mgmt-service"
	dc up -d --no-build user-mgmt-service || die "Compose no pudo arrancar user-mgmt-service"
	esperar_api user-mgmt-service "$$UM_URL" $(API_TIMEOUT)
	verificar_checks user-mgmt postgres_select_1 vault_initialized vault_unsealed \
	  vault_technical_credential admin_linked_in_postgres_and_vault
	ok "user-mgmt-service listo: conexion a PostgreSQL, Vault desbloqueado, credencial tecnica valida y administrador vinculado en los dos sistemas"
	dns_interno user-mgmt-service "postgres-service vault-service"
	act "docker compose up -d --no-build vault-mgmt-service"
	dc up -d --no-build vault-mgmt-service || die "Compose no pudo arrancar vault-mgmt-service"
	esperar_api vault-mgmt-service "$$VM_URL" $(API_TIMEOUT)
	verificar_checks vault-mgmt postgres_select_1 catalog_schema_present vault_initialized \
	  vault_unsealed user_mgmt_ready internal_gateway_authenticated
	ok "vault-mgmt-service listo: catalogo migrado, Vault desbloqueado, user-mgmt listo y pasarela interna autenticada"
	dns_interno vault-mgmt-service "postgres-service vault-service user-mgmt-service"

# --- 10. Resumen y liberacion del bloqueo -----------------------------------
.paso-10-resumen:
	@$(CARGA)
	tomar_bloqueo
	LIBERAR_AL_SALIR=1
	step "10/10 Resumen"
	dc ps --format "table {{.Service}}\t{{.Name}}\t{{.Status}}" 2>/dev/null | sed 's/^/   /' || true
	printf '\n   Puertos publicados en el host (lo que declara .env):\n'
	printf '     vault-service ......: %s:%s        UI   http://%s:%s/ui\n' "$$VAULT_BIND" "$$VAULT_PORT" "$$VAULT_BIND" "$$VAULT_PORT"
	printf '     postgres-service ...: %s:%s\n' "$$PG_BIND" "$$PG_PORT"
	printf '     user-mgmt-service ..: %s:%s        docs %s/docs\n' "$$UM_BIND" "$$UM_PORT" "$$UM_URL"
	printf '     vault-mgmt-service .: %s:%s        docs %s/docs   redoc %s/redoc\n' "$$VM_BIND" "$$VM_PORT" "$$VM_URL" "$$VM_URL"
	printf '\n   Comprobaciones de esta ejecucion:\n'
	if [ -s "$$RESUMEN" ]; then sed 's/^/     - /' "$$RESUMEN"; else printf '     (sin registro)\n'; fi
	printf '\n   Recordatorios:\n'
	if [ -s "$$ARCHIVO_UNSEAL" ]; then
	  printf '     * Vault arranca SELLADO tras cada reinicio y make all lo desbloquea con\n'
	  printf '       secrets/VAULT_UNSEAL_KEY. Quien tenga ese archivo abre todos los secretos:\n'
	  printf '       borralo para volver al desbloqueo manual.\n'
	else
	  printf '     * Vault arranca SELLADO tras cada reinicio: hay que desbloquearlo a mano, o\n'
	  printf '       dejarlo desatendido con  make config.\n'
	fi
	printf '     * make down conserva volumenes, imagenes y secretos; make purge los borra.\n'
	printf '     * Los recorridos interactivos no son parte del arranque:\n'
	printf '         bash scripts/vault_mgmt/walkthrough.sh      (CRUD de secretos, pide TOTP)\n'
	printf '         bash scripts/postgres/verify-vault-mfa.sh   (login userpass + TOTP real)\n'

# =============================================================================
# make down - detener conservando los datos
#
# 'docker compose down' con el mismo proyecto y la misma configuracion, sin
# --volumes, sin --rmi y sin ningun prune. Funciona con los servicios ya
# detenidos y no necesita Vault desbloqueado ni credenciales de bootstrap.
# =============================================================================
down:
	@$(CARGA)
	tomar_bloqueo
	LIBERAR_AL_SALIR=1
	printf '== VPG Contadores: make down (proyecto %s)\n' "$$PROJECT_NAME"
	step "Detener y eliminar contenedores y red, conservando los datos"
	docker_vivo
	info "sin --volumes, sin --rmi y sin prune: se conservan volumenes, imagenes, cache de build, los archivos de secrets/ y el estado de inicializacion de Vault"
	act "docker compose down"
	dc down || die "'docker compose down' fallo"
	ok "contenedores y red del proyecto eliminados"
	vols=$$(docker volume ls --filter "label=$$ETIQUETA_PROYECTO" --format '{{.Name}}' 2>/dev/null | tr '\n' ' ' | tr -d '\r')
	if [ -n "$$vols" ]; then ok "volumenes conservados: $$vols"; fi
	printf '\n   Siguiente arranque:  make all\n'
	printf '   Vault volvera a arrancar SELLADO: el desbloqueo sigue siendo manual.\n'

# =============================================================================
# make purge - limpieza destructiva, solo de lo que es exclusivo del proyecto
#
# BORRA los datos persistentes de Vault y PostgreSQL. Inventaria por etiquetas
# de Compose, muestra nombres e identificadores y exige confirmacion escribiendo
# el nombre del proyecto. Para uso no interactivo:
#     make purge PURGE_CONFIRM=vpg-contadores
#
# Conserva: codigo, .env, configuracion, imagenes base compartidas, cache de
# build compartida y cualquier recurso cuya propiedad no se pueda acreditar.
# Las unicas rutas del host que borra son las credenciales que generan los
# scripts del proyecto en secrets/, por nombre exacto, y solo cuando el volumen
# al que pertenecen ya no existe: nunca sigue enlaces simbolicos ni toca otra
# ruta. Prohibido por diseno: docker system prune, builder prune sobre builders
# compartidos, borrar todos los volumenes y tocar archivos internos de Docker
# Desktop.
# =============================================================================
purge:
	@$(CARGA)
	tomar_bloqueo
	LIBERAR_AL_SALIR=1
	printf '== VPG Contadores: make purge (proyecto %s)  [DESTRUCTIVO]\n' "$$PROJECT_NAME"
	step "1/5 Inventario de recursos exclusivos (propiedad acreditada por etiquetas de Compose)"
	docker_vivo
	inventariar
	imprimir_inventario
	step "2/5 Confirmacion"
	confirmar_purga '$(PURGE_CONFIRM)'
	step "3/5 Contenedores, huerfanos, red y volumenes del proyecto"
	retirar_contenedores_redes_volumenes
	step "4/5 Imagenes propias, cache de build y credenciales desechables"
	retirar_imagenes_propias
	retirar_cache_build
	retirar_credenciales_desechables
	step "5/5 Verificacion"
	invalidar_estado_local
	verificar_purga
	printf '\n== make purge completado. Para empezar de cero:  make all\n'
	printf '   Vault volvera a estar SIN INICIALIZAR: repite la etapa 1 (init, unseal, KV v2 y\n'
	printf '   vpg-auth-bootstrap) y despues el alta del administrador en PostgreSQL.\n'
