#!/usr/bin/env bash
# Prepara la identidad de MAQUINA del futuro crawler: AppRole dedicada de solo
# lectura, politica minima, TTL cortos, y su registro en el catalogo.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/crawler-approle-bootstrap.sh
#   bash scripts/vault_mgmt/crawler-approle-bootstrap.sh --rotate-secret-id
#   bash scripts/vault_mgmt/crawler-approle-bootstrap.sh --revoke
#
# Que hace, de forma idempotente:
#   1. Escribe la politica 'vpg-crawler' (solo lectura del prefijo gestionado).
#   2. Habilita un montaje AppRole PROPIO (approle-crawler), separado del de
#      user-mgmt: asi se puede revocar la maquina sin tocar la cuenta tecnica.
#   3. Crea o actualiza el rol con esa politica y TTL cortos.
#   4. Registra el consumidor en vault_mgmt.secret_consumers.
#   5. Muestra role_id y secret_id UNA sola vez, por stdout y nada mas.
#
# Por que una AppRole dedicada y no la api_session de un empleado:
#   Una api_session es de una persona, lleva MFA y caduca con su sesion. Un
#   proceso desatendido no puede tenerla, y prestarsela convertiria a la maquina
#   en ese empleado. La AppRole tiene sus propios permisos, su propio TTL y se
#   revoca por si sola.
#
# role_id y secret_id NO se guardan en el repositorio ni en el catalogo: el
# catalogo solo registra el montaje, el rol y la politica esperados, para poder
# comprobar la identidad del token que se presente.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

ROTATE=false
REVOKE=false
for arg in "$@"; do
  case "$arg" in
    --rotate-secret-id) ROTATE=true ;;
    --revoke) REVOKE=true ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "ERROR: argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

KV_MOUNT=$(env_get VAULT_MGMT_KV_MOUNT);   KV_MOUNT=${KV_MOUNT:-secret}
KV_PREFIX=$(env_get VAULT_MGMT_KV_PREFIX); KV_PREFIX=${KV_PREFIX:-vpg-managed}
APPROLE_MOUNT=$(env_get VAULT_CRAWLER_APPROLE_MOUNT); APPROLE_MOUNT=${APPROLE_MOUNT:-approle-crawler}
ROLE_NAME=$(env_get VAULT_CRAWLER_ROLE_NAME); ROLE_NAME=${ROLE_NAME:-vpg-crawler}
POLICY_NAME=$(env_get VAULT_CRAWLER_POLICY); POLICY_NAME=${POLICY_NAME:-vpg-crawler}
CONSUMER_NAME=$(env_get VAULT_CRAWLER_CONSUMER_NAME); CONSUMER_NAME=${CONSUMER_NAME:-crawler-sat}

PG_DB=$(env_get POSTGRES_DB);     PG_DB=${PG_DB:-vpg_contadores}
PG_USER=$(env_get POSTGRES_USER); PG_USER=${PG_USER:-vpg_admin}
VM_SCHEMA=$(env_get VAULT_MGMT_POSTGRES_SCHEMA); VM_SCHEMA=${VM_SCHEMA:-vault_mgmt}

echo "==> Comprobando Vault"
docker compose exec -T vault-service sh -s <<'PRECHECK'
set -eu
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
status=0; vault status >/dev/null 2>&1 || status=$?
case "$status" in
  0) ;;
  2) echo "ERROR: Vault esta sellado o sin inicializar. Desbloquealo primero." >&2; exit 1 ;;
  *) echo "ERROR: Vault no responde." >&2; exit 1 ;;
esac
vault token lookup >/dev/null 2>&1 \
  || { echo "ERROR: sin token administrativo valido en el contenedor." >&2; exit 1; }
PRECHECK

if [[ "$REVOKE" == true ]]; then
  echo "==> Revocando el consumidor '${CONSUMER_NAME}'"
  echo "    1. Se invalidan sus secret_id en Vault (no podra volver a entrar)."
  docker compose exec -T vault-service sh -s "$APPROLE_MOUNT" "$ROLE_NAME" <<'REVOKE'
set -eu
APPROLE_MOUNT=$1; ROLE_NAME=$2
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
# Destruye todos los secret_id del rol. Los TOKENS ya emitidos siguen vivos
# hasta su TTL: por eso el TTL es corto y por eso esto no es instantaneo.
vault write -f "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}/secret-id-num-uses" \
  secret_id_num_uses=1 >/dev/null 2>&1 || true
vault delete "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}" >/dev/null
echo "    rol ${ROLE_NAME} eliminado del montaje ${APPROLE_MOUNT}/"
REVOKE
  echo "    2. Se marca revocado en el catalogo (deja de preparar entregas)."
  docker compose exec -T postgres-service \
    psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet -U "$PG_USER" -d "$PG_DB" -c "
UPDATE ${VM_SCHEMA}.secret_consumers
   SET state = 'revoked', revoked_at = now()
 WHERE name = '${CONSUMER_NAME}';"
  echo
  echo "    AVISO: revocar NO caduca un wrapping token ya entregado ni borra lo"
  echo "    que el consumidor ya leyo. Lo que impide son entregas FUTURAS y"
  echo "    nuevos logins. Un token suyo ya emitido vive hasta su TTL."
  echo "    Para cortar tambien los tokens vivos:"
  echo "      docker compose exec vault-service vault lease revoke -prefix auth/${APPROLE_MOUNT}/login"
  exit 0
fi

echo
echo "==> Escribiendo la politica '${POLICY_NAME}' (solo lectura de ${KV_MOUNT}/data/${KV_PREFIX}/*)"
docker compose exec -T vault-service sh -c '
  set -eu
  if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
    VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
  fi
  vault policy write "$1" - >/dev/null
  echo "    politica escrita"
' vpg-policy-write "$POLICY_NAME" <<POLICY
# Generada por scripts/vault_mgmt/crawler-approle-bootstrap.sh.
# Solo lectura, y solo del prefijo gestionado. Sin escritura, sin borrado, sin
# metadata y sin list: el consumidor resuelve por UUID, no explora el arbol.
path "${KV_MOUNT}/data/${KV_PREFIX}/*" {
  capabilities = ["read"]
}
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}
path "sys/wrapping/unwrap" {
  capabilities = ["update"]
}
path "sys/wrapping/lookup" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
POLICY

echo "==> Habilitando el montaje AppRole '${APPROLE_MOUNT}/' y el rol '${ROLE_NAME}'"
docker compose exec -T vault-service sh -s "$APPROLE_MOUNT" "$ROLE_NAME" "$POLICY_NAME" <<'ROLE'
set -eu
APPROLE_MOUNT=$1; ROLE_NAME=$2; POLICY_NAME=$3
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
if ! vault auth list 2>/dev/null | grep -q "^${APPROLE_MOUNT}/ "; then
  vault auth enable -path="$APPROLE_MOUNT" \
    -description="Identidad de maquina del crawler (solo lectura)" approle >/dev/null
  echo "    auth approle habilitado en ${APPROLE_MOUNT}/"
else
  echo "    auth approle ya estaba habilitado en ${APPROLE_MOUNT}/"
fi

# TTL cortos: el token de la maquina vive poco y se renueva o se vuelve a
# autenticar. secret_id_ttl mas corto que el de user-mgmt porque esta credencial
# vive en la configuracion de un proceso desatendido.
vault write "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}" \
  token_policies="$POLICY_NAME" \
  token_ttl=20m \
  token_max_ttl=1h \
  token_num_uses=0 \
  secret_id_ttl=168h \
  secret_id_num_uses=0 \
  bind_secret_id=true >/dev/null
echo "    rol ${ROLE_NAME} configurado (politica ${POLICY_NAME}, token_ttl 20m)"
ROLE

echo
echo "==> Registrando el consumidor '${CONSUMER_NAME}' en el catalogo"
docker compose exec -T postgres-service \
  psql -v ON_ERROR_STOP=1 --no-psqlrc -qtAX -U "$PG_USER" -d "$PG_DB" -c "
INSERT INTO ${VM_SCHEMA}.secret_consumers
       (name, description, approle_mount, approle_role_name, expected_policy, state)
VALUES ('${CONSUMER_NAME}',
        'Identidad de maquina del futuro crawler (solo lectura)',
        '${APPROLE_MOUNT}', '${ROLE_NAME}', '${POLICY_NAME}', 'active')
ON CONFLICT (name) DO UPDATE
   SET approle_mount     = EXCLUDED.approle_mount,
       approle_role_name = EXCLUDED.approle_role_name,
       expected_policy   = EXCLUDED.expected_policy,
       state             = 'active',
       revoked_at        = NULL
RETURNING consumer_id;" | tr -d '\r' | sed 's/^/    consumer_id: /'

echo
echo "==> Credenciales de la maquina (se muestran UNA vez; no se guardan aqui)"
docker compose exec -T vault-service sh -s "$APPROLE_MOUNT" "$ROLE_NAME" "$ROTATE" <<'CREDS'
set -eu
APPROLE_MOUNT=$1; ROLE_NAME=$2; ROTATE=$3
if [ -z "${VAULT_TOKEN:-}" ] && [ ! -s "${HOME}/.vault-token" ] && [ -n "${VAULT_INITIAL_TOKEN:-}" ]; then
  VAULT_TOKEN=$VAULT_INITIAL_TOKEN; export VAULT_TOKEN
fi
printf '    role_id   : %s\n' "$(vault read -field=role_id "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}/role-id")"
if [ "$ROTATE" = "true" ]; then
  printf '    secret_id : %s\n' "$(vault write -f -field=secret_id "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}/secret-id")"
  echo "    (secret_id NUEVO; el anterior sigue valido hasta su TTL salvo que se destruya)"
else
  printf '    secret_id : %s\n' "$(vault write -f -field=secret_id "auth/${APPROLE_MOUNT}/role/${ROLE_NAME}/secret-id")"
fi
CREDS

cat <<'NEXT'

    Guarda esos dos valores en el gestor de contrasenas del equipo y limpia la
    pantalla. No se escriben en el repositorio, ni en el .env, ni en el catalogo.

    Siguiente paso: asignarle registros (solo admin, con su api_session):
      PUT http://127.0.0.1:8001/vault_mgmt/v1/vault/consumers/{consumer_id}/bindings

    Prueba de consumo con datos ficticios:
      python scripts/vault_mgmt/crawler-client.py \
        --role-id <role_id> --secret-id <secret_id> \
        --collection-id <uuid> --record-id <uuid>
NEXT
