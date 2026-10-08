#!/usr/bin/env bash
# Comprobaciones NO interactivas de vault-mgmt-service.
#
# Uso (host, Git Bash, desde la raiz del repositorio):
#   bash scripts/vault_mgmt/smoke-api.sh
#
# Que comprueba, sin pedir ninguna credencial:
#   1. Salud: live responde aunque Vault este sellado; ready dice que falta.
#   2. Documentacion: Swagger, ReDoc y OpenAPI, con las rutas del contrato
#      (25 rutas y 35 operaciones desde la etapa 4.6).
#   3. Que la pasarela interna NO esta en el OpenAPI publico.
#   4. Que la pasarela interna exige SUS DOS credenciales, probandola desde
#      otro contenedor de la red (que es de donde vendria un atacante interno).
#   5. DNS y conectividad entre servicios por nombre.
#   6. Que el puerto se publica solo en el loopback del host.
#   7. Que los endpoints de negocio exigen sesion.
#
# Lo que NO hace: no inicia sesion, no crea colecciones y no escribe en Vault.
# El recorrido completo necesita un codigo TOTP de una persona y esta en el
# README (etapa 4) y en la coleccion de Postman.
set -Eeuo pipefail

trap 'rc=$?; printf "\nERROR INTERNO: linea %s, codigo %s.\n  Orden: %s\n" \
      "$LINENO" "$rc" "$BASH_COMMAND" >&2' ERR

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
ENV_FILE="${REPO_ROOT}/.env"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | head -n 1 | tr -d '\r'; }

VM_PORT=$(env_get VAULT_MGMT_PORT_LOCAL); VM_PORT=${VM_PORT:-8001}
UM_PORT=$(env_get USER_MGMT_PORT_LOCAL);  UM_PORT=${UM_PORT:-8000}
VM_PREFIX=$(env_get VAULT_MGMT_API_PREFIX); VM_PREFIX=${VM_PREFIX:-/vault_mgmt/v1}
VM_BASE="http://127.0.0.1:${VM_PORT}"

fallos=0
ok()   { printf '    [ ok ] %s\n' "$1"; }
fail() { printf '    [FALLO] %s\n' "$1"; fallos=$((fallos + 1)); }

code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }

echo "==> 1. Salud"
if [[ "$(code "${VM_BASE}/health/live")" == "200" ]]; then
  ok "live responde 200 (el proceso esta vivo)"
else
  fail "live no responde 200: el contenedor no esta arriba"
fi

ready_code=$(code "${VM_BASE}/health/ready")
ready_body=$(curl -s "${VM_BASE}/health/ready")
case "$ready_code" in
  200) ok "ready responde 200: el servicio puede atender negocio" ;;
  503)
    ok "ready responde 503, que es correcto si falta una dependencia"
    echo "           detalle: $(printf '%s' "$ready_body" \
      | python -c 'import json,sys; print(json.load(sys.stdin)["detail"] or "")' 2>/dev/null \
      || echo '(ilegible)')"
    echo "           lo habitual en local: Vault sellado. El unseal es MANUAL:"
    echo "             docker compose exec vault-service vault operator unseal"
    ;;
  *) fail "ready responde ${ready_code}, que no es 200 ni 503" ;;
esac

echo
echo "==> 2. Documentacion y contrato"
for ruta in /docs /redoc /openapi.json; do
  if [[ "$(code "${VM_BASE}${ruta}")" == "200" ]]; then
    ok "${ruta} responde 200"
  else
    fail "${ruta} no responde 200"
  fi
done

# Se cuentan DOS cosas, porque son dos numeros distintos y confundirlos ya dejo
# este smoke desfasado una vez: PATHS son rutas unicas y OPERACIONES son pares
# metodo+ruta (una misma ruta con GET y PUT son dos operaciones).
conteo=$(curl -s "${VM_BASE}/openapi.json" | python -c '
import json, sys
spec = json.load(sys.stdin)["paths"]
print(len(spec), sum(len(ops) for ops in spec.values()))' 2>/dev/null || echo "0 0")
rutas=${conteo%% *}
operaciones=${conteo##* }
# Cota inferior y no un numero exacto: anadir un endpoint no deberia romper el
# smoke, y quedarse corto si deberia. En la etapa 4.6 son 25 rutas y 35
# operaciones (las de consumidores incluidas).
if [[ "$rutas" -ge 25 && "$operaciones" -ge 35 ]]; then
  ok "el OpenAPI publica ${rutas} rutas y ${operaciones} operaciones"
else
  fail "el OpenAPI solo publica ${rutas} rutas y ${operaciones} operaciones (se esperaban 25 y 35)"
fi

esquemas=$(curl -s "${VM_BASE}/openapi.json" | python -c \
  'import json,sys; print(",".join(sorted(json.load(sys.stdin)["components"]["securitySchemes"])))' \
  2>/dev/null || echo "")
if [[ "$esquemas" == "ApiSession,VaultMachineToken" ]]; then
  ok "declara las dos autenticaciones: ApiSession y VaultMachineToken"
else
  fail "esquemas de seguridad inesperados: ${esquemas}"
fi

echo
echo "==> 3. La pasarela interna NO esta en el OpenAPI publico"
internas=$(curl -s "${VM_BASE}/openapi.json" | python -c \
  'import json,sys; print(len([r for r in json.load(sys.stdin)["paths"] if r.startswith("/internal")]))' \
  2>/dev/null || echo "?")
if [[ "$internas" == "0" ]]; then
  ok "cero rutas /internal en vault-mgmt"
else
  fail "hay ${internas} rutas /internal en el OpenAPI publico"
fi
internas_um=$(curl -s "http://127.0.0.1:${UM_PORT}/openapi.json" | python -c \
  'import json,sys; print(len([r for r in json.load(sys.stdin)["paths"] if r.startswith("/internal")]))' \
  2>/dev/null || echo "?")
if [[ "$internas_um" == "0" ]]; then
  ok "cero rutas /internal en user-mgmt (include_in_schema=False)"
else
  fail "hay ${internas_um} rutas /internal en el OpenAPI de user-mgmt"
fi

echo
echo "==> 4. La pasarela interna exige SUS DOS credenciales"
echo "    (se prueba desde vault-mgmt-service: la red interna no autentica a nadie)"
if docker compose ps --status running --services 2>/dev/null | grep -q '^vault-mgmt-service$'; then
  salida=$(docker compose exec -T vault-mgmt-service python - <<'PY' 2>/dev/null || true
import json, urllib.request, urllib.error

URL = "http://user-mgmt-service:8000/internal/v1/vault-mgmt/session"

def probe(label, headers):
    req = urllib.request.Request(
        URL, data=b"{}", method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"{label}|{r.status}|")
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            pass
        print(f"{label}|{e.code}|{body.get('code','')}")
    except Exception as exc:
        print(f"{label}|error|{exc}")

probe("sin-nada", {})
probe("credencial-mala", {"X-VPG-Internal-Credential": "no-es-la-buena"})
try:
    cred = open("/run/secrets/vault_mgmt_internal_token").read().strip()
    probe("credencial-ok-sin-bearer", {"X-VPG-Internal-Credential": cred})
except OSError:
    print("credencial-ok-sin-bearer|sin-secreto|")
PY
)
  while IFS='|' read -r etiqueta estado detalle; do
    [[ -z "$etiqueta" ]] && continue
    case "$etiqueta:$estado" in
      sin-nada:401|credencial-mala:401)
        ok "${etiqueta}: 401 (${detalle:-sin codigo})" ;;
      credencial-ok-sin-bearer:401)
        ok "credencial correcta pero sin Bearer: 401 (${detalle})" ;;
      credencial-ok-sin-bearer:503)
        ok "credencial correcta: 503 porque falta una dependencia (Vault sellado)" ;;
      *)
        fail "${etiqueta}: respuesta inesperada ${estado} ${detalle}" ;;
    esac
  done <<< "$salida"
else
  fail "vault-mgmt-service no esta en ejecucion: no se puede probar la pasarela"
fi

echo
echo "==> 5. DNS y conectividad entre servicios, por nombre"
if docker compose ps --status running --services 2>/dev/null | grep -q '^vault-mgmt-service$'; then
  docker compose exec -T vault-mgmt-service python - <<'PY' || fallos=$((fallos + 1))
import socket, sys
fallos = 0
for host, port in (
    ("postgres-service", 5432),
    ("vault-service", 8200),
    ("user-mgmt-service", 8000),
):
    try:
        ip = socket.gethostbyname(host)
        with socket.create_connection((host, port), timeout=3):
            print(f"    [ ok ] {host}:{port} resuelve a {ip} y acepta conexion")
    except OSError as exc:
        print(f"    [FALLO] {host}:{port}: {exc}")
        fallos += 1
sys.exit(1 if fallos else 0)
PY
fi

echo
echo "==> 6. Publicacion del puerto"
puertos=$(docker compose ps vault-mgmt-service --format '{{.Ports}}' 2>/dev/null || echo "")
if [[ "$puertos" == *"127.0.0.1:${VM_PORT}->"* ]]; then
  ok "publicado solo en loopback: ${puertos}"
elif [[ -z "$puertos" ]]; then
  fail "el servicio no esta arriba"
else
  fail "publicado fuera del loopback: ${puertos}"
fi

echo
echo "==> 7. Los endpoints de negocio exigen sesion"
sin_sesion=$(code "${VM_BASE}${VM_PREFIX}/vault/collections")
case "$sin_sesion" in
  401) ok "sin Authorization: 401" ;;
  503) ok "503 porque el servicio no esta listo (Vault sellado); repite tras el unseal" ;;
  *)   fail "sin Authorization responde ${sin_sesion}, se esperaba 401 o 503" ;;
esac

inventada=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer sesion-inventada-para-la-prueba" \
  "${VM_BASE}${VM_PREFIX}/vault/collections")
case "$inventada" in
  401) ok "sesion inventada: 401" ;;
  503) ok "503 porque el servicio no esta listo; repite tras el unseal" ;;
  *)   fail "sesion inventada responde ${inventada}" ;;
esac

maquina=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sesion-inventada-para-la-prueba" \
  -d '{"records":[{"collection_id":"00000000-0000-4000-8000-000000000000","record_id":"00000000-0000-4000-8000-000000000000"}]}' \
  "${VM_BASE}${VM_PREFIX}/integrations/crawler/resolve")
case "$maquina" in
  401) ok "el endpoint de maquina no acepta una api_session: 401" ;;
  503) ok "503 porque el servicio no esta listo; repite tras el unseal" ;;
  *)   fail "el endpoint de maquina responde ${maquina}" ;;
esac

echo

echo
echo "==> 8. Canal interno de aprovisionamiento (etapa 4.6)"
# No se reclama ninguna emision: solo se comprueba que el canal EXIGE la
# credencial del receptor. Reclamar emitiria una credencial de verdad, y un
# smoke no debe tener ese efecto.
PROV_URL="${VM_BASE}/internal/v1/crawler/provisioning/claim"
sin_cred=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$PROV_URL" -H 'Content-Type: application/json' --data-binary '{}')
if [[ "$sin_cred" == "401" ]]; then
  ok "claim sin credencial de receptor: 401"
else
  fail "claim sin credencial responde ${sin_cred}, se esperaba 401"
fi
mala=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$PROV_URL" -H 'Content-Type: application/json' -H 'X-VPG-Receiver-Credential: credencial-que-no-es-de-nadie' --data-binary '{}')
if [[ "$mala" == "401" ]]; then
  ok "claim con credencial invalida: 401"
else
  fail "claim con credencial invalida responde ${mala}, se esperaba 401"
fi
# El worker no atiende HTTP: se comprueba que su contenedor esta en marcha.
worker=$(docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | sed -n 's/^vault-mgmt-worker //p' | head -n 1 | tr -d '
')
if [[ "$worker" == "running" ]]; then
  ok "vault-mgmt-worker en marcha (procesa la cola en PostgreSQL)"
else
  fail "vault-mgmt-worker no esta running (estado: ${worker:-desconocido})"
fi
if [[ "$fallos" -eq 0 ]]; then
  echo "==> Todas las comprobaciones no interactivas pasan."
else
  echo "==> ${fallos} comprobacion(es) fallida(s)." >&2
fi
echo
echo "    Lo que ESTA comprobacion no cubre, por diseno:"
echo "      * el recorrido CRUD completo necesita un codigo TOTP de una persona;"
echo "      * el alta y el aprovisionamiento de un consumidor tambien (rol admin);"
echo "      * el consumo de un consumidor heredado necesita role_id y secret_id reales."
echo "    Los recorridos interactivos:"
echo "      bash scripts/vault_mgmt/walkthrough.sh               CRUD de secretos"
echo "      bash scripts/vault_mgmt/provisioning-walkthrough.sh  aprovisionamiento 4.6"
echo "    Y en Postman, las dos colecciones."
exit $(( fallos > 0 ? 1 : 0 ))
