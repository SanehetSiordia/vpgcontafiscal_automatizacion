#!/usr/bin/env python3
"""Cliente CLI de EJEMPLO del contrato de maquina. No es el crawler.

Hace exactamente lo que hara el futuro crawler y nada mas:

1. Se autentica en Vault con **su** AppRole (``role_id`` + ``secret_id``) y
   obtiene un token de solo lectura con TTL corto.
2. Llama a ``POST /vault_mgmt/v1/integrations/crawler/resolve`` presentando ese
   token de Vault en ``Authorization``. **No** usa la ``api_session`` de ningun
   empleado: es otro contrato.
3. Desenvuelve en **Vault** cada wrapping token recibido (un solo uso) y
   comprueba que los campos esperados estan ahi.

Lo que este cliente NO hace, a proposito:

* No hace ninguna peticion a un sitio externo. No hay crawling aqui.
* No imprime valores de secretos. Imprime los **nombres** de los campos y su
  longitud, que es lo que hace falta para verificar que la entrega funciono.
* No guarda el token de Vault, ni el wrapping token, ni los valores en disco.
* No reintenta una entrega caducada en silencio: lo dice y explica que basta
  pedir otra entrega, sin repetir la tarea.

Uso (host, Git Bash, desde la raiz del repositorio)::

    python scripts/vault_mgmt/crawler_client.py \\
        --role-id <role_id> --secret-id <secret_id> \\
        --record <collection_id>:<record_id> \\
        [--record <collection_id>:<record_id>:<version>]

    # Para comprobar que un wrapping token es de un solo uso:
    python scripts/vault_mgmt/crawler_client.py ... --double-unwrap

Solo biblioteca estandar: no hace falta instalar nada en el host.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"
RECORD_RE = re.compile(
    r"^(?P<collection>[0-9a-fA-F-]{36}):(?P<record>[0-9a-fA-F-]{36})(?::(?P<version>\d+))?$"
)


def env_get(key: str, default: str = "") -> str:
    if not ENV_FILE.is_file():
        return default
    for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return default


def post(url: str, payload: dict[str, Any] | None, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode() if payload is not None else b"{}"
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"message": raw.decode(errors="replace")[:300]}
        return exc.code, body
    except urllib.error.URLError as exc:
        print(f"ERROR: no se pudo contactar con {url}: {exc.reason}", file=sys.stderr)
        raise SystemExit(1) from exc


def approle_login(vault_addr: str, mount: str, role_id: str, secret_id: str) -> str:
    """Paso 1: la maquina se autentica con SU AppRole. Nada de prestamos."""
    status, body = post(
        f"{vault_addr}/v1/auth/{mount}/login",
        {"role_id": role_id, "secret_id": secret_id},
        {},
    )
    if status != 200:
        errors = "; ".join(body.get("errors") or []) or body.get("message") or ""
        print(
            f"ERROR: el login AppRole fallo ({status}): {errors}\n"
            "       Comprueba el montaje, el role_id y que el secret_id no haya "
            "caducado. No hay credencial alternativa: si esto falla, no se "
            "resuelve nada.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    auth = body.get("auth") or {}
    token = auth.get("client_token")
    if not token:
        print("ERROR: Vault no devolvio token.", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"==> Autenticada en Vault: politicas {auth.get('token_policies')}, "
        f"ttl {auth.get('lease_duration')}s"
    )
    # El token NO se imprime.
    return str(token)


def unwrap(vault_addr: str, wrapping_token: str) -> tuple[int, dict[str, Any]]:
    """Paso 3: desenvolver ocurre en VAULT, con el token de envoltura."""
    return post(
        f"{vault_addr}/v1/sys/wrapping/unwrap",
        None,
        {"X-Vault-Token": wrapping_token},
    )


def describe(values: dict[str, Any]) -> str:
    """Resume una tupla SIN revelar su contenido."""
    parts = []
    for name in sorted(values):
        value = values[name]
        if isinstance(value, str):
            parts.append(f"{name}=<{len(value)} caracteres>")
        elif isinstance(value, bool):
            parts.append(f"{name}=<booleano>")
        elif isinstance(value, (int, float)):
            parts.append(f"{name}=<numero>")
        elif isinstance(value, dict):
            parts.append(f"{name}=<objeto con {len(value)} claves>")
        elif isinstance(value, list):
            parts.append(f"{name}=<lista de {len(value)}>")
        else:
            parts.append(f"{name}=<{type(value).__name__}>")
    return ", ".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cliente de ejemplo del contrato de maquina. No es el crawler.",
        epilog=(
            "role_id y secret_id se pasan por argumento o por las variables "
            "VPG_CRAWLER_ROLE_ID y VPG_CRAWLER_SECRET_ID. No se guardan."
        ),
    )
    parser.add_argument(
        "--vault-addr",
        default=os.environ.get("VAULT_ADDR")
        or f"http://127.0.0.1:{env_get('VAULT_PORT_LOCAL', '8200')}",
    )
    parser.add_argument(
        "--api",
        default=f"http://127.0.0.1:{env_get('VAULT_MGMT_PORT_LOCAL', '8001')}",
        help="Base de vault-mgmt-service publicada en el host.",
    )
    parser.add_argument(
        "--prefix", default=env_get("VAULT_MGMT_API_PREFIX", "/vault_mgmt/v1")
    )
    parser.add_argument(
        "--approle-mount", default=env_get("VAULT_CRAWLER_APPROLE_MOUNT", "approle-crawler")
    )
    parser.add_argument("--role-id", default=os.environ.get("VPG_CRAWLER_ROLE_ID", ""))
    parser.add_argument("--secret-id", default=os.environ.get("VPG_CRAWLER_SECRET_ID", ""))
    parser.add_argument(
        "--record",
        action="append",
        default=[],
        metavar="COLLECTION:RECORD[:VERSION]",
        help="Registro a resolver. Se puede repetir.",
    )
    parser.add_argument("--job-reference", default="ejemplo-cli")
    parser.add_argument("--wrap-ttl", type=int, default=None)
    parser.add_argument(
        "--double-unwrap",
        action="store_true",
        help="Desenvuelve dos veces para comprobar que es de un solo uso.",
    )
    args = parser.parse_args(argv)

    if not args.role_id or not args.secret_id:
        print(
            "ERROR: faltan --role-id y --secret-id (o VPG_CRAWLER_ROLE_ID y "
            "VPG_CRAWLER_SECRET_ID).\n"
            "       Los genera scripts/vault_mgmt/crawler-approle-bootstrap.sh",
            file=sys.stderr,
        )
        return 2
    if not args.record:
        print("ERROR: indica al menos un --record COLLECTION:RECORD", file=sys.stderr)
        return 2

    records = []
    for item in args.record:
        match = RECORD_RE.match(item)
        if match is None:
            print(
                f"ERROR: formato invalido: '{item}'. Se espera "
                "COLLECTION_UUID:RECORD_UUID[:VERSION]",
                file=sys.stderr,
            )
            return 2
        entry: dict[str, Any] = {
            "collection_id": match.group("collection"),
            "record_id": match.group("record"),
        }
        if match.group("version"):
            entry["version"] = int(match.group("version"))
        records.append(entry)

    vault_addr = args.vault_addr.rstrip("/")
    token = approle_login(vault_addr, args.approle_mount, args.role_id, args.secret_id)

    payload: dict[str, Any] = {"records": records, "job_reference": args.job_reference}
    if args.wrap_ttl:
        payload["wrap_ttl_seconds"] = args.wrap_ttl

    url = f"{args.api.rstrip('/')}{args.prefix}/integrations/crawler/resolve"
    print(f"==> Resolviendo {len(records)} registro(s) en {url}")
    # El token de Vault viaja como Bearer. Este endpoint NO acepta api_session.
    status, body = post(url, payload, {"Authorization": f"Bearer {token}"})

    if status != 200:
        print(
            f"ERROR: la API respondio {status}: "
            f"{body.get('code', '')} {body.get('message', '')}",
            file=sys.stderr,
        )
        if status == 403:
            print(
                "       Causas habituales: el consumidor no tiene binding para "
                "ese registro, su identidad AppRole no coincide con la registrada, "
                "o fue revocado.",
                file=sys.stderr,
            )
        return 1

    print(
        f"    consumidor '{body.get('consumer')}': "
        f"{body.get('delivered')} de {body.get('requested')} entregas"
    )
    for item in body.get("rejected") or []:
        print(
            f"    [rechazado] {item.get('record_id')}: "
            f"{item.get('code')} - {item.get('reason')}"
        )

    failures = 0
    for delivery in body.get("deliveries") or []:
        record_id = delivery.get("record_id")
        wrap_token = delivery.get("wrap_token") or ""
        print(
            f"\n    [entrega ] {record_id} version {delivery.get('version')} "
            f"({'fijada' if delivery.get('pinned') else 'latest'}), "
            f"ttl {delivery.get('ttl_seconds')}s"
        )
        unwrap_status, unwrapped = unwrap(vault_addr, wrap_token)
        if unwrap_status != 200:
            errors = "; ".join(unwrapped.get("errors") or [])
            print(
                f"      ERROR al desenvolver ({unwrap_status}): {errors}\n"
                "      Si caduco o ya se consumio, basta pedir otra entrega: "
                "no hace falta repetir la tarea.",
                file=sys.stderr,
            )
            failures += 1
            continue

        envelope = (unwrapped.get("data") or {}).get("data") or {}
        values = envelope.get("values") or {}
        print(f"      esquema: v{envelope.get('schema_version')}")
        # Nombres y tamanos, nunca contenido.
        print(f"      campos : {describe(values)}")

        if args.double_unwrap:
            again_status, again = unwrap(vault_addr, wrap_token)
            if again_status == 200:
                print(
                    "      AVISO: el wrapping token se pudo desenvolver DOS veces. "
                    "Eso no deberia pasar: revisalo.",
                    file=sys.stderr,
                )
                failures += 1
            else:
                errors = "; ".join(again.get("errors") or []) or str(again_status)
                print(f"      un solo uso confirmado: el segundo intento falla ({errors})")

    print()
    if failures:
        print(f"==> {failures} entrega(s) no se pudieron desenvolver.")
        return 1
    print("==> Todas las entregas se desenvolvieron correctamente.")
    print("    Ningun valor se ha impreso ni se ha escrito en disco.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
