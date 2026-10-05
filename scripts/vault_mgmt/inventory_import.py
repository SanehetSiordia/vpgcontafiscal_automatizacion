#!/usr/bin/env python3
"""Inventario e importacion EXPLICITA de secretos que ya existian en Vault.

Se ejecuta en el HOST, con la biblioteca estandar. No necesita instalar nada:
habla con Vault por HTTP (puerto publicado en loopback) y con el catalogo a
traves de ``docker compose exec postgres-service psql``.

Uso (Git Bash, desde la raiz del repositorio)::

    export VAULT_TOKEN=<token administrativo>   # no se escribe en ningun sitio

    # 1. Que hay, sin tocar nada:
    python scripts/vault_mgmt/inventory_import.py list --path sat

    # 2. Que pasaria al importar (dry-run; NO escribe):
    python scripts/vault_mgmt/inventory_import.py plan \
        --source sat/usuarios --collection <collection_id>

    # 3. Importar de verdad (hay que escribirlo):
    python scripts/vault_mgmt/inventory_import.py apply \
        --source sat/usuarios --collection <collection_id>

    # 4. Reconciliar el prefijo gestionado con el catalogo:
    python scripts/vault_mgmt/inventory_import.py audit

Que NO hace, y conviene leerlo antes de ejecutarlo
--------------------------------------------------
* **No migra nada automaticamente.** ``plan`` es el modo por defecto del
  diagnostico y ``apply`` hay que escribirlo.
* **No borra ni mueve el secreto de origen.** La importacion es una copia
  explicita al prefijo gestionado. ``secret/sat/usuarios`` sigue existiendo
  despues, con su historial intacto.
* **No sobrescribe.** Escribe con ``cas=0``. Si el destino ya tiene datos, esa
  entrada falla y el resto continua.
* **No imprime valores.** En ``plan`` se muestran los **nombres** de los campos,
  para poder compararlos con el esquema de la coleccion, nunca su contenido. Los
  valores pasan por la memoria de este proceso durante la copia y no se escriben
  en disco, ni en el log, ni en la salida.
* **No corrige las diferencias que encuentra ``audit``.** Una clave que esta en
  Vault y no en el catalogo puede ser trabajo legitimo de un administrador; una
  que esta en el catalogo y no en Vault puede ser una purga o una operacion a
  medias. Se informa y se deja la decision a una persona.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class Problem(RuntimeError):
    """Error de uso. Se imprime sin traza."""


def env_get(key: str, default: str = "") -> str:
    if not ENV_FILE.is_file():
        return default
    for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return default


# ---------------------------------------------------------------------------
# Vault por HTTP
# ---------------------------------------------------------------------------


class Vault:
    def __init__(self, addr: str, token: str, mount: str) -> None:
        self._addr = addr.rstrip("/")
        self._token = token
        self.mount = mount

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self._addr}/v1/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("X-Vault-Token", self._token)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {}
            detail = ""
            # El detalle es informativo: si el cuerpo no es el JSON de error de
            # Vault, se sigue sin el.
            with contextlib.suppress(Exception):
                detail = "; ".join(json.loads(exc.read()).get("errors") or [])
            if exc.code == 403:
                raise Problem(
                    f"Vault denego el acceso a {path}: {detail or 'sin permiso'}. "
                    "El recurso puede existir: no se concluye su inexistencia."
                ) from exc
            raise Problem(f"Vault devolvio {exc.code} en {path}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise Problem(
                f"no se pudo contactar con Vault en {self._addr}: {exc.reason}. "
                "Comprueba que el contenedor esta arriba y desbloqueado."
            ) from exc
        if not raw:
            return {}
        return json.loads(raw)

    def status(self) -> dict[str, Any]:
        return self._call("GET", "sys/health?standbyok=true&sealedcode=200&uninitcode=200")

    def list_children(self, logical: str) -> list[str]:
        payload = self._call("LIST", f"{self.mount}/metadata/{logical.strip('/')}")
        return [str(key) for key in ((payload.get("data") or {}).get("keys") or [])]

    def read(self, logical: str) -> dict[str, Any] | None:
        payload = self._call("GET", f"{self.mount}/data/{logical.strip('/')}")
        data = payload.get("data") or {}
        values = data.get("data")
        return values if isinstance(values, dict) else None

    def write_cas0(self, logical: str, values: dict[str, Any]) -> int:
        payload = self._call(
            "POST",
            f"{self.mount}/data/{logical.strip('/')}",
            {"data": values, "options": {"cas": 0}},
        )
        return int((payload.get("data") or {}).get("version") or 0)


# ---------------------------------------------------------------------------
# Catalogo por psql
# ---------------------------------------------------------------------------


def psql(sql: str, *, db: str, user: str, quiet: bool = True) -> str:
    command = [
        "docker", "compose", "exec", "-T", "postgres-service",
        "psql", "--no-psqlrc", "-qtAX", "-v", "ON_ERROR_STOP=1",
        "-U", user, "-d", db, "-c", sql,
    ]
    result = subprocess.run(
        command, cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise Problem(
            "psql fallo: " + (result.stderr.strip() or "sin detalle").splitlines()[-1]
        )
    if not quiet and result.stdout:
        print(result.stdout.strip())
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Subcomandos
# ---------------------------------------------------------------------------


def cmd_list(vault: Vault, args: argparse.Namespace) -> int:
    target = args.path.strip("/")
    print(f"==> Claves bajo '{vault.mount}/{target}'")
    print("    LIST enumera hijos de un prefijo: no devuelve documentos, no")
    print("    aplica filtrado de politicas elemento a elemento y no tiene")
    print("    paginacion nativa.")
    keys = vault.list_children(target)
    if not keys:
        print("    (sin hijos; en KV v2 un prefijo sin claves simplemente no existe)")
        return 0
    for key in keys:
        print(f"    {key}")
    print(f"\n    {len(keys)} claves.")
    return 0


def _collection_row(args: argparse.Namespace) -> tuple[str, int, str, str]:
    row = psql(
        "SELECT state || '|' || current_schema_version || '|' || kv_mount || '|' || kv_prefix "
        f"FROM {args.schema}.secret_collections WHERE collection_id = '{args.collection}';",
        db=args.db,
        user=args.pg_user,
    )
    if not row:
        raise Problem(
            f"la coleccion {args.collection} no existe en el catalogo. Creala "
            "antes por la API: POST /vault_mgmt/v1/vault/collections"
        )
    state, schema_version, mount, prefix = row.split("|")
    if state != "active":
        raise Problem(f"la coleccion esta '{state}': no se importa sobre ella.")
    return state, int(schema_version), mount, prefix


def _schema_fields(args: argparse.Namespace, schema_version: int) -> list[dict[str, Any]]:
    raw = psql(
        f"SELECT fields::text FROM {args.schema}.secret_collection_schemas "
        f"WHERE collection_id = '{args.collection}' AND schema_version = {schema_version};",
        db=args.db,
        user=args.pg_user,
    )
    return json.loads(raw) if raw else []


def cmd_import(vault: Vault, args: argparse.Namespace, *, apply: bool) -> int:
    _state, schema_version, mount, prefix = _collection_row(args)
    fields = _schema_fields(args, schema_version)
    declared = {str(field.get("name")) for field in fields}
    required = {
        str(field.get("name")) for field in fields if field.get("required")
    }

    if mount != vault.mount:
        print(
            f"    AVISO: la coleccion usa el montaje '{mount}' y este script "
            f"apunta a '{vault.mount}'. Se usara el de la coleccion."
        )
        vault.mount = mount

    source = args.source.strip("/")
    children = vault.list_children(source)
    entries: list[str] = []
    if children:
        entries = [f"{source}/{child.rstrip('/')}" for child in children if not child.endswith("/")]
        if not entries:
            raise Problem(
                f"'{source}' solo tiene subprefijos, no claves. Baja un nivel."
            )
        print(f"==> {len(entries)} claves hijas bajo '{source}'")
    else:
        entries = [source]
        print(f"==> '{source}' se trata como UNA clave")

    print(
        f"    Destino: {mount}/{prefix}/{args.collection}/<record_id>  "
        f"(esquema v{schema_version})"
    )
    print(
        "    " + ("IMPORTACION REAL" if apply else "DRY-RUN: no se escribe nada")
    )
    print()

    imported = failed = skipped = 0
    for logical in entries:
        values = vault.read(logical)
        if not values:
            print(f"    [omitida] {logical}: sin datos legibles en la version actual")
            skipped += 1
            continue

        names = sorted(values)
        unknown = [name for name in names if name not in declared]
        missing = sorted(required - set(names))

        print(f"    [origen ] {mount}/{logical}")
        # Solo NOMBRES de campo. El contenido no se imprime nunca.
        print(f"      campos : {', '.join(names)}")
        if unknown:
            print(f"      sobran : {', '.join(unknown)}  (no estan en el esquema)")
        if missing:
            print(f"      faltan : {', '.join(missing)}  (obligatorios del esquema)")

        if unknown or missing:
            print("      accion : NO importable; ajusta el esquema o el mapeo")
            failed += 1
            continue

        record_id = str(uuid.uuid4())
        destination = f"{prefix}/{args.collection}/{record_id}"
        print(f"      destino: {destination}")

        if not apply:
            print("      accion : ninguna (dry-run)")
            continue

        envelope = {"schema_version": schema_version, "values": values}
        try:
            version = vault.write_cas0(destination, envelope)
        except Problem as exc:
            print(f"      accion : FALLIDA ({exc})")
            failed += 1
            continue

        label = f"importado:{logical}".replace("'", "''")[:120]
        psql(
            f"INSERT INTO {args.schema}.secret_records "
            "(record_id, collection_id, state, current_version, schema_version, label) "
            f"VALUES ('{record_id}', '{args.collection}', 'active', {version}, "
            f"{schema_version}, '{label}');",
            db=args.db,
            user=args.pg_user,
        )
        psql(
            f"INSERT INTO {args.schema}.secret_audit "
            "(actor_kind, actor_label, action, outcome, collection_id, record_id, versions, detail) "
            f"VALUES ('cli', 'inventory_import', 'inventory_import', 'allowed', "
            f"'{args.collection}', '{record_id}', ARRAY[{version}], "
            f"'copia explicita desde {logical}; el origen no se modifico');",
            db=args.db,
            user=args.pg_user,
        )
        print(f"      accion : importado con CAS=0 (version {version})")
        imported += 1

    print()
    print(
        f"==> Resumen: {imported} importadas, {failed} no importables o fallidas, "
        f"{skipped} omitidas"
    )
    if not apply:
        print("    Era un dry-run: no se ha escrito nada.")
        print("    Repite con 'apply' cuando el mapeo de campos cuadre.")
    else:
        print("    Los secretos de origen siguen donde estaban, con su historial.")
        print("    Comprueba el resultado:")
        print("      python scripts/vault_mgmt/inventory_import.py audit")
    return 0 if failed == 0 else 1


def cmd_audit(vault: Vault, args: argparse.Namespace) -> int:
    prefix = args.kv_prefix
    print(f"==> Comparando {vault.mount}/{prefix}/ con el catalogo")

    in_vault: set[str] = set()
    for collection in vault.list_children(prefix):
        collection = collection.rstrip("/")
        for record in vault.list_children(f"{prefix}/{collection}"):
            in_vault.add(f"{collection}/{record.rstrip('/')}")

    raw = psql(
        f"SELECT collection_id || '/' || record_id FROM {args.schema}.secret_records "
        "WHERE state <> 'destroyed' ORDER BY 1;",
        db=args.db,
        user=args.pg_user,
    )
    in_catalog = {line.strip() for line in raw.splitlines() if line.strip()}

    only_vault = sorted(in_vault - in_catalog)
    only_catalog = sorted(in_catalog - in_vault)

    print()
    print(f"    En Vault y NO en el catalogo ({len(only_vault)}):")
    for item in only_vault:
        print(f"      {item}")
    if not only_vault:
        print("      (ninguna)")

    print()
    print(f"    En el catalogo y NO en Vault ({len(only_catalog)}):")
    for item in only_catalog:
        print(f"      {item}")
    if not only_catalog:
        print("      (ninguna)")

    print()
    print("    Nada de esto se corrige aqui. La primera lista pueden ser")
    print("    escrituras directas en Vault, legitimas o no; la segunda, purgas")
    print("    o operaciones que quedaron a medias. Revisa antes:")
    print("      bash scripts/vault_mgmt/reconcile-operations.sh")
    return 0


# ---------------------------------------------------------------------------
# Entrada
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inventario e importacion explicita, no destructiva, de secretos "
            "preexistentes de Vault al prefijo gestionado."
        ),
        epilog="El token se toma de VAULT_TOKEN y no se imprime en ningun momento.",
    )
    parser.add_argument(
        "--vault-addr",
        default=os.environ.get("VAULT_ADDR")
        or f"http://127.0.0.1:{env_get('VAULT_PORT_LOCAL', '8200')}",
        help="Direccion de Vault publicada en el host.",
    )
    parser.add_argument("--kv-mount", default=env_get("VAULT_MGMT_KV_MOUNT", "secret"))
    parser.add_argument("--kv-prefix", default=env_get("VAULT_MGMT_KV_PREFIX", "vpg-managed"))
    parser.add_argument("--db", default=env_get("POSTGRES_DB", "vpg_contadores"))
    parser.add_argument("--pg-user", default=env_get("POSTGRES_USER", "vpg_admin"))
    parser.add_argument(
        "--schema", default=env_get("VAULT_MGMT_POSTGRES_SCHEMA", "vault_mgmt")
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    listing = subparsers.add_parser("list", help="Enumerar un prefijo. No toca nada.")
    listing.add_argument("--path", required=True, help="Prefijo logico, p. ej. 'sat'.")

    for name, helptext in (
        ("plan", "Dry-run de la importacion. NO escribe."),
        ("apply", "Importacion real, con CAS=0. No borra el origen."),
    ):
        sub = subparsers.add_parser(name, help=helptext)
        sub.add_argument("--source", required=True, help="Clave o prefijo de origen.")
        sub.add_argument("--collection", required=True, help="UUID de la coleccion destino.")

    subparsers.add_parser(
        "audit", help="Comparar el prefijo gestionado con el catalogo. No toca nada."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    for value in (getattr(args, "source", ""), getattr(args, "path", "")):
        if value and (".." in value or value.startswith("/")):
            print(f"ERROR: ruta no admitida: {value}", file=sys.stderr)
            return 2
    collection = getattr(args, "collection", "")
    if collection and not UUID_RE.match(collection):
        print("ERROR: --collection debe ser un UUID.", file=sys.stderr)
        return 2

    token = os.environ.get("VAULT_TOKEN", "").strip()
    if not token:
        print(
            "ERROR: falta VAULT_TOKEN. Exportalo en esta terminal (no se guarda "
            "en ningun archivo):\n"
            "  export VAULT_TOKEN=<token administrativo>",
            file=sys.stderr,
        )
        return 2

    vault = Vault(args.vault_addr, token, args.kv_mount)
    try:
        health = vault.status()
        if health.get("sealed"):
            print(
                "ERROR: Vault esta sellado. El desbloqueo es manual:\n"
                "  docker compose exec vault-service vault operator unseal",
                file=sys.stderr,
            )
            return 1
        if not health.get("initialized"):
            print("ERROR: Vault no esta inicializado.", file=sys.stderr)
            return 1

        if args.command == "list":
            return cmd_list(vault, args)
        if args.command == "plan":
            return cmd_import(vault, args, apply=False)
        if args.command == "apply":
            return cmd_import(vault, args, apply=True)
        if args.command == "audit":
            return cmd_audit(vault, args)
    except Problem as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
