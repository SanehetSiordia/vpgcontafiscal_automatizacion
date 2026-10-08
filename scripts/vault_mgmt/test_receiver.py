#!/usr/bin/env python3
"""Receptor de pruebas AISLADO para el contrato de aprovisionamiento (4.6).

Que es y que no es
------------------
Es la pieza minima que demuestra el contrato ``claim`` -> ``unwrap`` ->
``login`` -> ``ack`` contra el sistema real. Hace exactamente lo que hara el
futuro crawler en su arranque, y **nada mas**: no descarga nada, no visita
ningun sitio externo, no programa tareas y no guarda el secreto en disco.

**No es el crawler.** Que este script funcione demuestra que el contrato esta
bien implementado, no que exista un crawler. Por eso vive en ``scripts/`` y no
se arranca con ``make all``: en un arranque normal no hay receptor, y la
operacion se queda en ``waiting_receiver``, que es el comportamiento correcto.

Uso (host, Git Bash, desde la raiz del repositorio)
---------------------------------------------------
    python scripts/vault_mgmt/test_receiver.py
    python scripts/vault_mgmt/test_receiver.py --receiver local
    python scripts/vault_mgmt/test_receiver.py --no-ack   # solo reclama

La credencial del receptor se lee del archivo de ``secrets/`` (la genera
``make all``), igual que la leeria el contenedor del crawler. No se pasa por
argumento y no se imprime.

Lo que este script NO imprime nunca: el secret_id desenvuelto, el wrapping
token completo ni el token de Vault. Solo sus accessors y sus TTL.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
ENV_FILE = REPO / ".env"


def env_get(clave: str, por_omision: str = "") -> str:
    """Lee una clave del .env sin cargarlo entero ni evaluarlo."""
    if not ENV_FILE.is_file():
        return por_omision
    for linea in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        nombre, _, valor = linea.partition("=")
        if nombre.strip() == clave:
            return valor.strip()
    return por_omision


def pedir(
    url: str,
    *,
    cuerpo: dict | None = None,
    cabeceras: dict[str, str] | None = None,
    metodo: str = "POST",
) -> tuple[int, dict]:
    datos = json.dumps(cuerpo or {}).encode("utf-8")
    peticion = urllib.request.Request(url, data=datos, method=metodo)
    peticion.add_header("Content-Type", "application/json")
    for clave, valor in (cabeceras or {}).items():
        peticion.add_header(clave, valor)
    try:
        with urllib.request.urlopen(peticion, timeout=20) as respuesta:
            return respuesta.status, json.loads(respuesta.read() or b"{}")
    except urllib.error.HTTPError as exc:
        crudo = exc.read()
        try:
            return exc.code, json.loads(crudo or b"{}")
        except ValueError:
            return exc.code, {"message": crudo.decode("utf-8", "replace")[:300]}
    except urllib.error.URLError as exc:
        print(f"ERROR: no se pudo contactar con {url}: {exc.reason}", file=sys.stderr)
        raise SystemExit(2) from exc


def vault_pedir(vault: str, ruta: str, *, token: str, cuerpo: dict | None = None):
    """Llamada a Vault con el token indicado. Se usa para unwrap y login."""
    codigo, cuerpo_respuesta = pedir(
        f"{vault}/v1/{ruta}", cuerpo=cuerpo or {}, cabeceras={"X-Vault-Token": token}
    )
    return codigo, cuerpo_respuesta


def resumen(valor: str) -> str:
    """Nunca se imprime una credencial completa."""
    if not valor:
        return "(vacio)"
    return f"{valor[:8]}...(+{len(valor) - 8} caracteres)"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Receptor de pruebas del contrato de aprovisionamiento. No es el "
            "crawler: solo demuestra claim/unwrap/login/ack."
        )
    )
    parser.add_argument(
        "--receiver",
        default="local",
        help="Nombre del receptor configurado (por omision: local).",
    )
    parser.add_argument(
        "--credential-file",
        default=None,
        help=(
            "Ruta del archivo con su credencial. Por omision "
            "secrets/crawler_receiver_<receptor>."
        ),
    )
    parser.add_argument("--api", default=None, help="Base de vault-mgmt-service.")
    parser.add_argument("--vault", default=None, help="Base de Vault.")
    parser.add_argument(
        "--no-ack",
        action="store_true",
        help=(
            "Reclama y desenvuelve, pero NO confirma. Deja la operacion en "
            "awaiting_ack, para ver que sin confirmacion no se completa."
        ),
    )
    args = parser.parse_args()

    vm_bind = env_get("VAULT_MGMT_HOST_BIND", "127.0.0.1")
    vm_port = env_get("VAULT_MGMT_PORT_LOCAL", "8001")
    vault_bind = env_get("VAULT_HOST_BIND", "127.0.0.1")
    vault_port = env_get("VAULT_PORT_LOCAL", "8200")
    api = (args.api or f"http://{vm_bind}:{vm_port}").rstrip("/")
    vault = (args.vault or f"http://{vault_bind}:{vault_port}").rstrip("/")
    interno = f"{api}/internal/v1/crawler/provisioning"

    ruta_cred = pathlib.Path(
        args.credential_file or REPO / "secrets" / f"crawler_receiver_{args.receiver}"
    )
    if not ruta_cred.is_file():
        print(
            f"ERROR: no existe el archivo de credencial {ruta_cred}.\n"
            "       La genera 'make all'. Comprueba VAULT_MGMT_RECEIVERS en .env.",
            file=sys.stderr,
        )
        return 2
    credencial = ruta_cred.read_text(encoding="utf-8").splitlines()[0].strip()
    if not credencial:
        print(f"ERROR: {ruta_cred} esta vacio.", file=sys.stderr)
        return 2
    cabeceras = {"X-VPG-Receiver-Credential": credencial}

    print(f"==> Receptor '{args.receiver}' contra {api}")
    print(f"    credencial leida de {ruta_cred.relative_to(REPO)} (no se imprime)")

    # 1. Reclamar la emision. El consumer_id NO se envia: lo resuelve el
    #    servidor desde la credencial.
    print("\n==> 1. claim")
    codigo, cuerpo = pedir(
        f"{interno}/claim",
        cuerpo={"instance": f"test-receiver-{args.receiver}"},
        cabeceras=cabeceras,
    )
    if codigo != 200:
        print(f"    HTTP {codigo}: {cuerpo.get('code')} - {cuerpo.get('message')}")
        if codigo == 401:
            print("    La credencial no es valida para ningun receptor configurado.")
        return 1

    estado = cuerpo.get("status")
    if estado != "issued":
        print(f"    status={estado}: {cuerpo.get('detail')}")
        if estado == "no_pending_request":
            print(
                "    Pide una emision primero (solo admin):\n"
                "      POST /vault_mgmt/v1/vault/consumers/{consumer_id}/provision"
            )
        elif estado == "waiting_provisioner":
            print("    El worker todavia esta preparando la identidad. Reintenta.")
        elif estado == "already_delivered":
            print(
                "    Ya hay una envoltura entregada sin confirmar. No se emite otra\n"
                "    encima: eso dejaria la anterior huerfana en Vault."
            )
        return 0

    print(f"    consumer_id  : {cuerpo['consumer_id']}")
    print(f"    operation_id : {cuerpo['operation_id']}")
    print(f"    delivery_id  : {cuerpo['delivery_id']}")
    print(f"    role_id      : {resumen(cuerpo['role_id'])}")
    print(f"    wrap_token   : {resumen(cuerpo['wrap_token'])}")
    print(f"    ttl          : {cuerpo['wrap_ttl_seconds']}s")
    print(f"    login_path   : {cuerpo['login_path']}")
    print("    La operacion esta en awaiting_ack: todavia NO esta completa.")

    # 2. Desenvolver en Vault. UN SOLO USO: si esto falla, hay que volver a
    #    reclamar, no reintentar el unwrap.
    print("\n==> 2. unwrap en Vault (un solo uso)")
    codigo, envuelto = vault_pedir(
        vault, "sys/wrapping/unwrap", token=cuerpo["wrap_token"]
    )
    if codigo != 200:
        print(f"    HTTP {codigo}: {envuelto}")
        print("    Si ya se consumio o caduco, vuelve a reclamar la emision.")
        return 1
    secret_id = (envuelto.get("data") or {}).get("secret_id", "")
    if not secret_id:
        print(f"    la envoltura no traia secret_id: {list(envuelto.get('data') or {})}")
        return 1
    print(f"    secret_id obtenido: {resumen(secret_id)}  (no se guarda en disco)")

    # 3. Login AppRole. El token se queda en memoria de este proceso.
    print("\n==> 3. login AppRole")
    codigo, sesion = pedir(
        f"{vault}/v1/{cuerpo['login_path']}",
        cuerpo={"role_id": cuerpo["role_id"], "secret_id": secret_id},
    )
    if codigo != 200:
        print(f"    HTTP {codigo}: {sesion}")
        return 1
    auth = sesion.get("auth") or {}
    token = auth.get("client_token", "")
    print(f"    token      : {resumen(token)}  (solo en memoria)")
    print(f"    accessor   : {auth.get('accessor')}")
    print(f"    politicas  : {', '.join(auth.get('token_policies') or [])}")
    print(f"    ttl        : {auth.get('lease_duration')}s")

    if args.no_ack:
        print(
            "\n==> 4. ack OMITIDO (--no-ack). La operacion sigue en awaiting_ack:\n"
            "    sin confirmacion no se completa, y eso es lo que se queria ver."
        )
        return 0

    # 4. Confirmar acreditando el token. El servidor hace lookup y comprueba su
    #    identidad antes de marcar completed.
    print("\n==> 4. ack (el servidor comprueba el token con lookup)")
    codigo, confirmado = pedir(
        f"{interno}/ack",
        cuerpo={
            "delivery_id": cuerpo["delivery_id"],
            "vault_token": token,
            "instance": f"test-receiver-{args.receiver}",
        },
        cabeceras=cabeceras,
    )
    if codigo != 200:
        print(f"    HTTP {codigo}: {confirmado.get('code')} - {confirmado.get('message')}")
        return 1
    print(f"    status             : {confirmado['status']}")
    print(f"    provisioning_state : {confirmado['provisioning_state']}")
    print(f"    token_accessor     : {confirmado['token_accessor']}")
    print(f"    token_ttl          : {confirmado['token_ttl_seconds']}s")
    if confirmado.get("retired_previous"):
        print("    la credencial anterior se ha retirado (rotacion after_ack)")

    print(
        "\n==> Listo. Comprueba el estado como administrador:\n"
        f"      GET {api}/vault_mgmt/v1/vault/consumers/{confirmado['consumer_id']}\n"
        f"      GET {api}/vault_mgmt/v1/vault/operations/{confirmado['operation_id']}\n"
        "    'ready' significa que este receptor acredito un token valido. No\n"
        "    garantiza que siga vivo: caduca por su TTL."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
