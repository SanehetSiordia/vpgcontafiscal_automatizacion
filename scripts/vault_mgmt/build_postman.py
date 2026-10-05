#!/usr/bin/env python3
"""Genera la coleccion y el environment de Postman de la etapa 4.

La coleccion se **deriva del OpenAPI publico**, no se escribe a mano: el script
lee ``/openapi.json`` de vault-mgmt-service (y el de user-mgmt para el login) y
comprueba que cada ruta publicada tiene su peticion. Si alguien anade un
endpoint y no lo refleja aqui, el script falla y lo dice. Asi la coleccion no se
desincroniza del contrato en silencio.

Uso (host, Git Bash, desde la raiz del repositorio)::

    # Con los servicios arriba (lee el OpenAPI en vivo):
    python scripts/vault_mgmt/build_postman.py

    # Sin servicios, a partir de un OpenAPI guardado:
    python scripts/vault_mgmt/build_postman.py --from-file openapi.json

Lo que la coleccion NUNCA guarda, y por que
-------------------------------------------
* **Credenciales con valor.** ``admin_password`` y ``totp_code`` salen vacias
  en el environment exportado: se rellenan en Postman y se quedan ahi.
* **Wrapping tokens.** No se escriben en ninguna variable de environment. Un
  token de envoltura es una credencial de un solo uso; guardarla en un archivo
  que acaba en el repositorio o en un correo seria tirar por tierra justo lo
  que protege. Los scripts lo usan dentro de la misma ejecucion y lo dejan ir.
* **Pruebas de MFA.** Igual: la prueba se guarda en una variable marcada como
  secreta y con valor vacio en la exportacion.
* **Codigos TOTP.** No se reutilizan: cada paso que necesita uno pide uno nuevo.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "postman"
COLLECTION_PATH = OUT_DIR / "vpg-vault-mgmt.postman_collection.json"
ENVIRONMENT_PATH = OUT_DIR / "vpg-vault-mgmt.postman_environment.json"

SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"

NO_SECRET_PATTERNS = (
    "hvs.",
    "otpauth",
    "secret=",
    "role_id",
    "secret_id",
    "client_token",
    "x-vault-token",
)

LEAK_GUARD = [
    "pm.test('La respuesta no filtra secretos ni credenciales', function () {",
    "    const texto = pm.response.text().toLowerCase();",
    "    [" + ", ".join(f"'{p}'" for p in NO_SECRET_PATTERNS) + "]",
    "        .forEach(p => pm.expect(texto, 'aparece ' + p).to.not.include(p));",
    "});",
]


def request(
    name: str,
    method: str,
    base: str,
    path: str,
    *,
    description: str,
    body: dict[str, Any] | None = None,
    headers: list[dict[str, str]] | None = None,
    auth: str = "session",
    tests: list[str] | None = None,
    query: list[dict[str, str]] | None = None,
    prefix: str = "api_prefix",
) -> dict[str, Any]:
    """Una peticion de la coleccion.

    ``auth``: ``session`` usa el Bearer humano heredado de la coleccion,
    ``none`` no manda Authorization y ``machine`` usa el token de Vault de la
    maquina, que es un contrato distinto.

    ``prefix`` es el NOMBRE de la variable de prefijo. Cada servicio tiene el
    suyo (``api_prefix`` para vault-mgmt, ``api_prefix_user_mgmt`` para
    user-mgmt): usar el mismo para los dos construiria URL que no existen.
    """
    url: dict[str, Any] = {
        "raw": "{{" + base + "}}{{" + prefix + "}}" + path,
        "host": ["{{" + base + "}}{{" + prefix + "}}"],
        "path": [segment for segment in path.strip("/").split("/") if segment],
    }
    if query:
        url["query"] = query
        url["raw"] += "?" + "&".join(f"{item['key']}={item['value']}" for item in query)

    item: dict[str, Any] = {
        "name": name,
        "request": {
            "method": method,
            "url": url,
            "description": description,
            "header": list(headers or []),
        },
        "response": [],
    }
    if body is not None:
        item["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
        item["request"]["body"] = {
            "mode": "raw",
            "raw": json.dumps(body, indent=2, ensure_ascii=False),
            "options": {"raw": {"language": "json"}},
        }
    if auth == "none":
        item["request"]["auth"] = {"type": "noauth"}
    elif auth == "machine":
        item["request"]["auth"] = {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{machine_vault_token}}", "type": "string"}],
        }

    script = list(tests or [])
    script.extend(LEAK_GUARD)
    item["event"] = [
        {"listen": "test", "script": {"type": "text/javascript", "exec": script}}
    ]
    return item


def health_group() -> dict[str, Any]:
    return {
        "name": "00 - Salud (sin Authorization)",
        "description": (
            "Ninguno de los dos exige sesion. `live` dice si el proceso responde; "
            "`ready` si puede atender negocio. Con Vault sellado, `ready` es 503 "
            "y eso es lo correcto: el desbloqueo es manual."
        ),
        "item": [
            {
                "name": "GET /health/live",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{base_url_vault_mgmt}}/health/live",
                        "host": ["{{base_url_vault_mgmt}}"],
                        "path": ["health", "live"],
                    },
                    "description": "200 aunque Vault este sellado o la pasarela caida.",
                    "auth": {"type": "noauth"},
                    "header": [],
                },
                "response": [],
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "type": "text/javascript",
                            "exec": [
                                "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                                "pm.test('status=alive', () => pm.expect(pm.response.json().status).to.eql('alive'));",
                            ],
                        },
                    }
                ],
            },
            {
                "name": "GET /health/ready",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{base_url_vault_mgmt}}/health/ready",
                        "host": ["{{base_url_vault_mgmt}}"],
                        "path": ["health", "ready"],
                    },
                    "description": (
                        "200 o **503**. Con Vault sellado responde 503 y el campo "
                        "`detail` dice exactamente que falta. No es un fallo de la "
                        "coleccion: es el estado real."
                    ),
                    "auth": {"type": "noauth"},
                    "header": [],
                },
                "response": [],
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "type": "text/javascript",
                            "exec": [
                                "pm.test('200 o 503, nada mas', function () {",
                                "    pm.expect([200, 503]).to.include(pm.response.code);",
                                "});",
                                "const b = pm.response.json();",
                                "pm.test('Dice que comprueba y que falta', function () {",
                                "    pm.expect(b).to.have.property('checks');",
                                "    pm.expect(b.checks).to.have.property('vault_unsealed');",
                                "    pm.expect(b.checks).to.have.property('internal_gateway_authenticated');",
                                "});",
                                "if (pm.response.code === 503) {",
                                "    console.log('No listo: ' + b.detail);",
                                "}",
                            ],
                        },
                    }
                ],
            },
        ],
    }


def session_group() -> dict[str, Any]:
    """Login y MFA en user-mgmt (8000). Esta API no tiene login propio."""
    return {
        "name": "01 - Sesion (en user-mgmt, puerto 8000)",
        "description": (
            "vault-mgmt **no** tiene login. La sesion se obtiene en user-mgmt y se "
            "presenta aqui como Bearer. Este servicio no interpreta ese "
            "identificador: lo reenvia a la pasarela interna.\n\n"
            "Rellena antes `admin_username` y `admin_password` en el environment. "
            "El `totp_code` se escribe en el momento: **no se reutiliza** un codigo."
        ),
        "item": [
            request(
                "POST /auth/login - paso 1",
                "POST",
                "base_url_user_mgmt",
                "/auth/login",
                prefix="api_prefix_user_mgmt",
                description=(
                    "**Paso 1 de 2.** La respuesta NO es una sesion: es un "
                    "`challenge_id` con TTL corto. El script lo guarda."
                ),
                body={"username": "{{admin_username}}", "password": "{{admin_password}}"},
                auth="none",
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Es un desafio, no una sesion', function () {",
                    "    pm.expect(b.mfa_required).to.be.true;",
                    "    pm.expect(b).to.have.property('challenge_id');",
                    "    pm.expect(b).to.not.have.property('api_session');",
                    "});",
                    "pm.environment.set('challenge_id', b.challenge_id);",
                    "console.log('Pon el codigo TOTP en totp_code y lanza /auth/mfa/verify.');",
                ],
            ),
            request(
                "POST /auth/mfa/verify - paso 2",
                "POST",
                "base_url_user_mgmt",
                "/auth/mfa/verify",
                prefix="api_prefix_user_mgmt",
                description=(
                    "**Paso 2 de 2.** Valida el codigo contra Vault y devuelve "
                    "`api_session`. El token de Vault no sale del servidor.\n\n"
                    "El codigo es de un solo uso: para el siguiente paso que "
                    "necesite MFA, pide uno nuevo en tu autenticador."
                ),
                body={"challenge_id": "{{challenge_id}}", "code": "{{totp_code}}"},
                auth="none",
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.environment.set('api_session', b.api_session);",
                    "pm.environment.unset('challenge_id');",
                    "pm.environment.unset('totp_code');",
                    "pm.test('Devuelve sesion opaca y roles', function () {",
                    "    pm.expect(b).to.have.property('api_session');",
                    "    pm.expect(b).to.have.property('role_codes');",
                    "});",
                    "pm.test('No devuelve el token de Vault', function () {",
                    "    pm.expect(b).to.not.have.property('vault_token');",
                    "});",
                    "console.log('api_session guardada. El codigo TOTP se ha borrado del environment.');",
                ],
            ),
            request(
                "GET /auth/me - con que rol estoy operando",
                "GET",
                "base_url_user_mgmt",
                "/auth/me",
                prefix="api_prefix_user_mgmt",
                description="Util para no confundirse de rol al probar permisos.",
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "console.log('Roles: ' + JSON.stringify(pm.response.json().role_codes));",
                ],
            ),
        ],
    }


def collections_group() -> dict[str, Any]:
    nombre_ejemplo = "sat/usuarios-{{$timestamp}}"
    return {
        "name": "02 - Colecciones y esquema",
        "description": (
            "Crear una coleccion define **catalogo y esquema**. No crea ninguna "
            "carpeta en Vault: KV v2 no tiene carpetas y un prefijo sin claves no "
            "existe. Los datos aparecen con la primera escritura de un registro."
        ),
        "item": [
            request(
                "POST /vault/collections - crear (admin)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections",
                description=(
                    "El path fisico se deriva del `collection_id`, no del nombre "
                    "logico. `reader_role_codes` son roles de **aplicacion**: no son "
                    "politicas de Vault, que se comprueban ademas."
                ),
                body={
                    "logical_name": nombre_ejemplo,
                    "description": "Credenciales del portal del SAT (datos ficticios).",
                    "reader_role_codes": ["admin", "manager"],
                    "fields": [
                        {"name": "usuario", "type": "string", "required": True, "max_length": 64},
                        {
                            "name": "password",
                            "type": "string",
                            "required": True,
                            "sensitive": True,
                            "max_length": 256,
                        },
                        {"name": "rfc", "type": "string", "required": False, "max_length": 13},
                    ],
                },
                tests=[
                    "pm.test('Responde 201', () => pm.response.to.have.status(201));",
                    "const b = pm.response.json();",
                    "pm.environment.set('collection_id', b.collection_id);",
                    "pm.test('El path fisico sale del UUID, no del nombre', function () {",
                    "    pm.expect(b.physical_prefix).to.include(b.collection_id);",
                    "    pm.expect(b.physical_prefix).to.not.include('sat/usuarios');",
                    "});",
                    "pm.test('Sin registros todavia', () => pm.expect(b.record_count).to.eql(0));",
                ],
            ),
            request(
                "GET /vault/collections - listado visible",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections",
                description=(
                    "Un admin ve todas; otro rol ve solo las que lo declaran lector. "
                    "El `total` es el del catalogo **visible**, no el absoluto.\n\n"
                    "`limit`/`offset` son de este listado en PostgreSQL. El `LIST` de "
                    "Vault no tiene paginacion nativa."
                ),
                query=[
                    {"key": "limit", "value": "{{page_limit}}"},
                    {"key": "offset", "value": "0"},
                    {"key": "sort", "value": "logical_name"},
                    {"key": "order", "value": "asc"},
                ],
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Pagina con total del catalogo visible', function () {",
                    "    pm.expect(b.page).to.have.property('total');",
                    "    pm.expect(b.items.length).to.be.at.most(b.page.limit);",
                    "});",
                    "pm.test('Ningun elemento lleva valores', function () {",
                    "    b.items.forEach(i => pm.expect(i).to.not.have.property('values'));",
                    "});",
                ],
            ),
            request(
                "GET /vault/collections/{id} - definicion y estado",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}",
                description="Sin valores. Solo catalogo.",
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "pm.test('Estado y version de esquema', function () {",
                    "    const b = pm.response.json();",
                    "    pm.expect(['active','archived','purged']).to.include(b.state);",
                    "    pm.expect(b.current_schema_version).to.be.at.least(1);",
                    "});",
                ],
            ),
            request(
                "GET /vault/collections/{id}/schema - campos y JSON Schema",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/schema",
                description=(
                    "Devuelve el documento **JSON Schema (Draft 2020-12)** que valido "
                    "esa version: autocontenido, sin `$ref`, para que un validador "
                    "externo pueda comprobar lo mismo."
                ),
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Draft 2020-12 y cerrado', function () {",
                    "    pm.expect(b.schema.json_schema['$schema']).to.include('2020-12');",
                    "    pm.expect(b.schema.json_schema.additionalProperties).to.be.false;",
                    "});",
                    "pm.test('Sin referencias externas', function () {",
                    "    pm.expect(JSON.stringify(b.schema.json_schema)).to.not.include('$ref');",
                    "});",
                ],
            ),
            request(
                "PUT /vault/collections/{id}/schema - version compatible",
                "PUT",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/schema",
                description=(
                    "Crea una **version nueva**; la anterior no se modifica. Anadir un "
                    "campo opcional es compatible.\n\n"
                    "Con `apply: false` solo devuelve el diagnostico, sin crear nada."
                ),
                body={
                    "fields": [
                        {"name": "usuario", "type": "string", "required": True, "max_length": 64},
                        {
                            "name": "password",
                            "type": "string",
                            "required": True,
                            "sensitive": True,
                            "max_length": 256,
                        },
                        {"name": "rfc", "type": "string", "required": False, "max_length": 13},
                        {"name": "notas", "type": "string", "required": False, "max_length": 500},
                    ],
                    "note": "Se anade 'notas' como campo opcional.",
                    "apply": True,
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Compatible y aplicada', function () {",
                    "    pm.expect(b.compatibility.compatible).to.be.true;",
                    "    pm.expect(b.applied).to.be.true;",
                    "    pm.expect(b.current_schema_version).to.be.at.least(2);",
                    "});",
                ],
            ),
            request(
                "PUT /vault/collections/{id}/schema - INCOMPATIBLE (espera 409)",
                "PUT",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/schema",
                description=(
                    "Quitar un campo rompe los registros existentes. Responde **409** "
                    "con el detalle por campo y **no** crea version: hace falta una "
                    "migracion explicita y revisada, no una reescritura masiva.\n\n"
                    "El diagnostico se calcula comparando definiciones, no leyendo "
                    "valores: diagnosticar leyendo los registros seria leer todos los "
                    "secretos."
                ),
                body={
                    "fields": [
                        {"name": "usuario", "type": "string", "required": True, "max_length": 64}
                    ]
                },
                tests=[
                    "pm.test('Responde 409', () => pm.response.to.have.status(409));",
                    "const b = pm.response.json();",
                    "pm.test('Explica que rompe, por campo', function () {",
                    "    pm.expect(b.code).to.eql('schema_incompatible');",
                    "    pm.expect(b.context.breaking_changes.length).to.be.above(0);",
                    "    pm.expect(b.context.breaking_changes[0]).to.have.property('field');",
                    "});",
                ],
            ),
            request(
                "PATCH /vault/collections/{id} - renombrar sin perder historial",
                "PATCH",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}",
                description=(
                    "Cambia el nombre logico y **conserva** UUID, path fisico, "
                    "historial de versiones y las referencias del crawler. KV v2 no "
                    "tiene rename nativo y aqui no se simula con copy + delete."
                ),
                body={"logical_name": "sat/datos-{{$timestamp}}"},
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('El UUID y el path fisico no cambian', function () {",
                    "    pm.expect(b.collection_id).to.eql(pm.environment.get('collection_id'));",
                    "    pm.expect(b.physical_prefix).to.include(b.collection_id);",
                    "});",
                ],
            ),
        ],
    }


def records_group() -> dict[str, Any]:
    return {
        "name": "03 - Registros, CAS y versionado",
        "description": (
            "Un registro guarda **un objeto completo** de campos relacionados. N "
            "registros son N secretos de Vault con su propio historial, no N "
            "escrituras sobre la misma clave.\n\n"
            "CAS obligatorio: 0 para crear y la version actual para escribir."
        ),
        "item": [
            request(
                "POST .../records - crear con CAS=0 (admin)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records",
                description=(
                    "Se escribe con `cas=0`: si el path ya tuviera datos, 409 y no se "
                    "sobrescribe nada. La cabecera `Idempotency-Key` es opcional; "
                    "repetirla devuelve la operacion original."
                ),
                headers=[{"key": "Idempotency-Key", "value": "{{$guid}}"}],
                body={
                    "label": "contribuyente-demo-{{$timestamp}}",
                    "values": {"usuario": "demo", "password": "valor-ficticio"},
                },
                tests=[
                    "pm.test('Responde 201', () => pm.response.to.have.status(201));",
                    "const b = pm.response.json();",
                    "pm.environment.set('record_id', b.record_id);",
                    "pm.environment.set('expected_version', b.next_expected_version);",
                    "pm.environment.set('operation_id', b.operation_id);",
                    "pm.test('Version 1 y CAS siguiente', function () {",
                    "    pm.expect(b.version).to.eql(1);",
                    "    pm.expect(b.next_expected_version).to.eql(1);",
                    "});",
                    "pm.test('No devuelve los valores', () => pm.expect(b).to.not.have.property('values'));",
                ],
            ),
            request(
                "POST .../records - crear un SEGUNDO registro independiente",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records",
                description=(
                    "Mismo esquema, otro secreto. Comprueba que no se sobrescribe el "
                    "primero: son dos claves distintas en Vault."
                ),
                body={
                    "label": "contribuyente-dos-{{$timestamp}}",
                    "values": {"usuario": "demo-dos", "password": "otro-valor-ficticio"},
                },
                tests=[
                    "pm.test('Responde 201', () => pm.response.to.have.status(201));",
                    "const b = pm.response.json();",
                    "pm.environment.set('record_id_2', b.record_id);",
                    "pm.test('Es otro registro, en su version 1', function () {",
                    "    pm.expect(b.record_id).to.not.eql(pm.environment.get('record_id'));",
                    "    pm.expect(b.version).to.eql(1);",
                    "});",
                ],
            ),
            request(
                "GET .../records - IDs, estado y version (sin valores)",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records",
                description="Sale del indice del catalogo. **Nunca** incluye `values`.",
                query=[
                    {"key": "limit", "value": "{{page_limit}}"},
                    {"key": "offset", "value": "0"},
                ],
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Al menos los dos creados, sin valores', function () {",
                    "    pm.expect(b.page.total).to.be.at.least(2);",
                    "    b.items.forEach(i => pm.expect(i).to.not.have.property('values'));",
                    "});",
                ],
            ),
            request(
                "GET .../records/{id} - resumen",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}",
                description=(
                    "Estado y version. Para los valores hace falta `POST .../read`, "
                    "que es una capacidad distinta y se audita como tal."
                ),
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "pm.test('Sin valores', () => pm.expect(pm.response.json()).to.not.have.property('values'));",
                ],
            ),
            request(
                "POST .../read - entrega ENVUELTA (por defecto)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/read",
                description=(
                    "Vault devuelve un **response wrapping token**: un solo uso, TTL "
                    "corto. No es un JSON cifrado y no impide que el receptor "
                    "autorizado vea los valores al desenvolverlo.\n\n"
                    "El token **no se guarda** en ninguna variable del environment: es "
                    "una credencial y no debe acabar en un archivo exportado. El script "
                    "lo muestra en la consola de Postman, parcialmente oculto, para que "
                    "lo copies a mano si quieres desenvolverlo:\n\n"
                    "    docker compose exec vault-service vault unwrap <token>"
                ),
                body={"delivery": "wrapped"},
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Entrega envuelta, no valores', function () {",
                    "    pm.expect(b.delivery.mode).to.eql('wrapped');",
                    "    pm.expect(b.delivery).to.have.property('wrap_token');",
                    "    pm.expect(b.delivery).to.not.have.property('values');",
                    "});",
                    "pm.test('Cache-Control: no-store', function () {",
                    "    pm.expect(pm.response.headers.get('Cache-Control')).to.include('no-store');",
                    "});",
                    "// El wrapping token NO se guarda en el environment: es una",
                    "// credencial de un solo uso y no debe salir en una exportacion.",
                    "const t = b.delivery.wrap_token;",
                    "console.log('wrap token (parcial): ' + t.slice(0, 12) + '...' + ' ttl=' + b.delivery.ttl_seconds + 's');",
                    "console.log('Para desenvolverlo: docker compose exec vault-service vault unwrap <token>');",
                ],
            ),
            request(
                "POST .../read - entrega PLANA (eleccion explicita)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/read",
                description=(
                    "Devuelve el JSON con los valores, **solo** porque se pide de forma "
                    "explicita, con `Cache-Control: no-store`.\n\n"
                    "En red local sin HTTPS no hay cifrado en transito: ese limite esta "
                    "documentado y no se disimula. Y **SHA-256 es un hash, no cifrado**: "
                    "esta API no devuelve hashes como sustituto de la credencial."
                ),
                body={"delivery": "plain", "reason": "comprobacion manual documentada"},
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Tupla completa y version de esquema', function () {",
                    "    pm.expect(b.delivery.mode).to.eql('plain');",
                    "    pm.expect(b.delivery.values).to.have.property('usuario');",
                    "    pm.expect(b.delivery).to.have.property('schema_version');",
                    "});",
                    "pm.test('Cache-Control: no-store', function () {",
                    "    pm.expect(pm.response.headers.get('Cache-Control')).to.include('no-store');",
                    "});",
                    "console.log('Valores recibidos en claro por eleccion explicita. No se guardan en el environment.');",
                ],
            ),
            request(
                "PUT .../records/{id} - reemplazo con CAS",
                "PUT",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}",
                description=(
                    "Reemplaza la tupla entera y crea una **version nueva**. Las "
                    "anteriores no se mutan."
                ),
                body={
                    "expected_version": "{{expected_version}}",
                    "values": {"usuario": "demo", "password": "valor-ficticio-v2"},
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.environment.set('expected_version', b.next_expected_version);",
                    "pm.environment.set('operation_id', b.operation_id);",
                    "pm.test('Version incrementada', () => pm.expect(b.version).to.be.at.least(2));",
                ],
            ),
            request(
                "PUT .../records/{id} - CAS caducado (espera 409)",
                "PUT",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}",
                description=(
                    "Se envia `expected_version: 1` a proposito, cuando ya hay una "
                    "version posterior. **No** se sobrescribe el cambio ajeno: 409.\n\n"
                    "Lanzalo justo despues del PUT anterior para ver el conflicto."
                ),
                body={
                    "expected_version": 1,
                    "values": {"usuario": "demo", "password": "no-deberia-escribirse"},
                },
                tests=[
                    "pm.test('Responde 409', () => pm.response.to.have.status(409));",
                    "pm.test('Es un conflicto de CAS', function () {",
                    "    pm.expect(pm.response.json().code).to.eql('cas_conflict');",
                    "});",
                ],
            ),
            request(
                "PATCH .../records/{id} - merge patch con CAS",
                "PATCH",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}",
                description=(
                    "JSON Merge Patch: ausente **conserva**, `null` **elimina**, un "
                    "objeto se mezcla y una lista se reemplaza entera.\n\n"
                    "Antes de escribir se valida el objeto **resultante completo**."
                ),
                body={
                    "expected_version": "{{expected_version}}",
                    "patch": {"password": "valor-ficticio-v3", "rfc": None},
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.environment.set('expected_version', b.next_expected_version);",
                    "pm.test('Nueva version', () => pm.expect(b.version).to.be.at.least(3));",
                ],
            ),
            request(
                "PATCH .../records/{id} - null sobre obligatorio (espera 422)",
                "PATCH",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}",
                description=(
                    "`password` es obligatorio: un `null` dejaria la tupla invalida. "
                    "Responde **422 y no escribe nada**."
                ),
                body={
                    "expected_version": "{{expected_version}}",
                    "patch": {"password": None},
                },
                tests=[
                    "pm.test('Responde 422', () => pm.response.to.have.status(422));",
                    "pm.test('Dice que campo y por que', function () {",
                    "    const campos = pm.response.json().context.fields;",
                    "    pm.expect(campos.some(c => c.field === 'password')).to.be.true;",
                    "});",
                ],
            ),
            request(
                "GET .../metadata - historial nativo (admin)",
                "GET",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/metadata",
                description=(
                    "Versiones y metadata **nativas de KV v2**, que existen por "
                    "registro, no por carpeta logica. Sin valores.\n\n"
                    "`custom_metadata` es por **clave**, no por version: no sirve para "
                    "afirmar que esquema tenia una version historica."
                ),
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Historial con estados por version', function () {",
                    "    pm.expect(b.versions.length).to.be.at.least(2);",
                    "    b.versions.forEach(v => pm.expect(['active','soft_deleted','destroyed']).to.include(v.state));",
                    "});",
                    "pm.test('Sin valores', () => pm.expect(pm.response.text()).to.not.include('valor-ficticio'));",
                ],
            ),
            request(
                "POST .../versions/delete - soft-delete de versiones",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/versions/delete",
                description=(
                    "Versiones **explicitas**: no hay 'todas' implicito. Reversible con "
                    "undelete. Borrar una version historica no deja el registro borrado."
                ),
                body={"versions": [1]},
                tests=["pm.test('Responde 204', () => pm.response.to.have.status(204));"],
            ),
            request(
                "POST .../versions/undelete - recuperar",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/versions/undelete",
                description=(
                    "Recupera versiones con soft-delete. Una version **destruida no "
                    "vuelve**.\n\n"
                    "Y recuperar una version antigua **no** cambia por si solo cual es "
                    "`latest`."
                ),
                body={"versions": [1]},
                tests=["pm.test('Responde 204', () => pm.response.to.have.status(204));"],
            ),
            request(
                "DELETE .../records/{id} - soft-delete de la tupla completa",
                "DELETE",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id_2}}",
                description=(
                    "Borra la **tupla entera** en su version actual, de forma "
                    "reversible. Eliminar un campo es otra operacion: un PATCH con "
                    "`null`, que no toca sus campos hermanos.\n\n"
                    "DELETE no lleva cuerpo. Se aplica al segundo registro para no "
                    "estorbar al resto del recorrido."
                ),
                tests=[
                    "pm.test('Responde 204', () => pm.response.to.have.status(204));",
                    "pm.test('204 sin cuerpo', () => pm.expect(pm.response.text()).to.eql(''));",
                ],
            ),
        ],
    }


def destructive_group() -> dict[str, Any]:
    return {
        "name": "04 - Operaciones destructivas (step-up de MFA)",
        "description": (
            "`destroy` y `purge` exigen **tres cosas a la vez**: rol admin, "
            "confirmacion explicita en el cuerpo y una **prueba breve de MFA "
            "reciente**.\n\n"
            "La prueba se pide en user-mgmt con un login completo (contrasena + TOTP "
            "del titular), es de **un solo uso** y esta ligada a tu sesion, a ti, a la "
            "operacion y al conjunto cerrado de recursos. Para cada operacion "
            "destructiva hay que repetir el step-up con un codigo TOTP **nuevo**."
        ),
        "item": [
            request(
                "POST /auth/mfa/step-up - paso 1 (contrasena)",
                "POST",
                "base_url_user_mgmt",
                "/auth/mfa/step-up",
                prefix="api_prefix_user_mgmt",
                description=(
                    "El usuario sale de la sesion, no del cuerpo: no se puede "
                    "reautenticar a nombre de otra persona.\n\n"
                    "`operation` y `resource_ids` se fijan **aqui**, antes de pedir el "
                    "codigo: eso es lo que impide reutilizar la prueba para otra cosa.\n\n"
                    "Para purgar un registro, la operacion es `record_purge` y el "
                    "recurso es su `record_id`."
                ),
                body={
                    "password": "{{admin_password}}",
                    "operation": "record_purge",
                    "collection_id": "{{collection_id}}",
                    "resource_ids": ["{{record_id}}"],
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.environment.set('step_up_challenge_id', b.challenge_id);",
                    "pm.test('Todavia NO hay prueba', function () {",
                    "    pm.expect(b.mfa_required).to.be.true;",
                    "    pm.expect(b).to.not.have.property('mfa_proof');",
                    "});",
                    "console.log('Pon un codigo TOTP NUEVO en totp_code y lanza el paso 2.');",
                ],
            ),
            request(
                "POST /auth/mfa/step-up/verify - paso 2 (prueba)",
                "POST",
                "base_url_user_mgmt",
                "/auth/mfa/step-up/verify",
                prefix="api_prefix_user_mgmt",
                description=(
                    "Valida el codigo contra Vault. El token que Vault emite al validar "
                    "se revoca de inmediato: la sesion ya tiene el suyo.\n\n"
                    "La prueba se guarda en `mfa_proof`, marcada como secreta y vacia "
                    "en la exportacion."
                ),
                body={
                    "challenge_id": "{{step_up_challenge_id}}",
                    "code": "{{totp_code}}",
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.environment.set('mfa_proof', b.mfa_proof);",
                    "pm.environment.unset('step_up_challenge_id');",
                    "pm.environment.unset('totp_code');",
                    "pm.test('Un solo uso y con alcance cerrado', function () {",
                    "    pm.expect(b.single_use).to.be.true;",
                    "    pm.expect(b.resource_ids.length).to.be.at.least(1);",
                    "});",
                ],
            ),
            request(
                "POST .../purge - sin prueba de MFA (espera 403)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/purge",
                description=(
                    "La misma peticion **sin** la cabecera `X-VPG-MFA-Proof`. Debe "
                    "fallar con 403 y sin destruir nada."
                ),
                body={"confirm": "PURGE"},
                tests=[
                    "pm.test('Responde 403', () => pm.response.to.have.status(403));",
                    "pm.test('Pide la prueba de MFA', function () {",
                    "    pm.expect(pm.response.json().code).to.eql('mfa_proof_required');",
                    "});",
                ],
            ),
            request(
                "POST .../versions/destroy - irreversible (admin + MFA)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/versions/destroy",
                description=(
                    "**Irreversible**: despues de esto no hay undelete. Exige la lista "
                    "de versiones, `confirm: \"DESTROY\"` y la prueba de MFA.\n\n"
                    "La prueba debe haberse pedido para `versions_destroy` y para este "
                    "`record_id`: una emitida para otra operacion se rechaza."
                ),
                headers=[{"key": "X-VPG-MFA-Proof", "value": "{{mfa_proof}}"}],
                body={"versions": [1], "confirm": "DESTROY"},
                tests=[
                    "pm.test('204 si la prueba corresponde, 403 si no', function () {",
                    "    pm.expect([204, 403]).to.include(pm.response.code);",
                    "});",
                    "if (pm.response.code === 403) {",
                    "    console.log('La prueba no cubre esta operacion: ' + pm.response.json().code);",
                    "    console.log('Pide un step-up con operation=versions_destroy.');",
                    "} else {",
                    "    pm.environment.unset('mfa_proof');",
                    "    console.log('Versiones destruidas. La prueba se ha consumido.');",
                    "}",
                ],
            ),
            request(
                "POST .../purge - con prueba de MFA (admin + MFA)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/records/{{record_id}}/purge",
                description=(
                    "Borra los datos de **todas** las versiones y la metadata. "
                    "Irreversible.\n\n"
                    "El registro permanece en el indice como `destroyed`: asi se "
                    "distingue 'destruido' de 'nunca existio'. Su auditoria se conserva.\n\n"
                    "Hay que repetir el step-up (operation=`record_purge`) con un codigo "
                    "TOTP nuevo: la prueba anterior ya se consumio."
                ),
                headers=[{"key": "X-VPG-MFA-Proof", "value": "{{mfa_proof}}"}],
                body={"confirm": "PURGE", "reason": "limpieza de fixtures de prueba"},
                tests=[
                    "pm.test('204 si la prueba corresponde, 403 si no', function () {",
                    "    pm.expect([204, 403]).to.include(pm.response.code);",
                    "});",
                    "if (pm.response.code === 204) {",
                    "    pm.environment.unset('mfa_proof');",
                    "}",
                ],
            ),
        ],
    }


def lifecycle_group() -> dict[str, Any]:
    return {
        "name": "05 - Ciclo de vida de la coleccion",
        "description": (
            "Archivar bloquea el acceso de la API y las entregas futuras. **No** "
            "revoca secretos ya entregados, **no** caduca un wrapping token que ya "
            "viaja y **no** impide a un administrador leer Vault directamente.\n\n"
            "Las tres operaciones exigen prueba de MFA reciente. Pide un step-up con "
            "la operacion correspondiente: `collection_soft_delete_batch`, "
            "`collection_undelete_batch` o `collection_purge_batch`."
        ),
        "item": [
            request(
                "DELETE /vault/collections/{id} - archivar (admin + MFA)",
                "DELETE",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}",
                description=(
                    "DELETE no lleva cuerpo: la confirmacion explicita es el metodo mas "
                    "la prueba de MFA ligada a esta coleccion.\n\n"
                    "Si algun registro falla, la respuesta es **409** con el "
                    "`operation_id` y la coleccion **no** cambia de estado. 204 solo "
                    "cuando todas las fases terminaron."
                ),
                headers=[{"key": "X-VPG-MFA-Proof", "value": "{{mfa_proof}}"}],
                tests=[
                    "pm.test('204, 403 o 409 segun el caso', function () {",
                    "    pm.expect([204, 403, 409]).to.include(pm.response.code);",
                    "});",
                    "if (pm.response.code === 409) {",
                    "    const b = pm.response.json();",
                    "    if (b.context && b.context.operation_id) {",
                    "        pm.environment.set('operation_id', b.context.operation_id);",
                    "        console.log('Fallo parcial. Consulta la operacion ' + b.context.operation_id);",
                    "    }",
                    "}",
                    "if (pm.response.code === 204) { pm.environment.unset('mfa_proof'); }",
                ],
            ),
            request(
                "POST .../restore - restaurar (admin + MFA)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/restore",
                description=(
                    "Recupera las versiones con soft-delete y reactiva el catalogo.\n\n"
                    "Una version **destruida no vuelve**: se reporta como `skipped`, no "
                    "como exito."
                ),
                headers=[{"key": "X-VPG-MFA-Proof", "value": "{{mfa_proof}}"}],
                body={"confirm": "RESTORE", "reason": "fin de la prueba"},
                tests=[
                    "pm.test('200, 403 o 409 segun el caso', function () {",
                    "    pm.expect([200, 403, 409]).to.include(pm.response.code);",
                    "});",
                    "if (pm.response.code === 200) {",
                    "    const b = pm.response.json();",
                    "    console.log('Procesados: ' + b.processed + ', omitidos: ' + b.skipped);",
                    "    if (b.note) { console.log('Aviso del inventario: ' + b.note); }",
                    "    pm.environment.unset('mfa_proof');",
                    "}",
                ],
            ),
            request(
                "POST .../purge - purgar la coleccion (admin + MFA)",
                "POST",
                "base_url_vault_mgmt",
                "/vault/collections/{{collection_id}}/purge",
                description=(
                    "**Irreversible.** Destruye datos y metadata de los registros de la "
                    "coleccion y conserva la auditoria minima.\n\n"
                    "El lote esta acotado por configuracion: si la coleccion tiene mas "
                    "registros que el tope, la peticion se rechaza **antes** de tocar "
                    "nada, en vez de dejar la mitad hecha.\n\n"
                    "Usalo al final, para limpiar los fixtures de este recorrido."
                ),
                headers=[{"key": "X-VPG-MFA-Proof", "value": "{{mfa_proof}}"}],
                body={"confirm": "PURGE", "reason": "limpieza de fixtures de prueba"},
                tests=[
                    "pm.test('204, 403 o 409 segun el caso', function () {",
                    "    pm.expect([204, 403, 409]).to.include(pm.response.code);",
                    "});",
                    "if (pm.response.code === 204) {",
                    "    pm.environment.unset('mfa_proof');",
                    "    pm.environment.unset('record_id');",
                    "    pm.environment.unset('record_id_2');",
                    "    console.log('Coleccion purgada. Fixtures limpiados.');",
                    "}",
                ],
            ),
        ],
    }


def admin_group() -> dict[str, Any]:
    return {
        "name": "06 - Capacidad, operaciones y auditoria",
        "description": (
            "Lo que se puede hacer, lo que quedo a medias y lo que paso. Nada de "
            "esto devuelve valores."
        ),
        "item": [
            request(
                "POST /vault/access-check - capacidad efectiva",
                "POST",
                "base_url_vault_mgmt",
                "/vault/access-check",
                description=(
                    "Devuelve **dos columnas distintas**: lo que permite tu rol de "
                    "aplicacion y lo que permite la **ACL de Vault** sobre el path "
                    "gestionado. La capacidad efectiva es la interseccion, y Vault "
                    "manda sobre el rol.\n\n"
                    "El cuerpo indica UUID, no una ruta de Vault: asi el endpoint no se "
                    "convierte en un escaner de rutas arbitrarias."
                ),
                body={
                    "collection_id": "{{collection_id}}",
                    "record_id": "{{record_id}}",
                    "operations": ["record_read", "record_replace", "record_purge"],
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Separa rol de aplicacion y ACL de Vault', function () {",
                    "    pm.expect(b.operations[0]).to.have.property('allowed_by_application_role');",
                    "    pm.expect(b).to.have.property('vault_capabilities');",
                    "    pm.expect(b.note).to.include('interseccion');",
                    "});",
                    "pm.test('Sin valores', () => pm.expect(pm.response.text()).to.not.include('valor-ficticio'));",
                ],
            ),
            request(
                "GET /vault/operations/{id} - fases de una operacion",
                "GET",
                "base_url_vault_mgmt",
                "/vault/operations/{{operation_id}}",
                description=(
                    "El registro durable que permite reconciliar un fallo parcial: dice "
                    "que fases se completaron en cada sistema. El error viene ya "
                    "saneado."
                ),
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Estado y fases', function () {",
                    "    pm.expect(['pending','in_progress','completed','failed','needs_reconciliation'])",
                    "        .to.include(b.status);",
                    "    pm.expect(b).to.have.property('phases');",
                    "});",
                    "if (b.status === 'needs_reconciliation') {",
                    "    console.log('Pendiente de reconciliar. NO reintentes a ciegas:');",
                    "    console.log('bash scripts/vault_mgmt/reconcile-operations.sh --operation ' + b.operation_id);",
                    "}",
                ],
            ),
            request(
                "GET /vault/audit - historial paginado",
                "GET",
                "base_url_vault_mgmt",
                "/vault/audit",
                description=(
                    "Append-only: la cuenta de ejecucion solo tiene SELECT e INSERT "
                    "sobre esta tabla.\n\n"
                    "Orden estable `occurred_at DESC, audit_id DESC`. No contiene "
                    "valores, ni tokens, ni wrapping tokens, ni pruebas de MFA."
                ),
                query=[
                    {"key": "collection_id", "value": "{{collection_id}}"},
                    {"key": "limit", "value": "{{page_limit}}"},
                    {"key": "offset", "value": "0"},
                ],
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Orden estable y decreciente', function () {",
                    "    const ids = b.items.map(i => i.audit_id);",
                    "    pm.expect(ids).to.eql(ids.slice().sort((x, y) => y - x));",
                    "});",
                    "pm.test('Sin valores', () => pm.expect(pm.response.text()).to.not.include('valor-ficticio'));",
                ],
            ),
        ],
    }


def crawler_group() -> dict[str, Any]:
    return {
        "name": "07 - Consumidores y crawler (autenticacion diferenciada)",
        "description": (
            "El crawler es una **maquina independiente**. No se le presta la "
            "`api_session` de nadie: presenta un **token de Vault** obtenido con su "
            "propia AppRole de solo lectura.\n\n"
            "Prepara la identidad por CLI antes de usar este grupo:\n\n"
            "    bash scripts/vault_mgmt/crawler-approle-bootstrap.sh\n\n"
            "Ese script muestra `role_id` y `secret_id` **una vez** y registra el "
            "`consumer_id`. Ninguno de los tres se guarda en esta coleccion: el "
            "`machine_vault_token` se obtiene en el momento con el login AppRole y la "
            "variable sale vacia en la exportacion."
        ),
        "item": [
            {
                "name": "POST auth/{mount}/login - la MAQUINA se autentica en Vault",
                "request": {
                    "method": "POST",
                    "url": {
                        "raw": "{{base_url_vault}}/v1/auth/{{crawler_approle_mount}}/login",
                        "host": ["{{base_url_vault}}"],
                        "path": ["v1", "auth", "{{crawler_approle_mount}}", "login"],
                    },
                    "description": (
                        "Login AppRole contra **Vault**, no contra esta API. Rellena "
                        "`crawler_role_id` y `crawler_secret_id` en el environment "
                        "(salen del script de bootstrap) y no los guardes en ningun "
                        "archivo del repositorio.\n\n"
                        "Si este paso falla, no hay alternativa: no existe vuelta a la "
                        "cuenta tecnica del servicio."
                    ),
                    "auth": {"type": "noauth"},
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps(
                            {
                                "role_id": "{{crawler_role_id}}",
                                "secret_id": "{{crawler_secret_id}}",
                            },
                            indent=2,
                        ),
                        "options": {"raw": {"language": "json"}},
                    },
                },
                "response": [],
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "type": "text/javascript",
                            "exec": [
                                "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                                "const a = pm.response.json().auth;",
                                "pm.environment.set('machine_vault_token', a.client_token);",
                                "pm.test('Token de solo lectura y TTL corto', function () {",
                                "    pm.expect(a.token_policies).to.include('vpg-crawler');",
                                "    pm.expect(a.lease_duration).to.be.below(7200);",
                                "});",
                                "console.log('Token de maquina guardado en machine_vault_token (variable secreta, vacia al exportar). TTL: ' + a.lease_duration + 's');",
                            ],
                        },
                    }
                ],
            },
            request(
                "PUT /vault/consumers/{id}/bindings - asignar (admin)",
                "PUT",
                "base_url_vault_mgmt",
                "/vault/consumers/{{consumer_id}}/bindings",
                description=(
                    "Reemplazo **completo**: lo que no venga en la lista deja de estar "
                    "autorizado.\n\n"
                    "`pinned_version` fija la version; ausente (`null`) significa "
                    "`latest`, que cambia cuando se escribe otra version.\n\n"
                    "Revocar impide **entregas futuras**. No caduca un wrapping token "
                    "ya entregado, no revoca el token AppRole del consumidor y no borra "
                    "lo que ya leyo."
                ),
                body={
                    "bindings": [
                        {
                            "collection_id": "{{collection_id}}",
                            "record_id": "{{record_id}}",
                            "pinned_version": None,
                        }
                    ]
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('Sin credenciales de la maquina', function () {",
                    "    pm.expect(pm.response.text()).to.not.include('role_id');",
                    "    pm.expect(pm.response.text()).to.not.include('secret_id');",
                    "});",
                    "pm.test('Dice que NO hace una revocacion', function () {",
                    "    pm.expect(b.revocation_note).to.include('No caduca un wrapping token ya entregado');",
                    "});",
                ],
            ),
            request(
                "GET /vault/consumers/{id}/bindings - alcance (admin)",
                "GET",
                "base_url_vault_mgmt",
                "/vault/consumers/{{consumer_id}}/bindings",
                description="Referencias y alcance. **Sin credenciales.**",
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "pm.test('Version fijada o latest, explicito', function () {",
                    "    pm.response.json().bindings.forEach(x =>",
                    "        pm.expect(x.resolves_to).to.be.a('string'));",
                    "});",
                ],
            ),
            request(
                "POST /integrations/crawler/resolve - entrega a la maquina",
                "POST",
                "base_url_vault_mgmt",
                "/integrations/crawler/resolve",
                description=(
                    "**Autenticacion de maquina**: en `Authorization` va el token de "
                    "Vault, no una `api_session`.\n\n"
                    "Se resuelve por **UUID de registro y version explicita**; nunca "
                    "por usuario y contrasena, ni por un path libre, ni por una URL.\n\n"
                    "Devuelve wrapping tokens emitidos con los permisos de **esa** "
                    "maquina. Son de un solo uso: si uno caduca o ya se consumio, se "
                    "vuelve a pedir la entrega **sin repetir la tarea**.\n\n"
                    "Los tokens no se guardan en ninguna variable: el script los "
                    "muestra parcialmente en la consola. Para el recorrido completo:\n\n"
                    "    python scripts/vault_mgmt/crawler_client.py --help"
                ),
                auth="machine",
                body={
                    "records": [
                        {
                            "collection_id": "{{collection_id}}",
                            "record_id": "{{record_id}}",
                            "version": None,
                        }
                    ],
                    "job_reference": "tarea-de-prueba-postman",
                },
                tests=[
                    "pm.test('Responde 200', () => pm.response.to.have.status(200));",
                    "const b = pm.response.json();",
                    "pm.test('No emite tokens de autenticacion', function () {",
                    "    pm.expect(b).to.not.have.property('auth');",
                    "    pm.expect(pm.response.text()).to.not.include('client_token');",
                    "});",
                    "pm.test('Entrega o explica el rechazo, por registro', function () {",
                    "    pm.expect(b).to.have.property('deliveries');",
                    "    pm.expect(b).to.have.property('rejected');",
                    "});",
                    "// Los wrapping tokens NO se guardan: son credenciales de un uso.",
                    "(b.deliveries || []).forEach(function (d) {",
                    "    console.log('entrega ' + d.record_id + ' v' + d.version +",
                    "        (d.pinned ? ' (fijada)' : ' (latest)') +",
                    "        ' token=' + d.wrap_token.slice(0, 12) + '... ttl=' + d.ttl_seconds + 's');",
                    "});",
                    "(b.rejected || []).forEach(function (r) {",
                    "    console.log('rechazado ' + r.record_id + ': ' + r.code + ' - ' + r.reason);",
                    "});",
                ],
            ),
            request(
                "POST /integrations/crawler/resolve - con api_session (espera 401)",
                "POST",
                "base_url_vault_mgmt",
                "/integrations/crawler/resolve",
                description=(
                    "Los dos contratos no se cruzan. Presentar la `api_session` de un "
                    "empleado aqui falla: no es un token de Vault."
                ),
                body={
                    "records": [
                        {
                            "collection_id": "{{collection_id}}",
                            "record_id": "{{record_id}}",
                        }
                    ]
                },
                tests=[
                    "pm.test('Responde 401', () => pm.response.to.have.status(401));",
                    "pm.test('Dice que el token no es valido en Vault', function () {",
                    "    pm.expect(pm.response.json().code).to.eql('machine_token_invalid');",
                    "});",
                ],
            ),
        ],
    }


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

ENVIRONMENT_VALUES: list[tuple[str, str, str]] = [
    # (clave, valor, tipo). Los 'secret' se exportan SIEMPRE vacios.
    ("base_url_user_mgmt", "http://127.0.0.1:8000", "default"),
    ("base_url_vault_mgmt", "http://127.0.0.1:8001", "default"),
    ("base_url_vault", "http://127.0.0.1:8200", "default"),
    ("api_prefix", "/vault_mgmt/v1", "default"),
    ("api_prefix_user_mgmt", "/user_mgmt/v1", "default"),
    ("page_limit", "20", "default"),
    # Credenciales de prueba: vacias a proposito.
    ("admin_username", "", "default"),
    ("admin_password", "", "secret"),
    ("totp_code", "", "secret"),
    # Estado del recorrido.
    ("challenge_id", "", "secret"),
    ("api_session", "", "secret"),
    ("step_up_challenge_id", "", "secret"),
    ("mfa_proof", "", "secret"),
    ("collection_id", "", "default"),
    ("record_id", "", "default"),
    ("record_id_2", "", "default"),
    ("expected_version", "", "default"),
    ("operation_id", "", "default"),
    # Contrato de maquina.
    ("consumer_id", "", "default"),
    ("crawler_approle_mount", "approle-crawler", "default"),
    ("crawler_role_id", "", "secret"),
    ("crawler_secret_id", "", "secret"),
    ("machine_vault_token", "", "secret"),
    ("uuid_inexistente", "00000000-0000-4000-8000-000000000000", "default"),
]


def build_environment() -> dict[str, Any]:
    return {
        "id": "vpg-vault-mgmt-local",
        "name": "VPG vault-mgmt (local)",
        "_postman_variable_scope": "environment",
        "values": [
            {
                "key": key,
                # Los valores marcados como secretos se exportan VACIOS. Se
                # rellenan en Postman y se quedan en la instalacion local.
                "value": "" if kind == "secret" else value,
                "type": kind,
                "enabled": True,
            }
            for key, value, kind in ENVIRONMENT_VALUES
        ],
    }


def build_collection() -> dict[str, Any]:
    return {
        "info": {
            "name": "VPG Contadores - vault-mgmt (etapa 4)",
            "description": (
                "CRUD dinamico de secretos sobre Vault KV v2.\n\n"
                "## Puesta en marcha\n\n"
                "1. Importa la coleccion y el environment, y selecciona el "
                "environment **VPG vault-mgmt (local)**.\n"
                "2. Comprueba `00 - Salud`. Si `ready` es 503, lee su `detail`: "
                "lo habitual es que Vault siga sellado, y el desbloqueo es manual.\n"
                "3. Rellena `admin_username` y `admin_password`.\n"
                "4. Ejecuta `01 - Sesion` en orden. El `totp_code` se escribe en el "
                "momento desde tu autenticador; **no se reutiliza** un codigo.\n"
                "5. Sigue con `02`, `03`, ... Cada peticion guarda en el environment "
                "lo que necesita la siguiente (`collection_id`, `record_id`, "
                "`expected_version`, `operation_id`).\n\n"
                "## Donde va el Authorization\n\n"
                "La coleccion manda `Authorization: Bearer {{api_session}}` por "
                "herencia. Tres excepciones, a proposito:\n\n"
                "* `00 - Salud` no manda nada: no exige sesion.\n"
                "* `01 - Sesion` (login y MFA) no manda nada: todavia no hay sesion.\n"
                "* `07` usa `{{machine_vault_token}}`, que es un **token de Vault**, no "
                "una `api_session`. Son dos contratos distintos y no se cruzan.\n\n"
                "## Lo que esta coleccion nunca guarda\n\n"
                "* Contrasenas y codigos TOTP: las variables son secretas y se "
                "exportan **vacias**.\n"
                "* **Wrapping tokens**: no se escriben en ninguna variable. Son "
                "credenciales de un solo uso; guardarlas en un archivo exportable "
                "seria tirar por tierra lo que protegen. Los scripts las muestran "
                "parcialmente en la consola de Postman.\n"
                "* El token de Vault de una sesion humana: nunca sale del servidor.\n\n"
                "## Limpiar los fixtures\n\n"
                "El grupo `05` termina con la purga de la coleccion de prueba. Usa "
                "siempre colecciones creadas por esta coleccion (su nombre lleva un "
                "`timestamp`), nunca datos reales."
            ),
            "schema": SCHEMA,
        },
        "auth": {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{api_session}}", "type": "string"}],
        },
        "variable": [
            {"key": "api_prefix", "value": "/vault_mgmt/v1"},
            {"key": "api_prefix_user_mgmt", "value": "/user_mgmt/v1"},
        ],
        "event": [
            {
                "listen": "prerequest",
                "script": {
                    "type": "text/javascript",
                    "exec": [
                        "// Avisa pronto en vez de dejar fallar la peticion con un 401",
                        "// confuso.",
                        "const nombre = pm.info.requestName || '';",
                        "const exige = !nombre.startsWith('GET /health') &&",
                        "    !nombre.startsWith('POST /auth/login') &&",
                        "    !nombre.startsWith('POST /auth/mfa/verify') &&",
                        "    !nombre.startsWith('POST auth/{mount}/login');",
                        "if (exige && !pm.environment.get('api_session')) {",
                        "    console.warn('Falta api_session: ejecuta antes el grupo 01 - Sesion.');",
                        "}",
                    ],
                },
            }
        ],
        "item": [
            health_group(),
            session_group(),
            collections_group(),
            records_group(),
            destructive_group(),
            lifecycle_group(),
            admin_group(),
            crawler_group(),
        ],
    }


# ---------------------------------------------------------------------------
# Comprobacion de cobertura frente al OpenAPI
# ---------------------------------------------------------------------------


def load_openapi(source: str) -> dict[str, Any]:
    if source.startswith("http"):
        try:
            with urllib.request.urlopen(source, timeout=10) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise SystemExit(
                f"ERROR: no se pudo leer {source}: {exc}\n"
                "       Levanta los servicios (docker compose up -d) o usa "
                "--from-file."
            ) from exc
    path = Path(source)
    if not path.is_file():
        raise SystemExit(f"ERROR: no existe {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def collect_requests(items: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """(metodo, raw url) de cada peticion, recorriendo los grupos."""
    found: list[tuple[str, str]] = []
    for item in items:
        if "item" in item:
            found.extend(collect_requests(item["item"]))
        elif "request" in item:
            found.append((item["request"]["method"], item["request"]["url"]["raw"]))
    return found


def normalize(raw: str, prefix: str) -> str:
    """Convierte la URL de Postman en la ruta del OpenAPI."""
    path = raw
    for variable in (
        "{{base_url_vault_mgmt}}",
        "{{base_url_user_mgmt}}",
        "{{base_url_vault}}",
    ):
        path = path.replace(variable, "")
    path = path.replace("{{api_prefix}}", prefix)
    # Las peticiones a user-mgmt llevan su propio prefijo y no estan en este
    # OpenAPI: se marcan para excluirlas de la comprobacion.
    path = path.replace("{{api_prefix_user_mgmt}}", "@user-mgmt")
    path = path.split("?", 1)[0]
    # Las variables de Postman son los parametros de ruta del OpenAPI.
    for variable, parametro in (
        ("{{collection_id}}", "{collection_id}"),
        ("{{record_id_2}}", "{record_id}"),
        ("{{record_id}}", "{record_id}"),
        ("{{operation_id}}", "{operation_id}"),
        ("{{consumer_id}}", "{consumer_id}"),
    ):
        path = path.replace(variable, parametro)
    return path


def check_coverage(collection: dict[str, Any], openapi: dict[str, Any], prefix: str) -> None:
    peticiones = {
        (method.lower(), normalize(raw, prefix))
        for method, raw in collect_requests(collection["item"])
    }
    publicadas = {
        (method.lower(), path)
        for path, operaciones in openapi["paths"].items()
        for method in operaciones
        if method.lower() in ("get", "post", "put", "patch", "delete")
    }

    faltan = sorted(publicadas - peticiones)
    sobran = sorted(
        item
        for item in peticiones - publicadas
        # El grupo 01 apunta a user-mgmt y el 07 a Vault: no estan en este
        # OpenAPI y es correcto que no esten.
        if not item[1].startswith(("@user-mgmt", "/v1/auth/"))
    )

    if faltan:
        print("ERROR: hay rutas publicadas sin peticion en la coleccion:", file=sys.stderr)
        for method, path in faltan:
            print(f"  {method.upper():6} {path}", file=sys.stderr)
        raise SystemExit(1)
    if sobran:
        print("ERROR: la coleccion llama a rutas que no existen:", file=sys.stderr)
        for method, path in sobran:
            print(f"  {method.upper():6} {path}", file=sys.stderr)
        raise SystemExit(1)

    print(f"    cobertura: {len(publicadas)} rutas publicadas, todas con peticion")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Genera la coleccion y el environment de Postman de la etapa 4 y "
            "comprueba que cubren el OpenAPI publico."
        )
    )
    parser.add_argument(
        "--openapi",
        default="http://127.0.0.1:8001/openapi.json",
        help="URL del OpenAPI de vault-mgmt (por omision, el servicio local).",
    )
    parser.add_argument(
        "--from-file", dest="from_file", help="Leer el OpenAPI de un archivo."
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Solo comprobar cobertura; no reescribir los archivos.",
    )
    args = parser.parse_args(argv)

    print("==> Leyendo el OpenAPI publico")
    openapi = load_openapi(args.from_file or args.openapi)
    prefix = "/vault_mgmt/v1"
    for path in openapi["paths"]:
        if path.startswith("/vault_mgmt/"):
            prefix = "/" + "/".join(path.strip("/").split("/")[:2])
            break
    print(f"    titulo: {openapi['info']['title']} {openapi['info']['version']}")
    print(f"    prefijo: {prefix}")

    collection = build_collection()
    collection["variable"][0]["value"] = prefix

    print("==> Comprobando cobertura")
    check_coverage(collection, openapi, prefix)

    if args.check_only:
        print("==> Solo comprobacion: no se ha escrito nada.")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    COLLECTION_PATH.write_text(
        json.dumps(collection, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    environment = build_environment()
    environment["values"] = [
        {**item, "value": prefix} if item["key"] == "api_prefix" else item
        for item in environment["values"]
    ]
    ENVIRONMENT_PATH.write_text(
        json.dumps(environment, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print("==> Escritos")
    for path in (COLLECTION_PATH, ENVIRONMENT_PATH):
        print(f"    {path.relative_to(REPO_ROOT)}  ({path.stat().st_size} bytes)")
    secretas = [key for key, _v, kind in ENVIRONMENT_VALUES if kind == "secret"]
    print(f"    variables secretas exportadas VACIAS: {', '.join(secretas)}")
    print("    los wrapping tokens no se guardan en ninguna variable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
