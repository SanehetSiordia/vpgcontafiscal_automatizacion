"""Superficie de seguridad: que NO sale, que NO se puede escribir y que se dice.

Lo que se comprueba:

* ningun valor de secreto llega a PostgreSQL, ni como valor ni como hash;
* ningun valor, token o wrapping token aparece en un log;
* la auditoria es append-only **de verdad**: la cuenta de ejecucion no puede
  actualizarla ni borrarla;
* las versiones de esquema son inmutables para la cuenta de ejecucion;
* el OpenAPI publico no expone la pasarela interna;
* los errores de validacion nombran el campo y el motivo, nunca el valor;
* salud sin autenticacion; negocio con 503 cuando falta una dependencia;
* ``access-check`` informa de capacidad sin devolver valores.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app.vault_mgmt.core.database import get_session_factory as get_vm_session_factory
from app.vault_mgmt.core.readiness import ReadinessReport
from tests.vault_mgmt.conftest import (
    auth,
    create_collection,
    create_record,
    step_up,
)

pytestmark = pytest.mark.asyncio

SECRETO = "valor-ficticio-que-no-debe-aparecer"


# ---------------------------------------------------------------------------
# Nada de valores en PostgreSQL
# ---------------------------------------------------------------------------


async def test_ningun_valor_llega_a_postgresql(
    vm_client, vm_api, admin_session, vm_engine
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(
        vm_client,
        vm_api,
        admin_session,
        collection_id,
        values={"usuario": "demo", "password": SECRETO},
    )
    # Tambien una lectura y un parche, que son los que mas manejan valores.
    await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={"delivery": "plain"},
    )
    await vm_client.patch(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "patch": {"password": SECRETO + "-2"}},
    )

    factory = get_vm_session_factory()
    async with factory() as session:
        # Se recorre TODA columna de texto y JSON del esquema del catalogo.
        columnas = await session.execute(
            text(
                """
                SELECT table_name, column_name
                  FROM information_schema.columns
                 WHERE table_schema = 'vault_mgmt'
                   AND data_type IN ('text', 'character varying', 'jsonb', 'json')
                """
            )
        )
        encontrados: list[str] = []
        for table_name, column_name in columnas:
            row = await session.execute(
                text(
                    f'SELECT count(*) FROM vault_mgmt."{table_name}" '
                    f'WHERE "{column_name}"::text LIKE :patron'
                ),
                {"patron": "%valor-ficticio%"},
            )
            if row.scalar_one():
                encontrados.append(f"{table_name}.{column_name}")

    assert encontrados == [], f"hay valores de secreto en: {encontrados}"


async def test_tampoco_hashes_de_los_valores(vm_client, vm_api, admin_session, vm_engine):
    """No se guarda un hash para comparar reintentos: seria un oraculo.

    Un hash de baja entropia en la base permite confirmar un valor por fuerza
    bruta. Y SHA-256 **no es cifrado**: no sirve como sustituto de la
    credencial, asi que guardarlo no aportaria nada y si quitaria seguridad.
    """
    import hashlib

    collection = await create_collection(vm_client, vm_api, admin_session)
    await create_record(
        vm_client,
        vm_api,
        admin_session,
        collection["collection_id"],
        values={"usuario": "demo", "password": SECRETO},
    )
    digest = hashlib.sha256(SECRETO.encode()).hexdigest()

    factory = get_vm_session_factory()
    async with factory() as session:
        for tabla in ("secret_records", "secret_operations", "secret_audit"):
            row = await session.execute(
                text(
                    f"SELECT count(*) FROM vault_mgmt.{tabla} t "
                    "WHERE t::text LIKE :patron"
                ),
                {"patron": f"%{digest[:16]}%"},
            )
            assert row.scalar_one() == 0, tabla


# ---------------------------------------------------------------------------
# Permisos minimos: lo que la cuenta de ejecucion NO puede hacer
# ---------------------------------------------------------------------------


async def test_la_auditoria_es_append_only_para_la_cuenta_de_ejecucion(
    vm_client, vm_api, admin_session, vm_engine
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    await create_record(vm_client, vm_api, admin_session, collection["collection_id"])

    factory = get_vm_session_factory()
    async with factory() as session:
        with pytest.raises(ProgrammingError):
            await session.execute(
                text("UPDATE vault_mgmt.secret_audit SET detail = 'reescrito'")
            )
        await session.rollback()

        with pytest.raises(ProgrammingError):
            await session.execute(text("DELETE FROM vault_mgmt.secret_audit"))
        await session.rollback()


async def test_las_versiones_de_esquema_son_inmutables(
    vm_client, vm_api, admin_session, vm_engine
):
    await create_collection(vm_client, vm_api, admin_session)

    factory = get_vm_session_factory()
    async with factory() as session:
        with pytest.raises(ProgrammingError):
            await session.execute(
                text(
                    "UPDATE vault_mgmt.secret_collection_schemas "
                    "SET fields = '[]'::jsonb"
                )
            )
        await session.rollback()

        with pytest.raises(ProgrammingError):
            await session.execute(
                text("DELETE FROM vault_mgmt.secret_collection_schemas")
            )
        await session.rollback()


async def test_la_cuenta_de_ejecucion_no_puede_emitir_ddl(vm_engine):
    factory = get_vm_session_factory()
    async with factory() as session:
        with pytest.raises(ProgrammingError):
            await session.execute(
                text("CREATE TABLE vault_mgmt.intento_de_ddl (x int)")
            )
        await session.rollback()


async def test_no_hay_create_all_en_el_servicio():
    """El esquema lo crean las migraciones, no el ORM.

    Se busca una LLAMADA real con el arbol de sintaxis, no la cadena de texto:
    varios modulos documentan en un comentario que ``create_all()`` nunca se
    ejecuta, y una busqueda textual acertaria justo en esa promesa.
    """
    import ast
    import pathlib

    raiz = pathlib.Path(__file__).resolve().parents[2] / "app"
    sospechosos: list[str] = []
    for archivo in raiz.rglob("*.py"):
        arbol = ast.parse(archivo.read_text(encoding="utf-8"))
        for nodo in ast.walk(arbol):
            if not isinstance(nodo, ast.Call):
                continue
            funcion = nodo.func
            nombre = (
                funcion.attr
                if isinstance(funcion, ast.Attribute)
                else funcion.id
                if isinstance(funcion, ast.Name)
                else ""
            )
            if nombre in ("create_all", "drop_all"):
                sospechosos.append(f"{archivo}:{nodo.lineno}")
    assert sospechosos == []


# ---------------------------------------------------------------------------
# Nada de valores en los logs
# ---------------------------------------------------------------------------


async def test_los_logs_no_llevan_valores_ni_tokens(
    vm_client, vm_api, admin_session, caplog
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    with caplog.at_level(logging.DEBUG):
        record = await create_record(
            vm_client,
            vm_api,
            admin_session,
            collection_id,
            values={"usuario": "demo", "password": SECRETO},
        )
        lectura = await vm_client.post(
            f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
            headers=auth(admin_session),
            json={},
        )

    texto = "\n".join(registro.getMessage() for registro in caplog.records)
    texto += "\n" + "\n".join(str(registro.__dict__) for registro in caplog.records)

    assert SECRETO not in texto
    assert admin_session not in texto
    wrap_token = lectura.json()["delivery"]["wrap_token"]
    assert wrap_token not in texto
    # La ruta si se registra: lleva UUID, no datos personales ni secretos.
    assert collection_id in texto or "peticion atendida" in texto


# ---------------------------------------------------------------------------
# Errores y superficie publica
# ---------------------------------------------------------------------------


async def test_el_error_de_validacion_nombra_el_campo_no_el_valor(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection['collection_id']}/records",
        headers=auth(admin_session),
        json={"values": {"usuario": "demo", "password": SECRETO, "sobrante": SECRETO}},
    )
    assert response.status_code == 422
    assert SECRETO not in response.text
    campos = response.json()["context"]["fields"]
    assert any(item["field"] == "values.sobrante" for item in campos)


async def test_el_openapi_publico_describe_las_dos_autenticaciones(vm_client):
    response = await vm_client.get("/openapi.json")
    assert response.status_code == 200
    documento = response.json()

    esquemas = documento["components"]["securitySchemes"]
    assert "ApiSession" in esquemas
    assert "VaultMachineToken" in esquemas
    # Y explica que no se cruzan.
    assert "no lo interpreta" in esquemas["ApiSession"]["description"]
    assert "distinto y separado" in esquemas["VaultMachineToken"]["description"]

    rutas = documento["paths"]
    assert "/vault_mgmt/v1/vault/collections" in rutas
    assert "/vault_mgmt/v1/integrations/crawler/resolve" in rutas
    assert "/health/live" in rutas
    # La pasarela interna no esta.
    assert not any(ruta.startswith("/internal/") for ruta in rutas)
    # Y el documento no contiene ningun valor de ejemplo que parezca real.
    assert "SecretoAdmin" not in response.text


async def test_salud_sin_autenticacion(vm_client):
    live = await vm_client.get("/health/live")
    assert live.status_code == 200
    assert live.json() == {"status": "alive"}

    ready = await vm_client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["ready"] is True
    assert set(ready.json()["checks"]) == {
        "postgres_select_1",
        "catalog_schema_present",
        "vault_initialized",
        "vault_unsealed",
        "user_mgmt_ready",
        "internal_gateway_authenticated",
    }


async def test_negocio_responde_503_si_falta_una_dependencia(
    vm_client, vm_api, admin_session, apps
):
    apps["vault_mgmt"].state.readiness._report = ReadinessReport(  # noqa: SLF001
        database=True,
        catalog_schema=True,
        vault_initialized=True,
        vault_unsealed=False,
        user_mgmt_ready=True,
        gateway_authenticated=True,
        detail="vault: sellado ('vault operator unseal', paso manual)",
    )

    ready = await vm_client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json()["ready"] is False

    negocio = await vm_client.get(
        f"{vm_api}/vault/collections", headers=auth(admin_session)
    )
    assert negocio.status_code == 503
    assert negocio.json()["code"] == "not_ready"
    assert "sellado" in negocio.json()["message"]

    # live sigue en 200: el proceso esta vivo, solo no puede atender negocio.
    live = await vm_client.get("/health/live")
    assert live.status_code == 200


async def test_access_check_informa_sin_devolver_valores(
    vm_client, vm_api, admin_session, manager_session, apps
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin", "manager"]
    )
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    apps["kv"].default_capabilities = ("read",)

    como_manager = await vm_client.post(
        f"{vm_api}/vault/access-check",
        headers=auth(manager_session),
        json={
            "collection_id": collection_id,
            "record_id": record["record_id"],
            "operations": ["record_read", "record_replace", "record_purge"],
        },
    )
    assert como_manager.status_code == 200, como_manager.text
    body = como_manager.json()
    capacidades = {item["operation"]: item for item in body["operations"]}

    assert capacidades["record_read"]["allowed_by_application_role"] is True
    assert capacidades["record_replace"]["allowed_by_application_role"] is False
    assert capacidades["record_purge"]["allowed_by_application_role"] is False
    assert body["your_roles"] == ["manager"]
    assert body["collection_readers"] == ["admin", "manager"]
    # Las capacidades REALES de Vault vienen aparte, y la respuesta dice que la
    # capacidad efectiva es la interseccion.
    assert body["vault_capabilities"]
    assert "interseccion" in body["note"]
    assert "Vault manda" in body["note"]
    # Sin valores.
    assert "valor-ficticio" not in como_manager.text


async def test_access_check_no_es_un_escaner_del_catalogo(
    vm_client, vm_api, admin_session, employee_session
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin"]
    )
    response = await vm_client.post(
        f"{vm_api}/vault/access-check",
        headers=auth(employee_session),
        json={"collection_id": collection["collection_id"], "operations": ["record_read"]},
    )
    # Sin ser lector autorizado no se informa ni de la capacidad.
    assert response.status_code == 403

    inventada = await vm_client.post(
        f"{vm_api}/vault/access-check",
        headers=auth(admin_session),
        json={
            "collection_id": collection["collection_id"],
            "operations": ["leer_todo_vault", "sys_seal"],
        },
    )
    assert inventada.status_code == 422
    assert "unknown" in inventada.json()["context"]


async def test_la_operacion_no_la_puede_consultar_cualquiera(
    vm_client, vm_api, admin_session, manager_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )

    response = await vm_client.get(
        f"{vm_api}/vault/operations/{record['operation_id']}",
        headers=auth(manager_session),
    )
    assert response.status_code == 403

    como_admin = await vm_client.get(
        f"{vm_api}/vault/operations/{record['operation_id']}",
        headers=auth(admin_session),
    )
    assert como_admin.status_code == 200
    assert como_admin.json()["status"] == "completed"
    assert como_admin.json()["result_version"] == 1
    assert "valor-ficticio" not in como_admin.text


async def test_operacion_inexistente(vm_client, vm_api, admin_session):
    response = await vm_client.get(
        f"{vm_api}/vault/operations/{uuid.uuid4()}", headers=auth(admin_session)
    )
    assert response.status_code == 404
    assert response.json()["code"] == "operation_not_found"


async def test_la_auditoria_se_pagina_con_orden_estable(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    for _ in range(5):
        await create_record(vm_client, vm_api, admin_session, collection_id)

    primera = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"collection_id": collection_id, "limit": 3, "offset": 0},
    )
    segunda = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"collection_id": collection_id, "limit": 3, "offset": 3},
    )
    assert primera.status_code == 200 and segunda.status_code == 200
    ids_primera = [item["audit_id"] for item in primera.json()["items"]]
    ids_segunda = [item["audit_id"] for item in segunda.json()["items"]]
    # Orden estrictamente decreciente y sin solapes entre paginas.
    assert ids_primera == sorted(ids_primera, reverse=True)
    assert set(ids_primera).isdisjoint(ids_segunda)
    assert primera.json()["page"]["total"] == 6  # 1 creacion + 5 registros


async def test_el_limite_de_pagina_esta_acotado(vm_client, vm_api, admin_session):
    demasiado = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        params={"limit": 500},
    )
    assert demasiado.status_code == 422

    negativo = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        params={"offset": -1},
    )
    assert negativo.status_code == 422

    orden_invalido = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        params={"sort": "lo_que_sea"},
    )
    assert orden_invalido.status_code == 422


async def test_un_registro_destruido_se_distingue_de_uno_inexistente(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="record_purge",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE"},
    )

    destruido = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={},
    )
    assert destruido.status_code == 409
    assert destruido.json()["code"] == "record_destroyed"

    inexistente = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{uuid.uuid4()}/read",
        headers=auth(admin_session),
        json={},
    )
    assert inexistente.status_code == 404
    assert inexistente.json()["code"] == "record_not_found"
