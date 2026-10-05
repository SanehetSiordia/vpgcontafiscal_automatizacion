"""Ciclo de vida de una coleccion, fallos parciales y reconciliacion.

Lo que se comprueba:

* archivar inventaria, aplica soft-delete y bloquea la API, sin prometer que
  revoca lo ya entregado;
* restaurar recupera lo recuperable y **omite** lo destruido;
* purgar destruye y conserva la auditoria minima;
* el lote esta acotado: si sobra trabajo, se rechaza **antes** de hacer la mitad;
* una operacion de coleccion en curso **serializa** las escrituras de la API;
* un fallo parcial responde 409 con ``operation_id`` y la coleccion **no**
  cambia de estado;
* una respuesta perdida deja la operacion en ``needs_reconciliation`` y **no**
  se reintenta sola;
* el inventario detecta claves de Vault que el catalogo no conoce.
"""

from __future__ import annotations

import uuid

import pytest

from sqlalchemy import text

from app.core.vault import VaultError
from app.vault_mgmt.core.database import get_session_factory as get_vm_session_factory
from app.vault_mgmt.core.gateway_client import GatewayUnavailable
from tests.vault_mgmt.conftest import (
    auth,
    create_collection,
    create_record,
    step_up,
)

pytestmark = pytest.mark.asyncio


async def test_archivar_bloquea_la_api_y_no_promete_mas(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[record_id],
    )
    response = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert response.status_code == 204, response.text
    assert response.content == b""

    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}", headers=auth(admin_session)
    )
    assert detalle.json()["state"] == "archived"
    assert detalle.json()["archived_at"] is not None

    # La version quedo con soft-delete: recuperable, no destruida.
    assert apps["kv"].store[path]["versions"][1]["deletion_time"] != ""
    assert apps["kv"].store[path]["versions"][1]["destroyed"] is False

    # La API ya no da acceso ni prepara entregas.
    lectura = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}/read",
        headers=auth(admin_session),
        json={},
    )
    assert lectura.status_code == 409
    assert lectura.json()["code"] == "collection_archived"

    escritura = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        json={"values": {"usuario": "demo", "password": "x"}},
    )
    assert escritura.status_code == 409
    assert escritura.json()["code"] == "collection_archived"

    # Pero el dato SIGUE en Vault: archivar no revoca ni destruye nada.
    assert path in apps["kv"].store


async def test_archivar_exige_prueba_de_mfa(vm_client, vm_api, admin_session):
    collection = await create_collection(vm_client, vm_api, admin_session)
    await create_record(vm_client, vm_api, admin_session, collection["collection_id"])

    response = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection['collection_id']}",
        headers=auth(admin_session),
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mfa_proof_required"

    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection['collection_id']}",
        headers=auth(admin_session),
    )
    assert detalle.json()["state"] == "active"


async def test_restaurar_recupera_lo_recuperable_y_omite_lo_destruido(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    recuperable = await create_record(vm_client, vm_api, admin_session, collection_id)
    perdido = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Uno de los dos se destruye antes de archivar.
    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="versions_destroy",
        collection_id=collection_id,
        resource_ids=[perdido["record_id"]],
    )
    await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{perdido['record_id']}"
        "/versions/destroy",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"versions": [1], "confirm": "DESTROY"},
    )

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[recuperable["record_id"]],
    )
    archivada = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert archivada.status_code == 204, archivada.text

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_undelete_batch",
        collection_id=collection_id,
        resource_ids=[recuperable["record_id"]],
    )
    restaurada = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/restore",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "RESTORE", "reason": "prueba"},
    )
    assert restaurada.status_code == 200, restaurada.text
    body = restaurada.json()
    assert body["state"] == "active"
    assert body["processed"] == 1
    assert body["failed"] == 0

    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}", headers=auth(admin_session)
    )
    assert detalle.json()["state"] == "active"

    # El recuperable vuelve a estar activo...
    resumen = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{recuperable['record_id']}",
        headers=auth(admin_session),
    )
    assert resumen.json()["state"] == "active"
    # ...y el destruido sigue destruido: una version destruida no vuelve.
    destruido = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{perdido['record_id']}",
        headers=auth(admin_session),
    )
    assert destruido.json()["state"] == "destroyed"


async def test_una_coleccion_purgada_no_se_restaura(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_purge_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    purgada = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE", "reason": "limpieza de fixtures"},
    )
    assert purgada.status_code == 204, purgada.text

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_undelete_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/restore",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "RESTORE"},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "collection_not_archived"


async def test_purgar_destruye_y_conserva_la_auditoria(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    path = f"{collection['physical_prefix']}/{record['record_id']}"

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_purge_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE"},
    )
    assert response.status_code == 204

    assert path not in apps["kv"].store

    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}", headers=auth(admin_session)
    )
    # La fila de la coleccion permanece como auditoria minima.
    assert detalle.status_code == 200
    assert detalle.json()["state"] == "purged"
    assert detalle.json()["purged_at"] is not None

    auditoria = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"collection_id": collection_id},
    )
    acciones = [item["action"] for item in auditoria.json()["items"]]
    assert "collection_purge" in acciones


async def test_purga_exige_confirmacion_literal(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_purge_batch",
        collection_id=collection_id,
        resource_ids=[],
    )
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "RESTORE"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "confirmation_required"


async def test_el_lote_se_rechaza_antes_de_hacer_la_mitad(
    vm_client, vm_api, um_client, um_api, admin_session, apps, monkeypatch
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    for _ in range(3):
        await create_record(vm_client, vm_api, admin_session, collection_id)

    # Tope de lote por debajo del numero de registros.
    settings = apps["vault_mgmt"].state.settings
    monkeypatch.setattr(settings, "max_collection_batch", 2, raising=False)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[],
    )
    response = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "batch_too_large"
    assert response.json()["context"] == {"records": 3, "limit": 2}

    # Nada se toco: los tres siguen activos y la coleccion sigue activa.
    listado = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        params={"state": "active"},
    )
    assert listado.json()["page"]["total"] == 3
    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}", headers=auth(admin_session)
    )
    assert detalle.json()["state"] == "active"


async def test_fallo_parcial_del_lote_no_cambia_el_estado_de_la_coleccion(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    bueno = await create_record(vm_client, vm_api, admin_session, collection_id)
    malo = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Vault denegara uno de los dos.
    apps["kv"].denied_paths.add(
        f"{collection['physical_prefix']}/{malo['record_id']}"
    )

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[bueno["record_id"], malo["record_id"]],
    )
    response = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    # 204 solo tras completar TODAS las fases. Aqui no.
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "partial_operation"
    assert body["context"]["processed"] == 1
    assert body["context"]["failed"] == 1
    operation_id = body["context"]["operation_id"]

    # La coleccion NO cambia de estado: decir 'archivada' seria mentir.
    detalle = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}", headers=auth(admin_session)
    )
    assert detalle.json()["state"] == "active"

    # Y la operacion queda registrada para reconciliar.
    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{operation_id}", headers=auth(admin_session)
    )
    assert operacion.status_code == 200
    assert operacion.json()["status"] == "needs_reconciliation"
    assert operacion.json()["counters"]["failed"] == 1
    fases = [item["phase"] for item in operacion.json()["phases"]]
    assert "inventory" in fases
    assert "inventory_verify" in fases
    assert "valor-ficticio" not in operacion.text


async def test_respuesta_perdida_deja_la_operacion_para_reconciliar(
    vm_client, vm_api, admin_session, apps, monkeypatch
):
    """Si no hay respuesta, Vault PUDO escribir: 409 y nada de reintentos."""
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    gateway = apps["vault_mgmt"].state.record_service._gateway  # noqa: SLF001
    llamadas = {"n": 0}

    async def sin_respuesta(**kwargs):
        llamadas["n"] += 1
        raise GatewayUnavailable(
            "la pasarela no respondio dentro del tiempo limite",
            code="gateway_timeout",
        )

    monkeypatch.setattr(gateway, "execute", sin_respuesta)

    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "x"}},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "reconciliation_required"
    operation_id = response.json()["context"]["operation_id"]
    # No se reintento sola.
    assert llamadas["n"] == 1

    monkeypatch.undo()
    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{operation_id}", headers=auth(admin_session)
    )
    assert operacion.json()["status"] == "needs_reconciliation"
    assert "pudo haber aplicado el cambio" in operacion.json()["error"]
    fases = {item["phase"]: item["state"] for item in operacion.json()["phases"]}
    assert fases["vault_write"] == "unknown"


async def test_una_operacion_de_coleccion_serializa_las_escrituras(
    vm_client, vm_api, um_client, um_api, admin_session, apps, monkeypatch
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Se deja una operacion de coleccion abierta: el lote falla a mitad porque
    # la pasarela deja de responder justo en el lote.
    gateway = apps["vault_mgmt"].state.lifecycle_service._gateway  # noqa: SLF001
    original = gateway.execute

    async def falla_en_el_lote(*, bearer, payload, mfa_proof=None, request_id=None):
        if str(payload.get("operation", "")).startswith("collection_"):
            raise GatewayUnavailable("sin respuesta en el lote")
        return await original(
            bearer=bearer, payload=payload, mfa_proof=mfa_proof, request_id=request_id
        )

    monkeypatch.setattr(gateway, "execute", falla_en_el_lote)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    fallida = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert fallida.status_code == 409
    monkeypatch.undo()

    # Con la transicion sin reconciliar, una escritura de registro se rechaza
    # en vez de colarse encima de una incoherencia conocida.
    escritura = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "x"}},
    )
    assert escritura.status_code == 409
    assert escritura.json()["code"] == "reconciliation_pending"
    assert "reconcile-operations.sh" in escritura.json()["message"]

    # Y se libera cuando una persona la revisa y la cierra, que es lo que hace
    # el script de reconciliacion.
    operation_id = escritura.json()["context"]["operation_id"]
    factory = get_vm_session_factory()
    async with factory() as session:
        await session.execute(
            text(
                "UPDATE vault_mgmt.secret_operations "
                "SET status = 'failed', finished_at = now() "
                "WHERE operation_id = :id"
            ),
            {"id": uuid.UUID(operation_id)},
        )
        await session.commit()

    reintento = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "x"}},
    )
    assert reintento.status_code == 200, reintento.text


async def test_el_inventario_detecta_claves_que_el_catalogo_no_conoce(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Alguien con permisos escribe DIRECTAMENTE en Vault, sin pasar por la API.
    intruso = uuid.uuid4()
    await apps["kv"].write(
        "token-de-un-administrador",
        f"{collection['physical_prefix']}/{intruso}",
        {"schema_version": 1, "values": {"usuario": "x", "password": "y"}},
        cas=0,
    )

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_undelete_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    # Se archiva primero para poder restaurar y ver la nota del inventario.
    proof_archivo = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof_archivo},
    )

    restaurada = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/restore",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "RESTORE"},
    )
    assert restaurada.status_code == 200, restaurada.text
    nota = restaurada.json()["note"]
    assert nota is not None
    assert "no estan en el catalogo" in nota
    assert "escrituras directas en Vault" in nota
    # Y no se ha tocado la clave ajena.
    assert f"{collection['physical_prefix']}/{intruso}" in apps["kv"].store


async def test_el_error_de_una_operacion_no_lleva_valores(
    vm_client, vm_api, admin_session, apps, monkeypatch
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    apps["kv"].fail_next = VaultError(
        "fallo simulado al escribir hvs.token-que-no-debe-salir", status_code=400
    )
    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={
            "expected_version": 1,
            "values": {"usuario": "demo", "password": "valor-ficticio-secreto"},
        },
    )
    assert response.status_code in (409, 502)
    # Ni el valor enviado ni nada que parezca un token aparecen en el error.
    assert "valor-ficticio-secreto" not in response.text
    assert "hvs.token-que-no-debe-salir" not in response.text
    assert "[REDACTADO]" in response.text or "fallo simulado" in response.text
