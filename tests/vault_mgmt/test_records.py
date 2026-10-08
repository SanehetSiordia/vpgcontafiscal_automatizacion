"""Registros completos: N secretos independientes, CAS, PUT/PATCH y versiones.

Lo que se comprueba aqui:

* N registros son N secretos de Vault, con su propio path y su propio historial;
* la tupla se valida completa, tambien el resultado de un PATCH;
* CAS obligatorio: 0 para crear y la version actual para escribir;
* un conflicto de CAS no sobrescribe el cambio ajeno;
* PUT y PATCH crean version nueva y no mutan las anteriores;
* soft-delete / undelete / destroy / purge, con sus irreversibilidades;
* recuperar una version antigua no cambia cual es ``latest``;
* ningun listado ni resumen devuelve ``values``.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.vault_mgmt.conftest import (
    auth,
    create_collection,
    create_record,
    step_up,
)

pytestmark = pytest.mark.asyncio


async def test_n_registros_son_n_secretos_independientes(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    primero = await create_record(
        vm_client,
        vm_api,
        admin_session,
        collection_id,
        values={"usuario": "demo-uno", "password": "valor-ficticio-1"},
        label="contribuyente-uno",
    )
    segundo = await create_record(
        vm_client,
        vm_api,
        admin_session,
        collection_id,
        values={"usuario": "demo-dos", "password": "valor-ficticio-2"},
        label="contribuyente-dos",
    )

    assert primero["record_id"] != segundo["record_id"]
    assert primero["version"] == 1 and segundo["version"] == 1

    # Dos claves distintas en Vault, no una sobrescrita dos veces.
    claves = sorted(apps["kv"].store)
    assert len(claves) == 2
    assert all(collection_id in clave for clave in claves)
    assert f"{collection['physical_prefix']}/{primero['record_id']}" in claves
    assert f"{collection['physical_prefix']}/{segundo['record_id']}" in claves

    # Y el listado del catalogo no devuelve valores.
    listado = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
    )
    assert listado.status_code == 200
    assert listado.json()["page"]["total"] == 2
    for item in listado.json()["items"]:
        assert "values" not in item
    assert "valor-ficticio" not in listado.text


async def test_etiqueta_unica_por_coleccion(vm_client, vm_api, admin_session):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    await create_record(vm_client, vm_api, admin_session, collection_id, label="repetida")

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        json={"label": "repetida", "values": {"usuario": "x", "password": "y"}},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "record_label_taken"


async def test_tupla_incompleta_o_con_campos_de_mas_se_rechaza(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    sin_obligatorio = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        json={"values": {"usuario": "demo"}},
    )
    assert sin_obligatorio.status_code == 422
    campos = sin_obligatorio.json()["context"]["fields"]
    assert any(item["field"] == "values.password" for item in campos)

    con_sobrante = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        json={
            "values": {"usuario": "demo", "password": "x", "inventado": "z"},
        },
    )
    assert con_sobrante.status_code == 422
    assert any(
        item["field"] == "values.inventado" for item in con_sobrante.json()["context"]["fields"]
    )

    demasiado_largo = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(admin_session),
        json={"values": {"usuario": "d" * 200, "password": "x"}},
    )
    assert demasiado_largo.status_code == 422

    # Ninguna de las tres llego a escribir en Vault.
    assert apps["kv"].store == {}


async def test_crear_exige_cas_cero_y_no_sobrescribe(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    path = f"{collection['physical_prefix']}/{record['record_id']}"

    # El doble registra cada escritura: solo una, con cas=0 -> version 1.
    assert apps["kv"].writes == [(path, 1)]
    assert apps["kv"].store[path]["current"] == 1


async def test_cas_concurrente_el_segundo_pierde_sin_sobrescribir(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    url = f"{vm_api}/vault/collections/{collection_id}/records/{record_id}"

    # Dos escrituras con el MISMO expected_version. La segunda debe perder.
    primera = await vm_client.put(
        url,
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "ganadora"}},
    )
    assert primera.status_code == 200
    assert primera.json()["version"] == 2

    segunda = await vm_client.put(
        url,
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "perdedora"}},
    )
    assert segunda.status_code == 409
    assert segunda.json()["code"] == "cas_conflict"

    # El cambio ajeno sigue intacto: la version 2 es la de la primera.
    assert apps["kv"].store[path]["current"] == 2
    assert apps["kv"].store[path]["versions"][2]["data"]["values"]["password"] == "ganadora"
    # Y la version 1 no se muto.
    assert apps["kv"].store[path]["versions"][1]["data"]["values"]["password"] == "valor-ficticio"


async def test_escrituras_concurrentes_reales_solo_una_gana(
    vm_client, vm_api, admin_session, apps
):
    """Dos peticiones en vuelo a la vez sobre el mismo registro."""
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    url = (
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}"
    )

    async def escribir(valor: str):
        return await vm_client.put(
            url,
            headers=auth(admin_session),
            json={
                "expected_version": 1,
                "values": {"usuario": "demo", "password": valor},
            },
        )

    respuestas = await asyncio.gather(
        escribir("a-ficticio"), escribir("b-ficticio"), return_exceptions=False
    )
    codigos = sorted(response.status_code for response in respuestas)
    # Una gana con 200 y la otra pierde. Puede perder por CAS (409) o porque el
    # indice de "una operacion viva por recurso" la excluyo antes (409 tambien).
    assert codigos[0] == 200
    assert codigos[1] == 409
    razones = {
        response.json().get("code")
        for response in respuestas
        if response.status_code == 409
    }
    assert razones <= {"cas_conflict", "operation_in_progress"}


async def test_put_crea_version_nueva_y_no_muta_las_anteriores(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    for esperada, valor in ((1, "v2-ficticio"), (2, "v3-ficticio")):
        response = await vm_client.put(
            f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
            headers=auth(admin_session),
            json={
                "expected_version": esperada,
                "values": {"usuario": "demo", "password": valor},
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["version"] == esperada + 1
        assert response.json()["next_expected_version"] == esperada + 1

    versiones = apps["kv"].store[path]["versions"]
    assert sorted(versiones) == [1, 2, 3]
    assert versiones[1]["data"]["values"]["password"] == "valor-ficticio"
    assert versiones[2]["data"]["values"]["password"] == "v2-ficticio"
    assert versiones[3]["data"]["values"]["password"] == "v3-ficticio"
    # Cada version guarda la envoltura con su schema_version.
    assert versiones[3]["data"]["schema_version"] == 1


async def test_patch_conserva_omite_y_elimina_con_null(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(
        vm_client,
        vm_api,
        admin_session,
        collection_id,
        values={"usuario": "demo", "password": "valor-ficticio", "rfc": "XAXX010101000"},
    )
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    response = await vm_client.patch(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
        json={"expected_version": 1, "patch": {"password": "nuevo-ficticio", "rfc": None}},
    )
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2

    resultado = apps["kv"].store[path]["versions"][2]["data"]["values"]
    # 'usuario' se omitio en el parche: se conserva.
    assert resultado["usuario"] == "demo"
    # 'password' se sustituyo.
    assert resultado["password"] == "nuevo-ficticio"
    # 'rfc' llevaba null: se elimino, y sus campos hermanos NO.
    assert "rfc" not in resultado
    assert set(resultado) == {"usuario", "password"}


async def test_patch_que_borraria_un_campo_obligatorio_no_escribe(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    response = await vm_client.patch(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
        json={"expected_version": 1, "patch": {"password": None}},
    )
    assert response.status_code == 422
    campos = response.json()["context"]["fields"]
    assert any(item["field"] == "password" for item in campos)
    # No se escribio nada: sigue habiendo una sola version.
    assert sorted(apps["kv"].store[path]["versions"]) == [1]


async def test_patch_con_campo_no_declarado_se_rechaza(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.patch(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "patch": {"inventado": "x"}},
    )
    assert response.status_code == 422
    assert any(
        item["field"] == "inventado"
        for item in response.json()["context"]["fields"]
    )


async def test_soft_delete_y_undelete_de_la_tupla_completa(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    path = f"{collection['physical_prefix']}/{record_id}"

    borrado = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
    )
    assert borrado.status_code == 204
    assert borrado.content == b""
    assert apps["kv"].store[path]["versions"][1]["deletion_time"] != ""

    resumen = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
    )
    assert resumen.json()["state"] == "soft_deleted"

    # Leer una version borrada no entrega contenido, y lo dice por su nombre.
    lectura = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}/read",
        headers=auth(admin_session),
        json={"delivery": "plain"},
    )
    assert lectura.status_code == 409
    assert lectura.json()["code"] == "record_soft_deleted"

    recuperado = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}/versions/undelete",
        headers=auth(admin_session),
        json={"versions": [1]},
    )
    assert recuperado.status_code == 204
    assert apps["kv"].store[path]["versions"][1]["deletion_time"] == ""

    resumen = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
    )
    assert resumen.json()["state"] == "active"


async def test_borrar_version_historica_no_borra_el_registro(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "v2"}},
    )

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}/versions/delete",
        headers=auth(admin_session),
        json={"versions": [1]},
    )
    assert response.status_code == 204

    resumen = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
    )
    # La version actual (2) sigue viva: el registro NO queda borrado.
    assert resumen.json()["state"] == "active"
    assert resumen.json()["current_version"] == 2


async def test_metadata_distingue_activa_borrada_y_destruida(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    base = f"{vm_api}/vault/collections/{collection_id}/records/{record_id}"

    for esperada in (1, 2):
        await vm_client.put(
            base,
            headers=auth(admin_session),
            json={
                "expected_version": esperada,
                "values": {"usuario": "demo", "password": f"v{esperada + 1}"},
            },
        )

    await vm_client.post(
        f"{base}/versions/delete", headers=auth(admin_session), json={"versions": [1]}
    )
    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="versions_destroy",
        collection_id=collection_id,
        resource_ids=[record_id],
    )
    destruida = await vm_client.post(
        f"{base}/versions/destroy",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"versions": [2], "confirm": "DESTROY"},
    )
    assert destruida.status_code == 204, destruida.text

    metadata = await vm_client.get(f"{base}/metadata", headers=auth(admin_session))
    assert metadata.status_code == 200
    estados = {item["version"]: item["state"] for item in metadata.json()["versions"]}
    assert estados == {1: "soft_deleted", 2: "destroyed", 3: "active"}
    assert metadata.json()["current_version"] == 3
    # custom_metadata es por clave, no por version: la respuesta lo dice.
    assert "no sirve para afirmar" in metadata.json()["custom_metadata_note"]
    assert "NO cambia por si solo cual es latest" in metadata.json()["restore_note"]
    # Y la metadata no lleva valores.
    assert "valor-ficticio" not in metadata.text


async def test_undelete_no_recupera_una_version_destruida(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    base = f"{vm_api}/vault/collections/{collection_id}/records/{record_id}"
    path = f"{collection['physical_prefix']}/{record_id}"

    await vm_client.put(
        base,
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "v2"}},
    )
    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="versions_destroy",
        collection_id=collection_id,
        resource_ids=[record_id],
    )
    await vm_client.post(
        f"{base}/versions/destroy",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"versions": [1], "confirm": "DESTROY"},
    )

    recuperar = await vm_client.post(
        f"{base}/versions/undelete",
        headers=auth(admin_session),
        json={"versions": [1]},
    )
    assert recuperar.status_code == 204
    # Sigue destruida: undelete no deshace un destroy.
    assert apps["kv"].store[path]["versions"][1]["destroyed"] is True

    metadata = await vm_client.get(f"{base}/metadata", headers=auth(admin_session))
    estados = {item["version"]: item["state"] for item in metadata.json()["versions"]}
    assert estados[1] == "destroyed"
    # Y latest sigue siendo la 2, no la 1 recien "recuperada".
    assert metadata.json()["current_version"] == 2


async def test_purgar_un_registro_destruye_todo_y_conserva_auditoria(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]
    base = f"{vm_api}/vault/collections/{collection_id}/records/{record_id}"
    path = f"{collection['physical_prefix']}/{record_id}"

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="record_purge",
        collection_id=collection_id,
        resource_ids=[record_id],
    )
    response = await vm_client.post(
        f"{base}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE", "reason": "fixture de prueba"},
    )
    assert response.status_code == 204, response.text
    assert response.content == b""

    # En Vault no queda nada de esa clave.
    assert path not in apps["kv"].store

    # En el catalogo queda como destruido: eso distingue 'destruido' de
    # 'nunca existio'.
    resumen = await vm_client.get(base, headers=auth(admin_session))
    assert resumen.status_code == 200
    assert resumen.json()["state"] == "destroyed"

    # Y el rastro de auditoria se conserva.
    auditoria = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"record_id": record_id},
    )
    assert auditoria.status_code == 200
    acciones = [item["action"] for item in auditoria.json()["items"]]
    assert "record_purge" in acciones
    assert "valor-ficticio" not in auditoria.text


async def test_purga_exige_confirmacion_y_prueba_de_mfa(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    base = (
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}"
    )

    sin_confirmacion = await vm_client.post(
        f"{base}/purge", headers=auth(admin_session), json={"confirm": "SI"}
    )
    assert sin_confirmacion.status_code == 422

    sin_prueba = await vm_client.post(
        f"{base}/purge", headers=auth(admin_session), json={"confirm": "PURGE"}
    )
    assert sin_prueba.status_code == 403
    assert sin_prueba.json()["code"] == "mfa_proof_required"
    # Nada se destruyo.
    assert len(apps["kv"].store) == 1


async def test_version_inexistente_y_registro_de_otra_coleccion(
    vm_client, vm_api, admin_session
):
    primera = await create_collection(vm_client, vm_api, admin_session)
    segunda = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, primera["collection_id"]
    )

    cruzado = await vm_client.get(
        f"{vm_api}/vault/collections/{segunda['collection_id']}/records/{record['record_id']}",
        headers=auth(admin_session),
    )
    assert cruzado.status_code == 404
    assert cruzado.json()["code"] == "record_not_found"

    inexistente = await vm_client.post(
        f"{vm_api}/vault/collections/{primera['collection_id']}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={"version": 99, "delivery": "plain"},
    )
    assert inexistente.status_code == 404
    assert inexistente.json()["code"] == "version_absent"


async def test_idempotency_key_no_ejecuta_dos_veces(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    # La clave es unica por ejecucion: el indice unico de la tabla es global y
    # las pruebas no vacian el catalogo (la cuenta de ejecucion no puede borrar
    # operaciones, por diseno).
    headers = {
        **auth(admin_session),
        "Idempotency-Key": f"clave-de-prueba-{uuid.uuid4().hex}",
    }
    body = {"values": {"usuario": "demo", "password": "valor-ficticio"}}

    primera = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=headers,
        json=body,
    )
    assert primera.status_code == 201

    repetida = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=headers,
        json=body,
    )
    assert repetida.status_code == 409
    assert repetida.json()["code"] == "idempotency_replay"
    assert "operation_id" in repetida.json()["context"]
    # Una sola escritura en Vault: la clave repetida no creo otro secreto.
    assert len(apps["kv"].store) == 1


async def test_solo_admin_escribe_registros(
    vm_client, vm_api, admin_session, manager_session
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin", "manager"]
    )
    collection_id = collection["collection_id"]

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(manager_session),
        json={"values": {"usuario": "demo", "password": "x"}},
    )
    assert response.status_code == 403
    assert response.json()["context"]["required_role"] == "admin"

    # Pero si puede listar: es lector autorizado.
    listado = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(manager_session),
    )
    assert listado.status_code == 200
