"""Catalogo dinamico: colecciones, esquemas versionados y renombrado.

Lo que se comprueba aqui, y por que importa:

* crear una coleccion define catalogo y esquema y **no** escribe en Vault;
* el nombre logico es unico y se valida como nombre, no como ruta;
* renombrar conserva UUID, path fisico, historial y referencias;
* un cambio de esquema compatible crea version nueva y la anterior no se muta;
* un cambio incompatible responde 409 con el detalle por campo y **sin valores**;
* ``GET`` de catalogo nunca devuelve ``values``.
"""

from __future__ import annotations

import pytest

from tests.vault_mgmt.conftest import (
    SIMPLE_FIELDS,
    auth,
    create_collection,
    create_record,
    unique_name,
)

pytestmark = pytest.mark.asyncio


async def test_crear_coleccion_define_catalogo_y_no_toca_vault(
    vm_client, vm_api, admin_session, apps
):
    name = unique_name("sat")
    body = await create_collection(
        vm_client, vm_api, admin_session, logical_name=name
    )

    assert body["logical_name"] == name
    assert body["state"] == "active"
    assert body["current_schema_version"] == 1
    assert body["record_count"] == 0
    # El path fisico se deriva del UUID, no del nombre logico.
    assert body["collection_id"] in body["physical_prefix"]
    assert name not in body["physical_prefix"]
    # Crear una coleccion NO crea ninguna clave en Vault: KV v2 no tiene
    # carpetas y un prefijo sin claves no existe.
    assert apps["kv"].store == {}


async def test_nombre_logico_unico_y_validado(vm_client, vm_api, admin_session):
    name = unique_name("sat")
    await create_collection(vm_client, vm_api, admin_session, logical_name=name)

    repetida = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        json={"logical_name": name, "reader_role_codes": ["admin"], "fields": SIMPLE_FIELDS},
    )
    assert repetida.status_code == 409
    assert repetida.json()["code"] == "collection_name_taken"

    for invalido in ("/sat/usuarios", "sat/usuarios/", "sat//usuarios", "sat/../etc"):
        response = await vm_client.post(
            f"{vm_api}/vault/collections",
            headers=auth(admin_session),
            json={
                "logical_name": invalido,
                "reader_role_codes": ["admin"],
                "fields": SIMPLE_FIELDS,
            },
        )
        assert response.status_code == 422, (invalido, response.text)

    # Las mayusculas NO son un error: se normalizan a minusculas, igual que hace
    # userpass con los nombres de usuario. Asi 'SAT/Usuarios' y 'sat/usuarios'
    # no pueden coexistir como dos colecciones distintas.
    con_mayusculas = unique_name("SAT").upper()
    response = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        json={
            "logical_name": con_mayusculas,
            "reader_role_codes": ["admin"],
            "fields": SIMPLE_FIELDS,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["logical_name"] == con_mayusculas.lower()


async def test_solo_admin_crea_coleccion(vm_client, vm_api, manager_session):
    response = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(manager_session),
        json={
            "logical_name": unique_name("sat"),
            "reader_role_codes": ["admin"],
            "fields": SIMPLE_FIELDS,
        },
    )
    assert response.status_code == 403
    assert response.json()["context"]["required_role"] == "admin"


async def test_listado_solo_muestra_colecciones_visibles(
    vm_client, vm_api, admin_session, manager_session
):
    etiqueta = unique_name("visib")
    solo_admin = await create_collection(
        vm_client, vm_api, admin_session, logical_name=f"{etiqueta}/privada", readers=["admin"]
    )
    compartida = await create_collection(
        vm_client,
        vm_api,
        admin_session,
        logical_name=f"{etiqueta}/compartida",
        readers=["admin", "manager"],
    )

    como_admin = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        params={"name_contains": etiqueta},
    )
    assert como_admin.status_code == 200
    assert {item["collection_id"] for item in como_admin.json()["items"]} == {
        solo_admin["collection_id"],
        compartida["collection_id"],
    }
    assert como_admin.json()["page"]["total"] == 2

    como_manager = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth(manager_session),
        params={"name_contains": etiqueta},
    )
    assert como_manager.status_code == 200
    ids = {item["collection_id"] for item in como_manager.json()["items"]}
    assert ids == {compartida["collection_id"]}
    # El total es el del catalogo VISIBLE, no el absoluto.
    assert como_manager.json()["page"]["total"] == 1
    # Y ningun elemento del listado lleva valores.
    for item in como_manager.json()["items"]:
        assert "values" not in item


async def test_lector_no_autorizado_recibe_403_no_404(
    vm_client, vm_api, admin_session, employee_session
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin"]
    )
    response = await vm_client.get(
        f"{vm_api}/vault/collections/{collection['collection_id']}",
        headers=auth(employee_session),
    )
    # 403 y no 404: enmascarar no es autorizar. Lo que no se revela es el
    # contenido, no la existencia de un recurso cuyo UUID ya tenia.
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"


async def test_renombrar_conserva_uuid_path_e_historial(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, logical_name=unique_name("sat")
    )
    collection_id = collection["collection_id"]
    prefijo_original = collection["physical_prefix"]

    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "v2"}},
    )
    claves_antes = sorted(apps["kv"].store)

    nuevo_nombre = unique_name("datos")
    renombrada = await vm_client.patch(
        f"{vm_api}/vault/collections/{collection_id}",
        headers=auth(admin_session),
        json={"logical_name": nuevo_nombre},
    )
    assert renombrada.status_code == 200
    body = renombrada.json()

    assert body["logical_name"] == nuevo_nombre
    assert body["collection_id"] == collection_id
    assert body["physical_prefix"] == prefijo_original
    # Ninguna clave de Vault se movio, se copio ni se borro: no hay rename
    # nativo en KV v2 y aqui no se simula con copy + delete.
    assert sorted(apps["kv"].store) == claves_antes

    metadata = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/metadata",
        headers=auth(admin_session),
    )
    assert metadata.status_code == 200
    # El historial completo sigue ahi tras el renombrado.
    assert [item["version"] for item in metadata.json()["versions"]] == [1, 2]


async def test_esquema_compatible_crea_version_y_conserva_la_anterior(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    nuevos = SIMPLE_FIELDS + [
        {"name": "notas", "type": "string", "required": False, "max_length": 500}
    ]
    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
        json={"fields": nuevos, "note": "se anade notas opcional"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applied"] is True
    assert body["current_schema_version"] == 2
    assert body["compatibility"]["compatible"] is True

    # La version 1 sigue existiendo y no se ha modificado.
    v1 = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
        params={"schema_version": 1},
    )
    assert v1.status_code == 200
    assert [field["name"] for field in v1.json()["schema"]["fields"]] == [
        "usuario",
        "password",
        "rfc",
    ]
    assert v1.json()["available_versions"] == [1, 2]
    # El documento publicado es JSON Schema estandar y autocontenido.
    documento = v1.json()["schema"]["json_schema"]
    assert documento["$schema"].endswith("2020-12/schema")
    assert documento["additionalProperties"] is False
    assert "$ref" not in str(documento)
    # Y declara los campos sensibles como anotacion, no como validacion.
    assert v1.json()["schema"]["sensitive_fields"] == ["password"]


@pytest.mark.parametrize(
    ("cambio", "motivo"),
    [
        (
            [SIMPLE_FIELDS[0], SIMPLE_FIELDS[1]],
            "el campo desaparece",
        ),
        (
            SIMPLE_FIELDS + [{"name": "curp", "type": "string", "required": True, "max_length": 18}],
            "campo nuevo obligatorio",
        ),
        (
            [
                {"name": "usuario", "type": "integer", "required": True},
                SIMPLE_FIELDS[1],
                SIMPLE_FIELDS[2],
            ],
            "el tipo cambia",
        ),
        (
            [
                {"name": "usuario", "type": "string", "required": True, "max_length": 8},
                SIMPLE_FIELDS[1],
                SIMPLE_FIELDS[2],
            ],
            "se estrecha",
        ),
    ],
)
async def test_esquema_incompatible_no_crea_version_ni_devuelve_valores(
    vm_client, vm_api, admin_session, cambio, motivo
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
        json={"fields": cambio},
    )
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "schema_incompatible"
    razones = " ".join(
        item["reason"] for item in body["context"]["breaking_changes"]
    )
    assert motivo in razones
    assert body["context"]["records_affected"] == 1
    # El diagnostico habla de campos, nunca de valores.
    assert "valor-ficticio" not in response.text
    assert "demo" not in response.text

    # Y la version vigente no ha cambiado.
    actual = await vm_client.get(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
    )
    assert actual.json()["current_schema_version"] == 1
    assert actual.json()["available_versions"] == [1]


async def test_diagnostico_sin_aplicar_no_crea_version(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
        json={
            "fields": SIMPLE_FIELDS
            + [{"name": "notas", "type": "string", "required": False}],
            "apply": False,
        },
    )
    assert response.status_code == 200
    assert response.json()["applied"] is False
    assert response.json()["current_schema_version"] == 1
    assert response.json()["schema"] is None


async def test_limites_del_esquema(vm_client, vm_api, admin_session):
    demasiados = [
        {"name": f"campo_{index}", "type": "string", "max_length": 16}
        for index in range(200)
    ]
    response = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        json={
            "logical_name": unique_name("limite"),
            "reader_role_codes": ["admin"],
            "fields": demasiados,
        },
    )
    assert response.status_code == 422

    profundo = [
        {
            "name": "nivel1",
            "type": "object",
            "properties": [
                {
                    "name": "nivel2",
                    "type": "object",
                    "properties": [
                        {
                            "name": "nivel3",
                            "type": "object",
                            "properties": [
                                {
                                    "name": "nivel4",
                                    "type": "object",
                                    "properties": [
                                        {"name": "hoja", "type": "string"}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]
    response = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(admin_session),
        json={
            "logical_name": unique_name("profundo"),
            "reader_role_codes": ["admin"],
            "fields": profundo,
        },
    )
    assert response.status_code == 422
    assert "profundidad" in response.text


async def test_coleccion_archivada_rechaza_cambios_de_esquema(
    vm_client, vm_api, um_client, um_api, admin_session
):
    from tests.vault_mgmt.conftest import step_up

    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[],
    )
    archivada = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert archivada.status_code == 204, archivada.text

    response = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/schema",
        headers=auth(admin_session),
        json={"fields": SIMPLE_FIELDS},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "collection_not_active"
