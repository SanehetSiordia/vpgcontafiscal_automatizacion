"""Contrato de maquina: consumidores, bindings y resolucion de entregas.

Lo que se comprueba:

* el contrato de maquina y el humano son **distintos**: una ``api_session`` no
  sirve aqui, y un token de Vault no sirve en los endpoints humanos;
* no se acepta cualquier token de Vault: tiene que acreditar la AppRole, el rol
  y la politica registrados para ese consumidor;
* el ``consumer_id`` se resuelve desde la **identidad del token**, no desde el
  cuerpo, y por eso (montaje, rol) identifica a un solo consumidor;
* sin binding no hay entrega, aunque el token sea perfectamente valido;
* version fijada frente a ``latest``;
* revocar impide entregas **futuras** y no caduca lo ya entregado;
* se entrega envoltura con los permisos de **esa** maquina, y nunca un token de
  autenticacion nuevo.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import text

from app.vault_mgmt.core.database import get_session_factory as get_vm_session_factory
from tests.vault_mgmt.conftest import auth, create_collection, create_record

pytestmark = pytest.mark.asyncio

MOUNT = "approle-crawler"
POLICY = "vpg-crawler"


@dataclass(slots=True)
class Consumer:
    """Un consumidor registrado y la identidad con la que debe presentarse."""

    consumer_id: str
    name: str
    mount: str
    role: str
    policy: str


async def register_consumer(
    *, mount: str = MOUNT, policy: str = POLICY
) -> Consumer:
    """Registra un consumidor como lo hace el script CLI de bootstrap.

    Cada uno recibe su propio rol AppRole: ``(montaje, rol)`` es unico por
    diseno, porque es lo que permite resolver la identidad de un token a un
    alcance de entrega sin preguntarle al cliente quien dice ser.
    """
    suffix = uuid.uuid4().hex[:8]
    name = f"crawler-{suffix}"
    role = f"vpg-crawler-{suffix}"
    factory = get_vm_session_factory()
    async with factory() as session:
        row = await session.execute(
            text(
                "INSERT INTO vault_mgmt.secret_consumers "
                "(name, description, approle_mount, approle_role_name, "
                " expected_policy, state) "
                "VALUES (:name, 'consumidor de prueba', :mount, :role, :policy, "
                "'active') RETURNING consumer_id"
            ),
            {"name": name, "mount": mount, "role": role, "policy": policy},
        )
        consumer_id = str(row.scalar_one())
        await session.commit()
    return Consumer(
        consumer_id=consumer_id, name=name, mount=mount, role=role, policy=policy
    )


def issue_token(
    apps,
    consumer: Consumer | None = None,
    *,
    mount: str | None = None,
    role: str | None = None,
    policies: tuple[str, ...] | None = None,
) -> str:
    """Emite en el doble de Vault un token con una identidad concreta."""
    token = "hvs.token-de-maquina-" + uuid.uuid4().hex
    apps["probe"].register_machine(
        token,
        mount=mount or (consumer.mount if consumer else MOUNT),
        role_name=role or (consumer.role if consumer else "vpg-crawler-desconocido"),
        policies=policies
        or ((consumer.policy, "default") if consumer else (POLICY, "default")),
    )
    return token


async def bind(
    vm_client, vm_api, admin_session, consumer: Consumer, entries: list[dict]
):
    response = await vm_client.put(
        f"{vm_api}/vault/consumers/{consumer.consumer_id}/bindings",
        headers=auth(admin_session),
        json={"bindings": entries},
    )
    return response


async def test_la_identidad_approle_no_se_puede_duplicar(vm_engine):
    """(montaje, rol) identifica a UN consumidor. Lo impone la base."""
    primero = await register_consumer()
    factory = get_vm_session_factory()
    from sqlalchemy.exc import IntegrityError

    async with factory() as session:
        with pytest.raises(IntegrityError):
            await session.execute(
                text(
                    "INSERT INTO vault_mgmt.secret_consumers "
                    "(name, approle_mount, approle_role_name, expected_policy) "
                    "VALUES (:name, :mount, :role, :policy)"
                ),
                {
                    "name": f"otro-{uuid.uuid4().hex[:8]}",
                    "mount": primero.mount,
                    "role": primero.role,
                    "policy": primero.policy,
                },
            )
        await session.rollback()


async def test_resolver_con_binding_entrega_envoltura(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]

    consumer = await register_consumer()
    bindings = await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record_id,
                "pinned_version": None,
            }
        ],
    )
    assert bindings.status_code == 200, bindings.text
    assert bindings.json()["bindings"][0]["resolves_to"] == "latest"
    # La respuesta no lleva credenciales de la maquina.
    assert "role_id" not in bindings.text
    assert "secret_id" not in bindings.text

    token = issue_token(apps, consumer)
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [{"collection_id": collection_id, "record_id": record_id}],
            "job_reference": "tarea-de-prueba",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["consumer"] == consumer.name
    assert body["delivered"] == 1
    assert body["rejected"] == []
    entrega = body["deliveries"][0]
    assert entrega["pinned"] is False
    assert entrega["wrap_token"].startswith("hvs.")
    # No se emite ningun token de autenticacion nuevo, solo envoltura.
    assert "client_token" not in response.text
    assert "auth" not in body
    # Y no viajan valores.
    assert "valor-ficticio" not in response.text
    assert response.headers["cache-control"] == "no-store"

    datos = await apps["kv"].unwrap(entrega["wrap_token"])
    assert datos["data"]["values"]["usuario"] == "demo"


async def test_sin_token_de_maquina_no_hay_entrega(vm_client, vm_api):
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        json={
            "records": [
                {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
            ]
        },
    )
    assert response.status_code == 401
    assert response.json()["code"] == "machine_token_missing"


async def test_una_api_session_no_sirve_como_token_de_maquina(
    vm_client, vm_api, admin_session
):
    """Los dos contratos son distintos y no se cruzan."""
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(admin_session),
        json={
            "records": [
                {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
            ]
        },
    )
    assert response.status_code == 401
    assert response.json()["code"] == "machine_token_invalid"


async def test_un_token_de_maquina_no_sirve_en_los_endpoints_humanos(
    vm_client, vm_api, apps
):
    consumer = await register_consumer()
    token = issue_token(apps, consumer)
    response = await vm_client.get(
        f"{vm_api}/vault/collections", headers=auth(token)
    )
    assert response.status_code == 401


async def test_token_valido_pero_identidad_no_registrada(vm_client, vm_api, apps):
    # Token perfectamente valido en Vault: es el de la cuenta tecnica de
    # user-mgmt. No le da acceso a las entregas del crawler.
    token = issue_token(
        apps, mount="approle", role="vpg-user-mgmt", policies=("vpg-user-mgmt",)
    )
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
            ]
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "consumer_not_registered"


async def test_token_sin_la_politica_minima(vm_client, vm_api, apps):
    consumer = await register_consumer()
    # Identidad correcta, pero sus politicas no incluyen la registrada.
    token = issue_token(apps, consumer, policies=("default",))

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
            ]
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "machine_identity_mismatch"
    assert "politica minima" in response.json()["message"]


async def test_token_de_otro_montaje(vm_client, vm_api, apps):
    consumer = await register_consumer()
    # Mismo nombre de rol, otro montaje: no es la misma identidad.
    token = issue_token(apps, consumer, mount="approle")
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
            ]
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "consumer_not_registered"


async def test_maquina_sin_binding_no_recibe_nada(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )
    consumer = await register_consumer()
    token = issue_token(apps, consumer)

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {
                    "collection_id": collection["collection_id"],
                    "record_id": record["record_id"],
                }
            ]
        },
    )
    # El token es valido y la identidad esta registrada: lo que falta es el
    # binding. Se responde 200 con el rechazo por registro, no 500.
    assert response.status_code == 200
    assert response.json()["delivered"] == 0
    assert response.json()["rejected"][0]["code"] == "binding_missing"


async def test_version_fijada_frente_a_latest(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    fijado = await create_record(vm_client, vm_api, admin_session, collection_id)
    al_dia = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Los dos llegan a la version 2.
    for record in (fijado, al_dia):
        await vm_client.put(
            f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
            headers=auth(admin_session),
            json={
                "expected_version": 1,
                "values": {"usuario": "demo", "password": "v2-ficticio"},
            },
        )

    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": fijado["record_id"],
                "pinned_version": 1,
            },
            {
                "collection_id": collection_id,
                "record_id": al_dia["record_id"],
                "pinned_version": None,
            },
        ],
    )
    token = issue_token(apps, consumer)

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": collection_id, "record_id": fijado["record_id"]},
                {"collection_id": collection_id, "record_id": al_dia["record_id"]},
            ]
        },
    )
    assert response.status_code == 200, response.text
    entregas = {item["record_id"]: item for item in response.json()["deliveries"]}

    # La fijada sigue en la 1 aunque exista la 2.
    assert entregas[fijado["record_id"]]["version"] == 1
    assert entregas[fijado["record_id"]]["pinned"] is True
    datos = await apps["kv"].unwrap(entregas[fijado["record_id"]]["wrap_token"])
    assert datos["data"]["values"]["password"] == "valor-ficticio"

    # La de latest entrega la 2.
    assert entregas[al_dia["record_id"]]["pinned"] is False
    datos = await apps["kv"].unwrap(entregas[al_dia["record_id"]]["wrap_token"])
    assert datos["data"]["values"]["password"] == "v2-ficticio"


async def test_no_se_puede_pedir_otra_version_que_la_fijada(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "v2"}},
    )

    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": 1,
            }
        ],
    )
    token = issue_token(apps, consumer)

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {
                    "collection_id": collection_id,
                    "record_id": record["record_id"],
                    "version": 2,
                }
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["delivered"] == 0
    assert response.json()["rejected"][0]["code"] == "version_not_allowed"


async def test_revocar_el_binding_impide_entregas_futuras(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )
    token = issue_token(apps, consumer)

    url = f"{vm_api}/integrations/crawler/resolve"
    payload = {
        "records": [
            {"collection_id": collection_id, "record_id": record["record_id"]}
        ]
    }

    antes = await vm_client.post(url, headers=auth(token), json=payload)
    assert antes.status_code == 200, antes.text
    entregado = antes.json()["deliveries"][0]["wrap_token"]

    # Se vacia el conjunto de asignaciones.
    vaciado = await bind(vm_client, vm_api, admin_session, consumer, [])
    assert vaciado.status_code == 200
    assert vaciado.json()["total"] == 0
    assert (
        "No caduca un wrapping token ya entregado"
        in vaciado.json()["revocation_note"]
    )

    despues = await vm_client.post(url, headers=auth(token), json=payload)
    assert despues.json()["delivered"] == 0
    assert despues.json()["rejected"][0]["code"] == "binding_missing"

    # Pero lo ya entregado SIGUE siendo valido: revocar no caduca una envoltura
    # que ya viaja. Es un limite real y la respuesta lo dice.
    datos = await apps["kv"].unwrap(entregado)
    assert datos["data"]["values"]["usuario"] == "demo"


async def test_consumidor_revocado_no_resuelve(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )
    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection["collection_id"],
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )

    factory = get_vm_session_factory()
    async with factory() as session:
        await session.execute(
            text(
                "UPDATE vault_mgmt.secret_consumers "
                "SET state = 'revoked', revoked_at = now() WHERE name = :name"
            ),
            {"name": consumer.name},
        )
        await session.commit()

    token = issue_token(apps, consumer)
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {
                    "collection_id": collection["collection_id"],
                    "record_id": record["record_id"],
                }
            ]
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "consumer_revoked"


async def test_coleccion_archivada_no_prepara_entregas(
    vm_client, vm_api, um_client, um_api, admin_session, apps
):
    from tests.vault_mgmt.conftest import step_up

    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )
    token = issue_token(apps, consumer)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="collection_soft_delete_batch",
        collection_id=collection_id,
        resource_ids=[record["record_id"]],
    )
    archivada = await vm_client.delete(
        f"{vm_api}/vault/collections/{collection_id}",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
    )
    assert archivada.status_code == 204, archivada.text

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": collection_id, "record_id": record["record_id"]}
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["delivered"] == 0
    assert response.json()["rejected"][0]["code"] == "collection_archived"


async def test_no_se_asigna_un_registro_destruido(
    vm_client, vm_api, um_client, um_api, admin_session
):
    from tests.vault_mgmt.conftest import step_up

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

    consumer = await register_consumer()
    response = await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )
    assert response.status_code == 409
    assert response.json()["code"] == "record_destroyed"


async def test_no_se_fija_una_version_que_no_existe(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )
    consumer = await register_consumer()

    response = await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection["collection_id"],
                "record_id": record["record_id"],
                "pinned_version": 99,
            }
        ],
    )
    assert response.status_code == 422
    assert response.json()["code"] == "pinned_version_unknown"


async def test_solo_admin_gestiona_bindings(vm_client, vm_api, manager_session):
    consumer = await register_consumer()
    response = await vm_client.get(
        f"{vm_api}/vault/consumers/{consumer.consumer_id}/bindings",
        headers=auth(manager_session),
    )
    assert response.status_code == 403


async def test_consumidor_inexistente(vm_client, vm_api, admin_session):
    response = await vm_client.get(
        f"{vm_api}/vault/consumers/{uuid.uuid4()}/bindings",
        headers=auth(admin_session),
    )
    assert response.status_code == 404
    assert response.json()["code"] == "consumer_not_found"
    assert "crawler-approle-bootstrap.sh" in response.json()["message"]


async def test_tope_de_registros_por_peticion(vm_client, vm_api, apps):
    consumer = await register_consumer()
    token = issue_token(apps, consumer)

    settings = apps["vault_mgmt"].state.settings
    demasiados = [
        {"collection_id": str(uuid.uuid4()), "record_id": str(uuid.uuid4())}
        for _ in range(settings.max_crawler_records + 1)
    ]
    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={"records": demasiados},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "too_many_records"


async def test_vault_deniega_a_la_maquina_aunque_tenga_binding(
    vm_client, vm_api, admin_session, apps
):
    """La ACL de la maquina manda sobre su binding."""
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )
    token = issue_token(apps, consumer)
    apps["kv"].denied_paths.add(
        f"{collection['physical_prefix']}/{record['record_id']}"
    )

    response = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": collection_id, "record_id": record["record_id"]}
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["delivered"] == 0
    assert response.json()["rejected"][0]["code"] == "vault_denied"


async def test_la_auditoria_de_maquina_queda_registrada(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    consumer = await register_consumer()
    await bind(
        vm_client,
        vm_api,
        admin_session,
        consumer,
        [
            {
                "collection_id": collection_id,
                "record_id": record["record_id"],
                "pinned_version": None,
            }
        ],
    )
    token = issue_token(apps, consumer)
    entrega = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        headers=auth(token),
        json={
            "records": [
                {"collection_id": collection_id, "record_id": record["record_id"]}
            ],
            "job_reference": "tarea-sat-de-prueba",
        },
    )
    assert entrega.status_code == 200, entrega.text
    wrap_token = entrega.json()["deliveries"][0]["wrap_token"]

    auditoria = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"record_id": record["record_id"], "action": "crawler_resolve"},
    )
    assert auditoria.status_code == 200
    items = auditoria.json()["items"]
    assert items
    assert items[0]["actor_kind"] == "machine"
    assert items[0]["actor_label"] == consumer.name
    assert "tarea-sat-de-prueba" in items[0]["detail"]
    # Ni el wrapping token ni los valores.
    assert wrap_token not in auditoria.text
    assert "valor-ficticio" not in auditoria.text
