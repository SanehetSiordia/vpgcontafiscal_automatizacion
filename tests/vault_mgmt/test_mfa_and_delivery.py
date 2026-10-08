"""Prueba de MFA reciente y entrega de secretos.

Sobre la prueba de MFA:

* se emite en user-mgmt tras un **login completo** (contrasena + TOTP del
  titular), no con un booleano que envie el cliente y no comparando digitos en
  PostgreSQL;
* esta ligada a la sesion, al actor, a la operacion y al **conjunto cerrado** de
  recursos: presentarla para otra cosa falla;
* es de **un solo uso** y caduca;
* no sobrevive al cierre de su sesion.

Sobre la entrega:

* envuelta por defecto (response wrapping de Vault, un solo uso, TTL corto);
* ``plain`` solo por eleccion explicita, con ``Cache-Control: no-store``;
* el wrapping token no aparece en la auditoria ni en los listados.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.vault import VaultError
from tests.conftest import GOOD_TOTP
from tests.vault_mgmt.conftest import (
    auth,
    create_collection,
    create_record,
    step_up,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Prueba de MFA
# ---------------------------------------------------------------------------


async def test_step_up_exige_login_completo_del_titular(
    um_client, um_api, admin_session
):
    mala = await um_client.post(
        f"{um_api}/auth/mfa/step-up",
        headers=auth(admin_session),
        json={
            "password": "contrasena-equivocada",
            "operation": "record_purge",
            "collection_id": None,
            "resource_ids": [],
        },
    )
    assert mala.status_code == 401
    assert mala.json()["code"] == "step_up_failed"

    buena = await um_client.post(
        f"{um_api}/auth/mfa/step-up",
        headers=auth(admin_session),
        json={
            "password": "contrasena-de-prueba",
            "operation": "record_purge",
            "collection_id": None,
            "resource_ids": [],
        },
    )
    assert buena.status_code == 200
    # Todavia NO hay prueba: hace falta el codigo TOTP.
    assert "mfa_proof" not in buena.text
    assert buena.json()["mfa_required"] is True

    codigo_malo = await um_client.post(
        f"{um_api}/auth/mfa/step-up/verify",
        headers=auth(admin_session),
        json={"challenge_id": buena.json()["challenge_id"], "code": "000000"},
    )
    assert codigo_malo.status_code == 401
    assert codigo_malo.json()["code"] == "mfa_failed"


async def test_el_desafio_de_step_up_no_se_reutiliza(um_client, um_api, admin_session):
    inicio = await um_client.post(
        f"{um_api}/auth/mfa/step-up",
        headers=auth(admin_session),
        json={
            "password": "contrasena-de-prueba",
            "operation": "record_purge",
            "collection_id": None,
            "resource_ids": [],
        },
    )
    challenge = inicio.json()["challenge_id"]

    primera = await um_client.post(
        f"{um_api}/auth/mfa/step-up/verify",
        headers=auth(admin_session),
        json={"challenge_id": challenge, "code": GOOD_TOTP},
    )
    assert primera.status_code == 200

    segunda = await um_client.post(
        f"{um_api}/auth/mfa/step-up/verify",
        headers=auth(admin_session),
        json={"challenge_id": challenge, "code": GOOD_TOTP},
    )
    assert segunda.status_code == 401
    assert segunda.json()["code"] == "step_up_expired"


async def test_la_prueba_es_de_un_solo_uso(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    primero = await create_record(vm_client, vm_api, admin_session, collection_id)
    segundo = await create_record(vm_client, vm_api, admin_session, collection_id)

    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="record_purge",
        collection_id=collection_id,
        resource_ids=[primero["record_id"], segundo["record_id"]],
    )
    headers = {**auth(admin_session), "X-VPG-MFA-Proof": proof}

    primera = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{primero['record_id']}/purge",
        headers=headers,
        json={"confirm": "PURGE"},
    )
    assert primera.status_code == 204

    # Aunque la prueba cubriera los dos recursos, ya se consumio.
    segunda = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{segundo['record_id']}/purge",
        headers=headers,
        json={"confirm": "PURGE"},
    )
    assert segunda.status_code == 403
    assert segunda.json()["code"] == "mfa_proof_invalid"


async def test_la_prueba_esta_ligada_a_la_operacion_y_al_recurso(
    vm_client, vm_api, um_client, um_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    objetivo = await create_record(vm_client, vm_api, admin_session, collection_id)
    otro = await create_record(vm_client, vm_api, admin_session, collection_id)

    # Prueba emitida para destruir versiones de 'objetivo'.
    proof = await step_up(
        um_client,
        um_api,
        admin_session,
        operation="versions_destroy",
        collection_id=collection_id,
        resource_ids=[objetivo["record_id"]],
    )

    # Se intenta usar para PURGAR otro registro: operacion distinta y recurso
    # distinto.
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{otro['record_id']}/purge",
        headers={**auth(admin_session), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mfa_proof_scope_mismatch"
    assert "conjunto cerrado" in response.json()["message"]


async def test_la_prueba_de_otra_sesion_no_sirve(
    vm_client, vm_api, um_client, um_api, admin_session
):
    from tests.vault_mgmt.conftest import login

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

    # Segunda sesion del MISMO administrador: la prueba sigue ligada a la
    # primera.
    otra_sesion = await login(um_client, um_api, "ada.admin")
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/purge",
        headers={**auth(otra_sesion), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mfa_proof_scope_mismatch"


async def test_la_prueba_no_sobrevive_al_cierre_de_su_sesion(
    vm_client, vm_api, um_client, um_api, admin_session
):
    from tests.vault_mgmt.conftest import login

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
    await um_client.post(f"{um_api}/auth/logout", headers=auth(admin_session))

    nueva = await login(um_client, um_api, "ada.admin")
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/purge",
        headers={**auth(nueva), "X-VPG-MFA-Proof": proof},
        json={"confirm": "PURGE"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mfa_proof_invalid"


async def test_una_prueba_inventada_no_vale(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/purge",
        headers={
            **auth(admin_session),
            "X-VPG-MFA-Proof": "prueba-inventada-" + uuid.uuid4().hex,
        },
        json={"confirm": "PURGE"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mfa_proof_invalid"


# ---------------------------------------------------------------------------
# Entrega
# ---------------------------------------------------------------------------


async def test_entrega_envuelta_por_defecto(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"

    delivery = response.json()["delivery"]
    assert delivery["mode"] == "wrapped"
    assert delivery["wrap_token"].startswith("hvs.")
    assert delivery["ttl_seconds"] == 60
    # La respuesta no lleva los valores.
    assert "valor-ficticio" not in response.text
    assert "values" not in delivery
    # Y avisa de lo que el wrapping es y de lo que no es.
    assert "un solo uso" in delivery["note"].lower()
    assert "sys/wrapping/unwrap" in delivery["unwrap_hint"]

    # El token se desenvuelve en Vault, y solo una vez.
    datos = await apps["kv"].unwrap(delivery["wrap_token"])
    assert datos["data"]["values"]["password"] == "valor-ficticio"
    with pytest.raises(VaultError, match="consumido"):
        await apps["kv"].unwrap(delivery["wrap_token"])


async def test_entrega_plana_solo_si_se_pide(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={"delivery": "plain", "reason": "comprobacion manual documentada"},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    delivery = response.json()["delivery"]
    assert delivery["mode"] == "plain"
    assert delivery["values"] == {"usuario": "demo", "password": "valor-ficticio"}
    assert delivery["schema_version"] == 1
    assert "no hay cifrado en transito" in delivery["note"]


async def test_wrapping_caducado_o_consumido_se_puede_volver_a_pedir(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    url = f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read"

    primera = await vm_client.post(url, headers=auth(admin_session), json={})
    token = primera.json()["delivery"]["wrap_token"]
    await apps["kv"].unwrap(token)

    # Reutilizarlo falla...
    with pytest.raises(VaultError, match="consumido"):
        await apps["kv"].unwrap(token)

    # ...y pedir otra entrega funciona sin repetir ninguna tarea.
    segunda = await vm_client.post(url, headers=auth(admin_session), json={})
    assert segunda.status_code == 200
    nuevo = segunda.json()["delivery"]["wrap_token"]
    assert nuevo != token
    datos = await apps["kv"].unwrap(nuevo)
    assert datos["data"]["values"]["usuario"] == "demo"


async def test_lector_autorizado_no_admin_puede_leer(
    vm_client, vm_api, admin_session, manager_session
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin", "manager"]
    )
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(manager_session),
        json={},
    )
    assert response.status_code == 200
    assert response.json()["delivery"]["mode"] == "wrapped"


async def test_lector_no_autorizado_no_lee(
    vm_client, vm_api, admin_session, employee_session
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin", "manager"]
    )
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(employee_session),
        json={},
    )
    assert response.status_code == 403


async def test_la_auditoria_registra_la_entrega_sin_el_token_ni_los_valores(
    vm_client, vm_api, admin_session
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)

    lectura = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record['record_id']}/read",
        headers=auth(admin_session),
        json={"reason": "motivo de la auditoria"},
    )
    token = lectura.json()["delivery"]["wrap_token"]

    auditoria = await vm_client.get(
        f"{vm_api}/vault/audit",
        headers=auth(admin_session),
        params={"record_id": record["record_id"], "action": "record_read"},
    )
    assert auditoria.status_code == 200
    items = auditoria.json()["items"]
    assert items and items[0]["outcome"] == "allowed"
    assert "entrega 'wrapped'" in items[0]["detail"]
    assert "motivo de la auditoria" in items[0]["detail"]
    # El wrapping token y los valores NO estan en la auditoria.
    assert token not in auditoria.text
    assert "valor-ficticio" not in auditoria.text


async def test_solo_admin_ve_la_auditoria(vm_client, vm_api, manager_session):
    response = await vm_client.get(
        f"{vm_api}/vault/audit", headers=auth(manager_session)
    )
    assert response.status_code == 403
