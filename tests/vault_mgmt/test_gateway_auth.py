"""Autenticacion y autorizacion entre procesos.

Aqui se comprueba lo que de verdad protege el sistema:

* una sesion inventada o revocada no sirve;
* un empleado desactivado pierde el acceso aunque su sesion siga en memoria;
* los roles se releen de PostgreSQL: retirarlos surte efecto en la peticion
  siguiente, sin esperar a que caduque la sesion;
* **Vault manda**: si su politica no cubre el path, la operacion falla aunque el
  rol de aplicacion la permita;
* la credencial interna **no** sustituye al Bearer humano, y al reves tampoco;
* no hay forma de pedir un path, un montaje ni una URL de Vault arbitrarios;
* la pasarela no devuelve tokens de Vault.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.core.database import get_session_factory as get_um_session_factory
from tests.vault_mgmt.conftest import (
    INTERNAL_CREDENTIAL,
    auth,
    create_collection,
    create_record,
)

pytestmark = pytest.mark.asyncio

INTERNAL = "/internal/v1/vault-mgmt"


# ---------------------------------------------------------------------------
# Sesion humana
# ---------------------------------------------------------------------------


async def test_sin_bearer_no_hay_nada(vm_client, vm_api):
    response = await vm_client.get(f"{vm_api}/vault/collections")
    assert response.status_code == 401
    assert "api_session" in response.json()["message"]


async def test_sesion_inventada(vm_client, vm_api):
    response = await vm_client.get(
        f"{vm_api}/vault/collections",
        headers=auth("sesion-que-no-existe-" + uuid.uuid4().hex),
    )
    assert response.status_code == 401
    assert response.json()["code"] in ("session_expired", "unauthenticated")


async def test_sesion_revocada_con_logout(vm_client, vm_api, um_client, um_api, admin_session):
    # Funciona antes del logout.
    antes = await vm_client.get(
        f"{vm_api}/vault/collections", headers=auth(admin_session)
    )
    assert antes.status_code == 200

    cerrada = await um_client.post(
        f"{um_api}/auth/logout", headers=auth(admin_session)
    )
    assert cerrada.status_code == 204

    despues = await vm_client.get(
        f"{vm_api}/vault/collections", headers=auth(admin_session)
    )
    assert despues.status_code == 401


async def test_empleado_desactivado_pierde_el_acceso(
    vm_client, vm_api, admin_session, employee_session, seeded
):
    factory = get_um_session_factory()
    async with factory() as session:
        await session.execute(
            text("UPDATE employees.users SET is_active = false WHERE id = :id"),
            {"id": seeded["employee"]["id"]},
        )
        await session.commit()

    response = await vm_client.get(
        f"{vm_api}/vault/collections", headers=auth(employee_session)
    )
    assert response.status_code == 401
    assert response.json()["code"] == "inactive_user"


async def test_roles_retirados_surten_efecto_en_la_siguiente_peticion(
    vm_client, vm_api, admin_session, seeded
):
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin"]
    )
    assert collection["state"] == "active"

    # Se le retira el rol admin con la sesion ya abierta.
    factory = get_um_session_factory()
    async with factory() as session:
        await session.execute(
            text(
                "DELETE FROM employees.user_roles ur USING employees.roles r "
                "WHERE ur.role_id = r.id AND ur.user_id = :id AND r.code = 'admin'"
            ),
            {"id": seeded["admin"]["id"]},
        )
        await session.commit()

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection['collection_id']}/records",
        headers=auth(admin_session),
        json={"values": {"usuario": "demo", "password": "x"}},
    )
    # Los roles se releen de PostgreSQL en cada peticion: no hace falta esperar
    # a que caduque la sesion.
    assert response.status_code == 403
    assert response.json()["context"]["your_roles"] == []


async def test_vault_deniega_aunque_el_rol_permita(
    vm_client, vm_api, admin_session, apps
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    collection_id = collection["collection_id"]
    record = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = record["record_id"]

    # La politica de Vault deja de cubrir ese path concreto.
    apps["kv"].denied_paths.add(f"{collection['physical_prefix']}/{record_id}")

    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}/read",
        headers=auth(admin_session),
        json={"delivery": "plain"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "vault_policy_denied"
    # Y se dice lo que significa un 403 de Vault: sin permiso, NO inexistente.
    assert "no se concluye su inexistencia" in response.json()["message"]

    escritura = await vm_client.put(
        f"{vm_api}/vault/collections/{collection_id}/records/{record_id}",
        headers=auth(admin_session),
        json={"expected_version": 1, "values": {"usuario": "demo", "password": "x"}},
    )
    assert escritura.status_code == 403
    assert escritura.json()["code"] == "vault_policy_denied"


# ---------------------------------------------------------------------------
# Pasarela interna
# ---------------------------------------------------------------------------


async def test_credencial_interna_sin_bearer_no_autoriza(um_client, admin_session):
    """La credencial de servicio NO sustituye la autorizacion de la persona."""
    response = await um_client.post(
        f"{INTERNAL}/session",
        headers={"X-VPG-Internal-Credential": INTERNAL_CREDENTIAL},
    )
    assert response.status_code == 401
    assert "Authorization" in response.json()["message"]


async def test_bearer_sin_credencial_interna_no_autoriza(um_client, admin_session):
    """Y al reves: el Bearer humano por si solo no abre la pasarela."""
    response = await um_client.post(
        f"{INTERNAL}/session", headers=auth(admin_session)
    )
    assert response.status_code == 401
    assert response.json()["code"] == "internal_credential_invalid"


async def test_credencial_interna_incorrecta(um_client, admin_session):
    response = await um_client.post(
        f"{INTERNAL}/session",
        headers={
            **auth(admin_session),
            "X-VPG-Internal-Credential": "valor-que-no-es",
        },
    )
    assert response.status_code == 401
    assert response.json()["code"] == "internal_credential_invalid"


async def test_la_pasarela_no_devuelve_el_token_de_vault(um_client, admin_session):
    response = await um_client.post(
        f"{INTERNAL}/session",
        headers={
            **auth(admin_session),
            "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "user_id",
        "username",
        "role_codes",
        "entity_id",
        "mfa_age_seconds",
        "mfa_verified_at",
        "session_expires_at",
    }
    # Ni token, ni accessor, ni politicas de Vault.
    assert "token" not in response.text.lower()
    assert "accessor" not in response.text.lower()
    assert body["role_codes"] == ["admin"]


async def test_la_pasarela_no_acepta_paths_ni_montajes_arbitrarios(
    um_client, admin_session, vm_client, vm_api
):
    """El contrato no tiene hueco para una ruta de Vault, y lo rechaza si se cuela."""
    collection = await create_collection(vm_client, vm_api, admin_session)
    headers = {
        **auth(admin_session),
        "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
    }

    for intento in (
        {"path": "secret/data/otra-cosa"},
        {"mount": "otro-montaje"},
        {"url": "http://vault-service:8200/v1/sys/policies"},
        {"vault_path": "auth/token/create"},
        {"endpoint": "sys/mounts"},
    ):
        response = await um_client.post(
            f"{INTERNAL}/execute",
            headers=headers,
            json={
                "operation": "record_read",
                "collection_id": collection["collection_id"],
                "record_id": str(uuid.uuid4()),
                **intento,
            },
        )
        # extra="forbid": un campo no declarado es 422, no se ignora en silencio.
        assert response.status_code == 422, (intento, response.text)


async def test_la_pasarela_rechaza_operaciones_fuera_de_la_allowlist(
    um_client, admin_session, vm_client, vm_api
):
    collection = await create_collection(vm_client, vm_api, admin_session)
    headers = {
        **auth(admin_session),
        "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
    }

    for operacion in (
        "token_create",
        "policy_write",
        "mount_enable",
        "sys_seal",
        "record_read_all",
    ):
        response = await um_client.post(
            f"{INTERNAL}/execute",
            headers=headers,
            json={
                "operation": operacion,
                "collection_id": collection["collection_id"],
            },
        )
        assert response.status_code == 422, (operacion, response.text)


async def test_la_pasarela_no_aparece_en_el_openapi_publico(um_client, vm_client):
    para_user_mgmt = await um_client.get("/openapi.json")
    assert para_user_mgmt.status_code == 200
    rutas = para_user_mgmt.json()["paths"]
    assert not any(ruta.startswith("/internal/") for ruta in rutas)

    para_vault_mgmt = await vm_client.get("/openapi.json")
    assert para_vault_mgmt.status_code == 200
    assert not any(
        ruta.startswith("/internal/") for ruta in para_vault_mgmt.json()["paths"]
    )


async def test_coleccion_inexistente_en_la_pasarela(um_client, admin_session):
    response = await um_client.post(
        f"{INTERNAL}/execute",
        headers={
            **auth(admin_session),
            "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
        },
        json={
            "operation": "record_read",
            "collection_id": str(uuid.uuid4()),
            "record_id": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 404
    assert response.json()["code"] == "collection_not_found"


async def test_la_pasarela_vuelve_a_autorizar_por_su_cuenta(
    um_client, vm_client, vm_api, admin_session, manager_session
):
    """Aunque el llamante afirme lo que quiera, la pasarela decide de nuevo."""
    collection = await create_collection(
        vm_client, vm_api, admin_session, readers=["admin", "manager"]
    )
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )

    # El manager llama a la pasarela DIRECTAMENTE con la credencial interna,
    # saltandose vault-mgmt, y pide una escritura.
    response = await um_client.post(
        f"{INTERNAL}/execute",
        headers={
            **auth(manager_session),
            "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
        },
        json={
            "operation": "record_replace",
            "collection_id": collection["collection_id"],
            "record_id": record["record_id"],
            "expected_version": 1,
            "values": {"usuario": "demo", "password": "intento"},
        },
    )
    assert response.status_code == 403
    assert response.json()["context"]["required_role"] == "admin"


async def test_la_pasarela_revalida_el_esquema_aunque_el_llamante_no(
    um_client, vm_client, vm_api, admin_session, apps
):
    """La validacion no se delega al llamante: la pasarela es la frontera."""
    collection = await create_collection(vm_client, vm_api, admin_session)
    record = await create_record(
        vm_client, vm_api, admin_session, collection["collection_id"]
    )

    response = await um_client.post(
        f"{INTERNAL}/execute",
        headers={
            **auth(admin_session),
            "X-VPG-Internal-Credential": INTERNAL_CREDENTIAL,
        },
        json={
            "operation": "record_replace",
            "collection_id": collection["collection_id"],
            "record_id": record["record_id"],
            "expected_version": 1,
            # Falta 'password', que es obligatorio, y sobra 'inventado'.
            "values": {"usuario": "demo", "inventado": "x"},
        },
    )
    assert response.status_code == 422
    campos = [item["field"] for item in response.json()["context"]["fields"]]
    assert "values.password" in campos
    assert "values.inventado" in campos
    # No se escribio: sigue habiendo una sola version.
    path = f"{collection['physical_prefix']}/{record['record_id']}"
    assert sorted(apps["kv"].store[path]["versions"]) == [1]
