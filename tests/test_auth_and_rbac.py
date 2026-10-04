"""Login/MFA, sesiones y matriz de permisos.

El MFA que se ejercita aqui es el **doble controlado**. El login con un codigo
TOTP real del titular es una comprobacion manual (README, etapa 2 y 3) y no se
deduce de estas pruebas.
"""

from __future__ import annotations

import pytest

from tests.conftest import GOOD_TOTP, auth

pytestmark = pytest.mark.asyncio


async def test_login_devuelve_desafio_y_no_sesion(client, api, vault):
    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "contrasena-de-prueba"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert "challenge_id" in body
    # Lo importante: ni sesion ni token en el paso 1.
    assert "api_session" not in body
    assert not any("token" in key.lower() for key in body)


async def test_login_con_contrasena_incorrecta(client, api):
    response = await client.post(
        f"{api}/auth/login", json={"username": "ada.admin", "password": "mala"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "unauthenticated"


async def test_usuario_inexistente_no_se_distingue(client, api):
    uno = await client.post(
        f"{api}/auth/login", json={"username": "ada.admin", "password": "mala"}
    )
    otro = await client.post(
        f"{api}/auth/login", json={"username": "nadie.existe", "password": "mala"}
    )
    # Mismo codigo y mismo mensaje: no se filtra que usuarios hay dados de alta.
    assert uno.status_code == otro.status_code == 401
    assert uno.json()["message"] == otro.json()["message"]


async def test_codigo_totp_incorrecto(client, api):
    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "contrasena-de-prueba"},
    )
    challenge = response.json()["challenge_id"]
    response = await client.post(
        f"{api}/auth/mfa/verify", json={"challenge_id": challenge, "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "mfa_failed"


async def test_desafio_no_se_reutiliza(client, api):
    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "contrasena-de-prueba"},
    )
    challenge = response.json()["challenge_id"]
    first = await client.post(
        f"{api}/auth/mfa/verify", json={"challenge_id": challenge, "code": GOOD_TOTP}
    )
    assert first.status_code == 200
    # El mismo desafio no vale dos veces.
    second = await client.post(
        f"{api}/auth/mfa/verify", json={"challenge_id": challenge, "code": GOOD_TOTP}
    )
    assert second.status_code == 401
    assert second.json()["code"] == "challenge_expired"


async def test_sesion_no_expone_token_de_vault(client, api, admin_session, vault):
    response = await client.get(f"{api}/auth/me", headers=auth(admin_session))
    assert response.status_code == 200
    serialized = response.text
    for token in vault.tokens:
        assert token not in serialized
    assert admin_session not in [t for t in vault.tokens]


async def test_pending_pasa_a_confirmed_tras_login_valido(client, api, seeded):
    from sqlalchemy import select

    from app.core.database import get_session_factory
    from app.models.employees import UserVaultIdentity

    factory = get_session_factory()
    async with factory() as session:
        before = (
            await session.execute(
                select(UserVaultIdentity.totp_status).where(
                    UserVaultIdentity.user_id == seeded["admin"]["id"]
                )
            )
        ).scalar_one()
    assert before == "pending"

    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "contrasena-de-prueba"},
    )
    challenge = response.json()["challenge_id"]
    await client.post(
        f"{api}/auth/mfa/verify", json={"challenge_id": challenge, "code": GOOD_TOTP}
    )

    async with factory() as session:
        row = (
            await session.execute(
                select(
                    UserVaultIdentity.totp_status,
                    UserVaultIdentity.totp_confirmed_at,
                    UserVaultIdentity.last_mfa_login_at,
                ).where(UserVaultIdentity.user_id == seeded["admin"]["id"])
            )
        ).one()
    # 'pending' no bloqueo el primer login valido: es justo donde se confirma.
    assert row.totp_status == "confirmed"
    assert row.totp_confirmed_at is not None
    assert row.last_mfa_login_at is not None


async def test_entity_id_distinto_rechaza_la_sesion(client, api, vault, seeded):
    # Vault devuelve una entidad que NO es la registrada en PostgreSQL.
    vault.aliases["ada.admin"] = "99999999-9999-4999-8999-999999999999"
    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "contrasena-de-prueba"},
    )
    challenge = response.json()["challenge_id"]
    response = await client.post(
        f"{api}/auth/mfa/verify", json={"challenge_id": challenge, "code": GOOD_TOTP}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "entity_mismatch"


async def test_logout_revoca_el_token_en_vault(client, api, admin_session, vault):
    assert len(vault.tokens) == 1
    response = await client.post(f"{api}/auth/logout", headers=auth(admin_session))
    assert response.status_code == 204
    assert len(vault.tokens) == 0
    assert len(vault.revoked) == 1
    # Y la sesion deja de servir.
    response = await client.get(f"{api}/auth/me", headers=auth(admin_session))
    assert response.status_code == 401


async def test_sin_cabecera_authorization(client, api):
    response = await client.get(f"{api}/user")
    assert response.status_code == 401


async def test_sesion_inventada(client, api):
    response = await client.get(f"{api}/user", headers=auth("sesion-que-no-existe"))
    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


async def test_employee_no_crea_empleados(client, api, employee_session):
    response = await client.post(
        f"{api}/user",
        headers=auth(employee_session),
        json={
            "username": "nuevo.empleado",
            "profile": {
                "first_name": "Nuevo",
                "last_name_paternal": "Empleado",
                "birth_date": "1995-05-05",
            },
        },
    )
    assert response.status_code == 403


async def test_manager_no_elige_roles(client, api, manager_session):
    response = await client.post(
        f"{api}/user",
        headers=auth(manager_session),
        json={
            "username": "sera.admin",
            "profile": {
                "first_name": "Sera",
                "last_name_paternal": "Admin",
                "birth_date": "1995-05-05",
            },
            "role_codes": ["admin"],
        },
    )
    assert response.status_code == 403
    assert "manager" in response.json()["message"]


async def test_manager_crea_siempre_employee(client, api, manager_session):
    response = await client.post(
        f"{api}/user",
        headers=auth(manager_session),
        json={
            "username": "creado.por.manager",
            "profile": {
                "first_name": "Creado",
                "last_name_paternal": "Manager",
                "birth_date": "1995-05-05",
            },
        },
    )
    assert response.status_code == 201
    assert response.json()["role_codes"] == ["employee"]


async def test_admin_elige_roles_existentes(client, api, admin_session):
    response = await client.post(
        f"{api}/user",
        headers=auth(admin_session),
        json={
            "username": "creado.por.admin",
            "profile": {
                "first_name": "Creado",
                "last_name_paternal": "Admin",
                "birth_date": "1995-05-05",
            },
            "role_codes": ["manager", "employee"],
        },
    )
    assert response.status_code == 201
    assert sorted(response.json()["role_codes"]) == ["employee", "manager"]


async def test_rol_inexistente_no_se_crea(client, api, admin_session):
    response = await client.post(
        f"{api}/user",
        headers=auth(admin_session),
        json={
            "username": "rol.raro",
            "profile": {
                "first_name": "Rol",
                "last_name_paternal": "Raro",
                "birth_date": "1995-05-05",
            },
            "role_codes": ["superusuario"],
        },
    )
    # Literal del DTO: ni siquiera llega al servicio.
    assert response.status_code == 422


async def test_manager_no_asigna_roles(client, api, manager_session, seeded):
    response = await client.put(
        f"{api}/user/{seeded['employee']['id']}/roles",
        headers=auth(manager_session),
        json={"role_codes": ["admin"]},
    )
    assert response.status_code == 403


async def test_ultimo_admin_protegido(client, api, admin_session, seeded):
    response = await client.put(
        f"{api}/user/{seeded['admin']['id']}/roles",
        headers=auth(admin_session),
        json={"role_codes": ["employee"]},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "last_admin_protected"


# ---------------------------------------------------------------------------
# Aislamiento por objeto (IDOR)
# ---------------------------------------------------------------------------


async def test_employee_no_lee_a_otro_aunque_sepa_su_uuid(
    client, api, employee_session, seeded
):
    response = await client.get(
        f"{api}/user/{seeded['manager']['id']}", headers=auth(employee_session)
    )
    # 403 y no un 404 cosmetico: enmascarar no es autorizar.
    assert response.status_code == 403


async def test_employee_lee_su_propia_ficha(client, api, employee_session, seeded):
    response = await client.get(
        f"{api}/user/{seeded['employee']['id']}", headers=auth(employee_session)
    )
    assert response.status_code == 200
    assert response.json()["username"] == "eva.employee"


async def test_employee_no_modifica_a_otro(client, api, employee_session, seeded):
    response = await client.patch(
        f"{api}/user/{seeded['manager']['id']}",
        headers=auth(employee_session),
        json={"emails": [{"email": "intruso@example.invalid"}]},
    )
    assert response.status_code == 403


async def test_employee_modifica_sus_contactos(client, api, employee_session, seeded):
    response = await client.patch(
        f"{api}/user/{seeded['employee']['id']}",
        headers=auth(employee_session),
        json={"emails": [{"email": "eva.nueva@example.invalid", "is_primary": True}]},
    )
    assert response.status_code == 200
    assert response.json()["emails"][0]["email"] == "eva.nueva@example.invalid"


async def test_employee_no_modifica_su_perfil_fiscal(client, api, employee_session, seeded):
    response = await client.patch(
        f"{api}/user/{seeded['employee']['id']}",
        headers=auth(employee_session),
        json={"profile": {"first_name": "Otro"}},
    )
    assert response.status_code == 422


async def test_employee_solo_se_ve_a_si_mismo_en_el_listado(
    client, api, employee_session, seeded
):
    response = await client.get(f"{api}/user", headers=auth(employee_session))
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(seeded["employee"]["id"])


async def test_employee_no_busca_a_otros(client, api, employee_session):
    response = await client.post(
        f"{api}/user/search",
        headers=auth(employee_session),
        json={"username": "ada.admin"},
    )
    assert response.status_code == 403
