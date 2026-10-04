"""Provisionamiento, credenciales, reset de MFA, baja, purga, idempotencia y
fallos parciales."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from app.core.database import get_session_factory
from app.core.vault import VaultError, VaultUnavailable
from app.models.employees import UserVaultIdentity, VaultOperation
from tests.conftest import auth

pytestmark = pytest.mark.asyncio

FICHA = {
    "username": "nuevo.empleado",
    "profile": {
        "first_name": "Nuevo",
        "last_name_paternal": "Empleado",
        "birth_date": "1992-02-02",
    },
}


async def _crear(client, api, session_id) -> str:
    response = await client.post(f"{api}/user", headers=auth(session_id), json=FICHA)
    assert response.status_code == 201, response.text
    return response.json()["id"]


# ---------------------------------------------------------------------------
# Provisionamiento
# ---------------------------------------------------------------------------


async def test_provision_crea_cuenta_entidad_y_semilla(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    response = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["totp_status"] == "pending"
    assert body["totp_enrollment_uri"].startswith("otpauth://")
    assert "una sola vez" in body["warning"].lower()
    # Cache-Control: no-store en la respuesta que lleva el enrolamiento.
    assert response.headers["cache-control"] == "no-store"
    assert "nuevo.empleado" in vault.users
    assert "nuevo.empleado" in vault.aliases


async def test_el_uri_de_enrolamiento_no_aparece_en_get(client, api, admin_session):
    user_id = await _crear(client, api, admin_session)
    await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    response = await client.get(f"{api}/user/{user_id}", headers=auth(admin_session))
    assert response.status_code == 200
    assert "otpauth" not in response.text
    assert "secret=" not in response.text
    assert response.json()["vault_link"]["totp_status"] == "pending"
    # El aviso dice justo lo que hay que entender de 'pending'.
    assert "no demuestra" in response.json()["vault_link"]["notice"]


async def test_get_no_genera_ni_destruye_totp(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    antes = set(vault.totp_secrets)
    for _ in range(3):
        await client.get(f"{api}/user/{user_id}", headers=auth(admin_session))
    assert vault.totp_secrets == antes


async def test_manager_no_provisiona(client, api, manager_session, admin_session):
    user_id = await _crear(client, api, admin_session)
    response = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(manager_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert response.status_code == 403


async def test_politica_fuera_de_la_allowlist(client, api, admin_session):
    user_id = await _crear(client, api, admin_session)
    response = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga", "policy": "vpg-admin"},
    )
    assert response.status_code == 422
    assert "lista aprobada" in response.json()["message"]


async def test_no_se_provisiona_dos_veces(client, api, admin_session):
    user_id = await _crear(client, api, admin_session)
    primera = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert primera.status_code == 201
    segunda = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "otra-contrasena-larga"},
    )
    assert segunda.status_code == 409
    assert segunda.json()["code"] == "already_provisioned"


async def test_idempotency_key_no_repite_la_operacion(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    headers = {**auth(admin_session), "Idempotency-Key": "clave-de-prueba-001"}
    primera = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=headers,
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert primera.status_code == 201
    cuentas = len(vault.users)

    segunda = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=headers,
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert segunda.status_code == 409
    # Y no se creo nada nuevo en Vault.
    assert len(vault.users) == cuentas


# ---------------------------------------------------------------------------
# Fallo parcial y compensacion
# ---------------------------------------------------------------------------


async def test_fallo_en_vault_compensa_lo_creado(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    cuentas_antes = set(vault.users)
    # La generacion de TOTP falla despues de crear cuenta y entidad.
    vault.fail_next = None

    original = vault.generate_totp

    async def boom(method_id: str, entity_id: str) -> str:
        raise VaultError("fallo simulado al generar la semilla")

    vault.generate_totp = boom  # type: ignore[assignment]
    response = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    vault.generate_totp = original  # type: ignore[assignment]

    assert response.status_code == 409
    # Compensacion: lo que creo esta operacion se deshizo.
    assert set(vault.users) == cuentas_antes
    assert "nuevo.empleado" not in vault.aliases

    factory = get_session_factory()
    async with factory() as session:
        operation = (
            await session.execute(
                select(VaultOperation).where(VaultOperation.target_user_id == user_id)
            )
        ).scalar_one()
    assert operation.status == "failed"
    fases = [p["phase"] for p in operation.phases]
    assert "userpass_user_created" in fases
    assert "compensate_userpass" in fases
    # Y el registro no guarda secretos.
    assert "contrasena" not in (operation.error or "").lower()


async def test_vault_caido_devuelve_503(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    vault.fail_next = VaultUnavailable("Vault no responde")
    response = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "upstream_unavailable"


# ---------------------------------------------------------------------------
# Credenciales
# ---------------------------------------------------------------------------


async def test_cambio_de_password(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    response = await client.patch(
        f"{api}/user/{user_id}/vault/credentials",
        headers=auth(admin_session),
        json={"new_password": "contrasena-nueva-larga"},
    )
    assert response.status_code == 200
    assert vault.users["nuevo.empleado"]["password"] == "contrasena-nueva-larga"

    # Y la contrasena NO se guarda en PostgreSQL.
    factory = get_session_factory()
    async with factory() as session:
        hash_local = (
            await session.execute(
                text("SELECT password_hash FROM employees.users WHERE id = :i"),
                {"i": user_id},
            )
        ).scalar_one()
    assert hash_local is None


async def test_rename_sin_password_se_bloquea(client, api, admin_session, vault):
    user_id = await _crear(client, api, admin_session)
    await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    response = await client.patch(
        f"{api}/user/{user_id}/vault/credentials",
        headers=auth(admin_session),
        json={"new_vault_username": "otro.nombre"},
    )
    # No se inventa la contrasena anterior: se pide reintento con una nueva.
    assert response.status_code == 422
    assert response.json()["code"] == "rename_requires_password"
    # Y no se toco nada.
    assert "nuevo.empleado" in vault.users
    assert "otro.nombre" not in vault.users


async def test_rename_conserva_entidad_y_bloquea_el_nombre_viejo(
    client, api, admin_session, vault
):
    user_id = await _crear(client, api, admin_session)
    provision = await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    entidad_original = provision.json()["vault_entity_id"]

    response = await client.patch(
        f"{api}/user/{user_id}/vault/credentials",
        headers=auth(admin_session),
        json={
            "new_vault_username": "nuevo.nombre",
            "new_password": "contrasena-nueva-larga",
        },
    )
    assert response.status_code == 200, response.text

    # El nombre viejo deja de existir; el nuevo apunta a la MISMA entidad, asi
    # que la semilla TOTP ya registrada sigue valiendo.
    assert "nuevo.empleado" not in vault.users
    assert "nuevo.nombre" in vault.users
    assert vault.aliases["nuevo.nombre"] == entidad_original

    factory = get_session_factory()
    async with factory() as session:
        identity = (
            await session.execute(
                select(UserVaultIdentity).where(UserVaultIdentity.user_id == user_id)
            )
        ).scalar_one()
    assert identity.vault_username == "nuevo.nombre"
    assert str(identity.vault_entity_id) == entidad_original


# ---------------------------------------------------------------------------
# Reset de MFA
# ---------------------------------------------------------------------------


async def test_reset_exige_confirmacion_explicita(client, api, admin_session):
    user_id = await _crear(client, api, admin_session)
    response = await client.post(
        f"{api}/user/{user_id}/mfa/reset",
        headers=auth(admin_session),
        json={"reason": "dispositivo perdido"},
    )
    assert response.status_code == 422


async def test_reset_solo_toca_la_entidad_objetivo(client, api, admin_session, vault, seeded):
    user_id = await _crear(client, api, admin_session)
    await client.post(
        f"{api}/user/{user_id}/vault/provision",
        headers=auth(admin_session),
        json={"initial_password": "contrasena-inicial-larga"},
    )
    otras_semillas = {
        vault.aliases[seeded[r]["username"]] for r in ("admin", "manager", "employee")
    }

    response = await client.post(
        f"{api}/user/{user_id}/mfa/reset",
        headers=auth(admin_session),
        json={"confirm": "RESET", "reason": "dispositivo perdido"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["totp_status"] == "reset_required"
    assert body["totp_enrollment_uri"].startswith("otpauth://")

    # Las semillas de los demas siguen intactas y el metodo compartido tambien.
    assert otras_semillas <= vault.totp_secrets

    factory = get_session_factory()
    async with factory() as session:
        identity = (
            await session.execute(
                select(UserVaultIdentity).where(UserVaultIdentity.user_id == user_id)
            )
        ).scalar_one()
    assert identity.totp_status == "reset_required"
    # La confirmacion vigente se limpia: el enrolamiento anterior ya no vale.
    assert identity.totp_confirmed_at is None


async def test_reset_invalida_las_sesiones_del_objetivo(
    client, api, admin_session, vault, seeded
):
    from tests.conftest import login_as

    victima = await login_as(client, api, "eva.employee")
    assert (
        await client.get(f"{api}/auth/me", headers=auth(victima))
    ).status_code == 200

    response = await client.post(
        f"{api}/user/{seeded['employee']['id']}/mfa/reset",
        headers=auth(admin_session),
        json={"confirm": "RESET", "reason": "rotacion"},
    )
    assert response.status_code == 200
    # Su sesion deja de valer.
    assert (
        await client.get(f"{api}/auth/me", headers=auth(victima))
    ).status_code == 401


# ---------------------------------------------------------------------------
# Baja logica y purga
# ---------------------------------------------------------------------------


async def test_baja_deshabilita_la_entidad_en_vault(client, api, admin_session, vault, seeded):
    entity_id = seeded["employee"]["entity_id"]
    assert vault.entities[entity_id]["disabled"] is False

    response = await client.delete(
        f"{api}/user/{seeded['employee']['id']}", headers=auth(admin_session)
    )
    assert response.status_code == 204
    # Deshabilitar la entidad es lo que bloquea tambien los tokens ya emitidos.
    assert vault.entities[entity_id]["disabled"] is True


async def test_baja_incompleta_no_devuelve_204(client, api, admin_session, vault, seeded):
    vault.fail_next = VaultUnavailable("Vault no responde")
    response = await client.delete(
        f"{api}/user/{seeded['employee']['id']}", headers=auth(admin_session)
    )
    # No se anuncia una baja completa si falta bloquear Vault.
    assert response.status_code == 409
    assert response.json()["code"] == "partial_operation"
    assert "NO esta completa" in response.json()["message"]


async def test_un_token_previo_deja_de_valer_tras_la_baja(
    client, api, admin_session, vault, seeded
):
    from tests.conftest import login_as

    victima = await login_as(client, api, "eva.employee")
    assert (await client.get(f"{api}/auth/me", headers=auth(victima))).status_code == 200

    await client.delete(f"{api}/user/{seeded['employee']['id']}", headers=auth(admin_session))
    assert (await client.get(f"{api}/auth/me", headers=auth(victima))).status_code == 401


async def test_no_se_puede_purgar_a_un_activo(client, api, admin_session, seeded):
    response = await client.delete(
        f"{api}/user/{seeded['employee']['id']}/purge", headers=auth(admin_session)
    )
    assert response.status_code == 409
    assert response.json()["code"] == "must_deactivate_first"


async def test_autopurga_bloqueada(client, api, admin_session, seeded):
    response = await client.delete(
        f"{api}/user/{seeded['admin']['id']}/purge", headers=auth(admin_session)
    )
    assert response.status_code == 403
    assert response.json()["code"] == "self_purge_blocked"


async def test_manager_no_purga(client, api, manager_session, admin_session, seeded):
    await client.delete(f"{api}/user/{seeded['employee']['id']}", headers=auth(admin_session))
    response = await client.delete(
        f"{api}/user/{seeded['employee']['id']}/purge", headers=auth(manager_session)
    )
    assert response.status_code == 403


async def test_purga_borra_solo_lo_suyo(client, api, admin_session, vault, seeded):
    objetivo = seeded["employee"]
    otros_usuarios = set(vault.users) - {objetivo["username"]}
    metodo_compartido = await vault.totp_method_id()

    await client.delete(f"{api}/user/{objetivo['id']}", headers=auth(admin_session))
    response = await client.delete(
        f"{api}/user/{objetivo['id']}/purge", headers=auth(admin_session)
    )
    assert response.status_code == 204, response.text

    # Solo sus recursos.
    assert objetivo["username"] not in vault.users
    assert objetivo["entity_id"] not in vault.entities
    assert set(vault.users) == otros_usuarios
    # El metodo TOTP compartido sigue existiendo.
    assert await vault.totp_method_id() == metodo_compartido

    factory = get_session_factory()
    async with factory() as session:
        quedan = (
            await session.execute(
                text("SELECT count(*) FROM employees.users WHERE id = :i"),
                {"i": objetivo["id"]},
            )
        ).scalar_one()
        # La auditoria minima sobrevive al borrado del agregado.
        auditoria = (
            await session.execute(
                text(
                    "SELECT target_username, status FROM employees.vault_operations "
                    "WHERE operation_type = 'user_purge'"
                )
            )
        ).one()
    assert quedan == 0
    assert auditoria.target_username == objetivo["username"]
    assert auditoria.status == "succeeded"


async def test_purga_se_detiene_con_alias_ajenos(client, api, admin_session, vault, seeded):
    objetivo = seeded["employee"]
    # La entidad tiene ademas un alias de OTRO montaje: borrarla destruiria
    # accesos que no son suyos.
    vault.entities[objetivo["entity_id"]]["aliases"].append(
        {"id": "alias-ajeno", "name": "otra.persona", "mount_accessor": "auth_oidc_xxxx"}
    )
    await client.delete(f"{api}/user/{objetivo['id']}", headers=auth(admin_session))
    response = await client.delete(
        f"{api}/user/{objetivo['id']}/purge", headers=auth(admin_session)
    )
    assert response.status_code == 409
    assert response.json()["code"] == "entity_has_foreign_aliases"
    # La entidad sigue ahi.
    assert objetivo["entity_id"] in vault.entities


# ---------------------------------------------------------------------------
# access-check
# ---------------------------------------------------------------------------


async def test_access_check_usa_la_allowlist(client, api, admin_session):
    response = await client.post(
        f"{api}/vault/access-check",
        headers=auth(admin_session),
        json={"resource": "secret/data/cualquier/cosa"},
    )
    assert response.status_code == 422
    assert "allowed" in response.json()["context"]


async def test_access_check_no_revela_valores(client, api, admin_session, vault):
    vault.capabilities = ("read", "list")
    vault.read_result = "autorizada"
    response = await client.post(
        f"{api}/vault/access-check",
        headers=auth(admin_session),
        json={"resource": "crawler_sat"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["result"] == "autorizada"
    assert body["capabilities"] == ["read", "list"]
    assert body["evaluated_with"] == "sesion del usuario"
    # Ni rutas internas ni valores.
    assert "secret/data" not in response.text


async def test_access_check_denegado(client, api, admin_session, vault):
    vault.capabilities = ("deny",)
    vault.read_result = "denegada_por_politica"
    response = await client.post(
        f"{api}/vault/access-check",
        headers=auth(admin_session),
        json={"resource": "crawler_sat"},
    )
    assert response.status_code == 200
    assert response.json()["authorized"] is False
