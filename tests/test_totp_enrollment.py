"""Inscripcion inicial del TOTP propio (etapa 5.1).

Lo que estas pruebas SI demuestran:

* el estado historico y la autorizacion de inscripcion aparecen en el paso 1
  **solo** cuando la contrasena es correcta y hay vinculo registrado;
* la autorizacion es de un solo uso, caduca con el desafio y no vale como
  sesion;
* una semilla que ya existe se respeta: la respuesta es 409 y no se destruye;
* generar la semilla **no** confirma el enrolamiento ni entrega sesion.

Lo que NO demuestran, porque el cliente de Vault es un doble: que el
``admin-generate`` real rechace una entidad que ya tiene semilla, ni que Google
Authenticator acepte el URI. Eso es comprobacion manual y esta documentada en
readme/etapa-5-1-frontend.md.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from app.core.vault import VaultSealed
from tests.conftest import GOOD_TOTP, FakeVault, auth


async def _login(client: AsyncClient, api: str, username: str) -> dict:
    response = await client.post(
        f"{api}/auth/login",
        json={"username": username, "password": "contrasena-de-prueba"},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _set_status(username: str, estado: str) -> None:
    from app.core.database import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        # 'confirmed' exige constancia de cuando se confirmo
        # (user_vault_identity_confirmed_ck): la base no acepta el estado a
        # secas, y esta prueba no es el sitio para saltarse ese invariante.
        await session.execute(
            text(
                "UPDATE employees.user_vault_identity "
                "   SET totp_status = :estado, "
                "       totp_confirmed_at = CASE WHEN :estado = 'confirmed' "
                "            THEN COALESCE(totp_confirmed_at, now()) "
                "            ELSE totp_confirmed_at END "
                " WHERE vault_username = :usuario"
            ),
            {"estado": estado, "usuario": username},
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Paso 1: estado historico y autorizacion
# ---------------------------------------------------------------------------


async def test_login_expone_estado_historico_y_autorizacion(client, api, seeded):
    body = await _login(client, api, "ada.admin")

    assert body["totp_status"] == "pending"
    assert body["enrollment_id"]
    # Sigue sin haber sesion: la ampliacion es aditiva, no un atajo.
    assert "api_session" not in body
    assert body["mfa_required"] is True


async def test_sin_contrasena_correcta_no_hay_estado_ni_autorizacion(client, api, seeded):
    response = await client.post(
        f"{api}/auth/login",
        json={"username": "ada.admin", "password": "la-que-no-es"},
    )
    assert response.status_code == 401
    cuerpo = response.json()
    assert "totp_status" not in cuerpo
    assert "enrollment_id" not in cuerpo


async def test_confirmed_no_recibe_autorizacion(client, api, seeded):
    await _set_status("ada.admin", "confirmed")
    body = await _login(client, api, "ada.admin")

    assert body["totp_status"] == "confirmed"
    assert body["enrollment_id"] is None


async def test_disabled_no_recibe_autorizacion(client, api, seeded):
    await _set_status("eva.employee", "disabled")
    body = await _login(client, api, "eva.employee")

    assert body["totp_status"] == "disabled"
    assert body["enrollment_id"] is None


async def test_reset_required_si_recibe_autorizacion(client, api, seeded):
    await _set_status("eva.employee", "reset_required")
    body = await _login(client, api, "eva.employee")

    assert body["totp_status"] == "reset_required"
    assert body["enrollment_id"]


# ---------------------------------------------------------------------------
# Paso 2: la inscripcion propiamente dicha
# ---------------------------------------------------------------------------


async def test_entidad_sin_semilla_entrega_uri_una_vez(
    client, api, seeded, vault: FakeVault
):
    # Esta identidad no tiene semilla todavia: es el caso del primer arranque.
    vault.totp_secrets.discard(seeded["admin"]["entity_id"])
    body = await _login(client, api, "ada.admin")

    response = await client.post(
        f"{api}/auth/enrollment/totp", json={"enrollment_id": body["enrollment_id"]}
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["totp_enrollment_uri"].startswith("otpauth://")
    assert payload["username"] == "ada.admin"
    # El estado historico NO cambia: generar no confirma nada.
    assert payload["totp_status"] == "pending"
    assert response.headers["cache-control"] == "no-store"
    assert "api_session" not in payload

    # Un solo uso: la segunda vez la autorizacion ya no existe.
    repetida = await client.post(
        f"{api}/auth/enrollment/totp", json={"enrollment_id": body["enrollment_id"]}
    )
    assert repetida.status_code == 401
    assert repetida.json()["code"] == "enrollment_expired"


async def test_semilla_existente_responde_409_y_no_la_destruye(
    client, api, seeded, vault: FakeVault
):
    entity_id = seeded["admin"]["entity_id"]
    assert entity_id in vault.totp_secrets
    body = await _login(client, api, "ada.admin")

    response = await client.post(
        f"{api}/auth/enrollment/totp", json={"enrollment_id": body["enrollment_id"]}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "totp_already_enrolled"
    # Lo que de verdad importa: la semilla de la persona sigue ahi.
    assert entity_id in vault.totp_secrets


async def test_autorizacion_inventada_no_vale(client, api, seeded):
    response = await client.post(
        f"{api}/auth/enrollment/totp",
        json={"enrollment_id": "inventado-" + uuid.uuid4().hex},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "enrollment_expired"


async def test_autorizacion_no_sirve_como_sesion(client, api, seeded):
    body = await _login(client, api, "ada.admin")

    response = await client.get(f"{api}/auth/me", headers=auth(body["enrollment_id"]))
    assert response.status_code == 401


async def test_autorizacion_no_abre_la_herramienta_administrativa(client, api, seeded):
    body = await _login(client, api, "ada.admin")
    objetivo = seeded["employee"]["id"]

    response = await client.post(
        f"{api}/user/{objetivo}/vault/provision",
        headers=auth(body["enrollment_id"]),
        json={"initial_password": "contrasena-inicial-de-prueba"},
    )
    assert response.status_code == 401


async def test_vault_sellado_responde_503_sin_dejar_semilla(
    client, api, seeded, vault: FakeVault
):
    vault.totp_secrets.discard(seeded["admin"]["entity_id"])
    body = await _login(client, api, "ada.admin")
    vault.fail_next = VaultSealed("sellado")

    response = await client.post(
        f"{api}/auth/enrollment/totp", json={"enrollment_id": body["enrollment_id"]}
    )
    assert response.status_code == 503
    assert seeded["admin"]["entity_id"] not in vault.totp_secrets


async def test_inscribirse_no_sustituye_al_mfa(client, api, seeded, vault: FakeVault):
    """Tras inscribirse sigue haciendo falta el codigo para tener sesion."""
    vault.totp_secrets.discard(seeded["admin"]["entity_id"])
    body = await _login(client, api, "ada.admin")

    inscripcion = await client.post(
        f"{api}/auth/enrollment/totp", json={"enrollment_id": body["enrollment_id"]}
    )
    assert inscripcion.status_code == 200

    # El desafio del login sigue vivo y sigue exigiendo el codigo correcto.
    malo = await client.post(
        f"{api}/auth/mfa/verify",
        json={"challenge_id": body["challenge_id"], "code": "000000"},
    )
    assert malo.status_code == 401

    # Y con el codigo correcto si hay sesion (otro login: el desafio se consumio).
    segundo = await _login(client, api, "ada.admin")
    bueno = await client.post(
        f"{api}/auth/mfa/verify",
        json={"challenge_id": segundo["challenge_id"], "code": GOOD_TOTP},
    )
    assert bueno.status_code == 200
    assert bueno.json()["api_session"]


@pytest.mark.parametrize(
    "cuerpo", [{}, {"enrollment_id": ""}, {"enrollment_id": "corto"}]
)
async def test_cuerpos_invalidos_son_422(client, api, seeded, cuerpo):
    response = await client.post(f"{api}/auth/enrollment/totp", json=cuerpo)
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


async def test_cuerpo_con_identidad_ajena_se_rechaza(client, api, seeded):
    """``extra='forbid'``: no se admite colar la entidad de otra persona."""
    body = await _login(client, api, "ada.admin")
    response = await client.post(
        f"{api}/auth/enrollment/totp",
        json={
            "enrollment_id": body["enrollment_id"],
            "entity_id": seeded["employee"]["entity_id"],
        },
    )
    assert response.status_code == 422
