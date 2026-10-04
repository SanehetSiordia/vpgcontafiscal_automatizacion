"""Superficie de seguridad: readiness, rate limiting, saneado de logs y OpenAPI."""

from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import JsonFormatter, scrub, validate_request_id
from app.core.readiness import ReadinessReport
from tests.conftest import auth

# asyncio_mode = auto en pytest.ini: no hace falta marcar cada prueba, y un
# pytestmark global avisaria sobre las pruebas sincronas de este modulo.


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------


async def test_live_responde_siempre(client):
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


async def test_ready_en_verde(client):
    response = await client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["ready"] is True


async def test_ready_devuelve_503_si_falta_algo(client, app):
    app.state.readiness._report = ReadinessReport(  # noqa: SLF001
        database=True,
        vault_initialized=True,
        vault_unsealed=False,
        vault_technical_credential=False,
        admin_linked=False,
        detail="vault: sellado ('vault operator unseal', paso manual)",
    )
    response = await client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["checks"]["vault_unsealed"] is False
    assert "sellado" in body["detail"]


async def test_negocio_bloqueado_con_vault_sellado(client, app, admin_session):
    app.state.readiness._report = ReadinessReport(database=True)  # noqa: SLF001
    response = await client.get("/user", headers=auth(admin_session))
    assert response.status_code in (404, 503)
    response = await client.get(
        f"{app.state.settings.api_prefix}/user", headers=auth(admin_session)
    )
    assert response.status_code == 503
    assert response.json()["code"] == "not_ready"


async def test_ready_no_expone_secretos(client):
    response = await client.get("/health/ready")
    texto = response.text.lower()
    for prohibido in ("password", "secret_id", "role_id", "token", "hvs."):
        assert prohibido not in texto


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


async def test_rate_limit_en_login_con_retry_after(client, api, app):
    await app.state.limiter.reset()
    limite = app.state.settings.rate_limit_login_per_minute
    codigos = []
    for _ in range(limite + 3):
        response = await client.post(
            f"{api}/auth/login",
            json={"username": "ada.admin", "password": "mala"},
        )
        codigos.append(response.status_code)
        if response.status_code == 429:
            assert "Retry-After" in response.headers
            assert int(response.headers["Retry-After"]) > 0
            assert response.json()["code"] == "rate_limited"
            break
    assert 429 in codigos
    await app.state.limiter.reset()


# ---------------------------------------------------------------------------
# Saneado de logs
# ---------------------------------------------------------------------------


def test_scrub_elimina_campos_sensibles():
    sucio = {
        "password": "secreta",
        "code": "123456",
        "token": "hvs.ABCDEF",
        "nested": {"secret_id": "abc", "ok": "visible"},
        "lista": [{"client_token": "hvs.XYZ"}],
    }
    limpio = scrub(sucio)
    serializado = json.dumps(limpio)
    assert "secreta" not in serializado
    assert "123456" not in serializado
    assert "hvs.ABCDEF" not in serializado
    assert "hvs.XYZ" not in serializado
    assert "visible" in serializado


def test_scrub_elimina_patrones_en_texto_libre():
    assert "hvs." not in scrub("el token hvs.CAESIJxyz fallo")
    assert "otpauth" not in scrub("uri otpauth://totp/x?secret=ABC generado").lower()


def test_formateador_json_sanea_los_extras():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        "t", logging.INFO, "f", 1, "login de %s", ("ada",), None
    )
    record.password = "no-deberia-salir"   # type: ignore[attr-defined]
    record.actor = "ada.admin"             # type: ignore[attr-defined]
    salida = json.loads(formatter.format(record))
    assert salida["password"] == "[REDACTADO]"
    assert salida["actor"] == "ada.admin"
    assert salida["level"] == "info"


def test_request_id_del_cliente_se_valida():
    assert validate_request_id("abc-123_456:7") == "abc-123_456:7"
    # Un valor con salto de linea no puede inyectar lineas en el log.
    inyectado = validate_request_id("malo\nINFO: falso")
    assert "\n" not in inyectado
    assert len(validate_request_id(None)) == 32
    assert len(validate_request_id("x" * 500)) == 32


async def test_cabecera_request_id_vuelve_en_la_respuesta(client):
    response = await client.get("/health/live", headers={"X-Request-ID": "prueba-123"})
    assert response.headers["X-Request-ID"] == "prueba-123"


async def test_error_incluye_request_id(client, api):
    response = await client.get(f"{api}/user", headers={"X-Request-ID": "err-001"})
    assert response.status_code == 401
    assert response.json()["request_id"] == "err-001"


async def test_la_validacion_no_devuelve_el_valor_enviado(client, api):
    response = await client.post(
        f"{api}/auth/mfa/verify",
        json={"challenge_id": "x" * 10, "code": "no-son-digitos"},
    )
    assert response.status_code == 422
    # El motivo si, el valor no.
    assert "no-son-digitos" not in response.text
    assert "6 digitos" in response.text


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


async def test_openapi_documenta_errores_y_esquemas(client):
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    spec = response.json()
    prefix = "/user_mgmt/v1"

    # El contrato original conserva /user.
    assert f"{prefix}/user" in spec["paths"]
    for ruta, metodo in (
        (f"{prefix}/user", "post"),
        (f"{prefix}/user/{{user_id}}", "put"),
        (f"{prefix}/user/{{user_id}}", "patch"),
        (f"{prefix}/user/{{user_id}}/purge", "delete"),
        (f"{prefix}/auth/login", "post"),
        (f"{prefix}/vault/access-check", "post"),
    ):
        assert metodo in spec["paths"][ruta], f"falta {metodo.upper()} {ruta}"

    # PUT y PATCH tienen cuerpos distintos: semanticas distintas.
    put_body = spec["paths"][f"{prefix}/user/{{user_id}}"]["put"]["requestBody"]
    patch_body = spec["paths"][f"{prefix}/user/{{user_id}}"]["patch"]["requestBody"]
    assert put_body != patch_body

    # Esquema de error documentado.
    assert "ErrorDetail" in spec["components"]["schemas"]

    # Codigos de respuesta esperados en el alta.
    respuestas = spec["paths"][f"{prefix}/user"]["post"]["responses"]
    for codigo in ("201", "401", "403", "409", "422", "429", "503"):
        assert codigo in respuestas, f"falta la respuesta {codigo} en POST /user"


async def test_openapi_no_contiene_datos_reales(client):
    """Los ejemplos son ficticios: ni el administrador real ni su correo."""
    response = await client.get("/openapi.json")
    texto = response.text.lower()
    for prohibido in ("sinhuesiordia", "carpediem.sinhue", "sims920425"):
        assert prohibido not in texto


async def test_openapi_describe_el_esquema_bearer(client):
    spec = (await client.get("/openapi.json")).json()
    schemes = spec["components"].get("securitySchemes", {})
    assert any(s.get("scheme") == "bearer" for s in schemes.values())
