"""El cliente de AppRole contra un transporte HTTP falso (etapa 4.6).

Por que esta prueba existe
--------------------------
El resto de la suite sustituye ``AppRoleAdminClient`` por un doble
(``FakeAppRole``). Eso prueba muy bien la maquina de estados del
aprovisionamiento, y no prueba **nada** del propio cliente: un doble no valida a
quien reemplaza.

Y ahi hubo un fallo real. ``auth/<montaje>/role/<rol>/secret-id`` declara su
campo ``metadata`` como **string** y espera un JSON ya serializado. El cliente
le enviaba un objeto, Vault respondia 400 (``expected type 'string', got
unconvertible type 'map[string]interface {}'``) y el claim devolvia 503. Las 38
pruebas de la etapa seguian en verde, porque el doble aceptaba el diccionario
sin quejarse.

Asi que este modulo prueba el cliente **de verdad** contra un transporte
``httpx.MockTransport``, afirmando sobre el **cuerpo que sale por el cable**:
paths, cabeceras y tipos de cada campo. No necesita PostgreSQL, ni Vault, ni la
pasarela.

Lo que sigue sin demostrar, y queda como comprobacion manual documentada: que
Vault acepte de verdad esos cuerpos. Un transporte falso reproduce el contrato
que creemos que Vault tiene; el recorrido
``scripts/vault_mgmt/provisioning-walkthrough.sh`` lo comprueba contra Vault.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest

from app.core.vault import VaultPermissionDenied
from app.vault_mgmt.core.approle_admin import AppRoleAdminClient
from app.vault_mgmt.core.config import get_settings
from app.vault_mgmt.core.vault_auth import ProvisioningUnavailable, StaticTokenProvider

pytestmark = pytest.mark.asyncio

TOKEN = "token-administrativo-de-prueba"
# Extrae los paths de un documento HCL de politica.
PATH_HCL = re.compile(r'path\s+"([^"]+)"')


class Grabadora:
    """Transporte falso que guarda cada peticion y devuelve lo que se le diga."""

    def __init__(self, respuestas: dict[str, Any] | None = None) -> None:
        self.peticiones: list[httpx.Request] = []
        self.respuestas = respuestas or {}

    def transporte(self) -> httpx.MockTransport:
        def manejar(request: httpx.Request) -> httpx.Response:
            self.peticiones.append(request)
            ruta = request.url.path
            cuerpo = self.respuestas.get(ruta, {})
            if isinstance(cuerpo, httpx.Response):
                return cuerpo
            return httpx.Response(200, json=cuerpo)

        return httpx.MockTransport(manejar)

    @property
    def ultima(self) -> httpx.Request:
        assert self.peticiones, "no se registro ninguna peticion"
        return self.peticiones[-1]

    def cuerpo(self, indice: int = -1) -> dict[str, Any]:
        return json.loads(self.peticiones[indice].content or b"{}")


def cliente(grabadora: Grabadora, *, token: str | None = TOKEN) -> AppRoleAdminClient:
    settings = get_settings()
    http = httpx.AsyncClient(
        base_url=settings.vault_addr, transport=grabadora.transporte()
    )
    return AppRoleAdminClient(settings, StaticTokenProvider(token), client=http)


# ---------------------------------------------------------------------------
# El fallo que motivo este modulo
# ---------------------------------------------------------------------------


async def test_metadata_del_secret_id_viaja_como_cadena_json():
    """Vault declara `metadata` como string: un objeto es 400.

    Esta es la afirmacion que faltaba. Si alguien vuelve a pasar el diccionario
    tal cual, esta prueba falla aqui y no en un recorrido manual.
    """
    settings = get_settings()
    rol = settings.managed_role_name("crawler-demo")
    grabadora = Grabadora(
        {
            f"/v1/auth/{settings.managed_approle_mount}/role/{rol}/secret-id": {
                "wrap_info": {"token": "wrap-xyz", "accessor": "wrapacc-1", "ttl": 120}
            }
        }
    )
    api = cliente(grabadora)
    try:
        await api.issue_wrapped_secret_id(
            rol,
            metadata={"consumer_id": "c-1", "operation_id": "o-1", "receiver": "local"},
            wrap_ttl_seconds=120,
        )
    finally:
        await api.aclose()

    enviado = grabadora.cuerpo()
    assert isinstance(enviado["metadata"], str), (
        "Vault espera una cadena JSON en 'metadata'; enviar un objeto responde "
        "400 con \"expected type 'string'\""
    )
    # Y esa cadena tiene que ser JSON valido, con los identificadores dentro.
    recuperado = json.loads(enviado["metadata"])
    assert recuperado == {
        "consumer_id": "c-1",
        "operation_id": "o-1",
        "receiver": "local",
    }


async def test_el_ttl_de_envoltura_va_en_la_cabecera_no_en_el_cuerpo():
    """Sin `X-Vault-Wrap-TTL`, Vault devolveria el SecretID EN CLARO."""
    settings = get_settings()
    rol = settings.managed_role_name("crawler-demo")
    grabadora = Grabadora(
        {
            f"/v1/auth/{settings.managed_approle_mount}/role/{rol}/secret-id": {
                "wrap_info": {"token": "wrap-xyz", "accessor": "wrapacc-1", "ttl": 90}
            }
        }
    )
    api = cliente(grabadora)
    try:
        await api.issue_wrapped_secret_id(rol, metadata={}, wrap_ttl_seconds=90)
    finally:
        await api.aclose()

    assert grabadora.ultima.headers["X-Vault-Wrap-TTL"] == "90"
    assert "wrap_ttl" not in grabadora.cuerpo()


async def test_sin_wrap_info_no_se_entrega_nada():
    """Si Vault no envuelve, se falla en vez de devolver un secreto en claro."""
    settings = get_settings()
    rol = settings.managed_role_name("crawler-demo")
    ruta = f"/v1/auth/{settings.managed_approle_mount}/role/{rol}/secret-id"
    # Respuesta SIN wrap_info y con el secret_id en claro: el caso peligroso.
    grabadora = Grabadora({ruta: {"data": {"secret_id": "valor-en-claro"}}})
    api = cliente(grabadora)
    try:
        with pytest.raises(Exception, match="no envolvio"):
            await api.issue_wrapped_secret_id(rol, metadata={}, wrap_ttl_seconds=60)
    finally:
        await api.aclose()


# ---------------------------------------------------------------------------
# Guarda de alcance: se comprueba ANTES de salir por el cable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rol",
    [
        "vpg-user-mgmt",          # la cuenta tecnica de la etapa 3
        "vpg-crawler",            # el consumidor heredado de la etapa 4
        "../vpg-managed-otro",    # intento de salirse del arbol
        "vpg-managed-a/b",        # path con barra
    ],
)
async def test_un_rol_ajeno_no_genera_ninguna_peticion(rol):
    """La guarda es local: ni se contacta con Vault para un rol que no es suyo."""
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        with pytest.raises(ValueError):
            await api.ensure_role(rol)
        with pytest.raises(ValueError):
            await api.delete_role(rol)
    finally:
        await api.aclose()
    assert grabadora.peticiones == [], "no deberia haber salido ninguna peticion"


async def test_el_rol_gestionado_usa_el_montaje_configurado():
    settings = get_settings()
    rol = settings.managed_role_name("crawler-demo")
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        await api.ensure_role(rol)
    finally:
        await api.aclose()

    esperado = f"/v1/auth/{settings.managed_approle_mount}/role/{rol}"
    assert grabadora.ultima.url.path == esperado
    cuerpo = grabadora.cuerpo()
    assert cuerpo["token_policies"] == [settings.managed_policy_name]
    assert cuerpo["secret_id_num_uses"] == settings.crawler_secret_id_num_uses
    assert cuerpo["bind_secret_id"] is True


# ---------------------------------------------------------------------------
# La politica se genera aqui, no se recibe
# ---------------------------------------------------------------------------


async def test_la_politica_gestionada_no_concede_lectura_de_kv():
    """Si la concediera, los bindings y pinned_version no acotarian nada."""
    settings = get_settings()
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        await api.ensure_policy()
    finally:
        await api.aclose()

    assert grabadora.ultima.url.path == (
        f"/v1/sys/policies/acl/{settings.managed_policy_name}"
    )
    hcl = grabadora.cuerpo()["policy"]
    assert isinstance(hcl, str)

    # Los paths concedidos, extraidos del HCL: exactamente tres, y ninguno de KV.
    paths = set(PATH_HCL.findall(hcl))
    assert paths == {
        "sys/wrapping/unwrap",
        "auth/token/lookup-self",
        "auth/token/renew-self",
    }, f"la politica gestionada concede algo inesperado: {sorted(paths)}"
    # Lo que importa: nada sobre el montaje KV ni sobre el prefijo gestionado.
    assert settings.kv_mount not in hcl
    assert settings.kv_prefix not in hcl


# ---------------------------------------------------------------------------
# Token del proveedor
# ---------------------------------------------------------------------------


async def test_el_token_viaja_en_la_cabecera_de_vault():
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        await api.ensure_policy()
    finally:
        await api.aclose()
    assert grabadora.ultima.headers["X-Vault-Token"] == TOKEN


async def test_sin_token_es_503_y_no_se_llama_a_vault():
    """Sin credencial, el aprovisionamiento esta desactivado: 503, no 500."""
    grabadora = Grabadora()
    api = cliente(grabadora, token=None)
    try:
        with pytest.raises(ProvisioningUnavailable):
            await api.ensure_policy()
    finally:
        await api.aclose()
    assert grabadora.peticiones == []


async def test_un_403_se_reintenta_una_vez_y_despues_es_permiso_denegado():
    """El token pudo rotar fuera; un 403 persistente es permisos de verdad."""
    settings = get_settings()
    ruta = f"/v1/sys/policies/acl/{settings.managed_policy_name}"
    grabadora = Grabadora({ruta: httpx.Response(403, json={"errors": ["denied"]})})
    api = cliente(grabadora)
    try:
        with pytest.raises(VaultPermissionDenied):
            await api.ensure_policy()
    finally:
        await api.aclose()
    # Exactamente dos: el intento original y UN reintento tras invalidar.
    assert len(grabadora.peticiones) == 2


# ---------------------------------------------------------------------------
# Accessors: lo que se envia para revocar
# ---------------------------------------------------------------------------


async def test_destruir_un_secret_id_usa_su_accessor():
    settings = get_settings()
    rol = settings.managed_role_name("crawler-demo")
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        await api.destroy_secret_id_accessor(rol, "sid-123")
    finally:
        await api.aclose()

    assert grabadora.ultima.url.path.endswith("/secret-id-accessor/destroy")
    assert grabadora.cuerpo() == {"secret_id_accessor": "sid-123"}


async def test_revocar_un_token_usa_su_accessor_no_el_token():
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        await api.revoke_token_accessor("acc-999")
    finally:
        await api.aclose()

    assert grabadora.ultima.url.path == "/v1/auth/token/revoke-accessor"
    assert grabadora.cuerpo() == {"accessor": "acc-999"}


async def test_un_accessor_vacio_no_genera_peticion():
    """Evita un 400 inutil y, peor, una revocacion con cuerpo vacio."""
    grabadora = Grabadora()
    api = cliente(grabadora)
    try:
        assert await api.destroy_secret_id_accessor("vpg-managed-x", "") is False
        assert await api.revoke_token_accessor("") is False
    finally:
        await api.aclose()
    assert grabadora.peticiones == []
