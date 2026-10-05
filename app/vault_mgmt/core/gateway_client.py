"""Cliente HTTP de la pasarela interna de user-mgmt.

Este servicio **no** valida sesiones ni ejecuta KV con credenciales propias.
Recibe el Bearer humano, lo reenvia a la pasarela junto con la credencial
interna del servicio y la operacion tipada, y la pasarela autoriza y ejecuta.

Dos cosas que este cliente nunca hace:

* construir una URL, un montaje o un path de Vault y pedir que se ejecute. El
  cuerpo que viaja solo lleva UUID, una operacion de la allowlist y parametros
  tipados; el path lo resuelve la pasarela desde el catalogo.
* registrar el Bearer, la credencial interna, la prueba de MFA, los valores
  enviados o el wrapping token devuelto.

Los errores de la pasarela se traducen conservando su codigo HTTP y su codigo
estable: un 403 de la pasarela sigue siendo un 403 aqui, no un 500 nuestro.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.errors import AppError, UpstreamUnavailableError
from app.core.logging import get_logger
from app.core.vault import sanitize_vault_message
from app.vault_mgmt.core.config import Settings

logger = get_logger(__name__)


class GatewayUnavailable(UpstreamUnavailableError):
    """La pasarela no responde. 503, no 500: la dependencia es de otro proceso."""

    code = "gateway_unavailable"


class GatewayClient:
    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=settings.user_mgmt_base_url,
            timeout=httpx.Timeout(settings.user_mgmt_timeout_seconds),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- cabeceras -----------------------------------------------------------

    def _headers(
        self, *, bearer: str, mfa_proof: str | None, request_id: str | None
    ) -> dict[str, str]:
        credential = self._settings.internal_credential
        if credential is None:
            raise GatewayUnavailable(
                "falta la credencial interna de la pasarela: ejecuta "
                "scripts/vault_mgmt/prepare-internal-secret.sh y recrea los "
                "contenedores",
                code="internal_credential_missing",
            )
        headers = {
            # El Bearer humano SIGUE siendo obligatorio: la credencial interna
            # no sustituye su autorizacion.
            "Authorization": f"Bearer {bearer}",
            self._settings.internal_credential_header: credential.get_secret_value(),
            "Content-Type": "application/json",
        }
        if mfa_proof:
            headers[self._settings.mfa_proof_header] = mfa_proof
        if request_id:
            headers["X-Request-ID"] = request_id
        return headers

    # -- llamadas ------------------------------------------------------------

    async def probe_session(
        self, *, bearer: str, request_id: str | None = None
    ) -> dict[str, Any]:
        """Valida la sesion humana. Devuelve principal, roles y antiguedad del MFA."""
        return await self._post(
            f"{self._settings.user_mgmt_internal_prefix}/session",
            payload=None,
            bearer=bearer,
            mfa_proof=None,
            request_id=request_id,
        )

    async def execute(
        self,
        *,
        bearer: str,
        payload: dict[str, Any],
        mfa_proof: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._post(
            f"{self._settings.user_mgmt_internal_prefix}/execute",
            payload=payload,
            bearer=bearer,
            mfa_proof=mfa_proof,
            request_id=request_id,
        )

    async def health(self) -> bool:
        """``/health/ready`` publico de user-mgmt. No necesita credenciales."""
        try:
            response = await self._client.get("/health/ready")
        except httpx.HTTPError:
            return False
        return response.status_code == 200

    async def gateway_authenticated(self) -> tuple[bool, str | None]:
        """Comprueba que la pasarela reconoce la credencial interna.

        Se llama a ``/session`` **sin** Bearer humano a proposito:

        * 401 con ``unauthenticated`` por el Bearer ausente -> la credencial
          interna es correcta y la pasarela esta exigiendo el Bearer. Es lo que
          se quiere comprobar.
        * 401 con ``internal_credential_invalid`` -> la credencial no coincide.
        * 503 -> la pasarela no tiene credencial montada o no esta lista.
        """
        credential = self._settings.internal_credential
        if credential is None:
            return False, "no hay credencial interna montada en vault-mgmt"
        try:
            response = await self._client.post(
                f"{self._settings.user_mgmt_internal_prefix}/session",
                headers={
                    self._settings.internal_credential_header: (
                        credential.get_secret_value()
                    )
                },
            )
        except httpx.HTTPError as exc:
            return False, f"pasarela inaccesible: {sanitize_vault_message(str(exc), limit=120)}"

        try:
            body = response.json()
        except ValueError:
            body = {}
        code = str(body.get("code") or "")

        if response.status_code == 401 and code == "internal_credential_invalid":
            return False, "la pasarela rechaza la credencial interna de este servicio"
        if response.status_code == 401:
            # Falta el Bearer humano: exactamente lo que debe pasar.
            return True, None
        if response.status_code == 503:
            # La pasarela comprueba la credencial ANTES de su propio readiness,
            # asi que un 503 aqui significa "no se puede confirmar todavia", no
            # "la credencial esta mal". Conviene no confundir las dos cosas en
            # un diagnostico.
            return False, (
                "no se puede confirmar todavia porque la pasarela responde 503: "
                + str(body.get("message") or "sin detalle")
            )
        if response.status_code == 404:
            return False, (
                "la pasarela interna no esta montada en user-mgmt: reconstruye "
                "user-mgmt-service con el codigo de la etapa 4"
            )
        return False, f"respuesta inesperada de la pasarela ({response.status_code})"

    # -- transporte ----------------------------------------------------------

    async def _post(
        self,
        path: str,
        *,
        payload: dict[str, Any] | None,
        bearer: str,
        mfa_proof: str | None,
        request_id: str | None,
    ) -> dict[str, Any]:
        headers = self._headers(
            bearer=bearer, mfa_proof=mfa_proof, request_id=request_id
        )
        try:
            response = await self._client.post(path, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise GatewayUnavailable(
                "la pasarela de user-mgmt no respondio dentro del tiempo limite. "
                "La operacion pudo ejecutarse en Vault: consulta la operacion "
                "antes de reintentar.",
                code="gateway_timeout",
            ) from exc
        except httpx.HTTPError as exc:
            raise GatewayUnavailable(
                "no se pudo contactar con la pasarela de user-mgmt: "
                + sanitize_vault_message(str(exc), limit=160)
            ) from exc

        if response.status_code == 204 or not response.content:
            return {}

        try:
            body: dict[str, Any] = response.json()
        except ValueError:
            body = {}

        if response.is_success:
            return body

        # Se conserva el codigo HTTP y el codigo estable que da la pasarela: es
        # la autoridad de autorizacion y su veredicto no se reinterpreta.
        # El mensaje de la pasarela ya viene saneado por su lado; se vuelve a
        # sanear aqui porque este texto se reenvia al cliente y la frontera
        # entre dos procesos es el sitio donde conviene no fiarse.
        message = sanitize_vault_message(
            str(body.get("message") or "la pasarela rechazo la operacion"), limit=500
        )
        code = str(body.get("code") or "gateway_error")
        context = body.get("context") if isinstance(body.get("context"), dict) else {}
        status = response.status_code
        if status == 404 and code == "http_error":
            # Ruta inexistente en user-mgmt, no un recurso inexistente.
            raise GatewayUnavailable(
                "la pasarela interna no esta montada en user-mgmt: reconstruye "
                "user-mgmt-service con el codigo de la etapa 4",
                code="gateway_not_mounted",
            )
        if status >= 500:
            raise GatewayUnavailable(
                f"la pasarela devolvio un error interno: {message}",
                code="gateway_internal_error",
            )
        raise AppError(message, status_code=status, code=code, context=dict(context or {}))


__all__ = ["GatewayClient", "GatewayUnavailable"]
