"""Autenticacion de una MAQUINA contra Vault. Contrato distinto del humano.

El crawler no presta la ``api_session`` de un empleado: presenta un **token de
Vault** que obtuvo antes con su propia AppRole de solo lectura. Esta pieza
comprueba que ese token es de la maquina que dice ser, y nada mas.

Que se valida, en este orden:

1. ``auth/token/lookup-self`` con **ese** token. Si falla, la autenticacion
   falla: no hay vuelta a la cuenta tecnica del servicio como alternativa.
2. El ``path`` del token es el login de la AppRole esperada
   (``auth/<montaje>/login``). Un token de userpass o de root no pasa, aunque
   tenga mas permisos.
3. El ``role_name`` de sus metadatos coincide con el rol registrado.
4. Sus politicas incluyen la politica minima registrada.
5. Sigue vigente (``ttl`` > 0 o sin caducidad por ser renovable).

Lo que NO se hace:

* No se acepta un ``consumer_id`` que venga del cliente. El consumidor se
  resuelve desde la identidad del token y se contrasta con el catalogo.
* No se emiten tokens de autenticacion nuevos. Este endpoint entrega envoltura
  de lectura, no credenciales.
* No se acepta cualquier token de Vault por el hecho de ser valido.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.vault import (
    VaultError,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)
from app.vault_mgmt.core.config import Settings


@dataclass(slots=True)
class VaultHealth:
    initialized: bool
    sealed: bool
    standby: bool
    version: str | None = None


@dataclass(slots=True)
class MachineIdentity:
    """Identidad comprobada de un token de maquina. Sin el token dentro."""

    accessor: str = field(repr=False)
    auth_path: str
    role_name: str
    policies: tuple[str, ...]
    display_name: str
    ttl_seconds: int
    renewable: bool

    @property
    def approle_mount(self) -> str:
        """``auth/approle-crawler/login`` -> ``approle-crawler``."""
        parts = self.auth_path.strip("/").split("/")
        return parts[1] if len(parts) >= 2 else ""


class MachineAuthError(VaultError):
    """El token no acredita a la maquina esperada. Se traduce a 401 o 403."""


class VaultProbe:
    """Cliente minimo de Vault para este servicio.

    Solo dos cosas: salud (readiness) y ``lookup-self`` de un token ajeno. No
    tiene credenciales propias y no puede leer secretos por si mismo.
    """

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=settings.vault_addr,
            timeout=httpx.Timeout(settings.vault_timeout_seconds),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def health(self) -> VaultHealth:
        try:
            response = await self._client.get(
                "/v1/sys/health",
                params={"standbyok": "true", "sealedcode": "200", "uninitcode": "200"},
            )
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise VaultUnavailable("respuesta de sys/health ilegible") from exc
        return VaultHealth(
            initialized=bool(data.get("initialized")),
            sealed=bool(data.get("sealed")),
            standby=bool(data.get("standby")),
            version=data.get("version"),
        )

    async def lookup_self(self, token: str) -> dict[str, Any]:
        try:
            response = await self._client.get(
                "/v1/auth/token/lookup-self", headers={"X-Vault-Token": token}
            )
        except httpx.TimeoutException as exc:
            raise VaultUnavailable("Vault no respondio al validar el token") from exc
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc

        if response.status_code in (501, 503):
            raise VaultSealed("Vault no esta operativo (sellado o sin inicializar)")
        if response.status_code in (401, 403):
            raise MachineAuthError(
                "el token presentado no es valido en Vault", status_code=401
            )
        if not response.is_success:
            raise VaultError(
                f"Vault devolvio {response.status_code} al validar el token",
                status_code=response.status_code,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise VaultUnavailable("respuesta de lookup-self ilegible") from exc
        return dict(payload.get("data") or {})


def identity_from_lookup(data: dict[str, Any]) -> MachineIdentity:
    """Traduce ``lookup-self`` a una identidad, sin interpretar de mas."""
    meta = data.get("meta") or {}
    return MachineIdentity(
        accessor=str(data.get("accessor") or ""),
        auth_path=str(data.get("path") or ""),
        role_name=str(meta.get("role_name") or ""),
        policies=tuple(str(p) for p in (data.get("policies") or ())),
        display_name=str(data.get("display_name") or ""),
        ttl_seconds=int(data.get("ttl") or 0),
        renewable=bool(data.get("renewable")),
    )


def assert_identity_matches(
    identity: MachineIdentity,
    *,
    expected_mount: str,
    expected_role: str,
    expected_policy: str,
) -> None:
    """Compara la identidad con lo registrado para el consumidor.

    Un fallo aqui es 403, no 404: el token es valido en Vault pero no es quien
    el catalogo espera para ese recurso.
    """
    expected_path = f"auth/{expected_mount.strip('/')}/login"
    if identity.auth_path.strip("/") != expected_path:
        raise MachineAuthError(
            "el token no proviene del montaje AppRole esperado para este "
            f"consumidor (esperado '{expected_path}')",
            status_code=403,
        )
    if identity.role_name != expected_role:
        raise MachineAuthError(
            "el token no corresponde al rol AppRole registrado para este consumidor",
            status_code=403,
        )
    if expected_policy not in identity.policies:
        raise MachineAuthError(
            f"el token no lleva la politica minima registrada ('{expected_policy}'): "
            "sus permisos no son los de este consumidor",
            status_code=403,
        )
    if identity.ttl_seconds <= 0 and not identity.renewable:
        raise MachineAuthError(
            "el token esta caducado o sin TTL util; vuelve a autenticarte con "
            "tu AppRole",
            status_code=401,
        )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "MachineAuthError",
    "MachineIdentity",
    "VaultHealth",
    "VaultProbe",
    "assert_identity_matches",
    "identity_from_lookup",
    "utc_now",
]
