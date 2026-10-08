"""Operaciones de Vault que necesita el aprovisionador, y solo esas.

El token que usa esta clase es administrativo (ver
``app/vault_mgmt/core/vault_auth.py``). Lo que impide que se convierta en una
llave maestra expuesta por HTTP es **este modulo**: cada metodo construye el
path el mismo, a partir del montaje gestionado de la configuracion y de un
nombre de rol derivado del consumidor. En ningun metodo entra un path, una URL
ni un fragmento de HCL que venga de una peticion.

Las cuatro reglas que se aplican aqui, y que las pruebas comprueban:

1. **Montaje fijo.** Solo ``settings.managed_approle_mount``. Cualquier otro
   valor es ``ValueError``, no una llamada a Vault.
2. **Rol con prefijo.** Solo roles que empiezan por
   ``settings.managed_role_prefix``. Asi no se puede tocar el rol de
   ``user-mgmt`` ni el del consumidor heredado de la etapa 4.
3. **Politica generada, no recibida.** El HCL lo escribe este modulo a partir
   de la configuracion. No se acepta HCL libre por ninguna via.
4. **Nada de root.** No se crean tokens root, no se habilitan autenticadores
   nuevos fuera del montaje gestionado y no se escriben politicas con nombre
   arbitrario.

Sobre la politica de los consumidores GESTIONADOS: **no** lleva lectura del
prefijo KV. Su entrega es mediada (la lee el backend autorizado y la envuelve),
asi que su token solo necesita desenvolver y mirarse a si mismo. Un token que
pudiera leer ``secret/data/vpg-managed/*`` haria irrelevantes los bindings y la
version fijada, porque podria leer cualquier otro registro del prefijo.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.logging import get_logger
from app.core.vault import (
    VaultError,
    VaultPermissionDenied,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.vault_auth import VaultTokenProvider

logger = get_logger(__name__)


@dataclass(slots=True)
class WrappedSecretId:
    """Envoltura que lleva dentro el SecretID. El SecretID NO esta aqui.

    ``token`` es el wrapping token: un solo uso, TTL corto. Se entrega al
    receptor y no se guarda en PostgreSQL. ``accessor`` si se guarda: identifica
    la envoltura para auditarla y revocarla sin poder usarla.
    """

    token: str = field(repr=False)
    accessor: str
    ttl_seconds: int
    expires_at: dt.datetime

    def __str__(self) -> str:  # pragma: no cover - defensa contra logs
        return f"<WrappedSecretId accessor={self.accessor} ttl={self.ttl_seconds}s>"


@dataclass(slots=True)
class RoleInfo:
    role_id: str = field(repr=False)
    policies: tuple[str, ...]
    token_ttl_seconds: int


class AppRoleAdminClient:
    """Cliente de las rutas ``auth/<montaje gestionado>/...`` y poco mas."""

    def __init__(
        self,
        settings: Settings,
        provider: VaultTokenProvider,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._provider = provider
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=settings.vault_addr,
            timeout=httpx.Timeout(settings.vault_timeout_seconds),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @property
    def available(self) -> bool:
        return self._provider.available

    @property
    def mount(self) -> str:
        return self._settings.managed_approle_mount

    # -- guardas de alcance --------------------------------------------------

    def _role_path(self, role_name: str, suffix: str = "") -> str:
        """Construye el path del rol, comprobando que es uno gestionado.

        Es la unica forma de nombrar un rol en esta clase. No hay metodo que
        acepte un path ya formado.
        """
        prefix = self._settings.managed_role_prefix
        if not role_name.startswith(prefix):
            raise ValueError(
                f"'{role_name}' no es un rol gestionado por esta API "
                f"(deberia empezar por '{prefix}'): no se toca"
            )
        if "/" in role_name or ".." in role_name:
            raise ValueError("un nombre de rol no puede llevar '/' ni '..'")
        base = f"auth/{self.mount}/role/{role_name}"
        return f"{base}/{suffix.strip('/')}" if suffix else base

    # -- transporte ----------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        wrap_ttl_seconds: int | None = None,
        retry_on_denied: bool = True,
    ) -> dict[str, Any]:
        token = await self._provider.token()
        headers = {"X-Vault-Token": token}
        if wrap_ttl_seconds is not None:
            headers["X-Vault-Wrap-TTL"] = str(wrap_ttl_seconds)

        try:
            response = await self._client.request(
                method, f"/v1/{path.lstrip('/')}", headers=headers, json=json
            )
        except httpx.TimeoutException as exc:
            raise VaultUnavailable(
                f"Vault no respondio en {self._settings.vault_timeout_seconds}s ({path})"
            ) from exc
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc

        if response.status_code == 204 or not response.content:
            return {}

        try:
            payload: dict[str, Any] = response.json()
        except ValueError:
            payload = {}

        if response.is_success:
            return payload

        errors = payload.get("errors") or []
        detail = sanitize_vault_message("; ".join(str(e) for e in errors) or response.text)

        if response.status_code in (401, 403):
            # El token pudo rotar fuera. Se descarta el cacheado y se reintenta
            # UNA vez; si vuelve a fallar, es permisos de verdad.
            if retry_on_denied:
                await self._provider.invalidate()
                return await self._request(
                    method,
                    path,
                    json=json,
                    wrap_ttl_seconds=wrap_ttl_seconds,
                    retry_on_denied=False,
                )
            raise VaultPermissionDenied(
                f"Vault denego la operacion de aprovisionamiento en {path}: {detail}",
                status_code=403,
            )
        if response.status_code == 404:
            return {"__not_found__": True}
        if response.status_code in (501, 503):
            raise VaultSealed(
                f"Vault no esta operativo (sellado o sin inicializar): {detail}",
                status_code=response.status_code,
            )
        raise VaultError(
            f"Vault devolvio {response.status_code} en {path}: {detail}",
            status_code=response.status_code,
        )

    # -- montaje, politica y rol --------------------------------------------

    async def ensure_mount(self) -> bool:
        """Habilita el montaje AppRole gestionado si falta. Idempotente."""
        payload = await self._request("GET", "sys/auth")
        existing = payload.get("data") or payload
        if f"{self.mount}/" in existing:
            return False
        await self._request(
            "POST",
            f"sys/auth/{self.mount}",
            json={
                "type": "approle",
                "description": "Identidades de maquina gestionadas por vault-mgmt",
            },
        )
        logger.info(
            "montaje AppRole habilitado", extra={"operation": "approle_mount"}
        )
        return True

    def managed_policy_hcl(self) -> str:
        """El HCL de la politica gestionada. Generado, nunca recibido.

        Sin lectura de KV a proposito: la entrega de un consumidor gestionado es
        mediada. Lo unico que su token necesita es desenvolver la entrega y
        poder mirarse y renovarse a si mismo.
        """
        return (
            "# Generada por app/vault_mgmt/core/approle_admin.py.\n"
            "# Consumidor GESTIONADO: entrega mediada, sin lectura directa de KV.\n"
            "#\n"
            "# No incluye 'read' sobre el prefijo gestionado a proposito. Con esa\n"
            "# capacidad, los bindings y la version fijada no protegerian nada:\n"
            "# el token podria leer cualquier registro del prefijo por su cuenta.\n"
            'path "sys/wrapping/unwrap" {\n'
            '  capabilities = ["update"]\n'
            "}\n"
            'path "auth/token/lookup-self" {\n'
            '  capabilities = ["read"]\n'
            "}\n"
            'path "auth/token/renew-self" {\n'
            '  capabilities = ["update"]\n'
            "}\n"
        )

    async def ensure_policy(self) -> None:
        """Escribe la politica gestionada. Nombre fijo de la configuracion."""
        await self._request(
            "PUT",
            f"sys/policies/acl/{self._settings.managed_policy_name}",
            json={"policy": self.managed_policy_hcl()},
        )

    async def ensure_role(self, role_name: str) -> None:
        """Crea o actualiza el rol del consumidor con los TTL configurados."""
        settings = self._settings
        await self._request(
            "POST",
            self._role_path(role_name),
            json={
                "token_policies": [settings.managed_policy_name],
                "token_ttl": settings.crawler_token_ttl_seconds,
                "token_max_ttl": settings.crawler_token_max_ttl_seconds,
                "token_num_uses": 0,
                "secret_id_ttl": settings.crawler_secret_id_ttl_seconds,
                "secret_id_num_uses": settings.crawler_secret_id_num_uses,
                "bind_secret_id": True,
            },
        )

    async def role_exists(self, role_name: str) -> bool:
        payload = await self._request("GET", self._role_path(role_name))
        return not payload.get("__not_found__")

    async def read_role(self, role_name: str) -> RoleInfo | None:
        """Lee el ``role_id`` y la configuracion efectiva del rol."""
        role = await self._request("GET", self._role_path(role_name))
        if role.get("__not_found__"):
            return None
        identity = await self._request("GET", self._role_path(role_name, "role-id"))
        if identity.get("__not_found__"):
            return None
        data = identity.get("data") or {}
        config = role.get("data") or {}
        role_id = str(data.get("role_id") or "")
        if not role_id:
            raise VaultError("Vault no devolvio el role_id del rol gestionado")
        return RoleInfo(
            role_id=role_id,
            policies=tuple(str(p) for p in (config.get("token_policies") or ())),
            token_ttl_seconds=int(config.get("token_ttl") or 0),
        )

    async def delete_role(self, role_name: str) -> None:
        """Borra el rol. Los TOKENS ya emitidos siguen vivos hasta su TTL."""
        await self._request("DELETE", self._role_path(role_name))

    # -- SecretID ------------------------------------------------------------

    async def issue_wrapped_secret_id(
        self, role_name: str, *, metadata: dict[str, str], wrap_ttl_seconds: int
    ) -> WrappedSecretId:
        """Emite un SecretID y devuelve su ENVOLTURA, no el valor.

        El SecretID nunca pasa por este proceso en claro: se pide con
        ``X-Vault-Wrap-TTL``, asi que Vault responde con un wrapping token y
        guarda el valor hasta que alguien lo desenvuelve. Si la envoltura caduca
        sin usarse, el SecretID sigue existiendo en Vault y hay que destruirlo
        por su accessor; de eso se encarga el aprovisionador al reconciliar.
        """
        payload = await self._request(
            "POST",
            self._role_path(role_name, "secret-id"),
            json={"metadata": _metadata_json(metadata)},
            wrap_ttl_seconds=wrap_ttl_seconds,
        )
        info = payload.get("wrap_info") or {}
        token = str(info.get("token") or "")
        if not token:
            raise VaultError(
                "Vault no envolvio el SecretID (sin wrap_info): no se entrega "
                "nada en claro"
            )
        ttl = int(info.get("ttl") or wrap_ttl_seconds)
        return WrappedSecretId(
            token=token,
            accessor=str(info.get("accessor") or ""),
            ttl_seconds=ttl,
            expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=ttl),
        )

    async def lookup_secret_id_accessor(
        self, role_name: str, accessor: str
    ) -> dict[str, Any] | None:
        """Comprueba si un SecretID sigue vivo, por su accessor."""
        if not accessor:
            return None
        payload = await self._request(
            "POST",
            self._role_path(role_name, "secret-id-accessor/lookup"),
            json={"secret_id_accessor": accessor},
        )
        if payload.get("__not_found__"):
            return None
        return dict(payload.get("data") or {})

    async def destroy_secret_id_accessor(self, role_name: str, accessor: str) -> bool:
        """Destruye un SecretID por su accessor. Idempotente.

        Es lo que cierra de verdad una rotacion: el SecretID anterior deja de
        servir para autenticarse. Los tokens que ya salieron de el **siguen
        vivos** hasta su TTL; para esos hay que revocar el accessor del token.
        """
        if not accessor:
            return False
        payload = await self._request(
            "POST",
            self._role_path(role_name, "secret-id-accessor/destroy"),
            json={"secret_id_accessor": accessor},
        )
        return not payload.get("__not_found__")

    async def list_secret_id_accessors(self, role_name: str) -> list[str]:
        payload = await self._request(
            "LIST", self._role_path(role_name, "secret-id")
        )
        if payload.get("__not_found__"):
            return []
        keys = (payload.get("data") or {}).get("keys") or []
        return [str(key) for key in keys]

    # -- tokens --------------------------------------------------------------

    async def revoke_token_accessor(self, accessor: str) -> bool:
        """Revoca un token concreto por su accessor, sin tener el token."""
        if not accessor:
            return False
        payload = await self._request(
            "POST", "auth/token/revoke-accessor", json={"accessor": accessor}
        )
        return not payload.get("__not_found__")

    async def lookup_token(self, token: str) -> dict[str, Any]:
        """``lookup`` de un token AJENO, con el token administrativo.

        Se usa en el ``ack``: el receptor dice que se autentico, y esto lo
        comprueba contra Vault en vez de creerse un ``success: true``.
        """
        payload = await self._request(
            "POST", "auth/token/lookup", json={"token": token}
        )
        if payload.get("__not_found__"):
            return {}
        return dict(payload.get("data") or {})


def _metadata_json(metadata: dict[str, str]) -> str:
    """Metadatos del SecretID, como **cadena JSON**.

    Vault no acepta un objeto aqui: el campo ``metadata`` de
    ``auth/<montaje>/role/<rol>/secret-id`` se declara como string y espera un
    JSON ya serializado. Pasarle un diccionario responde 400 con
    ``expected type 'string', got unconvertible type 'map[string]interface {}'``.
    Es un detalle de la API de Vault, no de este proyecto, y es el motivo de que
    la serializacion viva aqui y no en quien llama.

    Solo entran identificadores: Vault los devuelve en ``lookup``, asi que nada
    sensible pasa por este campo.
    """
    limpio = {
        key: str(value)[:200]
        for key, value in metadata.items()
        if value is not None and key.isidentifier()
    }
    return json.dumps(limpio, separators=(",", ":"), sort_keys=True)


__all__ = ["AppRoleAdminClient", "RoleInfo", "WrappedSecretId"]
