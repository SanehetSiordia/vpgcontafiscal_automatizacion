"""Cliente de Vault KV v2: datos, versiones, metadata y response wrapping.

Modulo compartido por los dos servicios porque el contrato de KV v2 es el mismo;
lo que cambia es **que token** se usa, y eso lo decide quien llama:

* ``user-mgmt-service`` lo usa con el **token humano** de la sesion, desde su
  pasarela interna. Vault aplica la ACL de esa persona: si su politica no
  cubre el path, la respuesta es 403 aunque el rol de aplicacion lo permitiera.
* ``vault-mgmt-service`` lo usa con el **token de la maquina** en
  ``/integrations/crawler/resolve``, nunca con una cuenta tecnica que supla sus
  permisos.

Cosas que conviene no confundir, y que el codigo respeta:

* ``data``, ``metadata``, ``delete``, ``undelete`` y ``destroy`` son segmentos
  del **cliente** KV v2, no carpetas del secreto. El path logico es uno solo y
  aqui se compone al vuelo.
* ``LIST`` enumera los hijos de un prefijo. No devuelve documentos, no aplica
  filtrado por politica elemento a elemento y **no tiene paginacion nativa**:
  el ``limit``/``offset`` de la API es del catalogo en PostgreSQL, no del motor.
* Un 403 significa "sin permiso", no "no existe". Nunca se traduce a 404.
* Soft-delete, destroy y ausencia son tres estados distintos y se distinguen
  sin filtrar valores.
* El response wrapping de Vault devuelve un token de un solo uso con TTL corto.
  **No** es un JSON cifrado y **no** impide que el receptor autorizado vea los
  valores al desenvolverlo. No se registra ni se persiste en ningun sitio.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from app.core.vault import (
    VaultError,
    VaultNotFound,
    VaultPermissionDenied,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)


class KvCasMismatch(VaultError):
    """El ``cas`` enviado no coincide con la version actual. No se sobrescribio nada."""

    def __init__(self, message: str, *, current_version: int | None = None) -> None:
        super().__init__(message, status_code=409)
        self.current_version = current_version


VersionState = Literal["active", "soft_deleted", "destroyed", "absent"]


@dataclass(slots=True)
class KvVersion:
    """Una version de un secreto. ``values`` solo viene en una lectura plana."""

    version: int
    state: VersionState
    created_time: str | None = None
    deletion_time: str | None = None
    destroyed: bool = False
    values: dict[str, Any] | None = field(default=None, repr=False)

    def __str__(self) -> str:  # pragma: no cover - defensa contra logs
        return f"KvVersion(version={self.version}, state={self.state})"


@dataclass(slots=True)
class KvMetadata:
    """Metadata nativa de una clave. Nunca contiene valores."""

    current_version: int
    oldest_version: int
    created_time: str | None
    updated_time: str | None
    max_versions: int
    cas_required: bool
    delete_version_after: str | None
    custom_metadata: dict[str, Any]
    versions: list[KvVersion]

    def version_states(self) -> dict[int, VersionState]:
        return {v.version: v.state for v in self.versions}


@dataclass(slots=True)
class WrappedDelivery:
    """Entrega envuelta. El token viaja al consumidor y no se guarda aqui."""

    token: str = field(repr=False)
    ttl_seconds: int
    creation_time: str | None
    creation_path: str | None
    accessor: str = field(repr=False, default="")

    def __str__(self) -> str:  # pragma: no cover - defensa contra logs
        return f"WrappedDelivery(ttl={self.ttl_seconds}s, path={self.creation_path})"


def _version_state(meta: dict[str, Any]) -> VersionState:
    if meta.get("destroyed"):
        return "destroyed"
    deletion_time = str(meta.get("deletion_time") or "")
    if deletion_time:
        return "soft_deleted"
    return "active"


class KvV2Client:
    """Envoltorio sobre el motor KV v2 con timeouts explicitos.

    No guarda ningun token: cada metodo recibe el que debe usar.
    """

    def __init__(
        self,
        *,
        base_url: str,
        mount: str,
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._mount = mount.strip("/")
        self._timeout = timeout_seconds
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @property
    def mount(self) -> str:
        return self._mount

    def data_path(self, logical_path: str) -> str:
        return f"{self._mount}/data/{logical_path.strip('/')}"

    def metadata_path(self, logical_path: str) -> str:
        return f"{self._mount}/metadata/{logical_path.strip('/')}"

    # -- transporte ----------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        wrap_ttl_seconds: int | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = {"X-Vault-Token": token}
        if wrap_ttl_seconds is not None:
            # Vault envuelve la respuesta y devuelve wrap_info en vez del cuerpo.
            headers["X-Vault-Wrap-TTL"] = str(wrap_ttl_seconds)

        try:
            response = await self._client.request(
                method,
                f"/v1/{path.lstrip('/')}",
                headers=headers,
                json=json,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise VaultUnavailable(
                f"Vault no respondio en {self._timeout}s ({path})"
            ) from exc
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc

        if response.status_code == 204 or not response.content:
            return response.status_code, {}

        try:
            payload: dict[str, Any] = response.json()
        except ValueError:
            payload = {}

        if response.is_success:
            return response.status_code, payload

        errors = payload.get("errors") or []
        detail = sanitize_vault_message("; ".join(str(e) for e in errors) or response.text)

        if response.status_code == 403:
            raise VaultPermissionDenied(
                f"Vault denego el acceso a {path}: {detail}. "
                "El recurso puede existir: no se concluye su inexistencia.",
                status_code=403,
            )
        if response.status_code == 404:
            # 404 de KV v2 NO siempre es ausencia: una version con soft-delete
            # tambien responde 404 y trae metadata. Lo resuelve quien llama.
            return 404, payload
        if response.status_code == 400 and "check-and-set" in detail.lower():
            raise KvCasMismatch(
                "la version esperada no coincide con la actual: otra escritura "
                "gano la carrera y no se ha sobrescrito nada. Vuelve a leer la "
                "version actual y reintenta de forma consciente."
            )
        if response.status_code in (501, 503):
            raise VaultSealed(
                f"Vault no esta operativo (sellado o sin inicializar): {detail}",
                status_code=response.status_code,
            )
        raise VaultError(
            f"Vault devolvio {response.status_code} en {path}: {detail}",
            status_code=response.status_code,
        )

    # -- lectura -------------------------------------------------------------

    async def read_version(
        self, token: str, logical_path: str, *, version: int | None = None
    ) -> KvVersion:
        """Lee una version. Distingue activa, soft-deleted, destruida y ausente."""
        params = {"version": version} if version else None
        status, payload = await self._request(
            "GET", self.data_path(logical_path), token=token, params=params
        )
        data = payload.get("data") or {}
        meta = data.get("metadata") or {}

        if status == 404 and not meta:
            return KvVersion(version=version or 0, state="absent")

        resolved = int(meta.get("version") or version or 0)
        state = _version_state(meta)
        values = data.get("data")
        return KvVersion(
            version=resolved,
            state=state,
            created_time=meta.get("created_time"),
            deletion_time=meta.get("deletion_time") or None,
            destroyed=bool(meta.get("destroyed")),
            values=values if isinstance(values, dict) else None,
        )

    async def read_version_wrapped(
        self,
        token: str,
        logical_path: str,
        *,
        version: int | None,
        wrap_ttl_seconds: int,
    ) -> WrappedDelivery:
        """Lectura entregada como response wrapping de Vault.

        El cuerpo del secreto no pasa por este proceso: Vault lo guarda bajo un
        token de un solo uso y aqui solo circula ese token, que no se registra.
        """
        params = {"version": version} if version else None
        _status, payload = await self._request(
            "GET",
            self.data_path(logical_path),
            token=token,
            params=params,
            wrap_ttl_seconds=wrap_ttl_seconds,
        )
        info = payload.get("wrap_info") or {}
        wrapping_token = info.get("token")
        if not wrapping_token:
            raise VaultError(
                "Vault no devolvio wrap_info: la entrega envuelta no se pudo "
                "preparar y no se entrega el valor en claro por defecto"
            )
        return WrappedDelivery(
            token=str(wrapping_token),
            ttl_seconds=int(info.get("ttl") or wrap_ttl_seconds),
            creation_time=info.get("creation_time"),
            creation_path=info.get("creation_path"),
            accessor=str(info.get("accessor") or ""),
        )

    async def read_metadata(self, token: str, logical_path: str) -> KvMetadata | None:
        status, payload = await self._request(
            "GET", self.metadata_path(logical_path), token=token
        )
        if status == 404:
            return None
        data = payload.get("data") or {}
        versions: list[KvVersion] = []
        for raw_version, meta in (data.get("versions") or {}).items():
            meta = meta or {}
            versions.append(
                KvVersion(
                    version=int(raw_version),
                    state=_version_state(meta),
                    created_time=meta.get("created_time"),
                    deletion_time=meta.get("deletion_time") or None,
                    destroyed=bool(meta.get("destroyed")),
                )
            )
        versions.sort(key=lambda item: item.version)
        return KvMetadata(
            current_version=int(data.get("current_version") or 0),
            oldest_version=int(data.get("oldest_version") or 0),
            created_time=data.get("created_time"),
            updated_time=data.get("updated_time"),
            max_versions=int(data.get("max_versions") or 0),
            cas_required=bool(data.get("cas_required")),
            delete_version_after=data.get("delete_version_after"),
            custom_metadata=dict(data.get("custom_metadata") or {}),
            versions=versions,
        )

    async def list_children(self, token: str, logical_prefix: str) -> list[str]:
        """Hijos directos de un prefijo. Sin paginacion: KV v2 no la ofrece."""
        status, payload = await self._request(
            "LIST", self.metadata_path(logical_prefix), token=token
        )
        if status == 404:
            return []
        keys = (payload.get("data") or {}).get("keys") or []
        return [str(key) for key in keys]

    # -- escritura -----------------------------------------------------------

    async def write(
        self,
        token: str,
        logical_path: str,
        values: dict[str, Any],
        *,
        cas: int,
    ) -> int:
        """Escribe una version NUEVA con check-and-set obligatorio.

        ``cas=0`` crea; cualquier otro valor exige que la version actual sea
        exactamente esa. Un conflicto lanza ``KvCasMismatch`` y **no**
        sobrescribe el cambio ajeno. Las versiones anteriores no se mutan.
        """
        _status, payload = await self._request(
            "POST",
            self.data_path(logical_path),
            token=token,
            json={"data": values, "options": {"cas": cas}},
        )
        data = payload.get("data") or {}
        version = data.get("version")
        if version is None:
            raise VaultError("Vault no devolvio el numero de version tras escribir")
        return int(version)

    async def delete_latest(self, token: str, logical_path: str) -> None:
        """Soft-delete de la version actual. Reversible con undelete."""
        status, _payload = await self._request(
            "DELETE", self.data_path(logical_path), token=token
        )
        if status == 404:
            raise VaultNotFound("no existe ese secreto en Vault", status_code=404)

    async def delete_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        """Soft-delete de versiones explicitas. Reversible."""
        await self._request(
            "POST",
            f"{self._mount}/delete/{logical_path.strip('/')}",
            token=token,
            json={"versions": versions},
        )

    async def undelete_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        """Recupera versiones con soft-delete. Una destruida NO se recupera."""
        await self._request(
            "POST",
            f"{self._mount}/undelete/{logical_path.strip('/')}",
            token=token,
            json={"versions": versions},
        )

    async def destroy_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        """Destruye versiones. IRREVERSIBLE: no hay undelete despues de esto."""
        await self._request(
            "POST",
            f"{self._mount}/destroy/{logical_path.strip('/')}",
            token=token,
            json={"versions": versions},
        )

    async def delete_metadata(self, token: str, logical_path: str) -> None:
        """Borra metadata y TODAS las versiones. IRREVERSIBLE."""
        status, _payload = await self._request(
            "DELETE", self.metadata_path(logical_path), token=token
        )
        if status == 404:
            # Ya no existe: la purga es idempotente hacia el estado final.
            return

    # -- capacidades y envoltura --------------------------------------------

    async def capabilities(self, token: str, paths: list[str]) -> dict[str, tuple[str, ...]]:
        """Capacidades efectivas del token sobre varios paths, en una llamada."""
        _status, payload = await self._request(
            "POST", "sys/capabilities-self", token=token, json={"paths": paths}
        )
        data = payload.get("data") or payload
        out: dict[str, tuple[str, ...]] = {}
        for path in paths:
            caps = data.get(path) or payload.get(path) or []
            out[path] = tuple(str(cap) for cap in caps)
        return out

    async def wrap(
        self, token: str, payload: dict[str, Any], *, wrap_ttl_seconds: int
    ) -> WrappedDelivery:
        """Envuelve un payload arbitrario (p. ej. una referencia de entrega)."""
        _status, response = await self._request(
            "POST",
            "sys/wrapping/wrap",
            token=token,
            json=payload,
            wrap_ttl_seconds=wrap_ttl_seconds,
        )
        info = response.get("wrap_info") or {}
        if not info.get("token"):
            raise VaultError("Vault no devolvio wrap_info al envolver el payload")
        return WrappedDelivery(
            token=str(info["token"]),
            ttl_seconds=int(info.get("ttl") or wrap_ttl_seconds),
            creation_time=info.get("creation_time"),
            creation_path=info.get("creation_path"),
            accessor=str(info.get("accessor") or ""),
        )

    async def unwrap(self, wrapping_token: str) -> dict[str, Any]:
        """Desenvuelve. Un token de envoltura se consume UNA vez.

        Se expone para el cliente CLI de ejemplo y las pruebas; el servicio no
        desenvuelve lo que entrega.
        """
        _status, payload = await self._request(
            "POST", "sys/wrapping/unwrap", token=wrapping_token
        )
        return dict(payload.get("data") or {})

    async def lookup_wrap(self, token: str, wrapping_token: str) -> dict[str, Any]:
        """Consulta TTL y creacion de un wrapping token sin consumirlo."""
        _status, payload = await self._request(
            "POST",
            "sys/wrapping/lookup",
            token=token,
            json={"token": wrapping_token},
        )
        return dict(payload.get("data") or {})


def utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


__all__ = [
    "KvCasMismatch",
    "KvMetadata",
    "KvV2Client",
    "KvVersion",
    "VersionState",
    "WrappedDelivery",
    "utc_now_iso",
]
