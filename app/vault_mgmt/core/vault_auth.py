"""De donde saca el APROVISIONADOR su token de Vault.

Esta pieza existe sola, y no incrustada en el cliente de AppRole, por un motivo
concreto: el token que usa el aprovisionamiento en local es una decision de
**entorno**, no de contrato. Separandolo, migrar a una identidad tecnica propia
(o a una identidad de carga de trabajo en la nube) es cambiar la implementacion
de ``VaultTokenProvider`` y nada mas: ningun endpoint, ningun servicio y ningun
DTO se entera.

Lo que hay hoy, dicho sin adornos
---------------------------------
``LocalFileTokenProvider`` lee el **token inicial de Vault** de un archivo
montado en solo lectura. Ese token es administrativo: puede hacer cualquier cosa
en Vault. Lo que lo acota aqui NO es la ACL de Vault, sino el codigo que lo usa
(``approle_admin.py``, limitado al montaje y a los roles gestionados). Es una
simplificacion aceptada para el entorno local y **no** es una configuracion de
produccion:

* El archivo se monta solo en los componentes que aprovisionan
  (``vault-mgmt-service`` y su worker). Las demas APIs no lo reciben.
* No se copia a ninguna imagen, no se pasa como argumento de ningun proceso, no
  se registra y no se devuelve en ninguna respuesta.
* Si el archivo no esta, el aprovisionamiento queda **desactivado** y se dice en
  readiness. El resto del servicio sigue funcionando.

Lo que NO hace este modulo: no hace unseal, no lee la clave de desbloqueo, no
emite tokens de autenticacion para nadie y no entrega su token a ningun cliente.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.core.logging import get_logger
from app.core.vault import VaultError
from app.vault_mgmt.core.config import Settings

logger = get_logger(__name__)


class ProvisioningUnavailable(VaultError):
    """No hay con que aprovisionar. Se traduce a 503, no a 500.

    Es una dependencia que falta, igual que Vault sellado: el servicio lo dice
    y no inventa un camino alternativo con otras credenciales.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=503)


@runtime_checkable
class VaultTokenProvider(Protocol):
    """Contrato minimo. Devuelve un token utilizable; nunca lo registra."""

    @property
    def available(self) -> bool: ...

    @property
    def description(self) -> str:
        """Como se obtiene el token, para readiness y logs. Sin el valor."""
        ...

    async def token(self) -> str: ...

    async def invalidate(self) -> None:
        """Descarta el token cacheado tras un 403: puede haber rotado."""
        ...

    async def aclose(self) -> None: ...


class LocalFileTokenProvider:
    """Token administrativo leido de un archivo montado en solo lectura.

    Relee el archivo cuando cambia su fecha de modificacion, de modo que rotar
    el token fuera no obliga a reiniciar el proceso. El valor vive en memoria y
    no sale de aqui por ningun otro camino.
    """

    def __init__(self, settings: Settings) -> None:
        self._path = Path(settings.vault_token_file)
        self._cached: str | None = None
        self._mtime: float | None = None
        self._lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        return self._path.is_file()

    @property
    def description(self) -> str:
        return (
            f"token administrativo del perfil local, leido de {self._path} "
            "(montado en solo lectura; no es configuracion de produccion)"
        )

    async def token(self) -> str:
        async with self._lock:
            try:
                stat = self._path.stat()
            except OSError as exc:
                self._cached = None
                raise ProvisioningUnavailable(
                    "el aprovisionamiento esta desactivado: no hay token de Vault "
                    f"montado en {self._path}. En local lo deja 'make all'; "
                    "comprueba el secreto vault_provisioner_token de compose.yaml"
                ) from exc

            if self._cached is not None and self._mtime == stat.st_mtime:
                return self._cached

            lines = self._path.read_text(encoding="utf-8").splitlines()
            value = lines[0].strip() if lines else ""
            if not value:
                self._cached = None
                raise ProvisioningUnavailable(
                    f"el archivo de token del aprovisionador esta vacio: {self._path}"
                )
            if self._cached is not None and value != self._cached:
                logger.info(
                    "token del aprovisionador releido tras cambiar el archivo",
                    extra={"operation": "vault_auth"},
                )
            self._cached = value
            self._mtime = stat.st_mtime
            return value

    async def invalidate(self) -> None:
        async with self._lock:
            self._cached = None
            self._mtime = None

    async def aclose(self) -> None:
        await self.invalidate()


class StaticTokenProvider:
    """Proveedor para pruebas y para un arranque sin aprovisionamiento.

    Con ``token=None`` representa de forma explicita "no hay credencial": las
    llamadas fallan con 503 en vez de con un error de atributo.
    """

    def __init__(self, token: str | None, *, description: str = "token fijo") -> None:
        self._token = token
        self._description = description

    @property
    def available(self) -> bool:
        return bool(self._token)

    @property
    def description(self) -> str:
        return self._description

    async def token(self) -> str:
        if not self._token:
            raise ProvisioningUnavailable(
                "el aprovisionamiento esta desactivado: este proceso no tiene "
                "token de Vault configurado"
            )
        return self._token

    async def invalidate(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


def build_token_provider(settings: Settings) -> VaultTokenProvider:
    """Elige el proveedor del entorno. Hoy solo hay uno, y es local."""
    provider = LocalFileTokenProvider(settings)
    if not provider.available:
        logger.warning(
            "sin token de aprovisionamiento: las altas de consumidores quedaran "
            "en 'waiting_receiver' y readiness lo indicara",
            extra={"operation": "vault_auth", "path": settings.vault_token_file},
        )
    return provider


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "LocalFileTokenProvider",
    "ProvisioningUnavailable",
    "StaticTokenProvider",
    "VaultTokenProvider",
    "build_token_provider",
    "utc_now",
]
