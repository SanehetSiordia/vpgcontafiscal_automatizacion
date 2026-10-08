"""Dependencias de FastAPI de vault-mgmt-service.

El estado compartido (cliente de la pasarela, sonda de Vault, readiness,
limitador) vive en ``app.state``, puesto ahi por el ``lifespan``. Aqui solo se
lee.

La diferencia importante con la etapa 3: ``current_principal`` **no** valida la
sesion por su cuenta. Las sesiones viven en memoria del worker de user-mgmt y la
``api_session`` es opaca; este proceso no puede verificarla. Se la envia a la
pasarela interna, que valida sesion, empleado activo, roles vigentes y
antiguedad del MFA, y devuelve solo lo necesario.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.errors import NotReadyError, RateLimitedError, UnauthenticatedError
from app.core.rate_limit import SlidingWindowLimiter
from app.vault_mgmt.core.config import Settings, get_settings
from app.vault_mgmt.core.gateway_client import GatewayClient
from app.vault_mgmt.core.machine_auth import VaultProbe
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.core.readiness import ReadinessState
from app.vault_mgmt.core.receiver_auth import ReceiverRegistry
from app.vault_mgmt.services.access import AccessService
from app.vault_mgmt.services.catalog import CatalogService
from app.vault_mgmt.services.consumers import ConsumerService
from app.vault_mgmt.services.lifecycle import LifecycleService
from app.vault_mgmt.services.provisioning import ProvisioningService
from app.vault_mgmt.services.records import RecordService

human_scheme = HTTPBearer(
    scheme_name="ApiSession",
    description=(
        "Identificador opaco devuelto por `POST /user_mgmt/v1/auth/mfa/verify` en "
        "el puerto 8000. **No** es un token de Vault ni un JWT: este servicio no "
        "lo interpreta, lo reenvia a la pasarela interna de user-mgmt."
    ),
    auto_error=False,
)

machine_scheme = HTTPBearer(
    scheme_name="VaultMachineToken",
    description=(
        "Token de Vault de la **maquina**, obtenido antes con su AppRole de solo "
        "lectura. Contrato distinto y separado del Bearer humano: no se acepta "
        "aqui una api_session, ni alli un token de Vault."
    ),
    auto_error=False,
)


def get_app_settings() -> Settings:
    return get_settings()


def get_readiness(request: Request) -> ReadinessState:
    return request.app.state.readiness


def get_limiter(request: Request) -> SlidingWindowLimiter:
    return request.app.state.limiter


def get_gateway(request: Request) -> GatewayClient:
    return request.app.state.gateway


def get_probe(request: Request) -> VaultProbe:
    return request.app.state.probe


def get_catalog_service(request: Request) -> CatalogService:
    return request.app.state.catalog_service


def get_record_service(request: Request) -> RecordService:
    return request.app.state.record_service


def get_lifecycle_service(request: Request) -> LifecycleService:
    return request.app.state.lifecycle_service


def get_consumer_service(request: Request) -> ConsumerService:
    return request.app.state.consumer_service


def get_access_service(request: Request) -> AccessService:
    return request.app.state.access_service


def get_provisioning_service(request: Request) -> ProvisioningService:
    return request.app.state.provisioning_service


def get_receivers(request: Request) -> ReceiverRegistry:
    return request.app.state.receivers


def get_request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


async def require_ready(
    readiness: Annotated[ReadinessState, Depends(get_readiness)],
) -> None:
    """Compuerta de negocio: 503 mientras falte una dependencia.

    Vault sellado, catalogo sin migrar, user-mgmt caido o pasarela sin
    credencial son todos casos de 503. No se sirve a medias.
    """
    if not readiness.ready:
        report = readiness.report
        raise NotReadyError(
            "el servicio todavia no esta listo: "
            + (report.detail or "comprobacion de arranque pendiente"),
            context=report.as_dict(),
        )


async def _enforce_limit(
    limiter: SlidingWindowLimiter, key: str, limit: int, scope: str
) -> None:
    decision = await limiter.check(key, limit)
    if not decision.allowed:
        raise RateLimitedError(
            f"has superado el limite de {limit} peticiones por minuto en {scope}",
            context={"scope": scope, "limit": limit},
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


async def rate_limit_global(
    request: Request,
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    client = request.client.host if request.client else "desconocido"
    await _enforce_limit(
        limiter, f"global:{client}", settings.rate_limit_global_per_minute, "global"
    )


async def rate_limit_receiver(
    request: Request,
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    """Limite del canal interno, por origen.

    La clave es la IP del cliente y NO la credencial presentada: contar por
    credencial obligaria a usarla como parte de una clave de diccionario, y una
    credencial no tiene por que acabar en una estructura de contabilidad.
    """
    client = request.client.host if request.client else "desconocido"
    await _enforce_limit(
        limiter,
        f"receiver:{client}",
        settings.rate_limit_receiver_per_minute,
        "receptor",
    )


async def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(human_scheme)],
    gateway: Annotated[GatewayClient, Depends(get_gateway)],
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> HumanPrincipal:
    """Resuelve quien pide **preguntando a user-mgmt**.

    Se limita por sesion antes de llamar: asi un cliente con una sesion valida
    no puede usar este servicio para martillear la pasarela.
    """
    if credentials is None or not credentials.credentials:
        raise UnauthenticatedError(
            "falta la cabecera Authorization: Bearer <api_session>. La sesion se "
            "obtiene en user-mgmt (puerto 8000) con login + TOTP."
        )
    bearer = credentials.credentials
    # La clave del limitador es un prefijo del identificador, no el valor
    # completo: no hace falta guardarlo entero para contar peticiones.
    await _enforce_limit(
        limiter,
        f"session:{bearer[:12]}",
        settings.rate_limit_session_per_minute,
        "sesion",
    )

    probe = await gateway.probe_session(bearer=bearer, request_id=request_id)
    try:
        user_id = uuid.UUID(str(probe["user_id"]))
    except (KeyError, ValueError) as exc:
        raise UnauthenticatedError(
            "la pasarela no devolvio un principal utilizable"
        ) from exc

    return HumanPrincipal(
        user_id=user_id,
        username=str(probe.get("username") or ""),
        role_codes=frozenset(str(code) for code in (probe.get("role_codes") or ())),
        entity_id=str(probe.get("entity_id") or ""),
        mfa_age_seconds=int(probe.get("mfa_age_seconds") or 0),
        bearer=bearer,
    )


async def machine_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(machine_scheme)],
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> str:
    """Token de Vault de una maquina. No se valida aqui: lo hace el servicio."""
    if credentials is None or not credentials.credentials:
        raise UnauthenticatedError(
            "falta la cabecera Authorization con el token de Vault de la maquina. "
            "Obtenlo con tu AppRole antes de llamar.",
            code="machine_token_missing",
        )
    token = credentials.credentials
    await _enforce_limit(
        limiter,
        f"consumer:{token[:12]}",
        settings.rate_limit_consumer_per_minute,
        "consumidor",
    )
    return token


IdempotencyHeader = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        description=(
            "Opcional. Repetir la peticion con la misma clave devuelve la operacion "
            "original en vez de ejecutarla dos veces. No se almacena el cuerpo ni "
            "un hash de los valores."
        ),
        max_length=128,
    ),
]

MfaProofHeader = Annotated[
    str | None,
    Header(
        alias="X-VPG-MFA-Proof",
        description=(
            "Prueba breve de MFA reciente, emitida por "
            "`POST /user_mgmt/v1/auth/mfa/step-up/verify`. Un solo uso, ligada a "
            "tu sesion, a ti, a la operacion y al conjunto cerrado de recursos."
        ),
        max_length=256,
    ),
]
