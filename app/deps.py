"""Dependencias de FastAPI: sesion de base de datos, principal y compuertas.

El estado compartido (cliente Vault, almacen de sesiones, readiness) vive en
``app.state``, puesto ahi por el ``lifespan``. Aqui solo se lee.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.errors import (
    NotReadyError,
    RateLimitedError,
    UnauthenticatedError,
)
from app.core.rate_limit import SlidingWindowLimiter
from app.core.readiness import ReadinessState
from app.core.security import ApiSession, SessionStore
from app.core.vault import VaultClient
from app.repositories import users as users_repo
from app.services.auth import AuthService
from app.services.rbac import Principal
from app.services.vault_gateway import VaultGatewayService
from app.services.vault_sync import VaultSyncService

bearer_scheme = HTTPBearer(
    scheme_name="ApiSession",
    description=(
        "Identificador opaco devuelto por /auth/mfa/verify. **No** es el token de "
        "Vault: ese nunca sale del servidor."
    ),
    auto_error=False,
)


def get_app_settings() -> Settings:
    return get_settings()


def get_vault(request: Request) -> VaultClient:
    return request.app.state.vault


def get_sessions(request: Request) -> SessionStore:
    return request.app.state.sessions


def get_readiness(request: Request) -> ReadinessState:
    return request.app.state.readiness


def get_limiter(request: Request) -> SlidingWindowLimiter:
    return request.app.state.limiter


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_vault_sync(request: Request) -> VaultSyncService:
    return request.app.state.vault_sync


def get_vault_gateway(request: Request) -> VaultGatewayService:
    """Pasarela interna de la etapa 4. Solo la usan los endpoints /internal/v1."""
    return request.app.state.vault_gateway


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """Una ``AsyncSession`` por peticion. Commit al salir bien, rollback si no."""
    factory = request.app.state.session_factory
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()


async def require_ready(
    readiness: Annotated[ReadinessState, Depends(get_readiness)],
) -> None:
    """Compuerta de negocio.

    Mientras la precondicion no este verificada (Vault sellado, credencial
    tecnica invalida, administrador sin vinculo), los endpoints de negocio
    devuelven 503. No se sirven a medias.
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


async def rate_limit_login(
    request: Request,
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    client = request.client.host if request.client else "desconocido"
    await _enforce_limit(
        limiter, f"login:{client}", settings.rate_limit_login_per_minute, "login"
    )


async def rate_limit_mfa(
    request: Request,
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    client = request.client.host if request.client else "desconocido"
    await _enforce_limit(
        limiter, f"mfa:{client}", settings.rate_limit_mfa_per_minute, "mfa"
    )


async def current_session(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    sessions: Annotated[SessionStore, Depends(get_sessions)],
) -> ApiSession:
    if credentials is None or not credentials.credentials:
        raise UnauthenticatedError("falta la cabecera Authorization: Bearer <api_session>")
    session = await sessions.get_session(credentials.credentials)
    if session is None:
        raise UnauthenticatedError(
            "sesion inexistente o caducada. Nota: reiniciar el worker invalida "
            "todas las sesiones, porque viven solo en memoria.",
            code="session_expired",
        )
    return session


async def current_principal(
    api_session: Annotated[ApiSession, Depends(current_session)],
    db: Annotated[AsyncSession, Depends(get_db)],
    vault: Annotated[VaultClient, Depends(get_vault)],
    limiter: Annotated[SlidingWindowLimiter, Depends(get_limiter)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> Principal:
    """Resuelve quien pide, comprobando que sigue siendo valido.

    En cada peticion autenticada:
      * el token de Vault debe seguir vivo (una entidad deshabilitada o un token
        revocado invalidan la sesion aunque siga en memoria);
      * el empleado debe seguir activo;
      * los roles se releen de PostgreSQL, no se confian al momento del login.
    """
    await _enforce_limit(
        limiter,
        f"session:{api_session.session_id}",
        settings.rate_limit_session_per_minute,
        "sesion",
    )

    try:
        await vault.lookup_self(api_session.vault_token)
    except Exception as exc:  # noqa: BLE001
        raise UnauthenticatedError(
            "la sesion de Vault ya no es valida (revocada, caducada o entidad "
            "deshabilitada)",
            code="vault_session_invalid",
        ) from exc

    user = await users_repo.get_by_id(db, api_session.user_id)
    if user is None or not user.is_active:
        raise UnauthenticatedError("la cuenta esta desactivada", code="inactive_user")

    roles = await users_repo.role_codes_for(db, api_session.user_id)
    return Principal(
        user_id=api_session.user_id,
        username=api_session.username,
        role_codes=frozenset(roles),
        entity_id=api_session.entity_id,
        mfa_age_seconds=api_session.mfa_age_seconds(),
    )


IdempotencyHeader = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        description=(
            "Opcional. Repetir la peticion con la misma clave devuelve la operacion "
            "original en vez de ejecutarla dos veces. No se almacena el cuerpo."
        ),
        max_length=128,
    ),
]
