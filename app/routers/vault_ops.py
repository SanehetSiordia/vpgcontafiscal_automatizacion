"""Operaciones sobre Vault: provisionamiento, credenciales, reset de MFA y
comprobacion de acceso."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response, status

from app.core.config import Settings
from app.core.errors import COMMON_ERRORS, NotFoundError
from app.core.security import ApiSession
from app.deps import (
    IdempotencyHeader,
    current_principal,
    current_session,
    get_app_settings,
    get_auth_service,
    get_vault_sync,
    rate_limit_global,
    require_ready,
)
from app.schemas.auth import (
    AccessCheckOut,
    AccessCheckRequest,
    CredentialsPatchRequest,
    EnrollmentOut,
    MfaResetRequest,
    OperationOut,
    VaultProvisionRequest,
)
from app.services import rbac
from app.services.auth import AuthService
from app.services.rbac import Principal
from app.services.vault_sync import VaultSyncService

router = APIRouter(
    tags=["vault"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)

UserId = Annotated[uuid.UUID, Path(description="UUID del empleado objetivo.")]

_ENROLLMENT_WARNING = (
    "Este URI otpauth:// se entrega UNA sola vez y no se registra en ningun log. "
    "Si se pierde, no se regenera en silencio: hace falta un reset explicito de MFA."
)


@router.post(
    "/user/{user_id}/vault/provision",
    response_model=EnrollmentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Provisionar identidad y enrolamiento inicial (solo admin)",
    description=(
        "Crea la cuenta `userpass`, su entidad y el alias con el **accessor "
        "existente**, los vincula al empleado y genera la semilla TOTP de esa "
        "entidad con el metodo compartido.\n\n"
        "La politica sale de una **allowlist** del servicio: el cuerpo no puede "
        "elegir una politica arbitraria, y `vpg-admin` nunca se asigna aqui.\n\n"
        "La respuesta incluye el URI de enrolamiento con `Cache-Control: no-store`. "
        "Es la unica vez que se entrega: ningun GET lo devuelve.\n\n"
        "Que exista el UUID del metodo TOTP no demuestra que la persona haya "
        "registrado su autenticador; por eso el estado inicial es `pending`.\n\n"
        "Si Vault queda provisionado pero PostgreSQL no registra el vinculo, la "
        "respuesta es **409** con `operation_id`, no 201."
    ),
)
async def provision(
    user_id: UserId,
    payload: VaultProvisionRequest,
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
    idempotency_key: IdempotencyHeader = None,
) -> EnrollmentOut:
    rbac.assert_can_manage_vault_credentials(principal, user_id)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    result = await sync.provision(
        user_id=user_id,
        actor_user_id=principal.user_id,
        vault_username=payload.vault_username,
        initial_password=payload.initial_password.get_secret_value(),
        policy=payload.policy,
        idempotency_key=idempotency_key,
    )
    return EnrollmentOut(
        operation_id=result.operation_id,
        user_id=result.user_id,
        vault_username=result.vault_username,
        vault_entity_id=result.vault_entity_id,
        totp_status=result.totp_status,
        totp_enrollment_uri=result.enrollment_uri,
        warning=_ENROLLMENT_WARNING,
    )


@router.patch(
    "/user/{user_id}/vault/credentials",
    response_model=OperationOut,
    summary="Cambiar username o contrasena en Vault (solo admin)",
    description=(
        "**Contrasena**: se envia directamente a Vault. No se persiste aqui, y no "
        "existe una segunda contrasena guardada en PostgreSQL.\n\n"
        "**Username**: Vault no ofrece un `rename` de userpass. La secuencia real es "
        "crear la cuenta nueva, repuntar el alias a la **misma entidad** (lo que "
        "conserva `entity_id` y la semilla TOTP ya registrada) y solo entonces "
        "borrar la cuenta anterior, que es lo que impide entrar con el nombre viejo.\n\n"
        "Por eso cambiar el username **exige** enviar tambien `new_password`: la "
        "cuenta nueva necesita una, Vault no guarda la anterior en claro y este "
        "servicio no se la inventa. Si falta, la peticion se rechaza con 422 y no "
        "se toca nada."
    ),
)
async def change_credentials(
    user_id: UserId,
    payload: CredentialsPatchRequest,
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
    idempotency_key: IdempotencyHeader = None,
) -> OperationOut:
    rbac.assert_can_manage_vault_credentials(principal, user_id)
    response.headers["Cache-Control"] = "no-store"

    operation_id = await sync.change_credentials(
        user_id=user_id,
        actor_user_id=principal.user_id,
        new_username=payload.new_vault_username,
        new_password=(
            payload.new_password.get_secret_value() if payload.new_password else None
        ),
        idempotency_key=idempotency_key,
    )
    from app.repositories import operations as ops_repo

    async with sync._session_factory() as session:  # noqa: SLF001 - lectura del registro
        operation = await ops_repo.get(session, operation_id)
    if operation is None:
        raise NotFoundError("no se encontro la operacion recien creada")
    return OperationOut.model_validate(operation)


@router.post(
    "/user/{user_id}/mfa/reset",
    response_model=EnrollmentOut,
    summary="Reset explicito del segundo factor (solo admin, MFA reciente)",
    description=(
        "Exige confirmacion explicita (`confirm: \"RESET\"`), rol admin y un MFA "
        "**reciente** del solicitante: una sesion vieja no basta.\n\n"
        "Destruye y regenera **solo** la semilla de la entidad objetivo. El metodo "
        "TOTP compartido, el enforcement y las demas personas no se tocan.\n\n"
        "Invalida las sesiones del objetivo, limpia su confirmacion vigente y deja "
        "`totp_status='reset_required'` hasta que haya un nuevo login correcto.\n\n"
        "Si Vault ya destruyo la semilla y PostgreSQL no pudo reflejarlo, la "
        "respuesta es 409 con `operation_id`: la fase queda registrada."
    ),
)
async def reset_mfa(
    user_id: UserId,
    payload: MfaResetRequest,
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    idempotency_key: IdempotencyHeader = None,
) -> EnrollmentOut:
    rbac.assert_can_manage_vault_credentials(principal, user_id)
    rbac.require_fresh_mfa(
        principal, settings.sensitive_op_mfa_max_age_seconds, "reiniciar el MFA de otra persona"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    operation_id, enrollment_uri = await sync.reset_mfa(
        user_id=user_id,
        actor_user_id=principal.user_id,
        reason=payload.reason,
        idempotency_key=idempotency_key,
        revoke_sessions=auth.revoke_user_sessions,
    )
    identity = await sync.describe_identity(user_id)
    return EnrollmentOut(
        operation_id=operation_id,
        user_id=user_id,
        vault_username=str(identity["vault_username"]),
        vault_entity_id=uuid.UUID(str(identity["vault_entity_id"])),
        totp_status=str(identity["totp_status"]),
        totp_enrollment_uri=enrollment_uri,
        warning=_ENROLLMENT_WARNING,
    )


@router.post(
    "/vault/access-check",
    response_model=AccessCheckOut,
    summary="Comprobar autorizacion sobre una ruta de Vault",
    description=(
        "Evalua la ruta con el **token humano** de la sesion. La credencial tecnica "
        "del servicio no se usa aqui: no debe suplir los permisos del usuario.\n\n"
        "El cuerpo indica un nombre **logico** de una allowlist, no una ruta: asi el "
        "endpoint no se convierte en un escaner de rutas arbitrarias.\n\n"
        "Devuelve unicamente el resultado de autorizacion y las capacidades. "
        "**Nunca** los valores del secreto."
    ),
)
async def access_check(
    payload: AccessCheckRequest,
    api_session: Annotated[ApiSession, Depends(current_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
) -> AccessCheckOut:
    result, capabilities = await sync.access_check(
        api_session.vault_token, payload.resource
    )
    return AccessCheckOut(
        resource=payload.resource,
        authorized=result != "denegada_por_politica",
        result=result,  # type: ignore[arg-type]
        capabilities=list(capabilities),
    )


@router.get(
    "/vault/operations/{operation_id}",
    response_model=OperationOut,
    summary="Estado de una operacion (solo admin)",
    description=(
        "Consulta el registro durable: fases completadas en cada sistema, estado y "
        "error ya saneado. Es lo que permite reconciliar un fallo parcial."
    ),
)
async def get_operation(
    operation_id: Annotated[uuid.UUID, Path()],
    principal: Annotated[Principal, Depends(current_principal)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
) -> OperationOut:
    rbac.require_admin(principal, "consultar operaciones")
    from app.repositories import operations as ops_repo

    async with sync._session_factory() as session:  # noqa: SLF001
        operation = await ops_repo.get(session, operation_id)
    if operation is None:
        raise NotFoundError("no existe esa operacion")
    return OperationOut.model_validate(operation)
