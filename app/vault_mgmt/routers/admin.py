"""Comprobacion de acceso, estado de operaciones y auditoria.

Los consumidores de maquina (alta, aprovisionamiento, bindings, rotacion y
revocacion) viven en ``app/vault_mgmt/routers/consumers.py`` desde la etapa 4.6:
comparten el prefijo ``/vault`` y su propia etiqueta de OpenAPI.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query

from app.core.errors import COMMON_ERRORS
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.deps import (
    current_principal,
    get_access_service,
    get_app_settings,
    get_record_service,
    get_request_id,
    rate_limit_global,
    require_ready,
)
from app.vault_mgmt.schemas.common import (
    AuditEntryOut,
    AuditListOut,
    OperationOut,
    PageMeta,
)
from app.vault_mgmt.schemas.records import AccessCheckIn, AccessCheckOut
from app.vault_mgmt.services.access import AccessService
from app.vault_mgmt.services.records import RecordService

router = APIRouter(
    prefix="/vault",
    tags=["admin"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)


@router.post(
    "/access-check",
    response_model=AccessCheckOut,
    summary="Capacidad efectiva por coleccion, registro y operacion",
    description=(
        "Devuelve **dos columnas distintas**, porque son dos cosas distintas:\n\n"
        "* lo que permite tu rol de **aplicacion** (admin escribe; un rol lector "
        "declarado en la coleccion lee);\n"
        "* lo que permite la **ACL de Vault** sobre el path gestionado, evaluada "
        "con tu token humano.\n\n"
        "La capacidad efectiva es la interseccion, y Vault manda sobre el rol. "
        "**Nunca** devuelve valores.\n\n"
        "El cuerpo indica UUID de coleccion o registro, no una ruta de Vault: asi "
        "el endpoint no se convierte en un escaner de rutas arbitrarias."
    ),
)
async def access_check(
    payload: AccessCheckIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[AccessService, Depends(get_access_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> AccessCheckOut:
    result = await service.check(
        principal=principal,
        collection_id=payload.collection_id,
        record_id=payload.record_id,
        operations=payload.operations,
        request_id=request_id,
    )
    return AccessCheckOut.model_validate(result)


@router.get(
    "/operations/{operation_id}",
    response_model=OperationOut,
    summary="Estado, fases y error saneado de una operacion (solo admin)",
    description=(
        "Es el registro durable que permite reconciliar un fallo parcial: dice "
        "que fases se completaron en cada sistema. El error viene ya saneado y "
        "nunca contiene valores, tokens ni wrapping tokens."
    ),
)
async def get_operation(
    operation_id: Annotated[uuid.UUID, Path(description="UUID de la operacion.")],
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
) -> OperationOut:
    operation = await service.get_operation(
        principal=principal, operation_id=operation_id
    )
    return OperationOut.model_validate(operation)


@router.get(
    "/audit",
    response_model=AuditListOut,
    summary="Historial paginado, sin valores (solo admin)",
    description=(
        "Append-only: la cuenta de ejecucion solo tiene SELECT e INSERT sobre "
        "esta tabla.\n\n"
        "Orden estable `occurred_at DESC, audit_id DESC`, para que dos lineas del "
        "mismo instante no se intercambien entre paginas. No contiene valores, ni "
        "tokens, ni wrapping tokens, ni pruebas de MFA."
    ),
)
async def list_audit(
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[AccessService, Depends(get_access_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    collection_id: Annotated[uuid.UUID | None, Query()] = None,
    record_id: Annotated[uuid.UUID | None, Query()] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    outcome: Annotated[
        str | None, Query(pattern="^(allowed|denied|error|partial)$")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditListOut:
    limit = min(limit, settings.max_page_limit)
    page = await service.list_audit(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        action=action,
        outcome=outcome,
        limit=limit,
        offset=offset,
    )
    return AuditListOut(
        page=PageMeta(
            limit=page.limit,
            offset=page.offset,
            total=page.total,
            returned=len(page.items),
        ),
        items=[AuditEntryOut.model_validate(item) for item in page.items],
    )
