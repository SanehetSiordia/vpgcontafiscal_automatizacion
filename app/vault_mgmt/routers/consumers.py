"""Contrato publico de consumidores de maquina (etapa 4.6).

Todas las rutas exigen **sesion valida y rol admin**. La sesion es la misma
``api_session`` de user-mgmt, con el MFA que ya existe en el login; esta
subetapa **no** anade una reautenticacion por accion, y las reglas de MFA de los
endpoints que ya la pedian (``destroy`` y ``purge`` de registros) siguen igual.

Las mutaciones son **asincronas a proposito**: devuelven 202 con
``operation_id`` y un ``Location`` para consultar. Quien llama no espera a Vault
dentro de una peticion HTTP, y un reinicio no pierde la solicitud porque esta en
PostgreSQL.

Ninguna respuesta de este modulo contiene ``role_id``, ``secret_id``, tokens de
Vault ni wrapping tokens. Lo unico que se devuelve de Vault son *accessors*, y
solo en el detalle de una entrega: identifican una credencial para revocarla y
auditarla, no para usarla.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.core.errors import COMMON_ERRORS
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.deps import (
    IdempotencyHeader,
    current_principal,
    get_app_settings,
    get_consumer_service,
    get_provisioning_service,
    get_request_id,
    rate_limit_global,
    require_ready,
)
from app.vault_mgmt.schemas.common import PageMeta
from app.vault_mgmt.schemas.consumers import (
    AcceptedOut,
    ConsumerCreateIn,
    ConsumerDetailOut,
    ConsumerListOut,
    ConsumerSummaryOut,
    DeliveryOut,
    LastOperationOut,
    ProvisionIn,
    RevokeIn,
    RotateIn,
)
from app.vault_mgmt.schemas.crawler import (
    BindingOut,
    BindingsOut,
    BindingsPutIn,
    ConsumerOut,
)
from app.vault_mgmt.services.consumers import ConsumerService
from app.vault_mgmt.services.provisioning import Accepted, ProvisioningService

router = APIRouter(
    prefix="/vault",
    tags=["consumers"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)

ACCEPTED_DESCRIPTION = (
    "**202, no 201.** La respuesta lleva exactamente `consumer_id`, "
    "`operation_id` y `status`.\n\n"
    "`pending` significa **solicitud guardada**, no entrega completada: en ese "
    "momento no existe ninguna credencial emitida. El ciclo real es "
    "`pending` -> `waiting_receiver` (identidad lista, esperando al receptor) -> "
    "`awaiting_ack` (envoltura entregada) -> `completed` (el receptor acredito "
    "su token). Consulta `Location` para seguirlo."
)


def _location(settings: Settings, accepted: Accepted) -> str:
    return f"{settings.api_prefix}/vault/operations/{accepted.operation_id}"


def _accepted(
    response: Response, settings: Settings, accepted: Accepted
) -> AcceptedOut:
    response.headers["Location"] = _location(settings, accepted)
    return AcceptedOut(
        consumer_id=accepted.consumer_id,
        operation_id=accepted.operation_id,
        status=accepted.status,  # type: ignore[arg-type]
    )


def _bindings_out(consumer: object, bindings: list, names: dict | None = None) -> BindingsOut:
    nombres = names or {}
    return BindingsOut(
        consumer=ConsumerOut.model_validate(consumer),
        bindings=[
            BindingOut(
                binding_id=item.binding_id,
                collection_id=item.collection_id,
                collection_name=nombres.get(item.collection_id),
                record_id=item.record_id,
                pinned_version=item.pinned_version,
                resolves_to=(
                    f"version fijada {item.pinned_version}"
                    if item.pinned_version
                    else "latest"
                ),
                created_at=item.created_at,
            )
            for item in bindings
        ],
        total=len(bindings),
    )


@router.post(
    "/consumers",
    response_model=AcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Registra un consumidor de maquina y su alcance (solo admin)",
    description=(
        "Alta de la identidad de maquina y de sus asignaciones iniciales.\n\n"
        + ACCEPTED_DESCRIPTION
        + "\n\nQue **no** se acepta en el cuerpo, por diseno: HCL, rutas de Vault, "
        "nombre de montaje o de rol, root token y URL del receptor. El montaje "
        "sale de la configuracion del servicio y el rol se deriva del nombre del "
        "consumidor, asi que una peticion no puede apuntar a una identidad "
        "ajena.\n\n"
        "El `receiver` debe ser un receptor **ya configurado** en el servicio: su "
        "credencial interna la genera `make all` en `secrets/`. Un alta con un "
        "receptor desconocido es 422, no un consumidor que nadie podria reclamar."
    ),
)
async def register_consumer(
    payload: ConsumerCreateIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> AcceptedOut:
    accepted = await service.register_consumer(
        principal=principal,
        name=payload.name,
        description=payload.description,
        receiver=payload.receiver,
        bindings=[
            (item.collection_id, item.record_id, item.pinned_version)
            for item in payload.bindings
        ],
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _accepted(response, settings, accepted)


@router.get(
    "/consumers",
    response_model=ConsumerListOut,
    summary="Lista paginada de consumidores, sin credenciales (solo admin)",
    description=(
        "Orden estable `created_at DESC, consumer_id`, para que dos altas del "
        "mismo instante no se intercambien entre paginas.\n\n"
        "No devuelve `role_id` ni `secret_id`: el primero no se guarda y el "
        "segundo no existe fuera de su envoltura.\n\n"
        "`delivery_mode='direct'` marca los consumidores **heredados** de la etapa "
        "4, preparados por CLI: su token lee el prefijo KV directamente, asi que "
        "sus bindings acotan lo que esta API les entrega, no lo que su token puede "
        "leer en Vault. `'mediated'` son los de la etapa 4.6, cuya politica no "
        "cubre la lectura de KV."
    ),
)
async def list_consumers(
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    state: Annotated[str | None, Query(pattern="^(active|revoked)$")] = None,
    delivery_mode: Annotated[
        str | None, Query(pattern="^(direct|mediated)$")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConsumerListOut:
    page = await service.list_consumers(
        principal=principal,
        state=state,
        delivery_mode=delivery_mode,
        limit=min(limit, settings.max_page_limit),
        offset=offset,
    )
    return ConsumerListOut(
        page=PageMeta(
            limit=page.limit,
            offset=page.offset,
            total=page.total,
            returned=len(page.items),
        ),
        items=[ConsumerSummaryOut.model_validate(item) for item in page.items],
    )


@router.get(
    "/consumers/{consumer_id}",
    response_model=ConsumerDetailOut,
    summary="Estado del consumidor y su ultima operacion (solo admin)",
    description=(
        "`provisioning_state` dice donde esta el aprovisionamiento:\n\n"
        "* `never_provisioned`: existe en el catalogo y nada mas.\n"
        "* `in_progress`: se esta preparando su identidad en Vault.\n"
        "* `ready`: el receptor acredito un token valido para esta identidad. "
        "**No** garantiza que siga vivo: un token caduca por su TTL y el SecretID "
        "por el suyo.\n"
        "* `failed` / `revoked`: lo que dicen.\n\n"
        "`last_delivery` lleva solo *accessors*, nunca credenciales."
    ),
)
async def get_consumer(
    consumer_id: Annotated[uuid.UUID, Path(description="UUID del consumidor.")],
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
) -> ConsumerDetailOut:
    consumer, operation, delivery, bindings_total = await service.get_consumer(
        principal=principal, consumer_id=consumer_id
    )
    return ConsumerDetailOut(
        consumer=ConsumerSummaryOut.model_validate(consumer),
        last_operation=(
            LastOperationOut.model_validate(operation) if operation is not None else None
        ),
        last_delivery=(
            DeliveryOut.model_validate(delivery) if delivery is not None else None
        ),
        bindings_total=bindings_total,
    )


@router.post(
    "/consumers/{consumer_id}/provision",
    response_model=AcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Prepara una emision pendiente para un consumidor existente",
    description=(
        "Deja la identidad lista y la operacion en `waiting_receiver`.\n\n"
        "**No emite ninguna credencial todavia.** Sin receptor que la recoja, un "
        "SecretID emitido seria una credencial viva esperando a un proceso que "
        "puede no existir. Se emite cuando el receptor reclama.\n\n" + ACCEPTED_DESCRIPTION
    ),
)
async def provision_consumer(
    consumer_id: Annotated[uuid.UUID, Path()],
    payload: ProvisionIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> AcceptedOut:
    accepted = await service.request_provision(
        principal=principal,
        consumer_id=consumer_id,
        note=payload.note,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _accepted(response, settings, accepted)


@router.put(
    "/consumers/{consumer_id}/bindings",
    response_model=BindingsOut,
    summary="Registros y versiones autorizados para una maquina (solo admin)",
    description=(
        "Reemplazo **completo** del conjunto de asignaciones: lo que no venga en "
        "la lista deja de estar autorizado.\n\n"
        "`pinned_version` fija la version; ausente significa `latest`, que cambia "
        "cuando se escribe otra version.\n\n"
        "Quitar una asignacion impide **entregas futuras**. No caduca un wrapping "
        "token ya entregado, no revoca el token del consumidor y no borra lo que "
        "ya leyo: para eso esta `POST .../revoke`.\n\n"
        "Para un consumidor **heredado** (`delivery_mode='direct'`) estas "
        "asignaciones "
        "acotan lo que esta API le entrega, pero su token puede leer el prefijo "
        "KV por su cuenta: ahi los bindings no son el limite real."
    ),
)
async def put_bindings(
    consumer_id: Annotated[uuid.UUID, Path(description="UUID del consumidor.")],
    payload: BindingsPutIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ConsumerService, Depends(get_consumer_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> BindingsOut:
    consumer, bindings = await service.put_bindings(
        principal=principal,
        consumer_id=consumer_id,
        entries=[
            (item.collection_id, item.record_id, item.pinned_version)
            for item in payload.bindings
        ],
        request_id=request_id,
    )
    return _bindings_out(consumer, bindings)


@router.get(
    "/consumers/{consumer_id}/bindings",
    response_model=BindingsOut,
    summary="Referencias y alcance de una maquina, sin credenciales (solo admin)",
    description=(
        "No devuelve `role_id` ni `secret_id`: el catalogo solo guarda el "
        "montaje, el rol y la politica esperados, para poder comprobar la "
        "identidad del token que se presente."
    ),
)
async def get_bindings(
    consumer_id: Annotated[uuid.UUID, Path()],
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ConsumerService, Depends(get_consumer_service)],
) -> BindingsOut:
    consumer, bindings, names = await service.get_bindings(
        principal=principal, consumer_id=consumer_id
    )
    return _bindings_out(consumer, bindings, names)


@router.post(
    "/consumers/{consumer_id}/rotate",
    response_model=AcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Rotacion controlada de la credencial de maquina (solo admin)",
    description=(
        "La estrategia es **explicita** y se elige en el cuerpo:\n\n"
        "* `after_ack` (por omision): se emite la nueva y la anterior se retira "
        "solo cuando el receptor confirma. Lo que se retira es el **token** "
        "anterior, por su accessor: su SecretID ya se consumio al entrar, porque "
        "es de un solo uso. Durante la ventana ese token sigue vivo, y eso evita "
        "dejar fuera al crawler que ya estaba dentro.\n"
        "* `immediate`: se retira la anterior al emitir la nueva, sin esperar. "
        "Mas estricto, con ventana de corte.\n\n"
        "En los dos casos, destruir un SecretID **no** revoca los tokens que ya "
        "salieron de el: viven hasta su TTL y se cortan por su accessor.\n\n"
        + ACCEPTED_DESCRIPTION
    ),
)
async def rotate_consumer(
    consumer_id: Annotated[uuid.UUID, Path()],
    payload: RotateIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> AcceptedOut:
    accepted = await service.request_rotation(
        principal=principal,
        consumer_id=consumer_id,
        strategy=payload.strategy,
        note=payload.note,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _accepted(response, settings, accepted)


@router.post(
    "/consumers/{consumer_id}/revoke",
    response_model=AcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bloquea entregas y revoca lo revocable (solo admin)",
    description=(
        "Hace tres cosas, en este orden: destruye los SecretID del rol, revoca "
        "por *accessor* el token que el receptor acredito, y borra el rol "
        "AppRole.\n\n"
        "Lo que **no** consigue, y conviene no confundir: borrar un rol AppRole "
        "no elimina los tokens ya emitidos (viven hasta su TTL si no se revocan "
        "por accessor) ni los secretos que el consumidor ya leyo.\n\n"
        "Si Vault no esta disponible, el consumidor queda bloqueado en el "
        "catalogo y la operacion en `needs_reconciliation`, diciendo que su "
        "AppRole sigue viva.\n\n"
        "`confirm` debe ser el nombre exacto del consumidor.\n\n" + ACCEPTED_DESCRIPTION
    ),
)
async def revoke_consumer(
    consumer_id: Annotated[uuid.UUID, Path()],
    payload: RevokeIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> AcceptedOut:
    accepted = await service.request_revocation(
        principal=principal,
        consumer_id=consumer_id,
        confirm=payload.confirm,
        reason=payload.reason,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _accepted(response, settings, accepted)
