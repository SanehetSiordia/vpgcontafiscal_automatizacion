"""Integracion de maquinas: ``/integrations/crawler/resolve``.

Contrato **distinto y separado** del humano. Aqui el ``Authorization`` lleva un
token de **Vault** que la maquina obtuvo antes con su propia AppRole de solo
lectura, no una ``api_session``. Y al reves: una ``api_session`` no sirve aqui.

Este endpoint no inicia ningun proceso de crawling, no hace peticiones a sitios
externos y no emite tokens de autenticacion nuevos.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.core.errors import COMMON_ERRORS
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.deps import (
    get_app_settings,
    get_consumer_service,
    get_request_id,
    machine_token,
    rate_limit_global,
    require_ready,
)
from app.vault_mgmt.schemas.crawler import (
    CrawlerDeliveryOut,
    CrawlerResolveIn,
    CrawlerResolveOut,
)
from app.vault_mgmt.services.consumers import ConsumerService

router = APIRouter(
    prefix="/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)


@router.post(
    "/crawler/resolve",
    response_model=CrawlerResolveOut,
    summary="Entrega envuelta de registros explicitos a una maquina autorizada",
    description=(
        "**Autenticacion de maquina.** En `Authorization: Bearer <token>` va un "
        "token de **Vault** obtenido antes con la AppRole dedicada del "
        "consumidor. No se presta aqui la `api_session` de ningun empleado.\n\n"
        "Que se valida, en este orden: `lookup-self` con ese token, que su `path` "
        "sea el login de la AppRole esperada, que su `role_name` coincida, que "
        "lleve la politica minima registrada, que siga vigente y que el "
        "consumidor tenga **binding** para cada registro pedido. El `consumer_id` "
        "**no** se acepta del cliente: se resuelve desde la identidad del token. "
        "Si la autenticacion falla, no hay vuelta a la cuenta tecnica del "
        "servicio.\n\n"
        "Se resuelve por **UUID de registro y version explicita**; nunca por "
        "usuario y contrasena, ni por un path libre, ni por una URL arbitraria.\n\n"
        "Devuelve wrapping tokens emitidos con los permisos de **esa** maquina. "
        "Son de un solo uso y con TTL corto: si uno caduca o ya se consumio, se "
        "vuelve a pedir la entrega **sin repetir la tarea**.\n\n"
        "Nunca se incluyen secretos en URL, en payloads de trabajo, en archivos "
        "exportados de Postman ni en errores."
    ),
)
async def resolve(
    payload: CrawlerResolveIn,
    response: Response,
    token: Annotated[str, Depends(machine_token)],
    service: Annotated[ConsumerService, Depends(get_consumer_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> CrawlerResolveOut:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    result = await service.resolve(
        token=token,
        requests=[
            (item.collection_id, item.record_id, item.version)
            for item in payload.records
        ],
        wrap_ttl_seconds=payload.wrap_ttl_seconds or settings.wrap_ttl_seconds,
        job_reference=payload.job_reference,
        request_id=request_id,
    )
    return CrawlerResolveOut(
        consumer=result.consumer_name,
        requested=result.requested,
        delivered=len(result.deliveries),
        deliveries=[
            CrawlerDeliveryOut(
                collection_id=item.collection_id,
                record_id=item.record_id,
                version=item.version,
                pinned=item.pinned,
                wrap_token=item.wrap_token,
                ttl_seconds=item.ttl_seconds,
                expires_at=item.expires_at,
            )
            for item in result.deliveries
        ],
        rejected=result.rejected,
    )
