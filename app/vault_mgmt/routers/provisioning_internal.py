"""Canal INTERNO de aprovisionamiento: ``claim`` y ``ack``.

Quien llama aqui es el receptor del futuro crawler, no una persona. Se autentica
con la credencial interna de **su** receptor, y el servidor resuelve desde ella
que consumidor le corresponde: el ``consumer_id`` no se acepta del cliente.

Sobre que protege a estos endpoints, sin medias verdades:

* Lo que los protege es **la credencial del receptor**, comparada en tiempo
  constante y nunca registrada.
* Estar fuera del OpenAPI publico (``include_in_schema=False``) no los vuelve
  inaccesibles: comparten el puerto de la API y responden igual si alguien
  acierta la ruta. Ocultarlos en Swagger es higiene de documentacion, no un
  control de acceso, y por eso cada peticion exige la credencial.
* El transporte es HTTP dentro de la red de Docker. La credencial autentica;
  **no cifra**. Para eso haria falta TLS, que en este entorno local no se usa.
* No se publican al host en ``compose.yaml`` y no se llega a ellos con una URL
  que suministre un cliente: la plataforma React no los conoce ni los necesita.

Una ``api_session`` humana no sirve aqui, y esta credencial no sirve en los
endpoints humanos. Son dos contratos separados, igual que en la etapa 4.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.core.errors import ErrorDetail
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.receiver_auth import ReceiverRegistry
from app.vault_mgmt.deps import (
    get_app_settings,
    get_provisioning_service,
    get_receivers,
    get_request_id,
    rate_limit_receiver,
    require_ready,
)
from app.vault_mgmt.schemas.provisioning import (
    AckIn,
    AckOut,
    ClaimIn,
    ClaimOut,
    ClaimPendingOut,
)
from app.vault_mgmt.services.provisioning import IssuedDelivery, ProvisioningService

INTERNAL_PREFIX = "/internal/v1/crawler/provisioning"


async def current_receiver(
    request: Request,
    receivers: Annotated[ReceiverRegistry, Depends(get_receivers)],
) -> str:
    """Resuelve el receptor desde su credencial. 401 si no cuadra."""
    presented = request.headers.get(receivers.header)
    return receivers.identify(presented)


router = APIRouter(
    prefix=INTERNAL_PREFIX,
    # Fuera del contrato publico: un cliente de navegador no tiene nada que
    # hacer aqui. No es lo que lo protege (ver el docstring del modulo).
    include_in_schema=False,
    dependencies=[Depends(require_ready), Depends(rate_limit_receiver)],
    responses={
        401: {"model": ErrorDetail},
        403: {"model": ErrorDetail},
        404: {"model": ErrorDetail},
        409: {"model": ErrorDetail},
        503: {"model": ErrorDetail},
    },
)


@router.post("/claim", response_model=None)
async def claim(
    payload: ClaimIn,
    response: Response,
    receiver: Annotated[str, Depends(current_receiver)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> ClaimOut | ClaimPendingOut:
    """El receptor reclama su emision.

    Dos respuestas legitimas, las dos con 200:

    * ``ClaimOut``: habia una emision esperando. Lleva ``role_id`` y el
      **wrapping token** de un solo uso. La operacion pasa a ``awaiting_ack``.
    * ``ClaimPendingOut``: todavia no hay nada (nadie lo pidio, el worker sigue
      preparando la identidad, o ya hay una envoltura entregada sin confirmar).

    No se emite una credencial nueva encima de una entrega viva: dejaria la
    anterior huerfana en Vault.
    """
    # Nunca en cache ni en un proxy: el cuerpo lleva un wrapping token.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    result = await service.claim(
        receiver_key=receiver,
        instance=payload.instance,
        wrap_ttl_seconds=payload.wrap_ttl_seconds,
        request_id=request_id,
    )
    if isinstance(result, IssuedDelivery):
        return ClaimOut(
            consumer_id=result.consumer_id,
            operation_id=result.operation_id,
            delivery_id=result.delivery_id,
            approle_mount=result.approle_mount,
            role_id=result.role_id,
            wrap_token=result.wrap_token,
            wrap_ttl_seconds=result.wrap_ttl_seconds,
            wrap_expires_at=result.wrap_expires_at,
            login_path=f"auth/{result.approle_mount}/login",
        )
    if result.retry_after_seconds:
        response.headers["Retry-After"] = str(result.retry_after_seconds)
    return ClaimPendingOut(
        status=result.status,  # type: ignore[arg-type]
        consumer_id=result.consumer_id,
        operation_id=result.operation_id,
        delivery_id=result.delivery_id,
        detail=result.detail,
        retry_after_seconds=result.retry_after_seconds,
    )


@router.post("/ack", response_model=AckOut)
async def ack(
    payload: AckIn,
    response: Response,
    receiver: Annotated[str, Depends(current_receiver)],
    service: Annotated[ProvisioningService, Depends(get_provisioning_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> AckOut:
    """Confirma la entrega acreditando el token obtenido.

    El token se **comprueba** con ``auth/token/lookup`` contra Vault y se
    verifica que su identidad es la del consumidor (montaje, rol y politica
    minima). Despues se descarta: no se guarda y no se registra. Lo que queda en
    el catalogo es su *accessor*, que permite revocarlo sin tenerlo.

    Un ``success: true`` del cliente no serviria: no prueba que se autenticara.
    """
    response.headers["Cache-Control"] = "no-store"

    result = await service.ack(
        receiver_key=receiver,
        delivery_id=payload.delivery_id,
        vault_token=payload.vault_token,
        instance=payload.instance,
        request_id=request_id,
    )
    del settings  # el TTL efectivo lo dice Vault, no la configuracion
    return AckOut(
        consumer_id=result.consumer_id,
        operation_id=result.operation_id,
        delivery_id=result.delivery_id,
        token_accessor=result.token_accessor,
        token_ttl_seconds=result.token_ttl_seconds,
        retired_previous=result.retired_previous,
    )


__all__ = ["INTERNAL_PREFIX", "router"]
