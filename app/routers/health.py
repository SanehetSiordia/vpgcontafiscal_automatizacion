"""Salud del servicio.

* ``/health/live``  : el proceso responde. No toca PostgreSQL ni Vault.
* ``/health/ready`` : SELECT 1 autenticado, Vault inicializado y desbloqueado,
  credencial tecnica valida y administrador vinculado. Devuelve **503** mientras
  algo falte, con el detalle de que falta y sin exponer ningun secreto.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.core.readiness import ReadinessState
from app.deps import get_readiness
from app.schemas.auth import LiveOut, ReadyOut

router = APIRouter(tags=["health"])


@router.get(
    "/health/live",
    response_model=LiveOut,
    summary="El proceso esta vivo",
    description=(
        "No comprueba dependencias: responde 200 aunque Vault este sellado o "
        "PostgreSQL caido. Sirve para saber si hay que reiniciar el contenedor."
    ),
)
async def live() -> LiveOut:
    return LiveOut()


@router.get(
    "/health/ready",
    response_model=ReadyOut,
    summary="El servicio puede atender peticiones de negocio",
    responses={
        200: {"description": "Todas las comprobaciones pasan."},
        503: {
            "model": ReadyOut,
            "description": (
                "Alguna comprobacion falla. Caso habitual en local: Vault arranca "
                "sellado y el desbloqueo es manual."
            ),
        },
    },
)
async def ready(
    response: Response,
    readiness: Annotated[ReadinessState, Depends(get_readiness)],
) -> ReadyOut:
    report = readiness.report
    if not report.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadyOut(**report.as_dict())
