"""Salud de vault-mgmt-service. Sin autenticacion.

* ``/health/live``  : el proceso responde. No toca PostgreSQL, ni Vault, ni la
  pasarela.
* ``/health/ready`` : SELECT 1, catalogo migrado, Vault desbloqueado, user-mgmt
  listo y pasarela autenticada. **503** mientras algo falte, con el detalle y
  sin exponer ningun secreto.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.vault_mgmt.core.readiness import ReadinessState
from app.vault_mgmt.deps import get_readiness
from app.vault_mgmt.schemas.common import LiveOut, ReadyOut

router = APIRouter(tags=["health"])


@router.get(
    "/health/live",
    response_model=LiveOut,
    summary="El proceso esta vivo",
    description=(
        "No comprueba dependencias: responde 200 aunque Vault este sellado, la "
        "pasarela caida o el catalogo sin migrar. Sirve para decidir si hay que "
        "reiniciar el contenedor, no si puede atender negocio."
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
                "Alguna comprobacion falla. Casos habituales en local: Vault "
                "arranca sellado y el desbloqueo es manual; o falta aplicar la "
                "migracion 003; o no esta montada la credencial interna."
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
