"""Pasarela interna para vault-mgmt-service. NO forma parte del OpenAPI publico.

Se registra con ``include_in_schema=False``: no aparece en ``/openapi.json``, ni
en Swagger, ni en ReDoc, ni en la coleccion de Postman. Eso **no** es su
proteccion: la proteccion son las dos credenciales que exige. Que la red de
Docker sea interna tampoco autentica a nadie; cualquier contenedor de
``network-service`` puede resolver ``user-mgmt-service`` y llamar aqui, y por eso
hay credencial de servicio.

Contrato y permisos (resumen; el detalle esta en el README, etapa 4):

  POST {prefix}/session   -> valida las DOS credenciales y devuelve unicamente
                             principal, roles vigentes y antiguedad del MFA.
  POST {prefix}/execute   -> recibe operacion de allowlist, UUID de coleccion y
                             de registro, CAS y parametros tipados; vuelve a
                             autorizar y ejecuta KV con el token humano.

Lo que NUNCA sale de aqui: el token de Vault de la persona, su accessor, el
token de la cuenta tecnica y cualquier path de Vault construido por el llamante.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request

from app.core.config import Settings
from app.core.errors import ErrorDetail
from app.core.security import ApiSession
from app.deps import (
    current_principal,
    current_session,
    get_app_settings,
    get_vault_gateway,
    rate_limit_global,
    require_ready,
)
from app.schemas.internal import ExecuteRequest, ExecuteResponse, SessionProbeOut
from app.services.rbac import Principal
from app.services.vault_gateway import VaultGatewayService

INTERNAL_PREFIX = "/internal/v1/vault-mgmt"


async def require_internal_credential(
    request: Request,
    gateway: Annotated[VaultGatewayService, Depends(get_vault_gateway)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> None:
    """Primera compuerta: credencial de servicio, en tiempo constante.

    Se declara como dependencia del ROUTER para que corra antes que la
    resolucion de la sesion humana. Aun asi, la credencial interna no sustituye
    al Bearer: las dos son obligatorias y la siguiente dependencia lo exige.
    """
    presented = request.headers.get(settings.internal_credential_header)
    gateway.verify_internal_credential(presented)


router = APIRouter(
    prefix=INTERNAL_PREFIX,
    include_in_schema=False,
    dependencies=[
        Depends(require_internal_credential),
        Depends(require_ready),
        Depends(rate_limit_global),
    ],
    responses={
        401: {"model": ErrorDetail},
        403: {"model": ErrorDetail},
        503: {"model": ErrorDetail},
    },
)


@router.post("/session", response_model=SessionProbeOut)
async def probe_session(
    api_session: Annotated[ApiSession, Depends(current_session)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> SessionProbeOut:
    """Valida sesion, empleado y roles. Devuelve lo minimo para autorizar fuera.

    No devuelve el token de Vault ni sus politicas internas: vault-mgmt no
    necesita ninguno de los dos para decidir si muestra una pantalla, y
    cualquier operacion real vuelve a autorizarse aqui.
    """
    return SessionProbeOut(
        user_id=principal.user_id,
        username=principal.username,
        role_codes=sorted(principal.role_codes),
        entity_id=principal.entity_id,
        mfa_age_seconds=int(principal.mfa_age_seconds),
        mfa_verified_at=api_session.mfa_verified_at,
        session_expires_at=api_session.expires_at,
    )


@router.post("/execute", response_model=ExecuteResponse)
async def execute(
    payload: ExecuteRequest,
    api_session: Annotated[ApiSession, Depends(current_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    gateway: Annotated[VaultGatewayService, Depends(get_vault_gateway)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    mfa_proof: Annotated[str | None, Header(alias="X-VPG-MFA-Proof")] = None,
) -> ExecuteResponse:
    """Vuelve a autorizar y ejecuta la operacion KV con el token humano."""
    del settings  # la cabecera se declara con su alias literal, no por ajuste
    return await gateway.execute(
        request=payload,
        api_session=api_session,
        principal=principal,
        proof_id=mfa_proof,
    )
