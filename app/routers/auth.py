"""Autenticacion: login, verificacion MFA y cierre de sesion."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import AUTH_ERRORS, COMMON_ERRORS
from app.core.security import ApiSession
from app.deps import (
    current_session,
    get_app_settings,
    get_auth_service,
    get_db,
    rate_limit_login,
    rate_limit_mfa,
    require_ready,
)
from app.repositories import users as users_repo
from app.schemas.auth import (
    LoginChallenge,
    LoginRequest,
    MfaVerifyRequest,
    SelfEnrollmentOut,
    SelfEnrollmentRequest,
    SessionOut,
    StepUpChallengeOut,
)
from app.schemas.internal import StepUpBeginRequest, StepUpProofOut, StepUpVerifyRequest
from app.services.auth import SELF_ENROLLMENT_WARNING, AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=LoginChallenge,
    status_code=status.HTTP_200_OK,
    responses=AUTH_ERRORS,
    dependencies=[Depends(require_ready), Depends(rate_limit_login)],
    summary="Paso 1: contrasena. Devuelve un desafio MFA, NO una sesion",
    description=(
        "Envia la contrasena a `auth/{path}/login/{username}` de Vault. Con el "
        "enforcement activo Vault responde **sin token** y con un `mfa_request_id`.\n\n"
        "La respuesta **no** autentica: hay que completar `/auth/mfa/verify`. Si "
        "Vault llegara a emitir token en este paso, el login se rechaza con 403 "
        "porque significaria que el MFA no se esta exigiendo.\n\n"
        "La contrasena no se conserva ni se registra en ningun punto.\n\n"
        "**Etapa 5.1.** La respuesta anade dos campos opcionales, resueltos "
        "*despues* de que Vault acepte la contrasena: `totp_status`, el estado "
        "**historico** del enrolamiento, y `enrollment_id`, una autorizacion de "
        "un solo uso para inscribir el TOTP propio. Ninguno de los dos es una "
        "sesion ni permite omitir el MFA."
    ),
)
async def login(
    payload: LoginRequest,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> LoginChallenge:
    response.headers["Cache-Control"] = "no-store"
    outcome = await auth.begin_login(
        payload.username, payload.password.get_secret_value()
    )
    return LoginChallenge(
        challenge_id=outcome.challenge.challenge_id,
        method_name=settings.vault_mfa_method_name,
        expires_in_seconds=settings.challenge_ttl_seconds,
        message=(
            "Login incompleto: todavia no hay sesion. Envia el codigo TOTP a "
            "/auth/mfa/verify antes de que caduque el desafio."
        ),
        totp_status=outcome.totp_status,  # type: ignore[arg-type]
        enrollment_id=(
            outcome.enrollment.grant_id if outcome.enrollment is not None else None
        ),
    )


@router.post(
    "/mfa/verify",
    response_model=SessionOut,
    status_code=status.HTTP_200_OK,
    responses=AUTH_ERRORS | {403: COMMON_ERRORS[403]},
    dependencies=[Depends(require_ready), Depends(rate_limit_mfa)],
    summary="Paso 2: codigo TOTP. Devuelve la sesion API",
    description=(
        "Valida el codigo contra `sys/mfa/validate`. Antes de entregar sesion se "
        "comprueba que el `entity_id` devuelto coincide con el registrado en "
        "PostgreSQL, que el empleado esta activo y que la configuracion es la "
        "esperada.\n\n"
        "`totp_status='pending'` **no** bloquea este primer login valido: es justo "
        "aqui donde pasa a `confirmed`. Y `confirmed` **no** omite el MFA: Vault "
        "acaba de validarlo.\n\n"
        "El identificador devuelto es opaco: el token de Vault no sale del servidor."
    ),
)
async def verify_mfa(
    payload: MfaVerifyRequest,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> SessionOut:
    response.headers["Cache-Control"] = "no-store"
    api_session, roles = await auth.complete_login(payload.challenge_id, payload.code)
    return SessionOut(
        api_session=api_session.session_id,
        user_id=api_session.user_id,
        username=api_session.username,
        role_codes=list(roles),
        entity_id=api_session.entity_id,
        vault_policies=list(api_session.vault_policies),
        expires_at=api_session.expires_at,
    )


@router.post(
    "/enrollment/totp",
    response_model=SelfEnrollmentOut,
    status_code=status.HTTP_200_OK,
    responses=AUTH_ERRORS | {403: COMMON_ERRORS[403], 409: COMMON_ERRORS[409]},
    dependencies=[Depends(require_ready), Depends(rate_limit_mfa)],
    summary="Inscripcion inicial del TOTP propio, antes del primer MFA",
    description=(
        "Pensado para quien ya esta registrado en PostgreSQL y en Vault pero "
        "todavia no tiene su autenticador: devuelve el URI `otpauth://` de **su "
        "propia** entidad para que lo escanee en Google Authenticator.\n\n"
        "No hay sesion ni cuerpo con identidades: el usuario y la entidad salen "
        "del `enrollment_id` que emitio `/auth/login` tras validar la contrasena, "
        "que es de **un solo uso** y caduca con el desafio. Esta autorizacion no "
        "habilita ninguna operacion administrativa.\n\n"
        "**Nunca sustituye una semilla existente.** Si la entidad ya tiene una, "
        "Vault rechaza generar otra y la respuesta es **409**: perder el URI se "
        "resuelve con un reset explicito de MFA, no regenerando en silencio. Un "
        "`totp_status` distinto de `confirmed` **no** autoriza por si solo a "
        "generar ni a reemplazar la semilla.\n\n"
        "La sesion API sigue entregandose solo en `/auth/mfa/verify`, con el "
        "codigo validado contra Vault."
    ),
)
async def self_enroll_totp(
    payload: SelfEnrollmentRequest,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> SelfEnrollmentOut:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    username, totp_status, enrollment_uri = await auth.self_enroll_totp(
        payload.enrollment_id
    )
    return SelfEnrollmentOut(
        username=username,
        totp_status=totp_status,  # type: ignore[arg-type]
        totp_enrollment_uri=enrollment_uri,
        warning=SELF_ENROLLMENT_WARNING,
    )


@router.post(
    "/mfa/step-up",
    response_model=StepUpChallengeOut,
    responses=AUTH_ERRORS | {403: COMMON_ERRORS[403]},
    dependencies=[Depends(require_ready), Depends(rate_limit_login)],
    summary="Paso 1 de la reautenticacion para una operacion destructiva",
    description=(
        "Pide la contrasena del **titular de la sesion**. El usuario sale de la "
        "sesion, no del cuerpo: no se puede reautenticar a nombre de otra persona.\n\n"
        "La operacion y el conjunto de recursos se fijan **aqui**, antes de pedir "
        "el codigo. La prueba que se emite despues autoriza esa operacion sobre "
        "ese conjunto cerrado y nada mas.\n\n"
        "Devuelve un `challenge_id`: **todavia no hay prueba**. Hay que completar "
        "`/auth/mfa/step-up/verify` con el codigo TOTP."
    ),
)
async def begin_step_up(
    payload: StepUpBeginRequest,
    response: Response,
    api_session: Annotated[ApiSession, Depends(current_session)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> StepUpChallengeOut:
    response.headers["Cache-Control"] = "no-store"
    challenge = await auth.begin_step_up(
        api_session=api_session,
        password=payload.password,
        operation=payload.operation,
        collection_id=payload.collection_id,
        resource_ids=tuple(payload.resource_ids),
    )
    return StepUpChallengeOut(
        challenge_id=challenge.challenge_id,
        operation=challenge.operation,
        collection_id=challenge.collection_id,
        resource_ids=list(challenge.resource_ids),
        method_name=settings.vault_mfa_method_name,
        expires_in_seconds=settings.challenge_ttl_seconds,
    )


@router.post(
    "/mfa/step-up/verify",
    response_model=StepUpProofOut,
    responses=AUTH_ERRORS | {403: COMMON_ERRORS[403]},
    dependencies=[Depends(require_ready), Depends(rate_limit_mfa)],
    summary="Paso 2 de la reautenticacion: devuelve la prueba breve de MFA",
    description=(
        "Valida el codigo contra `sys/mfa/validate` de Vault. Aqui **no** se "
        "comparan digitos ni se consultan semillas en PostgreSQL, y **no** se "
        "acepta un booleano enviado por el cliente.\n\n"
        "El token que Vault emite al validar se revoca de inmediato: la sesion ya "
        "tiene el suyo.\n\n"
        "La prueba se envia en la cabecera `X-VPG-MFA-Proof` a vault-mgmt-service. "
        "Es de **un solo uso**, caduca pronto y esta ligada a esta sesion, a ti, a "
        "la operacion y al conjunto de recursos declarados en el paso 1."
    ),
)
async def verify_step_up(
    payload: StepUpVerifyRequest,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> StepUpProofOut:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    proof = await auth.complete_step_up(payload.challenge_id, payload.code)
    return StepUpProofOut(
        mfa_proof=proof.proof_id,
        operation=proof.operation,
        collection_id=proof.collection_id,
        resource_ids=sorted(proof.resource_ids),
        expires_at=proof.expires_at,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={k: v for k, v in COMMON_ERRORS.items() if k in (401, 429, 503)},
    summary="Cierra la sesion y revoca el token de Vault",
    description=(
        "Elimina la sesion de memoria e intenta revocar el token en Vault. Si Vault "
        "no responde, la sesion deja de valer aqui pero el token seguira vivo hasta "
        "su TTL: quitarla de memoria no revoca nada por si solo. Queda constancia "
        "en el log."
    ),
)
async def logout(
    api_session: Annotated[ApiSession, Depends(current_session)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    await auth.logout(api_session.session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/me",
    response_model=dict,
    responses={k: v for k, v in COMMON_ERRORS.items() if k in (401, 429, 503)},
    summary="Datos de la sesion actual",
    description="Util en Swagger para comprobar con que rol se esta operando.",
)
async def whoami(
    api_session: Annotated[ApiSession, Depends(current_session)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    roles = await users_repo.role_codes_for(db, api_session.user_id)
    return {
        "user_id": str(api_session.user_id),
        "username": api_session.username,
        "role_codes": list(roles),
        "entity_id": api_session.entity_id,
        "vault_policies": list(api_session.vault_policies),
        "mfa_age_seconds": int(api_session.mfa_age_seconds()),
        "expires_at": api_session.expires_at.isoformat(),
    }
