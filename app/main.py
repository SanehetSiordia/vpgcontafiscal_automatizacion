"""Punto de entrada de user-mgmt-service.

El ``lifespan`` distingue dos clases de fallo a proposito:

* **No se arregla solo** (falta provisionamiento): PostgreSQL responde pero no
  hay administrador de aplicacion activo con rol ``admin`` y vinculo a Vault.
  El proceso **aborta el arranque** y dice que scripts CLI hay que ejecutar.
  FastAPI no crea administradores ni ejecuta semillas, y nunca emite DDL:
  ``create_all()`` no aparece en ningun punto del servicio.

* **Puede arreglarse sin tocar nada** (Vault sellado o inaccesible): el proceso
  **arranca**, pero ``/health/ready`` y todos los endpoints de negocio devuelven
  503 hasta que la comprobacion pase. El desbloqueo sigue siendo manual: la API
  no hace unseal.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings
from app.core.database import dispose_engine, get_session_factory, init_engine
from app.core.errors import AppError, ErrorDetail
from app.core.logging import REQUEST_ID_HEADER, configure_logging, get_logger, validate_request_id
from app.core.rate_limit import SlidingWindowLimiter
from app.core.readiness import ReadinessState, StartupPreconditionError, verify_admin_anchor
from app.core.security import SessionStore
from app.core.vault import VaultClient, VaultError, VaultSealed, VaultUnavailable
from app.core.vault_kv import KvV2Client
from app.routers import auth as auth_router
from app.routers import health as health_router
from app.routers import internal as internal_router
from app.routers import users as users_router
from app.routers import vault_ops as vault_router
from app.services.auth import AuthService
from app.services.vault_gateway import VaultGatewayService
from app.services.vault_sync import VaultSyncService

logger = get_logger("app.main")

DESCRIPTION = """
Backend local de **VPG Contadores** para gestionar empleados y su vinculo con
HashiCorp Vault.

### Como autenticarse en Swagger

1. `POST /user_mgmt/v1/auth/login` con usuario y contrasena. Devuelve un
   `challenge_id`: **todavia no hay sesion**.
2. `POST /user_mgmt/v1/auth/mfa/verify` con ese `challenge_id` y el codigo TOTP
   de 6 digitos. Devuelve `api_session`.
3. Pulsa **Authorize** y pega el valor de `api_session`.

Si `/auth/login` devuelve `enrollment_id`, esa identidad todavia no tiene un
login MFA confirmado y puede pedir **su propio** URI de inscripcion en
`POST /user_mgmt/v1/auth/enrollment/totp`. Esa autorizacion es de un solo uso,
no es una sesion y no sustituye al MFA.

El identificador de sesion es opaco. El token de Vault no sale del servidor,
no se devuelve al cliente y no se guarda en PostgreSQL.

### Limitaciones de esta etapa

* Las sesiones viven **en memoria**. Reiniciar el worker las invalida todas.
  Con varios workers o replicas cada proceso tendria las suyas: ese escenario
  exige otro diseno y no se aborda aqui.
* El rate limiting tambien es en memoria y por proceso. **No** es una defensa
  contra IDOR: la autorizacion por objeto se comprueba en cada endpoint.
* Vault arranca sellado y el desbloqueo es **manual**. Mientras tanto, los
  endpoints de negocio responden 503.
"""


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)

    init_engine(settings)
    session_factory = get_session_factory()
    vault = VaultClient(settings)
    readiness = ReadinessState(settings)

    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.vault = vault
    app.state.readiness = readiness
    app.state.sessions = SessionStore(
        session_ttl_seconds=settings.session_ttl_seconds,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        max_sessions=settings.max_sessions,
        max_challenges=settings.max_challenges,
        mfa_proof_ttl_seconds=settings.mfa_proof_ttl_seconds,
        max_mfa_proofs=settings.max_mfa_proofs,
    )
    app.state.limiter = SlidingWindowLimiter()
    app.state.auth_service = AuthService(
        vault=vault,
        sessions=app.state.sessions,
        session_factory=session_factory,
        mfa_method_name=settings.vault_mfa_method_name,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
    )
    app.state.vault_sync = VaultSyncService(
        vault=vault, settings=settings, session_factory=session_factory
    )
    # Pasarela interna de la etapa 4. El cliente KV se construye por montaje y
    # el montaje sale del catalogo, nunca del cuerpo de una peticion.
    app.state.vault_gateway = VaultGatewayService(
        settings=settings,
        session_factory=session_factory,
        sessions=app.state.sessions,
        kv_factory=lambda mount: KvV2Client(
            base_url=settings.vault_addr,
            mount=mount,
            timeout_seconds=settings.vault_timeout_seconds,
        ),
    )

    # --- precondicion que NO se arregla sola --------------------------------
    try:
        await verify_admin_anchor(
            session_factory, vault, settings, check_vault_side=False
        )
    except StartupPreconditionError as exc:
        await vault.aclose()
        await dispose_engine()
        logger.error("precondicion de arranque incumplida", extra={"operation": "startup"})
        raise RuntimeError(
            "ARRANQUE ABORTADO. " + str(exc)
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # PostgreSQL no responde: no se puede afirmar que falte el administrador.
        logger.warning(
            "no se pudo comprobar la precondicion al arrancar; "
            "readiness quedara en 503 hasta lograrlo",
            extra={"operation": "startup", "status": "deferred"},
        )
        del exc

    report = await readiness.refresh(session_factory, vault)
    logger.info(
        "arranque completado",
        extra={"operation": "startup", "ready": report.ready, "detail": report.detail},
    )

    stop = asyncio.Event()

    async def _recheck() -> None:
        while not stop.is_set():
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    stop.wait(), timeout=settings.readiness_recheck_seconds
                )
            if stop.is_set():
                return
            try:
                await readiness.refresh(session_factory, vault)
                await app.state.sessions.purge()
            except Exception:  # noqa: BLE001 - un fallo aqui no tumba el servicio
                logger.warning("fallo al refrescar readiness", extra={"operation": "readiness"})

    task = asyncio.create_task(_recheck(), name="readiness-recheck")

    try:
        yield
    finally:
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        # Al cerrar se revocan los tokens de Vault que quedaban vivos.
        victims = await app.state.sessions.clear()
        for victim in victims:
            with contextlib.suppress(Exception):
                await vault.revoke_self(victim.vault_token)
        await app.state.vault_gateway.aclose()
        await vault.aclose()
        await dispose_engine()
        logger.info("cierre completado", extra={"operation": "shutdown"})


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.4.0",
        description=DESCRIPTION,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "health", "description": "Liveness y readiness."},
            {"name": "auth", "description": "Login userpass + TOTP delegado a Vault."},
            {"name": "user", "description": "CRUD de empleados y roles."},
            {"name": "vault", "description": "Provisionamiento, credenciales y MFA."},
        ],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next) -> Any:
        request_id = validate_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            logger.exception(
                "peticion fallida",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "route": request.url.path,
                    "duration_ms": duration_ms,
                    "status": 500,
                },
            )
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers[REQUEST_ID_HEADER] = request_id
        # La ruta se registra tal cual: lleva UUID, no datos personales. Los
        # cuerpos nunca se registran.
        logger.info(
            "peticion atendida",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response

    def _error_response(request: Request, exc: AppError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        body = ErrorDetail(
            code=exc.code,
            message=exc.message,
            request_id=request_id,
            context=exc.context,
        )
        headers = dict(exc.headers)
        headers[REQUEST_ID_HEADER] = request_id
        return JSONResponse(
            status_code=exc.status_code, content=body.model_dump(), headers=headers
        )

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error(
                "error de dominio",
                extra={
                    "request_id": getattr(request.state, "request_id", ""),
                    "operation": request.url.path,
                    "code": exc.code,
                    "status": exc.status_code,
                },
            )
        return _error_response(request, exc)

    @app.exception_handler(VaultError)
    async def handle_vault_error(request: Request, exc: VaultError) -> JSONResponse:
        # Un VaultError que llega hasta aqui no es un error interno nuestro: es
        # la dependencia. Sellado o inaccesible -> 503; cualquier otro -> 502.
        # El mensaje ya viene saneado por el cliente de Vault.
        if isinstance(exc, (VaultSealed, VaultUnavailable)):
            mapped = AppError(
                f"Vault no esta disponible: {exc.message}",
                status_code=503,
                code="upstream_unavailable",
            )
        else:
            mapped = AppError(
                f"Vault rechazo la operacion: {exc.message}",
                status_code=502,
                code="upstream_error",
            )
        logger.warning(
            "error de Vault",
            extra={
                "request_id": getattr(request.state, "request_id", ""),
                "route": request.url.path,
                "code": mapped.code,
            },
        )
        return _error_response(request, mapped)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Se muestran campo y motivo, nunca el valor enviado: el cuerpo puede
        # llevar una contrasena o un codigo TOTP.
        fields = [
            {
                "field": ".".join(str(p) for p in err.get("loc", ())[1:]) or "body",
                "reason": err.get("msg", "invalido"),
            }
            for err in exc.errors()
        ]
        return _error_response(
            request,
            AppError(
                "el cuerpo o los parametros no superan la validacion",
                status_code=422,
                code="validation_error",
                context={"fields": fields},
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error_response(
            request,
            AppError(
                str(exc.detail),
                status_code=exc.status_code,
                code="http_error",
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Hacia fuera, un mensaje generico con el request_id. El diagnostico
        # interno se conserva en el log, ya saneado.
        logger.exception(
            "error no controlado",
            extra={
                "request_id": getattr(request.state, "request_id", ""),
                "route": request.url.path,
            },
        )
        return _error_response(
            request,
            AppError(
                "error interno; consulta el log del servicio con este request_id",
                status_code=500,
                code="internal_error",
            ),
        )

    prefix = settings.api_prefix
    app.include_router(health_router.router)
    app.include_router(auth_router.router, prefix=prefix)
    app.include_router(users_router.router, prefix=prefix)
    app.include_router(vault_router.router, prefix=prefix)
    # Pasarela interna: fuera del OpenAPI publico y con credencial de servicio
    # propia, ademas del Bearer humano. Su acceso se restringe en el despliegue.
    app.include_router(internal_router.router)
    return app


app = create_app()
