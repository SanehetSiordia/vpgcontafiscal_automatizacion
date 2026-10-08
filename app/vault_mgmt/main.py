"""Punto de entrada de vault-mgmt-service (etapa 4).

Que hace el ``lifespan`` y, sobre todo, que **no** hace:

* Monta el motor de base de datos, el cliente de la pasarela interna y la sonda
  de Vault. Nada mas.
* **No** habilita montajes KV, no escribe politicas, no habilita autenticadores
  y no siembra datos. Eso son scripts CLI idempotentes
  (``scripts/vault_mgmt/*``), por decision explicita: un servicio que se
  autoconcede permisos al arrancar es un servicio al que no se le puede
  recortar permisos.
* **No** hace unseal: sigue siendo manual.
* **No** emite DDL: el esquema lo crea la migracion 003.
* **No** comparte estado en memoria con user-mgmt. No puede: es otro proceso.
  Las sesiones y los tokens de Vault viven en el worker de user-mgmt y se
  consultan por la pasarela interna.

Si una dependencia falta, el proceso **arranca** igualmente y responde 503 en
readiness y en los endpoints de negocio. Lo contrario dejaria sin diagnostico el
caso mas comun en local, que es Vault sellado.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import AppError, ErrorDetail
from app.core.logging import REQUEST_ID_HEADER, configure_logging, get_logger, validate_request_id
from app.core.rate_limit import SlidingWindowLimiter
from app.core.vault import VaultError, VaultSealed, VaultUnavailable
from app.core.vault_kv import KvV2Client
from app.vault_mgmt.core.approle_admin import AppRoleAdminClient
from app.vault_mgmt.core.config import get_settings
from app.vault_mgmt.core.database import dispose_engine, get_session_factory, init_engine
from app.vault_mgmt.core.gateway_client import GatewayClient
from app.vault_mgmt.core.machine_auth import MachineAuthError, VaultProbe
from app.vault_mgmt.core.readiness import ReadinessState
from app.vault_mgmt.core.receiver_auth import ReceiverRegistry
from app.vault_mgmt.core.vault_auth import ProvisioningUnavailable, build_token_provider
from app.vault_mgmt.routers import admin as admin_router
from app.vault_mgmt.routers import collections as collections_router
from app.vault_mgmt.routers import consumers as consumers_router
from app.vault_mgmt.routers import health as health_router
from app.vault_mgmt.routers import integrations as integrations_router
from app.vault_mgmt.routers import provisioning_internal as provisioning_router
from app.vault_mgmt.routers import records as records_router
from app.vault_mgmt.services.access import AccessService
from app.vault_mgmt.services.catalog import CatalogService
from app.vault_mgmt.services.consumers import ConsumerService
from app.vault_mgmt.services.lifecycle import LifecycleService
from app.vault_mgmt.services.provisioning import ProvisioningService
from app.vault_mgmt.services.records import RecordService

logger = get_logger("app.vault_mgmt.main")

DESCRIPTION = """
API local de **VPG Contadores** para definir colecciones de secretos con campos
tipados y gestionar sus registros completos en **HashiCorp Vault KV v2**.

### Como autenticarse

Esta API **no** tiene login propio. La sesion se obtiene en `user-mgmt-service`
(puerto 8000):

1. `POST /user_mgmt/v1/auth/login` con usuario y contrasena -> `challenge_id`.
2. `POST /user_mgmt/v1/auth/mfa/verify` con el codigo TOTP -> `api_session`.
3. Pulsa **Authorize** aqui y pega ese `api_session`.

Este servicio no interpreta ese identificador: lo reenvia a la pasarela interna
de user-mgmt, que valida sesion, empleado activo, roles vigentes y ACL de Vault,
y ejecuta la operacion con el **token humano**. El token de Vault no sale de
user-mgmt y nunca llega aqui.

### Operaciones destructivas

`destroy` y `purge` exigen, a la vez: rol `admin`, confirmacion explicita en el
cuerpo y una **prueba breve de MFA reciente** que se pide en
`POST /user_mgmt/v1/auth/mfa/step-up` y se envia en `X-VPG-MFA-Proof`. La prueba
es de un solo uso y esta ligada a tu sesion, a ti, a la operacion y al conjunto
cerrado de recursos.

### Entrega de secretos

`POST .../records/{record_id}/read` entrega por defecto un **response wrapping
token** de Vault: un solo uso, TTL corto. No es un JSON cifrado y no impide que
el receptor autorizado vea los valores al desenvolverlo. La alternativa `plain`
devuelve JSON solo por eleccion explicita, con `Cache-Control: no-store`.

**SHA-256 es un hash, no cifrado reversible.** Esta API no devuelve hashes como
sustituto de las credenciales que un consumidor necesita usar.

### Limitaciones de esta etapa

* **HTTP en loopback y en la red local de pruebas no cifra el transito.** Vault
  protege el almacenamiento; HTTPS protegeria el transporte fuera de este
  entorno, y aqui no se usa.
* Las sesiones y el rate limiting viven en memoria del worker de user-mgmt y de
  este, respectivamente. Un reinicio invalida sesiones y contadores.
* Vault arranca sellado y el desbloqueo es **manual**. Mientras tanto, los
  endpoints de negocio responden 503.
* No hay transaccion distribuida entre PostgreSQL y Vault. Cuando una operacion
  queda a medias, la respuesta es 409 con `operation_id` y la operacion queda en
  `needs_reconciliation`.
* Esta etapa **no** implementa el crawler: solo su contrato de consumo.
"""


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)

    init_engine(settings)
    session_factory = get_session_factory()
    probe = VaultProbe(settings)
    gateway = GatewayClient(settings)
    readiness = ReadinessState(settings)

    def kv_factory(mount: str) -> KvV2Client:
        return KvV2Client(
            base_url=settings.vault_addr,
            mount=mount,
            timeout_seconds=settings.vault_timeout_seconds,
        )

    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.probe = probe
    app.state.gateway = gateway
    app.state.readiness = readiness
    app.state.limiter = SlidingWindowLimiter()
    app.state.catalog_service = CatalogService(
        settings=settings, session_factory=session_factory
    )
    app.state.record_service = RecordService(
        settings=settings, session_factory=session_factory, gateway=gateway
    )
    app.state.lifecycle_service = LifecycleService(
        settings=settings, session_factory=session_factory, gateway=gateway
    )
    app.state.access_service = AccessService(
        settings=settings, session_factory=session_factory, gateway=gateway
    )
    # --- Etapa 4.6: aprovisionamiento de consumidores de maquina ------------
    # El proveedor del token esta separado para poder sustituir el token local
    # por una identidad tecnica sin tocar endpoints (ver core/vault_auth.py).
    token_provider = build_token_provider(settings)
    approle = AppRoleAdminClient(settings, token_provider)
    receivers = ReceiverRegistry(settings)
    app.state.token_provider = token_provider
    app.state.approle = approle
    app.state.receivers = receivers
    app.state.provisioning_service = ProvisioningService(
        settings=settings, session_factory=session_factory, approle=approle
    )
    app.state.consumer_service = ConsumerService(
        settings=settings,
        session_factory=session_factory,
        probe=probe,
        kv_factory=kv_factory,
        token_provider=token_provider,
    )

    report = await readiness.refresh(session_factory, probe, gateway)
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
                await readiness.refresh(session_factory, probe, gateway)
            except Exception:  # noqa: BLE001 - un fallo aqui no tumba el servicio
                logger.warning(
                    "fallo al refrescar readiness", extra={"operation": "readiness"}
                )

    task = asyncio.create_task(_recheck(), name="readiness-recheck")

    try:
        yield
    finally:
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await app.state.consumer_service.aclose()
        await approle.aclose()
        await token_provider.aclose()
        await gateway.aclose()
        await probe.aclose()
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
            {
                "name": "collections",
                "description": "Catalogo de colecciones y esquemas versionados.",
            },
            {
                "name": "records",
                "description": "Registros completos, versiones y entrega.",
            },
            {
                "name": "admin",
                "description": "Capacidad efectiva, operaciones, auditoria y consumidores.",
            },
            {
                "name": "consumers",
                "description": (
                    "Consumidores de maquina: alta, aprovisionamiento, alcance, "
                    "rotacion y revocacion. Solo admin. Ninguna respuesta lleva "
                    "credenciales."
                ),
            },
            {
                "name": "integrations",
                "description": (
                    "Contrato de maquina. Autenticacion propia con token de Vault, "
                    "no con api_session."
                ),
            },
        ],
    )

    if settings.cors_allow_origins:
        # Lista explicita. Nunca '*' con credenciales: la configuracion lo
        # rechaza al arrancar.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Request-ID",
                settings.mfa_proof_header,
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
        # La ruta lleva UUID, no datos personales. Los cuerpos NUNCA se
        # registran: ahi viajan los valores de los secretos.
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

    @app.exception_handler(MachineAuthError)
    async def handle_machine_auth(request: Request, exc: MachineAuthError) -> JSONResponse:
        return _error_response(
            request,
            AppError(
                exc.message,
                status_code=exc.status_code or 403,
                code="machine_auth_failed",
            ),
        )

    @app.exception_handler(VaultError)
    async def handle_vault_error(request: Request, exc: VaultError) -> JSONResponse:
        if isinstance(exc, ProvisioningUnavailable):
            # Falta una dependencia del aprovisionamiento (su token). Es 503,
            # no 502: no es Vault el que falla, es que no hay con que llamarlo.
            mapped = AppError(
                exc.message, status_code=503, code="provisioning_unavailable"
            )
            logger.warning(
                "aprovisionamiento no disponible",
                extra={
                    "request_id": getattr(request.state, "request_id", ""),
                    "route": request.url.path,
                },
            )
            return _error_response(request, mapped)
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
        # Campo y motivo, NUNCA el valor enviado: el cuerpo lleva secretos.
        fields = [
            {
                "field": ".".join(str(part) for part in err.get("loc", ())[1:]) or "body",
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
            AppError(str(exc.detail), status_code=exc.status_code, code="http_error"),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
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
    app.include_router(collections_router.router, prefix=prefix)
    app.include_router(records_router.router, prefix=prefix)
    app.include_router(admin_router.router, prefix=prefix)
    app.include_router(consumers_router.router, prefix=prefix)
    app.include_router(integrations_router.router, prefix=prefix)
    # Canal interno de aprovisionamiento: fuera del OpenAPI publico y con su
    # propia credencial por receptor. Comparte puerto, asi que lo que lo
    # protege es la credencial, no estar oculto en Swagger.
    app.include_router(provisioning_router.router)
    return app


app = create_app()
