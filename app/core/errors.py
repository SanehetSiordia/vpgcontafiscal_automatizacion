"""Errores de dominio y su traduccion a respuestas HTTP.

Enmascarar no es autorizar: cuando alguien pide un recurso que existe pero no le
corresponde se devuelve **403**, no un 404 cosmetico, salvo en los casos donde
el propio enunciado pide ocultar la existencia. La autorizacion por objeto se
comprueba siempre en el servicio, nunca se deduce de que el error sea bonito.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Cuerpo de error uniforme de la API."""

    model_config = {
        "json_schema_extra": {
            "example": {
                "code": "forbidden",
                "message": "el rol 'employee' no puede modificar a otro empleado",
                "request_id": "0f9c2b8e4a7d4f1b9c3e5a6d7b8c9e01",
                "context": {},
            }
        }
    }

    code: str = Field(description="Identificador estable del error, apto para programar contra el.")
    message: str = Field(description="Explicacion breve. Nunca contiene secretos.")
    request_id: str = Field(description="Valor de X-Request-ID de esta peticion.")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Datos no sensibles de apoyo (campo invalido, operation_id...).",
    )


class AppError(Exception):
    """Error de dominio con codigo HTTP y codigo estable."""

    status_code: int = 400
    code: str = "bad_request"

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        context: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.context = context or {}
        self.headers = headers or {}


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class UnauthenticatedError(AppError):
    status_code = 401
    code = "unauthenticated"


class ForbiddenError(AppError):
    status_code = 403
    code = "forbidden"


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"


class NotReadyError(AppError):
    """503: la precondicion de arranque todavia no se ha verificado."""

    status_code = 503
    code = "not_ready"


class UpstreamUnavailableError(AppError):
    """503: Vault o PostgreSQL no responden."""

    status_code = 503
    code = "upstream_unavailable"


class PartialOperationError(AppError):
    """Vault ya cambio pero PostgreSQL no pudo reflejarlo (o al reves).

    No se devuelve 201/204: la operacion NO esta completa. El cliente recibe el
    ``operation_id`` para consultarla y reconciliarla.
    """

    status_code = 409
    code = "partial_operation"


# Respuestas reutilizables en la documentacion OpenAPI.
ERROR_RESPONSE = {"model": ErrorDetail}

COMMON_ERRORS: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorDetail, "description": "Peticion mal formada."},
    401: {"model": ErrorDetail, "description": "Falta sesion o ha caducado."},
    403: {"model": ErrorDetail, "description": "Sesion valida sin permiso sobre el recurso."},
    404: {"model": ErrorDetail, "description": "El recurso no existe."},
    409: {"model": ErrorDetail, "description": "Conflicto de estado o duplicado."},
    422: {"model": ErrorDetail, "description": "Validacion de cuerpo o parametros."},
    429: {"model": ErrorDetail, "description": "Limite de peticiones superado. Ver Retry-After."},
    503: {"model": ErrorDetail, "description": "Servicio no listo o dependencia caida."},
}

AUTH_ERRORS: dict[int | str, dict[str, Any]] = {
    k: v for k, v in COMMON_ERRORS.items() if k in (400, 401, 422, 429, 503)
}
