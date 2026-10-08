"""DTO de autenticacion y de las operaciones Vault.

Las contrasenas y los codigos TOTP viajan **solo en el cuerpo**, nunca en la
URL ni en parametros de consulta. Ningun DTO de salida contiene tokens.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.schemas.user import USERNAME_RE, StrictModel


class LoginRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"username": "ana.perez", "password": "<contrasena-de-vault>"}
        },
    )

    username: str = Field(description="Usuario userpass. Se normaliza a minusculas.")
    password: SecretStr = Field(
        description="Se envia a Vault y no se conserva ni se registra en ningun punto."
    )

    @field_validator("username", mode="before")
    @classmethod
    def _normalize(cls, value: object) -> object:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if not USERNAME_RE.match(lowered):
                raise ValueError("username invalido")
            return lowered
        return value


class LoginChallenge(BaseModel):
    """Respuesta del login: hay desafio MFA y **no** hay sesion todavia."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "challenge_id": "0JxS1n2mQ5s-ejemplo",
                "mfa_required": True,
                "method_name": "vpg-totp",
                "expires_in_seconds": 180,
                "message": "Login incompleto: envia el codigo TOTP a /auth/mfa/verify.",
            }
        }
    )

    challenge_id: str = Field(description="Identificador opaco. No es una sesion.")
    mfa_required: Literal[True] = True
    method_name: str
    expires_in_seconds: int
    message: str


class MfaVerifyRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"challenge_id": "0JxS1n2mQ5s-ejemplo", "code": "123456"}},
    )

    challenge_id: str = Field(min_length=8, max_length=128)
    code: str = Field(description="Codigo TOTP de 6 digitos. No se registra.")

    @field_validator("code")
    @classmethod
    def _six_digits(cls, value: str) -> str:
        cleaned = value.strip().replace(" ", "")
        if not re.fullmatch(r"\d{6}", cleaned):
            raise ValueError("el codigo TOTP debe tener exactamente 6 digitos")
        return cleaned


class SessionOut(BaseModel):
    """Sesion API. El token de Vault **no** aparece aqui ni en ningun sitio."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "api_session": "p7Qv...-identificador-opaco",
                "token_type": "Bearer",
                "user_id": "00000000-0000-4000-8000-000000000000",
                "username": "ana.perez",
                "role_codes": ["employee"],
                "entity_id": "00000000-0000-4000-8000-000000000001",
                "vault_policies": ["default", "vpg-oidc-user"],
                "expires_at": "2026-10-03T12:00:00Z",
            }
        }
    )

    api_session: str = Field(
        description="Identificador opaco. Usar como 'Authorization: Bearer <valor>'."
    )
    token_type: Literal["Bearer"] = "Bearer"
    user_id: uuid.UUID
    username: str
    role_codes: list[str]
    entity_id: str
    vault_policies: list[str]
    expires_at: dt.datetime


# ---------------------------------------------------------------------------
# Operaciones sobre Vault
# ---------------------------------------------------------------------------


class VaultProvisionRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "vault_username": "ana.perez",
                "initial_password": "<contrasena-inicial>",
                "policy": "vpg-oidc-user",
            }
        },
    )

    vault_username: str | None = Field(
        default=None,
        description="Por defecto, el username del empleado. Se normaliza a minusculas.",
    )
    initial_password: SecretStr = Field(
        description="Se envia a Vault. NO se guarda en PostgreSQL ni se registra."
    )
    policy: str | None = Field(
        default=None,
        description=(
            "Debe pertenecer a la allowlist del servicio "
            "(USER_MGMT_VAULT_ASSIGNABLE_POLICIES). No se admiten politicas arbitrarias."
        ),
    )

    @field_validator("vault_username", mode="before")
    @classmethod
    def _normalize(cls, value: object) -> object:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if not USERNAME_RE.match(lowered):
                raise ValueError("vault_username invalido")
            return lowered
        return value


class EnrollmentOut(BaseModel):
    """Respuesta de enrolamiento. Contiene el **unico** envio del URI otpauth.

    Se devuelve con ``Cache-Control: no-store``, no se registra y no vuelve a
    aparecer en ningun GET. Si se pierde, hay que hacer un reset explicito.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "operation_id": "00000000-0000-4000-8000-00000000000a",
                "user_id": "00000000-0000-4000-8000-000000000000",
                "vault_username": "ana.perez",
                "vault_entity_id": "00000000-0000-4000-8000-000000000001",
                "totp_status": "pending",
                "totp_enrollment_uri": "otpauth://totp/...",
                "warning": (
                    "Este URI se muestra UNA sola vez. Si se pierde, hace falta un "
                    "reset explicito de MFA: no se regenera en silencio."
                ),
            }
        }
    )

    operation_id: uuid.UUID
    user_id: uuid.UUID
    vault_username: str
    vault_entity_id: uuid.UUID
    totp_status: str
    totp_enrollment_uri: str | None = Field(
        default=None, description="URI otpauth://. Se entrega una sola vez."
    )
    warning: str


class CredentialsPatchRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"new_vault_username": "ana.perez.lopez", "new_password": "<nueva>"}
        },
    )

    new_vault_username: str | None = Field(default=None, description="Debe ser unico.")
    new_password: SecretStr | None = Field(
        default=None, description="Se envia a Vault. Nunca se persiste."
    )

    @field_validator("new_vault_username", mode="before")
    @classmethod
    def _normalize(cls, value: object) -> object:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if not USERNAME_RE.match(lowered):
                raise ValueError("new_vault_username invalido")
            return lowered
        return value


class MfaResetRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"confirm": "RESET", "reason": "dispositivo perdido"}
        },
    )

    confirm: Literal["RESET"] = Field(
        description="Confirmacion explicita. Destruye la semilla TOTP del empleado objetivo."
    )
    reason: str = Field(min_length=3, max_length=200, description="Queda en la auditoria.")


class OperationOut(BaseModel):
    """Estado de una operacion que toca Vault y PostgreSQL."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "operation_id": "00000000-0000-4000-8000-00000000000a",
                "operation_type": "vault_provision",
                "status": "needs_reconciliation",
                "target_user_id": "00000000-0000-4000-8000-000000000000",
                "phases": [
                    {
                        "phase": "vault_user_created",
                        "system": "vault",
                        "state": "done",
                        "at": "2026-10-03T10:00:00Z",
                    }
                ],
                "error": "postgres: no se pudo registrar el vinculo",
            }
        },
    )

    operation_id: uuid.UUID
    operation_type: str
    status: str
    target_user_id: uuid.UUID | None
    target_username: str | None
    phases: list[dict[str, Any]]
    error: str | None
    created_at: dt.datetime
    finished_at: dt.datetime | None


class AccessCheckRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"resource": "crawler_sat"}},
    )

    resource: str = Field(
        description=(
            "Nombre LOGICO de la allowlist del servicio, no una ruta de Vault. "
            "Evita convertir el endpoint en un escaner de rutas arbitrarias."
        ),
        examples=["crawler_sat"],
    )


class AccessCheckOut(BaseModel):
    """Resultado de autorizacion. **Nunca** incluye los valores del secreto."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "resource": "crawler_sat",
                "authorized": False,
                "result": "denegada_por_politica",
                "capabilities": ["deny"],
                "evaluated_with": "sesion del usuario",
            }
        }
    )

    resource: str
    authorized: bool
    result: Literal["autorizada", "autorizada_pero_sin_datos", "denegada_por_politica"]
    capabilities: list[str]
    evaluated_with: str = Field(
        default="sesion del usuario",
        description="Siempre el token humano: la credencial tecnica no suple sus permisos.",
    )


class StepUpChallengeOut(BaseModel):
    """Paso 1 de la reautenticacion. Todavia NO hay prueba de MFA."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "challenge_id": "aV9kQ2p-ejemplo",
                "mfa_required": True,
                "operation": "record_purge",
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "resource_ids": ["8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01"],
                "method_name": "vpg-totp",
                "expires_in_seconds": 180,
                "message": (
                    "Reautenticacion incompleta: envia el codigo TOTP a "
                    "/auth/mfa/step-up/verify."
                ),
            }
        }
    )

    challenge_id: str = Field(description="Identificador opaco. No es una prueba.")
    mfa_required: Literal[True] = True
    operation: str = Field(description="Operacion que autorizara la prueba resultante.")
    collection_id: uuid.UUID | None
    resource_ids: list[uuid.UUID] = Field(
        description="Conjunto cerrado de recursos. La prueba no cubrira ningun otro."
    )
    method_name: str
    expires_in_seconds: int
    message: str = (
        "Reautenticacion incompleta: envia el codigo TOTP del titular a "
        "/auth/mfa/step-up/verify antes de que caduque el desafio."
    )


class LiveOut(BaseModel):
    status: Literal["alive"] = "alive"


class ReadyOut(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ready": False,
                "checks": {
                    "postgres_select_1": True,
                    "vault_initialized": True,
                    "vault_unsealed": False,
                    "vault_technical_credential": False,
                    "admin_linked_in_postgres_and_vault": False,
                },
                "detail": "vault: sellado ('vault operator unseal', paso manual)",
                "checked_at": "2026-10-03T10:00:00Z",
            }
        }
    )

    ready: bool
    checks: dict[str, bool]
    detail: str | None
    checked_at: str | None


IdempotencyKey = Annotated[
    str | None,
    Field(
        default=None,
        max_length=128,
        description=(
            "Repetir la peticion con la misma clave devuelve la operacion original "
            "en vez de ejecutarla dos veces. No se almacena el cuerpo."
        ),
    ),
]
