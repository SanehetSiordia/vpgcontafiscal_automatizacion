"""DTO de la pasarela interna de user-mgmt para vault-mgmt-service.

Este contrato es **interno**: no aparece en el OpenAPI publico (los endpoints se
registran con ``include_in_schema=False``) y su acceso se restringe en el
despliegue. Se documenta aqui y en el README porque un endpoint sin documentar
es un endpoint que nadie revisa.

Dos invariantes del contrato, visibles en los tipos:

* No hay campo para una URL, un montaje, un path, una cabecera ni un endpoint de
  Vault. Solo UUID de coleccion y de registro, y una operacion de la allowlist.
  El path fisico lo resuelve la pasarela desde el catalogo compartido.
* No hay campo para un token de Vault en la respuesta. El token humano no sale
  del proceso de user-mgmt.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

# Allowlist de operaciones. Cualquier otro valor se rechaza con 422 en la
# validacion del cuerpo, antes de tocar el catalogo.
GatewayOperation = Literal[
    # lectura
    "record_read",
    "record_metadata",
    "collection_inventory",
    "capabilities",
    # escritura
    "record_create",
    "record_replace",
    "record_patch",
    "record_soft_delete",
    "versions_delete",
    "versions_undelete",
    # destructivas (exigen prueba de MFA reciente)
    "versions_destroy",
    "record_purge",
    # lotes de coleccion (una sola prueba de MFA para el conjunto cerrado)
    "collection_soft_delete_batch",
    "collection_undelete_batch",
    "collection_purge_batch",
]

DeliveryMode = Literal["wrapped", "plain"]


class SessionProbeOut(BaseModel):
    """Lo UNICO que devuelve ``/internal/v1/vault-mgmt/session``.

    Ni token de Vault, ni accessor, ni politicas internas del servicio: solo
    quien es, que roles tiene ahora mismo y que antiguedad tiene su MFA.
    """

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "6f1c0a52-6b1e-4a6f-9c6f-2b0d9a7e4c31",
                "username": "ada.admin",
                "role_codes": ["admin"],
                "entity_id": "9a7e4c31-6b1e-4a6f-9c6f-2b0d6f1c0a52",
                "mfa_age_seconds": 42,
                "mfa_verified_at": "2026-10-05T12:00:00+00:00",
                "session_expires_at": "2026-10-05T13:00:00+00:00",
            }
        }
    }

    user_id: uuid.UUID
    username: str
    role_codes: list[str] = Field(description="Roles VIGENTES, releidos de PostgreSQL.")
    entity_id: str
    mfa_age_seconds: int
    mfa_verified_at: dt.datetime
    session_expires_at: dt.datetime


class ExecuteRequest(BaseModel):
    """Peticion de ejecucion. Tipada por operacion, sin paths libres."""

    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "operation": "record_replace",
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": "8c90-1b5e-4a90-9f4c-3f2a7c182d44",
                "expected_version": 2,
                "values": {"usuario": "demo", "password": "valor-ficticio"},
            }
        },
    }

    operation: GatewayOperation
    collection_id: uuid.UUID
    record_id: uuid.UUID | None = None
    # Conjunto cerrado de registros para un lote. Lo acota el servicio.
    record_ids: list[uuid.UUID] = Field(default_factory=list)
    # CAS: 0 para crear, la version actual esperada para reemplazar o parchear.
    expected_version: Annotated[int | None, Field(ge=0)] = None
    # Version concreta a leer. None = la ultima viva (latest).
    version: Annotated[int | None, Field(ge=1)] = None
    versions: list[Annotated[int, Field(ge=1)]] = Field(default_factory=list)
    # Objeto COMPLETO para create/replace.
    values: dict[str, Any] | None = None
    # JSON Merge Patch para patch: ausente conserva, null elimina.
    patch: dict[str, Any] | None = None
    delivery: DeliveryMode = "wrapped"
    wrap_ttl_seconds: Annotated[int | None, Field(ge=10, le=600)] = None
    # Confirmacion explicita para operaciones irreversibles. La pasarela la
    # exige ademas de la prueba de MFA.
    confirm: str | None = None
    # Identificador de la operacion durable que abrio vault-mgmt. Solo viaja
    # para que el log de los dos servicios se pueda cruzar.
    operation_id: uuid.UUID | None = None
    request_id: str | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> "ExecuteRequest":
        op = self.operation
        record_scoped = {
            "record_read",
            "record_metadata",
            "record_create",
            "record_replace",
            "record_patch",
            "record_soft_delete",
            "versions_delete",
            "versions_undelete",
            "versions_destroy",
            "record_purge",
        }
        batch_scoped = {
            "collection_soft_delete_batch",
            "collection_undelete_batch",
            "collection_purge_batch",
        }

        if op in record_scoped and self.record_id is None:
            raise ValueError(f"la operacion '{op}' necesita record_id")
        if op in batch_scoped and not self.record_ids:
            raise ValueError(f"la operacion '{op}' necesita record_ids")
        if op in ("record_create", "record_replace") and self.values is None:
            raise ValueError(f"la operacion '{op}' necesita 'values' completos")
        if op == "record_patch" and self.patch is None:
            raise ValueError("la operacion 'record_patch' necesita 'patch'")
        if op == "record_create" and self.expected_version not in (None, 0):
            raise ValueError("crear un registro exige expected_version = 0 (CAS de creacion)")
        if op in ("record_replace", "record_patch") and self.expected_version is None:
            raise ValueError(f"la operacion '{op}' exige expected_version (CAS)")
        if op in ("versions_delete", "versions_undelete", "versions_destroy") and not self.versions:
            raise ValueError(f"la operacion '{op}' necesita la lista de versiones")
        if self.values is not None and self.patch is not None:
            raise ValueError("'values' y 'patch' son excluyentes")
        return self


class RecordOutcome(BaseModel):
    """Resultado por registro dentro de un lote."""

    record_id: uuid.UUID
    status: Literal["ok", "failed", "skipped"]
    version: int | None = None
    detail: str | None = Field(
        default=None, description="Motivo ya saneado. Nunca valores del secreto."
    )


class WrappedDeliveryOut(BaseModel):
    """Entrega envuelta. El token es de un solo uso y no se registra."""

    mode: Literal["wrapped"] = "wrapped"
    token: str = Field(description="Wrapping token de Vault. Un solo uso.")
    ttl_seconds: int
    version: int
    creation_path: str | None = None
    note: str = (
        "Desenvuelvelo en Vault (sys/wrapping/unwrap). No es un JSON cifrado: "
        "al desenvolverlo el receptor autorizado ve los valores."
    )


class PlainDeliveryOut(BaseModel):
    """Entrega en claro, solo por eleccion explicita del lector autorizado."""

    mode: Literal["plain"] = "plain"
    version: int
    schema_version: int
    values: dict[str, Any]


class ExecuteResponse(BaseModel):
    """Respuesta de la pasarela. Sin tokens de Vault, sin paths de Vault."""

    operation: GatewayOperation
    collection_id: uuid.UUID
    record_id: uuid.UUID | None = None
    outcome: Literal["completed", "partial"] = "completed"
    version: int | None = None
    schema_version: int | None = None
    version_states: dict[int, str] | None = None
    metadata: dict[str, Any] | None = None
    delivery: WrappedDeliveryOut | PlainDeliveryOut | None = None
    results: list[RecordOutcome] = Field(default_factory=list)
    children: list[str] = Field(default_factory=list)
    capabilities: dict[str, list[str]] = Field(default_factory=dict)
    actor: str | None = None


class StepUpBeginRequest(BaseModel):
    """Cuerpo de ``/auth/mfa/step-up``. El usuario sale de la sesion, no de aqui."""

    model_config = {"extra": "forbid"}

    password: Annotated[str, Field(min_length=1, max_length=256)]
    operation: str = Field(
        description="Operacion que autorizara la prueba, p. ej. 'record_purge'."
    )
    collection_id: uuid.UUID | None = None
    resource_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Conjunto CERRADO de recursos. La prueba no cubre nada mas.",
    )


class StepUpVerifyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    challenge_id: Annotated[str, Field(min_length=10, max_length=128)]
    code: Annotated[str, Field(min_length=6, max_length=8, pattern=r"^[0-9]+$")]


class StepUpProofOut(BaseModel):
    """La prueba. Es una credencial de corta vida: no se registra en ningun log."""

    mfa_proof: str = Field(description="Valor para la cabecera X-VPG-MFA-Proof.")
    operation: str
    collection_id: uuid.UUID | None
    resource_ids: list[uuid.UUID]
    expires_at: dt.datetime
    single_use: bool = True
    warning: str = (
        "Un solo uso y ligada a esta sesion, a ti, a esa operacion y a esos "
        "recursos. No autoriza nada mas."
    )


__all__ = [
    "DeliveryMode",
    "ExecuteRequest",
    "ExecuteResponse",
    "GatewayOperation",
    "PlainDeliveryOut",
    "RecordOutcome",
    "SessionProbeOut",
    "StepUpBeginRequest",
    "StepUpProofOut",
    "StepUpVerifyRequest",
    "WrappedDeliveryOut",
]
