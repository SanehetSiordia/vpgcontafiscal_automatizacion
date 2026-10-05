"""DTO comunes: salud, paginacion y piezas compartidas.

Reglas que se ven en los tipos:

* Los UUID van en el path; los nombres logicos, los valores y los codigos TOTP
  solo en el cuerpo. Ningun secreto viaja en una URL ni en un query string.
* Ningun DTO de salida lleva tokens de sesion, tokens de Vault ni wrapping
  tokens, salvo el DTO de entrega, que es la excepcion explicita y documentada.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Rechaza campos no declarados: un campo de mas suele ser un error de uso."""

    model_config = ConfigDict(extra="forbid")


class LiveOut(BaseModel):
    status: Literal["alive"] = "alive"


class ReadyOut(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ready": False,
                "checks": {
                    "postgres_select_1": True,
                    "catalog_schema_present": True,
                    "vault_initialized": True,
                    "vault_unsealed": False,
                    "user_mgmt_ready": False,
                    "internal_gateway_authenticated": True,
                },
                "detail": "vault: sellado ('vault operator unseal', paso manual)",
                "checked_at": "2026-10-05T10:00:00+00:00",
            }
        }
    )

    ready: bool
    checks: dict[str, bool]
    detail: str | None
    checked_at: str | None


class PageMeta(BaseModel):
    """Metadatos de paginacion del CATALOGO en PostgreSQL.

    El ``LIST`` de Vault no tiene paginacion nativa y aqui no se le atribuye:
    estos numeros salen de consultas SQL con ``LIMIT``/``OFFSET`` y ``COUNT``, y
    el total es el del catalogo **visible** para quien pregunta.
    """

    limit: int
    offset: int
    total: int = Field(description="Total del catalogo visible, no el absoluto.")
    returned: int


PaginationLimit = Annotated[
    int,
    Field(default=20, ge=1, le=100, description="Elementos por pagina (1-100)."),
]
PaginationOffset = Annotated[
    int, Field(default=0, ge=0, description="Desplazamiento desde el inicio.")
]


class OperationRef(BaseModel):
    """Referencia a una operacion durable. Se devuelve cuando algo queda a medias."""

    operation_id: uuid.UUID
    status: str
    hint: str = (
        "Consulta GET /vault_mgmt/v1/vault/operations/{operation_id} para ver "
        "las fases completadas antes de reintentar."
    )


class PhaseOut(BaseModel):
    phase: str
    system: Literal["postgres", "vault", "gateway"] | str
    state: str
    at: str
    detail: str | None = None


class OperationOut(BaseModel):
    """Estado de una operacion. El error viene ya saneado."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
                "operation_type": "record_replace",
                "status": "needs_reconciliation",
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                "actor_username": "ada.admin",
                "expected_version": 2,
                "result_version": 3,
                "phases": [
                    {
                        "phase": "vault_write",
                        "system": "vault",
                        "state": "done",
                        "at": "2026-10-05T10:00:01+00:00",
                    },
                    {
                        "phase": "catalog_update",
                        "system": "postgres",
                        "state": "failed",
                        "at": "2026-10-05T10:00:02+00:00",
                        "detail": "statement timeout",
                    },
                ],
                "counters": {"inventoried": 0, "processed": 0, "failed": 0},
                "error": "la version se escribio en Vault pero el catalogo no la reflejo",
                "created_at": "2026-10-05T10:00:00+00:00",
                "finished_at": "2026-10-05T10:00:02+00:00",
            }
        },
    )

    operation_id: uuid.UUID
    operation_type: str
    status: str
    collection_id: uuid.UUID | None
    record_id: uuid.UUID | None
    actor_username: str | None
    expected_version: int | None
    result_version: int | None
    phases: list[dict[str, Any]]
    counters: dict[str, Any]
    error: str | None
    created_at: dt.datetime
    finished_at: dt.datetime | None


class AuditEntryOut(BaseModel):
    """Una linea de auditoria. Nunca contiene valores de secretos."""

    model_config = ConfigDict(from_attributes=True)

    audit_id: int
    occurred_at: dt.datetime
    actor_kind: str
    actor_label: str | None
    action: str
    collection_id: uuid.UUID | None
    record_id: uuid.UUID | None
    versions: list[int] | None
    outcome: str
    operation_id: uuid.UUID | None
    request_id: str | None
    detail: str | None


class AuditListOut(BaseModel):
    page: PageMeta
    items: list[AuditEntryOut]


__all__ = [
    "AuditEntryOut",
    "AuditListOut",
    "LiveOut",
    "OperationOut",
    "OperationRef",
    "PageMeta",
    "PaginationLimit",
    "PaginationOffset",
    "PhaseOut",
    "ReadyOut",
    "StrictModel",
]
