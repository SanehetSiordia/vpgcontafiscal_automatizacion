"""Auditoria append-only de accesos y cambios sobre secretos.

La cuenta de ejecucion tiene SELECT e INSERT sobre esta tabla y nada mas: la
migracion 003 le revoca UPDATE, DELETE y TRUNCATE de forma explicita. Una linea
escrita no se reescribe desde la aplicacion.

Lo que se registra: quien, que, sobre que recurso, que versiones y con que
resultado. Lo que **no** se registra nunca: valores enviados o devueltos,
tokens de sesion, tokens de Vault, wrapping tokens, pruebas de MFA ni cuerpos
de peticion. El campo ``detail`` se sanea antes de escribirse.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vault import sanitize_vault_message
from app.vault_mgmt.models.catalog import SecretAudit

ACTOR_KINDS = ("human", "machine", "cli", "service")
OUTCOMES = ("allowed", "denied", "error", "partial")


@dataclass(slots=True)
class AuditPage:
    items: list[SecretAudit]
    total: int
    limit: int
    offset: int


async def record(
    session: AsyncSession,
    *,
    actor_kind: str,
    actor_user_id: uuid.UUID | None,
    actor_label: str | None,
    action: str,
    outcome: str,
    collection_id: uuid.UUID | None = None,
    record_id: uuid.UUID | None = None,
    versions: list[int] | None = None,
    operation_id: uuid.UUID | None = None,
    request_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Inserta una linea. No lanza por un detalle largo: lo recorta."""
    session.add(
        SecretAudit(
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            actor_label=(actor_label or None),
            action=action,
            outcome=outcome,
            collection_id=collection_id,
            record_id=record_id,
            versions=list(versions) if versions else None,
            operation_id=operation_id,
            request_id=request_id,
            detail=sanitize_vault_message(detail, limit=400) if detail else None,
        )
    )
    await session.flush()


async def list_entries(
    session: AsyncSession,
    *,
    collection_id: uuid.UUID | None,
    record_id: uuid.UUID | None,
    action: str | None,
    outcome: str | None,
    limit: int,
    offset: int,
) -> AuditPage:
    """Historial paginado, orden estable y sin valores.

    Orden: ``occurred_at DESC, audit_id DESC``. El segundo criterio evita que
    dos lineas del mismo instante se intercambien entre paginas.
    """
    stmt = select(SecretAudit)
    count_stmt = select(func.count()).select_from(SecretAudit)

    filters: list[Any] = []
    if collection_id is not None:
        filters.append(SecretAudit.collection_id == collection_id)
    if record_id is not None:
        filters.append(SecretAudit.record_id == record_id)
    if action:
        filters.append(SecretAudit.action == action)
    if outcome:
        filters.append(SecretAudit.outcome == outcome)
    for condition in filters:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    stmt = (
        stmt.order_by(SecretAudit.occurred_at.desc(), SecretAudit.audit_id.desc())
        .limit(limit)
        .offset(offset)
    )
    items = list((await session.execute(stmt)).scalars().all())
    total = int((await session.execute(count_stmt)).scalar_one())
    return AuditPage(items=items, total=total, limit=limit, offset=offset)


__all__ = ["ACTOR_KINDS", "OUTCOMES", "AuditPage", "list_entries", "record"]
