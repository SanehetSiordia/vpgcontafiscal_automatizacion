"""Registro durable de operaciones Vault + PostgreSQL.

Una transaccion de PostgreSQL **no revierte Vault**. Este registro deja por
escrito que fases se completaron, para poder reconciliar a mano lo que quedo a
medias (``scripts/user_mgmt/reconcile-operations.sh``).

Dos invariantes los impone la base, no el codigo:

* ``vault_operations_idempotency_ux``: una Idempotency-Key no crea dos
  operaciones.
* ``vault_operations_one_active_ux``: como maximo una operacion viva por usuario
  objetivo, lo que serializa peticiones concurrentes sobre el mismo empleado sin
  tener que mantener abierta una transaccion durante las llamadas de red.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.core.vault import sanitize_vault_message
from app.models.employees import VaultOperation


async def start(
    session: AsyncSession,
    *,
    operation_type: str,
    target_user_id: uuid.UUID | None,
    target_username: str | None,
    actor_user_id: uuid.UUID | None,
    idempotency_key: str | None,
) -> VaultOperation:
    """Crea la operacion en estado ``in_progress``.

    Si la Idempotency-Key ya existe devuelve la operacion previa en vez de
    repetir el trabajo. Si ya hay otra operacion viva sobre el mismo usuario,
    rechaza con 409.
    """
    if idempotency_key:
        existing = (
            await session.execute(
                select(VaultOperation).where(
                    VaultOperation.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    operation = VaultOperation(
        operation_type=operation_type,
        status="in_progress",
        target_user_id=target_user_id,
        target_username=target_username,
        actor_user_id=actor_user_id,
        idempotency_key=idempotency_key,
        phases=[],
    )
    session.add(operation)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        constraint = str(getattr(exc.orig, "diag", None) and exc.orig.diag.constraint_name or "")
        if "one_active" in constraint:
            raise ConflictError(
                "ya hay una operacion en curso sobre este empleado; espera a que termine",
                code="operation_in_progress",
            ) from exc
        if "idempotency" in constraint:
            found = (
                await session.execute(
                    select(VaultOperation).where(
                        VaultOperation.idempotency_key == idempotency_key
                    )
                )
            ).scalar_one_or_none()
            if found is not None:
                return found
        raise
    return operation


def _phase(name: str, system: str, state: str, detail: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "phase": name,
        "system": system,
        "state": state,
        "at": dt.datetime.now(dt.UTC).isoformat(),
    }
    if detail:
        entry["detail"] = sanitize_vault_message(detail, limit=200)
    return entry


async def add_phase(
    session: AsyncSession,
    operation_id: uuid.UUID,
    *,
    name: str,
    system: str,
    state: str,
    detail: str | None = None,
) -> None:
    """Anade una fase. Se hace en su propia transaccion corta.

    Importante: se relee la fila antes de escribir, porque entre fases hubo
    llamadas de red y la sesion no mantuvo la transaccion abierta.
    """
    operation = (
        await session.execute(
            select(VaultOperation).where(VaultOperation.operation_id == operation_id)
        )
    ).scalar_one_or_none()
    if operation is None:
        return
    phases = list(operation.phases or [])
    phases.append(_phase(name, system, state, detail))
    await session.execute(
        update(VaultOperation)
        .where(VaultOperation.operation_id == operation_id)
        .values(phases=phases)
    )


async def finish(
    session: AsyncSession,
    operation_id: uuid.UUID,
    *,
    status: str,
    error: str | None = None,
) -> None:
    await session.execute(
        update(VaultOperation)
        .where(VaultOperation.operation_id == operation_id)
        .values(
            status=status,
            error=sanitize_vault_message(error, limit=500) if error else None,
            finished_at=dt.datetime.now(dt.UTC),
        )
    )


async def get(session: AsyncSession, operation_id: uuid.UUID) -> VaultOperation | None:
    return (
        await session.execute(
            select(VaultOperation).where(VaultOperation.operation_id == operation_id)
        )
    ).scalar_one_or_none()


async def list_needing_reconciliation(
    session: AsyncSession, *, limit: int = 100
) -> list[VaultOperation]:
    stmt = (
        select(VaultOperation)
        .where(VaultOperation.status.in_(("needs_reconciliation", "in_progress", "pending")))
        .order_by(VaultOperation.created_at.asc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())
