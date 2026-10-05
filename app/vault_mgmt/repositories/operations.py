"""Registro durable de operaciones de secretos (fases, idempotencia, estado).

Una transaccion de PostgreSQL **no revierte Vault**. Este registro deja por
escrito que fases se completaron, para poder reconciliar lo que quedo a medias
(``scripts/vault_mgmt/reconcile-operations.sh``).

Dos invariantes los impone la base, no el codigo:

* ``secret_operations_idempotency_ux``: una Idempotency-Key no crea dos
  operaciones.
* ``secret_operations_one_active_ux``: como maximo una operacion viva por
  recurso (coleccion entera o registro concreto), lo que serializa peticiones
  concurrentes sin mantener abierta una transaccion durante las llamadas de red.

Lo que NO se guarda: cuerpos, valores, parches, ni hashes de contrasenas para
comparar reintentos. Un hash de baja entropia en la base seria un oraculo.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.core.vault import sanitize_vault_message
from app.vault_mgmt.models.catalog import (
    ACTIVE_OPERATION_STATUSES,
    SecretOperation,
)


async def start(
    session: AsyncSession,
    *,
    operation_type: str,
    collection_id: uuid.UUID | None,
    record_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    actor_username: str | None,
    idempotency_key: str | None,
    expected_version: int | None = None,
) -> tuple[SecretOperation, bool]:
    """Abre la operacion en ``in_progress``.

    Devuelve ``(operacion, repetida)``. ``repetida`` es True cuando la misma
    Idempotency-Key ya habia terminado: entonces NO se vuelve a ejecutar nada.
    """
    if idempotency_key:
        existing = (
            await session.execute(
                select(SecretOperation).where(
                    SecretOperation.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, existing.status not in ACTIVE_OPERATION_STATUSES

    # Exclusiones que el indice parcial no cubre, y que se comprueban aqui
    # antes de abrir la operacion:
    #
    #   1. Una operacion sobre la coleccion entera y otra sobre uno de sus
    #      registros tienen claves distintas en el indice, pero no deben
    #      solaparse: durante la transicion las escrituras se serializan.
    #
    #   2. Una operacion en 'needs_reconciliation' NO libera el recurso. Ese
    #      estado significa que la transicion no se completo y que Vault pudo
    #      quedar distinto del catalogo. Dejar escribir encima convertiria una
    #      incoherencia conocida en varias. Se libera cuando una persona la
    #      revisa y la cierra:
    #        bash scripts/vault_mgmt/reconcile-operations.sh --close <id> --as ...
    if collection_id is not None:
        blocking = tuple(ACTIVE_OPERATION_STATUSES) + ("needs_reconciliation",)
        clash = (
            await session.execute(
                select(
                    SecretOperation.operation_id,
                    SecretOperation.operation_type,
                    SecretOperation.status,
                    SecretOperation.record_id,
                )
                .where(
                    SecretOperation.collection_id == collection_id,
                    SecretOperation.status.in_(blocking),
                )
                .order_by(SecretOperation.created_at.asc())
                .limit(50)
            )
        ).all()
        for found_id, found_type, found_status, found_record in clash:
            alcance_coleccion = found_record is None
            mismo_registro = record_id is not None and found_record == record_id
            if not (alcance_coleccion or mismo_registro):
                continue
            if found_status == "needs_reconciliation":
                raise ConflictError(
                    "este recurso tiene una operacion pendiente de reconciliar: "
                    "Vault pudo quedar distinto del catalogo. Revisala antes de "
                    "escribir encima (scripts/vault_mgmt/reconcile-operations.sh).",
                    code="reconciliation_pending",
                    context={
                        "operation_id": str(found_id),
                        "operation_type": found_type,
                    },
                )
            raise ConflictError(
                "hay una operacion en curso sobre este recurso; espera a que "
                "termine o consultala",
                code="operation_in_progress",
                context={
                    "operation_id": str(found_id),
                    "operation_type": found_type,
                },
            )

    operation = SecretOperation(
        operation_type=operation_type,
        status="in_progress",
        collection_id=collection_id,
        record_id=record_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        idempotency_key=idempotency_key,
        expected_version=expected_version,
        phases=[],
        counters={},
    )
    session.add(operation)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        constraint = str(exc.orig)
        if "one_active" in constraint:
            raise ConflictError(
                "ya hay una operacion en curso sobre este recurso",
                code="operation_in_progress",
            ) from exc
        if "idempotency" in constraint and idempotency_key:
            found = (
                await session.execute(
                    select(SecretOperation).where(
                        SecretOperation.idempotency_key == idempotency_key
                    )
                )
            ).scalar_one_or_none()
            if found is not None:
                return found, found.status not in ACTIVE_OPERATION_STATUSES
        raise
    return operation, False


def _phase(name: str, system: str, state: str, detail: str | None) -> dict[str, Any]:
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
    """Anade una fase en su propia transaccion corta.

    Se relee la fila antes de escribir: entre fases hubo llamadas de red y la
    sesion no mantuvo la transaccion abierta.
    """
    operation = (
        await session.execute(
            select(SecretOperation).where(SecretOperation.operation_id == operation_id)
        )
    ).scalar_one_or_none()
    if operation is None:
        return
    phases = list(operation.phases or [])
    phases.append(_phase(name, system, state, detail))
    await session.execute(
        update(SecretOperation)
        .where(SecretOperation.operation_id == operation_id)
        .values(phases=phases)
    )


async def set_counters(
    session: AsyncSession, operation_id: uuid.UUID, counters: dict[str, Any]
) -> None:
    await session.execute(
        update(SecretOperation)
        .where(SecretOperation.operation_id == operation_id)
        .values(counters=counters)
    )


async def finish(
    session: AsyncSession,
    operation_id: uuid.UUID,
    *,
    status: str,
    error: str | None = None,
    result_version: int | None = None,
) -> None:
    values: dict[str, Any] = {
        "status": status,
        "error": sanitize_vault_message(error, limit=500) if error else None,
        "finished_at": dt.datetime.now(dt.UTC),
    }
    if result_version is not None:
        values["result_version"] = result_version
    await session.execute(
        update(SecretOperation)
        .where(SecretOperation.operation_id == operation_id)
        .values(**values)
    )


async def get(
    session: AsyncSession, operation_id: uuid.UUID
) -> SecretOperation | None:
    return (
        await session.execute(
            select(SecretOperation).where(SecretOperation.operation_id == operation_id)
        )
    ).scalar_one_or_none()


async def active_for_collection(
    session: AsyncSession, collection_id: uuid.UUID
) -> SecretOperation | None:
    return (
        await session.execute(
            select(SecretOperation)
            .where(
                SecretOperation.collection_id == collection_id,
                SecretOperation.status.in_(tuple(ACTIVE_OPERATION_STATUSES)),
            )
            .limit(1)
        )
    ).scalar_one_or_none()


async def list_needing_reconciliation(
    session: AsyncSession, *, limit: int = 100
) -> list[SecretOperation]:
    stmt = (
        select(SecretOperation)
        .where(
            SecretOperation.status.in_(
                ("needs_reconciliation", "in_progress", "pending")
            )
        )
        .order_by(SecretOperation.created_at.asc(), SecretOperation.operation_id.asc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


async def count_by_status(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(
        select(SecretOperation.status, func.count()).group_by(SecretOperation.status)
    )
    return {str(status): int(count) for status, count in rows}


__all__ = [
    "active_for_collection",
    "add_phase",
    "count_by_status",
    "finish",
    "get",
    "list_needing_reconciliation",
    "set_counters",
    "start",
]
