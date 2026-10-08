"""Acceso a consumidores gestionados, entregas y cola de operaciones (4.6).

Separado de ``catalog.py`` porque es otro ciclo de vida: aqui las filas las
escribe un worker en segundo plano, no una peticion humana, y eso impone dos
cosas que el catalogo no necesita.

**Arrendamiento, no transaccion larga.** El worker reserva trabajo con
``FOR UPDATE SKIP LOCKED`` y escribe un ``leased_until``; despues **cierra
la transaccion** y recien entonces llama a Vault. Mantener la transaccion
abierta durante una llamada de red convertiria cualquier timeout de Vault en
una conexion de PostgreSQL retenida y, con suficientes, en una base inaccesible.
El arrendamiento caduca solo, asi que un worker que muera no bloquea la cola.

**Idempotencia con huella.** Una ``Idempotency-Key`` repetida con los MISMOS
parametros devuelve la operacion original; con parametros distintos es un 409.
La huella se calcula sobre parametros no sensibles (nombre, receptor, bindings):
nunca sobre valores de secretos, donde un hash de baja entropia seria un oraculo.

Ninguna funcion de este modulo escribe un SecretID, un wrapping token ni un
token de Vault. Solo accessors, estados e instantes.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError
from app.core.vault import sanitize_vault_message
from app.vault_mgmt.models.catalog import (
    ACTIVE_OPERATION_STATUSES,
    CLAIMABLE_OPERATION_STATUSES,
    CONSUMER_OPERATION_TYPES,
    LIVE_DELIVERY_STATES,
    ProvisioningDelivery,
    SecretConsumer,
    SecretOperation,
    SecretReceiver,
)
from app.vault_mgmt.repositories.catalog import Page


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# ---------------------------------------------------------------------------
# Consumidores
# ---------------------------------------------------------------------------


async def create_consumer(
    session: AsyncSession,
    *,
    name: str,
    description: str | None,
    approle_mount: str,
    approle_role_name: str,
    expected_policy: str,
    created_by: uuid.UUID | None,
) -> SecretConsumer:
    """Alta de un consumidor con entrega MEDIADA.

    Nace en ``unprovisioned``: existe en el catalogo, pero todavia no tiene
    AppRole ni credencial. Eso lo hace el worker, y hasta que el receptor
    aparezca no se emite nada.
    """
    consumer = SecretConsumer(
        name=name,
        description=description,
        approle_mount=approle_mount,
        approle_role_name=approle_role_name,
        expected_policy=expected_policy,
        state="active",
        delivery_mode="mediated",
        provisioning_state="unprovisioned",
        created_by=created_by,
    )
    session.add(consumer)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        constraint = str(exc.orig)
        if "secret_consumers_name_ux" in constraint:
            raise ConflictError(
                "ya existe un consumidor con ese nombre", code="consumer_name_taken"
            ) from exc
        if "secret_consumers_identity_ux" in constraint:
            raise ConflictError(
                "ya hay un consumidor registrado con esa identidad AppRole",
                code="consumer_identity_taken",
            ) from exc
        raise
    return consumer


async def get_consumer(
    session: AsyncSession, consumer_id: uuid.UUID
) -> SecretConsumer | None:
    return (
        await session.execute(
            select(SecretConsumer).where(SecretConsumer.consumer_id == consumer_id)
        )
    ).scalar_one_or_none()


async def require_consumer(
    session: AsyncSession, consumer_id: uuid.UUID
) -> SecretConsumer:
    consumer = await get_consumer(session, consumer_id)
    if consumer is None:
        raise NotFoundError("no existe ese consumidor", code="consumer_not_found")
    return consumer


async def get_consumer_by_name(
    session: AsyncSession, name: str
) -> SecretConsumer | None:
    return (
        await session.execute(
            select(SecretConsumer).where(SecretConsumer.name == name)
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Receptores
# ---------------------------------------------------------------------------


async def get_receiver_by_name(
    session: AsyncSession, name: str
) -> SecretReceiver | None:
    """El receptor ACTIVO con ese nombre.

    Se filtra por estado porque un nombre puede repetirse entre un receptor
    retirado y el que lo sustituye: la unicidad es parcial, para que revocar un
    consumidor no queme su nombre de receptor para siempre.
    """
    return (
        await session.execute(
            select(SecretReceiver).where(
                SecretReceiver.name == name, SecretReceiver.state == "active"
            )
        )
    ).scalar_one_or_none()


async def get_receiver_for_consumer(
    session: AsyncSession, consumer_id: uuid.UUID
) -> SecretReceiver | None:
    return (
        await session.execute(
            select(SecretReceiver).where(
                SecretReceiver.consumer_id == consumer_id,
                SecretReceiver.state == "active",
            )
        )
    ).scalar_one_or_none()


async def disable_receiver(session: AsyncSession, consumer_id: uuid.UUID) -> str | None:
    """Retira el receptor de un consumidor y LIBERA su nombre.

    No se borra la fila: las entregas ya hechas apuntan a ella y son la unica
    prueba de que se emitio algo. Pasa a 'disabled', que es lo que la saca de
    los indices unicos parciales y deja el nombre disponible otra vez.
    """
    receiver = await get_receiver_for_consumer(session, consumer_id)
    if receiver is None:
        return None
    await session.execute(
        update(SecretReceiver)
        .where(SecretReceiver.receiver_id == receiver.receiver_id)
        .values(state="disabled")
    )
    return receiver.name


async def upsert_receiver(
    session: AsyncSession,
    *,
    name: str,
    consumer_id: uuid.UUID,
    credential_ref: str,
    description: str | None,
    created_by: uuid.UUID | None,
) -> SecretReceiver:
    """Registra el receptor y su REFERENCIA de credencial (no la credencial).

    El indice ``secret_receivers_consumer_ux`` impide que un consumidor tenga
    dos receptores, y ``secret_receivers_name_ux`` que un nombre sirva a dos
    consumidores: sin eso, una credencial no determinaria que emision reclamar.
    """
    receiver = SecretReceiver(
        name=name,
        consumer_id=consumer_id,
        credential_ref=credential_ref,
        state="active",
        description=description,
        created_by=created_by,
    )
    session.add(receiver)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        constraint = str(exc.orig)
        if "secret_receivers_name_active_ux" in constraint:
            raise ConflictError(
                "ese receptor ya sirve a otro consumidor: una credencial de "
                "receptor pertenece a un solo consumidor",
                code="receiver_taken",
            ) from exc
        if "secret_receivers_consumer_active_ux" in constraint:
            raise ConflictError(
                "ese consumidor ya tiene un receptor asignado",
                code="consumer_receiver_taken",
            ) from exc
        raise
    return receiver


async def resolve_consumer_for_receiver(
    session: AsyncSession, receiver_name: str
) -> tuple[SecretReceiver, SecretConsumer] | None:
    """Resuelve (receptor, consumidor) desde el NOMBRE del receptor.

    El nombre llega de la credencial presentada, no del cuerpo: aceptar un
    ``consumer_id`` del cliente permitiria a un receptor pedir la credencial de
    otro.
    """
    row = (
        await session.execute(
            select(SecretReceiver, SecretConsumer)
            .join(
                SecretConsumer,
                SecretConsumer.consumer_id == SecretReceiver.consumer_id,
            )
            .where(
                SecretReceiver.name == receiver_name,
                SecretReceiver.state == "active",
            )
        )
    ).first()
    if row is None:
        return None
    return row[0], row[1]


async def touch_receiver(session: AsyncSession, receiver_id: uuid.UUID) -> None:
    await session.execute(
        update(SecretReceiver)
        .where(SecretReceiver.receiver_id == receiver_id)
        .values(last_claim_at=utc_now())
    )


async def list_consumers(
    session: AsyncSession,
    *,
    state: str | None = None,
    delivery_mode: str | None = None,
    limit: int,
    offset: int,
) -> Page:
    """Pagina estable por ``created_at DESC, consumer_id``. Sin credenciales."""
    filters = []
    if state:
        filters.append(SecretConsumer.state == state)
    if delivery_mode:
        filters.append(SecretConsumer.delivery_mode == delivery_mode)

    total = (
        await session.execute(
            select(func.count()).select_from(SecretConsumer).where(*filters)
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(SecretConsumer)
            .where(*filters)
            .order_by(
                SecretConsumer.created_at.desc(), SecretConsumer.consumer_id.asc()
            )
            .limit(limit)
            .offset(offset)
        )
    ).scalars()
    return Page(items=list(rows), total=int(total), limit=limit, offset=offset)


async def update_consumer(
    session: AsyncSession, consumer_id: uuid.UUID, **values: Any
) -> None:
    """Actualiza campos concretos. Nunca escribe credenciales: no las hay."""
    forbidden = {"role_id", "secret_id", "token", "wrap_token"}
    if forbidden & set(values):
        raise ValueError(
            "intento de guardar una credencial en el catalogo: solo se guardan "
            "accessors"
        )
    if not values:
        return
    await session.execute(
        update(SecretConsumer)
        .where(SecretConsumer.consumer_id == consumer_id)
        .values(**values)
    )


# ---------------------------------------------------------------------------
# Operaciones de consumidor (cola del worker)
# ---------------------------------------------------------------------------


async def start_consumer_operation(
    session: AsyncSession,
    *,
    operation_type: str,
    consumer_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    actor_username: str | None,
    idempotency_key: str | None,
    request_fingerprint: str,
    status: str = "pending",
) -> tuple[SecretOperation, bool]:
    """Abre (o recupera) una operacion de consumidor.

    Devuelve ``(operacion, repetida)``. ``repetida`` es True cuando la misma
    Idempotency-Key, con los mismos parametros, ya existia: entonces no se
    vuelve a hacer nada y se devuelven los mismos identificadores.

    Con la misma clave y parametros DISTINTOS se lanza 409: reutilizar una clave
    para otra cosa es un error del cliente, no una peticion nueva.
    """
    if operation_type not in CONSUMER_OPERATION_TYPES:
        raise ValueError(f"tipo de operacion no es de consumidor: {operation_type}")

    if idempotency_key:
        existing = (
            await session.execute(
                select(SecretOperation).where(
                    SecretOperation.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            if (existing.request_fingerprint or "") != request_fingerprint:
                raise ConflictError(
                    "esa Idempotency-Key ya se uso con otros parametros. Usa una "
                    "clave nueva para una peticion distinta.",
                    code="idempotency_key_reused",
                    context={"operation_id": str(existing.operation_id)},
                )
            return existing, True

    if consumer_id is not None:
        clash = (
            await session.execute(
                select(SecretOperation.operation_id, SecretOperation.operation_type)
                .where(
                    SecretOperation.consumer_id == consumer_id,
                    SecretOperation.status.in_(
                        tuple(ACTIVE_OPERATION_STATUSES) + ("needs_reconciliation",)
                    ),
                )
                .order_by(SecretOperation.created_at.asc())
                .limit(1)
            )
        ).first()
        if clash is not None:
            raise ConflictError(
                "este consumidor ya tiene una operacion viva. Consultala antes de "
                "abrir otra: dos aprovisionamientos a la vez emitirian dos "
                "credenciales y dejarian una huerfana.",
                code="operation_in_progress",
                context={"operation_id": str(clash[0]), "operation_type": clash[1]},
            )

    operation = SecretOperation(
        operation_type=operation_type,
        status=status,
        consumer_id=consumer_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint,
        phases=[],
        counters={},
        attempts=0,
    )
    session.add(operation)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        constraint = str(exc.orig)
        if "one_active_consumer" in constraint:
            raise ConflictError(
                "este consumidor ya tiene una operacion viva",
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
                if (found.request_fingerprint or "") != request_fingerprint:
                    raise ConflictError(
                        "esa Idempotency-Key ya se uso con otros parametros",
                        code="idempotency_key_reused",
                    ) from exc
                return found, True
        raise
    return operation, False


async def claim_operations(
    session: AsyncSession,
    *,
    worker_name: str,
    limit: int,
    lease_seconds: int,
    max_attempts: int,
) -> list[SecretOperation]:
    """Reserva operaciones para ESTE worker y devuelve las reservadas.

    ``FOR UPDATE SKIP LOCKED`` deja que varios workers compartan la cola sin
    pisarse y sin memoria compartida: el que llega segundo salta las filas que
    el primero esta bloqueando, en vez de esperar. Se empieza con uno, pero el
    diseno no obliga a quedarse ahi.

    Solo se toman estados en los que hay trabajo que hacer. ``waiting_receiver``
    y ``awaiting_ack`` no estan: ahi no se espera a este proceso, se espera al
    receptor.
    """
    now = utc_now()
    rows = (
        await session.execute(
            select(SecretOperation)
            .where(
                SecretOperation.operation_type.in_(tuple(CONSUMER_OPERATION_TYPES)),
                SecretOperation.status.in_(tuple(CLAIMABLE_OPERATION_STATUSES)),
                SecretOperation.attempts < max_attempts,
                (SecretOperation.leased_until.is_(None))
                | (SecretOperation.leased_until < now),
            )
            .order_by(SecretOperation.created_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).scalars()

    claimed: list[SecretOperation] = []
    deadline = now + dt.timedelta(seconds=lease_seconds)
    for operation in rows:
        operation.status = "in_progress"
        operation.lease_owner = worker_name[:120]
        operation.leased_until = deadline
        operation.attempts = int(operation.attempts or 0) + 1
        claimed.append(operation)
    return claimed


async def renew_lease(
    session: AsyncSession,
    operation_id: uuid.UUID,
    *,
    worker_name: str,
    lease_seconds: int,
) -> None:
    await session.execute(
        update(SecretOperation)
        .where(
            SecretOperation.operation_id == operation_id,
            SecretOperation.lease_owner == worker_name[:120],
        )
        .values(leased_until=utc_now() + dt.timedelta(seconds=lease_seconds))
    )


async def release_lease(session: AsyncSession, operation_id: uuid.UUID) -> None:
    await session.execute(
        update(SecretOperation)
        .where(SecretOperation.operation_id == operation_id)
        .values(lease_owner=None, leased_until=None)
    )


async def set_operation_status(
    session: AsyncSession,
    operation_id: uuid.UUID,
    *,
    status: str,
    error: str | None = None,
    clear_lease: bool = True,
) -> None:
    """Cambia el estado. ``finished_at`` solo en estados terminales.

    Lo impone tambien el CHECK de la migracion 004: un estado vivo con fecha de
    fin, o uno terminal sin ella, no entra en la base.
    """
    values: dict[str, Any] = {
        "status": status,
        "error": sanitize_vault_message(error, limit=500) if error else None,
    }
    if status in ("completed", "failed", "needs_reconciliation"):
        values["finished_at"] = utc_now()
    else:
        values["finished_at"] = None
    if clear_lease:
        values["lease_owner"] = None
        values["leased_until"] = None
    await session.execute(
        update(SecretOperation)
        .where(SecretOperation.operation_id == operation_id)
        .values(**values)
    )


async def get_operation(
    session: AsyncSession, operation_id: uuid.UUID
) -> SecretOperation | None:
    return (
        await session.execute(
            select(SecretOperation).where(SecretOperation.operation_id == operation_id)
        )
    ).scalar_one_or_none()


async def get_operation_by_idempotency(
    session: AsyncSession, idempotency_key: str
) -> SecretOperation | None:
    """Busca por Idempotency-Key. El indice unico garantiza que hay 0 o 1."""
    return (
        await session.execute(
            select(SecretOperation).where(
                SecretOperation.idempotency_key == idempotency_key
            )
        )
    ).scalar_one_or_none()


async def latest_operation_for_consumer(
    session: AsyncSession, consumer_id: uuid.UUID
) -> SecretOperation | None:
    return (
        await session.execute(
            select(SecretOperation)
            .where(SecretOperation.consumer_id == consumer_id)
            .order_by(
                SecretOperation.created_at.desc(), SecretOperation.operation_id.desc()
            )
            .limit(1)
        )
    ).scalar_one_or_none()


async def count_pending(session: AsyncSession) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(SecretOperation)
                .where(
                    SecretOperation.operation_type.in_(
                        tuple(CONSUMER_OPERATION_TYPES)
                    ),
                    SecretOperation.status.in_(tuple(CLAIMABLE_OPERATION_STATUSES)),
                )
            )
        ).scalar_one()
    )


# ---------------------------------------------------------------------------
# Entregas
# ---------------------------------------------------------------------------


async def create_delivery(
    session: AsyncSession,
    *,
    operation_id: uuid.UUID,
    consumer_id: uuid.UUID,
    receiver_id: uuid.UUID,
) -> ProvisioningDelivery:
    """Reserva una entrega. El indice parcial garantiza que solo hay una viva."""
    delivery = ProvisioningDelivery(
        operation_id=operation_id,
        consumer_id=consumer_id,
        receiver_id=receiver_id,
        state="reserved",
        attempts=1,
        claimed_at=utc_now(),
    )
    session.add(delivery)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if "one_live" in str(exc.orig):
            raise ConflictError(
                "ya hay una entrega viva para este consumidor",
                code="delivery_in_progress",
            ) from exc
        raise
    return delivery


async def live_delivery(
    session: AsyncSession, consumer_id: uuid.UUID
) -> ProvisioningDelivery | None:
    return (
        await session.execute(
            select(ProvisioningDelivery)
            .where(
                ProvisioningDelivery.consumer_id == consumer_id,
                ProvisioningDelivery.state.in_(tuple(LIVE_DELIVERY_STATES)),
            )
            .order_by(ProvisioningDelivery.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def get_delivery(
    session: AsyncSession, delivery_id: uuid.UUID
) -> ProvisioningDelivery | None:
    return (
        await session.execute(
            select(ProvisioningDelivery).where(
                ProvisioningDelivery.delivery_id == delivery_id
            )
        )
    ).scalar_one_or_none()


async def update_delivery(
    session: AsyncSession, delivery_id: uuid.UUID, **values: Any
) -> None:
    forbidden = {"secret_id", "wrap_token", "token", "role_id"}
    if forbidden & set(values):
        raise ValueError(
            "intento de guardar una credencial en una entrega: solo accessors"
        )
    if values.get("error"):
        values["error"] = sanitize_vault_message(str(values["error"]), limit=300)
    await session.execute(
        update(ProvisioningDelivery)
        .where(ProvisioningDelivery.delivery_id == delivery_id)
        .values(**values)
    )


async def expired_deliveries(
    session: AsyncSession, *, limit: int = 50
) -> list[ProvisioningDelivery]:
    """Entregas emitidas cuya envoltura ya caduco sin consumirse.

    Son el caso que obliga a reconciliar en vez de reintentar a ciegas: el
    SecretID se emitio, nadie lo desenvolvio, y sigue existiendo en Vault hasta
    que se destruye por su accessor.
    """
    rows = (
        await session.execute(
            select(ProvisioningDelivery)
            .where(
                ProvisioningDelivery.state == "delivered",
                ProvisioningDelivery.expires_at.is_not(None),
                ProvisioningDelivery.expires_at < utc_now(),
            )
            .order_by(ProvisioningDelivery.expires_at.asc())
            .limit(limit)
        )
    ).scalars()
    return list(rows)


async def list_deliveries(
    session: AsyncSession, consumer_id: uuid.UUID, *, limit: int = 20
) -> list[ProvisioningDelivery]:
    rows = (
        await session.execute(
            select(ProvisioningDelivery)
            .where(ProvisioningDelivery.consumer_id == consumer_id)
            .order_by(
                ProvisioningDelivery.created_at.desc(),
                ProvisioningDelivery.delivery_id.desc(),
            )
            .limit(limit)
        )
    ).scalars()
    return list(rows)


async def advisory_unlock_all(session: AsyncSession) -> None:
    """Libera los locks de sesion. Defensa para pruebas y cierres sucios."""
    await session.execute(text("SELECT pg_advisory_unlock_all()"))


__all__ = [
    "advisory_unlock_all",
    "disable_receiver",
    "get_receiver_by_name",
    "get_receiver_for_consumer",
    "resolve_consumer_for_receiver",
    "touch_receiver",
    "upsert_receiver",
    "claim_operations",
    "count_pending",
    "create_consumer",
    "create_delivery",
    "expired_deliveries",
    "get_consumer",
    "get_consumer_by_name",
    "get_delivery",
    "get_operation",
    "get_operation_by_idempotency",
    "latest_operation_for_consumer",
    "list_consumers",
    "list_deliveries",
    "live_delivery",
    "release_lease",
    "renew_lease",
    "require_consumer",
    "set_operation_status",
    "start_consumer_operation",
    "update_consumer",
    "update_delivery",
    "utc_now",
]
