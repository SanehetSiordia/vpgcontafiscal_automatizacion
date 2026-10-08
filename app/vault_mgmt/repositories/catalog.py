"""Acceso al catalogo: colecciones, esquemas, registros, consumidores y bindings.

Nada de lo que pasa por aqui es un valor de secreto. Las consultas son cortas y
nunca se mantiene una transaccion abierta mientras se llama por red: eso lo
garantizan los servicios, que abren y cierran la sesion alrededor de cada fase.

Paginacion con ``limit``/``offset`` y **orden estable** (una clave unica como
ultimo criterio, para que dos filas con la misma fecha no se intercambien entre
paginas). Esta paginacion es del catalogo en PostgreSQL: el ``LIST`` de Vault no
tiene paginacion nativa y no se le atribuye ninguna.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError
from app.vault_mgmt.models.catalog import (
    SecretCollection,
    SecretCollectionSchema,
    SecretConsumer,
    SecretConsumerBinding,
    SecretRecord,
)

# Allowlist de campos por los que se puede ordenar. El cliente no elige una
# expresion SQL: elige una etiqueta de esta tabla.
COLLECTION_SORTS: dict[str, Any] = {
    "logical_name": SecretCollection.logical_name,
    "created_at": SecretCollection.created_at,
    "updated_at": SecretCollection.updated_at,
}
RECORD_SORTS: dict[str, Any] = {
    "created_at": SecretRecord.created_at,
    "updated_at": SecretRecord.updated_at,
    "label": SecretRecord.label,
}


@dataclass(slots=True)
class Page:
    """Una pagina de resultados con el total del catalogo VISIBLE."""

    items: list[Any]
    total: int
    limit: int
    offset: int


def _stable(stmt: Select[Any], column: Any, descending: bool, tiebreak: Any) -> Select[Any]:
    primary = column.desc() if descending else column.asc()
    return stmt.order_by(primary, tiebreak.asc())


# ---------------------------------------------------------------------------
# Colecciones
# ---------------------------------------------------------------------------


async def create_collection(
    session: AsyncSession,
    *,
    logical_name: str,
    description: str | None,
    reader_role_codes: list[str],
    kv_mount: str,
    kv_prefix: str,
    created_by: uuid.UUID | None,
) -> SecretCollection:
    collection = SecretCollection(
        logical_name=logical_name,
        description=description,
        state="active",
        current_schema_version=1,
        reader_role_codes=reader_role_codes,
        kv_mount=kv_mount,
        kv_prefix=kv_prefix,
        created_by=created_by,
    )
    session.add(collection)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if "secret_collections_name_ux" in str(exc.orig):
            raise ConflictError(
                "ya existe una coleccion con ese nombre logico",
                code="collection_name_taken",
            ) from exc
        raise
    return collection


async def get_collection(
    session: AsyncSession, collection_id: uuid.UUID
) -> SecretCollection | None:
    return (
        await session.execute(
            select(SecretCollection).where(
                SecretCollection.collection_id == collection_id
            )
        )
    ).scalar_one_or_none()


async def require_collection(
    session: AsyncSession, collection_id: uuid.UUID
) -> SecretCollection:
    collection = await get_collection(session, collection_id)
    if collection is None:
        raise NotFoundError("no existe esa coleccion", code="collection_not_found")
    return collection


async def get_collection_by_name(
    session: AsyncSession, logical_name: str
) -> SecretCollection | None:
    return (
        await session.execute(
            select(SecretCollection).where(
                SecretCollection.logical_name == logical_name
            )
        )
    ).scalar_one_or_none()


async def list_collections(
    session: AsyncSession,
    *,
    role_codes: frozenset[str],
    is_admin: bool,
    state: str | None,
    name_contains: str | None,
    sort: str,
    descending: bool,
    limit: int,
    offset: int,
) -> Page:
    """Colecciones VISIBLES para quien pregunta. Sin valores, nunca.

    Un administrador ve todas; cualquier otro rol ve las que lo declaran lector.
    El total que se devuelve es el del catalogo visible, no el absoluto: decir
    "hay 40" a quien solo puede ver 3 ya es una filtracion.
    """
    stmt = select(SecretCollection)
    count_stmt = select(func.count()).select_from(SecretCollection)

    if not is_admin:
        condition = SecretCollection.reader_role_codes.overlap(list(role_codes))
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    if state:
        stmt = stmt.where(SecretCollection.state == state)
        count_stmt = count_stmt.where(SecretCollection.state == state)

    if name_contains:
        pattern = f"%{name_contains.lower()}%"
        stmt = stmt.where(SecretCollection.logical_name.like(pattern))
        count_stmt = count_stmt.where(SecretCollection.logical_name.like(pattern))

    column = COLLECTION_SORTS[sort]
    stmt = _stable(stmt, column, descending, SecretCollection.collection_id)
    stmt = stmt.limit(limit).offset(offset)

    items = list((await session.execute(stmt)).scalars().all())
    total = int((await session.execute(count_stmt)).scalar_one())
    return Page(items=items, total=total, limit=limit, offset=offset)


async def rename_collection(
    session: AsyncSession,
    collection_id: uuid.UUID,
    *,
    logical_name: str | None,
    description: str | None,
    reader_role_codes: list[str] | None,
) -> SecretCollection:
    """Cambia SOLO metadatos del catalogo.

    El ``collection_id``, el montaje y el prefijo no se tocan: por eso renombrar
    conserva el path fisico, el historial de versiones y las referencias del
    crawler. KV v2 no tiene rename nativo y aqui no se simula con copy/delete.
    """
    values: dict[str, Any] = {}
    if logical_name is not None:
        values["logical_name"] = logical_name
    if description is not None:
        values["description"] = description
    if reader_role_codes is not None:
        values["reader_role_codes"] = reader_role_codes
    if not values:
        return await require_collection(session, collection_id)

    try:
        await session.execute(
            update(SecretCollection)
            .where(SecretCollection.collection_id == collection_id)
            .values(**values)
        )
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if "secret_collections_name_ux" in str(exc.orig):
            raise ConflictError(
                "ya existe una coleccion con ese nombre logico",
                code="collection_name_taken",
            ) from exc
        raise
    session.expire_all()
    return await require_collection(session, collection_id)


async def set_collection_state(
    session: AsyncSession,
    collection_id: uuid.UUID,
    *,
    state: str,
    now: dt.datetime,
) -> None:
    values: dict[str, Any] = {"state": state}
    if state == "archived":
        values["archived_at"] = now
    elif state == "active":
        values["archived_at"] = None
    elif state == "purged":
        values["purged_at"] = now
    await session.execute(
        update(SecretCollection)
        .where(SecretCollection.collection_id == collection_id)
        .values(**values)
    )


# ---------------------------------------------------------------------------
# Esquemas versionados
# ---------------------------------------------------------------------------


async def add_schema_version(
    session: AsyncSession,
    *,
    collection_id: uuid.UUID,
    schema_version: int,
    fields: list[dict[str, Any]],
    json_schema: dict[str, Any],
    note: str | None,
    created_by: uuid.UUID | None,
) -> SecretCollectionSchema:
    row = SecretCollectionSchema(
        collection_id=collection_id,
        schema_version=schema_version,
        fields=fields,
        json_schema=json_schema,
        note=note,
        created_by=created_by,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(
            "esa version de esquema ya existe: las versiones son inmutables",
            code="schema_version_exists",
        ) from exc
    return row


async def get_schema(
    session: AsyncSession, collection_id: uuid.UUID, schema_version: int
) -> SecretCollectionSchema | None:
    return (
        await session.execute(
            select(SecretCollectionSchema).where(
                SecretCollectionSchema.collection_id == collection_id,
                SecretCollectionSchema.schema_version == schema_version,
            )
        )
    ).scalar_one_or_none()


async def require_schema(
    session: AsyncSession, collection_id: uuid.UUID, schema_version: int
) -> SecretCollectionSchema:
    row = await get_schema(session, collection_id, schema_version)
    if row is None:
        raise NotFoundError(
            f"la coleccion no tiene la version de esquema {schema_version}",
            code="schema_version_not_found",
        )
    return row


async def list_schema_versions(
    session: AsyncSession, collection_id: uuid.UUID
) -> list[SecretCollectionSchema]:
    return list(
        (
            await session.execute(
                select(SecretCollectionSchema)
                .where(SecretCollectionSchema.collection_id == collection_id)
                .order_by(SecretCollectionSchema.schema_version.asc())
            )
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# Registros
# ---------------------------------------------------------------------------


async def create_record(
    session: AsyncSession,
    *,
    record_id: uuid.UUID,
    collection_id: uuid.UUID,
    schema_version: int,
    label: str | None,
    created_by: uuid.UUID | None,
) -> SecretRecord:
    record = SecretRecord(
        record_id=record_id,
        collection_id=collection_id,
        state="active",
        current_version=0,
        schema_version=schema_version,
        label=label,
        created_by=created_by,
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if "secret_records_label_ux" in str(exc.orig):
            raise ConflictError(
                "ya hay un registro con esa etiqueta en la coleccion",
                code="record_label_taken",
            ) from exc
        raise
    return record


async def get_record(session: AsyncSession, record_id: uuid.UUID) -> SecretRecord | None:
    return (
        await session.execute(
            select(SecretRecord).where(SecretRecord.record_id == record_id)
        )
    ).scalar_one_or_none()


async def require_record(
    session: AsyncSession, collection_id: uuid.UUID, record_id: uuid.UUID
) -> SecretRecord:
    record = await get_record(session, record_id)
    if record is None or record.collection_id != collection_id:
        # No se distingue "no existe" de "existe en otra coleccion": confirmar
        # que un UUID vive en otro sitio ya seria filtrar el catalogo.
        raise NotFoundError(
            "no existe ese registro en esa coleccion", code="record_not_found"
        )
    return record


async def list_records(
    session: AsyncSession,
    *,
    collection_id: uuid.UUID,
    state: str | None,
    sort: str,
    descending: bool,
    limit: int,
    offset: int,
) -> Page:
    stmt = select(SecretRecord).where(SecretRecord.collection_id == collection_id)
    count_stmt = (
        select(func.count())
        .select_from(SecretRecord)
        .where(SecretRecord.collection_id == collection_id)
    )
    if state:
        stmt = stmt.where(SecretRecord.state == state)
        count_stmt = count_stmt.where(SecretRecord.state == state)

    column = RECORD_SORTS[sort]
    stmt = _stable(stmt, column, descending, SecretRecord.record_id).limit(limit).offset(offset)
    items = list((await session.execute(stmt)).scalars().all())
    total = int((await session.execute(count_stmt)).scalar_one())
    return Page(items=items, total=total, limit=limit, offset=offset)


async def record_ids_for_collection(
    session: AsyncSession, collection_id: uuid.UUID, *, limit: int, states: tuple[str, ...]
) -> list[SecretRecord]:
    """Inventario acotado para una operacion de coleccion."""
    stmt = (
        select(SecretRecord)
        .where(
            SecretRecord.collection_id == collection_id,
            SecretRecord.state.in_(states),
        )
        .order_by(SecretRecord.created_at.asc(), SecretRecord.record_id.asc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


async def count_records(
    session: AsyncSession, collection_id: uuid.UUID, *, states: tuple[str, ...]
) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(SecretRecord)
                .where(
                    SecretRecord.collection_id == collection_id,
                    SecretRecord.state.in_(states),
                )
            )
        ).scalar_one()
    )


async def touch_record(
    session: AsyncSession,
    record_id: uuid.UUID,
    *,
    current_version: int | None = None,
    schema_version: int | None = None,
    state: str | None = None,
    deleted_at: dt.datetime | None = None,
    clear_deleted_at: bool = False,
) -> None:
    values: dict[str, Any] = {}
    if current_version is not None:
        values["current_version"] = current_version
    if schema_version is not None:
        values["schema_version"] = schema_version
    if state is not None:
        values["state"] = state
    if deleted_at is not None:
        values["deleted_at"] = deleted_at
    if clear_deleted_at:
        values["deleted_at"] = None
    if not values:
        return
    await session.execute(
        update(SecretRecord).where(SecretRecord.record_id == record_id).values(**values)
    )


async def delete_record_row(session: AsyncSession, record_id: uuid.UUID) -> None:
    """Quita el registro del indice. Solo tras purgar sus datos en Vault."""
    await session.execute(delete(SecretRecord).where(SecretRecord.record_id == record_id))


# ---------------------------------------------------------------------------
# Consumidores y bindings
# ---------------------------------------------------------------------------


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
        raise NotFoundError(
            "no existe ese consumidor. Se registra por CLI "
            "(scripts/vault_mgmt/crawler-approle-bootstrap.sh), no desde la API",
            code="consumer_not_found",
        )
    return consumer


async def find_consumer_by_identity(
    session: AsyncSession, *, approle_mount: str, approle_role_name: str
) -> SecretConsumer | None:
    """Resuelve el consumidor desde la IDENTIDAD del token, no desde el cuerpo.

    ``secret_consumers_identity_ux`` garantiza que (montaje, rol) identifica a
    como maximo un consumidor: si hubiera dos, un token no determinaria que
    alcance de entrega le corresponde y elegir "el primero" seria darle a una
    maquina los permisos de otra.
    """
    return (
        await session.execute(
            select(SecretConsumer).where(
                SecretConsumer.approle_mount == approle_mount,
                SecretConsumer.approle_role_name == approle_role_name,
            )
        )
    ).scalar_one_or_none()


async def replace_bindings(
    session: AsyncSession,
    *,
    consumer_id: uuid.UUID,
    entries: list[tuple[uuid.UUID, uuid.UUID, int | None]],
    created_by: uuid.UUID | None,
) -> int:
    """Sustituye el conjunto de asignaciones del consumidor.

    Es un reemplazo completo (PUT): lo que no venga en la lista deja de estar
    autorizado. Revocar una asignacion impide **entregas futuras**; no caduca
    un wrapping token ya entregado ni borra lo que el consumidor ya leyo.
    """
    await session.execute(
        delete(SecretConsumerBinding).where(
            SecretConsumerBinding.consumer_id == consumer_id
        )
    )
    for collection_id, record_id, pinned_version in entries:
        session.add(
            SecretConsumerBinding(
                consumer_id=consumer_id,
                collection_id=collection_id,
                record_id=record_id,
                pinned_version=pinned_version,
                created_by=created_by,
            )
        )
    await session.flush()
    return len(entries)


async def list_bindings(
    session: AsyncSession, consumer_id: uuid.UUID
) -> list[SecretConsumerBinding]:
    return list(
        (
            await session.execute(
                select(SecretConsumerBinding)
                .where(SecretConsumerBinding.consumer_id == consumer_id)
                .order_by(
                    SecretConsumerBinding.collection_id.asc(),
                    SecretConsumerBinding.record_id.asc(),
                )
            )
        )
        .scalars()
        .all()
    )


async def get_binding(
    session: AsyncSession, *, consumer_id: uuid.UUID, record_id: uuid.UUID
) -> SecretConsumerBinding | None:
    return (
        await session.execute(
            select(SecretConsumerBinding).where(
                SecretConsumerBinding.consumer_id == consumer_id,
                SecretConsumerBinding.record_id == record_id,
            )
        )
    ).scalar_one_or_none()


__all__ = [
    "COLLECTION_SORTS",
    "Page",
    "RECORD_SORTS",
    "add_schema_version",
    "count_records",
    "create_collection",
    "create_record",
    "delete_record_row",
    "find_consumer_by_identity",
    "get_binding",
    "get_collection",
    "get_collection_by_name",
    "get_consumer",
    "get_record",
    "get_schema",
    "list_bindings",
    "list_collections",
    "list_records",
    "list_schema_versions",
    "record_ids_for_collection",
    "rename_collection",
    "replace_bindings",
    "require_collection",
    "require_consumer",
    "require_record",
    "require_schema",
    "set_collection_state",
    "touch_record",
]
