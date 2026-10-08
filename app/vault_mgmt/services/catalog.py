"""Colecciones y esquemas: catalogo puro, sin tocar Vault.

Crear una coleccion define **catalogo y esquema**. No crea ninguna carpeta en
Vault: KV v2 no tiene carpetas, y un prefijo sin claves simplemente no existe.
La primera escritura de un registro es la que crea datos.

Renombrar cambia el nombre logico y conserva ``collection_id``, path fisico,
historial de versiones y las referencias del crawler. KV v2 no ofrece rename
nativo; aqui no se simula con copy + delete, que perderia el historial y dejaria
una copia del secreto en otro path.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ConflictError, ValidationError
from app.core.logging import get_logger
from app.core.secret_schema import (
    Limits,
    SchemaDefinitionError,
    build_json_schema,
    check_compatibility,
    normalize_fields,
    sensitive_field_names,
)
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.principal import (
    HumanPrincipal,
    assert_can_read_collection,
    require_admin,
)
from app.vault_mgmt.models.catalog import SecretCollection
from app.vault_mgmt.repositories import audit as audit_repo
from app.vault_mgmt.repositories import catalog as repo
from app.vault_mgmt.repositories import operations as ops_repo

logger = get_logger(__name__)


def limits_from(settings: Settings) -> Limits:
    return Limits(
        max_fields_per_schema=settings.max_fields_per_schema,
        max_field_name_length=settings.max_field_name_length,
        max_string_value_length=settings.max_string_value_length,
        max_object_depth=settings.max_object_depth,
        max_array_items=settings.max_array_items,
        max_record_bytes=settings.max_record_bytes,
    )


class CatalogService:
    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory

    # -- creacion ------------------------------------------------------------

    async def create_collection(
        self,
        *,
        principal: HumanPrincipal,
        logical_name: str,
        description: str | None,
        reader_role_codes: list[str],
        raw_fields: list[dict[str, Any]],
        request_id: str | None,
    ) -> tuple[SecretCollection, dict[str, Any], list[dict[str, Any]], uuid.UUID]:
        require_admin(principal, "crear una coleccion de secretos")
        fields = self._normalize(raw_fields)

        async with self._session_factory() as session:
            collection = await repo.create_collection(
                session,
                logical_name=logical_name,
                description=description,
                reader_role_codes=reader_role_codes,
                kv_mount=self._settings.kv_mount,
                kv_prefix=self._settings.kv_prefix,
                created_by=principal.user_id,
            )
            json_schema = build_json_schema(
                fields,
                collection_id=collection.collection_id,
                schema_version=1,
                logical_name=logical_name,
            )
            await repo.add_schema_version(
                session,
                collection_id=collection.collection_id,
                schema_version=1,
                fields=fields,
                json_schema=json_schema,
                note="esquema inicial",
                created_by=principal.user_id,
            )
            operation, _replayed = await ops_repo.start(
                session,
                operation_type="collection_create",
                collection_id=collection.collection_id,
                record_id=None,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=None,
            )
            await ops_repo.add_phase(
                session,
                operation.operation_id,
                name="catalog_insert",
                system="postgres",
                state="done",
            )
            await ops_repo.finish(session, operation.operation_id, status="completed")
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="collection_create",
                outcome="allowed",
                collection_id=collection.collection_id,
                operation_id=operation.operation_id,
                request_id=request_id,
                detail=f"nombre logico '{logical_name}', esquema v1",
            )
            await session.commit()
            operation_id = operation.operation_id

        logger.info(
            "coleccion creada",
            extra={
                "operation": "collection_create",
                "actor": principal.username,
                "collection": str(collection.collection_id),
            },
        )
        return collection, json_schema, fields, operation_id

    # -- lectura -------------------------------------------------------------

    async def list_collections(
        self,
        *,
        principal: HumanPrincipal,
        state: str | None,
        name_contains: str | None,
        sort: str,
        descending: bool,
        limit: int,
        offset: int,
    ) -> tuple[repo.Page, dict[uuid.UUID, int]]:
        if sort not in repo.COLLECTION_SORTS:
            raise ValidationError(
                f"orden no admitido: '{sort}'",
                context={"allowed": sorted(repo.COLLECTION_SORTS)},
            )
        async with self._session_factory() as session:
            page = await repo.list_collections(
                session,
                role_codes=principal.role_codes,
                is_admin=principal.is_admin,
                state=state,
                name_contains=name_contains,
                sort=sort,
                descending=descending,
                limit=limit,
                offset=offset,
            )
            counts = {
                item.collection_id: await repo.count_records(
                    session, item.collection_id, states=("active", "soft_deleted")
                )
                for item in page.items
            }
        return page, counts

    async def get_collection(
        self, *, principal: HumanPrincipal, collection_id: uuid.UUID
    ) -> tuple[SecretCollection, int]:
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            count = await repo.count_records(
                session, collection_id, states=("active", "soft_deleted")
            )
        return collection, count

    async def get_schema(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        schema_version: int | None,
    ) -> tuple[SecretCollection, Any, list[int]]:
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            version = schema_version or collection.current_schema_version
            row = await repo.require_schema(session, collection_id, version)
            available = [
                item.schema_version
                for item in await repo.list_schema_versions(session, collection_id)
            ]
        return collection, row, available

    # -- modificacion de metadatos -------------------------------------------

    async def patch_collection(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        logical_name: str | None,
        description: str | None,
        reader_role_codes: list[str] | None,
        request_id: str | None,
    ) -> SecretCollection:
        require_admin(principal, "modificar una coleccion")

        async with self._session_factory() as session:
            before = await repo.require_collection(session, collection_id)
            if before.state == "purged":
                raise ConflictError(
                    "la coleccion esta purgada: solo queda su registro de auditoria",
                    code="collection_purged",
                )
            previous_name = before.logical_name
            collection = await repo.rename_collection(
                session,
                collection_id,
                logical_name=logical_name,
                description=description,
                reader_role_codes=reader_role_codes,
            )
            detail_parts = []
            if logical_name and logical_name != previous_name:
                detail_parts.append(f"renombrada '{previous_name}' -> '{logical_name}'")
            if reader_role_codes is not None:
                detail_parts.append("lectores actualizados")
            if description is not None:
                detail_parts.append("descripcion actualizada")

            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="collection_update",
                outcome="allowed",
                collection_id=collection_id,
                request_id=request_id,
                detail="; ".join(detail_parts) or "sin cambios",
            )
            await session.commit()

        if logical_name and logical_name != previous_name:
            logger.info(
                "coleccion renombrada; el path fisico y el historial no cambian",
                extra={
                    "operation": "collection_update",
                    "actor": principal.username,
                    "collection": str(collection_id),
                },
            )
        return collection

    # -- nueva version de esquema --------------------------------------------

    async def update_schema(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        raw_fields: list[dict[str, Any]],
        note: str | None,
        apply: bool,
        request_id: str | None,
    ) -> dict[str, Any]:
        """Crea una version nueva si es compatible con los registros existentes.

        La compatibilidad se juzga comparando la DEFINICION con la version
        vigente, no leyendo los registros: diagnosticar leyendo valores
        significaria leer todos los secretos, y el diagnostico no debe
        devolverlos.

        Un cambio incompatible responde 409 con el detalle por campo y **no**
        crea version. Reescribir en masa los registros para que encajen seria
        exactamente lo que el enunciado prohibe.
        """
        require_admin(principal, "cambiar el esquema de una coleccion")
        fields = self._normalize(raw_fields)

        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            if collection.state != "active":
                raise ConflictError(
                    f"la coleccion esta '{collection.state}': restaurala antes de "
                    "cambiar su esquema",
                    code="collection_not_active",
                )
            current = await repo.require_schema(
                session, collection_id, collection.current_schema_version
            )
            affected = await repo.count_records(
                session, collection_id, states=("active", "soft_deleted")
            )
            report = check_compatibility(list(current.fields or []), fields)

            payload: dict[str, Any] = {
                "collection_id": collection_id,
                "applied": False,
                "current_schema_version": collection.current_schema_version,
                "compatibility": {
                    **report.as_dict(),
                    "records_affected": affected,
                },
                "schema": None,
            }

            if not report.compatible:
                await audit_repo.record(
                    session,
                    actor_kind="human",
                    actor_user_id=principal.user_id,
                    actor_label=principal.username,
                    action="collection_schema_update",
                    outcome="denied",
                    collection_id=collection_id,
                    request_id=request_id,
                    detail=(
                        f"{len(report.breaking)} cambios incompatibles con "
                        f"{affected} registros"
                    ),
                )
                await session.commit()
                raise ConflictError(
                    "el esquema propuesto no es compatible con los registros "
                    "existentes. Hace falta una migracion explicita y revisada: "
                    "este servicio no reescribe registros en masa.",
                    code="schema_incompatible",
                    context=payload["compatibility"],
                )

            if not apply:
                await session.commit()
                return payload

            new_version = collection.current_schema_version + 1
            json_schema = build_json_schema(
                fields,
                collection_id=collection_id,
                schema_version=new_version,
                logical_name=collection.logical_name,
            )
            row = await repo.add_schema_version(
                session,
                collection_id=collection_id,
                schema_version=new_version,
                fields=fields,
                json_schema=json_schema,
                note=note,
                created_by=principal.user_id,
            )
            await session.execute(
                SecretCollection.__table__.update()
                .where(SecretCollection.collection_id == collection_id)
                .values(current_schema_version=new_version)
            )
            operation, _replayed = await ops_repo.start(
                session,
                operation_type="collection_schema_update",
                collection_id=collection_id,
                record_id=None,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=None,
            )
            await ops_repo.add_phase(
                session,
                operation.operation_id,
                name="schema_version_insert",
                system="postgres",
                state="done",
                detail=f"v{new_version}",
            )
            await ops_repo.finish(session, operation.operation_id, status="completed")
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="collection_schema_update",
                outcome="allowed",
                collection_id=collection_id,
                operation_id=operation.operation_id,
                request_id=request_id,
                detail=f"nueva version v{new_version}; {len(report.relaxing)} cambios seguros",
            )
            await session.commit()

            payload["applied"] = True
            payload["current_schema_version"] = new_version
            payload["schema"] = {
                "schema_version": row.schema_version,
                "fields": row.fields,
                "json_schema": row.json_schema,
                "sensitive_fields": sorted(sensitive_field_names(fields)),
                "note": row.note,
                "created_at": row.created_at,
            }
        return payload

    # -- utilidades ----------------------------------------------------------

    def _normalize(self, raw_fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            return normalize_fields(raw_fields, limits=limits_from(self._settings))
        except SchemaDefinitionError as exc:
            raise ValidationError(str(exc), code="schema_definition_invalid") from exc


__all__ = ["CatalogService", "limits_from"]
