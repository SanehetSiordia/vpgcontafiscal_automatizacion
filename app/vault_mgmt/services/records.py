"""Registros: crear, reemplazar, parchear, leer, borrar y operar versiones.

Un registro es **un objeto completo** de campos relacionados y vive en su propio
path de Vault, ``{prefijo}/{collection_id}/{record_id}``. Consecuencias que el
codigo respeta:

* N registros son N secretos, no N escrituras sobre la misma clave.
* Borrar un registro elimina su tupla completa. Eliminar un campo es otra
  operacion (un PATCH con ``null``) y no borra sus campos hermanos.
* CAS obligatorio: 0 para crear, la version actual esperada para reemplazar o
  parchear. Un conflicto no sobrescribe el cambio ajeno.
* PUT y PATCH crean una version NUEVA. Las anteriores no se mutan.
* Soft-delete admite undelete; ``destroy`` y el borrado de metadata no.
* Recuperar una version antigua **no** cambia por si solo cual es ``latest``.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.secret_schema import ValuesInvalid, validate_values
from app.vault_mgmt.core.principal import (
    HumanPrincipal,
    assert_can_read_collection,
    require_admin,
)
from app.vault_mgmt.models.catalog import SecretCollection, SecretRecord
from app.vault_mgmt.repositories import catalog as repo
from app.vault_mgmt.repositories import operations as ops_repo
from app.vault_mgmt.services.base import GatewayBackedService

logger = get_logger(__name__)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@dataclass(slots=True)
class WriteResult:
    record_id: uuid.UUID
    collection_id: uuid.UUID
    version: int
    schema_version: int
    operation_id: uuid.UUID
    state: str


class RecordService(GatewayBackedService):
    # -- comprobaciones compartidas -----------------------------------------

    async def _load_for_write(
        self, collection_id: uuid.UUID, principal: HumanPrincipal, action: str
    ) -> tuple[SecretCollection, dict[str, Any]]:
        require_admin(principal, action)
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            self._assert_writable(collection)
            schema = await repo.require_schema(
                session, collection_id, collection.current_schema_version
            )
            payload = {
                "schema_version": schema.schema_version,
                "fields": list(schema.fields or []),
                "json_schema": dict(schema.json_schema or {}),
            }
        return collection, payload

    def _assert_writable(self, collection: SecretCollection) -> None:
        if collection.state == "purged":
            raise ConflictError(
                "la coleccion esta purgada: sus datos se destruyeron y solo queda "
                "su registro de auditoria",
                code="collection_purged",
            )
        if collection.state == "archived":
            raise ConflictError(
                "la coleccion esta archivada: la API no da acceso ni prepara "
                "entregas nuevas. Restaurala antes de operar.",
                code="collection_archived",
            )

    def _validate_local(self, values: dict[str, Any], schema: dict[str, Any]) -> None:
        """Primera validacion, aqui. La pasarela la repite antes de escribir.

        Se valida dos veces a proposito: aqui para dar un 422 claro sin gastar
        una llamada, y alli porque la pasarela es la frontera de autorizacion y
        no da por buena la validacion de quien llama.
        """
        try:
            validate_values(
                values,
                schema["json_schema"],
                fields=schema["fields"],
                max_record_bytes=self._settings.max_record_bytes,
            )
        except ValuesInvalid as exc:
            raise ValidationError(
                "los valores no superan el esquema de la coleccion",
                context={"fields": [p.as_dict() for p in exc.problems]},
            ) from exc

    # -- crear ---------------------------------------------------------------

    async def create(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        label: str | None,
        values: dict[str, Any],
        idempotency_key: str | None,
        request_id: str | None,
    ) -> WriteResult:
        collection, schema = await self._load_for_write(
            collection_id, principal, "crear registros de secretos"
        )
        self._validate_local(values, schema)
        record_id = uuid.uuid4()

        # --- transaccion 1: indice y operacion ------------------------------
        async with self._session_factory() as session:
            operation, replayed = await ops_repo.start(
                session,
                operation_type="record_create",
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
                expected_version=0,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original "
                    "en vez de repetir la escritura",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            # El registro existe en el indice con current_version=0: indexado,
            # todavia sin datos en Vault.
            await repo.create_record(
                session,
                record_id=record_id,
                collection_id=collection_id,
                schema_version=schema["schema_version"],
                label=label,
                created_by=principal.user_id,
            )
            await ops_repo.add_phase(
                session,
                operation_id,
                name="catalog_index",
                system="postgres",
                state="done",
            )
            await session.commit()

        # --- Vault, sin transaccion abierta ---------------------------------
        try:
            result = await self._execute(
                principal=principal,
                payload={
                    "operation": "record_create",
                    "collection_id": str(collection_id),
                    "record_id": str(record_id),
                    "expected_version": 0,
                    "values": values,
                },
                proof=None,
                request_id=request_id,
                operation_id=operation_id,
                phase_name="vault_write",
            )
        except ConflictError:
            # Rechazo determinado: el indice queda sin datos y estorba. Se
            # retira para no dejar un registro fantasma en el catalogo.
            await self._drop_orphan_index(record_id)
            await self._audit(
                principal=principal,
                action="record_create",
                outcome="error",
                collection_id=collection_id,
                record_id=record_id,
                operation_id=operation_id,
                request_id=request_id,
                detail="Vault rechazo la creacion; el indice se retiro",
            )
            raise

        version = int(result.get("version") or 1)
        return await self._reflect_write(
            principal=principal,
            collection=collection,
            record_id=record_id,
            operation_id=operation_id,
            version=version,
            schema_version=int(result.get("schema_version") or schema["schema_version"]),
            action="record_create",
            request_id=request_id,
        )

    async def _drop_orphan_index(self, record_id: uuid.UUID) -> None:
        async with self._session_factory() as session:
            await repo.delete_record_row(session, record_id)
            await session.commit()

    # -- reemplazar y parchear ----------------------------------------------

    async def replace(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        expected_version: int,
        values: dict[str, Any],
        label: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> WriteResult:
        collection, schema = await self._load_for_write(
            collection_id, principal, "reemplazar registros de secretos"
        )
        self._validate_local(values, schema)

        async with self._session_factory() as session:
            record = await repo.require_record(session, collection_id, record_id)
            self._assert_record_writable(record)
            operation, replayed = await ops_repo.start(
                session,
                operation_type="record_replace",
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            await session.commit()

        result = await self._execute(
            principal=principal,
            payload={
                "operation": "record_replace",
                "collection_id": str(collection_id),
                "record_id": str(record_id),
                "expected_version": expected_version,
                "values": values,
            },
            proof=None,
            request_id=request_id,
            operation_id=operation_id,
            phase_name="vault_write",
        )
        if label is not None:
            await self._set_label(record_id, label)
        version = int(result.get("version") or expected_version + 1)
        return await self._reflect_write(
            principal=principal,
            collection=collection,
            record_id=record_id,
            operation_id=operation_id,
            version=version,
            schema_version=int(result.get("schema_version") or schema["schema_version"]),
            action="record_replace",
            request_id=request_id,
        )

    async def patch(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        expected_version: int,
        patch: dict[str, Any],
        idempotency_key: str | None,
        request_id: str | None,
    ) -> WriteResult:
        """JSON Merge Patch. El merge ocurre en la pasarela, con el token humano.

        Tiene que ser alli: mezclar exige leer los valores actuales, y este
        proceso no tiene credencial para leerlos. La pasarela lee, mezcla,
        valida el objeto RESULTANTE COMPLETO y solo entonces escribe con CAS.
        """
        collection, schema = await self._load_for_write(
            collection_id, principal, "parchear registros de secretos"
        )
        if not patch:
            raise ValidationError(
                "el parche esta vacio: no hay nada que cambiar", code="empty_patch"
            )
        self._assert_patch_keys(patch, schema)

        async with self._session_factory() as session:
            record = await repo.require_record(session, collection_id, record_id)
            self._assert_record_writable(record)
            operation, replayed = await ops_repo.start(
                session,
                operation_type="record_patch",
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            await session.commit()

        result = await self._execute(
            principal=principal,
            payload={
                "operation": "record_patch",
                "collection_id": str(collection_id),
                "record_id": str(record_id),
                "expected_version": expected_version,
                "patch": patch,
            },
            proof=None,
            request_id=request_id,
            operation_id=operation_id,
            phase_name="vault_write",
        )
        version = int(result.get("version") or expected_version + 1)
        return await self._reflect_write(
            principal=principal,
            collection=collection,
            record_id=record_id,
            operation_id=operation_id,
            version=version,
            schema_version=int(result.get("schema_version") or schema["schema_version"]),
            action="record_patch",
            request_id=request_id,
        )

    def _assert_patch_keys(self, patch: dict[str, Any], schema: dict[str, Any]) -> None:
        """Rechaza claves no declaradas antes de gastar una llamada.

        Solo mira el primer nivel: el objeto resultante completo lo valida la
        pasarela, que es la que conoce los valores actuales.
        """
        declared = {field["name"] for field in schema["fields"]}
        unknown = sorted(set(patch) - declared)
        if unknown:
            raise ValidationError(
                "el parche menciona campos no declarados en el esquema",
                context={
                    "fields": [
                        {"field": name, "reason": "no declarado en el esquema"}
                        for name in unknown
                    ]
                },
            )
        required = {
            field["name"] for field in schema["fields"] if field.get("required")
        }
        removing_required = sorted(
            name for name, value in patch.items() if value is None and name in required
        )
        if removing_required:
            # null elimina el campo. Si es obligatorio, la tupla resultante no
            # seria valida: 422 y no se escribe nada.
            raise ValidationError(
                "el parche eliminaria campos obligatorios: la tupla resultante no "
                "seria valida y no se escribe nada",
                context={
                    "fields": [
                        {"field": name, "reason": "campo obligatorio: null lo eliminaria"}
                        for name in removing_required
                    ]
                },
            )

    def _assert_record_writable(self, record: SecretRecord) -> None:
        if record.state == "destroyed":
            raise ConflictError(
                "el registro esta destruido: no se puede escribir sobre el y no se "
                "puede recuperar",
                code="record_destroyed",
            )
        if record.state == "soft_deleted":
            raise ConflictError(
                "la version actual del registro esta borrada (soft-delete): "
                "recuperala con undelete antes de escribir",
                code="record_soft_deleted",
            )

    async def _set_label(self, record_id: uuid.UUID, label: str) -> None:
        async with self._session_factory() as session:
            record = await repo.get_record(session, record_id)
            if record is not None:
                record.label = label
            await session.commit()

    async def _reflect_write(
        self,
        *,
        principal: HumanPrincipal,
        collection: SecretCollection,
        record_id: uuid.UUID,
        operation_id: uuid.UUID,
        version: int,
        schema_version: int,
        action: str,
        request_id: str | None,
    ) -> WriteResult:
        """Refleja en el catalogo lo que Vault ya hizo.

        Si esta fase falla, Vault **ya tiene** la version nueva y el catalogo no
        lo sabe: la respuesta no es 200, es 409 con el ``operation_id``.
        """
        try:
            async with self._session_factory() as session:
                await repo.touch_record(
                    session,
                    record_id,
                    current_version=version,
                    schema_version=schema_version,
                    state="active",
                    clear_deleted_at=True,
                )
                await ops_repo.add_phase(
                    session,
                    operation_id,
                    name="catalog_reflect",
                    system="postgres",
                    state="done",
                    detail=f"version {version}",
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001 - se registra y se reporta
            await self._phase(
                operation_id,
                "catalog_reflect",
                "postgres",
                "failed",
                detail=str(exc)[:200],
            )
            await self._finish(
                operation_id,
                "needs_reconciliation",
                error=(
                    f"Vault escribio la version {version} pero el catalogo no la "
                    "reflejo"
                ),
                result_version=version,
            )
            logger.error(
                "fallo parcial: Vault escribio y el catalogo no lo reflejo",
                extra={
                    "operation": action,
                    "actor": principal.username,
                    "collection": str(collection.collection_id),
                    "record": str(record_id),
                    "operation_id": str(operation_id),
                },
            )
            raise ConflictError(
                "la version se escribio en Vault pero el catalogo no pudo "
                "reflejarlo. La operacion NO esta completa: consultala y "
                "reconciliala antes de reintentar.",
                code="partial_operation",
                context={"operation_id": str(operation_id), "vault_version": version},
            ) from exc

        await self._finish(
            operation_id, "completed", result_version=version
        )
        await self._audit(
            principal=principal,
            action=action,
            outcome="allowed",
            collection_id=collection.collection_id,
            record_id=record_id,
            versions=[version],
            operation_id=operation_id,
            request_id=request_id,
            detail=f"version {version}, esquema v{schema_version}",
        )
        return WriteResult(
            record_id=record_id,
            collection_id=collection.collection_id,
            version=version,
            schema_version=schema_version,
            operation_id=operation_id,
            state="active",
        )

    # -- lectura y entrega ---------------------------------------------------

    async def read(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        version: int | None,
        delivery: str,
        wrap_ttl_seconds: int | None,
        reason: str | None,
        request_id: str | None,
    ) -> dict[str, Any]:
        """Entrega una version autorizada. Envuelta por defecto.

        El modo ``plain`` solo se sirve si el lector autorizado lo pide de forma
        explicita y la configuracion lo permite. En red local sin HTTPS no hay
        cifrado en transito: el limite esta documentado y no se disimula.
        """
        if delivery == "plain" and not self._settings.allow_plain_delivery:
            raise ConflictError(
                "la entrega en claro esta deshabilitada en este despliegue; usa "
                "la entrega envuelta",
                code="plain_delivery_disabled",
            )

        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            if collection.state != "active":
                raise ConflictError(
                    f"la coleccion esta '{collection.state}': la API no prepara "
                    "entregas nuevas",
                    code=f"collection_{collection.state}",
                )
            record = await repo.require_record(session, collection_id, record_id)
            if record.state == "destroyed":
                raise ConflictError(
                    "el registro esta destruido: su contenido no existe",
                    code="record_destroyed",
                )
            if record.state == "soft_deleted" and version is None:
                raise ConflictError(
                    "la version actual esta borrada (soft-delete). Pide una "
                    "version concreta viva o recuperala con undelete.",
                    code="record_soft_deleted",
                )
            catalog_schema_version = record.schema_version

        try:
            result = await self._execute(
                principal=principal,
                payload={
                    "operation": "record_read",
                    "collection_id": str(collection_id),
                    "record_id": str(record_id),
                    "version": version,
                    "delivery": delivery,
                    "wrap_ttl_seconds": wrap_ttl_seconds
                    or self._settings.wrap_ttl_seconds,
                },
                proof=None,
                request_id=request_id,
                operation_id=None,
                phase_name="vault_read",
            )
        except Exception:
            await self._audit(
                principal=principal,
                action="record_read",
                outcome="denied",
                collection_id=collection_id,
                record_id=record_id,
                versions=[version] if version else None,
                request_id=request_id,
                detail=f"entrega '{delivery}' no autorizada o no disponible",
            )
            raise

        await self._audit(
            principal=principal,
            action="record_read",
            outcome="allowed",
            collection_id=collection_id,
            record_id=record_id,
            versions=[int(result.get("version") or version or 0)] if (result.get("version") or version) else None,
            request_id=request_id,
            # Se registra el MODO de entrega y el motivo, nunca los valores ni
            # el wrapping token.
            detail=f"entrega '{delivery}'" + (f"; motivo: {reason}" if reason else ""),
        )
        result["catalog_schema_version"] = catalog_schema_version
        return result

    async def metadata(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        request_id: str | None,
    ) -> dict[str, Any]:
        require_admin(principal, "consultar la metadata nativa de un registro")
        async with self._session_factory() as session:
            await repo.require_collection(session, collection_id)
            record = await repo.require_record(session, collection_id, record_id)
            catalog_schema_version = record.schema_version

        result = await self._execute(
            principal=principal,
            payload={
                "operation": "record_metadata",
                "collection_id": str(collection_id),
                "record_id": str(record_id),
            },
            proof=None,
            request_id=request_id,
            operation_id=None,
            phase_name="vault_metadata",
        )
        result["catalog_schema_version"] = catalog_schema_version
        await self._audit(
            principal=principal,
            action="record_metadata",
            outcome="allowed",
            collection_id=collection_id,
            record_id=record_id,
            request_id=request_id,
            detail="metadata nativa consultada (sin valores)",
        )
        return result

    # -- borrado y versiones -------------------------------------------------

    async def soft_delete(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> uuid.UUID:
        """Soft-delete de la version actual del registro COMPLETO.

        Borra la tupla entera, no un campo. Eliminar un campo es un PATCH con
        ``null`` y no toca sus campos hermanos.
        """
        require_admin(principal, "borrar registros de secretos")
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            self._assert_writable(collection)
            record = await repo.require_record(session, collection_id, record_id)
            if record.state == "destroyed":
                raise ConflictError(
                    "el registro esta destruido: no hay version actual que borrar",
                    code="record_destroyed",
                )
            operation, replayed = await ops_repo.start(
                session,
                operation_type="record_soft_delete",
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            await session.commit()

        await self._execute(
            principal=principal,
            payload={
                "operation": "record_soft_delete",
                "collection_id": str(collection_id),
                "record_id": str(record_id),
            },
            proof=None,
            request_id=request_id,
            operation_id=operation_id,
            phase_name="vault_soft_delete",
        )

        async with self._session_factory() as session:
            await repo.touch_record(
                session, record_id, state="soft_deleted", deleted_at=_now()
            )
            await ops_repo.add_phase(
                session,
                operation_id,
                name="catalog_reflect",
                system="postgres",
                state="done",
            )
            await ops_repo.finish(session, operation_id, status="completed")
            await session.commit()

        await self._audit(
            principal=principal,
            action="record_soft_delete",
            outcome="allowed",
            collection_id=collection_id,
            record_id=record_id,
            operation_id=operation_id,
            request_id=request_id,
            detail="soft-delete de la version actual; recuperable con undelete",
        )
        return operation_id

    async def version_action(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        action: str,
        versions: list[int],
        proof: str | None,
        confirm: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> uuid.UUID:
        """``versions_delete`` / ``versions_undelete`` / ``versions_destroy``.

        Las versiones son **explicitas**: no hay "todas" implicito. ``destroy``
        es irreversible y exige confirmacion y MFA reciente.
        """
        require_admin(principal, "operar versiones de un registro")
        if action not in ("versions_delete", "versions_undelete", "versions_destroy"):
            raise ValidationError("accion de versiones no admitida")

        bounded = sorted(set(versions))
        if len(bounded) > self._settings.max_versions_per_request:
            raise ValidationError(
                f"como maximo {self._settings.max_versions_per_request} versiones "
                "por operacion",
                code="too_many_versions",
            )

        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            if action != "versions_undelete":
                self._assert_writable(collection)
            elif collection.state == "purged":
                raise ConflictError(
                    "la coleccion esta purgada: no hay nada que recuperar",
                    code="collection_purged",
                )
            record = await repo.require_record(session, collection_id, record_id)
            operation, replayed = await ops_repo.start(
                session,
                operation_type=action,
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            await session.commit()
            previous_state = record.state
            current_version = record.current_version

        payload: dict[str, Any] = {
            "operation": action,
            "collection_id": str(collection_id),
            "record_id": str(record_id),
            "versions": bounded,
        }
        if confirm:
            payload["confirm"] = confirm

        await self._execute(
            principal=principal,
            payload=payload,
            proof=proof,
            request_id=request_id,
            operation_id=operation_id,
            phase_name=f"vault_{action}",
        )

        new_state = self._state_after(
            action, previous_state, bounded, current_version
        )
        async with self._session_factory() as session:
            await repo.touch_record(
                session,
                record_id,
                state=new_state,
                deleted_at=_now() if new_state != "active" else None,
                clear_deleted_at=new_state == "active",
            )
            await ops_repo.add_phase(
                session,
                operation_id,
                name="catalog_reflect",
                system="postgres",
                state="done",
                detail=f"estado '{new_state}'",
            )
            await ops_repo.finish(session, operation_id, status="completed")
            await session.commit()

        await self._audit(
            principal=principal,
            action=action,
            outcome="allowed",
            collection_id=collection_id,
            record_id=record_id,
            versions=bounded,
            operation_id=operation_id,
            request_id=request_id,
            detail=(
                f"{len(bounded)} versiones; estado del registro '{new_state}'. "
                + (
                    "Irreversible: no hay undelete despues de destroy."
                    if action == "versions_destroy"
                    else "Recuperar una version antigua no cambia por si solo cual es latest."
                )
            ),
        )
        return operation_id

    def _state_after(
        self,
        action: str,
        previous_state: str,
        versions: list[int],
        current_version: int,
    ) -> str:
        """Estado del registro en el indice despues de la operacion.

        Solo cambia si la operacion afecta a la version ACTUAL. Borrar una
        version historica no deja el registro borrado, y recuperar una antigua
        no lo reactiva: ``latest`` sigue siendo la mayor no destruida.
        """
        touches_current = current_version in versions
        if action == "versions_delete":
            return "soft_deleted" if touches_current else previous_state
        if action == "versions_undelete":
            if touches_current and previous_state == "soft_deleted":
                return "active"
            return previous_state
        # versions_destroy
        if touches_current:
            return "destroyed"
        return previous_state

    async def purge_record(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        proof: str | None,
        confirm: str,
        reason: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> uuid.UUID:
        """Borra datos de TODAS las versiones y la metadata. Irreversible.

        El registro permanece en el indice con estado ``destroyed``: asi se
        distingue "destruido" de "nunca existio", que es informacion distinta.
        Su rastro de auditoria se conserva.
        """
        require_admin(principal, "purgar un registro")
        async with self._session_factory() as session:
            await repo.require_collection(session, collection_id)
            await repo.require_record(session, collection_id, record_id)
            operation, replayed = await ops_repo.start(
                session,
                operation_type="record_purge",
                collection_id=collection_id,
                record_id=record_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            if replayed:
                await session.commit()
                raise ConflictError(
                    "esa Idempotency-Key ya se uso; consulta la operacion original",
                    code="idempotency_replay",
                    context={"operation_id": str(operation_id)},
                )
            await session.commit()

        await self._execute(
            principal=principal,
            payload={
                "operation": "record_purge",
                "collection_id": str(collection_id),
                "record_id": str(record_id),
                "confirm": confirm,
            },
            proof=proof,
            request_id=request_id,
            operation_id=operation_id,
            phase_name="vault_purge",
        )

        async with self._session_factory() as session:
            await repo.touch_record(
                session, record_id, state="destroyed", deleted_at=_now()
            )
            await ops_repo.add_phase(
                session,
                operation_id,
                name="catalog_reflect",
                system="postgres",
                state="done",
            )
            await ops_repo.finish(session, operation_id, status="completed")
            await session.commit()

        await self._audit(
            principal=principal,
            action="record_purge",
            outcome="allowed",
            collection_id=collection_id,
            record_id=record_id,
            operation_id=operation_id,
            request_id=request_id,
            detail="datos y metadata destruidos"
            + (f"; motivo: {reason}" if reason else ""),
        )
        return operation_id

    # -- listados ------------------------------------------------------------

    async def list_records(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        state: str | None,
        sort: str,
        descending: bool,
        limit: int,
        offset: int,
    ) -> repo.Page:
        if sort not in repo.RECORD_SORTS:
            raise ValidationError(
                f"orden no admitido: '{sort}'",
                context={"allowed": sorted(repo.RECORD_SORTS)},
            )
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            return await repo.list_records(
                session,
                collection_id=collection_id,
                state=state,
                sort=sort,
                descending=descending,
                limit=limit,
                offset=offset,
            )

    async def get_record(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
    ) -> SecretRecord:
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            return await repo.require_record(session, collection_id, record_id)

    async def get_operation(
        self, *, principal: HumanPrincipal, operation_id: uuid.UUID
    ) -> Any:
        require_admin(principal, "consultar operaciones")
        async with self._session_factory() as session:
            operation = await ops_repo.get(session, operation_id)
        if operation is None:
            raise NotFoundError("no existe esa operacion", code="operation_not_found")
        return operation


__all__ = ["RecordService", "WriteResult"]
