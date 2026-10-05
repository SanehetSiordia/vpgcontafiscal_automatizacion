"""Ciclo de vida de una coleccion: archivar, restaurar y purgar.

Lo que estas operaciones SI hacen y lo que NO:

* Archivar inventaria sus registros y les aplica soft-delete, y marca la
  coleccion ``archived``. La API deja de dar acceso y de preparar entregas
  nuevas. **No** revoca secretos ya entregados, **no** caduca un wrapping token
  que ya viaja, y **no** impide a un administrador leer Vault directamente: eso
  lo decide la ACL de Vault, no esta API.
* Restaurar recupera las versiones recuperables. Una version **destruida no
  vuelve**, y eso se reporta como ``skipped``, no como exito.
* Purgar destruye datos y metadata de sus registros. Se conserva la auditoria
  minima: la fila de la coleccion, las filas de los registros en estado
  ``destroyed`` y el historial.

Como se trata la concurrencia, sin prometer lo que el motor no da:

* El lote esta **acotado** por configuracion. Si la coleccion tiene mas
  registros que el tope, la operacion se rechaza antes de tocar nada en vez de
  dejar la mitad hecha.
* Mientras la transicion esta abierta, el indice parcial de operaciones y la
  comprobacion en ``operations.start`` **serializan** las escrituras de la API
  sobre esa coleccion. Eso cubre a esta API, no a Vault: alguien con permisos
  puede escribir directamente en Vault y por eso se compara el inventario.
* Antes de cerrar se **verifica el inventario** y se comparan las claves reales
  de Vault con el indice del catalogo. Una clave que esta en Vault y no en el
  catalogo se reporta como posible escritura externa; no se borra ni se adopta
  en silencio.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.errors import ConflictError, PartialOperationError
from app.core.logging import get_logger
from app.vault_mgmt.core.principal import HumanPrincipal, require_admin
from app.vault_mgmt.repositories import catalog as repo
from app.vault_mgmt.repositories import operations as ops_repo
from app.vault_mgmt.services.base import GatewayBackedService

logger = get_logger(__name__)

_ACTIONS: dict[str, dict[str, Any]] = {
    "archive": {
        "operation_type": "collection_archive",
        "gateway_operation": "collection_soft_delete_batch",
        "confirm": "ARCHIVE",
        "source_states": ("active",),
        "record_state": "soft_deleted",
        "collection_state": "archived",
    },
    "restore": {
        "operation_type": "collection_restore",
        "gateway_operation": "collection_undelete_batch",
        "confirm": "RESTORE",
        "source_states": ("soft_deleted",),
        "record_state": "active",
        "collection_state": "active",
    },
    "purge": {
        "operation_type": "collection_purge",
        "gateway_operation": "collection_purge_batch",
        "confirm": "PURGE",
        "source_states": ("active", "soft_deleted"),
        "record_state": "destroyed",
        "collection_state": "purged",
    },
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@dataclass(slots=True)
class LifecycleResult:
    collection_id: uuid.UUID
    operation_id: uuid.UUID
    state: str
    inventoried: int
    processed: int
    failed: int
    skipped: int
    results: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None


class LifecycleService(GatewayBackedService):
    async def run(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        action: str,
        proof: str | None,
        idempotency_key: str | None,
        request_id: str | None,
        reason: str | None = None,
    ) -> LifecycleResult:
        require_admin(principal, f"{action} una coleccion de secretos")
        plan = _ACTIONS[action]

        # --- transaccion 1: validar, inventariar y abrir la operacion -------
        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            self._assert_transition(collection.state, action)

            total = await repo.count_records(
                session, collection_id, states=plan["source_states"]
            )
            limit = self._settings.max_collection_batch
            if total > limit:
                raise ConflictError(
                    f"la coleccion tiene {total} registros que procesar y el tope "
                    f"por operacion es {limit}. Sube "
                    "VAULT_MGMT_MAX_COLLECTION_BATCH de forma consciente o opera "
                    "los registros uno a uno: dejar la mitad hecha seria peor.",
                    code="batch_too_large",
                    context={"records": total, "limit": limit},
                )

            records = await repo.record_ids_for_collection(
                session, collection_id, limit=limit, states=plan["source_states"]
            )
            operation, replayed = await ops_repo.start(
                session,
                operation_type=plan["operation_type"],
                collection_id=collection_id,
                record_id=None,
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
            await ops_repo.add_phase(
                session,
                operation_id,
                name="inventory",
                system="postgres",
                state="done",
                detail=f"{len(records)} registros inventariados",
            )
            await ops_repo.set_counters(
                session,
                operation_id,
                {"inventoried": len(records), "processed": 0, "failed": 0, "skipped": 0},
            )
            await session.commit()
            record_ids = [record.record_id for record in records]

        # --- inventario real en Vault (deteccion de cambios externos) -------
        external = await self._compare_inventory(
            principal=principal,
            collection_id=collection_id,
            operation_id=operation_id,
            known=record_ids,
            request_id=request_id,
        )

        if not record_ids:
            # Nada que procesar en Vault: solo cambia el catalogo.
            await self._close_catalog(
                collection_id=collection_id,
                operation_id=operation_id,
                record_ids=[],
                plan=plan,
            )
            await self._finish(operation_id, "completed")
            await self._audit(
                principal=principal,
                action=plan["operation_type"],
                outcome="allowed",
                collection_id=collection_id,
                operation_id=operation_id,
                request_id=request_id,
                detail="sin registros que procesar"
                + (f"; motivo: {reason}" if reason else ""),
            )
            return LifecycleResult(
                collection_id=collection_id,
                operation_id=operation_id,
                state=plan["collection_state"],
                inventoried=0,
                processed=0,
                failed=0,
                skipped=0,
                note=self._external_note(external),
            )

        # --- lote en Vault, con una sola prueba de MFA ----------------------
        result = await self._execute(
            principal=principal,
            payload={
                "operation": plan["gateway_operation"],
                "collection_id": str(collection_id),
                "record_ids": [str(value) for value in record_ids],
                "confirm": plan["confirm"],
            },
            proof=proof,
            request_id=request_id,
            operation_id=operation_id,
            phase_name=f"vault_{action}_batch",
        )

        outcomes = list(result.get("results") or [])
        ok = [item for item in outcomes if item.get("status") == "ok"]
        failed = [item for item in outcomes if item.get("status") == "failed"]
        skipped = [item for item in outcomes if item.get("status") == "skipped"]

        # --- reflejo en el catalogo, solo de lo que SI se hizo --------------
        await self._close_catalog(
            collection_id=collection_id,
            operation_id=operation_id,
            record_ids=[uuid.UUID(str(item["record_id"])) for item in ok],
            plan=plan,
            # Si algo fallo, la coleccion no cambia de estado: decir que esta
            # archivada cuando parte de sus registros siguen vivos seria mentir.
            change_collection_state=not failed,
        )

        # --- verificacion del inventario antes de cerrar --------------------
        async with self._session_factory() as session:
            pending = await repo.count_records(
                session, collection_id, states=plan["source_states"]
            )
        await self._counters(
            operation_id,
            {
                "inventoried": len(record_ids),
                "processed": len(ok),
                "failed": len(failed),
                "skipped": len(skipped),
                "pending_after": pending,
                "external_keys": len(external),
            },
        )
        await self._phase(
            operation_id,
            "inventory_verify",
            "postgres",
            "done" if not pending or skipped else "partial",
            detail=f"{pending} registros siguen en el estado de origen",
        )

        if failed:
            await self._finish(
                operation_id,
                "needs_reconciliation",
                error=(
                    f"{len(failed)} de {len(record_ids)} registros no se pudieron "
                    "procesar en Vault"
                ),
            )
            await self._audit(
                principal=principal,
                action=plan["operation_type"],
                outcome="partial",
                collection_id=collection_id,
                operation_id=operation_id,
                request_id=request_id,
                detail=f"{len(ok)} ok, {len(failed)} fallidos, {len(skipped)} omitidos",
            )
            raise PartialOperationError(
                f"la operacion quedo a medias: {len(ok)} registros procesados y "
                f"{len(failed)} fallidos. La coleccion NO cambia de estado. "
                "Consulta la operacion y reconciliala.",
                code="partial_operation",
                context={
                    "operation_id": str(operation_id),
                    "processed": len(ok),
                    "failed": len(failed),
                    "skipped": len(skipped),
                    "results": outcomes,
                },
            )

        await self._finish(operation_id, "completed")
        await self._audit(
            principal=principal,
            action=plan["operation_type"],
            outcome="allowed",
            collection_id=collection_id,
            operation_id=operation_id,
            request_id=request_id,
            detail=(
                f"{len(ok)} registros procesados, {len(skipped)} omitidos"
                + (f"; motivo: {reason}" if reason else "")
            ),
        )
        logger.info(
            "ciclo de vida de coleccion completado",
            extra={
                "operation": plan["operation_type"],
                "actor": principal.username,
                "collection": str(collection_id),
                "processed": len(ok),
                "skipped": len(skipped),
            },
        )
        return LifecycleResult(
            collection_id=collection_id,
            operation_id=operation_id,
            state=plan["collection_state"],
            inventoried=len(record_ids),
            processed=len(ok),
            failed=0,
            skipped=len(skipped),
            results=outcomes,
            note=self._external_note(external),
        )

    # -- utilidades ----------------------------------------------------------

    def _assert_transition(self, state: str, action: str) -> None:
        if action == "archive" and state != "active":
            raise ConflictError(
                f"la coleccion esta '{state}': solo se archiva una activa",
                code="collection_not_active",
            )
        if action == "restore" and state != "archived":
            raise ConflictError(
                f"la coleccion esta '{state}': solo se restaura una archivada. "
                "Una coleccion purgada no se restaura: sus datos se destruyeron.",
                code="collection_not_archived",
            )
        if action == "purge" and state == "purged":
            raise ConflictError(
                "la coleccion ya esta purgada", code="collection_purged"
            )

    async def _compare_inventory(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        operation_id: uuid.UUID,
        known: list[uuid.UUID],
        request_id: str | None,
    ) -> list[str]:
        """Compara las claves reales de Vault con el indice del catalogo.

        ``LIST`` enumera hijos de un prefijo: no devuelve documentos y no aplica
        filtrado de politicas elemento a elemento. Se usa solo para detectar
        claves que el catalogo no conoce, que son posibles escrituras directas
        en Vault. No se borran ni se adoptan en silencio.
        """
        try:
            result = await self._execute(
                principal=principal,
                payload={
                    "operation": "collection_inventory",
                    "collection_id": str(collection_id),
                },
                proof=None,
                request_id=request_id,
                operation_id=None,
                phase_name="vault_inventory",
            )
        except Exception as exc:  # noqa: BLE001 - el inventario es informativo
            await self._phase(
                operation_id,
                "vault_inventory",
                "vault",
                "skipped",
                detail=f"no se pudo enumerar el prefijo: {exc}"[:200],
            )
            return []

        children = {str(key).rstrip("/") for key in (result.get("children") or [])}
        known_text = {str(value) for value in known}
        external = sorted(children - known_text)
        await self._phase(
            operation_id,
            "vault_inventory",
            "vault",
            "done",
            detail=(
                f"{len(children)} claves en Vault, {len(known_text)} en el catalogo, "
                f"{len(external)} desconocidas"
            ),
        )
        return external

    def _external_note(self, external: list[str]) -> str | None:
        if not external:
            return None
        return (
            f"{len(external)} claves del prefijo no estan en el catalogo: pueden "
            "ser escrituras directas en Vault. No se han tocado. Revisa el "
            "inventario con scripts/vault_mgmt/inventory-import.sh antes de "
            "concluir nada."
        )

    async def _close_catalog(
        self,
        *,
        collection_id: uuid.UUID,
        operation_id: uuid.UUID,
        record_ids: list[uuid.UUID],
        plan: dict[str, Any],
        change_collection_state: bool = True,
    ) -> None:
        async with self._session_factory() as session:
            for record_id in record_ids:
                await repo.touch_record(
                    session,
                    record_id,
                    state=plan["record_state"],
                    deleted_at=_now() if plan["record_state"] != "active" else None,
                    clear_deleted_at=plan["record_state"] == "active",
                )
            if change_collection_state:
                await repo.set_collection_state(
                    session,
                    collection_id,
                    state=plan["collection_state"],
                    now=_now(),
                )
            await ops_repo.add_phase(
                session,
                operation_id,
                name="catalog_reflect",
                system="postgres",
                state="done",
                detail=f"{len(record_ids)} registros a '{plan['record_state']}'",
            )
            await session.commit()


__all__ = ["LifecycleResult", "LifecycleService"]
