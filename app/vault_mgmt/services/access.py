"""Capacidad efectiva por coleccion, registro y operacion. Nunca valores.

La capacidad efectiva es una **interseccion** de dos cosas distintas:

1. El rol de APLICACION: ``admin`` escribe, y un rol lector declarado en la
   coleccion lee. Esto se decide aqui.
2. La ACL de **Vault** sobre el path gestionado, consultada con el token humano
   a traves de la pasarela. Esto lo decide Vault, y manda.

Un rol que permita no sirve de nada si la politica de Vault no cubre el path, y
al reves tampoco. La respuesta muestra las dos columnas para que no se confunda
una con la otra.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.core.errors import ValidationError
from app.vault_mgmt.core.principal import (
    HumanPrincipal,
    assert_can_read_collection,
    can_read_collection,
)
from app.vault_mgmt.repositories import audit as audit_repo
from app.vault_mgmt.repositories import catalog as repo
from app.vault_mgmt.services.base import GatewayBackedService

# Operaciones que se pueden consultar y que rol de aplicacion exige cada una.
# Es la misma tabla que aplica la pasarela; aqui solo se informa.
_REQUIRES_ADMIN = {
    "record_create": True,
    "record_replace": True,
    "record_patch": True,
    "record_soft_delete": True,
    "record_metadata": True,
    "versions_delete": True,
    "versions_undelete": True,
    "versions_destroy": True,
    "record_purge": True,
    "collection_inventory": True,
    "record_read": False,
    "capabilities": False,
}

_NEEDS_FRESH_MFA = {"versions_destroy", "record_purge"}


class AccessService(GatewayBackedService):
    async def check(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID,
        record_id: uuid.UUID | None,
        operations: list[str],
        request_id: str | None,
    ) -> dict[str, Any]:
        unknown = sorted(set(operations) - set(_REQUIRES_ADMIN))
        if unknown:
            raise ValidationError(
                "operaciones no reconocidas",
                context={
                    "unknown": unknown,
                    "allowed": sorted(_REQUIRES_ADMIN),
                },
            )

        async with self._session_factory() as session:
            collection = await repo.require_collection(session, collection_id)
            # Sin ser lector autorizado no se informa ni de la capacidad: el
            # endpoint no debe convertirse en un escaner del catalogo.
            assert_can_read_collection(
                principal, collection.reader_role_codes, collection_id=collection_id
            )
            if record_id is not None:
                await repo.require_record(session, collection_id, record_id)

        rows: list[dict[str, Any]] = []
        for operation in operations:
            needs_admin = _REQUIRES_ADMIN[operation]
            allowed = (
                principal.is_admin
                if needs_admin
                else can_read_collection(principal, collection.reader_role_codes)
            )
            reason: str | None = None
            if not allowed:
                reason = (
                    "solo un administrador ejecuta esta operacion"
                    if needs_admin
                    else "ninguno de tus roles vigentes es lector de esta coleccion"
                )
            elif collection.state != "active":
                allowed = False
                reason = (
                    f"la coleccion esta '{collection.state}': la API no da acceso "
                    "ni prepara entregas nuevas"
                )
            elif operation in _NEEDS_FRESH_MFA:
                reason = (
                    "ademas exige una prueba de MFA reciente ligada a esta "
                    "operacion y a estos recursos"
                )
            rows.append(
                {
                    "operation": operation,
                    "allowed_by_application_role": allowed,
                    "reason": reason,
                }
            )

        # Capacidades reales del token humano sobre el path gestionado.
        capabilities: dict[str, list[str]] = {}
        try:
            result = await self._execute(
                principal=principal,
                payload={
                    "operation": "capabilities",
                    "collection_id": str(collection_id),
                    "record_id": str(record_id) if record_id else None,
                },
                proof=None,
                request_id=request_id,
                operation_id=None,
                phase_name="vault_capabilities",
            )
            capabilities = {
                str(path): list(value)
                for path, value in (result.get("capabilities") or {}).items()
            }
        except Exception as exc:  # noqa: BLE001 - la parte de Vault es informativa
            capabilities = {}
            rows.append(
                {
                    "operation": "vault_capabilities",
                    "allowed_by_application_role": False,
                    "reason": (
                        "no se pudo consultar la ACL de Vault: "
                        + str(getattr(exc, "message", exc))[:160]
                    ),
                }
            )

        async with self._session_factory() as session:
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="access_check",
                outcome="allowed",
                collection_id=collection_id,
                record_id=record_id,
                request_id=request_id,
                detail=f"{len(operations)} operaciones consultadas",
            )
            await session.commit()

        return {
            "collection_id": collection_id,
            "record_id": record_id,
            "collection_state": collection.state,
            "your_roles": sorted(principal.role_codes),
            "collection_readers": sorted(collection.reader_role_codes),
            "operations": rows,
            "vault_capabilities": capabilities,
        }

    async def list_audit(
        self,
        *,
        principal: HumanPrincipal,
        collection_id: uuid.UUID | None,
        record_id: uuid.UUID | None,
        action: str | None,
        outcome: str | None,
        limit: int,
        offset: int,
    ) -> audit_repo.AuditPage:
        from app.vault_mgmt.core.principal import require_admin

        require_admin(principal, "consultar la auditoria de secretos")
        async with self._session_factory() as session:
            return await audit_repo.list_entries(
                session,
                collection_id=collection_id,
                record_id=record_id,
                action=action,
                outcome=outcome,
                limit=limit,
                offset=offset,
            )


__all__ = ["AccessService"]
