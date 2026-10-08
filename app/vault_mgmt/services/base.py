"""Piezas comunes de los servicios: fases durables, auditoria y llamada a la pasarela.

El principio es el mismo de la etapa 3, aplicado a otro par de sistemas:

* **No hay transaccion distribuida.** PostgreSQL no revierte Vault. Cada
  operacion escribe sus fases antes de seguir, en transacciones cortas.
* **Ninguna transaccion de base de datos permanece abierta durante una llamada
  HTTP.** Ni a la pasarela, ni a Vault.
* **Nada se reintenta solo.** Si la pasarela no contesta y Vault pudo haber
  escrito, la respuesta es 409 con ``operation_id`` y la operacion queda en
  ``needs_reconciliation``. Reintentar a ciegas una escritura que quizas se
  aplico es como se duplican versiones.
* Una Idempotency-Key repetida devuelve la operacion original en vez de
  ejecutar dos veces. No se guarda el cuerpo ni un hash de los valores para
  comparar reintentos: un hash de baja entropia en la base seria un oraculo.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import AppError, PartialOperationError
from app.core.logging import get_logger
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.gateway_client import GatewayClient, GatewayUnavailable
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.repositories import audit as audit_repo
from app.vault_mgmt.repositories import operations as ops_repo

logger = get_logger(__name__)


class GatewayBackedService:
    """Base de los servicios que necesitan la pasarela para tocar Vault."""

    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        gateway: GatewayClient,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._gateway = gateway

    # -- registro durable ----------------------------------------------------

    async def _phase(
        self,
        operation_id: uuid.UUID,
        name: str,
        system: str,
        state: str,
        detail: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await ops_repo.add_phase(
                session, operation_id, name=name, system=system, state=state, detail=detail
            )
            await session.commit()

    async def _counters(self, operation_id: uuid.UUID, counters: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            await ops_repo.set_counters(session, operation_id, counters)
            await session.commit()

    async def _finish(
        self,
        operation_id: uuid.UUID,
        status: str,
        *,
        error: str | None = None,
        result_version: int | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await ops_repo.finish(
                session,
                operation_id,
                status=status,
                error=error,
                result_version=result_version,
            )
            await session.commit()

    async def _audit(
        self,
        *,
        principal: HumanPrincipal | None,
        action: str,
        outcome: str,
        collection_id: uuid.UUID | None = None,
        record_id: uuid.UUID | None = None,
        versions: list[int] | None = None,
        operation_id: uuid.UUID | None = None,
        request_id: str | None = None,
        detail: str | None = None,
        actor_kind: str = "human",
        actor_label: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await audit_repo.record(
                session,
                actor_kind=actor_kind,
                actor_user_id=principal.user_id if principal else None,
                actor_label=actor_label or (principal.username if principal else None),
                action=action,
                outcome=outcome,
                collection_id=collection_id,
                record_id=record_id,
                versions=versions,
                operation_id=operation_id,
                request_id=request_id,
                detail=detail,
            )
            await session.commit()

    # -- llamada a la pasarela ----------------------------------------------

    async def _execute(
        self,
        *,
        principal: HumanPrincipal,
        payload: dict[str, Any],
        proof: str | None,
        request_id: str | None,
        operation_id: uuid.UUID | None,
        phase_name: str,
    ) -> dict[str, Any]:
        """Ejecuta en la pasarela y registra la fase, con o sin exito.

        Distingue dos clases de fallo, porque no se tratan igual:

        * **Determinado** (403, 404, 409, 422): la pasarela o Vault rechazaron y
          no se escribio nada. La operacion termina en ``failed`` y el error se
          propaga tal cual, conservando su codigo.
        * **Indeterminado** (la pasarela no responde o tarda de mas): Vault
          **pudo** haber escrito y se perdio la respuesta. La operacion queda en
          ``needs_reconciliation`` y el llamante recibe 409 con el
          ``operation_id``. No se reintenta en silencio.
        """
        if operation_id is not None:
            payload = {**payload, "operation_id": str(operation_id)}
        if request_id:
            payload = {**payload, "request_id": request_id}

        try:
            result = await self._gateway.execute(
                bearer=principal.bearer,
                payload=payload,
                mfa_proof=proof,
                request_id=request_id,
            )
        except GatewayUnavailable as exc:
            if operation_id is not None:
                await self._phase(
                    operation_id,
                    phase_name,
                    "gateway",
                    "unknown",
                    detail=exc.message,
                )
                await self._finish(
                    operation_id,
                    "needs_reconciliation",
                    error=(
                        "no se recibio respuesta de la pasarela: Vault pudo haber "
                        "aplicado el cambio. " + exc.message
                    ),
                )
            raise PartialOperationError(
                "no se pudo confirmar el resultado en Vault: la operacion queda "
                "pendiente de reconciliacion. NO reintentes a ciegas; consulta la "
                "operacion primero.",
                code="reconciliation_required",
                context={"operation_id": str(operation_id) if operation_id else None},
            ) from exc
        except AppError as exc:
            if operation_id is not None:
                await self._phase(
                    operation_id,
                    phase_name,
                    "gateway",
                    "failed",
                    detail=f"{exc.code}: {exc.message}",
                )
                await self._finish(
                    operation_id, "failed", error=f"{exc.code}: {exc.message}"
                )
            raise

        if operation_id is not None:
            await self._phase(
                operation_id,
                phase_name,
                "vault",
                "done",
                detail=str(result.get("outcome") or "completed"),
            )
        return result


__all__ = ["GatewayBackedService"]
