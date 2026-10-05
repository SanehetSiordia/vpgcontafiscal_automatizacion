"""Readiness de vault-mgmt-service.

Cuatro comprobaciones, todas necesarias para atender negocio:

1. ``SELECT 1`` autenticado contra PostgreSQL y catalogo presente.
2. Vault inicializado y **desbloqueado**. El unseal sigue siendo manual: este
   servicio no lo intenta.
3. ``/health/ready`` de user-mgmt en 200.
4. La pasarela interna reconoce la credencial de servicio.

Mientras algo falte, ``/health/ready`` responde **503** con el detalle, y los
endpoints de negocio tambien. El proceso, en cambio, **arranca**: un
healthcheck que impidiera arrancar dejaria sin diagnostico el caso mas comun en
local, que es Vault sellado.

Lo que este servicio NO hace al arrancar: habilitar montajes KV, escribir
politicas, crear autenticadores ni sembrar datos. Todo eso son scripts CLI
idempotentes.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.logging import get_logger
from app.core.vault import VaultError, sanitize_vault_message
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.gateway_client import GatewayClient
from app.vault_mgmt.core.machine_auth import VaultProbe

logger = get_logger(__name__)

# Tablas que la migracion 003 debe haber creado para que el servicio opere.
REQUIRED_TABLES = (
    "secret_collections",
    "secret_collection_schemas",
    "secret_records",
    "secret_consumers",
    "secret_consumer_bindings",
    "secret_operations",
    "secret_audit",
)


@dataclasses.dataclass(slots=True)
class ReadinessReport:
    database: bool = False
    catalog_schema: bool = False
    vault_initialized: bool = False
    vault_unsealed: bool = False
    user_mgmt_ready: bool = False
    gateway_authenticated: bool = False
    detail: str | None = None
    checked_at: dt.datetime | None = None

    @property
    def ready(self) -> bool:
        return (
            self.database
            and self.catalog_schema
            and self.vault_initialized
            and self.vault_unsealed
            and self.user_mgmt_ready
            and self.gateway_authenticated
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "checks": {
                "postgres_select_1": self.database,
                "catalog_schema_present": self.catalog_schema,
                "vault_initialized": self.vault_initialized,
                "vault_unsealed": self.vault_unsealed,
                "user_mgmt_ready": self.user_mgmt_ready,
                "internal_gateway_authenticated": self.gateway_authenticated,
            },
            "detail": self.detail,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class ReadinessState:
    """Estado compartido, refrescado en segundo plano por el ``lifespan``."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._report = ReadinessReport()
        self._lock = asyncio.Lock()

    @property
    def report(self) -> ReadinessReport:
        return self._report

    @property
    def ready(self) -> bool:
        return self._report.ready

    async def refresh(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        probe: VaultProbe,
        gateway: GatewayClient,
    ) -> ReadinessReport:
        report = ReadinessReport(checked_at=dt.datetime.now(dt.UTC))
        details: list[str] = []

        # 1. PostgreSQL y catalogo.
        try:
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))
                report.database = True
                missing = await _missing_tables(session, self._settings.postgres_schema)
            if missing:
                details.append(
                    "catalogo: faltan tablas ("
                    + ", ".join(missing)
                    + "). Ejecuta bash scripts/vault_mgmt/apply-migrations.sh"
                )
            else:
                report.catalog_schema = True
        except Exception as exc:  # noqa: BLE001 - se sanea y se reporta
            details.append(f"postgres: {sanitize_vault_message(str(exc), limit=160)}")

        # 2. Vault inicializado y desbloqueado.
        try:
            health = await probe.health()
            report.vault_initialized = health.initialized
            report.vault_unsealed = health.initialized and not health.sealed
            if not health.initialized:
                details.append("vault: sin inicializar ('vault operator init')")
            elif health.sealed:
                details.append("vault: sellado ('vault operator unseal', paso manual)")
        except VaultError as exc:
            details.append(f"vault: {exc.message}")

        # 3. user-mgmt listo.
        report.user_mgmt_ready = await gateway.health()
        if not report.user_mgmt_ready:
            details.append(
                "user-mgmt: /health/ready no responde 200 (puede estar esperando "
                "el unseal manual de Vault)"
            )

        # 4. Pasarela autenticada.
        authenticated, problem = await gateway.gateway_authenticated()
        report.gateway_authenticated = authenticated
        if problem:
            details.append(f"pasarela: {problem}")

        report.detail = "; ".join(details) if details else None
        self._report = report
        return report


async def _missing_tables(session: AsyncSession, schema: str) -> list[str]:
    rows = await session.execute(
        text(
            """
            SELECT c.relname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = :schema AND c.relkind = 'r'
            """
        ),
        {"schema": schema},
    )
    present = {row[0] for row in rows}
    return [name for name in REQUIRED_TABLES if name not in present]


__all__ = ["REQUIRED_TABLES", "ReadinessReport", "ReadinessState"]
