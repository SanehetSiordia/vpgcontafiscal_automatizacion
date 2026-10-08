"""Worker de operaciones de consumidor (etapa 4.6).

Se ejecuta como un proceso aparte, con la **misma imagen** que la API:

    python -m app.vault_mgmt.worker

Por que un proceso y no una tarea en el ``lifespan`` de la API: una peticion
HTTP no debe esperar a Vault, y un reinicio de la API no debe perder trabajo en
curso. El trabajo esta en PostgreSQL; este proceso lo toma, lo hace y lo marca.

Como se reparte el trabajo, sin Redis ni Celery
-----------------------------------------------
La cola es una tabla. Se reserva con ``SELECT ... FOR UPDATE SKIP LOCKED`` y un
``lease_expires_at``, y **la transaccion se cierra antes de llamar a Vault**.
Eso da tres propiedades que importan:

* Varios workers pueden compartir la cola sin memoria compartida: el que llega
  segundo salta las filas bloqueadas en vez de esperar. Se arranca con uno, pero
  el diseno no obliga a quedarse ahi.
* Un worker que muera no bloquea la cola: su arrendamiento caduca y otro la toma.
* Ninguna conexion de PostgreSQL queda retenida durante un timeout de Vault.

Las sesiones humanas de user-mgmt siguen con su limite actual de un worker: eso
es otra cosa (viven en memoria de **ese** proceso) y esta etapa no lo cambia.

Lo que este proceso NO hace: no atiende HTTP, no hace unseal, no ejecuta shell,
no usa el socket de Docker y no escribe credenciales en ningun sitio.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import uuid

from app.core.logging import configure_logging, get_logger
from app.vault_mgmt.core.approle_admin import AppRoleAdminClient
from app.vault_mgmt.core.config import Settings, get_settings
from app.vault_mgmt.core.database import (
    dispose_engine,
    get_session_factory,
    init_engine,
)
from app.vault_mgmt.core.vault_auth import build_token_provider
from app.vault_mgmt.repositories import provisioning as repo
from app.vault_mgmt.services.provisioning import ProvisioningService

logger = get_logger("app.vault_mgmt.worker")


def worker_name(settings: Settings) -> str:
    """Nombre estable y legible del worker, para el campo ``lease_owner``."""
    if settings.worker_name:
        return settings.worker_name
    return f"{socket.gethostname()}:{os.getpid()}"


class ProvisioningWorker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._name = worker_name(settings)
        self._stop = asyncio.Event()
        self._provider = build_token_provider(settings)
        self._approle = AppRoleAdminClient(settings, self._provider)
        init_engine(settings)
        self._session_factory = get_session_factory()
        self._service = ProvisioningService(
            settings=settings,
            session_factory=self._session_factory,
            approle=self._approle,
        )

    @property
    def name(self) -> str:
        return self._name

    def request_stop(self) -> None:
        self._stop.set()

    async def aclose(self) -> None:
        await self._approle.aclose()
        await self._provider.aclose()
        await dispose_engine()

    async def claim_batch(self) -> list[uuid.UUID]:
        """Reserva un lote. La transaccion se cierra antes de salir de aqui."""
        async with self._session_factory() as session:
            claimed = await repo.claim_operations(
                session,
                worker_name=self._name,
                limit=self._settings.worker_batch,
                lease_seconds=self._settings.worker_lease_seconds,
                max_attempts=self._settings.worker_max_attempts,
            )
            ids = [op.operation_id for op in claimed]
            await session.commit()
        return ids

    async def run_once(self) -> int:
        """Un ciclo: reconciliar lo caducado y procesar lo reservado."""
        hechas = 0

        # 1. Reconciliacion antes que nada: una envoltura caducada deja un
        #    SecretID vivo que nadie recogio. Hay que destruirlo ANTES de emitir
        #    otro, no despues.
        try:
            cerradas = await self._service.reconcile_expired_deliveries()
            if cerradas:
                logger.info(
                    "entregas caducadas reconciliadas",
                    extra={"operation": "reconcile", "count": cerradas},
                )
        except Exception:  # noqa: BLE001 - un fallo aqui no para el worker
            logger.exception(
                "fallo al reconciliar entregas caducadas",
                extra={"operation": "reconcile"},
            )

        # 2. Lote de operaciones.
        try:
            pendientes = await self.claim_batch()
        except Exception:  # noqa: BLE001
            logger.exception("fallo al reservar operaciones", extra={"operation": "claim"})
            return 0

        for operation_id in pendientes:
            if self._stop.is_set():
                # Se suelta el arrendamiento para que otro la tome enseguida en
                # vez de esperar a que caduque.
                await self._release(operation_id)
                break
            try:
                status = await self._service.run_operation(operation_id)
                hechas += 1
                logger.info(
                    "operacion procesada",
                    extra={
                        "operation": "run",
                        "operation_id": str(operation_id),
                        "status": status,
                    },
                )
            except Exception:  # noqa: BLE001 - se anota y se sigue con el lote
                logger.exception(
                    "operacion fallida sin controlar",
                    extra={"operation": "run", "operation_id": str(operation_id)},
                )
                await self._fail(
                    operation_id,
                    "error interno del worker; revisa el log con este operation_id",
                )
        return hechas

    async def _release(self, operation_id: uuid.UUID) -> None:
        with contextlib.suppress(Exception):
            async with self._session_factory() as session:
                await repo.release_lease(session, operation_id)
                await session.commit()

    async def _fail(self, operation_id: uuid.UUID, detail: str) -> None:
        with contextlib.suppress(Exception):
            async with self._session_factory() as session:
                await repo.set_operation_status(
                    session, operation_id, status="failed", error=detail
                )
                await session.commit()

    async def run_forever(self) -> None:
        logger.info(
            "worker de aprovisionamiento en marcha",
            extra={
                "operation": "startup",
                "worker": self._name,
                "provisioning": self._provider.available,
            },
        )
        if not self._provider.available:
            logger.warning(
                "sin token de aprovisionamiento: las operaciones se quedaran en "
                "'pending' hasta que se monte el secreto",
                extra={"operation": "startup"},
            )

        while not self._stop.is_set():
            await self.run_once()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self._settings.worker_poll_seconds
                )
        logger.info("worker detenido", extra={"operation": "shutdown"})


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    worker = ProvisioningWorker(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, AttributeError):
            # En Windows no todas las senales tienen manejador de bucle; el
            # KeyboardInterrupt de abajo cubre ese caso.
            loop.add_signal_handler(sig, worker.request_stop)

    try:
        await worker.run_forever()
    finally:
        await worker.aclose()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
