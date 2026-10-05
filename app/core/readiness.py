"""Precondicion de arranque y estado de readiness.

Hay dos clases de fallo y se tratan distinto a proposito:

1. **Fallo de provisionamiento** (no se arregla solo): PostgreSQL responde pero
   no hay ningun administrador de aplicacion activo con rol ``admin`` y vinculo
   a Vault, o el vinculo es incoherente. El proceso **aborta el arranque** con
   un mensaje que dice que hay que ejecutar antes los scripts CLI. FastAPI no
   crea administradores ni ejecuta semillas.

2. **Fallo transitorio** (puede arreglarse sin tocar nada): Vault esta sellado o
   no responde. El proceso **arranca**, pero ``/health/ready`` y todos los
   endpoints de negocio devuelven 503 hasta que la comprobacion pase. El
   desbloqueo es manual y sigue siendo manual: FastAPI no hace unseal.

``totp_status='pending'`` NO es un fallo: es estado historico. No demuestra que
la persona no tenga autenticador ni justifica reiniciar su TOTP.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.vault import (
    VaultClient,
    VaultError,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)
from app.repositories import users as users_repo

logger = get_logger(__name__)


class StartupPreconditionError(RuntimeError):
    """Impide arrancar: falta provisionamiento previo por CLI."""


@dataclasses.dataclass(slots=True)
class ReadinessReport:
    database: bool = False
    vault_initialized: bool = False
    vault_unsealed: bool = False
    vault_technical_credential: bool = False
    admin_linked: bool = False
    detail: str | None = None
    checked_at: dt.datetime | None = None

    @property
    def ready(self) -> bool:
        return (
            self.database
            and self.vault_initialized
            and self.vault_unsealed
            and self.vault_technical_credential
            and self.admin_linked
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "checks": {
                "postgres_select_1": self.database,
                "vault_initialized": self.vault_initialized,
                "vault_unsealed": self.vault_unsealed,
                "vault_technical_credential": self.vault_technical_credential,
                "admin_linked_in_postgres_and_vault": self.admin_linked,
            },
            "detail": self.detail,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


@dataclasses.dataclass(slots=True)
class AdminAnchor:
    """Administrador de referencia verificado al arrancar."""

    user_id: uuid.UUID
    username: str
    vault_username: str
    entity_id: uuid.UUID
    userpass_path: str
    userpass_accessor: str
    totp_method_id: uuid.UUID
    mfa_enforcement_name: str
    totp_status: str


class ReadinessState:
    """Estado compartido de readiness, refrescado en segundo plano."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._report = ReadinessReport()
        self._anchor: AdminAnchor | None = None
        self._lock = asyncio.Lock()

    @property
    def report(self) -> ReadinessReport:
        return self._report

    @property
    def anchor(self) -> AdminAnchor | None:
        return self._anchor

    @property
    def ready(self) -> bool:
        return self._report.ready

    async def set_anchor(self, anchor: AdminAnchor) -> None:
        async with self._lock:
            self._anchor = anchor

    async def refresh(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        vault: VaultClient,
    ) -> ReadinessReport:
        report = ReadinessReport(checked_at=dt.datetime.now(dt.UTC))
        details: list[str] = []

        # 1. PostgreSQL: SELECT 1 autenticado.
        try:
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))
            report.database = True
        except Exception as exc:  # noqa: BLE001 - se sanea y se reporta
            details.append(f"postgres: {sanitize_vault_message(str(exc), limit=160)}")

        # 2. Vault inicializado y desbloqueado.
        try:
            health = await vault.health()
            report.vault_initialized = health.initialized
            report.vault_unsealed = health.initialized and not health.sealed
            if not health.initialized:
                details.append("vault: sin inicializar ('vault operator init')")
            elif health.sealed:
                details.append("vault: sellado ('vault operator unseal', paso manual)")
        except VaultUnavailable as exc:
            details.append(f"vault: {exc.message}")
        except VaultError as exc:
            details.append(f"vault: {exc.message}")

        # 3. Credencial tecnica (AppRole) valida.
        if report.vault_unsealed:
            if not self._settings.has_vault_technical_credentials:
                details.append(
                    "vault: faltan role_id/secret_id montados "
                    "(scripts/user_mgmt/vault-approle-bootstrap.sh)"
                )
            else:
                try:
                    await vault.check_technical_credentials()
                    report.vault_technical_credential = True
                except VaultError as exc:
                    details.append(f"vault (cuenta tecnica): {exc.message}")

        # 4. Administrador activo, vinculado y coherente con Vault.
        if report.database:
            try:
                anchor, problem = await verify_admin_anchor(
                    session_factory,
                    vault,
                    self._settings,
                    check_vault_side=report.vault_unsealed
                    and report.vault_technical_credential,
                )
                if anchor is not None and problem is None:
                    report.admin_linked = True
                    await self.set_anchor(anchor)
                elif problem:
                    details.append(problem)
            except StartupPreconditionError as exc:
                details.append(str(exc))
            except Exception as exc:  # noqa: BLE001
                details.append(f"admin: {sanitize_vault_message(str(exc), limit=160)}")

        report.detail = "; ".join(details) if details else None
        self._report = report
        return report


async def load_admin_candidates(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[Any]:
    async with session_factory() as session:
        return list(await users_repo.linked_active_admins(session))


async def verify_admin_anchor(
    session_factory: async_sessionmaker[AsyncSession],
    vault: VaultClient,
    settings: Settings,
    *,
    check_vault_side: bool,
) -> tuple[AdminAnchor | None, str | None]:
    """Comprueba la precondicion del administrador.

    Devuelve ``(anchor, problema)``. Lanza ``StartupPreconditionError`` solo
    cuando el fallo NO se arregla solo (no hay administrador, o el vinculo
    almacenado es incoherente consigo mismo).
    """
    candidates = await load_admin_candidates(session_factory)
    if not candidates:
        raise StartupPreconditionError(
            "no hay ningun administrador de aplicacion activo con rol 'admin' y "
            "vinculo a Vault en employees.user_vault_identity. "
            "Ejecuta primero el bootstrap del administrador en Vault "
            "(docker compose exec vault-service vpg-auth-bootstrap) y su "
            "insercion y vinculacion en PostgreSQL "
            "(bash scripts/postgres/seed-initial-user.sh). "
            "FastAPI no crea administradores ni ejecuta semillas."
        )

    admin = candidates[0]
    identity = admin.vault_identity
    config = identity.auth_config if identity is not None else None
    if identity is None or config is None:
        raise StartupPreconditionError(
            f"el administrador '{admin.username}' no tiene configuracion de "
            "autenticacion Vault asociada (employees.vault_auth_config). "
            "Vuelve a ejecutar bash scripts/postgres/seed-initial-user.sh."
        )

    if identity.vault_username != identity.vault_username.lower():
        raise StartupPreconditionError(
            "el vinculo del administrador tiene vault_username con mayusculas; "
            "userpass normaliza a minusculas y el alias no coincidiria."
        )

    anchor = AdminAnchor(
        user_id=admin.id,
        username=admin.username,
        vault_username=identity.vault_username,
        entity_id=identity.vault_entity_id,
        userpass_path=config.userpass_path,
        userpass_accessor=config.userpass_accessor,
        totp_method_id=config.totp_method_id,
        mfa_enforcement_name=config.mfa_enforcement_name,
        totp_status=identity.totp_status,
    )

    if not check_vault_side:
        # Vault no esta disponible todavia: no se puede confirmar el lado
        # remoto, pero eso NO es un fallo de provisionamiento.
        return anchor, "vault: pendiente de comprobar el vinculo del administrador"

    # --- lado Vault --------------------------------------------------------
    try:
        accessor = await vault.userpass_accessor()
        if accessor != anchor.userpass_accessor:
            return anchor, (
                f"el accessor de userpass en Vault ({accessor}) no coincide con el "
                f"registrado ({anchor.userpass_accessor}): el montaje se recreo. "
                "Repite bash scripts/postgres/seed-initial-user.sh."
            )

        entity_id = await vault.lookup_entity_by_alias(anchor.vault_username, accessor)
        if entity_id is None:
            return anchor, (
                f"Vault no tiene entidad para el alias '{anchor.vault_username}' en "
                f"{anchor.userpass_path}/. Ejecuta vpg-auth-bootstrap."
            )
        if entity_id != str(anchor.entity_id):
            return anchor, (
                "el entity_id del administrador en Vault no coincide con el "
                "registrado en PostgreSQL: la entidad se recreo. Revisa "
                "employees.user_vault_identity antes de tocar nada."
            )

        method_id = await vault.totp_method_id()
        if method_id != str(anchor.totp_method_id):
            return anchor, (
                f"el method_id del metodo TOTP '{settings.vault_mfa_method_name}' "
                "cambio respecto al registrado. Repite seed-initial-user.sh."
            )

        enforcement = await vault.mfa_enforcement()
        accessors = [str(a) for a in (enforcement.get("auth_method_accessors") or [])]
        methods = [str(m) for m in (enforcement.get("mfa_method_ids") or [])]
        restricted = bool(enforcement.get("identity_entity_ids")) or bool(
            enforcement.get("identity_group_ids")
        )
        if accessor not in accessors or method_id not in methods or restricted:
            return anchor, (
                f"el enforcement '{anchor.mfa_enforcement_name}' no cubre todo el "
                f"montaje {anchor.userpass_path}/ con el metodo TOTP esperado."
            )
    except VaultSealed as exc:
        return anchor, f"vault: {exc.message}"
    except VaultUnavailable as exc:
        return anchor, f"vault: {exc.message}"
    except VaultError as exc:
        # Un 403 NO significa que el recurso no exista: se reporta como lo que
        # es, un problema de permisos de la cuenta tecnica.
        return anchor, f"vault: {exc.message}"

    return anchor, None
