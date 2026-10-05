"""Operaciones que tocan Vault y PostgreSQL a la vez.

Principio rector: **una transaccion de PostgreSQL no revierte Vault.** De ahi
todo lo demas:

* Ninguna transaccion de base de datos permanece abierta durante una llamada de
  red. Cada metodo abre transacciones cortas: validar y registrar la operacion,
  llamar a Vault, registrar el resultado.
* Cada fase se escribe en ``employees.vault_operations`` antes de seguir, para
  que un fallo a mitad deje por escrito que quedo hecho en Vault.
* Nada se reintenta solo. Login, TOTP y generacion de semillas no son
  idempotentes y un reintento automatico puede dejar peor el sistema.
* Si Vault ya cambio y PostgreSQL no puede reflejarlo, la respuesta **no** es
  201/204: es 409 con el ``operation_id`` para reconciliar.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    NotFoundError,
    PartialOperationError,
    UpstreamUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.vault import (
    VaultClient,
    VaultError,
    VaultNotFound,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)
from app.models.employees import UserVaultIdentity, VaultAuthConfig
from app.repositories import operations as ops_repo
from app.repositories import users as repo

logger = get_logger(__name__)


@dataclass(slots=True)
class ProvisionResult:
    operation_id: uuid.UUID
    user_id: uuid.UUID
    vault_username: str
    vault_entity_id: uuid.UUID
    totp_status: str
    enrollment_uri: str | None


@dataclass(slots=True)
class DeactivationResult:
    operation_id: uuid.UUID
    sessions_invalidated: int
    vault_tokens_revoked: int
    entity_disabled: bool
    warning: str | None


class VaultSyncService:
    def __init__(
        self,
        *,
        vault: VaultClient,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._vault = vault
        self._settings = settings
        self._session_factory = session_factory

    # -- utilidades ----------------------------------------------------------

    async def _phase(
        self, operation_id: uuid.UUID, name: str, system: str, state: str,
        detail: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await ops_repo.add_phase(
                session, operation_id, name=name, system=system, state=state, detail=detail
            )
            await session.commit()

    async def _finish(
        self, operation_id: uuid.UUID, status: str, error: str | None = None
    ) -> None:
        async with self._session_factory() as session:
            await ops_repo.finish(session, operation_id, status=status, error=error)
            await session.commit()

    async def _ensure_auth_config(self, session: AsyncSession) -> VaultAuthConfig:
        """Configuracion compartida de userpass + TOTP, consultada a Vault.

        No se copian UUID ni accessors de ejemplos: se leen de los recursos
        reales y se comparan con lo registrado.
        """
        settings = self._settings
        config = await repo.get_vault_auth_config(session, settings.vault_userpass_path)
        if config is None:
            raise ConflictError(
                "no hay configuracion de autenticacion Vault registrada. "
                "Ejecuta bash scripts/postgres/seed-initial-user.sh",
                code="vault_config_missing",
            )

        accessor = await self._vault.userpass_accessor()
        if accessor != config.userpass_accessor:
            raise ConflictError(
                "el accessor de userpass en Vault no coincide con el registrado: "
                "el montaje se recreo. Revisa employees.vault_auth_config antes de "
                "provisionar a nadie.",
                code="accessor_mismatch",
            )
        return config

    def _resolve_policy(self, requested: str | None) -> str:
        """Allowlist estricta: el cuerpo HTTP nunca elige una politica libre."""
        policy = requested or self._settings.vault_default_user_policy
        if policy not in self._settings.vault_assignable_policies:
            raise ValidationError(
                f"la politica '{policy}' no esta en la lista aprobada del servicio",
                context={"allowed": self._settings.vault_assignable_policies},
            )
        return policy

    # -- 1. provisionar ------------------------------------------------------

    async def provision(
        self,
        *,
        user_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        vault_username: str | None,
        initial_password: str,
        policy: str | None,
        idempotency_key: str | None,
    ) -> ProvisionResult:
        policy_name = self._resolve_policy(policy)

        # --- transaccion 1: validar y abrir la operacion --------------------
        async with self._session_factory() as session:
            user = await repo.get_by_id(session, user_id)
            if user is None:
                raise NotFoundError("no existe ese empleado")
            if not user.is_active:
                raise ConflictError("no se provisiona acceso a un empleado desactivado")

            existing = await repo.get_vault_identity(session, user_id)
            if existing is not None:
                raise ConflictError(
                    "este empleado ya tiene identidad en Vault. Para sustituir su "
                    "segundo factor usa el reset explicito de MFA.",
                    code="already_provisioned",
                    context={"vault_username": existing.vault_username},
                )

            username = (vault_username or user.username).lower()
            clash = await repo.get_vault_identity_by_username(session, username)
            if clash is not None:
                raise ConflictError(
                    "ese usuario de Vault ya esta vinculado a otro empleado",
                    code="vault_username_taken",
                )

            config = await self._ensure_auth_config(session)
            operation = await ops_repo.start(
                session,
                operation_type="vault_provision",
                target_user_id=user_id,
                target_username=user.username,
                actor_user_id=actor_user_id,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            replayed = operation.status in ("succeeded", "failed", "needs_reconciliation")
            accessor = config.userpass_accessor
            config_id = config.id
            await session.commit()

        if replayed:
            # Misma Idempotency-Key: no se vuelve a ejecutar nada. El URI de
            # enrolamiento NO se reenvia: solo se entrega una vez.
            raise ConflictError(
                "esa Idempotency-Key ya se uso; consulta la operacion original",
                code="idempotency_replay",
                context={"operation_id": str(operation_id)},
            )

        # --- llamadas a Vault, sin transaccion abierta -----------------------
        entity_id: str | None = None
        created_user = False
        created_entity = False
        enrollment_uri: str | None = None
        try:
            if await self._vault.userpass_user_exists(username):
                raise ConflictError(
                    f"ya existe la cuenta userpass '{username}' en Vault y no esta "
                    "vinculada aqui. Revisala a mano antes de provisionar.",
                    code="vault_user_exists",
                )

            await self._vault.create_userpass_user(
                username, initial_password, [policy_name]
            )
            created_user = True
            await self._phase(operation_id, "userpass_user_created", "vault", "done")

            entity_id = await self._vault.lookup_entity_by_alias(username, accessor)
            if entity_id is None:
                entity_id = await self._vault.create_entity(
                    f"vpg-{username}", {"role": "employee", "source": "user-mgmt"}
                )
                await self._vault.create_entity_alias(username, entity_id, accessor)
                created_entity = True
                await self._phase(operation_id, "entity_and_alias_created", "vault", "done")
            else:
                await self._phase(operation_id, "entity_reused", "vault", "done")

            method_id = await self._vault.totp_method_id()
            enrollment_uri = await self._vault.generate_totp(method_id, entity_id)
            await self._phase(operation_id, "totp_generated", "vault", "done")

        except ConflictError:
            await self._finish(operation_id, "failed", "conflicto previo a tocar Vault")
            raise
        except (VaultSealed, VaultUnavailable) as exc:
            await self._phase(operation_id, "vault_unavailable", "vault", "error", exc.message)
            await self._compensate_provision(
                operation_id, username, entity_id, created_user, created_entity
            )
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultError as exc:
            await self._phase(operation_id, "vault_error", "vault", "error", exc.message)
            await self._compensate_provision(
                operation_id, username, entity_id, created_user, created_entity
            )
            await self._finish(operation_id, "failed", exc.message)
            raise ConflictError(
                f"Vault rechazo el provisionamiento: {exc.message}",
                code="vault_rejected",
                context={"operation_id": str(operation_id)},
            ) from exc
        finally:
            del initial_password

        assert entity_id is not None

        # --- transaccion 2: registrar el vinculo ----------------------------
        try:
            async with self._session_factory() as session:
                session.add(
                    UserVaultIdentity(
                        user_id=user_id,
                        vault_auth_config_id=config_id,
                        vault_username=username,
                        vault_entity_id=uuid.UUID(entity_id),
                        totp_status="pending",
                        totp_generated_at=dt.datetime.now(dt.UTC),
                    )
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            detail = sanitize_vault_message(str(exc), limit=200)
            await self._phase(operation_id, "link_persisted", "postgres", "error", detail)
            await self._finish(
                operation_id,
                "needs_reconciliation",
                "Vault ya tiene cuenta, entidad y semilla TOTP, pero PostgreSQL no "
                f"registro el vinculo: {detail}",
            )
            # Vault YA cambio: no se puede deshacer la semilla sin destruirla, y
            # destruirla dejaria al usuario sin el enrolamiento que quiza ya
            # registro. Se devuelve 409, no 201.
            raise PartialOperationError(
                "Vault quedo provisionado pero PostgreSQL no registro el vinculo. "
                "La operacion esta marcada para reconciliacion; no se repite sola.",
                context={
                    "operation_id": str(operation_id),
                    "vault_username": username,
                    "vault_entity_id": entity_id,
                },
            ) from exc

        await self._phase(operation_id, "link_persisted", "postgres", "done")
        await self._finish(operation_id, "succeeded")
        logger.info(
            "provisionamiento completado",
            extra={"operation": "vault_provision", "target": str(user_id), "status": "ok"},
        )

        return ProvisionResult(
            operation_id=operation_id,
            user_id=user_id,
            vault_username=username,
            vault_entity_id=uuid.UUID(entity_id),
            totp_status="pending",
            enrollment_uri=enrollment_uri,
        )

    async def _compensate_provision(
        self,
        operation_id: uuid.UUID,
        username: str,
        entity_id: str | None,
        created_user: bool,
        created_entity: bool,
    ) -> None:
        """Compensacion segura: deshace SOLO lo que creo esta operacion."""
        if created_user:
            try:
                await self._vault.delete_userpass_user(username)
                await self._phase(operation_id, "compensate_userpass", "vault", "done")
            except VaultError as exc:
                await self._phase(
                    operation_id, "compensate_userpass", "vault", "error", exc.message
                )
        if created_entity and entity_id:
            try:
                await self._vault.delete_entity(entity_id)
                await self._phase(operation_id, "compensate_entity", "vault", "done")
            except VaultError as exc:
                await self._phase(
                    operation_id, "compensate_entity", "vault", "error", exc.message
                )

    # -- 3. credenciales ------------------------------------------------------

    async def change_credentials(
        self,
        *,
        user_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        new_username: str | None,
        new_password: str | None,
        idempotency_key: str | None,
    ) -> uuid.UUID:
        if new_username is None and new_password is None:
            raise ValidationError("indica new_vault_username, new_password o ambos")

        async with self._session_factory() as session:
            user = await repo.get_by_id(session, user_id)
            if user is None:
                raise NotFoundError("no existe ese empleado")
            identity = await repo.get_vault_identity(session, user_id)
            if identity is None:
                raise ConflictError(
                    "el empleado no tiene identidad en Vault; provisionala primero",
                    code="not_provisioned",
                )
            if new_username and new_username != identity.vault_username:
                clash = await repo.get_vault_identity_by_username(session, new_username)
                if clash is not None:
                    raise ConflictError(
                        "ese usuario de Vault ya esta en uso", code="vault_username_taken"
                    )

            config = await self._ensure_auth_config(session)
            operation = await ops_repo.start(
                session,
                operation_type="vault_credentials",
                target_user_id=user_id,
                target_username=user.username,
                actor_user_id=actor_user_id,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            old_username = identity.vault_username
            entity_id = str(identity.vault_entity_id)
            accessor = config.userpass_accessor
            await session.commit()

        try:
            # --- contrasena ------------------------------------------------
            if new_password is not None:
                await self._vault.set_userpass_password(old_username, new_password)
                await self._phase(operation_id, "password_changed", "vault", "done")

            # --- cambio de nombre -------------------------------------------
            if new_username and new_username != old_username:
                if new_password is None:
                    # Vault no tiene "rename" de userpass: hay que crear la
                    # cuenta nueva, y eso exige una contrasena. No se inventa
                    # ninguna ni se reutiliza la anterior (no se conoce).
                    await self._finish(
                        operation_id,
                        "failed",
                        "cambio de username sin contrasena nueva",
                    )
                    raise ValidationError(
                        "Vault no permite renombrar una cuenta userpass conservando "
                        "su contrasena: no la almacena en claro y este servicio "
                        "tampoco. Para cambiar el username envia tambien "
                        "new_password en la misma peticion.",
                        code="rename_requires_password",
                    )

                policies = [self._settings.vault_default_user_policy]
                await self._vault.create_userpass_user(
                    new_username, new_password, policies
                )
                await self._phase(operation_id, "new_userpass_created", "vault", "done")

                # El alias se repunta a la MISMA entidad: asi se conservan el
                # entity_id y la semilla TOTP ya registrada por la persona.
                entity = await self._vault.read_entity(entity_id)
                alias_id = ""
                for alias in entity.get("aliases") or []:
                    if alias.get("mount_accessor") == accessor:
                        alias_id = str(alias.get("id") or "")
                        break
                if not alias_id:
                    raise VaultError(
                        "la entidad no tiene alias en el montaje userpass esperado"
                    )
                await self._vault.update_entity_alias(
                    alias_id, new_username, entity_id, accessor
                )
                await self._phase(operation_id, "alias_repointed", "vault", "done")

                # Solo ahora se borra la cuenta vieja: hasta aqui todo era
                # reversible. Esto es lo que impide entrar con el nombre anterior.
                await self._vault.delete_userpass_user(old_username)
                await self._phase(operation_id, "old_userpass_deleted", "vault", "done")

        except ValidationError:
            raise
        except (VaultSealed, VaultUnavailable) as exc:
            await self._finish(operation_id, "needs_reconciliation", exc.message)
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultError as exc:
            await self._finish(operation_id, "needs_reconciliation", exc.message)
            raise PartialOperationError(
                f"el cambio de credenciales quedo a medias en Vault: {exc.message}",
                context={"operation_id": str(operation_id)},
            ) from exc
        finally:
            if new_password is not None:
                del new_password

        if new_username and new_username != old_username:
            try:
                async with self._session_factory() as session:
                    identity = await repo.get_vault_identity(session, user_id)
                    if identity is not None:
                        identity.vault_username = new_username
                    await session.commit()
            except Exception as exc:  # noqa: BLE001
                await self._finish(
                    operation_id,
                    "needs_reconciliation",
                    "Vault ya usa el username nuevo pero PostgreSQL conserva el "
                    f"anterior: {sanitize_vault_message(str(exc), limit=160)}",
                )
                raise PartialOperationError(
                    "Vault ya usa el username nuevo pero PostgreSQL no lo reflejo",
                    context={"operation_id": str(operation_id)},
                ) from exc
            await self._phase(operation_id, "link_username_updated", "postgres", "done")

        await self._finish(operation_id, "succeeded")
        return operation_id

    # -- 4. reset de MFA ------------------------------------------------------

    async def reset_mfa(
        self,
        *,
        user_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        reason: str,
        idempotency_key: str | None,
        revoke_sessions,
    ) -> tuple[uuid.UUID, str | None]:
        """Destruye y regenera la semilla TOTP de **esa** entidad.

        El metodo TOTP y el enforcement son compartidos y no se tocan. Las demas
        personas no se ven afectadas.
        """
        async with self._session_factory() as session:
            user = await repo.get_by_id(session, user_id)
            if user is None:
                raise NotFoundError("no existe ese empleado")
            identity = await repo.get_vault_identity(session, user_id)
            if identity is None:
                raise ConflictError(
                    "el empleado no tiene identidad en Vault", code="not_provisioned"
                )
            operation = await ops_repo.start(
                session,
                operation_type="mfa_reset",
                target_user_id=user_id,
                target_username=user.username,
                actor_user_id=actor_user_id,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            entity_id = str(identity.vault_entity_id)
            await session.commit()

        logger.info(
            "reset de MFA solicitado",
            extra={
                "operation": "mfa_reset",
                "target": str(user_id),
                "reason_length": len(reason),
            },
        )

        enrollment_uri: str | None = None
        try:
            method_id = await self._vault.totp_method_id()
            await self._vault.destroy_totp(method_id, entity_id)
            await self._phase(operation_id, "totp_destroyed", "vault", "done")
            enrollment_uri = await self._vault.generate_totp(method_id, entity_id)
            await self._phase(operation_id, "totp_regenerated", "vault", "done")
        except (VaultSealed, VaultUnavailable) as exc:
            await self._finish(operation_id, "needs_reconciliation", exc.message)
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultError as exc:
            await self._finish(operation_id, "needs_reconciliation", exc.message)
            raise PartialOperationError(
                f"el reset de MFA quedo a medias: {exc.message}. "
                "La semilla anterior puede estar ya destruida.",
                context={"operation_id": str(operation_id)},
            ) from exc

        # Las sesiones del objetivo dejan de valer: su segundo factor cambio.
        invalidated, revoked = await revoke_sessions(user_id)

        try:
            async with self._session_factory() as session:
                identity = await repo.get_vault_identity(session, user_id)
                if identity is not None:
                    identity.totp_status = "reset_required"
                    identity.totp_generated_at = dt.datetime.now(dt.UTC)
                    # Se limpia la confirmacion vigente: el enrolamiento anterior
                    # ya no sirve y el nuevo aun no se ha demostrado.
                    identity.totp_confirmed_at = None
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._finish(
                operation_id,
                "needs_reconciliation",
                "Vault ya tiene semilla nueva pero PostgreSQL conserva el estado "
                f"anterior: {sanitize_vault_message(str(exc), limit=160)}",
            )
            raise PartialOperationError(
                "la semilla se regenero en Vault pero PostgreSQL no reflejo el reset",
                context={"operation_id": str(operation_id)},
            ) from exc

        await self._phase(operation_id, "status_reset_required", "postgres", "done")
        await self._phase(
            operation_id,
            "sessions_revoked",
            "vault",
            "done",
            f"invalidadas={invalidated} revocadas={revoked}",
        )
        await self._finish(operation_id, "succeeded")
        return operation_id, enrollment_uri

    # -- 5. baja logica -------------------------------------------------------

    async def deactivate(
        self, *, user_id: uuid.UUID, actor_user_id: uuid.UUID, revoke_sessions
    ) -> DeactivationResult:
        async with self._session_factory() as session:
            user = await repo.get_by_id(session, user_id)
            if user is None:
                raise NotFoundError("no existe ese empleado")
            from app.services.users import assert_can_deactivate

            await assert_can_deactivate(session, user)
            identity = await repo.get_vault_identity(session, user_id)
            operation = await ops_repo.start(
                session,
                operation_type="user_deactivate",
                target_user_id=user_id,
                target_username=user.username,
                actor_user_id=actor_user_id,
                idempotency_key=None,
            )
            operation_id = operation.operation_id
            entity_id = str(identity.vault_entity_id) if identity is not None else None
            user.is_active = False
            await session.commit()

        await self._phase(operation_id, "is_active_false", "postgres", "done")

        invalidated, revoked = await revoke_sessions(user_id)
        entity_disabled = False
        warning: str | None = None

        if entity_id is None:
            warning = (
                "El empleado no tenia identidad en Vault: solo se desactivo en "
                "PostgreSQL. Desactivar aqui NO bloquea por si solo un acceso "
                "directo a Vault."
            )
        else:
            try:
                # Deshabilitar la entidad bloquea TAMBIEN los tokens ya emitidos,
                # cosa que borrar sesiones de memoria no hace.
                await self._vault.set_entity_disabled(entity_id, True)
                entity_disabled = True
                await self._phase(operation_id, "entity_disabled", "vault", "done")
            except (VaultSealed, VaultUnavailable) as exc:
                warning = (
                    f"El empleado quedo inactivo en PostgreSQL, pero su entidad de "
                    f"Vault NO se pudo deshabilitar ({exc.message}). La baja NO esta "
                    "completa: todavia puede autenticarse en Vault."
                )
                await self._phase(operation_id, "entity_disabled", "vault", "error", exc.message)
                await self._finish(operation_id, "needs_reconciliation", warning)
                return DeactivationResult(
                    operation_id, invalidated, revoked, False, warning
                )
            except VaultError as exc:
                warning = (
                    f"La entidad de Vault no se pudo deshabilitar: {exc.message}. "
                    "La baja NO esta completa."
                )
                await self._phase(operation_id, "entity_disabled", "vault", "error", exc.message)
                await self._finish(operation_id, "needs_reconciliation", warning)
                return DeactivationResult(
                    operation_id, invalidated, revoked, False, warning
                )

        await self._phase(
            operation_id,
            "sessions_revoked",
            "vault",
            "done",
            f"invalidadas={invalidated} revocadas={revoked}",
        )
        await self._finish(operation_id, "succeeded")
        return DeactivationResult(operation_id, invalidated, revoked, entity_disabled, warning)

    # -- 6. purga --------------------------------------------------------------

    async def purge(
        self,
        *,
        user_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        idempotency_key: str | None,
        revoke_sessions,
    ) -> uuid.UUID:
        async with self._session_factory() as session:
            user = await repo.get_by_id(session, user_id)
            if user is None:
                raise NotFoundError("no existe ese empleado")
            if user.is_active:
                raise ConflictError(
                    "solo se purga un empleado ya desactivado; haz antes la baja logica",
                    code="must_deactivate_first",
                )
            identity = await repo.get_vault_identity(session, user_id)
            operation = await ops_repo.start(
                session,
                operation_type="user_purge",
                target_user_id=user_id,
                target_username=user.username,
                actor_user_id=actor_user_id,
                idempotency_key=idempotency_key,
            )
            operation_id = operation.operation_id
            entity_id = str(identity.vault_entity_id) if identity is not None else None
            vault_username = identity.vault_username if identity is not None else None
            accessor = identity.auth_config.userpass_accessor if identity is not None else None
            await session.commit()

        await revoke_sessions(user_id)

        if entity_id is not None and accessor is not None:
            try:
                entity = await self._vault.read_entity(entity_id)
                aliases = entity.get("aliases") or []
                # Si la entidad tiene identidades de OTROS montajes o de otras
                # personas, borrarla destruiria accesos ajenos: se detiene.
                foreign = [
                    a for a in aliases
                    if a.get("mount_accessor") != accessor
                    or (vault_username and a.get("name") != vault_username)
                ]
                if foreign:
                    await self._finish(
                        operation_id,
                        "failed",
                        "la entidad tiene alias ajenos; purga detenida",
                    )
                    raise ConflictError(
                        "la entidad de Vault de este empleado tiene ademas alias de "
                        "otros montajes o nombres. Borrarla afectaria a accesos que "
                        "no son suyos, asi que la purga se detiene. Revisala a mano.",
                        code="entity_has_foreign_aliases",
                        context={
                            "operation_id": str(operation_id),
                            "foreign_alias_count": len(foreign),
                        },
                    )

                for alias in aliases:
                    alias_id = str(alias.get("id") or "")
                    if alias_id:
                        await self._vault.delete_entity_alias(alias_id)
                await self._phase(operation_id, "aliases_deleted", "vault", "done")

                if vault_username:
                    await self._vault.delete_userpass_user(vault_username)
                    await self._phase(operation_id, "userpass_deleted", "vault", "done")

                # Borrar la entidad arrastra SU enrolamiento TOTP. El metodo
                # compartido, el enforcement y los secretos SAT no se tocan.
                await self._vault.delete_entity(entity_id)
                await self._phase(operation_id, "entity_deleted", "vault", "done")
            except ConflictError:
                raise
            except (VaultSealed, VaultUnavailable) as exc:
                await self._finish(operation_id, "needs_reconciliation", exc.message)
                raise UpstreamUnavailableError(
                    f"Vault no esta disponible; la purga se detuvo: {exc.message}"
                ) from exc
            except VaultError as exc:
                await self._finish(operation_id, "needs_reconciliation", exc.message)
                raise PartialOperationError(
                    f"la purga en Vault quedo a medias: {exc.message}",
                    context={"operation_id": str(operation_id)},
                ) from exc

        try:
            async with self._session_factory() as session:
                await repo.delete_user(session, user_id)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._finish(
                operation_id,
                "needs_reconciliation",
                "Vault ya quedo limpio pero PostgreSQL conserva el agregado: "
                f"{sanitize_vault_message(str(exc), limit=160)}",
            )
            raise PartialOperationError(
                "los recursos de Vault se borraron pero el agregado sigue en PostgreSQL",
                context={"operation_id": str(operation_id)},
            ) from exc

        # El registro de la operacion sobrevive: target_user_id pasa a NULL por
        # ON DELETE SET NULL, pero target_username queda como auditoria minima.
        await self._phase(operation_id, "aggregate_deleted", "postgres", "done")
        await self._finish(operation_id, "succeeded")
        return operation_id

    # -- 2. lectura -----------------------------------------------------------

    async def describe_identity(self, user_id: uuid.UUID) -> dict[str, object]:
        """Solo lectura. **Nunca** genera, destruye ni reinicia TOTP."""
        async with self._session_factory() as session:
            identity = await repo.get_vault_identity(session, user_id)
            if identity is None:
                raise NotFoundError("el empleado no tiene identidad en Vault")
            return {
                "vault_username": identity.vault_username,
                "vault_entity_id": str(identity.vault_entity_id),
                "totp_status": identity.totp_status,
                "totp_generated_at": identity.totp_generated_at,
                "totp_confirmed_at": identity.totp_confirmed_at,
                "last_mfa_login_at": identity.last_mfa_login_at,
            }

    async def access_check(self, vault_token: str, resource: str) -> tuple[str, tuple[str, ...]]:
        """Evalua una ruta con el token HUMANO, nunca con la credencial tecnica."""
        path = self._settings.vault_access_check_paths.get(resource)
        if path is None:
            raise ValidationError(
                f"recurso desconocido: '{resource}'",
                context={"allowed": sorted(self._settings.vault_access_check_paths)},
            )
        try:
            capabilities = await self._vault.capabilities_self(vault_token, path)
            result = await self._vault.can_read_path(vault_token, path)
        except (VaultSealed, VaultUnavailable) as exc:
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultNotFound:
            return "autorizada_pero_sin_datos", ()
        return result, capabilities
