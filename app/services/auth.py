"""Login userpass + TOTP delegado a Vault.

El flujo tiene dos pasos porque Vault lo tiene:

1. ``POST auth/{path}/login/{username}`` con la contrasena. Con el enforcement
   activo, Vault responde **sin token** y con un ``mfa_request_id``. Si llegara
   a entregar token en este paso seria un fallo de configuracion del
   enforcement, y asi se trata.
2. ``POST sys/mfa/validate`` con el codigo. Solo entonces hay token.

La contrasena no se conserva en ningun punto: se envia y se descarta. El token
de Vault se guarda en memoria, asociado a un identificador opaco de sesion, y
nunca se devuelve al cliente ni se escribe en PostgreSQL.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ForbiddenError, UnauthenticatedError, UpstreamUnavailableError
from app.core.logging import get_logger
from app.core.security import (
    ApiSession,
    MfaProof,
    PendingChallenge,
    SessionStore,
    StepUpChallenge,
)
from app.core.vault import (
    VaultClient,
    VaultError,
    VaultInvalidCredentials,
    VaultMFAFailed,
    VaultSealed,
    VaultSession,
    VaultUnavailable,
)
from app.repositories import users as repo

logger = get_logger(__name__)


class AuthService:
    def __init__(
        self,
        *,
        vault: VaultClient,
        sessions: SessionStore,
        session_factory: async_sessionmaker[AsyncSession],
        mfa_method_name: str,
        challenge_ttl_seconds: int,
    ) -> None:
        self._vault = vault
        self._sessions = sessions
        self._session_factory = session_factory
        self._mfa_method_name = mfa_method_name
        self._challenge_ttl = challenge_ttl_seconds

    # -- paso 1 --------------------------------------------------------------

    async def begin_login(self, username: str, password: str) -> PendingChallenge:
        async with self._session_factory() as session:
            identity = await repo.get_vault_identity_by_username(session, username)
            user = await repo.get_by_username(session, username)

        try:
            challenge = await self._vault.userpass_login(username, password)
        except VaultInvalidCredentials as exc:
            # Mismo mensaje tanto si el usuario no existe como si la contrasena
            # es incorrecta: no se filtra que usuarios hay dados de alta.
            raise UnauthenticatedError("usuario o contrasena incorrectos") from exc
        except VaultSealed as exc:
            raise UpstreamUnavailableError(
                "Vault esta sellado: desbloquealo (paso manual) y reintenta"
            ) from exc
        except VaultUnavailable as exc:
            raise UpstreamUnavailableError(f"Vault no responde: {exc.message}") from exc
        finally:
            del password

        if challenge.token_issued_without_mfa:
            # Vault entrego token con solo la contrasena. No se usa: se trata
            # como un fallo de configuracion grave y se rechaza el login.
            logger.error(
                "vault emitio token sin exigir MFA",
                extra={"operation": "login", "actor": username},
            )
            raise ForbiddenError(
                "el enforcement MFA no esta cubriendo el montaje userpass; "
                "el login se rechaza por seguridad",
                code="mfa_not_enforced",
            )

        if not challenge.mfa_request_id or not challenge.method_ids:
            raise UpstreamUnavailableError(
                "Vault no devolvio un desafio MFA valido para este usuario"
            )

        return await self._sessions.create_challenge(
            username=username,
            mfa_request_id=challenge.mfa_request_id,
            method_id=challenge.method_ids[0],
            expected_user_id=user.id if user is not None else None,
            expected_entity_id=str(identity.vault_entity_id) if identity is not None else None,
        )

    # -- paso 2 --------------------------------------------------------------

    async def complete_login(
        self, challenge_id: str, code: str
    ) -> tuple[ApiSession, tuple[str, ...]]:
        challenge = await self._sessions.pop_challenge(challenge_id)
        if challenge is None:
            raise UnauthenticatedError(
                "el desafio MFA no existe o ha caducado; repite el login",
                code="challenge_expired",
            )

        try:
            vault_session = await self._vault.mfa_validate(
                challenge.mfa_request_id, challenge.method_id, code
            )
        except VaultMFAFailed as exc:
            # No se reintenta de forma automatica ni se reutiliza el desafio:
            # ya se consumio arriba.
            raise UnauthenticatedError(exc.message, code="mfa_failed") from exc
        except VaultSealed as exc:
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultUnavailable as exc:
            raise UpstreamUnavailableError(f"Vault no responde: {exc.message}") from exc
        finally:
            del code

        return await self._establish_session(challenge.username, vault_session)

    async def _establish_session(
        self, username: str, vault_session: VaultSession
    ) -> tuple[ApiSession, tuple[str, ...]]:
        if not vault_session.entity_id:
            await self._vault.revoke_self(vault_session.client_token)
            raise UpstreamUnavailableError(
                "Vault no devolvio entity_id para la sesion; no se puede verificar "
                "la identidad contra PostgreSQL"
            )

        try:
            entity_uuid = uuid.UUID(vault_session.entity_id)
        except ValueError as exc:
            await self._vault.revoke_self(vault_session.client_token)
            raise UpstreamUnavailableError("entity_id de Vault con formato inesperado") from exc

        async with self._session_factory() as session:
            user = await repo.get_by_username(session, username)
            if user is None:
                await self._vault.revoke_self(vault_session.client_token)
                raise ForbiddenError(
                    "la autenticacion en Vault fue correcta, pero este usuario no "
                    "esta registrado como empleado en PostgreSQL",
                    code="not_provisioned",
                )
            if not user.is_active:
                await self._vault.revoke_self(vault_session.client_token)
                raise ForbiddenError("la cuenta esta desactivada", code="inactive_user")

            identity = await repo.get_vault_identity(session, user.id)
            if identity is None:
                await self._vault.revoke_self(vault_session.client_token)
                raise ForbiddenError(
                    "el empleado no tiene vinculo con Vault registrado",
                    code="not_linked",
                )
            if identity.vault_entity_id != entity_uuid:
                await self._vault.revoke_self(vault_session.client_token)
                logger.error(
                    "entity_id del login distinto del registrado",
                    extra={"operation": "mfa_verify", "target": str(user.id)},
                )
                raise ForbiddenError(
                    "la entidad de Vault no coincide con la registrada para este "
                    "empleado; revisa el vinculo antes de continuar",
                    code="entity_mismatch",
                )

            # Comprobacion de la configuracion esperada antes de tocar el estado.
            config = identity.auth_config
            now = dt.datetime.now(dt.UTC)
            # 'pending' NO bloquea este primer login valido: justo aqui es donde
            # pasa a 'confirmed'. 'confirmed' tampoco omitio el MFA: acabamos de
            # validarlo contra Vault.
            updated = await repo.touch_mfa_login(
                session, user_id=user.id, entity_id=entity_uuid, now=now
            )
            if not updated:
                await self._vault.revoke_self(vault_session.client_token)
                raise ForbiddenError(
                    "no se pudo confirmar el vinculo del empleado", code="link_mismatch"
                )
            await session.commit()

            roles = await repo.role_codes_for(session, user.id)
            logger.info(
                "login MFA correcto",
                extra={
                    "operation": "mfa_verify",
                    "actor": user.username,
                    "target": str(user.id),
                    "status": "ok",
                    "userpass_path": config.userpass_path if config else None,
                },
            )

        api_session = await self._sessions.create_session(
            user_id=user.id, username=user.username, vault=vault_session
        )
        return api_session, roles

    # -- reautenticacion para operaciones destructivas (etapa 4) -------------

    async def begin_step_up(
        self,
        *,
        api_session: ApiSession,
        password: str,
        operation: str,
        collection_id: uuid.UUID | None,
        resource_ids: tuple[uuid.UUID, ...],
    ) -> StepUpChallenge:
        """Paso 1 de la reautenticacion: contrasena del TITULAR de la sesion.

        No se admite reautenticar a nombre de otra persona: el usuario sale de
        la sesion, no del cuerpo. La operacion y el conjunto de recursos quedan
        fijados **antes** de pedir el codigo, de modo que la prueba resultante
        no pueda reutilizarse para otra cosa.
        """
        try:
            challenge = await self._vault.userpass_login(api_session.username, password)
        except VaultInvalidCredentials as exc:
            raise UnauthenticatedError(
                "la contrasena no es correcta", code="step_up_failed"
            ) from exc
        except VaultSealed as exc:
            raise UpstreamUnavailableError(
                "Vault esta sellado: desbloquealo (paso manual) y reintenta"
            ) from exc
        except VaultUnavailable as exc:
            raise UpstreamUnavailableError(f"Vault no responde: {exc.message}") from exc
        finally:
            del password

        if challenge.token_issued_without_mfa:
            logger.error(
                "vault emitio token sin exigir MFA en una reautenticacion",
                extra={"operation": "step_up", "actor": api_session.username},
            )
            raise ForbiddenError(
                "el enforcement MFA no esta cubriendo el montaje userpass; "
                "la reautenticacion se rechaza por seguridad",
                code="mfa_not_enforced",
            )
        if not challenge.mfa_request_id or not challenge.method_ids:
            raise UpstreamUnavailableError(
                "Vault no devolvio un desafio MFA valido para este usuario"
            )

        return await self._sessions.create_step_up(
            session_id=api_session.session_id,
            user_id=api_session.user_id,
            username=api_session.username,
            mfa_request_id=challenge.mfa_request_id,
            method_id=challenge.method_ids[0],
            operation=operation,
            collection_id=collection_id,
            resource_ids=resource_ids,
        )

    async def complete_step_up(self, challenge_id: str, code: str) -> MfaProof:
        """Paso 2: codigo TOTP del titular. Devuelve la prueba breve.

        El codigo se valida **contra Vault**, no contra PostgreSQL: aqui no hay
        semillas ni se comparan digitos. El token que Vault emite al validar no
        se usa para nada y se revoca de inmediato: la sesion ya tiene el suyo y
        dejar vivo otro token humano seria superficie gratuita.
        """
        challenge = await self._sessions.pop_step_up(challenge_id)
        if challenge is None:
            raise UnauthenticatedError(
                "la reautenticacion no existe o ha caducado; repitela",
                code="step_up_expired",
            )

        # La sesion debe seguir viva: una prueba no sobrevive a su sesion.
        live = await self._sessions.get_session(challenge.session_id)
        if live is None:
            raise UnauthenticatedError(
                "la sesion de la reautenticacion ya no existe", code="session_expired"
            )

        try:
            vault_session = await self._vault.mfa_validate(
                challenge.mfa_request_id, challenge.method_id, code
            )
        except VaultMFAFailed as exc:
            raise UnauthenticatedError(exc.message, code="mfa_failed") from exc
        except VaultSealed as exc:
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultUnavailable as exc:
            raise UpstreamUnavailableError(f"Vault no responde: {exc.message}") from exc
        finally:
            del code

        # Comprobacion de identidad: el codigo tiene que ser del titular.
        if (
            vault_session.entity_id
            and live.entity_id
            and vault_session.entity_id != live.entity_id
        ):
            await self._vault.revoke_self(vault_session.client_token)
            logger.error(
                "entity_id de la reautenticacion distinto del de la sesion",
                extra={"operation": "step_up", "target": str(challenge.user_id)},
            )
            raise ForbiddenError(
                "la reautenticacion no corresponde al titular de la sesion",
                code="entity_mismatch",
            )

        await self._vault.revoke_self(vault_session.client_token)

        proof = await self._sessions.create_proof(challenge)
        logger.info(
            "reautenticacion MFA correcta",
            extra={
                "operation": "step_up",
                "actor": challenge.username,
                "target_operation": challenge.operation,
                "resources": len(challenge.resource_ids),
                "status": "ok",
            },
        )
        return proof

    # -- cierre --------------------------------------------------------------

    async def logout(self, session_id: str) -> bool:
        api_session = await self._sessions.pop_session(session_id)
        if api_session is None:
            return False
        revoked = await self._vault.revoke_self(api_session.vault_token)
        if not revoked:
            # Quitarla de memoria no revoca nada en Vault: hay que decirlo.
            logger.warning(
                "sesion cerrada en la API pero el token de Vault no pudo revocarse; "
                "caducara por TTL",
                extra={"operation": "logout", "target": str(api_session.user_id)},
            )
        return True

    async def revoke_user_sessions(self, user_id: uuid.UUID) -> tuple[int, int]:
        """Invalida las sesiones de un usuario y revoca sus tokens en Vault.

        Devuelve ``(invalidadas, revocadas_en_vault)``. Son numeros distintos a
        proposito: deshabilitar o borrar de memoria **no** equivale a revocar.
        """
        victims = await self._sessions.drop_sessions_for_user(user_id)
        revoked = 0
        for victim in victims:
            try:
                if await self._vault.revoke_self(victim.vault_token):
                    revoked += 1
            except VaultError:
                continue
        return len(victims), revoked
