"""Sesiones API y desafios MFA, **solo en memoria**.

Decisiones deliberadas:

* El cliente recibe un identificador **opaco** sin relacion matematica con el
  token de Vault. El token de Vault nunca sale de este proceso.
* Nada de esto se guarda en PostgreSQL. Reiniciar el worker invalida todas las
  sesiones: es el precio de no tener almacen compartido y esta documentado.
* Hay TTL, tope de entradas y limpieza periodica, para que el diccionario no
  crezca sin limite.

**Limitacion conocida:** con un solo worker esto es correcto. Con varios workers
o replicas cada proceso tendria su propio diccionario y una sesion solo
funcionaria en el proceso que la creo. Ese escenario exige otro diseno (almacen
compartido); no se aborda en esta etapa.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import secrets
import uuid
from dataclasses import dataclass, field

from app.core.vault import VaultSession


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@dataclass(slots=True)
class PendingChallenge:
    """Login con contrasena correcta, pendiente del segundo factor."""

    challenge_id: str
    username: str
    mfa_request_id: str = field(repr=False)
    method_id: str
    expected_user_id: uuid.UUID | None
    expected_entity_id: str | None
    expires_at: dt.datetime
    attempts: int = 0

    @property
    def expired(self) -> bool:
        return _now() >= self.expires_at


@dataclass(slots=True)
class ApiSession:
    """Sesion API viva. Guarda el token de Vault, que jamas se devuelve."""

    session_id: str = field(repr=False)
    user_id: uuid.UUID
    username: str
    vault_token: str = field(repr=False)
    vault_accessor: str = field(repr=False)
    entity_id: str
    vault_policies: tuple[str, ...]
    mfa_verified_at: dt.datetime
    expires_at: dt.datetime
    last_seen_at: dt.datetime

    @property
    def expired(self) -> bool:
        return _now() >= self.expires_at

    def mfa_age_seconds(self) -> float:
        return (_now() - self.mfa_verified_at).total_seconds()


class SessionStore:
    """Almacen en memoria de desafios y sesiones, con TTL y tope."""

    def __init__(
        self,
        *,
        session_ttl_seconds: int,
        challenge_ttl_seconds: int,
        max_sessions: int,
        max_challenges: int,
    ) -> None:
        self._session_ttl = session_ttl_seconds
        self._challenge_ttl = challenge_ttl_seconds
        self._max_sessions = max_sessions
        self._max_challenges = max_challenges
        self._sessions: dict[str, ApiSession] = {}
        self._challenges: dict[str, PendingChallenge] = {}
        self._lock = asyncio.Lock()

    # -- desafios ------------------------------------------------------------

    async def create_challenge(
        self,
        *,
        username: str,
        mfa_request_id: str,
        method_id: str,
        expected_user_id: uuid.UUID | None,
        expected_entity_id: str | None,
    ) -> PendingChallenge:
        async with self._lock:
            self._purge_locked()
            if len(self._challenges) >= self._max_challenges:
                # Descarta el mas antiguo antes que rechazar logins legitimos.
                oldest = min(self._challenges.values(), key=lambda c: c.expires_at)
                self._challenges.pop(oldest.challenge_id, None)

            challenge = PendingChallenge(
                challenge_id=secrets.token_urlsafe(24),
                username=username,
                mfa_request_id=mfa_request_id,
                method_id=method_id,
                expected_user_id=expected_user_id,
                expected_entity_id=expected_entity_id,
                expires_at=_now() + dt.timedelta(seconds=self._challenge_ttl),
            )
            self._challenges[challenge.challenge_id] = challenge
            return challenge

    async def pop_challenge(self, challenge_id: str) -> PendingChallenge | None:
        async with self._lock:
            challenge = self._challenges.pop(challenge_id, None)
            if challenge is None or challenge.expired:
                return None
            return challenge

    # -- sesiones ------------------------------------------------------------

    async def create_session(
        self,
        *,
        user_id: uuid.UUID,
        username: str,
        vault: VaultSession,
    ) -> ApiSession:
        async with self._lock:
            self._purge_locked()
            if len(self._sessions) >= self._max_sessions:
                oldest = min(self._sessions.values(), key=lambda s: s.expires_at)
                self._sessions.pop(oldest.session_id, None)

            now = _now()
            # El TTL efectivo nunca supera al del token de Vault.
            ttl = self._session_ttl
            if vault.lease_duration:
                ttl = min(ttl, vault.lease_duration)

            session = ApiSession(
                session_id=secrets.token_urlsafe(32),
                user_id=user_id,
                username=username,
                vault_token=vault.client_token,
                vault_accessor=vault.accessor,
                entity_id=vault.entity_id,
                vault_policies=vault.policies,
                mfa_verified_at=now,
                expires_at=now + dt.timedelta(seconds=ttl),
                last_seen_at=now,
            )
            self._sessions[session.session_id] = session
            return session

    async def get_session(self, session_id: str) -> ApiSession | None:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expired:
                self._sessions.pop(session_id, None)
                return None
            session.last_seen_at = _now()
            return session

    async def pop_session(self, session_id: str) -> ApiSession | None:
        async with self._lock:
            return self._sessions.pop(session_id, None)

    async def sessions_for_user(self, user_id: uuid.UUID) -> list[ApiSession]:
        async with self._lock:
            return [s for s in self._sessions.values() if s.user_id == user_id]

    async def drop_sessions_for_user(self, user_id: uuid.UUID) -> list[ApiSession]:
        """Invalida en memoria todas las sesiones de un usuario y las devuelve.

        Devolverlas permite al llamador revocar ademas sus tokens en Vault:
        quitarlas de aqui no revoca nada por si solo.
        """
        async with self._lock:
            victims = [s for s in self._sessions.values() if s.user_id == user_id]
            for session in victims:
                self._sessions.pop(session.session_id, None)
            return victims

    # -- mantenimiento -------------------------------------------------------

    def _purge_locked(self) -> None:
        for key, session in list(self._sessions.items()):
            if session.expired:
                self._sessions.pop(key, None)
        for key, challenge in list(self._challenges.items()):
            if challenge.expired:
                self._challenges.pop(key, None)

    async def purge(self) -> None:
        async with self._lock:
            self._purge_locked()

    async def snapshot_counts(self) -> dict[str, int]:
        async with self._lock:
            return {"sessions": len(self._sessions), "challenges": len(self._challenges)}

    async def all_sessions(self) -> list[ApiSession]:
        async with self._lock:
            return list(self._sessions.values())

    async def clear(self) -> list[ApiSession]:
        async with self._lock:
            victims = list(self._sessions.values())
            self._sessions.clear()
            self._challenges.clear()
            return victims
