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
class StepUpChallenge:
    """Reautenticacion completa en curso para una operacion destructiva.

    Lleva ya la operacion y el conjunto CERRADO de recursos que autorizara la
    prueba resultante. Fijarlos antes de pedir el codigo es lo que impide que
    una reautenticacion sirva para otra cosa.
    """

    challenge_id: str
    session_id: str = field(repr=False)
    user_id: uuid.UUID
    username: str
    mfa_request_id: str = field(repr=False)
    method_id: str
    operation: str
    collection_id: uuid.UUID | None
    resource_ids: tuple[uuid.UUID, ...]
    expires_at: dt.datetime

    @property
    def expired(self) -> bool:
        return _now() >= self.expires_at


@dataclass(slots=True)
class MfaProof:
    """Prueba breve de MFA reciente, ligada a sesion, actor, operacion y recurso.

    Tres cosas que NO es:

    * no es un booleano que envie el cliente: lo emite este proceso tras validar
      el codigo del titular contra Vault;
    * no es reutilizable: se consume en el primer uso;
    * no es un permiso general: autoriza esa operacion sobre ese conjunto
      cerrado de recursos y nada mas.
    """

    proof_id: str = field(repr=False)
    session_id: str = field(repr=False)
    user_id: uuid.UUID
    username: str
    operation: str
    collection_id: uuid.UUID | None
    resource_ids: frozenset[uuid.UUID]
    verified_at: dt.datetime
    expires_at: dt.datetime

    @property
    def expired(self) -> bool:
        return _now() >= self.expires_at

    def covers(
        self,
        *,
        session_id: str,
        user_id: uuid.UUID,
        operation: str,
        collection_id: uuid.UUID | None,
        resource_ids: frozenset[uuid.UUID],
    ) -> bool:
        """La prueba cubre esta peticion solo si coincide todo."""
        return (
            secrets.compare_digest(self.session_id, session_id)
            and self.user_id == user_id
            and self.operation == operation
            and self.collection_id == collection_id
            # Subconjunto: la prueba puede cubrir el lote declarado, nunca mas.
            and resource_ids <= self.resource_ids
        )


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
        mfa_proof_ttl_seconds: int = 300,
        max_mfa_proofs: int = 50,
    ) -> None:
        self._session_ttl = session_ttl_seconds
        self._challenge_ttl = challenge_ttl_seconds
        self._max_sessions = max_sessions
        self._max_challenges = max_challenges
        self._proof_ttl = mfa_proof_ttl_seconds
        self._max_proofs = max_mfa_proofs
        self._sessions: dict[str, ApiSession] = {}
        self._challenges: dict[str, PendingChallenge] = {}
        self._step_ups: dict[str, StepUpChallenge] = {}
        self._proofs: dict[str, MfaProof] = {}
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
            # Cerrar la sesion invalida tambien sus pruebas de MFA: estaban
            # ligadas a ella y no deben sobrevivirle.
            for key, proof in list(self._proofs.items()):
                if proof.session_id == session_id:
                    self._proofs.pop(key, None)
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
            for key, proof in list(self._proofs.items()):
                if proof.user_id == user_id:
                    self._proofs.pop(key, None)
            for key, step_up in list(self._step_ups.items()):
                if step_up.user_id == user_id:
                    self._step_ups.pop(key, None)
            return victims

    # -- reautenticacion para operaciones destructivas -----------------------

    async def create_step_up(
        self,
        *,
        session_id: str,
        user_id: uuid.UUID,
        username: str,
        mfa_request_id: str,
        method_id: str,
        operation: str,
        collection_id: uuid.UUID | None,
        resource_ids: tuple[uuid.UUID, ...],
    ) -> StepUpChallenge:
        async with self._lock:
            self._purge_locked()
            if len(self._step_ups) >= self._max_challenges:
                oldest = min(self._step_ups.values(), key=lambda c: c.expires_at)
                self._step_ups.pop(oldest.challenge_id, None)

            challenge = StepUpChallenge(
                challenge_id=secrets.token_urlsafe(24),
                session_id=session_id,
                user_id=user_id,
                username=username,
                mfa_request_id=mfa_request_id,
                method_id=method_id,
                operation=operation,
                collection_id=collection_id,
                resource_ids=resource_ids,
                expires_at=_now() + dt.timedelta(seconds=self._challenge_ttl),
            )
            self._step_ups[challenge.challenge_id] = challenge
            return challenge

    async def pop_step_up(self, challenge_id: str) -> StepUpChallenge | None:
        async with self._lock:
            challenge = self._step_ups.pop(challenge_id, None)
            if challenge is None or challenge.expired:
                return None
            return challenge

    async def create_proof(self, challenge: StepUpChallenge) -> MfaProof:
        async with self._lock:
            self._purge_locked()
            if len(self._proofs) >= self._max_proofs:
                oldest = min(self._proofs.values(), key=lambda p: p.expires_at)
                self._proofs.pop(oldest.proof_id, None)

            now = _now()
            proof = MfaProof(
                proof_id=secrets.token_urlsafe(32),
                session_id=challenge.session_id,
                user_id=challenge.user_id,
                username=challenge.username,
                operation=challenge.operation,
                collection_id=challenge.collection_id,
                resource_ids=frozenset(challenge.resource_ids),
                verified_at=now,
                expires_at=now + dt.timedelta(seconds=self._proof_ttl),
            )
            self._proofs[proof.proof_id] = proof
            return proof

    async def consume_proof(self, proof_id: str) -> MfaProof | None:
        """Saca la prueba del almacen: es de un solo uso."""
        async with self._lock:
            proof = self._proofs.pop(proof_id, None)
            if proof is None or proof.expired:
                return None
            return proof

    async def drop_proofs_for_session(self, session_id: str) -> int:
        async with self._lock:
            victims = [
                key for key, proof in self._proofs.items() if proof.session_id == session_id
            ]
            for key in victims:
                self._proofs.pop(key, None)
            return len(victims)

    # -- mantenimiento -------------------------------------------------------

    def _purge_locked(self) -> None:
        for key, session in list(self._sessions.items()):
            if session.expired:
                self._sessions.pop(key, None)
        for key, challenge in list(self._challenges.items()):
            if challenge.expired:
                self._challenges.pop(key, None)
        for key, step_up in list(self._step_ups.items()):
            if step_up.expired:
                self._step_ups.pop(key, None)
        for key, proof in list(self._proofs.items()):
            if proof.expired:
                self._proofs.pop(key, None)

    async def purge(self) -> None:
        async with self._lock:
            self._purge_locked()

    async def snapshot_counts(self) -> dict[str, int]:
        async with self._lock:
            return {
                "sessions": len(self._sessions),
                "challenges": len(self._challenges),
                "step_ups": len(self._step_ups),
                "mfa_proofs": len(self._proofs),
            }

    async def all_sessions(self) -> list[ApiSession]:
        async with self._lock:
            return list(self._sessions.values())

    async def clear(self) -> list[ApiSession]:
        async with self._lock:
            victims = list(self._sessions.values())
            self._sessions.clear()
            self._challenges.clear()
            self._step_ups.clear()
            self._proofs.clear()
            return victims
