"""Aprovisionamiento de consumidores de maquina (etapa 4.6).

Como esta repartido el trabajo, y por que
-----------------------------------------
La peticion humana **no** habla con Vault. Valida, guarda la solicitud y
devuelve 202 con ``operation_id``. El trabajo con Vault lo hace el worker
(``app/vault_mgmt/worker.py``) leyendo esa misma fila de PostgreSQL. Dos
consecuencias buscadas:

* Un reinicio no pierde nada: la solicitud esta en la base, no en memoria.
* Una futura plataforma React solo necesita *solicitar* y *consultar*. No
  espera a Vault en una peticion HTTP y no guarda ninguna credencial.

El ciclo de una emision
-----------------------
``pending`` -> el worker prepara montaje, politica y rol -> ``waiting_receiver``.

Ahi se **para**, y eso es lo correcto: sin receptor que recoja la credencial,
emitir un SecretID es repartir credenciales a nadie. Cuando el receptor reclama
(``claim``), se emite el SecretID **envuelto** y la operacion pasa a
``awaiting_ack``. Solo cuando el receptor acredita el token que obtuvo
(``ack``, comprobado con ``lookup`` contra Vault) la operacion llega a
``completed`` y el consumidor a ``ready``.

Lo que este modulo NO hace
--------------------------
* No guarda SecretID, wrapping tokens ni tokens de Vault. Solo accessors.
* No acepta HCL, paths, montajes, roles ni URL del cliente.
* No promete *exactamente una vez*. El SecretID, su envoltura y el token tienen
  TTL distintos, y una respuesta incierta de Vault se reconcilia (se destruye el
  SecretID huerfano por su accessor) antes de emitir otra cosa.
* No hace unseal y no ejecuta shell ni usa el socket de Docker.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    AppError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UpstreamUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.vault import VaultError, VaultSealed, VaultUnavailable
from app.vault_mgmt.core.approle_admin import AppRoleAdminClient
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.machine_auth import (
    MachineAuthError,
    assert_identity_matches,
    identity_from_lookup,
)
from app.vault_mgmt.core.principal import HumanPrincipal, require_admin
from app.vault_mgmt.core.vault_auth import ProvisioningUnavailable
from app.vault_mgmt.models.catalog import (
    ACTIVE_OPERATION_STATUSES,
    ProvisioningDelivery,
    SecretConsumer,
)
from app.vault_mgmt.repositories import audit as audit_repo
from app.vault_mgmt.repositories import catalog as catalog_repo
from app.vault_mgmt.repositories import operations as operations_repo
from app.vault_mgmt.repositories import provisioning as repo

logger = get_logger(__name__)

BindingTuple = tuple[uuid.UUID, uuid.UUID, int | None]


@dataclass(slots=True)
class Accepted:
    """Los tres campos del contrato de solicitud administrativa."""

    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    status: str


@dataclass(slots=True)
class IssuedDelivery:
    """Emision lista para el receptor. El SecretID no esta aqui: va envuelto."""

    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    delivery_id: uuid.UUID
    approle_mount: str
    role_id: str
    wrap_token: str
    wrap_ttl_seconds: int
    wrap_expires_at: dt.datetime


@dataclass(slots=True)
class PendingClaim:
    """No hay nada que entregar ahora. Es una respuesta, no un error."""

    status: str
    consumer_id: uuid.UUID
    operation_id: uuid.UUID | None
    delivery_id: uuid.UUID | None
    detail: str
    retry_after_seconds: int | None = None


@dataclass(slots=True)
class AckResult:
    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    delivery_id: uuid.UUID
    token_accessor: str
    token_ttl_seconds: int
    retired_previous: bool


def _delivery_de(datos: dict[str, Any]) -> str:
    """Extrae el ``delivery_id`` de los metadatos de un SecretID.

    Vault los devuelve bajo ``metadata`` en ``secret-id-accessor/lookup``. Son
    los que escribio el ``claim``, y solo llevan identificadores.
    """
    meta = datos.get("metadata") or datos.get("meta") or {}
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("delivery_id") or "")


def _not_managed(consumer_name: str, exc: ValueError) -> ConflictError:
    """Traduce la guarda de alcance de ``approle_admin`` a un 409 legible.

    Llega aqui cuando el rol AppRole de un consumidor NO esta en el espacio de
    nombres gestionado (``VAULT_MGMT_MANAGED_ROLE_PREFIX``): lo creo otra
    herramienta, o una version anterior con otro prefijo. Negarse es lo correcto
    (no se toca un rol ajeno), pero es un conflicto de estado del catalogo, no
    un error interno del servidor.
    """
    return ConflictError(
        f"el consumidor '{consumer_name}' apunta a un rol AppRole que esta "
        "fuera del espacio de nombres gestionado por esta API, asi que no se "
        "toca. Lo preparo otra herramienta o una version anterior: registralo "
        "de nuevo con POST /vault_mgmt/v1/vault/consumers, o preparalo por CLI "
        "con scripts/vault_mgmt/crawler-approle-bootstrap.sh y dejalo como "
        "consumidor heredado.",
        code="role_not_managed",
        context={"detail": str(exc)},
    )


def fingerprint(payload: dict[str, Any]) -> str:
    """Huella de los parametros NO sensibles de una solicitud.

    Sirve para una sola cosa: distinguir "misma Idempotency-Key, misma peticion"
    de "misma clave, otra peticion" (409). Se calcula sobre nombres, receptores
    y UUID de bindings, que ya son identificadores internos conocidos. **Nunca**
    sobre valores de secretos: ahi un hash de baja entropia en la base seria un
    oraculo para adivinarlos.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProvisioningService:
    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        approle: AppRoleAdminClient,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._approle = approle

    # =====================================================================
    # Lado humano: solicitar y consultar. Sin llamadas a Vault.
    # =====================================================================

    async def register_consumer(
        self,
        *,
        principal: HumanPrincipal,
        name: str,
        description: str | None,
        receiver: str,
        bindings: list[BindingTuple],
        idempotency_key: str | None,
        request_id: str | None,
    ) -> Accepted:
        """Alta del consumidor y de su alcance inicial. Devuelve 202."""
        require_admin(principal, "registrar un consumidor de maquina")
        self._require_known_receiver(receiver)

        huella = fingerprint(
            {
                "op": "consumer_register",
                "name": name,
                "receiver": receiver,
                "bindings": sorted(
                    [str(c), str(r), v] for c, r, v in bindings
                ),
            }
        )

        async with self._session_factory() as session:
            # Idempotencia ANTES de crear el consumidor: repetir la misma
            # peticion no debe chocar con el nombre que ella misma creo.
            if idempotency_key:
                previous = await self._replay(session, idempotency_key, huella)
                if previous is not None:
                    return previous

            existing = await repo.get_consumer_by_name(session, name)
            if existing is not None:
                raise ConflictError(
                    f"ya existe un consumidor llamado '{name}'",
                    code="consumer_name_taken",
                    context={"consumer_id": str(existing.consumer_id)},
                )
            ocupado = await repo.get_receiver_by_name(session, receiver)
            if ocupado is not None:
                otro = await repo.get_consumer(session, ocupado.consumer_id)
                raise ConflictError(
                    f"el receptor '{receiver}' ya sirve al consumidor "
                    f"'{otro.name if otro else ocupado.consumer_id}': una "
                    "credencial de receptor pertenece a un solo consumidor",
                    code="receiver_taken",
                )

            await self._validate_bindings(session, bindings)

            consumer = await repo.create_consumer(
                session,
                name=name,
                description=description,
                approle_mount=self._settings.managed_approle_mount,
                approle_role_name=self._settings.managed_role_name(name),
                expected_policy=self._settings.managed_policy_name,
                created_by=principal.user_id,
            )
            # El receptor se registra en el servidor con la REFERENCIA de su
            # credencial (el nombre del archivo), nunca con su valor. Esa fila
            # es lo que asocia una credencial concreta con este consumidor.
            await repo.upsert_receiver(
                session,
                name=receiver,
                consumer_id=consumer.consumer_id,
                credential_ref=self._credential_ref(receiver),
                description=f"Receptor del consumidor '{name}'",
                created_by=principal.user_id,
            )
            if bindings:
                await catalog_repo.replace_bindings(
                    session,
                    consumer_id=consumer.consumer_id,
                    entries=bindings,
                    created_by=principal.user_id,
                )
            operation, _repeated = await repo.start_consumer_operation(
                session,
                operation_type="consumer_register",
                consumer_id=consumer.consumer_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
                request_fingerprint=huella,
            )
            await repo.update_consumer(
                session,
                consumer.consumer_id,
                last_operation_id=operation.operation_id,
            )
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="consumer_register",
                outcome="allowed",
                operation_id=operation.operation_id,
                request_id=request_id,
                detail=(
                    f"consumidor '{name}', receptor '{receiver}', "
                    f"{len(bindings)} asignaciones. Solicitud guardada: no hay "
                    "credencial emitida todavia."
                ),
            )
            await session.commit()
            return Accepted(
                consumer_id=consumer.consumer_id,
                operation_id=operation.operation_id,
                status=operation.status,
            )

    async def request_provision(
        self,
        *,
        principal: HumanPrincipal,
        consumer_id: uuid.UUID,
        note: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> Accepted:
        """Prepara una emision pendiente para un consumidor que ya existe."""
        require_admin(principal, "aprovisionar un consumidor de maquina")
        return await self._open_operation(
            principal=principal,
            consumer_id=consumer_id,
            operation_type="consumer_provision",
            extra={"note": note},
            counters={},
            idempotency_key=idempotency_key,
            request_id=request_id,
            detail=f"aprovisionamiento solicitado{f' ({note})' if note else ''}",
        )

    async def request_rotation(
        self,
        *,
        principal: HumanPrincipal,
        consumer_id: uuid.UUID,
        strategy: str,
        note: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> Accepted:
        """Rotacion controlada, con la estrategia escrita en la operacion."""
        require_admin(principal, "rotar la credencial de un consumidor")
        if strategy not in ("after_ack", "immediate"):
            raise ValidationError(
                "estrategia de rotacion no reconocida", code="unknown_strategy"
            )
        detail = (
            "rotacion solicitada; la credencial anterior se retira "
            + (
                "cuando el receptor confirme la nueva"
                if strategy == "after_ack"
                else "al emitir la nueva (ventana de corte)"
            )
        )
        return await self._open_operation(
            principal=principal,
            consumer_id=consumer_id,
            operation_type="consumer_rotate",
            extra={"strategy": strategy, "note": note},
            counters={"strategy": strategy},
            idempotency_key=idempotency_key,
            request_id=request_id,
            detail=detail,
        )

    async def request_revocation(
        self,
        *,
        principal: HumanPrincipal,
        consumer_id: uuid.UUID,
        confirm: str,
        reason: str | None,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> Accepted:
        """Bloquea entregas y revoca lo que es revocable."""
        require_admin(principal, "revocar un consumidor de maquina")

        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            if confirm != consumer.name:
                raise ValidationError(
                    "la confirmacion debe ser el nombre exacto del consumidor",
                    code="confirmation_mismatch",
                )

            # Una revocacion SUPERSEDE cualquier operacion viva del consumidor,
            # en vez de chocar con ella. Lo contrario convertia un consumidor
            # atascado (por ejemplo, esperando para siempre a un receptor que ya
            # no existe) en un consumidor imposible de revocar, que es justo
            # cuando mas falta hace poder hacerlo.
            viva = await repo.latest_operation_for_consumer(session, consumer_id)
            if viva is not None and viva.status in ACTIVE_OPERATION_STATUSES:
                await repo.set_operation_status(
                    session,
                    viva.operation_id,
                    status="failed",
                    error=(
                        "cancelada por una revocacion del consumidor: la "
                        "emision que esperaba ya no se va a entregar"
                    ),
                )
                en_curso = await repo.live_delivery(session, consumer_id)
                if en_curso is not None:
                    await repo.update_delivery(
                        session,
                        en_curso.delivery_id,
                        state="superseded",
                        error="revocacion del consumidor",
                    )
                await audit_repo.record(
                    session,
                    actor_kind="human",
                    actor_user_id=principal.user_id,
                    actor_label=principal.username,
                    action="consumer_revoke",
                    outcome="partial",
                    operation_id=viva.operation_id,
                    request_id=request_id,
                    detail=(
                        f"operacion '{viva.operation_type}' cancelada para poder "
                        "revocar el consumidor"
                    ),
                )
                await session.commit()

        return await self._open_operation(
            principal=principal,
            consumer_id=consumer_id,
            operation_type="consumer_revoke",
            extra={"reason": reason},
            counters={},
            idempotency_key=idempotency_key,
            request_id=request_id,
            detail=(
                f"revocacion solicitada{f': {reason}' if reason else ''}. "
                "Bloquea entregas futuras y destruye los SecretID; los tokens ya "
                "emitidos viven hasta su TTL salvo revocacion por accessor."
            ),
            allow_revoked=True,
        )

    async def list_consumers(
        self,
        *,
        principal: HumanPrincipal,
        state: str | None,
        delivery_mode: str | None,
        limit: int,
        offset: int,
    ) -> Any:
        require_admin(principal, "listar consumidores de maquina")
        async with self._session_factory() as session:
            return await repo.list_consumers(
                session,
                state=state,
                delivery_mode=delivery_mode,
                limit=limit,
                offset=offset,
            )

    async def get_consumer(
        self, *, principal: HumanPrincipal, consumer_id: uuid.UUID
    ) -> tuple[SecretConsumer, Any, ProvisioningDelivery | None, int]:
        require_admin(principal, "consultar un consumidor de maquina")
        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            operation = await repo.latest_operation_for_consumer(session, consumer_id)
            deliveries = await repo.list_deliveries(session, consumer_id, limit=1)
            bindings = await catalog_repo.list_bindings(session, consumer_id)
        return consumer, operation, (deliveries[0] if deliveries else None), len(bindings)

    # -- utilidades del lado humano ----------------------------------------

    def _credential_ref(self, receiver: str) -> str:
        """Nombre del archivo de secreto del receptor. Nunca su contenido."""
        for name, path in self._settings.receiver_entries:
            if name == receiver:
                return path.rsplit("/", 1)[-1]
        return receiver

    def _require_known_receiver(self, receiver: str) -> None:
        """El receptor tiene que estar CONFIGURADO en el servicio.

        Si se aceptara cualquier nombre, un alta crearia un consumidor que nadie
        puede reclamar, y el fallo se descubriria mucho despues.
        """
        if receiver not in self._settings.configured_receivers:
            raise ValidationError(
                f"'{receiver}' no es un receptor configurado en este servicio. "
                "Los declarados son: "
                + (", ".join(self._settings.configured_receivers) or "(ninguno)")
                + ". Se configuran con VAULT_MGMT_RECEIVERS y su "
                "credencial la genera 'make all' en secrets/.",
                code="unknown_receiver",
            )
        if receiver not in self._settings.receiver_credentials:
            raise ValidationError(
                f"el receptor '{receiver}' esta declarado pero su archivo de "
                "credencial no es legible en este proceso: no podria reclamar "
                "nada. Ejecuta 'make all' para generarlo y recrea el contenedor.",
                code="receiver_credential_missing",
            )

    async def _replay(
        self, session: AsyncSession, idempotency_key: str, huella: str
    ) -> Accepted | None:
        """Devuelve la solicitud original si la clave ya se uso igual."""
        operation = await repo.get_operation_by_idempotency(session, idempotency_key)
        if operation is None:
            return None
        if (operation.request_fingerprint or "") != huella:
            raise ConflictError(
                "esa Idempotency-Key ya se uso con otros parametros. Usa una "
                "clave nueva para una peticion distinta.",
                code="idempotency_key_reused",
                context={"operation_id": str(operation.operation_id)},
            )
        if operation.consumer_id is None:
            return None
        return Accepted(
            consumer_id=operation.consumer_id,
            operation_id=operation.operation_id,
            status=operation.status,
        )

    async def _validate_bindings(
        self, session: AsyncSession, bindings: list[BindingTuple]
    ) -> None:
        """Comprueba cada asignacion contra el catalogo antes de aceptarla."""
        for collection_id, record_id, pinned_version in bindings:
            collection = await catalog_repo.require_collection(session, collection_id)
            if collection.state != "active":
                raise ConflictError(
                    f"la coleccion '{collection.logical_name}' esta "
                    f"'{collection.state}': no se asignan entregas sobre ella",
                    code="collection_not_active",
                )
            record = await catalog_repo.require_record(session, collection_id, record_id)
            if record.state == "destroyed":
                raise ConflictError(
                    "no se asigna un registro destruido: su contenido no existe",
                    code="record_destroyed",
                    context={"record_id": str(record_id)},
                )
            if pinned_version is not None and pinned_version > record.current_version:
                raise ValidationError(
                    f"la version fijada {pinned_version} no existe todavia "
                    f"(la ultima conocida es {record.current_version})",
                    code="pinned_version_unknown",
                    context={"record_id": str(record_id)},
                )

    async def _open_operation(
        self,
        *,
        principal: HumanPrincipal,
        consumer_id: uuid.UUID,
        operation_type: str,
        extra: dict[str, Any],
        counters: dict[str, Any],
        idempotency_key: str | None,
        request_id: str | None,
        detail: str,
        allow_revoked: bool = False,
    ) -> Accepted:
        huella = fingerprint(
            {"op": operation_type, "consumer_id": str(consumer_id), **extra}
        )
        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            if consumer.delivery_mode != "mediated":
                raise ConflictError(
                    f"'{consumer.name}' es un consumidor HEREDADO (delivery_mode "
                    "'direct') de la etapa 4: lo prepara "
                    "scripts/vault_mgmt/crawler-approle-bootstrap.sh y su token lee "
                    "KV directamente. Esta API no lo aprovisiona; migrarlo a "
                    "entrega mediada es una decision explicita, porque hay que "
                    "estrechar su politica en Vault.",
                    code="legacy_consumer",
                    context={"consumer_id": str(consumer_id)},
                )
            if consumer.state != "active" and not allow_revoked:
                raise ConflictError(
                    "el consumidor esta revocado: no se preparan emisiones nuevas",
                    code="consumer_revoked",
                )

            if idempotency_key:
                previous = await self._replay(session, idempotency_key, huella)
                if previous is not None:
                    return previous

            operation, repeated = await repo.start_consumer_operation(
                session,
                operation_type=operation_type,
                consumer_id=consumer_id,
                actor_user_id=principal.user_id,
                actor_username=principal.username,
                idempotency_key=idempotency_key,
                request_fingerprint=huella,
            )
            if repeated:
                return Accepted(
                    consumer_id=consumer_id,
                    operation_id=operation.operation_id,
                    status=operation.status,
                )
            if counters:
                await operations_repo.set_counters(
                    session, operation.operation_id, counters
                )
            await repo.update_consumer(
                session, consumer_id, last_operation_id=operation.operation_id
            )
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action=operation_type,
                outcome="allowed",
                operation_id=operation.operation_id,
                request_id=request_id,
                detail=detail,
            )
            await session.commit()
            return Accepted(
                consumer_id=consumer_id,
                operation_id=operation.operation_id,
                status=operation.status,
            )

    # =====================================================================
    # Lado worker: aqui si se habla con Vault
    # =====================================================================

    async def run_operation(self, operation_id: uuid.UUID) -> str:
        """Ejecuta una operacion ya reservada. Devuelve el estado resultante.

        Cada fase se anota en su propia transaccion corta. Entre fases NO hay
        transaccion abierta: en medio se llama a Vault.
        """
        async with self._session_factory() as session:
            operation = await repo.get_operation(session, operation_id)
            if operation is None:
                return "failed"
            op_type = operation.operation_type
            consumer_id = operation.consumer_id
            counters = dict(operation.counters or {})
        if consumer_id is None:
            await self._finish(operation_id, "failed", "la operacion no tiene consumidor")
            return "failed"

        try:
            if op_type in ("consumer_register", "consumer_provision", "consumer_rotate"):
                return await self._prepare_identity(
                    operation_id=operation_id,
                    consumer_id=consumer_id,
                    operation_type=op_type,
                    counters=counters,
                )
            if op_type == "consumer_revoke":
                return await self._revoke(
                    operation_id=operation_id, consumer_id=consumer_id
                )
        except ProvisioningUnavailable as exc:
            # Falta el token del aprovisionador: la solicitud sigue guardada y se
            # reintentara. No es un fallo de la peticion.
            await self._phase(operation_id, "approle_setup", "vault", "deferred", exc.message)
            await self._finish(operation_id, "pending", exc.message, clear_lease=True)
            return "pending"
        except (VaultSealed, VaultUnavailable) as exc:
            await self._phase(operation_id, "approle_setup", "vault", "deferred", exc.message)
            await self._finish(operation_id, "pending", exc.message, clear_lease=True)
            return "pending"
        except VaultError as exc:
            await self._phase(operation_id, "approle_setup", "vault", "failed", exc.message)
            await self._finish(operation_id, "failed", exc.message)
            await self._mark_provisioning(consumer_id, "failed")
            return "failed"
        except ValueError as exc:
            # Guarda de alcance de approle_admin: el rol no es gestionado.
            await self._finish(operation_id, "failed", str(exc))
            return "failed"

        await self._finish(operation_id, "failed", f"tipo no soportado: {op_type}")
        return "failed"

    async def _prepare_identity(
        self,
        *,
        operation_id: uuid.UUID,
        consumer_id: uuid.UUID,
        operation_type: str,
        counters: dict[str, Any],
    ) -> str:
        """Deja la AppRole lista y espera al receptor. NO emite SecretID.

        Emitir aqui seria el error facil: dejaria una credencial viva esperando
        a un proceso que puede no existir. El SecretID se emite en el ``claim``,
        cuando hay alguien al otro lado.
        """
        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            role_name = consumer.approle_role_name
            receiver = await repo.get_receiver_for_consumer(session, consumer_id)
            receiver_key = receiver.name if receiver is not None else ""
            previous_accessor = consumer.secret_id_accessor
            previous_token = consumer.last_token_accessor or ""

        if not receiver_key:
            await self._finish(
                operation_id,
                "failed",
                "el consumidor no tiene receptor configurado: no hay a quien entregar",
            )
            return "failed"

        await self._mark_provisioning(consumer_id, "provisioning")

        await self._approle.ensure_mount()
        await self._phase(operation_id, "approle_mount", "vault", "done")
        await self._approle.ensure_policy()
        await self._phase(
            operation_id,
            "managed_policy",
            "vault",
            "done",
            f"politica {self._settings.managed_policy_name} sin lectura de KV "
            "(entrega mediada)",
        )
        await self._approle.ensure_role(role_name)
        await self._phase(operation_id, "approle_role", "vault", "done", role_name)

        # La rotacion inmediata retira la credencial anterior AHORA. Es la
        # estrategia con ventana de corte, y se eligio de forma explicita.
        if operation_type == "consumer_rotate" and counters.get("strategy") == "immediate":
            # Ventana de corte: se retira AHORA lo anterior, sin esperar a que el
            # receptor recoja lo nuevo. Hay que retirar las DOS cosas, porque son
            # distintas: el SecretID (si quedaba alguno sin consumir) y el TOKEN
            # que ya salio de el, que sobrevive hasta su TTL si no se revoca.
            retirado = []
            if previous_accessor and await self._approle.destroy_secret_id_accessor(
                role_name, previous_accessor
            ):
                retirado.append("SecretID anterior destruido")
            if previous_token and await self._approle.revoke_token_accessor(
                previous_token
            ):
                retirado.append("token anterior revocado por su accessor")
            await self._phase(
                operation_id,
                "retire_previous",
                "vault",
                "done" if retirado else "skipped",
                "; ".join(retirado) or "no habia credencial anterior que retirar",
            )
            async with self._session_factory() as session:
                await repo.update_consumer(
                    session,
                    consumer_id,
                    secret_id_accessor=None,
                    previous_secret_id_accessor=None,
                    last_token_accessor=None,
                )
                await session.commit()

        if operation_type == "consumer_rotate" and counters.get("strategy") == "after_ack":
            # Se anota QUE hay que retirar, para hacerlo EXACTAMENTE cuando el
            # receptor confirme la nueva y no antes. El token anterior va en los
            # contadores de la operacion (no necesita columna propia: pertenece a
            # esta rotacion, no al consumidor).
            async with self._session_factory() as session:
                if previous_accessor:
                    await repo.update_consumer(
                        session,
                        consumer_id,
                        previous_secret_id_accessor=previous_accessor,
                    )
                if previous_token:
                    nuevos = dict(counters)
                    nuevos["previous_token_accessor"] = previous_token
                    await operations_repo.set_counters(
                        session, operation_id, nuevos
                    )
                await session.commit()

        await self._finish(operation_id, "waiting_receiver", None)
        await self._phase(
            operation_id,
            "await_receiver",
            "gateway",
            "waiting",
            f"identidad lista; esperando que el receptor '{receiver_key}' reclame",
        )
        return "waiting_receiver"

    async def _revoke(self, *, operation_id: uuid.UUID, consumer_id: uuid.UUID) -> str:
        """Destruye SecretID, revoca el token acreditado y borra el rol."""
        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            role_name = consumer.approle_role_name
            secret_accessor = consumer.secret_id_accessor
            previous_accessor = consumer.previous_secret_id_accessor
            token_accessor = consumer.last_token_accessor

        notes: list[str] = []
        try:
            for accessor in (secret_accessor, previous_accessor):
                if accessor:
                    await self._approle.destroy_secret_id_accessor(role_name, accessor)
                    notes.append("SecretID destruido")
            # Los accessors que queden sueltos (envolturas caducadas sin
            # consumir) tambien se destruyen: si no, siguen sirviendo para entrar.
            for accessor in await self._approle.list_secret_id_accessors(role_name):
                await self._approle.destroy_secret_id_accessor(role_name, accessor)
            if token_accessor:
                revoked = await self._approle.revoke_token_accessor(token_accessor)
                notes.append(
                    "token acreditado revocado"
                    if revoked
                    else "el token acreditado ya no existia"
                )
            await self._approle.delete_role(role_name)
            notes.append("rol AppRole eliminado")
        except ProvisioningUnavailable as exc:
            # Sin token no se puede revocar en Vault. Se bloquea la entrega en el
            # catalogo, que es lo que esta API controla, y se dice lo que falta.
            await self._block_deliveries(
                consumer_id, detail="revocado en el catalogo; Vault sin revocar"
            )
            await self._phase(operation_id, "vault_revoke", "vault", "failed", exc.message)
            await self._finish(
                operation_id,
                "needs_reconciliation",
                "el consumidor queda bloqueado para entregas, pero su AppRole "
                "sigue viva en Vault: " + exc.message,
            )
            return "needs_reconciliation"

        await self._phase(
            operation_id, "vault_revoke", "vault", "done", "; ".join(notes) or "nada que revocar"
        )
        await self._block_deliveries(consumer_id, detail="; ".join(notes))
        await self._finish(operation_id, "completed", None)
        return "completed"

    async def _block_deliveries(self, consumer_id: uuid.UUID, *, detail: str) -> None:
        async with self._session_factory() as session:
            live = await repo.live_delivery(session, consumer_id)
            if live is not None:
                await repo.update_delivery(
                    session,
                    live.delivery_id,
                    state="superseded",
                    error="consumidor revocado antes de completar la entrega",
                )
            # Se retira el receptor y, con el, se LIBERA su nombre: sin esto, el
            # receptor quedaba ocupado para siempre y no se podia registrar otro
            # consumidor con el, aunque el anterior estuviese revocado.
            receptor = await repo.disable_receiver(session, consumer_id)
            if receptor:
                detail = f"{detail}; receptor '{receptor}' liberado"
            await repo.update_consumer(
                session,
                consumer_id,
                state="revoked",
                provisioning_state="revoked",
                revoked_at=repo.utc_now(),
                secret_id_accessor=None,
                previous_secret_id_accessor=None,
                last_token_accessor=None,
            )
            await audit_repo.record(
                session,
                actor_kind="service",
                actor_user_id=None,
                actor_label="provisioner",
                action="consumer_revoke",
                outcome="allowed",
                detail=(
                    detail
                    + ". Revocar impide entregas futuras; no caduca un wrapping "
                    "token ya entregado ni borra lo que el consumidor ya leyo."
                ),
            )
            await session.commit()

    async def reconcile_expired_deliveries(self) -> int:
        """Cierra envolturas caducadas sin consumir y destruye su SecretID.

        Es el caso que obliga a reconciliar en vez de reintentar: el SecretID se
        emitio, nadie lo desenvolvio y **sigue existiendo en Vault**. Emitir otro
        sin destruir el anterior iria acumulando credenciales validas que nadie
        controla.

        **Como se identifica el huerfano.** Al envolver, Vault devuelve el
        accessor del *wrapping token*, no el del SecretID: ese viaja DENTRO de la
        envoltura y el servicio no lo ve nunca. Asi que no se puede destruir "por
        su accessor" sin mas.

        Se identifica por sus **metadatos**: el ``claim`` etiqueta cada SecretID
        con el ``delivery_id`` de su entrega, de modo que aqui se listan los
        accessors vivos del rol, se consulta cada uno y se destruye el que lleva
        el ``delivery_id`` de la entrega caducada. Es exacto, y no depende de
        suponer que no hay otros SecretID vivos: por eso esos metadatos se
        escriben.
        """
        async with self._session_factory() as session:
            pendientes = await repo.expired_deliveries(session)
            lote = [
                (d.delivery_id, d.consumer_id, d.operation_id, d.secret_id_accessor)
                for d in pendientes
            ]

        cerradas = 0
        for delivery_id, consumer_id, operation_id, accessor_conocido in lote:
            async with self._session_factory() as session:
                consumer = await repo.get_consumer(session, consumer_id)
            if consumer is None:
                continue
            role_name = consumer.approle_role_name
            vigente = consumer.secret_id_accessor

            destruidos = 0
            try:
                if accessor_conocido:
                    # Caso raro pero posible: ya se sabia cual era.
                    if await self._approle.destroy_secret_id_accessor(
                        role_name, accessor_conocido
                    ):
                        destruidos += 1
                else:
                    for candidato in await self._approle.list_secret_id_accessors(
                        role_name
                    ):
                        if candidato == vigente:
                            # El que el consumidor usa de verdad: no se toca.
                            continue
                        datos = await self._approle.lookup_secret_id_accessor(
                            role_name, candidato
                        )
                        if datos is None:
                            continue
                        etiqueta = _delivery_de(datos)
                        # Solo el de ESTA entrega. Si no lleva etiqueta, no se
                        # toca: pudo emitirlo otra cosa, y destruir a ciegas una
                        # credencial ajena es peor que dejar una huerfana.
                        if etiqueta != str(delivery_id):
                            continue
                        if await self._approle.destroy_secret_id_accessor(
                            role_name, candidato
                        ):
                            destruidos += 1
            except (VaultError, ProvisioningUnavailable) as exc:
                logger.warning(
                    "no se pudo destruir un SecretID huerfano; se reintentara",
                    extra={"operation": "reconcile", "detail": exc.message},
                )
                continue
            except ValueError as exc:
                # Rol fuera del espacio gestionado: no se toca, pero la entrega
                # se cierra igualmente para no reintentarla en bucle.
                logger.warning(
                    "entrega caducada sobre un rol no gestionado: el SecretID hay "
                    "que retirarlo a mano",
                    extra={"operation": "reconcile", "detail": str(exc)},
                )

            async with self._session_factory() as session:
                await repo.update_delivery(
                    session,
                    delivery_id,
                    state="expired",
                    error=(
                        "la envoltura caduco sin consumirse; "
                        + (
                            f"{destruidos} SecretID destruido(s) por reconciliacion"
                            if destruidos
                            else "no habia ningun SecretID huerfano que destruir"
                        )
                    ),
                )
                # La operacion vuelve a esperar al receptor: puede reclamar otra
                # vez y se emitira una credencial nueva, no la huerfana.
                await repo.set_operation_status(
                    session,
                    operation_id,
                    status="waiting_receiver",
                    error="la entrega anterior caduco sin consumirse",
                )
                await audit_repo.record(
                    session,
                    actor_kind="service",
                    actor_user_id=None,
                    actor_label="provisioner",
                    action="provisioning_reconcile",
                    outcome="partial",
                    operation_id=operation_id,
                    detail=(
                        f"envoltura caducada sin consumir; {destruidos} SecretID "
                        "destruido(s). El consumidor puede volver a reclamar."
                    ),
                )
                await session.commit()
            cerradas += 1
        return cerradas

    # =====================================================================
    # Canal interno: claim y ack
    # =====================================================================

    async def claim(
        self,
        *,
        receiver_key: str,
        instance: str | None,
        wrap_ttl_seconds: int | None,
        request_id: str | None,
    ) -> IssuedDelivery | PendingClaim:
        """El receptor reclama su emision. El consumidor sale de la credencial."""
        async with self._session_factory() as session:
            resuelto = await repo.resolve_consumer_for_receiver(session, receiver_key)
            if resuelto is None:
                raise ForbiddenError(
                    "esa credencial de receptor no tiene consumidor asignado. "
                    "Registra el consumidor con POST /vault_mgmt/v1/vault/consumers "
                    "indicando este receptor.",
                    code="receiver_not_bound",
                )
            receiver, consumer = resuelto
            if receiver.state != "active":
                raise ForbiddenError(
                    "el receptor esta deshabilitado: no se entregan credenciales",
                    code="receiver_disabled",
                )
            receiver_id = receiver.receiver_id
            consumer_id = consumer.consumer_id
            if consumer.state != "active":
                raise ForbiddenError(
                    "el consumidor esta revocado: no se entregan credenciales",
                    code="consumer_revoked",
                )
            role_name = consumer.approle_role_name
            operation = await repo.latest_operation_for_consumer(session, consumer_id)
            live = await repo.live_delivery(session, consumer_id)

        # Una entrega ya emitida no se vuelve a emitir: se le recuerda al
        # receptor que tiene una viva. Emitir otra dejaria la primera huerfana.
        if live is not None and live.state == "delivered":
            return PendingClaim(
                status="already_delivered",
                consumer_id=consumer_id,
                operation_id=live.operation_id,
                delivery_id=live.delivery_id,
                detail=(
                    "ya se te entrego una envoltura para esta emision y todavia no "
                    "la has confirmado. Si caduco, espera a que se reconcilie y "
                    "vuelve a reclamar: no se emite otra credencial encima."
                ),
                retry_after_seconds=self._settings.provisioning_wrap_ttl_seconds,
            )

        if operation is None or operation.status not in ("waiting_receiver",):
            return PendingClaim(
                status=(
                    "waiting_provisioner"
                    if operation is not None and operation.status in ("pending", "in_progress")
                    else "no_pending_request"
                ),
                consumer_id=consumer_id,
                operation_id=operation.operation_id if operation else None,
                delivery_id=None,
                detail=(
                    "la identidad todavia no esta preparada; reintenta en unos "
                    "segundos"
                    if operation is not None
                    and operation.status in ("pending", "in_progress")
                    else "no hay ninguna emision solicitada para este consumidor. "
                    "Pidela con POST /vault_mgmt/v1/vault/consumers/"
                    f"{consumer_id}/provision"
                ),
                retry_after_seconds=5
                if operation is not None
                and operation.status in ("pending", "in_progress")
                else None,
            )

        operation_id = operation.operation_id
        ttl = min(
            wrap_ttl_seconds or self._settings.provisioning_wrap_ttl_seconds,
            self._settings.provisioning_wrap_ttl_seconds,
        )

        # 1. Reserva en PostgreSQL. El indice parcial impide dos vivas.
        async with self._session_factory() as session:
            if live is not None and live.state == "reserved":
                delivery_id = live.delivery_id
                await repo.update_delivery(
                    session,
                    delivery_id,
                    attempts=int(live.attempts or 0) + 1,
                    claimed_at=repo.utc_now(),
                )
            else:
                delivery = await repo.create_delivery(
                    session,
                    operation_id=operation_id,
                    consumer_id=consumer_id,
                    receiver_id=receiver_id,
                )
                delivery_id = delivery.delivery_id
            await repo.touch_receiver(session, receiver_id)
            await session.commit()

        # 2. Vault: role_id y SecretID ENVUELTO. Sin transaccion abierta.
        try:
            role = await self._approle.read_role(role_name)
            if role is None:
                await self._mark_delivery_failed(
                    delivery_id, "el rol AppRole no existe todavia"
                )
                return PendingClaim(
                    status="waiting_provisioner",
                    consumer_id=consumer_id,
                    operation_id=operation_id,
                    delivery_id=None,
                    detail="la AppRole todavia no esta creada; reintenta",
                    retry_after_seconds=5,
                )
            wrapped = await self._approle.issue_wrapped_secret_id(
                role_name,
                metadata={
                    "consumer_id": str(consumer_id),
                    "operation_id": str(operation_id),
                    "delivery_id": str(delivery_id),
                    "receiver": receiver_key,
                },
                wrap_ttl_seconds=ttl,
            )
        except (ProvisioningUnavailable, VaultSealed, VaultUnavailable) as exc:
            await self._release_reservation(delivery_id, exc.message)
            raise UpstreamUnavailableError(
                f"no se puede emitir la credencial ahora: {exc.message}"
            ) from exc
        except VaultError as exc:
            await self._mark_delivery_failed(delivery_id, exc.message)
            raise UpstreamUnavailableError(
                f"Vault rechazo la emision: {exc.message}"
            ) from exc
        except ValueError as exc:
            await self._mark_delivery_failed(delivery_id, str(exc))
            raise _not_managed(consumer.name, exc) from exc

        # 3. Se anota lo entregable (accessors, no credenciales) y se pasa a
        #    awaiting_ack: la operacion NO esta completa todavia.
        async with self._session_factory() as session:
            await repo.update_delivery(
                session,
                delivery_id,
                state="delivered",
                wrap_accessor=wrapped.accessor,
                wrap_ttl_seconds=wrapped.ttl_seconds,
                expires_at=wrapped.expires_at,
            )
            await repo.set_operation_status(
                session, operation_id, status="awaiting_ack", clear_lease=True
            )
            await audit_repo.record(
                session,
                actor_kind="machine",
                actor_user_id=None,
                actor_label=receiver_key,
                action="provisioning_claim",
                outcome="allowed",
                operation_id=operation_id,
                request_id=request_id,
                detail=(
                    f"envoltura entregada, ttl {wrapped.ttl_seconds}s, accessor "
                    f"{wrapped.accessor}"
                    + (f", instancia {instance}" if instance else "")
                    + ". Pendiente de ack."
                ),
            )
            await session.commit()

        await self._phase(
            operation_id,
            "issue_secret_id",
            "vault",
            "done",
            f"SecretID envuelto, ttl {wrapped.ttl_seconds}s",
        )

        return IssuedDelivery(
            consumer_id=consumer_id,
            operation_id=operation_id,
            delivery_id=delivery_id,
            approle_mount=self._approle.mount,
            role_id=role.role_id,
            wrap_token=wrapped.token,
            wrap_ttl_seconds=wrapped.ttl_seconds,
            wrap_expires_at=wrapped.expires_at,
        )

    async def ack(
        self,
        *,
        receiver_key: str,
        delivery_id: uuid.UUID,
        vault_token: str,
        instance: str | None,
        request_id: str | None,
    ) -> AckResult:
        """Confirma la entrega COMPROBANDO el token, no creyendo al cliente."""
        async with self._session_factory() as session:
            delivery = await repo.get_delivery(session, delivery_id)
            if delivery is None:
                raise NotFoundError("no existe esa entrega", code="delivery_not_found")
            su_receptor = await repo.get_receiver_by_name(session, receiver_key)
            if su_receptor is None or delivery.receiver_id != su_receptor.receiver_id:
                # Enmascarar no es autorizar: el recurso existe y no es suyo.
                raise ForbiddenError(
                    "esa entrega es de otro receptor", code="delivery_not_yours"
                )
            if delivery.state == "acked":
                raise ConflictError(
                    "esa entrega ya estaba confirmada", code="delivery_already_acked"
                )
            if delivery.state != "delivered":
                raise ConflictError(
                    f"la entrega esta '{delivery.state}': no se puede confirmar",
                    code="delivery_not_delivered",
                )
            consumer = await repo.require_consumer(session, delivery.consumer_id)
            consumer_id = consumer.consumer_id
            operation_id = delivery.operation_id
            role_name = consumer.approle_role_name
            expected_mount = consumer.approle_mount
            expected_policy = consumer.expected_policy
            previous_accessor = consumer.previous_secret_id_accessor
            operation = await repo.get_operation(session, operation_id)
            previous_token_accessor = str(
                (operation.counters or {}).get("previous_token_accessor") or ""
            ) if operation else ""
            strategy = str((operation.counters or {}).get("strategy") or "") if operation else ""

        # Comprobacion real contra Vault. Un 'success: true' del cliente no
        # prueba nada: esto si, porque un token falso no pasa el lookup.
        try:
            data = await self._approle.lookup_token(vault_token)
        except (ProvisioningUnavailable, VaultSealed, VaultUnavailable) as exc:
            raise UpstreamUnavailableError(
                f"no se puede comprobar el token ahora: {exc.message}"
            ) from exc
        except VaultError as exc:
            raise ForbiddenError(
                f"Vault no reconocio el token presentado: {exc.message}",
                code="ack_token_invalid",
            ) from exc
        if not data:
            raise ForbiddenError(
                "el token presentado no es valido en Vault: la entrega no se "
                "confirma",
                code="ack_token_invalid",
            )

        identity = identity_from_lookup(data)
        try:
            assert_identity_matches(
                identity,
                expected_mount=expected_mount,
                expected_role=role_name,
                expected_policy=expected_policy,
            )
        except MachineAuthError as exc:
            async with self._session_factory() as session:
                await audit_repo.record(
                    session,
                    actor_kind="machine",
                    actor_user_id=None,
                    actor_label=receiver_key,
                    action="provisioning_ack",
                    outcome="denied",
                    operation_id=operation_id,
                    request_id=request_id,
                    detail=f"identidad incorrecta: {exc.message}",
                )
                await session.commit()
            raise ForbiddenError(
                "el token presentado no corresponde a la identidad de este "
                f"consumidor: {exc.message}",
                code="ack_identity_mismatch",
            ) from exc

        # El token tiene que venir de ESTA entrega, no solo del rol correcto.
        #
        # Vault copia en los metadatos del token los del SecretID que se canjeo,
        # y entre ellos va el delivery_id que puso el claim. Comprobarlo cierra
        # un hueco: un token obtenido con la credencial de OTRA entrega del mismo
        # consumidor pasaria la comprobacion de identidad (mismo montaje, rol y
        # politica) y no deberia confirmar esta.
        meta = dict(data.get("meta") or {})
        entrega_del_token = str(meta.get("delivery_id") or "")
        if entrega_del_token and entrega_del_token != str(delivery_id):
            async with self._session_factory() as session:
                await audit_repo.record(
                    session,
                    actor_kind="machine",
                    actor_user_id=None,
                    actor_label=receiver_key,
                    action="provisioning_ack",
                    outcome="denied",
                    operation_id=operation_id,
                    request_id=request_id,
                    detail="el token proviene de otra entrega del mismo consumidor",
                )
                await session.commit()
            raise ForbiddenError(
                "el token presentado se obtuvo con la credencial de otra entrega: "
                "confirma la entrega que te corresponde",
                code="ack_delivery_mismatch",
            )

        # Vault NO expone el accessor del SecretID en el lookup del token (se
        # comprobo contra Vault real: 'meta' trae consumer_id, delivery_id,
        # operation_id, receiver y role_name, y nada mas). Asi que el catalogo no
        # puede registrarlo aqui, y tampoco hace falta: con
        # secret_id_num_uses=1 el SecretID queda consumido en este login y ya no
        # sirve para autenticarse.
        #
        # Lo que SI sobrevive a la rotacion es el TOKEN anterior, hasta su TTL.
        # Retirarlo es lo que de verdad cierra una rotacion 'after_ack', y se
        # hace por su accessor, que si conocemos.
        retired = False
        if strategy == "after_ack":
            try:
                if previous_token_accessor:
                    retired = await self._approle.revoke_token_accessor(
                        previous_token_accessor
                    )
                # Y si quedaba un SecretID anterior sin consumir, se destruye.
                if previous_accessor and await self._approle.destroy_secret_id_accessor(
                    role_name, previous_accessor
                ):
                    retired = True
            except (VaultError, ProvisioningUnavailable) as exc:
                logger.warning(
                    "la credencial nueva se confirmo pero no se pudo retirar la "
                    "anterior; revocala por su accessor",
                    extra={"operation": "rotate", "detail": exc.message},
                )
            except ValueError as exc:
                logger.warning(
                    "la credencial nueva se confirmo pero la anterior vive en un "
                    "rol no gestionado: hay que retirarla a mano",
                    extra={"operation": "rotate", "detail": str(exc)},
                )

        async with self._session_factory() as session:
            await repo.update_delivery(
                session,
                delivery_id,
                state="acked",
                token_accessor=identity.accessor,
                acked_at=repo.utc_now(),
            )
            await repo.update_consumer(
                session,
                consumer_id,
                provisioning_state="ready",
                provisioned_at=repo.utc_now(),
                last_token_accessor=identity.accessor,
                # El SecretID se consumio en este login (num_uses=1): ya no hay
                # ninguno vigente que registrar, y la anterior deja de estar
                # pendiente de retirar.
                secret_id_accessor=None,
                previous_secret_id_accessor=None,
            )
            await repo.set_operation_status(
                session, operation_id, status="completed", clear_lease=True
            )
            await audit_repo.record(
                session,
                actor_kind="machine",
                actor_user_id=None,
                actor_label=receiver_key,
                action="provisioning_ack",
                outcome="allowed",
                operation_id=operation_id,
                request_id=request_id,
                detail=(
                    f"identidad comprobada con lookup; accessor del token "
                    f"{identity.accessor}, ttl {identity.ttl_seconds}s"
                    + (f", instancia {instance}" if instance else "")
                    + ("; credencial anterior retirada" if retired else "")
                ),
            )
            await session.commit()

        await self._phase(
            operation_id,
            "receiver_ack",
            "gateway",
            "done",
            "token acreditado y comprobado en Vault",
        )
        return AckResult(
            consumer_id=consumer_id,
            operation_id=operation_id,
            delivery_id=delivery_id,
            token_accessor=identity.accessor,
            token_ttl_seconds=identity.ttl_seconds,
            retired_previous=retired,
        )

    # =====================================================================
    # Utilidades internas
    # =====================================================================

    async def _phase(
        self,
        operation_id: uuid.UUID,
        name: str,
        system: str,
        state: str,
        detail: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await operations_repo.add_phase(
                session, operation_id, name=name, system=system, state=state, detail=detail
            )
            await session.commit()

    async def _finish(
        self,
        operation_id: uuid.UUID,
        status: str,
        error: str | None,
        *,
        clear_lease: bool = True,
    ) -> None:
        async with self._session_factory() as session:
            await repo.set_operation_status(
                session, operation_id, status=status, error=error, clear_lease=clear_lease
            )
            await session.commit()

    async def _mark_provisioning(self, consumer_id: uuid.UUID, state: str) -> None:
        async with self._session_factory() as session:
            await repo.update_consumer(session, consumer_id, provisioning_state=state)
            await session.commit()

    async def _release_reservation(self, delivery_id: uuid.UUID, detail: str) -> None:
        """Deja la reserva como 'reserved' para poder reintentar el claim."""
        async with self._session_factory() as session:
            await repo.update_delivery(session, delivery_id, error=detail)
            await session.commit()

    async def _mark_delivery_failed(self, delivery_id: uuid.UUID, detail: str) -> None:
        async with self._session_factory() as session:
            await repo.update_delivery(
                session, delivery_id, state="failed", error=detail
            )
            await session.commit()


def to_app_error(exc: Exception) -> AppError:
    """Traduce lo que sube del aprovisionador a un error de dominio."""
    if isinstance(exc, AppError):
        return exc
    if isinstance(exc, ProvisioningUnavailable):
        return UpstreamUnavailableError(exc.message)
    if isinstance(exc, (VaultSealed, VaultUnavailable)):
        return UpstreamUnavailableError(f"Vault: {exc.message}")
    if isinstance(exc, VaultError):
        return UpstreamUnavailableError(f"Vault rechazo la operacion: {exc.message}")
    return AppError("error interno del aprovisionador", status_code=500)


__all__ = [
    "Accepted",
    "AckResult",
    "IssuedDelivery",
    "PendingClaim",
    "ProvisioningService",
    "fingerprint",
    "to_app_error",
]
