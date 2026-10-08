"""Consumidores de maquina y resolucion de entregas para el futuro crawler.

El crawler es una maquina independiente. Dos contratos separados, a proposito:

* **Humano**: ``api_session`` opaca -> pasarela interna -> token humano. Lo usan
  los endpoints de negocio.
* **Maquina**: token de Vault obtenido con su propia AppRole de solo lectura,
  presentado en ``Authorization``. Lo usa ``/integrations/crawler/resolve``.

Aqui no se presta la sesion de nadie, no se acepta un ``consumer_id`` del
cliente (se resuelve desde la identidad del token), no se admite un path libre
ni una URL, y no se emiten tokens de autenticacion nuevos. Si la autenticacion
de la maquina falla, **no** hay vuelta a la cuenta tecnica del servicio.

Dos modos de lectura, y la diferencia importa
---------------------------------------------
* **Consumidor HEREDADO** (``delivery_mode='direct'``, etapa 4, por CLI): la
  lectura se hace con el token de **esa** maquina, asi que la ACL de Vault
  aplica sus permisos. El limite real de lo que puede leer es su politica, que
  cubre todo el prefijo gestionado: sus bindings acotan lo que esta API le
  entrega, **no** lo que su token podria leer por su cuenta. Decir lo contrario
  seria falso.
* **Consumidor GESTIONADO** (``delivery_mode='mediated'``, etapa 4.6): su politica **no**
  incluye lectura del prefijo KV. La entrega es *mediada*: el backend autorizado
  lee la version permitida por el binding y la envuelve para el. Aqui si los
  bindings y ``pinned_version`` son el limite efectivo, porque el token del
  consumidor no puede leer nada mas por si mismo.

Migrar un consumidor heredado a entrega mediada es una decision explicita (hay
que estrechar su politica en Vault), no algo que ocurra solo.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthenticatedError,
    UpstreamUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.vault import VaultError, VaultSealed, VaultUnavailable
from app.core.vault_kv import KvV2Client
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.machine_auth import (
    MachineAuthError,
    MachineIdentity,
    VaultProbe,
    assert_identity_matches,
    identity_from_lookup,
)
from app.vault_mgmt.core.principal import HumanPrincipal, require_admin
from app.vault_mgmt.core.vault_auth import ProvisioningUnavailable, VaultTokenProvider
from app.vault_mgmt.models.catalog import SecretConsumer
from app.vault_mgmt.repositories import audit as audit_repo
from app.vault_mgmt.repositories import catalog as repo

logger = get_logger(__name__)


@dataclass(slots=True)
class Delivery:
    collection_id: uuid.UUID
    record_id: uuid.UUID
    version: int
    pinned: bool
    wrap_token: str
    ttl_seconds: int
    expires_at: dt.datetime
    # True cuando la leyo el backend autorizado por cuenta del consumidor
    # (consumidor gestionado). False cuando la leyo su propio token (heredado).
    mediated: bool = False


@dataclass(slots=True)
class ResolveResult:
    consumer_name: str
    requested: int
    deliveries: list[Delivery]
    rejected: list[dict[str, str]]


class ConsumerService:
    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        probe: VaultProbe,
        kv_factory: Any,
        token_provider: VaultTokenProvider | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._probe = probe
        self._kv_factory = kv_factory
        self._kv_cache: dict[str, KvV2Client] = {}
        # Solo para la entrega MEDIADA de consumidores gestionados. Sin el, un
        # consumidor gestionado recibe 503 en vez de una lectura con permisos
        # que no le corresponden.
        self._token_provider = token_provider

    async def aclose(self) -> None:
        for client in self._kv_cache.values():
            await client.aclose()
        self._kv_cache.clear()

    def _kv(self, mount: str) -> KvV2Client:
        if mount not in self._kv_cache:
            self._kv_cache[mount] = self._kv_factory(mount)
        return self._kv_cache[mount]

    # -- administracion de bindings (humano, admin) --------------------------

    async def put_bindings(
        self,
        *,
        principal: HumanPrincipal,
        consumer_id: uuid.UUID,
        entries: list[tuple[uuid.UUID, uuid.UUID, int | None]],
        request_id: str | None,
    ) -> tuple[SecretConsumer, list[Any]]:
        """Reemplazo COMPLETO de las asignaciones de un consumidor."""
        require_admin(principal, "asignar registros a un consumidor de maquina")

        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            if consumer.state != "active":
                raise ConflictError(
                    "el consumidor esta revocado: reactivalo por CLI antes de "
                    "asignarle registros",
                    code="consumer_revoked",
                )

            # Cada entrada se valida contra el catalogo: coleccion activa,
            # registro existente en ESA coleccion y version viva si se fija.
            for collection_id, record_id, pinned_version in entries:
                collection = await repo.require_collection(session, collection_id)
                if collection.state != "active":
                    raise ConflictError(
                        f"la coleccion '{collection.logical_name}' esta "
                        f"'{collection.state}': no se asignan entregas sobre ella",
                        code="collection_not_active",
                    )
                record = await repo.require_record(session, collection_id, record_id)
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

            count = await repo.replace_bindings(
                session,
                consumer_id=consumer_id,
                entries=entries,
                created_by=principal.user_id,
            )
            await audit_repo.record(
                session,
                actor_kind="human",
                actor_user_id=principal.user_id,
                actor_label=principal.username,
                action="consumer_bindings_update",
                outcome="allowed",
                request_id=request_id,
                detail=(
                    f"consumidor '{consumer.name}': {count} asignaciones. "
                    "Revocar impide entregas futuras, no caduca lo ya entregado."
                ),
            )
            await session.commit()
            bindings = await repo.list_bindings(session, consumer_id)
        return consumer, bindings

    async def get_bindings(
        self, *, principal: HumanPrincipal, consumer_id: uuid.UUID
    ) -> tuple[SecretConsumer, list[Any], dict[uuid.UUID, str]]:
        require_admin(principal, "consultar las asignaciones de un consumidor")
        async with self._session_factory() as session:
            consumer = await repo.require_consumer(session, consumer_id)
            bindings = await repo.list_bindings(session, consumer_id)
            names: dict[uuid.UUID, str] = {}
            for binding in bindings:
                if binding.collection_id not in names:
                    collection = await repo.get_collection(session, binding.collection_id)
                    names[binding.collection_id] = (
                        collection.logical_name if collection else ""
                    )
        return consumer, bindings, names

    # -- autenticacion de la maquina ----------------------------------------

    async def authenticate_machine(self, token: str) -> tuple[SecretConsumer, MachineIdentity]:
        """Valida el token y resuelve el consumidor desde su IDENTIDAD.

        Nunca desde un ``consumer_id`` que venga del cliente: eso permitiria a
        una maquina reclamar el alcance de otra.
        """
        if not token:
            raise UnauthenticatedError(
                "falta la cabecera Authorization con el token de Vault de la "
                "maquina. Obtenlo antes con tu AppRole: "
                "POST auth/<montaje>/login",
                code="machine_token_missing",
            )
        try:
            data = await self._probe.lookup_self(token)
        except MachineAuthError as exc:
            raise UnauthenticatedError(
                "el token presentado no es valido en Vault", code="machine_token_invalid"
            ) from exc
        except (VaultSealed, VaultUnavailable) as exc:
            raise UpstreamUnavailableError(f"Vault: {exc.message}") from exc
        except VaultError as exc:
            raise UpstreamUnavailableError(
                f"no se pudo validar el token en Vault: {exc.message}"
            ) from exc

        identity = identity_from_lookup(data)
        mount = identity.approle_mount
        if not mount or not identity.role_name:
            raise ForbiddenError(
                "el token no acredita una identidad AppRole: no lleva montaje ni "
                "rol reconocibles. Un token de userpass o de root no sirve aqui.",
                code="machine_identity_unknown",
            )

        async with self._session_factory() as session:
            consumer = await repo.find_consumer_by_identity(
                session, approle_mount=mount, approle_role_name=identity.role_name
            )
        if consumer is None:
            raise ForbiddenError(
                "ningun consumidor registrado corresponde a esa identidad AppRole. "
                "Registralo por CLI: "
                "scripts/vault_mgmt/crawler-approle-bootstrap.sh",
                code="consumer_not_registered",
            )
        if consumer.state != "active":
            raise ForbiddenError(
                "el consumidor esta revocado: no se preparan entregas nuevas",
                code="consumer_revoked",
            )

        try:
            assert_identity_matches(
                identity,
                expected_mount=consumer.approle_mount,
                expected_role=consumer.approle_role_name,
                expected_policy=consumer.expected_policy,
            )
        except MachineAuthError as exc:
            if exc.status_code == 401:
                raise UnauthenticatedError(exc.message, code="machine_token_expired") from exc
            raise ForbiddenError(exc.message, code="machine_identity_mismatch") from exc

        return consumer, identity

    # -- resolucion de entregas ---------------------------------------------

    async def resolve(
        self,
        *,
        token: str,
        requests: list[tuple[uuid.UUID, uuid.UUID, int | None]],
        wrap_ttl_seconds: int | None,
        job_reference: str | None,
        request_id: str | None,
    ) -> ResolveResult:
        """Entrega envuelta de registros explicitos. No inicia ningun crawling."""
        if len(requests) > self._settings.max_crawler_records:
            raise ValidationError(
                f"como maximo {self._settings.max_crawler_records} registros por "
                "peticion",
                code="too_many_records",
            )

        consumer, _identity = await self.authenticate_machine(token)
        ttl = wrap_ttl_seconds or self._settings.wrap_ttl_seconds

        deliveries: list[Delivery] = []
        rejected: list[dict[str, str]] = []

        for collection_id, record_id, requested_version in requests:
            try:
                plan = await self._plan_delivery(
                    consumer_id=consumer.consumer_id,
                    collection_id=collection_id,
                    record_id=record_id,
                    requested_version=requested_version,
                )
            except (NotFoundError, ForbiddenError, ConflictError, ValidationError) as exc:
                rejected.append(
                    {
                        "record_id": str(record_id),
                        "code": exc.code,
                        "reason": exc.message,
                    }
                )
                await self._audit_machine(
                    consumer=consumer,
                    action="crawler_resolve",
                    outcome="denied",
                    collection_id=collection_id,
                    record_id=record_id,
                    request_id=request_id,
                    detail=f"{exc.code}: {exc.message}",
                )
                continue

            mount, logical_path, version, pinned = plan
            kv = self._kv(mount)
            try:
                reading_token = await self._reading_token(consumer, token)
                wrapped = await kv.read_version_wrapped(
                    reading_token, logical_path, version=version, wrap_ttl_seconds=ttl
                )
            except ProvisioningUnavailable as exc:
                rejected.append(
                    {
                        "record_id": str(record_id),
                        "code": "mediated_delivery_unavailable",
                        "reason": exc.message,
                    }
                )
                continue
            except VaultError as exc:
                # La ACL de la maquina manda: si su politica no cubre el path,
                # el rechazo es de Vault y se reporta como tal.
                rejected.append(
                    {
                        "record_id": str(record_id),
                        "code": "vault_denied",
                        "reason": exc.message,
                    }
                )
                await self._audit_machine(
                    consumer=consumer,
                    action="crawler_resolve",
                    outcome="denied",
                    collection_id=collection_id,
                    record_id=record_id,
                    versions=[version] if version else None,
                    request_id=request_id,
                    detail=f"vault rechazo la lectura: {exc.message}",
                )
                continue

            deliveries.append(
                Delivery(
                    collection_id=collection_id,
                    record_id=record_id,
                    version=version or 0,
                    pinned=pinned,
                    wrap_token=wrapped.token,
                    ttl_seconds=wrapped.ttl_seconds,
                    expires_at=dt.datetime.now(dt.UTC)
                    + dt.timedelta(seconds=wrapped.ttl_seconds),
                    mediated=consumer.is_mediated,
                )
            )
            await self._audit_machine(
                consumer=consumer,
                action="crawler_resolve",
                outcome="allowed",
                collection_id=collection_id,
                record_id=record_id,
                versions=[version] if version else None,
                request_id=request_id,
                # Se registra que se entrego y con que TTL. NUNCA el wrapping
                # token ni los valores.
                detail=(
                    f"entrega envuelta, ttl {wrapped.ttl_seconds}s, "
                    f"{'version fijada' if pinned else 'latest'}"
                    + (f"; tarea: {job_reference}" if job_reference else "")
                ),
            )

        return ResolveResult(
            consumer_name=consumer.name,
            requested=len(requests),
            deliveries=deliveries,
            rejected=rejected,
        )

    async def _reading_token(self, consumer: SecretConsumer, machine_token: str) -> str:
        """Con que token se lee el registro, segun el tipo de consumidor.

        Gestionado -> el del backend autorizado (entrega mediada), porque su
        politica no cubre la lectura de KV. Heredado -> el suyo, como en la
        etapa 4, de modo que la ACL de Vault aplique SUS permisos.
        """
        if not consumer.is_mediated:
            return machine_token
        if self._token_provider is None:
            raise ProvisioningUnavailable(
                "este consumidor usa entrega mediada y el servicio no tiene "
                "token autorizado para leer por el"
            )
        return await self._token_provider.token()

    async def _plan_delivery(
        self,
        *,
        consumer_id: uuid.UUID,
        collection_id: uuid.UUID,
        record_id: uuid.UUID,
        requested_version: int | None,
    ) -> tuple[str, str, int | None, bool]:
        """Resuelve montaje, path y version desde el catalogo y el binding."""
        async with self._session_factory() as session:
            binding = await repo.get_binding(
                session, consumer_id=consumer_id, record_id=record_id
            )
            if binding is None:
                raise ForbiddenError(
                    "este consumidor no tiene asignado ese registro",
                    code="binding_missing",
                )
            if binding.collection_id != collection_id:
                raise ForbiddenError(
                    "el registro no pertenece a la coleccion indicada",
                    code="binding_mismatch",
                )
            collection = await repo.require_collection(session, collection_id)
            if collection.state != "active":
                raise ConflictError(
                    f"la coleccion esta '{collection.state}': no se preparan "
                    "entregas nuevas",
                    code=f"collection_{collection.state}",
                )
            record = await repo.require_record(session, collection_id, record_id)
            if record.state == "destroyed":
                raise ConflictError(
                    "el registro esta destruido: su contenido no existe y no se "
                    "puede recuperar",
                    code="record_destroyed",
                )
            if record.state == "soft_deleted":
                raise ConflictError(
                    "la version actual del registro esta borrada (soft-delete)",
                    code="record_soft_deleted",
                )

            pinned = binding.pinned_version is not None
            if (
                requested_version is not None
                and pinned
                and requested_version != binding.pinned_version
            ):
                raise ForbiddenError(
                    f"el binding fija la version {binding.pinned_version}: no "
                    "se entrega otra",
                    code="version_not_allowed",
                )
            version = requested_version or binding.pinned_version
            mount = collection.kv_mount
            logical_path = collection.record_path(record_id)
        return mount, logical_path, version, pinned

    async def _audit_machine(
        self,
        *,
        consumer: SecretConsumer,
        action: str,
        outcome: str,
        collection_id: uuid.UUID | None = None,
        record_id: uuid.UUID | None = None,
        versions: list[int] | None = None,
        request_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            await audit_repo.record(
                session,
                actor_kind="machine",
                actor_user_id=None,
                actor_label=consumer.name,
                action=action,
                outcome=outcome,
                collection_id=collection_id,
                record_id=record_id,
                versions=versions,
                request_id=request_id,
                detail=detail,
            )
            await session.commit()


__all__ = ["ConsumerService", "Delivery", "ResolveResult"]
