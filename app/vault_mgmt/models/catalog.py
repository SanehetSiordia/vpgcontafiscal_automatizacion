"""Mapeo ORM del esquema ``vault_mgmt`` que YA existe en PostgreSQL.

Los nombres de columna salen de ``sql/003_vault_mgmt.sql``, no de las etiquetas
del README. Nada aqui crea esquema: no hay ``create_all()`` en ningun punto del
servicio. Los ``server_default`` declarados son los que ya tiene la base y estan
presentes solo para que el ORM no escriba valores propios encima.

``Base`` es una declarativa PROPIA, distinta de la de la etapa 3: los dos
servicios comparten imagen pero no metadatos, y asi un mapeo no arrastra al
otro. La unica tabla ajena que se referencia es ``employees.users``, y solo por
clave foranea en la base, no por relacion del ORM.

Ninguna de estas tablas guarda valores de secretos, ni hashes, ni longitudes.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA = "vault_mgmt"
EMPLOYEES_SCHEMA = "employees"

# UUID todo-ceros: en ``secret_operations`` representa "la coleccion entera" en
# el indice parcial que serializa operaciones. No es un recurso real.
COLLECTION_SCOPE_SENTINEL = uuid.UUID("00000000-0000-0000-0000-000000000000")


class Base(DeclarativeBase):
    """Base declarativa de vault-mgmt. Se usa SOLO para mapear, nunca para DDL."""


def _pk_uuid() -> Mapped[uuid.UUID]:
    return mapped_column(
        PgUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )


def _created_at() -> Mapped[dt.datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _updated_at() -> Mapped[dt.datetime]:
    # server_onupdate no se declara: lo hace el trigger set_updated_at.
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _actor_column() -> Mapped[uuid.UUID | None]:
    """Referencia al empleado que actuo.

    La clave foranea a ``employees.users`` existe en la BASE (la declara la
    migracion 003 con ``ON DELETE SET NULL``), pero NO se declara aqui a
    proposito: ``employees.users`` se mapea en la declarativa de la etapa 3, no
    en esta. Declarar la FK en estos metadatos obligaria a SQLAlchemy a
    resolver una tabla que no conoce y fallaria al ordenar las escrituras
    (``NoReferencedTableError``).

    Compartir una sola declarativa entre los dos servicios resolveria la
    resolucion, pero acoplaria los mapeos: un cambio en el modelo de empleados
    arrastraria a este. La integridad la impone PostgreSQL, que es donde debe
    estar; el ORM solo necesita el tipo de la columna.
    """
    return mapped_column(PgUUID(as_uuid=True), nullable=True)


class SecretCollection(Base):
    __tablename__ = "secret_collections"
    __table_args__ = {"schema": SCHEMA}

    collection_id: Mapped[uuid.UUID] = _pk_uuid()
    logical_name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    current_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1"
    )
    reader_role_codes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    kv_mount: Mapped[str] = mapped_column(Text, nullable=False, server_default="secret")
    kv_prefix: Mapped[str] = mapped_column(Text, nullable=False, server_default="vpg-managed")
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    archived_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    purged_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # -- derivados -----------------------------------------------------------

    @property
    def base_path(self) -> str:
        """Prefijo logico del secreto, SIN los segmentos data/metadata.

        ``{prefix}/{collection_id}``. Se deriva del UUID y no del nombre
        logico: renombrar la coleccion no cambia donde viven los datos.
        """
        return f"{self.kv_prefix}/{self.collection_id}"

    def record_path(self, record_id: uuid.UUID) -> str:
        return f"{self.base_path}/{record_id}"


class SecretCollectionSchema(Base):
    __tablename__ = "secret_collection_schemas"
    __table_args__ = {"schema": SCHEMA}

    collection_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_collections.collection_id", ondelete="CASCADE"),
        primary_key=True,
    )
    schema_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    fields: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    json_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()


class SecretRecord(Base):
    __tablename__ = "secret_records"
    __table_args__ = {"schema": SCHEMA}

    record_id: Mapped[uuid.UUID] = _pk_uuid()
    collection_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_collections.collection_id", ondelete="CASCADE"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    deleted_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class SecretConsumer(Base):
    __tablename__ = "secret_consumers"
    __table_args__ = {"schema": SCHEMA}

    consumer_id: Mapped[uuid.UUID] = _pk_uuid()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    approle_mount: Mapped[str] = mapped_column(Text, nullable=False)
    approle_role_name: Mapped[str] = mapped_column(Text, nullable=False)
    expected_policy: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- etapa 4.6: aprovisionamiento automatico (migracion 004) ------------
    # direct: consumidor HEREDADO de la etapa 4, preparado por CLI. Su token lee
    #   el prefijo KV por si mismo.
    # mediated: consumidor de la etapa 4.6. Su politica NO cubre la lectura de
    #   KV: el backend autorizado lee la version permitida y se la envuelve.
    delivery_mode: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="direct"
    )
    provisioning_state: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="unprovisioned"
    )
    # Accessors, no credenciales: identifican para revocar, no permiten usar.
    secret_id_accessor: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Credencial anterior durante una rotacion after_ack. Se destruye cuando el
    # receptor confirma la nueva, no antes.
    previous_secret_id_accessor: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    last_token_accessor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_operation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )
    provisioned_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def is_mediated(self) -> bool:
        return self.delivery_mode == "mediated"


class SecretConsumerBinding(Base):
    __tablename__ = "secret_consumer_bindings"
    __table_args__ = {"schema": SCHEMA}

    binding_id: Mapped[uuid.UUID] = _pk_uuid()
    consumer_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_consumers.consumer_id", ondelete="CASCADE"),
        nullable=False,
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_collections.collection_id", ondelete="CASCADE"),
        nullable=False,
    )
    record_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_records.record_id", ondelete="CASCADE"),
        nullable=False,
    )
    pinned_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()


class SecretOperation(Base):
    __tablename__ = "secret_operations"
    __table_args__ = {"schema": SCHEMA}

    operation_id: Mapped[uuid.UUID] = _pk_uuid()
    operation_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    collection_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_collections.collection_id", ondelete="SET NULL"),
        nullable=True,
    )
    # Sin FK: una purga borra el registro y la operacion debe sobrevivir.
    record_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    actor_user_id: Mapped[uuid.UUID | None] = _actor_column()
    actor_username: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    phases: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    counters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- etapa 4.6 (migracion 004) -----------------------------------------
    consumer_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_consumers.consumer_id", ondelete="SET NULL"),
        nullable=True,
    )
    # Huella de los parametros NO sensibles de la solicitud. Permite distinguir
    # "misma clave, misma peticion" de "misma clave, otra peticion" -> 409.
    request_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Arrendamiento del worker. Caduca solo: un worker muerto no bloquea la cola.
    lease_owner: Mapped[str | None] = mapped_column(Text, nullable=True)
    leased_until: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


class SecretReceiver(Base):
    """Quien puede reclamar la emision de un consumidor.

    ``credential_ref`` es el NOMBRE del archivo de secreto, no su contenido. Esa
    referencia es lo que asocia, en el servidor, una credencial concreta con un
    consumidor autorizado; el ``consumer_id`` no sirve para eso porque no es una
    contrasena y aparece en respuestas de inventario.
    """

    __tablename__ = "secret_receivers"
    __table_args__ = {"schema": SCHEMA}

    receiver_id: Mapped[uuid.UUID] = _pk_uuid()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    consumer_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_consumers.consumer_id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_ref: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = _actor_column()
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    last_claim_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ProvisioningDelivery(Base):
    """Una emision concreta hacia un receptor.

    No guarda el SecretID, ni el wrapping token, ni el token de Vault: solo sus
    ACCESSORS, que sirven para revocar y auditar pero no para autenticarse.
    """

    __tablename__ = "secret_provisioning_deliveries"
    __table_args__ = {"schema": SCHEMA}

    delivery_id: Mapped[uuid.UUID] = _pk_uuid()
    operation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_operations.operation_id", ondelete="CASCADE"),
        nullable=False,
    )
    consumer_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_consumers.consumer_id", ondelete="CASCADE"),
        nullable=False,
    )
    receiver_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.secret_receivers.receiver_id", ondelete="CASCADE"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="reserved")
    secret_id_accessor: Mapped[str | None] = mapped_column(Text, nullable=True)
    wrap_accessor: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_accessor: Mapped[str | None] = mapped_column(Text, nullable=True)
    wrap_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    claimed_at: Mapped[dt.datetime] = _created_at()
    # Caducidad de la ENVOLTURA. Pasada sin ack, el SecretID sigue vivo en Vault
    # y hay que destruirlo por su accessor: eso es reconciliar.
    expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()


class SecretAudit(Base):
    __tablename__ = "secret_audit"
    __table_args__ = {"schema": SCHEMA}

    audit_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[dt.datetime] = _created_at()
    actor_kind: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = _actor_column()
    actor_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    collection_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    record_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    versions: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    operation_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    request_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


# Valores admitidos por los CHECK de la base, replicados aqui solo para validar
# antes de llegar a PostgreSQL y devolver 422 en vez de 500.
COLLECTION_STATES = ("active", "archived", "purged")
RECORD_STATES = ("active", "soft_deleted", "destroyed")
CONSUMER_STATES = ("active", "revoked")
PROVISIONING_STATES = (
    "unprovisioned",
    "provisioning",
    "ready",
    "failed",
    "revoked",
)
DELIVERY_MODES = ("direct", "mediated")
RECEIVER_STATES = ("active", "disabled")
DELIVERY_STATES = (
    "reserved",
    "delivered",
    "acked",
    "expired",
    "failed",
    "superseded",
)
# Una entrega "viva" es la que todavia puede acabar en manos del receptor. El
# indice parcial secret_provisioning_deliveries_one_live_ux usa estas dos.
LIVE_DELIVERY_STATES = frozenset({"reserved", "delivered"})

OPERATION_STATUSES = (
    "pending",
    "in_progress",
    "waiting_receiver",
    "awaiting_ack",
    "completed",
    "failed",
    "needs_reconciliation",
)
# Estados vivos. 'waiting_receiver' y 'awaiting_ack' son de la etapa 4.6: la
# solicitud esta guardada y la operacion sigue abierta, pero el trabajo no
# depende de este proceso sino de que aparezca el receptor.
ACTIVE_OPERATION_STATUSES = frozenset(
    {"pending", "in_progress", "waiting_receiver", "awaiting_ack"}
)
# Lo que el worker puede tomar de la cola. 'awaiting_ack' NO esta: ahi se espera
# al receptor, no hay trabajo que hacer.
CLAIMABLE_OPERATION_STATUSES = frozenset({"pending", "in_progress"})
TERMINAL_OPERATION_STATUSES = frozenset({"completed", "failed", "needs_reconciliation"})
CONSUMER_OPERATION_TYPES = frozenset(
    {"consumer_register", "consumer_provision", "consumer_rotate", "consumer_revoke"}
)
OPERATION_TYPES = (
    "collection_create",
    "collection_update",
    "collection_schema_update",
    "collection_archive",
    "collection_restore",
    "collection_purge",
    "record_create",
    "record_replace",
    "record_patch",
    "record_soft_delete",
    "versions_delete",
    "versions_undelete",
    "versions_destroy",
    "record_purge",
    "consumer_bindings_update",
    "inventory_import",
    "consumer_register",
    "consumer_provision",
    "consumer_rotate",
    "consumer_revoke",
)
READER_ROLE_CODES = ("admin", "manager", "employee")

__all__ = [
    "Base",
    "SCHEMA",
    "EMPLOYEES_SCHEMA",
    "COLLECTION_SCOPE_SENTINEL",
    "ProvisioningDelivery",
    "SecretAudit",
    "SecretCollection",
    "SecretCollectionSchema",
    "SecretConsumer",
    "SecretReceiver",
    "SecretConsumerBinding",
    "SecretOperation",
    "SecretRecord",
    "ACTIVE_OPERATION_STATUSES",
    "CLAIMABLE_OPERATION_STATUSES",
    "COLLECTION_STATES",
    "CONSUMER_OPERATION_TYPES",
    "CONSUMER_STATES",
    "DELIVERY_MODES",
    "DELIVERY_STATES",
    "LIVE_DELIVERY_STATES",
    "OPERATION_STATUSES",
    "OPERATION_TYPES",
    "PROVISIONING_STATES",
    "RECEIVER_STATES",
    "READER_ROLE_CODES",
    "RECORD_STATES",
    "TERMINAL_OPERATION_STATUSES",
]
