"""Mapeo ORM del esquema ``employees`` que YA existe en PostgreSQL.

Los nombres de columna salen de ``sql/001_employees.sql`` y
``sql/002_vault_operations.sql``, no de las etiquetas del README.

Nada aqui crea esquema: no hay ``create_all()`` ni ``metadata.create_all`` en
ningun punto del servicio. Los ``server_default`` declarados son los que ya
tiene la base (``gen_random_uuid()``, ``now()``) y estan presentes solo para que
el ORM no intente escribir valores propios encima.

``updated_at`` lo mantiene un trigger de PostgreSQL
(``employees.set_updated_at``): el ORM no lo toca y lo relee tras escribir.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCHEMA = "employees"


class Base(DeclarativeBase):
    """Base declarativa. Se usa SOLO para mapear, nunca para emitir DDL."""

    metadata_schema = SCHEMA


def _pk_uuid() -> Mapped[uuid.UUID]:
    return mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )


def _created_at() -> Mapped[dt.datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _updated_at() -> Mapped[dt.datetime]:
    # server_onupdate no se declara: lo hace el trigger set_updated_at.
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    username: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    auth_provider: Mapped[str] = mapped_column(Text, nullable=False, server_default="vault")
    # Reservado para Argon2id. Debe ser NULL con auth_provider != 'local'
    # (lo impone users_delegated_no_hash_ck en la base).
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    profile: Mapped["UserProfile | None"] = relationship(
        back_populates="user", uselist=False, lazy="raise", cascade="all, delete-orphan"
    )
    emails: Mapped[list["UserEmail"]] = relationship(
        back_populates="user", lazy="raise", cascade="all, delete-orphan"
    )
    phones: Mapped[list["UserPhone"]] = relationship(
        back_populates="user", lazy="raise", cascade="all, delete-orphan"
    )
    addresses: Mapped[list["UserAddress"]] = relationship(
        back_populates="user", lazy="raise", cascade="all, delete-orphan"
    )
    role_links: Mapped[list["UserRole"]] = relationship(
        back_populates="user",
        lazy="raise",
        cascade="all, delete-orphan",
        foreign_keys="UserRole.user_id",
    )
    vault_identity: Mapped["UserVaultIdentity | None"] = relationship(
        back_populates="user", uselist=False, lazy="raise", cascade="all, delete-orphan"
    )


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = {"schema": SCHEMA}

    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.roles.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    assigned_at: Mapped[dt.datetime] = _created_at()
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    user: Mapped["User"] = relationship(
        back_populates="role_links", foreign_keys=[user_id], lazy="raise"
    )
    role: Mapped["Role"] = relationship(lazy="joined")


class UserProfile(Base):
    __tablename__ = "user_profiles"
    __table_args__ = {"schema": SCHEMA}

    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    first_name: Mapped[str] = mapped_column(Text, nullable=False)
    last_name_paternal: Mapped[str] = mapped_column(Text, nullable=False)
    last_name_maternal: Mapped[str | None] = mapped_column(Text, nullable=True)
    birth_date: Mapped[dt.date] = mapped_column(Date, nullable=False)
    rfc: Mapped[str | None] = mapped_column(Text, nullable=True)
    curp: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    user: Mapped["User"] = relationship(back_populates="profile", lazy="raise")


class UserEmail(Base):
    __tablename__ = "user_emails"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    user: Mapped["User"] = relationship(back_populates="emails", lazy="raise")


class UserPhone(Base):
    __tablename__ = "user_phones"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    country_code: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="52")
    phone_number: Mapped[str] = mapped_column(Text, nullable=False)
    phone_type: Mapped[str] = mapped_column(Text, nullable=False, server_default="mobile")
    extension: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    user: Mapped["User"] = relationship(back_populates="phones", lazy="raise")


class UserAddress(Base):
    __tablename__ = "user_addresses"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    neighborhood: Mapped[str | None] = mapped_column(Text, nullable=True)
    street: Mapped[str] = mapped_column(Text, nullable=False)
    exterior_number: Mapped[str] = mapped_column(Text, nullable=False)
    interior_number: Mapped[str | None] = mapped_column(Text, nullable=True)
    postal_code: Mapped[str] = mapped_column(Text, nullable=False)
    city: Mapped[str | None] = mapped_column(Text, nullable=True)
    state_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    country_code: Mapped[str] = mapped_column(Text, nullable=False, server_default="MX")
    address_type: Mapped[str] = mapped_column(Text, nullable=False, server_default="home")
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    user: Mapped["User"] = relationship(back_populates="addresses", lazy="raise")


class VaultAuthConfig(Base):
    __tablename__ = "vault_auth_config"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = _pk_uuid()
    userpass_path: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # TEXT, no UUID: los accessors de Vault son "auth_userpass_1a2b3c4d".
    userpass_accessor: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    totp_method_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    mfa_enforcement_name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()


class UserVaultIdentity(Base):
    __tablename__ = "user_vault_identity"
    __table_args__ = {"schema": SCHEMA}

    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    vault_auth_config_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.vault_auth_config.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vault_username: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    vault_entity_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), nullable=False, unique=True
    )
    totp_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    totp_generated_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    totp_confirmed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_mfa_login_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()

    user: Mapped["User"] = relationship(back_populates="vault_identity", lazy="raise")
    auth_config: Mapped["VaultAuthConfig"] = relationship(lazy="joined")


class VaultOperation(Base):
    """Registro durable de operaciones que tocan Vault y PostgreSQL (migracion 002)."""

    __tablename__ = "vault_operations"
    __table_args__ = {"schema": SCHEMA}

    operation_id: Mapped[uuid.UUID] = _pk_uuid()
    operation_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{SCHEMA}.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    target_username: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    phases: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = _created_at()
    updated_at: Mapped[dt.datetime] = _updated_at()
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# Estados terminales de una operacion.
TERMINAL_OPERATION_STATUSES = frozenset({"succeeded", "failed", "needs_reconciliation"})
ACTIVE_OPERATION_STATUSES = frozenset({"pending", "in_progress"})

# Valores admitidos por los CHECK de la base, replicados aqui solo para validar
# antes de llegar a PostgreSQL y devolver 422 en vez de 500.
TOTP_STATUSES = ("pending", "confirmed", "reset_required", "disabled")
AUTH_PROVIDERS = ("vault", "oidc", "local")
ROLE_CODES = ("admin", "manager", "employee")

__all__ = [
    "Base",
    "SCHEMA",
    "User",
    "Role",
    "UserRole",
    "UserProfile",
    "UserEmail",
    "UserPhone",
    "UserAddress",
    "VaultAuthConfig",
    "UserVaultIdentity",
    "VaultOperation",
    "TOTP_STATUSES",
    "AUTH_PROVIDERS",
    "ROLE_CODES",
    "ACTIVE_OPERATION_STATUSES",
    "TERMINAL_OPERATION_STATUSES",
]


# Silenciar linters sobre importaciones usadas solo en anotaciones de columna.
_UNUSED = (CheckConstraint, Index, UniqueConstraint, String, Integer)
