"""Consultas sobre el agregado de empleado.

Todo va por SQLAlchemy con parametros vinculados: no se construye SQL
concatenando valores. Las relaciones se cargan con ``selectinload`` explicito
para no provocar N+1 (los ``relationship`` estan declarados ``lazy="raise"``, de
modo que un acceso perezoso accidental falla en pruebas en vez de disparar
consultas sueltas en produccion).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence

from sqlalchemy import Select, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.employees import (
    Role,
    User,
    UserAddress,
    UserEmail,
    UserPhone,
    UserProfile,
    UserRole,
    UserVaultIdentity,
    VaultAuthConfig,
)

# Allowlist de columnas por las que se puede ordenar. Impide que el cliente
# inyecte una expresion arbitraria en el ORDER BY.
SORTABLE_COLUMNS = {
    "created_at": User.created_at,
    "updated_at": User.updated_at,
    "username": User.username,
}

_FULL_LOAD = (
    selectinload(User.profile),
    selectinload(User.emails),
    selectinload(User.phones),
    selectinload(User.addresses),
    selectinload(User.role_links).selectinload(UserRole.role),
    selectinload(User.vault_identity).selectinload(UserVaultIdentity.auth_config),
)


def _with_relations(stmt: Select) -> Select:
    return stmt.options(*_FULL_LOAD)


async def get_by_id(
    session: AsyncSession, user_id: uuid.UUID, *, refresh: bool = False
) -> User | None:
    """Carga el agregado completo.

    ``refresh=True`` fuerza ``populate_existing``: sin el, SQLAlchemy devuelve
    la instancia que ya esta en el identity map **con sus colecciones tal como
    se cargaron**, asi que un borrado o un alta recien aplicados no se verian.
    Se usa despues de cada mutacion, antes de proyectar la respuesta.
    """
    stmt = _with_relations(select(User).where(User.id == user_id))
    if refresh:
        stmt = stmt.execution_options(populate_existing=True)
    return (await session.execute(stmt)).scalar_one_or_none()


async def get_by_username(session: AsyncSession, username: str) -> User | None:
    stmt = _with_relations(select(User).where(func.lower(User.username) == username.lower()))
    return (await session.execute(stmt)).scalar_one_or_none()


async def username_exists(session: AsyncSession, username: str) -> bool:
    stmt = select(func.count()).select_from(User).where(
        func.lower(User.username) == username.lower()
    )
    return bool((await session.execute(stmt)).scalar_one())


async def email_owner(session: AsyncSession, email: str) -> uuid.UUID | None:
    stmt = select(UserEmail.user_id).where(func.lower(UserEmail.email) == email.lower())
    return (await session.execute(stmt)).scalar_one_or_none()


async def rfc_or_curp_owner(
    session: AsyncSession, *, rfc: str | None, curp: str | None
) -> uuid.UUID | None:
    conditions = []
    if rfc:
        conditions.append(UserProfile.rfc == rfc)
    if curp:
        conditions.append(UserProfile.curp == curp)
    if not conditions:
        return None
    from sqlalchemy import or_

    stmt = select(UserProfile.user_id).where(or_(*conditions)).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_users(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    role_code: str | None = None,
    is_active: bool | None = None,
    sort_by: str = "created_at",
    descending: bool = True,
) -> tuple[Sequence[User], int]:
    """Listado paginado con orden ESTABLE.

    El orden siempre termina en ``User.id`` para que dos filas con el mismo
    valor de ordenacion no cambien de posicion entre paginas.
    """
    column = SORTABLE_COLUMNS.get(sort_by)
    if column is None:
        raise ValueError(f"columna de orden no permitida: {sort_by}")

    filters = []
    if is_active is not None:
        filters.append(User.is_active.is_(is_active))
    if role_code is not None:
        filters.append(
            User.id.in_(
                select(UserRole.user_id)
                .join(Role, Role.id == UserRole.role_id)
                .where(Role.code == role_code)
            )
        )

    count_stmt = select(func.count()).select_from(User)
    for condition in filters:
        count_stmt = count_stmt.where(condition)
    total = int((await session.execute(count_stmt)).scalar_one())

    order = column.desc() if descending else column.asc()
    stmt = _with_relations(select(User))
    for condition in filters:
        stmt = stmt.where(condition)
    stmt = stmt.order_by(order, User.id.asc()).limit(limit).offset(offset)

    rows = (await session.execute(stmt)).scalars().unique().all()
    return rows, total


async def count_active_admins(session: AsyncSession, *, exclude: uuid.UUID | None = None) -> int:
    stmt = (
        select(func.count(func.distinct(User.id)))
        .select_from(User)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(Role.code == "admin", User.is_active.is_(True))
    )
    if exclude is not None:
        stmt = stmt.where(User.id != exclude)
    return int((await session.execute(stmt)).scalar_one())


async def linked_active_admins(session: AsyncSession) -> Sequence[User]:
    """Administradores activos CON vinculo a Vault.

    Es la precondicion de arranque: no basta con que exista una fila admin, el
    vinculo con su entidad de Vault tiene que existir tambien.
    """
    stmt = (
        _with_relations(select(User))
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .join(UserVaultIdentity, UserVaultIdentity.user_id == User.id)
        .where(Role.code == "admin", User.is_active.is_(True))
        .order_by(User.created_at.asc())
    )
    return (await session.execute(stmt)).scalars().unique().all()


async def role_codes_for(session: AsyncSession, user_id: uuid.UUID) -> tuple[str, ...]:
    stmt = (
        select(Role.code)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.code)
    )
    return tuple((await session.execute(stmt)).scalars().all())


async def roles_by_codes(session: AsyncSession, codes: Sequence[str]) -> list[Role]:
    if not codes:
        return []
    stmt = select(Role).where(Role.code.in_(list(codes))).order_by(Role.code)
    return list((await session.execute(stmt)).scalars().all())


async def replace_roles(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    role_ids: Sequence[uuid.UUID],
    assigned_by: uuid.UUID | None,
) -> None:
    await session.execute(
        delete(UserRole).where(
            UserRole.user_id == user_id, UserRole.role_id.notin_(list(role_ids))
        )
    )
    existing = set(
        (
            await session.execute(select(UserRole.role_id).where(UserRole.user_id == user_id))
        ).scalars().all()
    )
    for role_id in role_ids:
        if role_id not in existing:
            session.add(UserRole(user_id=user_id, role_id=role_id, assigned_by=assigned_by))
    await session.flush()


async def get_vault_auth_config(session: AsyncSession, userpass_path: str) -> VaultAuthConfig | None:
    stmt = select(VaultAuthConfig).where(VaultAuthConfig.userpass_path == userpass_path)
    return (await session.execute(stmt)).scalar_one_or_none()


async def get_vault_identity(
    session: AsyncSession, user_id: uuid.UUID
) -> UserVaultIdentity | None:
    stmt = (
        select(UserVaultIdentity)
        .options(selectinload(UserVaultIdentity.auth_config))
        .where(UserVaultIdentity.user_id == user_id)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def get_vault_identity_by_username(
    session: AsyncSession, vault_username: str
) -> UserVaultIdentity | None:
    stmt = (
        select(UserVaultIdentity)
        .options(selectinload(UserVaultIdentity.auth_config))
        .where(UserVaultIdentity.vault_username == vault_username.lower())
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def touch_mfa_login(
    session: AsyncSession, *, user_id: uuid.UUID, entity_id: uuid.UUID, now: dt.datetime
) -> bool:
    """Marca un login MFA correcto. El filtro por ``entity_id`` es la garantia.

    Solo confirma el enrolamiento si la entidad que devolvio Vault es la
    registrada. ``disabled`` no se reactiva solo.
    """
    identity = (
        await session.execute(
            select(UserVaultIdentity).where(
                UserVaultIdentity.user_id == user_id,
                UserVaultIdentity.vault_entity_id == entity_id,
            )
        )
    ).scalar_one_or_none()
    if identity is None:
        return False

    identity.last_mfa_login_at = now
    if identity.totp_status in ("pending", "reset_required"):
        identity.totp_status = "confirmed"
        identity.totp_confirmed_at = identity.totp_confirmed_at or now
    await session.flush()
    return True


async def delete_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Borra el agregado. Las FK ON DELETE CASCADE hacen el resto."""
    await session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    await session.execute(delete(UserVaultIdentity).where(UserVaultIdentity.user_id == user_id))
    await session.execute(delete(UserEmail).where(UserEmail.user_id == user_id))
    await session.execute(delete(UserPhone).where(UserPhone.user_id == user_id))
    await session.execute(delete(UserAddress).where(UserAddress.user_id == user_id))
    await session.execute(delete(UserProfile).where(UserProfile.user_id == user_id))
    await session.execute(delete(User).where(User.id == user_id))
    await session.flush()
