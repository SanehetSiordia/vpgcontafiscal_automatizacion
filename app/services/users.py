"""Reglas de negocio del agregado de empleado.

El alta ocurre en **una sola transaccion**: ``users`` + ``user_profiles`` +
``user_roles`` (y los contactos que vengan). Si algo falla, no queda nada.

Las credenciales y el MFA en Vault no se tocan desde aqui: para eso estan los
endpoints de provisionamiento, en ``services/vault_sync.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.models.employees import (
    User,
    UserAddress,
    UserEmail,
    UserPhone,
    UserProfile,
)
from app.repositories import users as repo
from app.schemas.user import (
    AddressIn,
    AddressOut,
    EmailIn,
    EmailOut,
    PhoneIn,
    PhoneOut,
    ProfileOut,
    UserCreate,
    UserOut,
    UserPatch,
    UserReplace,
    VaultLinkOut,
)
from app.services.rbac import Principal

_PENDING_NOTICE = (
    "Estado historico. 'pending' no demuestra que la persona no haya registrado "
    "su autenticador; solo que este sistema no ha visto todavia un login MFA "
    "correcto. No justifica reiniciar el TOTP."
)
_CONFIRMED_NOTICE = (
    "Estado historico de un enrolamiento pasado. Vault sigue exigiendo "
    "contrasena + TOTP en cada login: esta marca no permite omitir el MFA."
)
_RESET_NOTICE = (
    "Se destruyo la semilla anterior y todavia no hay un login MFA correcto con "
    "la nueva."
)


def to_out(user: User) -> UserOut:
    """Proyeccion de salida. Nunca incluye el hash ni nada secreto de Vault."""
    link = user.vault_identity
    vault_link = None
    if link is not None:
        notice = {
            "pending": _PENDING_NOTICE,
            "confirmed": _CONFIRMED_NOTICE,
            "reset_required": _RESET_NOTICE,
            "disabled": "El acceso MFA de esta identidad esta deshabilitado.",
        }.get(link.totp_status)
        vault_link = VaultLinkOut(
            vault_username=link.vault_username,
            vault_entity_id=link.vault_entity_id,
            totp_status=link.totp_status,  # type: ignore[arg-type]
            totp_generated_at=link.totp_generated_at,
            totp_confirmed_at=link.totp_confirmed_at,
            last_mfa_login_at=link.last_mfa_login_at,
            notice=notice,
        )

    profile = user.profile
    return UserOut(
        id=user.id,
        username=user.username,
        is_active=user.is_active,
        auth_provider=user.auth_provider,
        has_local_password=user.password_hash is not None,
        role_codes=sorted(link_.role.code for link_ in user.role_links),
        profile=(
            ProfileOut(
                first_name=profile.first_name,
                last_name_paternal=profile.last_name_paternal,
                last_name_maternal=profile.last_name_maternal,
                birth_date=profile.birth_date,
                rfc=profile.rfc,
                curp=profile.curp,
            )
            if profile is not None
            else None
        ),
        emails=[
            EmailOut(
                id=e.id, email=e.email, is_primary=e.is_primary, is_verified=e.is_verified
            )
            for e in sorted(user.emails, key=lambda e: (not e.is_primary, e.email))
        ],
        phones=[
            PhoneOut(
                id=p.id,
                country_code=p.country_code,
                phone_number=p.phone_number,
                phone_type=p.phone_type,
                extension=p.extension,
                is_primary=p.is_primary,
            )
            for p in sorted(user.phones, key=lambda p: (not p.is_primary, p.phone_number))
        ],
        addresses=[
            AddressOut(
                id=a.id,
                neighborhood=a.neighborhood,
                street=a.street,
                exterior_number=a.exterior_number,
                interior_number=a.interior_number,
                postal_code=a.postal_code,
                city=a.city,
                state_code=a.state_code,
                country_code=a.country_code,
                address_type=a.address_type,
                is_primary=a.is_primary,
            )
            for a in sorted(user.addresses, key=lambda a: (not a.is_primary, a.street))
        ],
        vault_link=vault_link,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _translate_integrity_error(exc: IntegrityError) -> ConflictError:
    """Convierte la violacion de una restriccion real en un 409 entendible."""
    constraint = ""
    diag = getattr(exc.orig, "diag", None)
    if diag is not None:
        constraint = str(getattr(diag, "constraint_name", "") or "")

    mapping = {
        "users_username_lower_ux": "ya existe un empleado con ese username",
        "user_emails_email_lower_ux": "ese correo ya pertenece a otro empleado",
        "user_emails_one_primary_ux": "ya hay un correo principal para este empleado",
        "user_phones_one_primary_ux": "ya hay un telefono principal para este empleado",
        "user_phones_unique_per_user_uq": "ese telefono ya esta registrado para el empleado",
        "user_addresses_one_primary_ux": "ya hay una direccion principal para este empleado",
        "user_profiles_rfc_uq": "ese RFC ya pertenece a otro empleado",
        "user_profiles_curp_uq": "esa CURP ya pertenece a otro empleado",
        "user_vault_identity_username_uq": "ese usuario de Vault ya esta vinculado",
        "user_vault_identity_entity_uq": "esa entidad de Vault ya esta vinculada",
    }
    message = mapping.get(constraint)
    if message:
        return ConflictError(message, context={"constraint": constraint})

    if constraint:
        return ConflictError(
            f"la operacion viola la restriccion '{constraint}' del esquema",
            context={"constraint": constraint},
        )
    return ConflictError("la operacion viola una restriccion de integridad")


async def create_user(
    session: AsyncSession,
    *,
    payload: UserCreate,
    role_codes: Sequence[str],
    actor: Principal,
) -> User:
    """Alta completa en UNA transaccion. El llamador hace commit."""
    if await repo.username_exists(session, payload.username):
        raise ConflictError(
            "ya existe un empleado con ese username",
            context={"username": payload.username},
        )

    roles = await repo.roles_by_codes(session, list(role_codes))
    missing = set(role_codes) - {r.code for r in roles}
    if missing:
        # No se crean filas nuevas en el catalogo roles desde este endpoint.
        raise ValidationError(
            f"estos codigos de rol no existen en employees.roles: {sorted(missing)}",
            context={"unknown_roles": sorted(missing)},
        )

    # Todo el alta va dentro de un solo try: `replace_roles` dispara su
    # propio flush, y una violacion de unicidad alli debe traducirse a 409
    # igual que en el flush final, no escapar como error interno.
    try:
        user = User(
            username=payload.username,
            auth_provider="vault",
            password_hash=None,   # autenticacion delegada: debe quedar NULL
            is_active=True,
        )
        session.add(user)
        await session.flush()

        session.add(
            UserProfile(
                user_id=user.id,
                first_name=payload.profile.first_name,
                last_name_paternal=payload.profile.last_name_paternal,
                last_name_maternal=payload.profile.last_name_maternal,
                birth_date=payload.profile.birth_date,
                rfc=payload.profile.rfc,
                curp=payload.profile.curp,
            )
        )
        for email in payload.emails:
            session.add(UserEmail(user_id=user.id, email=email.email, is_primary=email.is_primary))
        for phone in payload.phones:
            session.add(
                UserPhone(
                    user_id=user.id,
                    country_code=phone.country_code,
                    phone_number=phone.phone_number,
                    phone_type=phone.phone_type,
                    extension=phone.extension,
                    is_primary=phone.is_primary,
                )
            )
        for address in payload.addresses:
            session.add(
                UserAddress(
                    user_id=user.id,
                    neighborhood=address.neighborhood,
                    street=address.street,
                    exterior_number=address.exterior_number,
                    interior_number=address.interior_number,
                    postal_code=address.postal_code,
                    city=address.city,
                    state_code=address.state_code,
                    country_code=address.country_code,
                    address_type=address.address_type,
                    is_primary=address.is_primary,
                )
            )

        await repo.replace_roles(
            session,
            user_id=user.id,
            role_ids=[r.id for r in roles],
            assigned_by=actor.user_id,
        )
        await session.flush()
    except IntegrityError as exc:
        raise _translate_integrity_error(exc) from exc

    reloaded = await repo.get_by_id(session, user.id, refresh=True)
    assert reloaded is not None
    return reloaded


async def _load_or_404(session: AsyncSession, user_id: uuid.UUID) -> User:
    user = await repo.get_by_id(session, user_id)
    if user is None:
        raise NotFoundError("no existe ese empleado", context={"user_id": str(user_id)})
    return user


async def replace_user(
    session: AsyncSession, *, user_id: uuid.UUID, payload: UserReplace
) -> User:
    """PUT: reemplazo. Las colecciones que no vengan quedan VACIAS."""
    user = await _load_or_404(session, user_id)

    profile = user.profile
    if profile is None:
        profile = UserProfile(user_id=user.id)
        session.add(profile)
    profile.first_name = payload.profile.first_name
    profile.last_name_paternal = payload.profile.last_name_paternal
    profile.last_name_maternal = payload.profile.last_name_maternal
    profile.birth_date = payload.profile.birth_date
    profile.rfc = payload.profile.rfc
    profile.curp = payload.profile.curp

    for existing in list(user.emails):
        await session.delete(existing)
    for existing in list(user.phones):
        await session.delete(existing)
    for existing in list(user.addresses):
        await session.delete(existing)
    await session.flush()

    for email in payload.emails:
        await _assert_email_free(session, email.email, user.id)
        session.add(UserEmail(user_id=user.id, email=email.email, is_primary=email.is_primary))
    for phone in payload.phones:
        session.add(
            UserPhone(
                user_id=user.id,
                country_code=phone.country_code,
                phone_number=phone.phone_number,
                phone_type=phone.phone_type,
                extension=phone.extension,
                is_primary=phone.is_primary,
            )
        )
    for address in payload.addresses:
        session.add(
            UserAddress(
                user_id=user.id,
                neighborhood=address.neighborhood,
                street=address.street,
                exterior_number=address.exterior_number,
                interior_number=address.interior_number,
                postal_code=address.postal_code,
                city=address.city,
                state_code=address.state_code,
                country_code=address.country_code,
                address_type=address.address_type,
                is_primary=address.is_primary,
            )
        )

    try:
        await session.flush()
    except IntegrityError as exc:
        raise _translate_integrity_error(exc) from exc

    reloaded = await repo.get_by_id(session, user.id, refresh=True)
    assert reloaded is not None
    return reloaded


async def _assert_email_free(
    session: AsyncSession, email: str, owner_id: uuid.UUID
) -> None:
    other = await repo.email_owner(session, email)
    if other is not None and other != owner_id:
        raise ConflictError("ese correo ya pertenece a otro empleado")


async def patch_user(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    payload: UserPatch,
    may_edit_profile: bool,
) -> User:
    """PATCH: parcial. Lo omitido se deja como esta; borrar es explicito."""
    user = await _load_or_404(session, user_id)

    if payload.profile is not None:
        if not may_edit_profile:
            raise ValidationError("no puedes modificar el perfil de este empleado")
        profile = user.profile
        if profile is None:
            raise ValidationError("el empleado no tiene perfil; usa PUT para crearlo")
        data = payload.profile.model_dump(exclude_unset=True)
        for field, value in data.items():
            setattr(profile, field, value)
        # Si cambia la fecha, RFC y CURP deben seguir cuadrando: lo comprueba el
        # CHECK de la base y se traduce a 409.

    by_id = {e.id: e for e in user.emails}
    for item in payload.emails or []:
        if item.id is not None:
            existing = by_id.get(item.id)
            if existing is None:
                raise ValidationError(
                    "ese correo no pertenece al empleado",
                    context={"email_id": str(item.id)},
                )
            await _assert_email_free(session, item.email, user.id)
            existing.email = item.email
            existing.is_primary = item.is_primary
        else:
            await _assert_email_free(session, item.email, user.id)
            session.add(
                UserEmail(user_id=user.id, email=item.email, is_primary=item.is_primary)
            )

    phones_by_id = {p.id: p for p in user.phones}
    for item in payload.phones or []:
        if item.id is not None:
            existing_phone = phones_by_id.get(item.id)
            if existing_phone is None:
                raise ValidationError("ese telefono no pertenece al empleado")
            existing_phone.country_code = item.country_code
            existing_phone.phone_number = item.phone_number
            existing_phone.phone_type = item.phone_type
            existing_phone.extension = item.extension
            existing_phone.is_primary = item.is_primary
        else:
            session.add(
                UserPhone(
                    user_id=user.id,
                    country_code=item.country_code,
                    phone_number=item.phone_number,
                    phone_type=item.phone_type,
                    extension=item.extension,
                    is_primary=item.is_primary,
                )
            )

    addresses_by_id = {a.id: a for a in user.addresses}
    for item in payload.addresses or []:
        if item.id is not None:
            existing_address = addresses_by_id.get(item.id)
            if existing_address is None:
                raise ValidationError("esa direccion no pertenece al empleado")
            for field in (
                "neighborhood", "street", "exterior_number", "interior_number",
                "postal_code", "city", "state_code", "country_code",
                "address_type", "is_primary",
            ):
                setattr(existing_address, field, getattr(item, field))
        else:
            session.add(
                UserAddress(
                    user_id=user.id,
                    neighborhood=item.neighborhood,
                    street=item.street,
                    exterior_number=item.exterior_number,
                    interior_number=item.interior_number,
                    postal_code=item.postal_code,
                    city=item.city,
                    state_code=item.state_code,
                    country_code=item.country_code,
                    address_type=item.address_type,
                    is_primary=item.is_primary,
                )
            )

    for email_id in payload.remove_email_ids:
        target = by_id.get(email_id)
        if target is None:
            raise ValidationError("ese correo no pertenece al empleado")
        await session.delete(target)
    for phone_id in payload.remove_phone_ids:
        target_phone = phones_by_id.get(phone_id)
        if target_phone is None:
            raise ValidationError("ese telefono no pertenece al empleado")
        await session.delete(target_phone)
    for address_id in payload.remove_address_ids:
        target_address = addresses_by_id.get(address_id)
        if target_address is None:
            raise ValidationError("esa direccion no pertenece al empleado")
        await session.delete(target_address)

    try:
        await session.flush()
    except IntegrityError as exc:
        raise _translate_integrity_error(exc) from exc

    reloaded = await repo.get_by_id(session, user.id, refresh=True)
    assert reloaded is not None
    return reloaded


async def set_roles(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    role_codes: Sequence[str],
    actor: Principal,
) -> User:
    user = await _load_or_404(session, user_id)

    roles = await repo.roles_by_codes(session, list(role_codes))
    missing = set(role_codes) - {r.code for r in roles}
    if missing:
        raise ValidationError(
            f"estos codigos de rol no existen: {sorted(missing)}",
            context={"unknown_roles": sorted(missing)},
        )

    # Proteccion de la ultima cuenta admin activa.
    losing_admin = "admin" not in role_codes and any(
        link.role.code == "admin" for link in user.role_links
    )
    if losing_admin and user.is_active:
        remaining = await repo.count_active_admins(session, exclude=user.id)
        if remaining == 0:
            raise ConflictError(
                "no se puede quitar el rol admin: es la ultima cuenta administradora activa",
                code="last_admin_protected",
            )

    await repo.replace_roles(
        session, user_id=user.id, role_ids=[r.id for r in roles], assigned_by=actor.user_id
    )
    try:
        await session.flush()
    except IntegrityError as exc:
        raise _translate_integrity_error(exc) from exc

    reloaded = await repo.get_by_id(session, user.id, refresh=True)
    assert reloaded is not None
    return reloaded


async def assert_can_deactivate(session: AsyncSession, user: User) -> None:
    is_admin = any(link.role.code == "admin" for link in user.role_links)
    if is_admin and user.is_active:
        remaining = await repo.count_active_admins(session, exclude=user.id)
        if remaining == 0:
            raise ConflictError(
                "no se puede desactivar: es la ultima cuenta administradora activa",
                code="last_admin_protected",
            )
