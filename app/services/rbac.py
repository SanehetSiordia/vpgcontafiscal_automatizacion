"""Matriz de permisos de la aplicacion.

Implementa lo que el README documenta:

* ``admin``    administra empleados, roles y credenciales.
* ``manager``  CRUD operativo de empleados; **no** toca roles ni credenciales ajenas.
* ``employee`` consulta su propio perfil y modifica sus **propios** contactos.

Dos avisos que conviene no perder de vista:

* Estos son roles de **aplicacion**. No son roles de PostgreSQL ni politicas de
  Vault. Tener el rol ``admin`` aqui no otorga la politica ``vpg-admin`` en
  Vault, y este servicio nunca la asigna automaticamente.
* La autorizacion es **por objeto**: conocer el UUID de otro empleado no da
  derecho a leerlo ni a modificarlo. Cada operacion lo comprueba.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.errors import ForbiddenError

ADMIN = "admin"
MANAGER = "manager"
EMPLOYEE = "employee"


@dataclass(slots=True, frozen=True)
class Principal:
    """Quien hace la peticion, con sus roles vigentes leidos de PostgreSQL."""

    user_id: uuid.UUID
    username: str
    role_codes: frozenset[str]
    entity_id: str
    mfa_age_seconds: float

    @property
    def is_admin(self) -> bool:
        return ADMIN in self.role_codes

    @property
    def is_manager(self) -> bool:
        return MANAGER in self.role_codes

    @property
    def is_employee_only(self) -> bool:
        return not self.is_admin and not self.is_manager

    def is_self(self, target_id: uuid.UUID) -> bool:
        return self.user_id == target_id


def require_admin(principal: Principal, action: str) -> None:
    if not principal.is_admin:
        raise ForbiddenError(
            f"solo un administrador puede {action}",
            context={"required_role": ADMIN, "your_roles": sorted(principal.role_codes)},
        )


def require_fresh_mfa(principal: Principal, max_age_seconds: int, action: str) -> None:
    """Operaciones destructivas exigen un MFA reciente, no solo una sesion viva."""
    if principal.mfa_age_seconds > max_age_seconds:
        raise ForbiddenError(
            f"para {action} hace falta un MFA reciente "
            f"(maximo {max_age_seconds}s; el tuyo tiene {int(principal.mfa_age_seconds)}s). "
            "Vuelve a iniciar sesion con userpass + TOTP.",
            code="stale_mfa",
        )


def can_read_user(principal: Principal, target_id: uuid.UUID) -> bool:
    if principal.is_admin or principal.is_manager:
        return True
    return principal.is_self(target_id)


def assert_can_read_user(principal: Principal, target_id: uuid.UUID) -> None:
    if not can_read_user(principal, target_id):
        # 403 y no 404: el recurso existe y la respuesta lo dice con claridad.
        # Enmascarar no es autorizar.
        raise ForbiddenError(
            "no tienes permiso sobre este empleado",
            context={"target_user_id": str(target_id)},
        )


def assert_can_write_user(principal: Principal, target_id: uuid.UUID) -> None:
    """Escritura del agregado (perfil y contactos)."""
    if principal.is_admin or principal.is_manager:
        return
    if principal.is_self(target_id):
        return
    raise ForbiddenError(
        "un empleado solo puede modificar sus propios datos de contacto",
        context={"target_user_id": str(target_id)},
    )


def assert_can_edit_profile(principal: Principal, target_id: uuid.UUID) -> None:
    """El perfil (nombre, RFC, CURP, fecha) no lo edita el propio empleado."""
    if principal.is_admin or principal.is_manager:
        return
    raise ForbiddenError(
        "un empleado puede modificar sus contactos, pero no su perfil fiscal "
        "(nombre, RFC, CURP o fecha de nacimiento)",
        context={"target_user_id": str(target_id)},
    )


def assert_can_create_user(principal: Principal) -> None:
    if principal.is_admin or principal.is_manager:
        return
    raise ForbiddenError("solo admin o manager pueden dar de alta empleados")


def resolve_role_codes_for_create(
    principal: Principal, requested: list[str] | None
) -> list[str]:
    """Que roles recibe un empleado recien creado.

    * ``admin``   puede elegir uno o varios codigos ya existentes.
    * ``manager`` no elige: el servidor asigna ``employee`` y rechaza cualquier
      intento de seleccionar roles.
    """
    if principal.is_admin:
        return list(requested) if requested else [EMPLOYEE]

    if requested:
        raise ForbiddenError(
            "un manager no puede seleccionar roles; el empleado se crea con 'employee'",
            context={"assigned_role": EMPLOYEE},
        )
    return [EMPLOYEE]


def assert_can_manage_vault_credentials(principal: Principal, target_id: uuid.UUID) -> None:
    """Credenciales y MFA ajenos: solo admin.

    Un manager puede crear la ficha del empleado, pero el provisionamiento en
    Vault lo hace despues un administrador.
    """
    if principal.is_admin:
        return
    raise ForbiddenError(
        "solo un administrador gestiona credenciales y MFA; "
        "un manager puede crear la ficha, pero no provisionar el acceso a Vault",
        context={"target_user_id": str(target_id)},
    )


def assert_not_self_purge(principal: Principal, target_id: uuid.UUID) -> None:
    if principal.is_self(target_id):
        raise ForbiddenError(
            "no puedes purgar tu propia cuenta",
            code="self_purge_blocked",
        )
