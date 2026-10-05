"""Quien pide, y que puede hacer segun el rol de APLICACION.

El principal no se deduce aqui: lo devuelve la pasarela interna de user-mgmt,
que es la unica que puede validar una ``api_session``. Este modulo solo lo
representa y aplica la matriz de permisos de este dominio:

* ``admin``                      escribe y administra colecciones y registros.
* ``admin``/``manager``/``employee``  leen **unicamente** las colecciones
  compartidas que los declaran lectores, segun sus roles vigentes.

Dos avisos que conviene no perder de vista:

* Estos son roles de aplicacion. No son politicas de Vault. Pasar esta
  comprobacion no garantiza nada: la operacion se ejecuta con el token humano y
  la ACL de Vault puede denegarla igualmente. Vault manda.
* La autorizacion es **por objeto**: conocer el UUID de una coleccion o de un
  registro no da derecho a leerlo. Cada operacion lo comprueba.

El Bearer se guarda aqui porque hay que reenviarlo a la pasarela en cada
operacion. No se registra en ningun log y ``repr`` no lo muestra.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.core.errors import ForbiddenError

ADMIN = "admin"
MANAGER = "manager"
EMPLOYEE = "employee"


@dataclass(slots=True, frozen=True)
class HumanPrincipal:
    user_id: uuid.UUID
    username: str
    role_codes: frozenset[str]
    entity_id: str
    mfa_age_seconds: int
    bearer: str = field(repr=False, default="")

    @property
    def is_admin(self) -> bool:
        return ADMIN in self.role_codes

    def __str__(self) -> str:  # pragma: no cover - defensa contra logs
        return f"HumanPrincipal(username={self.username}, roles={sorted(self.role_codes)})"


def require_admin(principal: HumanPrincipal, action: str) -> None:
    if not principal.is_admin:
        raise ForbiddenError(
            f"solo un administrador puede {action}",
            context={
                "required_role": ADMIN,
                "your_roles": sorted(principal.role_codes),
            },
        )


def can_read_collection(
    principal: HumanPrincipal, reader_role_codes: tuple[str, ...] | list[str]
) -> bool:
    if principal.is_admin:
        return True
    return bool(principal.role_codes & set(reader_role_codes))


def assert_can_read_collection(
    principal: HumanPrincipal,
    reader_role_codes: tuple[str, ...] | list[str],
    *,
    collection_id: uuid.UUID,
) -> None:
    """403 y no 404: la coleccion existe y la respuesta lo dice con claridad.

    Enmascarar no es autorizar. Lo que no se revela es el contenido, no la
    existencia de un recurso cuyo UUID ya tenia el solicitante.
    """
    if not can_read_collection(principal, reader_role_codes):
        raise ForbiddenError(
            "ninguno de tus roles vigentes es lector autorizado de esta coleccion",
            context={
                "collection_id": str(collection_id),
                "collection_readers": sorted(reader_role_codes),
                "your_roles": sorted(principal.role_codes),
            },
        )


__all__ = [
    "ADMIN",
    "EMPLOYEE",
    "MANAGER",
    "HumanPrincipal",
    "assert_can_read_collection",
    "can_read_collection",
    "require_admin",
]
