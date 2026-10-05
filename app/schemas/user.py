"""DTO de empleados.

Tres cuerpos distintos a proposito:

* ``UserCreate``  -> POST   (alta completa)
* ``UserReplace`` -> PUT    (reemplazo de **todos** los campos editables)
* ``UserPatch``   -> PATCH  (modificacion parcial; lo omitido NO se borra)

Todos rechazan campos desconocidos (``extra="forbid"``). Ninguno acepta ``id``,
``created_at``, ``updated_at``, ``auth_provider``, ``password_hash``, ``roles``
ni nada del vinculo con Vault: esos cambian por endpoints propios, nunca por
asignacion masiva.

La validacion normaliza por dominio (RFC/CURP en mayusculas, correo y usuario en
minusculas, telefono a digitos). No hay un "sanitizador generico": alterar en
silencio una contrasena o enmascarar un error seria peor que rechazarlo.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
RFC_RE = re.compile(r"^[A-Z&N]{4}[0-9]{6}[A-Z0-9]{3}$")
CURP_RE = re.compile(r"^[A-Z]{4}[0-9]{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9][0-9]$")
PHONE_RE = re.compile(r"^[0-9]{7,15}$")
# El MISMO patron que el CHECK user_emails_format_ck de la base, para que la API
# y PostgreSQL no discrepen. No se usa EmailStr a proposito: email-validator
# rechaza los dominios de uso reservado (.invalid, .test, example.com), que son
# justo los que deben aparecer en ejemplos y pruebas segun el RFC 2606.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def _normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 254 or not EMAIL_RE.match(normalized):
        raise ValueError("correo electronico invalido")
    return normalized


EmailStr = Annotated[str, AfterValidator(_normalize_email)]
POSTAL_RE = re.compile(r"^[0-9]{5}$")

RoleCode = Literal["admin", "manager", "employee"]
PhoneType = Literal["mobile", "home", "work", "other"]
AddressType = Literal["home", "work", "fiscal", "other"]
TotpStatus = Literal["pending", "confirmed", "reset_required", "disabled"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _check_birth_consistency(
    value: str | None, birth_date: dt.date | None, label: str
) -> None:
    """Las posiciones 5-10 de RFC y CURP codifican la fecha de nacimiento."""
    if value and birth_date is not None:
        encoded = value[4:10]
        if encoded != birth_date.strftime("%y%m%d"):
            raise ValueError(
                f"{label} no concuerda con la fecha de nacimiento "
                f"(esperado {birth_date.strftime('%y%m%d')} en las posiciones 5-10)"
            )


# ---------------------------------------------------------------------------
# Subrecursos de contacto
# ---------------------------------------------------------------------------


class EmailIn(StrictModel):
    id: uuid.UUID | None = Field(
        default=None,
        description="Obligatorio en PATCH para modificar una fila existente. Nulo = alta.",
    )
    email: EmailStr = Field(description="Unico en todo el sistema, sin distinguir mayusculas.")
    is_primary: bool = Field(default=False, description="Como maximo uno principal por empleado.")


class PhoneIn(StrictModel):
    id: uuid.UUID | None = None
    country_code: Annotated[int, Field(ge=1, le=999)] = 52
    phone_number: str = Field(description="Solo digitos, 7 a 15.", examples=["5512345678"])
    phone_type: PhoneType = "mobile"
    extension: str | None = Field(default=None, examples=["102"])
    is_primary: bool = False

    @field_validator("phone_number", mode="before")
    @classmethod
    def _digits(cls, value: object) -> object:
        if isinstance(value, str):
            cleaned = re.sub(r"[\s()\-+.]", "", value)
            if not PHONE_RE.match(cleaned):
                raise ValueError("el telefono debe tener entre 7 y 15 digitos")
            return cleaned
        return value

    @field_validator("extension")
    @classmethod
    def _ext(cls, value: str | None) -> str | None:
        if value and not re.match(r"^[0-9]{1,8}$", value):
            raise ValueError("la extension debe tener entre 1 y 8 digitos")
        return value or None


class AddressIn(StrictModel):
    id: uuid.UUID | None = None
    neighborhood: str | None = Field(default=None, examples=["Lomas de Ejemplo"])
    street: str = Field(min_length=1, examples=["Av. Ficticia"])
    exterior_number: str = Field(min_length=1, examples=["100"])
    interior_number: str | None = Field(default=None, examples=["3B"])
    postal_code: str = Field(examples=["01000"])
    city: str | None = Field(default=None, examples=["Ciudad Ejemplo"])
    state_code: str | None = Field(default=None, examples=["CMX"])
    country_code: str = Field(default="MX", examples=["MX"])
    address_type: AddressType = "home"
    is_primary: bool = False

    @field_validator("postal_code")
    @classmethod
    def _postal(cls, value: str) -> str:
        if not POSTAL_RE.match(value):
            raise ValueError("el codigo postal debe tener 5 digitos")
        return value

    @field_validator("country_code", "state_code")
    @classmethod
    def _upper(cls, value: str | None) -> str | None:
        return value.upper() if value else value


# ---------------------------------------------------------------------------
# Perfil
# ---------------------------------------------------------------------------


class ProfileIn(StrictModel):
    first_name: str = Field(min_length=1, max_length=120, examples=["Ana"])
    last_name_paternal: str = Field(min_length=1, max_length=120, examples=["Perez"])
    last_name_maternal: str | None = Field(default=None, max_length=120, examples=["Lopez"])
    birth_date: dt.date = Field(
        description="Formato YYYY-MM-DD.", examples=["1990-01-15"]
    )
    rfc: str | None = Field(default=None, examples=["PELA900115AB1"])
    curp: str | None = Field(default=None, examples=["PELA900115MDFRPN03"])

    @field_validator("rfc", "curp", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        return value.upper().strip() if isinstance(value, str) else value

    @field_validator("birth_date")
    @classmethod
    def _range(cls, value: dt.date) -> dt.date:
        if value > dt.date.today():
            raise ValueError("la fecha de nacimiento no puede ser futura")
        if value < dt.date(1900, 1, 1):
            raise ValueError("la fecha de nacimiento no puede ser anterior a 1900")
        return value

    @model_validator(mode="after")
    def _formats(self) -> "ProfileIn":
        if self.rfc and not RFC_RE.match(self.rfc):
            raise ValueError("RFC invalido: 4 letras + AAMMDD + 3 de homoclave")
        if self.curp and not CURP_RE.match(self.curp):
            raise ValueError("CURP invalido: 18 caracteres con el formato oficial")
        _check_birth_consistency(self.rfc, self.birth_date, "el RFC")
        _check_birth_consistency(self.curp, self.birth_date, "la CURP")
        return self


# ---------------------------------------------------------------------------
# Cuerpos de entrada
# ---------------------------------------------------------------------------


class UserCreate(StrictModel):
    """Alta de empleado. Crea users + user_profiles + user_roles en UNA transaccion."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "username": "ana.perez",
                "profile": {
                    "first_name": "Ana",
                    "last_name_paternal": "Perez",
                    "last_name_maternal": "Lopez",
                    "birth_date": "1990-01-15",
                    "rfc": "PELA900115AB1",
                    "curp": "PELA900115MDFRPN03",
                },
                "role_codes": ["employee"],
                "emails": [{"email": "ana.perez@example.invalid", "is_primary": True}],
                "phones": [{"phone_number": "5512345678", "is_primary": True}],
                "addresses": [
                    {
                        "street": "Av. Ficticia",
                        "exterior_number": "100",
                        "postal_code": "01000",
                        "is_primary": True,
                    }
                ],
            }
        },
    )

    username: str = Field(
        description="Login unico sin distinguir mayusculas. Se normaliza a minusculas.",
        examples=["ana.perez"],
    )
    profile: ProfileIn
    role_codes: list[RoleCode] | None = Field(
        default=None,
        description=(
            "Solo un solicitante con rol admin puede elegirlos, y deben existir ya en "
            "employees.roles. Un manager NO puede enviarlos: el servidor asigna 'employee'."
        ),
    )
    emails: list[EmailIn] = Field(default_factory=list)
    phones: list[PhoneIn] = Field(default_factory=list)
    addresses: list[AddressIn] = Field(default_factory=list)

    @field_validator("username", mode="before")
    @classmethod
    def _normalize(cls, value: object) -> object:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if not USERNAME_RE.match(lowered):
                raise ValueError(
                    "el username admite 3-64 caracteres de [a-z0-9._-] "
                    "(se normaliza a minusculas)"
                )
            return lowered
        return value

    @model_validator(mode="after")
    def _single_primary(self) -> "UserCreate":
        _assert_single_primary(self.emails, "correo")
        _assert_single_primary(self.phones, "telefono")
        _assert_single_primary(self.addresses, "direccion")
        if self.role_codes is not None and not self.role_codes:
            raise ValueError("role_codes no puede ser una lista vacia; omitelo para el valor por defecto")
        return self


def _assert_single_primary(items: list, label: str) -> None:
    if sum(1 for item in items if getattr(item, "is_primary", False)) > 1:
        raise ValueError(f"como maximo un {label} principal por empleado")


class UserReplace(StrictModel):
    """PUT: reemplaza **todos** los campos editables.

    Lo que no venga en el cuerpo se elimina (en las colecciones) o vuelve a su
    valor por defecto. Es la diferencia con PATCH.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "profile": {
                    "first_name": "Ana Maria",
                    "last_name_paternal": "Perez",
                    "birth_date": "1990-01-15",
                },
                "emails": [{"email": "ana.m.perez@example.invalid", "is_primary": True}],
                "phones": [],
                "addresses": [],
            }
        },
    )

    profile: ProfileIn
    emails: list[EmailIn] = Field(
        default_factory=list, description="Sustituye la lista completa. [] borra todos."
    )
    phones: list[PhoneIn] = Field(default_factory=list)
    addresses: list[AddressIn] = Field(default_factory=list)

    @model_validator(mode="after")
    def _single_primary(self) -> "UserReplace":
        _assert_single_primary(self.emails, "correo")
        _assert_single_primary(self.phones, "telefono")
        _assert_single_primary(self.addresses, "direccion")
        return self


class ProfilePatch(StrictModel):
    first_name: str | None = Field(default=None, min_length=1, max_length=120)
    last_name_paternal: str | None = Field(default=None, min_length=1, max_length=120)
    last_name_maternal: str | None = Field(default=None, max_length=120)
    birth_date: dt.date | None = Field(default=None, description="YYYY-MM-DD")
    rfc: str | None = None
    curp: str | None = None

    @field_validator("rfc", "curp", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        return value.upper().strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _formats(self) -> "ProfilePatch":
        if self.rfc and not RFC_RE.match(self.rfc):
            raise ValueError("RFC invalido")
        if self.curp and not CURP_RE.match(self.curp):
            raise ValueError("CURP invalido")
        return self


class UserPatch(StrictModel):
    """PATCH: modificacion parcial.

    Un campo **omitido** se deja como esta; nunca se interpreta como borrado.
    Para modificar un contacto concreto hay que enviar su ``id``; para borrarlo,
    usar ``remove_*_ids``.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "profile": {"last_name_maternal": "Lopez"},
                "emails": [
                    {
                        "id": "3f1a7a1e-0000-4000-8000-000000000001",
                        "email": "nueva.direccion@example.invalid",
                        "is_primary": True,
                    }
                ],
                "remove_phone_ids": [],
            }
        },
    )

    profile: ProfilePatch | None = None
    emails: list[EmailIn] | None = Field(
        default=None,
        description="Altas (sin id) y modificaciones (con id). Omitirlo no borra nada.",
    )
    phones: list[PhoneIn] | None = None
    addresses: list[AddressIn] | None = None
    remove_email_ids: list[uuid.UUID] = Field(default_factory=list)
    remove_phone_ids: list[uuid.UUID] = Field(default_factory=list)
    remove_address_ids: list[uuid.UUID] = Field(default_factory=list)


class RoleAssignment(StrictModel):
    """PUT /user/{id}/roles. Solo admin."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"role_codes": ["manager", "employee"]}},
    )

    role_codes: list[RoleCode] = Field(
        min_length=1,
        description="Reemplaza el conjunto completo. Deben existir en employees.roles.",
    )

    @field_validator("role_codes")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("role_codes no admite duplicados")
        return value


class UserSearch(StrictModel):
    """POST /user/search: busqueda por datos personales, con cuerpo.

    Va por POST y no por GET a proposito: asi los datos personales no acaban en
    la URL, ni en los logs de acceso, ni en el historial del navegador. Sus
    valores no se registran.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"email": "ana.perez@example.invalid", "limit": 20}},
    )

    username: str | None = None
    email: EmailStr | None = None
    rfc: str | None = None
    curp: str | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 20
    offset: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def _at_least_one(self) -> "UserSearch":
        if not any([self.username, self.email, self.rfc, self.curp]):
            raise ValueError("indica al menos un criterio de busqueda")
        return self


# ---------------------------------------------------------------------------
# Cuerpos de salida
# ---------------------------------------------------------------------------


class EmailOut(BaseModel):
    id: uuid.UUID
    email: str
    is_primary: bool
    is_verified: bool


class PhoneOut(BaseModel):
    id: uuid.UUID
    country_code: int
    phone_number: str
    phone_type: str
    extension: str | None
    is_primary: bool


class AddressOut(BaseModel):
    id: uuid.UUID
    neighborhood: str | None
    street: str
    exterior_number: str
    interior_number: str | None
    postal_code: str
    city: str | None
    state_code: str | None
    country_code: str
    address_type: str
    is_primary: bool


class ProfileOut(BaseModel):
    first_name: str
    last_name_paternal: str
    last_name_maternal: str | None
    birth_date: dt.date
    rfc: str | None
    curp: str | None


class VaultLinkOut(BaseModel):
    """Estado del vinculo con Vault. **Nunca** incluye semillas, QR ni tokens."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vault_username": "ana.perez",
                "vault_entity_id": "00000000-0000-4000-8000-000000000000",
                "totp_status": "pending",
                "totp_generated_at": "2026-10-03T10:00:00Z",
                "totp_confirmed_at": None,
                "last_mfa_login_at": None,
                "notice": (
                    "Estado historico: 'pending' no demuestra que la persona no tenga "
                    "autenticador, y 'confirmed' no permite omitir el MFA."
                ),
            }
        }
    )

    vault_username: str
    vault_entity_id: uuid.UUID
    totp_status: TotpStatus
    totp_generated_at: dt.datetime | None
    totp_confirmed_at: dt.datetime | None
    last_mfa_login_at: dt.datetime | None
    notice: str | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    is_active: bool
    auth_provider: str
    has_local_password: bool = Field(
        description="True solo con auth_provider='local'. El hash nunca se expone."
    )
    role_codes: list[str]
    profile: ProfileOut | None
    emails: list[EmailOut]
    phones: list[PhoneOut]
    addresses: list[AddressOut]
    vault_link: VaultLinkOut | None
    created_at: dt.datetime
    updated_at: dt.datetime


class PageMeta(BaseModel):
    limit: int
    offset: int
    total: int
    returned: int


class UserPage(BaseModel):
    items: list[UserOut]
    page: PageMeta
