"""DTO de colecciones y de sus esquemas versionados."""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.secret_schema import FIELD_TYPES, NESTED_TYPES
from app.vault_mgmt.schemas.common import PageMeta, StrictModel

# Mismo patron que el CHECK de la base: minusculas, digitos, '.', '_', '-' y
# '/' como separador, sin barra inicial ni final y sin '..'.
LOGICAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$")
READER_ROLES = ("admin", "manager", "employee")


class FieldSpecIn(BaseModel):
    """Definicion de UN campo del esquema.

    ``sensitive`` controla presentacion y registro (no se muestra ni se escribe
    en logs). **No** convierte el valor en seguro: sigue siendo un secreto y lo
    que lo protege es Vault y los permisos de entrega.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "name": "password",
                "type": "string",
                "required": True,
                "sensitive": True,
                "max_length": 256,
                "description": "Contrasena del portal. Valor ficticio en ejemplos.",
            }
        },
    )

    name: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]
    type: Literal[FIELD_TYPES]  # type: ignore[valid-type]
    required: bool = False
    sensitive: bool = False
    description: Annotated[str | None, Field(default=None, max_length=400)] = None
    # string
    max_length: Annotated[int | None, Field(default=None, ge=1, le=65536)] = None
    min_length: Annotated[int | None, Field(default=None, ge=0, le=65536)] = None
    enum: list[str] | None = None
    # number / integer
    minimum: float | None = None
    maximum: float | None = None
    # array
    items_type: Literal[NESTED_TYPES] | None = None  # type: ignore[valid-type]
    max_items: Annotated[int | None, Field(default=None, ge=1, le=1000)] = None
    # object y array de object
    properties: list["FieldSpecIn"] | None = None


FieldSpecIn.model_rebuild()


class CollectionCreateIn(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "logical_name": "sat/usuarios",
                "description": "Credenciales del portal del SAT por contribuyente.",
                "reader_role_codes": ["admin", "manager"],
                "fields": [
                    {"name": "usuario", "type": "string", "required": True, "max_length": 64},
                    {
                        "name": "password",
                        "type": "string",
                        "required": True,
                        "sensitive": True,
                        "max_length": 256,
                    },
                    {"name": "rfc", "type": "string", "required": False, "max_length": 13},
                ],
            }
        },
    )

    logical_name: Annotated[str, Field(min_length=3, max_length=120)]
    description: Annotated[str | None, Field(default=None, max_length=1000)] = None
    reader_role_codes: list[Literal[READER_ROLES]] = Field(  # type: ignore[valid-type]
        default_factory=lambda: ["admin"],
        description=(
            "Roles de APLICACION lectores. No son politicas de Vault: la ACL de "
            "Vault se comprueba ademas y manda ella. 'admin' siempre esta."
        ),
    )
    fields: list[FieldSpecIn] = Field(min_length=1)

    @field_validator("logical_name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        lowered = value.strip().lower()
        if not LOGICAL_NAME_RE.match(lowered) or ".." in lowered:
            raise ValueError(
                "el nombre logico admite minusculas, digitos, '.', '_', '-' y '/' "
                "como separador; sin barra inicial o final y sin '..'"
            )
        return lowered

    @field_validator("reader_role_codes")
    @classmethod
    def _with_admin(cls, value: list[str]) -> list[str]:
        roles = sorted(set(value) | {"admin"})
        return roles


class CollectionPatchIn(StrictModel):
    """Cambia SOLO metadatos. Nunca valores, nunca el path fisico.

    Renombrar cambia el nombre logico del catalogo y **conserva** el UUID, el
    path fisico, el historial de versiones y las referencias del crawler. KV v2
    no ofrece rename nativo y aqui no se simula con copy + delete.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"logical_name": "sat/datos", "reader_role_codes": ["admin"]}
        },
    )

    logical_name: Annotated[str | None, Field(default=None, min_length=3, max_length=120)] = None
    description: Annotated[str | None, Field(default=None, max_length=1000)] = None
    reader_role_codes: list[Literal[READER_ROLES]] | None = None  # type: ignore[valid-type]

    @field_validator("logical_name")
    @classmethod
    def _check_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if not LOGICAL_NAME_RE.match(lowered) or ".." in lowered:
            raise ValueError(
                "el nombre logico admite minusculas, digitos, '.', '_', '-' y '/' "
                "como separador; sin barra inicial o final y sin '..'"
            )
        return lowered

    @field_validator("reader_role_codes")
    @classmethod
    def _with_admin(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return sorted(set(value) | {"admin"})


class SchemaPutIn(StrictModel):
    """Esquema COMPLETO nuevo. Crea una version, no modifica la anterior."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "fields": [
                    {"name": "usuario", "type": "string", "required": True, "max_length": 64},
                    {
                        "name": "password",
                        "type": "string",
                        "required": True,
                        "sensitive": True,
                        "max_length": 256,
                    },
                    {"name": "rfc", "type": "string", "required": False, "max_length": 13},
                    {"name": "notas", "type": "string", "required": False, "max_length": 500},
                ],
                "note": "Se anade 'notas' como campo opcional.",
            }
        },
    )

    fields: list[FieldSpecIn] = Field(min_length=1)
    note: Annotated[str | None, Field(default=None, max_length=500)] = None
    # Si es False se valida y se informa, pero no se escribe nada.
    apply: bool = Field(
        default=True,
        description="False: solo diagnostico de compatibilidad, sin crear version.",
    )


class CollectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    collection_id: uuid.UUID
    logical_name: str
    description: str | None
    state: str
    current_schema_version: int
    reader_role_codes: list[str]
    kv_mount: str = Field(description="Montaje KV v2. Sin los segmentos data/metadata.")
    physical_prefix: str = Field(
        description=(
            "Prefijo fisico derivado del UUID: cambiar el nombre logico no lo "
            "mueve. Los segmentos data/metadata/delete/undelete/destroy son del "
            "cliente KV v2 y no forman parte de este valor."
        )
    )
    record_count: int | None = Field(
        default=None, description="Registros en el indice del catalogo."
    )
    created_at: dt.datetime
    updated_at: dt.datetime
    archived_at: dt.datetime | None = None
    purged_at: dt.datetime | None = None


class CollectionListOut(BaseModel):
    page: PageMeta
    items: list[CollectionOut]


class SchemaVersionOut(BaseModel):
    schema_version: int
    fields: list[dict[str, Any]]
    json_schema: dict[str, Any] = Field(
        description=(
            "Documento JSON Schema (Draft 2020-12) autocontenido: sin $ref ni "
            "referencias externas. Es el que valido esta version."
        )
    )
    sensitive_fields: list[str]
    note: str | None
    created_at: dt.datetime


class SchemaOut(BaseModel):
    collection_id: uuid.UUID
    logical_name: str
    current_schema_version: int
    available_versions: list[int]
    schema_: SchemaVersionOut = Field(alias="schema")

    model_config = ConfigDict(populate_by_name=True)


class CompatibilityOut(BaseModel):
    """Diagnostico de compatibilidad. Nunca devuelve valores de registros."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "compatible": False,
                "breaking_changes": [
                    {
                        "field": "fields.rfc",
                        "reason": "campo nuevo obligatorio: los registros existentes no lo traen",
                    }
                ],
                "safe_changes": ["fields.notas: campo opcional nuevo"],
                "records_affected": 12,
                "note": (
                    "Se compara la DEFINICION, no los valores: diagnosticar leyendo "
                    "todos los registros significaria leer todos los secretos."
                ),
            }
        }
    )

    compatible: bool
    breaking_changes: list[dict[str, str]]
    safe_changes: list[str]
    records_affected: int
    note: str = (
        "Se compara la definicion de campos, no los valores almacenados. Un "
        "cambio incompatible exige migracion explicita y revisada, no una "
        "reescritura masiva automatica."
    )


class SchemaUpdateOut(BaseModel):
    collection_id: uuid.UUID
    applied: bool
    current_schema_version: int
    compatibility: CompatibilityOut
    schema_: SchemaVersionOut | None = Field(default=None, alias="schema")

    model_config = ConfigDict(populate_by_name=True)


__all__ = [
    "CollectionCreateIn",
    "CollectionListOut",
    "CollectionOut",
    "CollectionPatchIn",
    "CompatibilityOut",
    "FieldSpecIn",
    "LOGICAL_NAME_RE",
    "SchemaOut",
    "SchemaPutIn",
    "SchemaUpdateOut",
    "SchemaVersionOut",
]
