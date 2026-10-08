"""DTO de registros: creacion, reemplazo, parche, entrega y versiones.

Un registro guarda **un objeto completo** de campos relacionados, por ejemplo
``{"usuario": "demo", "password": "valor-ficticio"}``. N registros son N
secretos de Vault con su propio path y su propio historial: no son N escrituras
que sobrescriben el mismo ``sat/usuarios``.

Ningun DTO de listado o resumen incluye ``values``. El unico que los devuelve es
``PlainDelivery``, y solo cuando el lector autorizado lo pide de forma explicita.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.vault_mgmt.schemas.common import PageMeta, StrictModel

EXAMPLE_VALUES = {"usuario": "demo", "password": "valor-ficticio"}


class RecordCreateIn(StrictModel):
    """Crea un registro con CAS=0. Si el path ya tiene datos, 409."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "label": "contribuyente-demo",
                "values": EXAMPLE_VALUES,
            }
        },
    )

    label: Annotated[str | None, Field(default=None, min_length=1, max_length=120)] = None
    values: dict[str, Any] = Field(
        description="Objeto COMPLETO de campos. Se valida contra el esquema vigente."
    )


class RecordReplaceIn(StrictModel):
    """Reemplazo completo con CAS. Crea una version nueva; no muta las anteriores."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "expected_version": 1,
                "values": {"usuario": "demo", "password": "otro-valor-ficticio"},
            }
        },
    )

    expected_version: Annotated[int, Field(ge=1)] = Field(
        description=(
            "Version actual esperada (check-and-set). Si no coincide, 409 y no se "
            "sobrescribe el cambio ajeno."
        )
    )
    values: dict[str, Any]
    label: Annotated[str | None, Field(default=None, min_length=1, max_length=120)] = None


class RecordPatchIn(StrictModel):
    """JSON Merge Patch con CAS.

    Semantica: una clave ausente **conserva** su valor, ``null`` la **elimina**,
    un objeto se mezcla de forma recursiva y una lista se reemplaza entera.

    Antes de escribir se valida el objeto RESULTANTE COMPLETO. Si el parche deja
    la tupla invalida (por ejemplo un ``null`` sobre un campo obligatorio), la
    respuesta es 422 y **no se escribe nada**.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "expected_version": 2,
                "patch": {"password": "valor-ficticio-nuevo", "rfc": None},
            }
        },
    )

    expected_version: Annotated[int, Field(ge=1)]
    patch: dict[str, Any] = Field(
        description="Ausente conserva, null elimina, objeto mezcla, lista reemplaza."
    )


class RecordReadIn(StrictModel):
    """Peticion de lectura. La entrega envuelta es el valor por defecto."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"version": None, "delivery": "wrapped", "wrap_ttl_seconds": 60}
        },
    )

    version: Annotated[int | None, Field(default=None, ge=1)] = Field(
        default=None,
        description="Version concreta. Ausente = la ultima viva (latest).",
    )
    delivery: Literal["wrapped", "plain"] = Field(
        default="wrapped",
        description=(
            "'wrapped': response wrapping de Vault (token de un solo uso, TTL "
            "corto). 'plain': JSON con los valores, solo por eleccion explicita."
        ),
    )
    wrap_ttl_seconds: Annotated[int | None, Field(default=None, ge=10, le=600)] = None
    reason: Annotated[str | None, Field(default=None, max_length=200)] = Field(
        default=None, description="Motivo para la auditoria. No admite secretos."
    )


class VersionsIn(StrictModel):
    """Lista explicita de versiones. Nunca 'todas' de forma implicita."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"versions": [1, 2]}},
    )

    versions: list[Annotated[int, Field(ge=1)]] = Field(min_length=1)


class DestroyVersionsIn(VersionsIn):
    """Destruccion irreversible: exige confirmacion explicita y MFA reciente."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"versions": [1], "confirm": "DESTROY"}},
    )

    confirm: Literal["DESTROY"] = Field(
        description="Confirmacion literal. Sin ella, 422 y no se toca nada."
    )


class PurgeIn(StrictModel):
    """Purga de un registro: borra datos de TODAS las versiones y su metadata."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"confirm": "PURGE", "reason": "fixture de prueba"}},
    )

    confirm: Literal["PURGE"]
    reason: Annotated[str | None, Field(default=None, max_length=200)] = None


class CollectionLifecycleIn(StrictModel):
    """Restaurar o purgar una coleccion entera. Lote acotado por configuracion."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"confirm": "PURGE", "reason": "limpieza de fixtures"}},
    )

    confirm: Literal["PURGE", "RESTORE"]
    reason: Annotated[str | None, Field(default=None, max_length=200)] = None


class RecordSummaryOut(BaseModel):
    """Resumen de un registro. **Sin valores.**"""

    model_config = ConfigDict(from_attributes=True)

    record_id: uuid.UUID
    collection_id: uuid.UUID
    state: str
    current_version: int
    schema_version: int
    label: str | None
    created_at: dt.datetime
    updated_at: dt.datetime
    deleted_at: dt.datetime | None = None


class RecordListOut(BaseModel):
    page: PageMeta
    items: list[RecordSummaryOut]


class RecordWriteOut(BaseModel):
    """Resultado de una escritura. Devuelve la version nueva, no los valores."""

    record_id: uuid.UUID
    collection_id: uuid.UUID
    version: int
    schema_version: int
    operation_id: uuid.UUID
    state: str = "active"
    next_expected_version: int = Field(
        description="Valor de 'expected_version' para la siguiente escritura."
    )


class WrappedDelivery(BaseModel):
    """Entrega envuelta: la UNICA salida que lleva una credencial.

    El ``wrap_token`` es un token de Vault de **un solo uso** y TTL corto. No es
    un JSON cifrado y no impide que el receptor autorizado vea los valores al
    desenvolverlo. No se registra en logs ni se persiste en ningun sitio, ni
    aqui ni en la auditoria.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "mode": "wrapped",
                "wrap_token": "hvs.CAESIJ...-ejemplo-no-reutilizable",
                "ttl_seconds": 60,
                "version": 2,
                "unwrap_hint": "vault unwrap <wrap_token>",
            }
        }
    )

    mode: Literal["wrapped"] = "wrapped"
    wrap_token: str
    ttl_seconds: int
    version: int
    creation_path: str | None = None
    unwrap_hint: str = "vault unwrap <wrap_token>  (o POST sys/wrapping/unwrap)"
    note: str = (
        "Un solo uso y TTL corto. Si caduca o ya se consumio, pide otra entrega: "
        "no hace falta repetir la tarea."
    )


class PlainDelivery(BaseModel):
    """Entrega en claro. Solo por eleccion explicita del lector autorizado."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "mode": "plain",
                "version": 2,
                "schema_version": 1,
                "values": EXAMPLE_VALUES,
            }
        }
    )

    mode: Literal["plain"] = "plain"
    version: int
    schema_version: int
    values: dict[str, Any]
    note: str = (
        "Respuesta con Cache-Control: no-store. En red local sin HTTPS no hay "
        "cifrado en transito: ese limite esta documentado."
    )


class RecordReadOut(BaseModel):
    record_id: uuid.UUID
    collection_id: uuid.UUID
    schema_version: int
    delivery: WrappedDelivery | PlainDelivery


class VersionStateOut(BaseModel):
    version: int
    state: Literal["active", "soft_deleted", "destroyed"]
    created_time: str | None = None
    deletion_time: str | None = None
    destroyed: bool = False


class RecordMetadataOut(BaseModel):
    """Metadata nativa de KV v2, por REGISTRO. No existe por carpeta logica."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "current_version": 3,
                "oldest_version": 1,
                "catalog_schema_version": 1,
                "versions": [
                    {"version": 1, "state": "soft_deleted", "destroyed": False},
                    {"version": 2, "state": "destroyed", "destroyed": True},
                    {"version": 3, "state": "active", "destroyed": False},
                ],
                "custom_metadata": {},
                "custom_metadata_note": (
                    "custom_metadata es por CLAVE, no por version: no sirve para "
                    "afirmar que esquema tenia una version historica."
                ),
            }
        }
    )

    record_id: uuid.UUID
    collection_id: uuid.UUID
    current_version: int
    oldest_version: int
    catalog_schema_version: int
    created_time: str | None
    updated_time: str | None
    max_versions: int
    cas_required: bool
    delete_version_after: str | None
    versions: list[VersionStateOut]
    custom_metadata: dict[str, Any]
    custom_metadata_note: str = (
        "custom_metadata es por CLAVE, no por version: no sirve para afirmar que "
        "esquema tenia una version historica. Eso lo dice la envoltura "
        "{'schema_version': N, 'values': {...}} guardada en cada version."
    )
    restore_note: str = (
        "Recuperar una version antigua con undelete NO cambia por si solo cual es "
        "latest: latest sigue siendo la mayor no destruida."
    )


class RecordOutcomeOut(BaseModel):
    record_id: uuid.UUID
    status: Literal["ok", "failed", "skipped"]
    version: int | None = None
    detail: str | None = None


class BatchResultOut(BaseModel):
    """Resultado de un lote de coleccion. Un fallo parcial no se oculta."""

    collection_id: uuid.UUID
    operation_id: uuid.UUID
    state: str
    inventoried: int
    processed: int
    failed: int
    skipped: int
    results: list[RecordOutcomeOut]
    note: str | None = None


class AccessCheckIn(StrictModel):
    """Capacidad efectiva sobre una coleccion o un registro. Sin valores."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": None,
                "operations": ["record_read", "record_replace"],
            }
        },
    )

    collection_id: uuid.UUID
    record_id: uuid.UUID | None = None
    operations: list[str] = Field(
        default_factory=lambda: ["record_read"],
        max_length=20,
        description="Operaciones de la allowlist cuya capacidad se quiere conocer.",
    )

    @model_validator(mode="after")
    def _not_empty(self) -> "AccessCheckIn":
        if not self.operations:
            raise ValueError("indica al menos una operacion")
        return self


class OperationCapability(BaseModel):
    operation: str
    allowed_by_application_role: bool
    reason: str | None = None


class AccessCheckOut(BaseModel):
    """Lo que puedes hacer, segun rol de aplicacion Y segun la ACL de Vault.

    Las dos cosas son necesarias: un rol que permita no sirve si la politica de
    Vault no cubre el path, y al reves tampoco.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": None,
                "collection_state": "active",
                "your_roles": ["manager"],
                "collection_readers": ["admin", "manager"],
                "operations": [
                    {"operation": "record_read", "allowed_by_application_role": True},
                    {
                        "operation": "record_replace",
                        "allowed_by_application_role": False,
                        "reason": "solo un administrador escribe",
                    },
                ],
                "vault_capabilities": {"secret/data/vpg-managed/3f2a.../*": ["read"]},
            }
        }
    )

    collection_id: uuid.UUID
    record_id: uuid.UUID | None
    collection_state: str
    your_roles: list[str]
    collection_readers: list[str]
    operations: list[OperationCapability]
    vault_capabilities: dict[str, list[str]]
    note: str = (
        "La capacidad efectiva es la interseccion: rol de aplicacion Y politica "
        "de Vault. Vault manda sobre el rol."
    )


__all__ = [
    "AccessCheckIn",
    "AccessCheckOut",
    "BatchResultOut",
    "CollectionLifecycleIn",
    "DestroyVersionsIn",
    "OperationCapability",
    "PlainDelivery",
    "PurgeIn",
    "RecordCreateIn",
    "RecordListOut",
    "RecordMetadataOut",
    "RecordOutcomeOut",
    "RecordPatchIn",
    "RecordReadIn",
    "RecordReadOut",
    "RecordReplaceIn",
    "RecordSummaryOut",
    "RecordWriteOut",
    "VersionStateOut",
    "VersionsIn",
    "WrappedDelivery",
]
