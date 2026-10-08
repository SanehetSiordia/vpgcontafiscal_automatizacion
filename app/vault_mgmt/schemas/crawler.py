"""DTO de consumidores de maquina y del contrato del futuro crawler.

El crawler es una **maquina independiente**, no un empleado con sesion:

* No se le presta la ``api_session`` de nadie.
* Presenta en ``Authorization`` un **token de Vault** que obtuvo antes con su
  propia AppRole de solo lectura. Es otro contrato, separado del Bearer humano.
* Resuelve por UUID de registro y version explicita. Nunca por usuario y
  contrasena, nunca por un path libre, nunca por una URL arbitraria.
* Recibe wrapping tokens emitidos con **sus** permisos, no con los de un
  empleado ni con los de la cuenta tecnica de bootstrap.
* No recibe tokens de autenticacion nuevos: este endpoint no los emite.

Este contrato no inicia ningun proceso de crawling y no hace peticiones a sitios
externos.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.vault_mgmt.schemas.common import StrictModel


class BindingIn(StrictModel):
    """Una asignacion: que registro y que version puede resolver el consumidor."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                "pinned_version": 2,
            }
        },
    )

    collection_id: uuid.UUID
    record_id: uuid.UUID
    pinned_version: Annotated[int | None, Field(default=None, ge=1)] = Field(
        default=None,
        description=(
            "Version fijada. Ausente (null) significa 'la ultima viva' (latest): "
            "cambia cuando se escribe otra version. Una version fijada no cambia."
        ),
    )


class BindingsPutIn(StrictModel):
    """Reemplazo COMPLETO del conjunto de asignaciones (PUT, no PATCH).

    Lo que no venga en la lista deja de estar autorizado. Revocar impide
    **entregas futuras**: no caduca un wrapping token ya entregado ni borra lo
    que el consumidor ya leyo.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "bindings": [
                    {
                        "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                        "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                        "pinned_version": None,
                    }
                ]
            }
        },
    )

    bindings: list[BindingIn] = Field(default_factory=list, max_length=200)


class BindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    binding_id: uuid.UUID
    collection_id: uuid.UUID
    collection_name: str | None = None
    record_id: uuid.UUID
    pinned_version: int | None
    resolves_to: str = Field(
        description="'version fijada' o 'latest'. Sin credenciales ni valores."
    )
    created_at: dt.datetime


class ConsumerOut(BaseModel):
    """Referencia y alcance de un consumidor. **Sin credenciales.**

    No se devuelven ``role_id`` ni ``secret_id``: no se guardan aqui. Los crea y
    los entrega ``scripts/vault_mgmt/crawler-approle-bootstrap.sh``.
    """

    model_config = ConfigDict(from_attributes=True)

    consumer_id: uuid.UUID
    name: str
    description: str | None
    state: str
    approle_mount: str
    approle_role_name: str
    expected_policy: str
    created_at: dt.datetime
    revoked_at: dt.datetime | None = None


class BindingsOut(BaseModel):
    consumer: ConsumerOut
    bindings: list[BindingOut]
    total: int
    revocation_note: str = (
        "Quitar una asignacion impide entregas futuras. No caduca un wrapping "
        "token ya entregado, no revoca el token AppRole del consumidor y no "
        "borra lo que ya leyo. Para cortar de raiz, revoca su AppRole en Vault."
    )


class CrawlerRecordRequest(StrictModel):
    """Un registro solicitado. Solo UUID y version; nunca un path."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                "version": None,
            }
        },
    )

    collection_id: uuid.UUID
    record_id: uuid.UUID
    version: Annotated[int | None, Field(default=None, ge=1)] = Field(
        default=None,
        description=(
            "Version explicita. Ausente usa la fijada en el binding; si el "
            "binding no fija ninguna, la ultima viva."
        ),
    )


class CrawlerResolveIn(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "records": [
                    {
                        "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                        "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                        "version": None,
                    }
                ],
                "wrap_ttl_seconds": 60,
                "job_reference": "tarea-sat-2026-10-05",
            }
        },
    )

    records: list[CrawlerRecordRequest] = Field(min_length=1, max_length=100)
    wrap_ttl_seconds: Annotated[int | None, Field(default=None, ge=10, le=600)] = None
    job_reference: Annotated[str | None, Field(default=None, max_length=120)] = Field(
        default=None,
        description=(
            "Referencia NO sensible de la tarea, para la auditoria. Nunca metas "
            "aqui un secreto: el valor se guarda en el historial."
        ),
    )


class CrawlerDeliveryOut(BaseModel):
    """Entrega envuelta para la maquina. Emitida con SUS permisos."""

    collection_id: uuid.UUID
    record_id: uuid.UUID
    version: int
    pinned: bool = Field(
        description="True si el binding fija la version; False si resuelve a latest."
    )
    wrap_token: str
    ttl_seconds: int
    expires_at: dt.datetime
    mediated: bool = Field(
        default=False,
        description=(
            "True: la leyo el backend autorizado por cuenta del consumidor "
            "(consumidor gestionado, cuya politica NO cubre la lectura de KV). "
            "False: la leyo el token del propio consumidor (consumidor heredado "
            "de la etapa 4), cuya politica cubre todo el prefijo gestionado."
        ),
    )


class CrawlerResolveOut(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "consumer": "crawler-sat",
                "requested": 1,
                "delivered": 1,
                "deliveries": [
                    {
                        "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                        "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                        "version": 2,
                        "pinned": False,
                        "wrap_token": "hvs.CAESIJ...-ejemplo-no-reutilizable",
                        "ttl_seconds": 60,
                        "expires_at": "2026-10-05T10:01:00+00:00",
                    }
                ],
                "rejected": [],
            }
        }
    )

    consumer: str
    requested: int
    delivered: int
    deliveries: list[CrawlerDeliveryOut]
    rejected: list[dict[str, str]] = Field(
        default_factory=list,
        description="Motivo por registro no entregado. Sin valores ni paths.",
    )
    note: str = (
        "Un wrapping token es de un solo uso y caduca. Si caduca o ya se consumio, "
        "vuelve a pedir la entrega: no hace falta repetir la tarea. Este endpoint "
        "no inicia ningun crawling y no emite tokens de autenticacion."
    )


__all__ = [
    "BindingIn",
    "BindingOut",
    "BindingsOut",
    "BindingsPutIn",
    "ConsumerOut",
    "CrawlerDeliveryOut",
    "CrawlerRecordRequest",
    "CrawlerResolveIn",
    "CrawlerResolveOut",
]
