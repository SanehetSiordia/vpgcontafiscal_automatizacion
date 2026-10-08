"""DTO del contrato de consumidores de maquina (etapa 4.6).

Pensados para que un cliente TypeScript se genere del OpenAPI sin sorpresas:
tipos cerrados, ``extra="forbid"`` en las entradas y ningun campo opcional que
en realidad sea obligatorio.

Tres reglas que se ven en los tipos, no solo en la documentacion:

* **Ningun DTO humano lleva credenciales.** No hay ``role_id``, ni
  ``secret_id``, ni tokens de Vault, ni wrapping tokens en ninguna respuesta de
  estos endpoints. Lo que se devuelve de Vault son ``accessors``, que sirven
  para revocar y auditar pero no para autenticarse.
* **El alta no acepta nada de Vault.** No hay HCL, ni path, ni montaje, ni rol,
  ni URL del receptor: el montaje y el rol los deriva el servidor de la
  configuracion y del nombre del consumidor.
* **La respuesta de alta es 202 y tres campos.** ``pending`` significa
  *solicitud guardada*, no *entrega completada*. El estado real se consulta
  despues en la operacion.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.vault_mgmt.schemas.common import PageMeta, StrictModel
from app.vault_mgmt.schemas.crawler import BindingIn

# Mismo alfabeto que el CHECK de secret_consumers.name en la migracion 003.
ConsumerName = Annotated[
    str,
    Field(
        min_length=2,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9._-]{1,62}$",
        description=(
            "Minusculas, digitos, '.', '_' y '-'. Se usa para derivar el nombre "
            "del rol AppRole, asi que no se puede cambiar despues del alta."
        ),
    ),
]
ReceiverKey = Annotated[
    str,
    Field(
        min_length=2,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9._-]{1,62}$",
        description=(
            "Receptor CONFIGURADO que podra reclamar la emision. Debe existir "
            "en la configuracion del servicio (su credencial interna vive en "
            "secrets/). No es una URL y no es una contrasena."
        ),
    ),
]

OperationStatus = Literal[
    "pending",
    "in_progress",
    "waiting_receiver",
    "awaiting_ack",
    "completed",
    "failed",
    "needs_reconciliation",
]
ProvisioningState = Literal[
    "unprovisioned", "provisioning", "ready", "failed", "revoked"
]


class ConsumerCreateIn(StrictModel):
    """Alta de un consumidor de maquina y su alcance inicial."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "name": "crawler-sat",
                "description": "Crawler del portal del SAT (futuro)",
                "receiver": "crawler-sat",
                "bindings": [
                    {
                        "collection_id": "3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90",
                        "record_id": "8c902d44-1b5e-4a90-9f4c-3f2a7c18ab01",
                        "pinned_version": 2,
                    }
                ],
            }
        },
    )

    name: ConsumerName
    description: Annotated[str | None, Field(default=None, max_length=500)] = None
    receiver: ReceiverKey
    bindings: list[BindingIn] = Field(
        default_factory=list,
        max_length=200,
        description=(
            "Alcance inicial. Se puede dejar vacio y fijarlo despues con "
            "PUT /vault/consumers/{consumer_id}/bindings."
        ),
    )


class ProvisionIn(StrictModel):
    """Solicita una emision para un consumidor que ya existe."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"note": "rearranque del receptor"}},
    )

    note: Annotated[str | None, Field(default=None, max_length=200)] = Field(
        default=None,
        description=(
            "Referencia NO sensible para la auditoria. Nunca metas aqui un "
            "secreto: queda en el historial."
        ),
    )


class RotateIn(StrictModel):
    """Rotacion controlada de la credencial de maquina.

    La estrategia local es explicita y se elige aqui:

    * ``after_ack`` (por omision): se emite la credencial nueva y la anterior se
      retira **solo** cuando el receptor confirma la nueva. Durante la ventana
      el **token** anterior sigue vivo hasta su TTL (su SecretID ya se consumio
      al entrar, porque es de un solo uso). Es lo que evita dejar fuera al
      crawler que ya estaba dentro si el rearranque falla.
    * ``immediate``: se destruye la anterior al emitir la nueva. Mas estricto y
      con ventana de corte: si el receptor no recoge la nueva, se queda fuera
      hasta el siguiente aprovisionamiento.

    En los dos casos, destruir un SecretID **no** revoca los tokens que ya
    salieron de el: esos viven hasta su TTL y se cortan por su accessor.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"strategy": "after_ack", "note": "rotacion mensual"}},
    )

    strategy: Literal["after_ack", "immediate"] = "after_ack"
    note: Annotated[str | None, Field(default=None, max_length=200)] = None


class RevokeIn(StrictModel):
    """Bloqueo de entregas y revocacion tecnica.

    ``confirm`` debe ser el nombre del consumidor: una revocacion no se dispara
    por un clic accidental en un formulario.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"confirm": "crawler-sat", "reason": "maquina retirada"}
        },
    )

    confirm: ConsumerName
    reason: Annotated[str | None, Field(default=None, max_length=200)] = None


class AcceptedOut(BaseModel):
    """Respuesta 202 de toda solicitud administrativa.

    Exactamente los tres campos del contrato. ``pending`` significa *solicitud
    guardada*: no hay entrega, no hay credencial emitida y no hay nada que el
    receptor pueda usar todavia.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "consumer_id": "9f1a77f0-c2a9-4e50-b1d0-e7a45c334c0e",
                "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
                "status": "pending",
            }
        }
    )

    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    status: OperationStatus


class DeliveryOut(BaseModel):
    """Una emision, vista por un administrador. Sin credenciales.

    ``secret_id_accessor``, ``wrap_accessor`` y ``token_accessor`` identifican
    credenciales para poder revocarlas y auditarlas; no permiten usarlas.
    """

    model_config = ConfigDict(from_attributes=True)

    delivery_id: uuid.UUID
    operation_id: uuid.UUID
    receiver_id: uuid.UUID
    state: Literal[
        "reserved", "delivered", "acked", "expired", "failed", "superseded"
    ]
    secret_id_accessor: str | None = None
    wrap_accessor: str | None = None
    token_accessor: str | None = None
    wrap_ttl_seconds: int | None = None
    # Caducidad de la ENVOLTURA, no del token resultante: son TTL distintos.
    expires_at: dt.datetime | None = None
    attempts: int
    error: str | None = None
    created_at: dt.datetime
    claimed_at: dt.datetime | None = None
    acked_at: dt.datetime | None = None


class ConsumerSummaryOut(BaseModel):
    """Fila de listado. Sin credenciales y sin accessors."""

    model_config = ConfigDict(from_attributes=True)

    consumer_id: uuid.UUID
    name: str
    description: str | None
    state: Literal["active", "revoked"]
    provisioning_state: ProvisioningState
    delivery_mode: Literal["direct", "mediated"]
    approle_mount: str
    approle_role_name: str
    expected_policy: str
    created_at: dt.datetime
    provisioned_at: dt.datetime | None = None
    revoked_at: dt.datetime | None = None


class ConsumerListOut(BaseModel):
    page: PageMeta
    items: list[ConsumerSummaryOut]
    legacy_note: str = (
        "Un consumidor con delivery_mode 'direct' viene de la etapa 4: lo preparo "
        "scripts/vault_mgmt/crawler-approle-bootstrap.sh y su token LEE el "
        "prefijo KV directamente, asi que sus bindings acotan lo que esta API le "
        "entrega, no lo que su token puede leer en Vault. Migrarlo a entrega "
        "mediada es una decision explicita: ver readme/etapa-4-6."
    )


class LastOperationOut(BaseModel):
    """Resumen de la ultima operacion del consumidor, ya saneado."""

    model_config = ConfigDict(from_attributes=True)

    operation_id: uuid.UUID
    operation_type: str
    status: OperationStatus
    attempts: int
    error: str | None
    created_at: dt.datetime
    finished_at: dt.datetime | None


class ConsumerDetailOut(BaseModel):
    """Estado del consumidor y su ultima operacion. Sin credenciales."""

    consumer: ConsumerSummaryOut
    last_operation: LastOperationOut | None = None
    last_delivery: DeliveryOut | None = None
    bindings_total: int = 0
    note: str = (
        "provisioning_state 'ready' significa que el receptor acredito un token "
        "de Vault valido para esta identidad. No garantiza que siga vivo: un "
        "token caduca por su TTL y el SecretID por el suyo."
    )


__all__ = [
    "AcceptedOut",
    "ConsumerCreateIn",
    "ConsumerDetailOut",
    "ConsumerListOut",
    "ConsumerName",
    "ConsumerSummaryOut",
    "DeliveryOut",
    "LastOperationOut",
    "OperationStatus",
    "ProvisionIn",
    "ProvisioningState",
    "ReceiverKey",
    "RevokeIn",
    "RotateIn",
]
