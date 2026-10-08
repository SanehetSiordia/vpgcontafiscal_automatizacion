"""DTO del canal INTERNO de aprovisionamiento (claim y ack).

Estos dos endpoints son los unicos de todo el proyecto cuya respuesta lleva una
credencial, y conviene tener claro exactamente que lleva y que no:

* ``ClaimOut`` devuelve ``role_id`` y un **wrapping token**. El wrapping token
  no es el SecretID: es un vale de un solo uso que el receptor canjea en Vault
  por el SecretID. Si alguien lo intercepta y lo desenvuelve primero, el
  receptor se queda sin poder usarlo y la operacion no llega a ``completed``, lo
  que deja rastro en vez de pasar desapercibido.
* El SecretID **nunca** pasa por este proceso en claro. Se pide a Vault con
  ``X-Vault-Wrap-TTL``, asi que el servicio solo ve el vale.
* Ninguno de los dos se guarda en PostgreSQL ni se registra en ningun log. De
  la envoltura se guarda su ``accessor``.

Quien puede llamar: el receptor configurado, con su credencial interna en la
cabecera correspondiente. No se acepta un ``consumer_id`` del cliente: el
servidor lo resuelve desde esa credencial. Estos endpoints estan fuera del
OpenAPI publico y no se publican al host, pero eso **no** es lo que los
protege: lo que los protege es la credencial.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.vault_mgmt.schemas.common import StrictModel


class ClaimIn(StrictModel):
    """El receptor reclama su emision.

    No lleva ``consumer_id`` a proposito: aceptarlo permitiria a un receptor
    pedir la credencial de otro. Se resuelve desde la credencial presentada.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"instance": "crawler-sat-1", "wrap_ttl_seconds": 120}
        },
    )

    instance: Annotated[str | None, Field(default=None, max_length=120)] = Field(
        default=None,
        description=(
            "Identificador NO sensible de la instancia que reclama, para la "
            "auditoria. No se usa para autorizar nada."
        ),
    )
    wrap_ttl_seconds: Annotated[int | None, Field(default=None, ge=30, le=600)] = Field(
        default=None,
        description=(
            "TTL de la envoltura. Se acota al maximo configurado en el servicio: "
            "un cliente no puede pedir una ventana mas larga que la permitida."
        ),
    )


class ClaimOut(BaseModel):
    """Lo que recibe el receptor cuando hay emision preparada.

    ``wrap_token`` es de **un solo uso**. Desenvolverlo da el SecretID, que
    junto a ``role_id`` sirve para un ``POST auth/<montaje>/login``. El token
    resultante se queda en memoria del receptor y no vuelve aqui: lo que vuelve
    en el ``ack`` es ese token para comprobarlo, no para guardarlo.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "issued",
                "consumer_id": "9f1a77f0-c2a9-4e50-b1d0-e7a45c334c0e",
                "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
                "delivery_id": "5c334c0e-9f1a-4e50-b1d0-e7a477f0c2a9",
                "approle_mount": "approle-crawler",
                "role_id": "7b8c9e01-3f2a-4c18-9f4c-2d441b5e6a7d",
                "wrap_token": "hvs.CAESIJ...-ejemplo-no-reutilizable",
                "wrap_ttl_seconds": 120,
                "wrap_expires_at": "2026-10-07T10:02:00+00:00",
                "login_path": "auth/approle-crawler/login",
            }
        }
    )

    status: Literal["issued"] = "issued"
    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    delivery_id: uuid.UUID
    approle_mount: str
    role_id: str = Field(
        description=(
            "Identificador del rol. No es un secreto por si solo: sin SecretID "
            "no autentica. Aun asi, no se devuelve en ningun endpoint humano."
        )
    )
    wrap_token: str = Field(
        description=(
            "Wrapping token de un solo uso. Desenvuelvelo en "
            "'POST sys/wrapping/unwrap' para obtener el secret_id."
        )
    )
    wrap_ttl_seconds: int
    wrap_expires_at: dt.datetime
    login_path: str
    next_step: str = (
        "1) sys/wrapping/unwrap con wrap_token -> secret_id. "
        "2) login_path con role_id y secret_id -> token de Vault. "
        "3) POST .../provisioning/ack con delivery_id y ESE token. "
        "Hasta el ack, la operacion sigue en awaiting_ack y no esta completa."
    )


class ClaimPendingOut(BaseModel):
    """No hay nada que entregar ahora mismo, y por que.

    Es una respuesta 200 legitima, no un error: el receptor pregunta, y la
    respuesta honesta puede ser "todavia no".
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "waiting_provisioner",
                "consumer_id": "9f1a77f0-c2a9-4e50-b1d0-e7a45c334c0e",
                "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
                "detail": "la AppRole todavia no esta preparada; reintenta",
                "retry_after_seconds": 5,
            }
        }
    )

    status: Literal["no_pending_request", "waiting_provisioner", "already_delivered"]
    consumer_id: uuid.UUID
    operation_id: uuid.UUID | None = None
    delivery_id: uuid.UUID | None = None
    detail: str
    retry_after_seconds: int | None = None


class AckIn(StrictModel):
    """Confirmacion del receptor, acreditando el token que obtuvo.

    El token se envia para **comprobarlo**, no para guardarlo: el servidor hace
    ``lookup`` contra Vault y verifica que su identidad es la esperada (montaje,
    rol y politica del consumidor). Despues se descarta. No se persiste y no se
    registra.

    Por eso no basta un ``success: true``: un receptor que no logro autenticarse
    (o que no es quien dice) no puede fabricar un token que pase el ``lookup``.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "delivery_id": "5c334c0e-9f1a-4e50-b1d0-e7a477f0c2a9",
                "vault_token": "hvs.CAESI...-token-obtenido-con-la-approle",
                "instance": "crawler-sat-1",
            }
        },
    )

    delivery_id: uuid.UUID
    vault_token: str = Field(
        min_length=8,
        max_length=512,
        description=(
            "Token obtenido con role_id y secret_id. Se comprueba con "
            "'auth/token/lookup' y se descarta: no se guarda ni se registra."
        ),
    )
    instance: Annotated[str | None, Field(default=None, max_length=120)] = None


class AckOut(BaseModel):
    """Resultado del ack, ya con la identidad comprobada."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "completed",
                "consumer_id": "9f1a77f0-c2a9-4e50-b1d0-e7a45c334c0e",
                "operation_id": "b1d0e7a4-5c33-4c0e-9f1a-77f0c2a9e501",
                "delivery_id": "5c334c0e-9f1a-4e50-b1d0-e7a477f0c2a9",
                "provisioning_state": "ready",
                "token_accessor": "8f2b1c90-aa31-4c7e-b0d4-6e5f1a9c2d33",
                "token_ttl_seconds": 1200,
            }
        }
    )

    status: Literal["completed"] = "completed"
    consumer_id: uuid.UUID
    operation_id: uuid.UUID
    delivery_id: uuid.UUID
    provisioning_state: Literal["ready"] = "ready"
    token_accessor: str = Field(
        description=(
            "Accessor del token acreditado. Permite revocar ESE token sin "
            "tenerlo. No es el token."
        )
    )
    token_ttl_seconds: int
    retired_previous: bool = Field(
        default=False,
        description=(
            "True si esta confirmacion retiro la credencial anterior (rotacion "
            "con estrategia after_ack)."
        ),
    )


__all__ = ["AckIn", "AckOut", "ClaimIn", "ClaimOut", "ClaimPendingOut"]
