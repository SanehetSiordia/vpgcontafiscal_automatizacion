"""Registros y versiones: el CRUD completo de una tupla de secretos."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.core.errors import COMMON_ERRORS
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.deps import (
    IdempotencyHeader,
    MfaProofHeader,
    current_principal,
    get_app_settings,
    get_record_service,
    get_request_id,
    rate_limit_global,
    require_ready,
)
from app.vault_mgmt.schemas.common import PageMeta
from app.vault_mgmt.schemas.records import (
    DestroyVersionsIn,
    PlainDelivery,
    PurgeIn,
    RecordCreateIn,
    RecordListOut,
    RecordMetadataOut,
    RecordPatchIn,
    RecordReadIn,
    RecordReadOut,
    RecordReplaceIn,
    RecordSummaryOut,
    RecordWriteOut,
    VersionsIn,
    VersionStateOut,
    WrappedDelivery,
)
from app.vault_mgmt.services.records import RecordService

router = APIRouter(
    prefix="/vault/collections/{collection_id}/records",
    tags=["records"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)

CollectionId = Annotated[uuid.UUID, Path(description="UUID de la coleccion.")]
RecordId = Annotated[uuid.UUID, Path(description="UUID estable del registro.")]


def _write_out(result) -> RecordWriteOut:
    return RecordWriteOut(
        record_id=result.record_id,
        collection_id=result.collection_id,
        version=result.version,
        schema_version=result.schema_version,
        operation_id=result.operation_id,
        state=result.state,
        next_expected_version=result.version,
    )


@router.post(
    "",
    response_model=RecordWriteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un registro completo con CAS=0 (solo admin)",
    description=(
        "Guarda **un objeto completo** de campos relacionados, por ejemplo "
        "`{\"usuario\": \"demo\", \"password\": \"valor-ficticio\"}`.\n\n"
        "N registros son N secretos de Vault, cada uno con su propio path "
        "`{prefijo}/{collection_id}/{record_id}` y su propio historial. **No** son "
        "N escrituras que sobrescriben la misma clave.\n\n"
        "Se escribe con `cas=0`: si el path ya tuviera datos, la respuesta es 409 "
        "y no se sobrescribe nada.\n\n"
        "Si Vault escribe y el catalogo no puede reflejarlo, la respuesta es 409 "
        "con `operation_id`, no 201."
    ),
)
async def create_record(
    collection_id: CollectionId,
    payload: RecordCreateIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> RecordWriteOut:
    response.headers["Cache-Control"] = "no-store"
    result = await service.create(
        principal=principal,
        collection_id=collection_id,
        label=payload.label,
        values=payload.values,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _write_out(result)


@router.get(
    "",
    response_model=RecordListOut,
    summary="IDs, estado y version de los registros (lector autorizado)",
    description=(
        "**Sin valores.** Sale del indice del catalogo en PostgreSQL.\n\n"
        "`limit`/`offset` son de este listado, no del motor: el `LIST` de Vault no "
        "tiene paginacion nativa, y leer todos los valores para paginar seria "
        "exactamente lo contrario de lo que hay que hacer."
    ),
)
async def list_records(
    collection_id: CollectionId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    state: Annotated[
        str | None, Query(pattern="^(active|soft_deleted|destroyed)$")
    ] = None,
    sort: Annotated[str, Query(pattern="^(created_at|updated_at|label)$")] = "created_at",
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "asc",
) -> RecordListOut:
    limit = min(limit, settings.max_page_limit)
    page = await service.list_records(
        principal=principal,
        collection_id=collection_id,
        state=state,
        sort=sort,
        descending=order == "desc",
        limit=limit,
        offset=offset,
    )
    return RecordListOut(
        page=PageMeta(
            limit=page.limit,
            offset=page.offset,
            total=page.total,
            returned=len(page.items),
        ),
        items=[RecordSummaryOut.model_validate(item) for item in page.items],
    )


@router.get(
    "/{record_id}",
    response_model=RecordSummaryOut,
    summary="Resumen de un registro, sin valores (lector autorizado)",
    description=(
        "Estado, version actual y version de esquema. Para obtener los valores "
        "hace falta el endpoint de entrega (`POST .../read`), que es una "
        "capacidad distinta y se audita como tal."
    ),
)
async def get_record(
    collection_id: CollectionId,
    record_id: RecordId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
) -> RecordSummaryOut:
    record = await service.get_record(
        principal=principal, collection_id=collection_id, record_id=record_id
    )
    return RecordSummaryOut.model_validate(record)


@router.post(
    "/{record_id}/read",
    response_model=RecordReadOut,
    summary="Entregar una version autorizada (lector autorizado)",
    description=(
        "**Entrega envuelta por defecto.** Vault devuelve un *response wrapping "
        "token* de un solo uso y TTL corto; el consumidor lo desenvuelve en Vault "
        "(`vault unwrap`, o `POST sys/wrapping/unwrap`).\n\n"
        "Lo que el wrapping **no** es: no es un JSON cifrado, y no impide que el "
        "receptor autorizado vea los valores al desenvolverlo. Es una capacidad "
        "sensible, distinta de la `api_session` y del token de autenticacion de "
        "Vault, y es la excepcion explicita de entrega: no se registra en logs ni "
        "se persiste en la auditoria.\n\n"
        "La alternativa `plain` devuelve JSON **solo por eleccion explicita** del "
        "lector autorizado, con `Cache-Control: no-store`. En red local sin HTTPS "
        "no hay cifrado en transito: ese limite esta documentado y no se disimula.\n\n"
        "Y un aviso que conviene repetir: **SHA-256 es un hash, no cifrado "
        "reversible**. Aqui no se devuelven hashes como sustituto de las "
        "credenciales que el consumidor necesita usar."
    ),
)
async def read_record(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: RecordReadIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> RecordReadOut:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    result = await service.read(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        version=payload.version,
        delivery=payload.delivery,
        wrap_ttl_seconds=payload.wrap_ttl_seconds,
        reason=payload.reason,
        request_id=request_id,
    )
    delivery = result.get("delivery") or {}
    if delivery.get("mode") == "wrapped":
        body: WrappedDelivery | PlainDelivery = WrappedDelivery(
            wrap_token=str(delivery.get("token") or ""),
            ttl_seconds=int(delivery.get("ttl_seconds") or 0),
            version=int(delivery.get("version") or 0),
            creation_path=delivery.get("creation_path"),
        )
    else:
        body = PlainDelivery(
            version=int(delivery.get("version") or 0),
            schema_version=int(delivery.get("schema_version") or 0),
            values=dict(delivery.get("values") or {}),
        )
    return RecordReadOut(
        record_id=record_id,
        collection_id=collection_id,
        schema_version=int(
            result.get("schema_version") or result.get("catalog_schema_version") or 0
        ),
        delivery=body,
    )


@router.put(
    "/{record_id}",
    response_model=RecordWriteOut,
    summary="Reemplazo completo validado con CAS (solo admin)",
    description=(
        "Reemplaza la tupla entera y crea una **version nueva**. Las versiones "
        "anteriores no se mutan.\n\n"
        "`expected_version` es el CAS: si no coincide con la version actual, la "
        "respuesta es 409 y **no** se sobrescribe el cambio ajeno."
    ),
)
async def replace_record(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: RecordReplaceIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> RecordWriteOut:
    response.headers["Cache-Control"] = "no-store"
    result = await service.replace(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        expected_version=payload.expected_version,
        values=payload.values,
        label=payload.label,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _write_out(result)


@router.patch(
    "/{record_id}",
    response_model=RecordWriteOut,
    summary="JSON Merge Patch validado con CAS (solo admin)",
    description=(
        "Semantica de JSON Merge Patch: una clave **ausente conserva** su valor, "
        "`null` la **elimina**, un objeto se mezcla de forma recursiva y una lista "
        "se reemplaza entera.\n\n"
        "Antes de escribir se valida el objeto **resultante completo**. Si el "
        "parche deja la tupla invalida (por ejemplo un `null` sobre un campo "
        "obligatorio), la respuesta es **422 y no se escribe nada**.\n\n"
        "Eliminar un campo con `null` no borra sus campos hermanos: para eliminar "
        "la tupla completa existe DELETE."
    ),
)
async def patch_record(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: RecordPatchIn,
    response: Response,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> RecordWriteOut:
    response.headers["Cache-Control"] = "no-store"
    result = await service.patch(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        expected_version=payload.expected_version,
        patch=payload.patch,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return _write_out(result)


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete de la version actual del registro completo (solo admin)",
    description=(
        "Borra la **tupla completa** en su version actual, de forma reversible "
        "(`undelete`). Eliminar un campo es otra operacion: un PATCH con `null`, "
        "que no toca sus campos hermanos.\n\n"
        "DELETE no lleva cuerpo. 204 solo despues de completar todas las fases: "
        "si Vault borro y el catalogo no lo reflejo, la respuesta es 409 con el "
        "`operation_id`."
    ),
)
async def delete_record(
    collection_id: CollectionId,
    record_id: RecordId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.soft_delete(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{record_id}/metadata",
    response_model=RecordMetadataOut,
    summary="Metadata nativa e historial, sin valores (solo admin)",
    description=(
        "Versiones y metadata **nativas de KV v2**, que existen por **registro**, "
        "no por una carpeta logica. De la coleccion solo se agregan resumenes.\n\n"
        "`custom_metadata` es por **clave**, no por version: no sirve para afirmar "
        "que esquema tenia una version historica. Eso lo dice la envoltura "
        "`{\"schema_version\": N, \"values\": {...}}` guardada en cada version."
    ),
)
async def record_metadata(
    collection_id: CollectionId,
    record_id: RecordId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> RecordMetadataOut:
    result = await service.metadata(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        request_id=request_id,
    )
    metadata = result.get("metadata") or {}
    return RecordMetadataOut(
        record_id=record_id,
        collection_id=collection_id,
        current_version=int(metadata.get("current_version") or 0),
        oldest_version=int(metadata.get("oldest_version") or 0),
        catalog_schema_version=int(result.get("catalog_schema_version") or 0),
        created_time=metadata.get("created_time"),
        updated_time=metadata.get("updated_time"),
        max_versions=int(metadata.get("max_versions") or 0),
        cas_required=bool(metadata.get("cas_required")),
        delete_version_after=metadata.get("delete_version_after"),
        versions=[
            VersionStateOut(
                version=int(item.get("version") or 0),
                state=item.get("state") or "active",
                created_time=item.get("created_time"),
                deletion_time=item.get("deletion_time"),
                destroyed=bool(item.get("destroyed")),
            )
            for item in (metadata.get("versions") or [])
        ],
        custom_metadata=dict(metadata.get("custom_metadata") or {}),
    )


@router.post(
    "/{record_id}/versions/delete",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete de versiones explicitas (solo admin)",
    description=(
        "Las versiones son **explicitas**: no hay 'todas' implicito. Reversible "
        "con `undelete`.\n\n"
        "Si la lista no incluye la version actual, el registro sigue activo: "
        "borrar una version historica no deja el registro borrado."
    ),
)
async def delete_versions(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: VersionsIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.version_action(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        action="versions_delete",
        versions=payload.versions,
        proof=None,
        confirm=None,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{record_id}/versions/undelete",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Recuperar versiones no destruidas (solo admin)",
    description=(
        "Recupera versiones con soft-delete. Una version **destruida no se "
        "recupera**: para esas, Vault responde sin cambios y el estado se refleja "
        "tal cual.\n\n"
        "Recuperar una version antigua **no** cambia por si solo cual es `latest`: "
        "`latest` sigue siendo la mayor no destruida."
    ),
)
async def undelete_versions(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: VersionsIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.version_action(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        action="versions_undelete",
        versions=payload.versions,
        proof=None,
        confirm=None,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{record_id}/versions/destroy",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Destruir versiones explicitas, irreversible (admin + MFA reciente)",
    description=(
        "**Irreversible.** Exige tres cosas a la vez: rol admin, confirmacion "
        "explicita `confirm: \"DESTROY\"` con la lista de versiones, y una prueba "
        "breve de MFA reciente en `X-VPG-MFA-Proof` ligada a esta operacion y a "
        "este registro.\n\n"
        "Despues de esto no hay `undelete`."
    ),
)
async def destroy_versions(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: DestroyVersionsIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    mfa_proof: MfaProofHeader = None,
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.version_action(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        action="versions_destroy",
        versions=payload.versions,
        proof=mfa_proof,
        confirm=payload.confirm,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{record_id}/purge",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Borrar datos de todas las versiones y la metadata (admin + MFA reciente)",
    description=(
        "**Irreversible.** Borra los datos de todas las versiones y la metadata "
        "nativa del registro. Exige `confirm: \"PURGE\"` y prueba de MFA reciente.\n\n"
        "El registro permanece en el indice con estado `destroyed`: asi se "
        "distingue 'destruido' de 'nunca existio'. Su rastro de auditoria se "
        "conserva, y sus asignaciones a consumidores dejan de resolver."
    ),
)
async def purge_record(
    collection_id: CollectionId,
    record_id: RecordId,
    payload: PurgeIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[RecordService, Depends(get_record_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    mfa_proof: MfaProofHeader = None,
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.purge_record(
        principal=principal,
        collection_id=collection_id,
        record_id=record_id,
        proof=mfa_proof,
        confirm=payload.confirm,
        reason=payload.reason,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
