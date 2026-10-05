"""Colecciones y esquemas: ``/vault/collections`` y su ciclo de vida."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.core.errors import COMMON_ERRORS, ValidationError
from app.core.secret_schema import sensitive_field_names
from app.vault_mgmt.core.config import Settings
from app.vault_mgmt.core.principal import HumanPrincipal
from app.vault_mgmt.deps import (
    IdempotencyHeader,
    MfaProofHeader,
    current_principal,
    get_app_settings,
    get_catalog_service,
    get_lifecycle_service,
    get_request_id,
    rate_limit_global,
    require_ready,
)
from app.vault_mgmt.schemas.collections import (
    CollectionCreateIn,
    CollectionListOut,
    CollectionOut,
    CollectionPatchIn,
    SchemaOut,
    SchemaPutIn,
    SchemaUpdateOut,
    SchemaVersionOut,
)
from app.vault_mgmt.schemas.common import PageMeta
from app.vault_mgmt.schemas.records import BatchResultOut, CollectionLifecycleIn
from app.vault_mgmt.services.catalog import CatalogService
from app.vault_mgmt.services.lifecycle import LifecycleService

router = APIRouter(
    prefix="/vault",
    tags=["collections"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)

CollectionId = Annotated[uuid.UUID, Path(description="UUID de la coleccion.")]


def _assert_confirm(sent: str, expected: str) -> None:
    """La confirmacion explicita la escribe quien pide, no el servidor."""
    if sent != expected:
        raise ValidationError(
            f"esta operacion es irreversible o afecta a toda la coleccion: envia "
            f"confirm='{expected}'",
            code="confirmation_required",
        )


def _to_out(collection, record_count: int | None = None) -> CollectionOut:
    return CollectionOut(
        collection_id=collection.collection_id,
        logical_name=collection.logical_name,
        description=collection.description,
        state=collection.state,
        current_schema_version=collection.current_schema_version,
        reader_role_codes=list(collection.reader_role_codes or []),
        kv_mount=collection.kv_mount,
        physical_prefix=collection.base_path,
        record_count=record_count,
        created_at=collection.created_at,
        updated_at=collection.updated_at,
        archived_at=collection.archived_at,
        purged_at=collection.purged_at,
    )


@router.post(
    "/collections",
    response_model=CollectionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Crear una coleccion con su esquema inicial (solo admin)",
    description=(
        "Define **catalogo y esquema**. No crea ninguna carpeta en Vault: KV v2 no "
        "tiene carpetas y un prefijo sin claves no existe. Los datos aparecen con "
        "la primera escritura de un registro.\n\n"
        "El path fisico se deriva del `collection_id`, no del nombre logico: "
        "`{prefijo}/{collection_id}/{record_id}`. Por eso renombrar despues no "
        "mueve nada.\n\n"
        "`reader_role_codes` son roles de **aplicacion**. No son politicas de "
        "Vault: la ACL de Vault se comprueba ademas y manda ella."
    ),
)
async def create_collection(
    payload: CollectionCreateIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> CollectionOut:
    collection, _json_schema, _fields, _operation_id = await service.create_collection(
        principal=principal,
        logical_name=payload.logical_name,
        description=payload.description,
        reader_role_codes=list(payload.reader_role_codes),
        raw_fields=[field.model_dump(exclude_none=True) for field in payload.fields],
        request_id=request_id,
    )
    return _to_out(collection, record_count=0)


@router.get(
    "/collections",
    response_model=CollectionListOut,
    summary="Colecciones visibles para tus roles (lector autorizado)",
    description=(
        "Un administrador ve todas; cualquier otro rol ve solo las que lo declaran "
        "lector. **Sin valores**: este listado sale del catalogo en PostgreSQL.\n\n"
        "El `total` es el del catalogo **visible**, no el absoluto: decir cuantas "
        "colecciones hay en total a quien solo puede ver tres ya seria filtrar."
    ),
)
async def list_collections(
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    state: Annotated[str | None, Query(pattern="^(active|archived|purged)$")] = None,
    name_contains: Annotated[str | None, Query(max_length=120)] = None,
    sort: Annotated[
        str, Query(pattern="^(logical_name|created_at|updated_at)$")
    ] = "logical_name",
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "asc",
) -> CollectionListOut:
    limit = min(limit, settings.max_page_limit)
    page, counts = await service.list_collections(
        principal=principal,
        state=state,
        name_contains=name_contains,
        sort=sort,
        descending=order == "desc",
        limit=limit,
        offset=offset,
    )
    return CollectionListOut(
        page=PageMeta(
            limit=page.limit,
            offset=page.offset,
            total=page.total,
            returned=len(page.items),
        ),
        items=[_to_out(item, counts.get(item.collection_id)) for item in page.items],
    )


@router.get(
    "/collections/{collection_id}",
    response_model=CollectionOut,
    summary="Definicion y estado de una coleccion (lector autorizado)",
)
async def get_collection(
    collection_id: CollectionId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
) -> CollectionOut:
    collection, count = await service.get_collection(
        principal=principal, collection_id=collection_id
    )
    return _to_out(collection, count)


@router.patch(
    "/collections/{collection_id}",
    response_model=CollectionOut,
    summary="Renombrar o cambiar lectores y descripcion (solo admin)",
    description=(
        "Cambia **solo** metadatos del catalogo. Nunca valores.\n\n"
        "Renombrar `sat/usuarios` a `sat/datos` modifica el nombre logico y "
        "**conserva** el UUID, el path fisico, el historial de versiones y las "
        "referencias del crawler. KV v2 no ofrece rename nativo y aqui no se "
        "simula con copy + delete: eso perderia el historial y dejaria una copia "
        "del secreto en otro path."
    ),
)
async def patch_collection(
    collection_id: CollectionId,
    payload: CollectionPatchIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> CollectionOut:
    collection = await service.patch_collection(
        principal=principal,
        collection_id=collection_id,
        logical_name=payload.logical_name,
        description=payload.description,
        reader_role_codes=(
            list(payload.reader_role_codes) if payload.reader_role_codes else None
        ),
        request_id=request_id,
    )
    return _to_out(collection)


@router.get(
    "/collections/{collection_id}/schema",
    response_model=SchemaOut,
    summary="Campos, tipos y version del esquema (lector autorizado)",
    description=(
        "Devuelve la definicion y el documento **JSON Schema (Draft 2020-12)** "
        "que valido esa version. El documento es autocontenido: sin `$ref` ni "
        "referencias externas, de modo que un validador externo puede comprobar "
        "los mismos valores."
    ),
)
async def get_schema(
    collection_id: CollectionId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
    schema_version: Annotated[int | None, Query(ge=1)] = None,
) -> SchemaOut:
    collection, row, available = await service.get_schema(
        principal=principal, collection_id=collection_id, schema_version=schema_version
    )
    return SchemaOut(
        collection_id=collection.collection_id,
        logical_name=collection.logical_name,
        current_schema_version=collection.current_schema_version,
        available_versions=available,
        schema=SchemaVersionOut(
            schema_version=row.schema_version,
            fields=list(row.fields or []),
            json_schema=dict(row.json_schema or {}),
            sensitive_fields=sorted(sensitive_field_names(list(row.fields or []))),
            note=row.note,
            created_at=row.created_at,
        ),
    )


@router.put(
    "/collections/{collection_id}/schema",
    response_model=SchemaUpdateOut,
    summary="Nueva version de esquema, compatible (solo admin)",
    description=(
        "Crea una **version nueva**; la anterior no se modifica. Cada version de "
        "Vault guarda la envoltura `{\"schema_version\": N, \"values\": {...}}`, "
        "asi que una version historica conserva el esquema que la valido.\n\n"
        "`custom_metadata` de KV v2 es por **clave**, no por version: no se usa "
        "para afirmar que esquema tenia una version antigua.\n\n"
        "La compatibilidad se juzga comparando la **definicion**, no leyendo los "
        "registros: diagnosticar leyendo valores significaria leer todos los "
        "secretos. Un cambio incompatible responde **409** con el detalle por "
        "campo y no crea version: hace falta una migracion explicita y revisada, "
        "no una reescritura masiva automatica.\n\n"
        "Con `apply: false` solo se devuelve el diagnostico."
    ),
)
async def put_schema(
    collection_id: CollectionId,
    payload: SchemaPutIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[CatalogService, Depends(get_catalog_service)],
    request_id: Annotated[str, Depends(get_request_id)],
) -> SchemaUpdateOut:
    result = await service.update_schema(
        principal=principal,
        collection_id=collection_id,
        raw_fields=[field.model_dump(exclude_none=True) for field in payload.fields],
        note=payload.note,
        apply=payload.apply,
        request_id=request_id,
    )
    return SchemaUpdateOut.model_validate(result)


@router.delete(
    "/collections/{collection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archivar la coleccion y aplicar soft-delete a sus registros",
    description=(
        "**Solo admin y con MFA reciente.** DELETE no lleva cuerpo: la "
        "confirmacion explicita es el metodo mas la prueba breve de MFA que se "
        "envia en `X-VPG-MFA-Proof`, ligada a esta coleccion y a sus registros.\n\n"
        "Inventaria sus registros, les aplica soft-delete (recuperable) y marca la "
        "coleccion `archived`.\n\n"
        "Lo que **no** hace: no revoca secretos ya entregados, no caduca un "
        "wrapping token que ya viaja y no impide a un administrador leer Vault "
        "directamente. Eso lo decide la ACL de Vault.\n\n"
        "Si algun registro falla, la respuesta es **409** con el `operation_id` y "
        "la coleccion **no** cambia de estado. 204 solo cuando todas las fases "
        "terminaron."
    ),
)
async def archive_collection(
    collection_id: CollectionId,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    mfa_proof: MfaProofHeader = None,
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    await service.run(
        principal=principal,
        collection_id=collection_id,
        action="archive",
        proof=mfa_proof,
        idempotency_key=idempotency_key,
        request_id=request_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/collections/{collection_id}/restore",
    response_model=BatchResultOut,
    summary="Restaurar la coleccion y sus versiones recuperables",
    description=(
        "**Solo admin y con MFA reciente.** Recupera las versiones con "
        "soft-delete y reactiva el catalogo.\n\n"
        "Una version **destruida no vuelve**: se reporta como `skipped`, no como "
        "exito. Y recuperar una version antigua no cambia por si solo cual es "
        "`latest`."
    ),
)
async def restore_collection(
    collection_id: CollectionId,
    payload: CollectionLifecycleIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    mfa_proof: MfaProofHeader = None,
    idempotency_key: IdempotencyHeader = None,
) -> BatchResultOut:
    _assert_confirm(payload.confirm, "RESTORE")
    result = await service.run(
        principal=principal,
        collection_id=collection_id,
        action="restore",
        proof=mfa_proof,
        idempotency_key=idempotency_key,
        request_id=request_id,
        reason=payload.reason,
    )
    return BatchResultOut(
        collection_id=result.collection_id,
        operation_id=result.operation_id,
        state=result.state,
        inventoried=result.inventoried,
        processed=result.processed,
        failed=result.failed,
        skipped=result.skipped,
        results=result.results,  # type: ignore[arg-type]
        note=result.note,
    )


@router.post(
    "/collections/{collection_id}/purge",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Destruir datos y metadata de sus registros (irreversible)",
    description=(
        "**Solo admin, con confirmacion explicita y MFA reciente.** Destruye "
        "datos y metadata de los registros de la coleccion. No hay undelete "
        "despues de esto.\n\n"
        "Se conserva la auditoria minima: la fila de la coleccion, las de sus "
        "registros en estado `destroyed` y el historial.\n\n"
        "El lote esta acotado por configuracion. Si la coleccion tiene mas "
        "registros que el tope, la peticion se rechaza **antes** de tocar nada."
    ),
)
async def purge_collection(
    collection_id: CollectionId,
    payload: CollectionLifecycleIn,
    principal: Annotated[HumanPrincipal, Depends(current_principal)],
    service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    request_id: Annotated[str, Depends(get_request_id)],
    mfa_proof: MfaProofHeader = None,
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    _assert_confirm(payload.confirm, "PURGE")
    await service.run(
        principal=principal,
        collection_id=collection_id,
        action="purge",
        proof=mfa_proof,
        idempotency_key=idempotency_key,
        request_id=request_id,
        reason=payload.reason,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# El router de registros se monta desde main con el mismo prefijo /vault; se
# declara aparte solo para que cada archivo quepa en la cabeza de quien lo lee.
__all__ = ["router"]
