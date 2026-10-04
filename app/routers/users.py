"""CRUD de empleados.

Nota sobre datos personales: los filtros de listado se limitan a rol y estado.
Para buscar por correo, RFC o CURP esta ``POST /user/search``, con cuerpo, para
que esos valores no acaben en la URL ni en los logs.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import COMMON_ERRORS, ForbiddenError, NotFoundError
from app.deps import (
    IdempotencyHeader,
    current_principal,
    get_app_settings,
    get_auth_service,
    get_db,
    get_vault_sync,
    rate_limit_global,
    require_ready,
)
from app.repositories import users as repo
from app.schemas.auth import OperationOut
from app.schemas.user import (
    PageMeta,
    RoleAssignment,
    UserCreate,
    UserOut,
    UserPage,
    UserPatch,
    UserReplace,
    UserSearch,
)
from app.services import rbac
from app.services import users as service
from app.services.auth import AuthService
from app.services.rbac import Principal
from app.services.vault_sync import VaultSyncService

router = APIRouter(
    prefix="/user",
    tags=["user"],
    dependencies=[Depends(require_ready), Depends(rate_limit_global)],
    responses=COMMON_ERRORS,
)

UserId = Annotated[uuid.UUID, Path(description="UUID del empleado.")]


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Alta de empleado",
    description=(
        "Crea en **una sola transaccion** `employees.users`, `employees.user_profiles` "
        "y `employees.user_roles`, mas los contactos que se envien. Si cualquier "
        "insercion o validacion falla, se revierte todo.\n\n"
        "**Roles:** un `admin` puede elegir uno o varios codigos que ya existan en "
        "`employees.roles`. Un `manager` no puede enviarlos: el servidor asigna "
        "`employee` y rechaza la peticion si intenta elegir. Este endpoint nunca "
        "crea filas nuevas en el catalogo de roles.\n\n"
        "**No** provisiona credenciales ni MFA: eso es "
        "`POST /user/{user_id}/vault/provision`, y lo hace un administrador."
    ),
)
async def create_user(
    payload: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserOut:
    rbac.assert_can_create_user(principal)
    role_codes = rbac.resolve_role_codes_for_create(principal, payload.role_codes)
    user = await service.create_user(
        db, payload=payload, role_codes=role_codes, actor=principal
    )
    return service.to_out(user)


@router.get(
    "",
    response_model=UserPage,
    summary="Listado paginado de empleados",
    description=(
        "Orden **estable**: la columna elegida y, como desempate, el UUID. Los "
        "filtros se limitan a rol y estado; no hay filtros por datos personales en "
        "la URL a proposito.\n\n"
        "Un `employee` solo se ve a si mismo."
    ),
)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    limit: Annotated[int, Query(ge=1, le=100, description="Elementos por pagina.")] = 20,
    offset: Annotated[int, Query(ge=0, description="Elementos a saltar.")] = 0,
    role_code: Annotated[
        Literal["admin", "manager", "employee"] | None,
        Query(description="Filtra por rol de aplicacion."),
    ] = None,
    is_active: Annotated[bool | None, Query(description="Filtra por estado.")] = None,
    sort_by: Annotated[
        Literal["created_at", "updated_at", "username"],
        Query(description="Allowlist de columnas ordenables."),
    ] = "created_at",
    order: Annotated[Literal["asc", "desc"], Query()] = "desc",
) -> UserPage:
    limit = min(limit, settings.max_page_limit)

    if principal.is_employee_only:
        user = await repo.get_by_id(db, principal.user_id)
        items = [service.to_out(user)] if user is not None else []
        return UserPage(
            items=items,
            page=PageMeta(limit=limit, offset=0, total=len(items), returned=len(items)),
        )

    rows, total = await repo.list_users(
        db,
        limit=limit,
        offset=offset,
        role_code=role_code,
        is_active=is_active,
        sort_by=sort_by,
        descending=(order == "desc"),
    )
    items = [service.to_out(u) for u in rows]
    return UserPage(
        items=items,
        page=PageMeta(limit=limit, offset=offset, total=total, returned=len(items)),
    )


@router.post(
    "/search",
    response_model=UserPage,
    summary="Busqueda por datos personales (cuerpo, no URL)",
    description=(
        "Va por POST para que el correo, el RFC o la CURP no viajen en la URL ni "
        "queden en logs de acceso o en el historial. Sus **valores no se registran**.\n\n"
        "Solo `admin` y `manager`."
    ),
)
async def search_users(
    payload: UserSearch,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserPage:
    if principal.is_employee_only:
        raise ForbiddenError("un empleado no puede buscar a otros empleados")

    found: list = []
    if payload.username:
        user = await repo.get_by_username(db, payload.username)
        if user is not None:
            found.append(user)
    if payload.email and not found:
        owner = await repo.email_owner(db, payload.email)
        if owner is not None:
            user = await repo.get_by_id(db, owner)
            if user is not None:
                found.append(user)
    if (payload.rfc or payload.curp) and not found:
        owner = await repo.rfc_or_curp_owner(db, rfc=payload.rfc, curp=payload.curp)
        if owner is not None:
            user = await repo.get_by_id(db, owner)
            if user is not None:
                found.append(user)

    items = [service.to_out(u) for u in found]
    return UserPage(
        items=items,
        page=PageMeta(
            limit=payload.limit, offset=payload.offset, total=len(items), returned=len(items)
        ),
    )


@router.get(
    "/{user_id}",
    response_model=UserOut,
    summary="Detalle de un empleado",
    description=(
        "Autorizacion **por objeto**: conocer el UUID de otro empleado no da derecho "
        "a leerlo. Un `employee` solo accede a su propia ficha.\n\n"
        "Muestra el estado historico del TOTP y su aviso correspondiente. Este GET "
        "**nunca** genera, destruye ni reinicia TOTP, y no cambia credenciales."
    ),
)
async def get_user(
    user_id: UserId,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserOut:
    rbac.assert_can_read_user(principal, user_id)
    user = await repo.get_by_id(db, user_id)
    if user is None:
        raise NotFoundError("no existe ese empleado")
    return service.to_out(user)


@router.put(
    "/{user_id}",
    response_model=UserOut,
    summary="Reemplazo de los campos editables (PUT)",
    description=(
        "**Semantica de reemplazo**: el cuerpo describe el estado final. Las "
        "colecciones que lleguen vacias se vacian. Para cambios parciales usa PATCH.\n\n"
        "No admite `id`, marcas de auditoria, `auth_provider`, `password_hash`, roles "
        "ni el vinculo con Vault: esos se cambian por sus endpoints."
    ),
)
async def replace_user(
    user_id: UserId,
    payload: UserReplace,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserOut:
    rbac.assert_can_write_user(principal, user_id)
    rbac.assert_can_edit_profile(principal, user_id)
    user = await service.replace_user(db, user_id=user_id, payload=payload)
    return service.to_out(user)


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    summary="Modificacion parcial (PATCH)",
    description=(
        "**Semantica parcial**: un campo omitido se deja como esta; nunca se "
        "interpreta como borrado. Para modificar un contacto concreto hay que "
        "enviar su `id`; para borrarlo, usar `remove_*_ids`.\n\n"
        "Un `employee` puede modificar sus **propios contactos**, pero no su perfil "
        "fiscal (nombre, RFC, CURP, fecha de nacimiento)."
    ),
)
async def patch_user(
    user_id: UserId,
    payload: UserPatch,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserOut:
    rbac.assert_can_write_user(principal, user_id)
    may_edit_profile = principal.is_admin or principal.is_manager
    user = await service.patch_user(
        db, user_id=user_id, payload=payload, may_edit_profile=may_edit_profile
    )
    return service.to_out(user)


@router.put(
    "/{user_id}/roles",
    response_model=UserOut,
    summary="Asignacion de roles (solo admin)",
    description=(
        "Reemplaza el conjunto completo de roles. Los codigos deben existir ya en "
        "`employees.roles`; este endpoint no crea roles nuevos.\n\n"
        "Protege la **ultima cuenta admin activa**: quitarle el rol devuelve 409.\n\n"
        "Son roles de aplicacion. No asignan politicas de Vault."
    ),
)
async def set_roles(
    user_id: UserId,
    payload: RoleAssignment,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> UserOut:
    rbac.require_admin(principal, "asignar roles")
    user = await service.set_roles(
        db, user_id=user_id, role_codes=payload.role_codes, actor=principal
    )
    return service.to_out(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Baja logica",
    description=(
        "Marca `is_active=false`, invalida las sesiones del empleado y **deshabilita "
        "su entidad en Vault**, que es lo que bloquea tambien los tokens ya emitidos.\n\n"
        "Si la entidad no se pudo deshabilitar, la respuesta **no** es 204: la baja "
        "no esta completa y se devuelve 409 con el `operation_id`. Deshabilitar no "
        "equivale a revocar, y la revocacion es solo del objetivo: nunca se hace una "
        "revocacion global del montaje userpass."
    ),
    responses=COMMON_ERRORS
    | {204: {"description": "Baja completa en PostgreSQL y en Vault."}},
)
async def deactivate_user(
    user_id: UserId,
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    rbac.assert_can_write_user(principal, user_id)
    if principal.is_employee_only:
        raise ForbiddenError("un empleado no puede darse de baja a si mismo")

    result = await sync.deactivate(
        user_id=user_id,
        actor_user_id=principal.user_id,
        revoke_sessions=auth.revoke_user_sessions,
    )
    if result.warning is not None:
        from app.core.errors import PartialOperationError

        raise PartialOperationError(
            result.warning, context={"operation_id": str(result.operation_id)}
        )

    response.headers["X-Operation-Id"] = str(result.operation_id)
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"X-Operation-Id": str(result.operation_id)},
    )


@router.delete(
    "/{user_id}/purge",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminacion definitiva (solo admin)",
    description=(
        "Solo sobre un empleado **ya desactivado** y nunca sobre uno mismo.\n\n"
        "Borra unicamente **sus** recursos: cuenta userpass, alias, entidad y el "
        "enrolamiento TOTP de esa entidad. El metodo TOTP compartido, el "
        "enforcement y los secretos del SAT **no se tocan**.\n\n"
        "Si la entidad tuviera alias de otros montajes o nombres, la purga se "
        "detiene con 409 y lo explica, en vez de destruir accesos ajenos.\n\n"
        "El registro de la operacion sobrevive al borrado como auditoria minima."
    ),
)
async def purge_user(
    user_id: UserId,
    principal: Annotated[Principal, Depends(current_principal)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    sync: Annotated[VaultSyncService, Depends(get_vault_sync)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    idempotency_key: IdempotencyHeader = None,
) -> Response:
    rbac.require_admin(principal, "purgar un empleado")
    rbac.assert_not_self_purge(principal, user_id)
    rbac.require_fresh_mfa(
        principal, settings.sensitive_op_mfa_max_age_seconds, "purgar un empleado"
    )

    operation_id = await sync.purge(
        user_id=user_id,
        actor_user_id=principal.user_id,
        idempotency_key=idempotency_key,
        revoke_sessions=auth.revoke_user_sessions,
    )
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"X-Operation-Id": str(operation_id)},
    )


@router.get(
    "/{user_id}/operations",
    response_model=list[OperationOut],
    summary="Operaciones Vault de este empleado",
    description=(
        "Historial del registro durable: que fases se completaron en cada sistema. "
        "Util para reconciliar un fallo parcial. No contiene secretos."
    ),
)
async def user_operations(
    user_id: UserId,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> list[OperationOut]:
    rbac.require_admin(principal, "consultar el historial de operaciones")
    from sqlalchemy import select

    from app.models.employees import VaultOperation

    rows = (
        await db.execute(
            select(VaultOperation)
            .where(VaultOperation.target_user_id == user_id)
            .order_by(VaultOperation.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [OperationOut.model_validate(row) for row in rows]
