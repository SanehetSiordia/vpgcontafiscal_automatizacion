"""Pasarela interna: autoriza y ejecuta operaciones KV con el token HUMANO.

Por que existe esta pasarela y no una copia del almacen de sesiones
------------------------------------------------------------------
Las sesiones y los tokens de Vault viven **en memoria del unico worker de
user-mgmt**. Copiar ``SessionStore`` a otro contenedor no da acceso a las
sesiones existentes: daria un diccionario vacio en otro proceso. Y la
``api_session`` es un identificador opaco, no un JWT ni un token de Vault: no se
puede "verificar" en otro sitio. De ahi que vault-mgmt no valide sesiones: envia
la operacion tipada aqui y aqui se valida y se ejecuta.

Que se comprueba en CADA ejecucion, en este orden
-------------------------------------------------
1. Credencial interna de servicio, con comparacion en tiempo constante.
2. Bearer humano: sesion viva, token de Vault vigente, empleado activo y roles
   releidos de PostgreSQL. La credencial interna **no** sustituye nada de esto.
3. Catalogo compartido: la coleccion y el registro existen, el estado lo
   permite y el path fisico se deriva del catalogo, nunca del cuerpo.
4. Permisos de aplicacion: admin para escribir, rol lector autorizado para leer.
5. Prueba de MFA reciente para lo irreversible, ligada a sesion, actor,
   operacion y conjunto cerrado de recursos.
6. ACL de Vault: la operacion se ejecuta con el token de la persona. Si su
   politica no cubre el path, Vault responde 403 aunque el rol de aplicacion lo
   permitiera. Vault manda.

Lo que esta pasarela NO hace
----------------------------
* No devuelve el token de Vault ni su accessor.
* No acepta URL, montaje, path, cabecera ni endpoint de Vault del llamante.
* No ejecuta un shell ni habla con el socket de Docker.
* No usa la cuenta tecnica (AppRole) para leer secretos: esa cuenta prepara
  infraestructura, no suplanta permisos humanos.
* No escribe en el catalogo: sus consultas son SELECT.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthenticatedError,
    UpstreamUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.secret_schema import (
    ValuesInvalid,
    apply_merge_patch,
    sensitive_field_names,
    validate_values,
)
from app.core.security import ApiSession, SessionStore
from app.core.vault import (
    VaultError,
    VaultPermissionDenied,
    VaultSealed,
    VaultUnavailable,
    sanitize_vault_message,
)
from app.core.vault_kv import KvCasMismatch, KvV2Client
from app.schemas.internal import (
    ExecuteRequest,
    ExecuteResponse,
    PlainDeliveryOut,
    RecordOutcome,
    WrappedDeliveryOut,
)
from app.services.rbac import ADMIN, Principal

logger = get_logger(__name__)

# Que exige cada operacion. Es la tabla que convierte la allowlist en permisos.
#   admin       : requiere rol de aplicacion 'admin'
#   mfa         : requiere prueba de MFA reciente ligada al objetivo
#   write       : modifica Vault (bloqueada si la coleccion esta archivada)
#   confirm     : exige confirmacion explicita en el cuerpo
_RULES: dict[str, dict[str, Any]] = {
    "record_read": {"admin": False, "mfa": False, "write": False, "confirm": None},
    "record_metadata": {"admin": True, "mfa": False, "write": False, "confirm": None},
    "collection_inventory": {"admin": True, "mfa": False, "write": False, "confirm": None},
    "capabilities": {"admin": False, "mfa": False, "write": False, "confirm": None},
    "record_create": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "record_replace": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "record_patch": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "record_soft_delete": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "versions_delete": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "versions_undelete": {"admin": True, "mfa": False, "write": True, "confirm": None},
    "versions_destroy": {"admin": True, "mfa": True, "write": True, "confirm": "DESTROY"},
    "record_purge": {"admin": True, "mfa": True, "write": True, "confirm": "PURGE"},
    "collection_soft_delete_batch": {
        "admin": True, "mfa": True, "write": True, "confirm": "ARCHIVE",
    },
    "collection_undelete_batch": {
        "admin": True, "mfa": True, "write": True, "confirm": "RESTORE",
    },
    "collection_purge_batch": {
        "admin": True, "mfa": True, "write": True, "confirm": "PURGE",
    },
}


@dataclass(slots=True)
class CatalogCollection:
    collection_id: uuid.UUID
    logical_name: str
    state: str
    current_schema_version: int
    reader_role_codes: tuple[str, ...]
    kv_mount: str
    kv_prefix: str

    @property
    def base_path(self) -> str:
        return f"{self.kv_prefix}/{self.collection_id}"

    def record_path(self, record_id: uuid.UUID) -> str:
        return f"{self.base_path}/{record_id}"


@dataclass(slots=True)
class CatalogRecord:
    record_id: uuid.UUID
    collection_id: uuid.UUID
    state: str
    current_version: int
    schema_version: int


@dataclass(slots=True)
class CatalogSchema:
    schema_version: int
    fields: list[dict[str, Any]]
    json_schema: dict[str, Any]
    sensitive: frozenset[str] = field(default_factory=frozenset)


class VaultGatewayService:
    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        sessions: SessionStore,
        kv_factory: Any,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._sessions = sessions
        # Se inyecta una fabrica y no un cliente para poder sustituirlo en las
        # pruebas sin tocar la red.
        self._kv_factory = kv_factory
        self._kv_cache: dict[str, KvV2Client] = {}

    async def aclose(self) -> None:
        for client in self._kv_cache.values():
            await client.aclose()
        self._kv_cache.clear()

    def _kv(self, mount: str) -> KvV2Client:
        """Un cliente por montaje. El montaje viene del CATALOGO, no del cuerpo."""
        if mount not in self._kv_cache:
            self._kv_cache[mount] = self._kv_factory(mount)
        return self._kv_cache[mount]

    # -- 1. credencial interna ----------------------------------------------

    def verify_internal_credential(self, presented: str | None) -> None:
        """Comparacion en tiempo constante. Sin credencial montada: 503, no 200."""
        expected = self._settings.internal_credential
        if expected is None:
            raise UpstreamUnavailableError(
                "la credencial interna de la pasarela no esta montada; ejecuta "
                "scripts/vault_mgmt/prepare-internal-secret.sh y recrea los "
                "contenedores",
                code="internal_credential_missing",
            )
        if not presented or not secrets.compare_digest(
            presented, expected.get_secret_value()
        ):
            # El mismo mensaje para ausente e incorrecta: no se informa de cual
            # de las dos cosas falla.
            raise UnauthenticatedError(
                "credencial interna de servicio ausente o incorrecta",
                code="internal_credential_invalid",
            )

    # -- 2. catalogo (SOLO LECTURA) -----------------------------------------

    async def _load_collection(
        self, session: AsyncSession, collection_id: uuid.UUID
    ) -> CatalogCollection:
        schema = self._settings.catalog_schema
        row = (
            await session.execute(
                text(
                    f"""
                    SELECT collection_id, logical_name, state,
                           current_schema_version, reader_role_codes,
                           kv_mount, kv_prefix
                      FROM {schema}.secret_collections
                     WHERE collection_id = :collection_id
                    """
                ),
                {"collection_id": collection_id},
            )
        ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(
                "no existe esa coleccion en el catalogo", code="collection_not_found"
            )
        return CatalogCollection(
            collection_id=row["collection_id"],
            logical_name=row["logical_name"],
            state=row["state"],
            current_schema_version=int(row["current_schema_version"]),
            reader_role_codes=tuple(row["reader_role_codes"] or ()),
            kv_mount=row["kv_mount"],
            kv_prefix=row["kv_prefix"],
        )

    async def _load_record(
        self, session: AsyncSession, collection_id: uuid.UUID, record_id: uuid.UUID
    ) -> CatalogRecord:
        schema = self._settings.catalog_schema
        row = (
            await session.execute(
                text(
                    f"""
                    SELECT record_id, collection_id, state, current_version,
                           schema_version
                      FROM {schema}.secret_records
                     WHERE record_id = :record_id
                       AND collection_id = :collection_id
                    """
                ),
                {"record_id": record_id, "collection_id": collection_id},
            )
        ).mappings().one_or_none()
        if row is None:
            # El registro no pertenece a esa coleccion, o no existe. No se
            # distingue: saber que un UUID existe en otra coleccion seria una
            # filtracion del catalogo.
            raise NotFoundError(
                "no existe ese registro en esa coleccion", code="record_not_found"
            )
        return CatalogRecord(
            record_id=row["record_id"],
            collection_id=row["collection_id"],
            state=row["state"],
            current_version=int(row["current_version"]),
            schema_version=int(row["schema_version"]),
        )

    async def _load_schema(
        self, session: AsyncSession, collection_id: uuid.UUID, schema_version: int
    ) -> CatalogSchema:
        schema = self._settings.catalog_schema
        row = (
            await session.execute(
                text(
                    f"""
                    SELECT schema_version, fields, json_schema
                      FROM {schema}.secret_collection_schemas
                     WHERE collection_id = :collection_id
                       AND schema_version = :schema_version
                    """
                ),
                {"collection_id": collection_id, "schema_version": schema_version},
            )
        ).mappings().one_or_none()
        if row is None:
            raise ConflictError(
                f"la coleccion no tiene registrada la version de esquema "
                f"{schema_version}; el catalogo esta incoherente",
                code="schema_version_missing",
            )
        fields = list(row["fields"] or [])
        return CatalogSchema(
            schema_version=int(row["schema_version"]),
            fields=fields,
            json_schema=dict(row["json_schema"] or {}),
            sensitive=sensitive_field_names(fields),
        )

    # -- 3. autorizacion -----------------------------------------------------

    def _authorize(
        self,
        *,
        request: ExecuteRequest,
        principal: Principal,
        collection: CatalogCollection,
    ) -> dict[str, Any]:
        rules = _RULES.get(request.operation)
        if rules is None:  # pragma: no cover - la allowlist ya lo filtra
            raise ForbiddenError(
                "operacion no admitida por la pasarela", code="operation_not_allowed"
            )

        if collection.state == "purged":
            raise ConflictError(
                "la coleccion esta purgada: sus datos se destruyeron y solo "
                "queda su registro de auditoria",
                code="collection_purged",
            )

        if collection.state == "archived" and request.operation not in (
            "collection_undelete_batch",
            "collection_inventory",
            "record_metadata",
        ):
            # Archivada bloquea acceso de la API y entregas futuras. No equivale
            # a revocar lo ya entregado, ni impide a un administrador leer Vault
            # directamente: eso lo decide la ACL de Vault, no esta API.
            raise ConflictError(
                "la coleccion esta archivada: la API no da acceso ni prepara "
                "entregas nuevas. Restaurala antes de operar.",
                code="collection_archived",
            )

        if rules["admin"] and ADMIN not in principal.role_codes:
            raise ForbiddenError(
                f"la operacion '{request.operation}' la ejecuta solo un administrador",
                context={
                    "required_role": ADMIN,
                    "your_roles": sorted(principal.role_codes),
                },
            )

        if not rules["admin"]:
            allowed = set(collection.reader_role_codes)
            if not (principal.role_codes & allowed):
                raise ForbiddenError(
                    "ninguno de tus roles vigentes es lector autorizado de esta "
                    "coleccion",
                    context={
                        "collection_readers": sorted(allowed),
                        "your_roles": sorted(principal.role_codes),
                    },
                )

        expected_confirm = rules["confirm"]
        if expected_confirm and request.confirm != expected_confirm:
            raise ValidationError(
                f"esta operacion es irreversible: envia confirm='{expected_confirm}'",
                code="confirmation_required",
            )

        return rules

    async def _verify_mfa_proof(
        self,
        *,
        request: ExecuteRequest,
        api_session: ApiSession,
        principal: Principal,
        proof_id: str | None,
    ) -> None:
        """Consume la prueba y comprueba que cubre ESTA operacion y ESTOS recursos."""
        if not proof_id:
            raise ForbiddenError(
                "esta operacion exige un MFA reciente: pide una prueba en "
                f"POST {self._settings.api_prefix}/auth/mfa/step-up y envia su "
                f"valor en la cabecera {self._settings.mfa_proof_header}",
                code="mfa_proof_required",
            )

        proof = await self._sessions.consume_proof(proof_id)
        if proof is None:
            raise ForbiddenError(
                "la prueba de MFA no existe, ya se uso o ha caducado; repite la "
                "reautenticacion",
                code="mfa_proof_invalid",
            )

        targets: set[uuid.UUID] = set(request.record_ids)
        if request.record_id is not None:
            targets.add(request.record_id)

        if not proof.covers(
            session_id=api_session.session_id,
            user_id=principal.user_id,
            operation=request.operation,
            collection_id=request.collection_id,
            resource_ids=frozenset(targets),
        ):
            logger.warning(
                "prueba de MFA presentada para otra operacion o otro recurso",
                extra={
                    "operation": "gateway_execute",
                    "actor": principal.username,
                    "requested": request.operation,
                },
            )
            raise ForbiddenError(
                "la prueba de MFA no corresponde a esta operacion, a esta sesion "
                "o a estos recursos. Una prueba autoriza una operacion registrada "
                "sobre un conjunto cerrado de recursos, no acciones ilimitadas.",
                code="mfa_proof_scope_mismatch",
            )

    # -- 4. ejecucion --------------------------------------------------------

    async def execute(
        self,
        *,
        request: ExecuteRequest,
        api_session: ApiSession,
        principal: Principal,
        proof_id: str | None,
    ) -> ExecuteResponse:
        async with self._session_factory() as session:
            collection = await self._load_collection(session, request.collection_id)
            rules = self._authorize(
                request=request, principal=principal, collection=collection
            )

            record: CatalogRecord | None = None
            if request.record_id is not None:
                record = await self._load_record(
                    session, collection.collection_id, request.record_id
                )
            batch: list[CatalogRecord] = []
            if request.record_ids:
                limit = self._settings.max_collection_batch
                if len(request.record_ids) > limit:
                    raise ValidationError(
                        f"el lote supera el tope de {limit} registros por operacion",
                        code="batch_too_large",
                    )
                for record_id in request.record_ids:
                    batch.append(
                        await self._load_record(
                            session, collection.collection_id, record_id
                        )
                    )

            schema_version = (
                record.schema_version if record else collection.current_schema_version
            )
            needs_schema = request.operation in (
                "record_create",
                "record_replace",
                "record_patch",
                "record_read",
            )
            if request.operation == "record_create":
                schema_version = collection.current_schema_version
            catalog_schema = (
                await self._load_schema(session, collection.collection_id, schema_version)
                if needs_schema
                else None
            )
        # La transaccion se cierra ANTES de llamar por red a Vault.

        if rules["mfa"]:
            await self._verify_mfa_proof(
                request=request,
                api_session=api_session,
                principal=principal,
                proof_id=proof_id,
            )

        token = api_session.vault_token
        kv = self._kv(collection.kv_mount)

        try:
            response = await self._dispatch(
                request=request,
                collection=collection,
                record=record,
                batch=batch,
                catalog_schema=catalog_schema,
                kv=kv,
                token=token,
            )
        except VaultPermissionDenied as exc:
            # Vault deniega aunque el rol de aplicacion permitiera: manda Vault.
            logger.info(
                "vault denego la operacion pese al rol de aplicacion",
                extra={
                    "operation": "gateway_execute",
                    "actor": principal.username,
                    "requested": request.operation,
                    "status": 403,
                },
            )
            raise ForbiddenError(
                "Vault denego la operacion con tu token: tu politica no cubre "
                "este recurso. El recurso puede existir: no se concluye su "
                "inexistencia.",
                code="vault_policy_denied",
            ) from exc
        except KvCasMismatch as exc:
            raise ConflictError(exc.message, code="cas_conflict") from exc
        except (VaultSealed, VaultUnavailable) as exc:
            raise UpstreamUnavailableError(
                f"Vault: {sanitize_vault_message(exc.message)}"
            ) from exc
        except VaultError as exc:
            # Se vuelve a sanear aqui aunque el cliente KV ya lo haga: un
            # VaultError construido en otro punto (o por un doble de pruebas)
            # podria traer un token en el texto, y este mensaje sale al cliente.
            raise ConflictError(
                f"Vault rechazo la operacion: {sanitize_vault_message(exc.message)}",
                code="upstream_rejected",
            ) from exc

        response.actor = principal.username
        logger.info(
            "operacion de secretos ejecutada",
            extra={
                "operation": "gateway_execute",
                "actor": principal.username,
                "requested": request.operation,
                "collection": str(request.collection_id),
                "record": str(request.record_id) if request.record_id else None,
                "outcome": response.outcome,
                "operation_id": str(request.operation_id) if request.operation_id else None,
            },
        )
        return response

    async def _dispatch(
        self,
        *,
        request: ExecuteRequest,
        collection: CatalogCollection,
        record: CatalogRecord | None,
        batch: list[CatalogRecord],
        catalog_schema: CatalogSchema | None,
        kv: KvV2Client,
        token: str,
    ) -> ExecuteResponse:
        op = request.operation
        base = {
            "operation": op,
            "collection_id": collection.collection_id,
            "record_id": request.record_id,
        }

        if op == "capabilities":
            paths = [kv.data_path(collection.base_path + "/*")]
            if request.record_id is not None:
                paths = [
                    kv.data_path(collection.record_path(request.record_id)),
                    kv.metadata_path(collection.record_path(request.record_id)),
                ]
            caps = await kv.capabilities(token, paths)
            return ExecuteResponse(
                **base, capabilities={path: list(value) for path, value in caps.items()}
            )

        if op == "collection_inventory":
            children = await kv.list_children(token, collection.base_path)
            return ExecuteResponse(**base, children=children)

        if op == "record_metadata":
            assert record is not None
            metadata = await kv.read_metadata(token, collection.record_path(record.record_id))
            if metadata is None:
                raise NotFoundError(
                    "Vault no tiene metadata para ese registro: pudo purgarse",
                    code="metadata_absent",
                )
            return ExecuteResponse(
                **base,
                version=metadata.current_version,
                schema_version=record.schema_version,
                version_states={k: v for k, v in metadata.version_states().items()},
                metadata={
                    "current_version": metadata.current_version,
                    "oldest_version": metadata.oldest_version,
                    "created_time": metadata.created_time,
                    "updated_time": metadata.updated_time,
                    "max_versions": metadata.max_versions,
                    "cas_required": metadata.cas_required,
                    "delete_version_after": metadata.delete_version_after,
                    # custom_metadata es por CLAVE, no por version: no sirve
                    # para afirmar que esquema tenia una version historica.
                    "custom_metadata": metadata.custom_metadata,
                    "versions": [
                        {
                            "version": item.version,
                            "state": item.state,
                            "created_time": item.created_time,
                            "deletion_time": item.deletion_time,
                            "destroyed": item.destroyed,
                        }
                        for item in metadata.versions
                    ],
                },
            )

        if op == "record_read":
            assert record is not None and catalog_schema is not None
            return await self._read(
                request=request,
                collection=collection,
                record=record,
                catalog_schema=catalog_schema,
                kv=kv,
                token=token,
                base=base,
            )

        if op in ("record_create", "record_replace"):
            assert catalog_schema is not None
            values = dict(request.values or {})
            self._validate(values, catalog_schema)
            path = collection.record_path(request.record_id)  # type: ignore[arg-type]
            envelope = {
                "schema_version": catalog_schema.schema_version,
                "values": values,
            }
            cas = 0 if op == "record_create" else int(request.expected_version or 0)
            version = await kv.write(token, path, envelope, cas=cas)
            return ExecuteResponse(
                **base, version=version, schema_version=catalog_schema.schema_version
            )

        if op == "record_patch":
            assert record is not None and catalog_schema is not None
            path = collection.record_path(record.record_id)
            current = await kv.read_version(token, path)
            if current.state == "absent":
                raise NotFoundError(
                    "no hay una version viva que parchear", code="record_absent"
                )
            if current.state == "soft_deleted":
                raise ConflictError(
                    "la version actual esta borrada (soft-delete): recuperala con "
                    "undelete antes de parchearla",
                    code="record_soft_deleted",
                )
            if current.state == "destroyed":
                raise ConflictError(
                    "la version actual esta destruida: no hay nada que parchear y "
                    "no se puede recuperar",
                    code="record_destroyed",
                )
            stored = current.values or {}
            current_values = dict(stored.get("values") or {})
            merged = apply_merge_patch(current_values, dict(request.patch or {}))
            # Se valida el objeto RESULTANTE COMPLETO. Si el patch deja la tupla
            # invalida (por ejemplo un null sobre un campo obligatorio), se
            # responde 422 y no se escribe nada.
            self._validate(merged, catalog_schema)
            envelope = {
                "schema_version": catalog_schema.schema_version,
                "values": merged,
            }
            version = await kv.write(
                token, path, envelope, cas=int(request.expected_version or 0)
            )
            return ExecuteResponse(
                **base, version=version, schema_version=catalog_schema.schema_version
            )

        if op == "record_soft_delete":
            assert record is not None
            await kv.delete_latest(token, collection.record_path(record.record_id))
            return ExecuteResponse(**base, version=record.current_version)

        if op in ("versions_delete", "versions_undelete", "versions_destroy"):
            assert record is not None
            versions = self._bounded_versions(request.versions)
            path = collection.record_path(record.record_id)
            if op == "versions_delete":
                await kv.delete_versions(token, path, versions)
            elif op == "versions_undelete":
                await kv.undelete_versions(token, path, versions)
            else:
                await kv.destroy_versions(token, path, versions)
            return ExecuteResponse(
                **base, version_states={v: _state_after(op) for v in versions}
            )

        if op == "record_purge":
            assert record is not None
            await kv.delete_metadata(token, collection.record_path(record.record_id))
            return ExecuteResponse(**base)

        if op in (
            "collection_soft_delete_batch",
            "collection_undelete_batch",
            "collection_purge_batch",
        ):
            return await self._batch(
                op=op, collection=collection, batch=batch, kv=kv, token=token, base=base
            )

        raise ForbiddenError(  # pragma: no cover - allowlist exhaustiva
            "operacion no admitida por la pasarela", code="operation_not_allowed"
        )

    # -- lectura y entrega ---------------------------------------------------

    async def _read(
        self,
        *,
        request: ExecuteRequest,
        collection: CatalogCollection,
        record: CatalogRecord,
        catalog_schema: CatalogSchema,
        kv: KvV2Client,
        token: str,
        base: dict[str, Any],
    ) -> ExecuteResponse:
        path = collection.record_path(record.record_id)

        if request.delivery == "wrapped":
            delivery = await kv.read_version_wrapped(
                token,
                path,
                version=request.version,
                wrap_ttl_seconds=request.wrap_ttl_seconds
                or self._settings.wrap_ttl_seconds,
            )
            return ExecuteResponse(
                **base,
                schema_version=record.schema_version,
                delivery=WrappedDeliveryOut(
                    token=delivery.token,
                    ttl_seconds=delivery.ttl_seconds,
                    version=request.version or record.current_version,
                    creation_path=delivery.creation_path,
                ),
            )

        # Entrega plana: solo por eleccion explicita del lector autorizado.
        current = await kv.read_version(token, path, version=request.version)
        if current.state == "absent":
            raise NotFoundError(
                "esa version no existe", code="version_absent",
                context={"requested_version": request.version},
            )
        if current.state == "soft_deleted":
            raise ConflictError(
                "esa version esta borrada (soft-delete): se puede recuperar con "
                "undelete, pero no se entrega su contenido",
                code="version_soft_deleted",
            )
        if current.state == "destroyed":
            raise ConflictError(
                "esa version esta destruida: el contenido no existe y no se "
                "puede recuperar",
                code="version_destroyed",
            )

        stored = current.values or {}
        values = dict(stored.get("values") or {})
        stored_schema = stored.get("schema_version")
        return ExecuteResponse(
            **base,
            version=current.version,
            schema_version=int(stored_schema) if stored_schema else record.schema_version,
            delivery=PlainDeliveryOut(
                version=current.version,
                schema_version=int(stored_schema)
                if stored_schema
                else record.schema_version,
                values=values,
            ),
        )

    # -- lotes ---------------------------------------------------------------

    async def _batch(
        self,
        *,
        op: str,
        collection: CatalogCollection,
        batch: list[CatalogRecord],
        kv: KvV2Client,
        token: str,
        base: dict[str, Any],
    ) -> ExecuteResponse:
        """Procesa el conjunto CERRADO y reporta cada registro por separado.

        Un fallo a mitad no se oculta: la respuesta es ``partial`` y vault-mgmt
        la traduce a 409 con el ``operation_id``. No hay transaccion distribuida
        y no se finge que la haya.
        """
        results: list[RecordOutcome] = []
        failures = 0
        for record in batch:
            path = collection.record_path(record.record_id)
            try:
                if op == "collection_soft_delete_batch":
                    await kv.delete_latest(token, path)
                elif op == "collection_undelete_batch":
                    metadata = await kv.read_metadata(token, path)
                    if metadata is None:
                        results.append(
                            RecordOutcome(
                                record_id=record.record_id,
                                status="skipped",
                                detail="sin metadata en Vault: nada que recuperar",
                            )
                        )
                        continue
                    recoverable = [
                        item.version
                        for item in metadata.versions
                        if item.state == "soft_deleted"
                    ]
                    if not recoverable:
                        results.append(
                            RecordOutcome(
                                record_id=record.record_id,
                                status="skipped",
                                detail=(
                                    "no hay versiones recuperables; una version "
                                    "destruida no vuelve"
                                ),
                            )
                        )
                        continue
                    await kv.undelete_versions(token, path, recoverable)
                else:
                    await kv.delete_metadata(token, path)
                results.append(
                    RecordOutcome(record_id=record.record_id, status="ok")
                )
            except (VaultError, KvCasMismatch) as exc:
                failures += 1
                results.append(
                    RecordOutcome(
                        record_id=record.record_id,
                        status="failed",
                        detail=sanitize_vault_message(
                            getattr(exc, "message", str(exc)), limit=200
                        ),
                    )
                )

        return ExecuteResponse(
            **base,
            outcome="partial" if failures else "completed",
            results=results,
        )

    # -- utilidades ----------------------------------------------------------

    def _validate(self, values: dict[str, Any], catalog_schema: CatalogSchema) -> None:
        try:
            validate_values(
                values,
                catalog_schema.json_schema,
                fields=catalog_schema.fields,
                max_record_bytes=None,
            )
        except ValuesInvalid as exc:
            # Se devuelven campo y motivo, nunca el valor: puede ser el secreto.
            raise ValidationError(
                "el objeto completo no supera el esquema de la coleccion",
                context={"fields": [p.as_dict() for p in exc.problems]},
            ) from exc

    def _bounded_versions(self, versions: list[int]) -> list[int]:
        unique = sorted(set(versions))
        limit = self._settings.max_versions_per_request
        if len(unique) > limit:
            raise ValidationError(
                f"como maximo {limit} versiones por operacion",
                code="too_many_versions",
            )
        return unique


def _state_after(op: str) -> str:
    return {
        "versions_delete": "soft_deleted",
        "versions_undelete": "active",
        "versions_destroy": "destroyed",
    }[op]


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["CatalogCollection", "CatalogRecord", "CatalogSchema", "VaultGatewayService"]
