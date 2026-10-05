"""Fixtures de la etapa 4.

Tres decisiones que conviene leer antes de interpretar los resultados:

* **PostgreSQL es real**, en ``vpg_contadores_test``, con los esquemas
  ``employees`` y ``vault_mgmt`` y **los mismos permisos DML que en
  produccion**. Las restricciones que se comprueban (indices parciales con
  ``COALESCE``, CHECK con regex y con operadores de array, FK compuesta con
  ``RESTRICT``) solo existen en PostgreSQL.

* **La pasarela interna es REAL y corre en el proceso de pruebas.** La app de
  user-mgmt se monta de verdad y el cliente de vault-mgmt le habla por
  ``ASGITransport``. Asi se ejercita lo que de verdad importa: credencial
  interna, Bearer humano obligatorio, roles releidos de PostgreSQL, pruebas de
  MFA ligadas a operacion y recurso, y traduccion de errores entre los dos
  servicios. No es un mock de la autorizacion: es la autorizacion.

* **Vault es un doble explicito** (``FakeKv`` y ``FakeVault``). Reproduce lo que
  importa de KV v2: CAS, soft-delete, undelete, destroy, metadata nativa,
  distincion entre ausente / borrado / destruido, y response wrapping de un
  solo uso. Lo que NO se demuestra con esto, y queda como comprobacion manual
  documentada en el README: una instancia de Vault real, un codigo TOTP de
  verdad y el comportamiento exacto de las politicas HCL.

**Sobre la limpieza entre pruebas.** La cuenta de ejecucion ``vpg_app`` no tiene
DELETE sobre ``secret_audit``, ``secret_operations`` ni ``secret_collections``,
ni UPDATE/DELETE sobre ``secret_collection_schemas``: la migracion 003 se lo
revoca a proposito. Por eso las pruebas **no** vacian esas tablas: cada una usa
nombres y UUID propios y filtra por ellos. Que no se pueda limpiar es, de hecho,
una de las cosas que se comprueban. Para empezar de cero:
``bash scripts/vault_mgmt/prepare-test-db.sh --recreate``.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

# La configuracion se fija ANTES de importar los modulos: get_settings() cachea.
os.environ.setdefault("VAULT_MGMT_POSTGRES_DB", "vpg_contadores_test")
os.environ.setdefault("VAULT_MGMT_ENVIRONMENT", "ci")
os.environ.setdefault("VAULT_MGMT_LOG_LEVEL", "warning")
os.environ.setdefault("VAULT_MGMT_RATE_LIMIT_SESSION_PER_MINUTE", "2000")
os.environ.setdefault("VAULT_MGMT_RATE_LIMIT_GLOBAL_PER_MINUTE", "5000")
os.environ.setdefault("VAULT_MGMT_RATE_LIMIT_CONSUMER_PER_MINUTE", "2000")
os.environ.setdefault("USER_MGMT_RATE_LIMIT_SESSION_PER_MINUTE", "2000")
os.environ.setdefault("USER_MGMT_RATE_LIMIT_GLOBAL_PER_MINUTE", "5000")

from app.core.config import get_settings as get_user_mgmt_settings  # noqa: E402
from app.core.rate_limit import SlidingWindowLimiter  # noqa: E402
from app.core.readiness import (  # noqa: E402
    AdminAnchor,
    ReadinessReport as UserReadinessReport,
    ReadinessState as UserReadinessState,
)
from app.core.security import SessionStore  # noqa: E402
from app.core.vault import (  # noqa: E402
    VaultError,
    VaultNotFound,
    VaultPermissionDenied,
)
from app.core.vault_kv import KvCasMismatch, KvMetadata, KvVersion, WrappedDelivery  # noqa: E402
from app.main import create_app as create_user_mgmt_app  # noqa: E402
from app.services.auth import AuthService  # noqa: E402
from app.services.vault_gateway import VaultGatewayService  # noqa: E402
from app.services.vault_sync import VaultSyncService  # noqa: E402
from app.vault_mgmt.core.config import get_settings as get_vault_mgmt_settings  # noqa: E402
from app.vault_mgmt.core.database import (  # noqa: E402
    dispose_engine as dispose_vm_engine,
    get_session_factory as get_vm_session_factory,
    init_engine as init_vm_engine,
)
from app.vault_mgmt.core.gateway_client import GatewayClient  # noqa: E402
from app.vault_mgmt.core.machine_auth import MachineAuthError  # noqa: E402
from app.vault_mgmt.core.readiness import ReadinessReport, ReadinessState  # noqa: E402
from app.vault_mgmt.main import create_app as create_vault_mgmt_app  # noqa: E402
from app.vault_mgmt.services.access import AccessService  # noqa: E402
from app.vault_mgmt.services.catalog import CatalogService  # noqa: E402
from app.vault_mgmt.services.consumers import ConsumerService  # noqa: E402
from app.vault_mgmt.services.lifecycle import LifecycleService  # noqa: E402
from app.vault_mgmt.services.records import RecordService  # noqa: E402
from tests.conftest import TEST_ACCESSOR, TEST_ENFORCEMENT, TEST_METHOD_ID  # noqa: E402

INTERNAL_CREDENTIAL = "credencial-interna-solo-para-pruebas"


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


# ---------------------------------------------------------------------------
# Doble de Vault KV v2
# ---------------------------------------------------------------------------


class FakeKv:
    """Doble de ``KvV2Client`` con el mismo contrato publico.

    Reproduce el comportamiento de KV v2 que el codigo depende de:

    * ``cas=0`` solo crea si la clave no tiene ninguna version. Despues de un
      soft-delete la clave SIGUE existiendo, asi que ``cas=0`` falla: es la
      razon por la que recrear un registro borrado no "funciona por accidente".
    * ``cas=N`` exige que la version actual sea exactamente N.
    * una version con soft-delete responde como 404 CON metadata, no como
      ausencia; una destruida, como destruida. Son tres estados distintos.
    * ``destroy`` y el borrado de metadata son irreversibles.
    * el response wrapping entrega un token de **un solo uso**.
    """

    def __init__(self, mount: str = "secret") -> None:
        self._mount = mount
        # path -> {"versions": {n: {...}}, "current": n, "oldest": n}
        self.store: dict[str, dict[str, Any]] = {}
        self.wrap_tokens: dict[str, dict[str, Any]] = {}
        # Paths (logicos) que Vault denegara aunque el rol de aplicacion permita.
        self.denied_paths: set[str] = set()
        # Capacidades que devuelve sys/capabilities-self.
        self.capability_map: dict[str, tuple[str, ...]] = {}
        self.default_capabilities: tuple[str, ...] = ("read",)
        self.fail_next: Exception | None = None
        self.writes: list[tuple[str, int]] = []

    # -- utilidades de las pruebas ------------------------------------------

    @property
    def mount(self) -> str:
        return self._mount

    def data_path(self, logical_path: str) -> str:
        return f"{self._mount}/data/{logical_path.strip('/')}"

    def metadata_path(self, logical_path: str) -> str:
        return f"{self._mount}/metadata/{logical_path.strip('/')}"

    async def aclose(self) -> None:
        return None

    def _guard(self, logical_path: str) -> None:
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error
        if logical_path in self.denied_paths:
            raise VaultPermissionDenied(
                f"Vault denego el acceso a {logical_path}: permission denied",
                status_code=403,
            )

    def _entry(self, logical_path: str) -> dict[str, Any] | None:
        return self.store.get(logical_path.strip("/"))

    # -- lectura -------------------------------------------------------------

    async def read_version(
        self, token: str, logical_path: str, *, version: int | None = None
    ) -> KvVersion:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            return KvVersion(version=version or 0, state="absent")
        wanted = version or entry["current"]
        meta = entry["versions"].get(wanted)
        if meta is None:
            return KvVersion(version=wanted, state="absent")
        if meta["destroyed"]:
            return KvVersion(version=wanted, state="destroyed", destroyed=True)
        if meta["deletion_time"]:
            return KvVersion(
                version=wanted,
                state="soft_deleted",
                deletion_time=meta["deletion_time"],
            )
        return KvVersion(
            version=wanted,
            state="active",
            created_time=meta["created_time"],
            values=dict(meta["data"]),
        )

    async def read_version_wrapped(
        self,
        token: str,
        logical_path: str,
        *,
        version: int | None,
        wrap_ttl_seconds: int,
    ) -> WrappedDelivery:
        current = await self.read_version(token, logical_path, version=version)
        if current.state != "active":
            raise VaultError(
                f"no hay una version viva que envolver ({current.state})",
                status_code=404,
            )
        wrap_token = f"hvs.fake-{uuid.uuid4().hex}"
        self.wrap_tokens[wrap_token] = {
            "data": {
                "data": current.values,
                "metadata": {"version": current.version},
            },
            "uses": 0,
            "path": self.data_path(logical_path),
        }
        return WrappedDelivery(
            token=wrap_token,
            ttl_seconds=wrap_ttl_seconds,
            creation_time=_now_iso(),
            creation_path=self.data_path(logical_path),
        )

    async def read_metadata(self, token: str, logical_path: str) -> KvMetadata | None:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            return None
        versions = []
        for number, meta in sorted(entry["versions"].items()):
            if meta["destroyed"]:
                state = "destroyed"
            elif meta["deletion_time"]:
                state = "soft_deleted"
            else:
                state = "active"
            versions.append(
                KvVersion(
                    version=number,
                    state=state,  # type: ignore[arg-type]
                    created_time=meta["created_time"],
                    deletion_time=meta["deletion_time"] or None,
                    destroyed=meta["destroyed"],
                )
            )
        return KvMetadata(
            current_version=entry["current"],
            oldest_version=entry["oldest"],
            created_time=entry.get("created_time"),
            updated_time=entry.get("updated_time"),
            max_versions=0,
            cas_required=True,
            delete_version_after=None,
            # custom_metadata es por CLAVE: el doble lo deja vacio a proposito,
            # porque el codigo no debe apoyarse en el para nada.
            custom_metadata={},
            versions=versions,
        )

    async def list_children(self, token: str, logical_prefix: str) -> list[str]:
        prefix = logical_prefix.strip("/") + "/"
        children: set[str] = set()
        for path in self.store:
            if path.startswith(prefix):
                rest = path[len(prefix) :]
                children.add(rest.split("/", 1)[0])
        return sorted(children)

    # -- escritura -----------------------------------------------------------

    async def write(
        self, token: str, logical_path: str, values: dict[str, Any], *, cas: int
    ) -> int:
        self._guard(logical_path)
        key = logical_path.strip("/")
        entry = self.store.get(key)
        current = entry["current"] if entry else 0
        if cas != current:
            raise KvCasMismatch(
                "la version esperada no coincide con la actual: otra escritura "
                "gano la carrera y no se ha sobrescrito nada.",
                current_version=current,
            )
        version = current + 1
        if entry is None:
            entry = {"versions": {}, "current": 0, "oldest": version,
                     "created_time": _now_iso()}
            self.store[key] = entry
        entry["versions"][version] = {
            "data": dict(values),
            "deletion_time": "",
            "destroyed": False,
            "created_time": _now_iso(),
        }
        entry["current"] = version
        entry["updated_time"] = _now_iso()
        self.writes.append((key, version))
        return version

    async def delete_latest(self, token: str, logical_path: str) -> None:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            raise VaultNotFound("no existe ese secreto en Vault", status_code=404)
        meta = entry["versions"].get(entry["current"])
        if meta and not meta["destroyed"]:
            meta["deletion_time"] = _now_iso()

    async def delete_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            return
        for number in versions:
            meta = entry["versions"].get(number)
            if meta and not meta["destroyed"]:
                meta["deletion_time"] = _now_iso()

    async def undelete_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            return
        for number in versions:
            meta = entry["versions"].get(number)
            # Una version destruida NO vuelve. Vault no falla: simplemente no
            # la recupera, y el doble hace lo mismo.
            if meta and not meta["destroyed"]:
                meta["deletion_time"] = ""

    async def destroy_versions(
        self, token: str, logical_path: str, versions: list[int]
    ) -> None:
        self._guard(logical_path)
        entry = self._entry(logical_path)
        if entry is None:
            return
        for number in versions:
            meta = entry["versions"].get(number)
            if meta:
                meta["destroyed"] = True
                meta["data"] = {}

    async def delete_metadata(self, token: str, logical_path: str) -> None:
        self._guard(logical_path)
        self.store.pop(logical_path.strip("/"), None)

    # -- capacidades y envoltura --------------------------------------------

    async def capabilities(
        self, token: str, paths: list[str]
    ) -> dict[str, tuple[str, ...]]:
        return {
            path: self.capability_map.get(path, self.default_capabilities)
            for path in paths
        }

    async def unwrap(self, wrapping_token: str) -> dict[str, Any]:
        record = self.wrap_tokens.get(wrapping_token)
        if record is None:
            raise VaultError("wrapping token invalido o ya consumido", status_code=400)
        if record["uses"] >= 1:
            # Un solo uso: el segundo intento falla, como en Vault.
            del self.wrap_tokens[wrapping_token]
            raise VaultError("wrapping token ya consumido", status_code=400)
        record["uses"] += 1
        return dict(record["data"])


# ---------------------------------------------------------------------------
# Doble de la sonda de Vault para la autenticacion de maquina
# ---------------------------------------------------------------------------


class FakeProbe:
    """Doble de ``VaultProbe``: salud y ``lookup-self`` de un token ajeno."""

    def __init__(self) -> None:
        self.tokens: dict[str, dict[str, Any]] = {}
        self.sealed = False

    async def aclose(self) -> None:
        return None

    async def health(self) -> Any:
        from app.vault_mgmt.core.machine_auth import VaultHealth

        return VaultHealth(initialized=True, sealed=self.sealed, standby=False)

    async def lookup_self(self, token: str) -> dict[str, Any]:
        data = self.tokens.get(token)
        if data is None:
            raise MachineAuthError(
                "el token presentado no es valido en Vault", status_code=401
            )
        return dict(data)

    def register_machine(
        self,
        token: str,
        *,
        mount: str,
        role_name: str,
        policies: tuple[str, ...],
        ttl: int = 1200,
    ) -> None:
        self.tokens[token] = {
            "accessor": f"acc-{uuid.uuid4().hex[:8]}",
            "path": f"auth/{mount}/login",
            "meta": {"role_name": role_name},
            "policies": list(policies),
            "display_name": f"approle-{role_name}",
            "ttl": ttl,
            "renewable": True,
        }


# ---------------------------------------------------------------------------
# Motor de base de datos de vault-mgmt
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def vm_engine():
    settings = get_vault_mgmt_settings()
    init_vm_engine(settings)
    yield
    await dispose_vm_engine()


@pytest.fixture
def kv() -> FakeKv:
    return FakeKv(mount=get_vault_mgmt_settings().kv_mount)


@pytest.fixture
def probe() -> FakeProbe:
    return FakeProbe()


@pytest_asyncio.fixture
async def apps(vm_engine, kv, probe, vault, seeded):
    """Las dos apps conectadas: vault-mgmt -> pasarela real de user-mgmt.

    El doble de KV es el MISMO objeto en los dos lados: la pasarela lo usa para
    ejecutar las operaciones humanas y el servicio de consumidores para las
    entregas de maquina. Si fueran dos, una prueba de extremo a extremo no
    probaria nada.
    """
    settings = get_vault_mgmt_settings()
    settings.__dict__["internal_credential"] = SecretStr(INTERNAL_CREDENTIAL)

    # user-mgmt, montado a mano (sin lifespan).
    um_app = await _build_user_mgmt(vault, seeded, kv)

    um_client = AsyncClient(
        transport=ASGITransport(app=um_app), base_url="http://user-mgmt-service"
    )
    gateway = GatewayClient(settings, client=um_client)

    vm_app = create_vault_mgmt_app()
    factory = get_vm_session_factory()

    vm_app.state.settings = settings
    vm_app.state.session_factory = factory
    vm_app.state.probe = probe
    vm_app.state.gateway = gateway
    vm_app.state.limiter = SlidingWindowLimiter()
    vm_app.state.catalog_service = CatalogService(
        settings=settings, session_factory=factory
    )
    vm_app.state.record_service = RecordService(
        settings=settings, session_factory=factory, gateway=gateway
    )
    vm_app.state.lifecycle_service = LifecycleService(
        settings=settings, session_factory=factory, gateway=gateway
    )
    vm_app.state.access_service = AccessService(
        settings=settings, session_factory=factory, gateway=gateway
    )
    vm_app.state.consumer_service = ConsumerService(
        settings=settings,
        session_factory=factory,
        probe=probe,
        kv_factory=lambda mount: kv,
    )

    readiness = ReadinessState(settings)
    readiness._report = ReadinessReport(  # noqa: SLF001
        database=True,
        catalog_schema=True,
        vault_initialized=True,
        vault_unsealed=True,
        user_mgmt_ready=True,
        gateway_authenticated=True,
    )
    vm_app.state.readiness = readiness

    try:
        yield {"user_mgmt": um_app, "vault_mgmt": vm_app, "kv": kv, "probe": probe}
    finally:
        await um_client.aclose()


async def _build_user_mgmt(vault, seeded, kv_double):
    settings = get_user_mgmt_settings()
    settings.__dict__["internal_credential"] = SecretStr(INTERNAL_CREDENTIAL)

    application = create_user_mgmt_app()
    from app.core.database import get_session_factory as get_um_session_factory

    factory = get_um_session_factory()

    application.state.settings = settings
    application.state.session_factory = factory
    application.state.vault = vault
    application.state.sessions = SessionStore(
        session_ttl_seconds=settings.session_ttl_seconds,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        max_sessions=settings.max_sessions,
        max_challenges=settings.max_challenges,
        mfa_proof_ttl_seconds=settings.mfa_proof_ttl_seconds,
        max_mfa_proofs=settings.max_mfa_proofs,
    )
    application.state.limiter = SlidingWindowLimiter()
    application.state.auth_service = AuthService(
        vault=vault,
        sessions=application.state.sessions,
        session_factory=factory,
        mfa_method_name=settings.vault_mfa_method_name,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
    )
    application.state.vault_sync = VaultSyncService(
        vault=vault, settings=settings, session_factory=factory
    )
    application.state.vault_gateway = VaultGatewayService(
        settings=settings,
        session_factory=factory,
        sessions=application.state.sessions,
        kv_factory=lambda mount: kv_double,
    )

    readiness = UserReadinessState(settings)
    readiness._report = UserReadinessReport(  # noqa: SLF001
        database=True,
        vault_initialized=True,
        vault_unsealed=True,
        vault_technical_credential=True,
        admin_linked=True,
    )
    await readiness.set_anchor(
        AdminAnchor(
            user_id=seeded["admin"]["id"],
            username=seeded["admin"]["username"],
            vault_username=seeded["admin"]["username"],
            entity_id=uuid.UUID(seeded["admin"]["entity_id"]),
            userpass_path="userpass",
            userpass_accessor=TEST_ACCESSOR,
            totp_method_id=uuid.UUID(TEST_METHOD_ID),
            mfa_enforcement_name=TEST_ENFORCEMENT,
            totp_status="pending",
        )
    )
    application.state.readiness = readiness
    return application


@pytest_asyncio.fixture
async def vm_client(apps) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=apps["vault_mgmt"]),
        base_url="http://vault-mgmt-test",
    ) as http:
        yield http


@pytest_asyncio.fixture
async def um_client(apps) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=apps["user_mgmt"]),
        base_url="http://user-mgmt-test",
    ) as http:
        yield http


@pytest.fixture
def vm_api() -> str:
    return get_vault_mgmt_settings().api_prefix


@pytest.fixture
def um_api() -> str:
    return get_user_mgmt_settings().api_prefix


# ---------------------------------------------------------------------------
# Ayudas de sesion y de datos
# ---------------------------------------------------------------------------


async def login(client: AsyncClient, prefix: str, username: str) -> str:
    """Login completo (contrasena + TOTP) contra el doble. Devuelve la sesion."""
    from tests.conftest import GOOD_TOTP

    response = await client.post(
        f"{prefix}/auth/login",
        json={"username": username, "password": "contrasena-de-prueba"},
    )
    assert response.status_code == 200, response.text
    challenge = response.json()["challenge_id"]
    response = await client.post(
        f"{prefix}/auth/mfa/verify",
        json={"challenge_id": challenge, "code": GOOD_TOTP},
    )
    assert response.status_code == 200, response.text
    return response.json()["api_session"]


async def step_up(
    client: AsyncClient,
    prefix: str,
    session_id: str,
    *,
    operation: str,
    collection_id: str | None,
    resource_ids: list[str],
) -> str:
    """Reautenticacion completa. Devuelve la prueba breve de MFA."""
    from tests.conftest import GOOD_TOTP

    response = await client.post(
        f"{prefix}/auth/mfa/step-up",
        headers=auth(session_id),
        json={
            "password": "contrasena-de-prueba",
            "operation": operation,
            "collection_id": collection_id,
            "resource_ids": resource_ids,
        },
    )
    assert response.status_code == 200, response.text
    challenge = response.json()["challenge_id"]
    response = await client.post(
        f"{prefix}/auth/mfa/step-up/verify",
        headers=auth(session_id),
        json={"challenge_id": challenge, "code": GOOD_TOTP},
    )
    assert response.status_code == 200, response.text
    return response.json()["mfa_proof"]


def auth(session_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {session_id}"}


def unique_name(prefix: str = "test") -> str:
    """Nombre logico unico por prueba.

    Las pruebas no vacian el catalogo (la cuenta de ejecucion no puede borrar
    auditoria ni esquemas, por diseno), asi que cada una se mueve en su propio
    espacio de nombres y filtra por el.
    """
    return f"{prefix}/{uuid.uuid4().hex[:12]}"


SIMPLE_FIELDS = [
    {"name": "usuario", "type": "string", "required": True, "max_length": 64},
    {
        "name": "password",
        "type": "string",
        "required": True,
        "sensitive": True,
        "max_length": 256,
    },
    {"name": "rfc", "type": "string", "required": False, "max_length": 13},
]


@pytest_asyncio.fixture
async def admin_session(um_client, um_api) -> str:
    return await login(um_client, um_api, "ada.admin")


@pytest_asyncio.fixture
async def manager_session(um_client, um_api) -> str:
    return await login(um_client, um_api, "max.manager")


@pytest_asyncio.fixture
async def employee_session(um_client, um_api) -> str:
    return await login(um_client, um_api, "eva.employee")


async def create_collection(
    vm_client: AsyncClient,
    vm_api: str,
    session_id: str,
    *,
    logical_name: str | None = None,
    readers: list[str] | None = None,
    fields: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    response = await vm_client.post(
        f"{vm_api}/vault/collections",
        headers=auth(session_id),
        json={
            "logical_name": logical_name or unique_name("sat"),
            "description": "coleccion de prueba con datos ficticios",
            "reader_role_codes": readers or ["admin"],
            "fields": fields or SIMPLE_FIELDS,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def create_record(
    vm_client: AsyncClient,
    vm_api: str,
    session_id: str,
    collection_id: str,
    *,
    values: dict[str, Any] | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    response = await vm_client.post(
        f"{vm_api}/vault/collections/{collection_id}/records",
        headers=auth(session_id),
        json={
            "label": label,
            "values": values or {"usuario": "demo", "password": "valor-ficticio"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()
