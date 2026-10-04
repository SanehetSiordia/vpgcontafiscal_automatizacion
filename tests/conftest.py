"""Fixtures de las pruebas.

Dos decisiones importantes:

* **PostgreSQL real**, en una base aparte (``vpg_contadores_test``) con el mismo
  esquema. Las pruebas comprueban restricciones que solo existen en PostgreSQL
  (indices unicos sobre expresiones, indices parciales, CHECK con regex,
  ``ON DELETE RESTRICT``); con SQLite "pasarian" sin demostrar nada.

* **Doble controlado de Vault**, no la instancia real. Asi las pruebas no
  dependen de un codigo TOTP ni pueden destruir la semilla del administrador de
  verdad. El login con MFA **real** es una comprobacion manual, documentada en
  el README: no se deduce de estos dobles.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

# La configuracion se fija ANTES de importar la app: get_settings() cachea.
os.environ.setdefault("USER_MGMT_POSTGRES_DB", "vpg_contadores_test")
os.environ.setdefault("USER_MGMT_ENVIRONMENT", "ci")
os.environ.setdefault("USER_MGMT_LOG_LEVEL", "warning")
os.environ.setdefault("USER_MGMT_RATE_LIMIT_LOGIN_PER_MINUTE", "5")
os.environ.setdefault("USER_MGMT_RATE_LIMIT_SESSION_PER_MINUTE", "1000")

from app.core.config import get_settings  # noqa: E402
from app.core.database import dispose_engine, get_session_factory, init_engine  # noqa: E402
from app.core.rate_limit import SlidingWindowLimiter  # noqa: E402
from app.core.readiness import AdminAnchor, ReadinessReport, ReadinessState  # noqa: E402
from app.core.security import SessionStore  # noqa: E402
from app.core.vault import (  # noqa: E402
    MFAChallenge,
    VaultError,
    VaultHealth,
    VaultMFAFailed,
    VaultNotFound,
    VaultSession,
)
from app.main import create_app  # noqa: E402
from app.models.employees import Role, User, UserProfile, UserRole, UserVaultIdentity  # noqa: E402
from app.models.employees import VaultAuthConfig  # noqa: E402
from app.services.auth import AuthService  # noqa: E402
from app.services.vault_sync import VaultSyncService  # noqa: E402

TEST_ACCESSOR = "auth_userpass_testacc"
TEST_METHOD_ID = "11111111-1111-4111-8111-111111111111"
TEST_ENFORCEMENT = "vpg-userpass-totp"
GOOD_TOTP = "123456"


class FakeVault:
    """Doble de ``VaultClient`` con el mismo contrato publico.

    Reproduce el comportamiento que importa: el login con contrasena **no**
    entrega token, hace falta validar el TOTP, y las operaciones de identidad
    fallan como falla Vault (409 si la cuenta existe, 403 si falta permiso).
    """

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.entities: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = {}       # alias_name -> entity_id
        self.totp_secrets: set[str] = set()      # entity_ids con semilla
        self.tokens: dict[str, dict[str, Any]] = {}
        self.revoked: list[str] = []
        self.sealed = False
        self.available = True
        self.fail_next: Exception | None = None
        self.capabilities: tuple[str, ...] = ("read",)
        self.read_result = "autorizada"
        self.challenges: dict[str, str] = {}     # request_id -> username

    # -- salud y credencial tecnica -----------------------------------------

    async def health(self) -> VaultHealth:
        return VaultHealth(initialized=True, sealed=self.sealed, standby=False)

    async def technical_token(self) -> str:
        return "fake-technical-token"

    async def check_technical_credentials(self) -> tuple[str, ...]:
        return ("default", "vpg-user-mgmt")

    async def aclose(self) -> None:
        return None

    def _guard(self) -> None:
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error

    # -- login ---------------------------------------------------------------

    async def userpass_login(self, username: str, password: str) -> MFAChallenge:
        from app.core.vault import VaultInvalidCredentials

        record = self.users.get(username)
        if record is None or record["password"] != password:
            raise VaultInvalidCredentials("usuario o contrasena incorrectos")
        request_id = uuid.uuid4().hex
        self.challenges[request_id] = username
        # Igual que Vault con el enforcement activo: ningun token todavia.
        return MFAChallenge(
            mfa_request_id=request_id,
            method_ids=(TEST_METHOD_ID,),
            enforcement_names=(TEST_ENFORCEMENT,),
            token_issued_without_mfa=False,
        )

    async def mfa_validate(
        self, mfa_request_id: str, method_id: str, passcode: str
    ) -> VaultSession:
        username = self.challenges.pop(mfa_request_id, None)
        if username is None:
            raise VaultMFAFailed("el desafio MFA caduco; repite el login")
        if passcode != GOOD_TOTP:
            raise VaultMFAFailed("codigo TOTP incorrecto")
        entity_id = self.aliases.get(username, "")
        token = f"fake-token-{uuid.uuid4().hex}"
        self.tokens[token] = {"entity_id": entity_id, "username": username}
        return VaultSession(
            client_token=token,
            accessor=f"acc-{uuid.uuid4().hex[:8]}",
            entity_id=entity_id,
            policies=("default", "vpg-oidc-user"),
            display_name=f"userpass-{username}",
            lease_duration=3600,
        )

    async def lookup_self(self, token: str) -> dict[str, Any]:
        if token not in self.tokens:
            raise VaultError("token invalido")
        return dict(self.tokens[token])

    async def revoke_self(self, token: str) -> bool:
        if token in self.tokens:
            del self.tokens[token]
            self.revoked.append(token)
            return True
        return False

    async def capabilities_self(self, token: str, path: str) -> tuple[str, ...]:
        return self.capabilities

    async def can_read_path(self, token: str, path: str) -> str:
        return self.read_result

    # -- configuracion -------------------------------------------------------

    async def userpass_accessor(self, token: str | None = None) -> str:
        self._guard()
        return TEST_ACCESSOR

    async def totp_method_id(self, token: str | None = None) -> str:
        self._guard()
        return TEST_METHOD_ID

    async def mfa_enforcement(self, token: str | None = None) -> dict[str, Any]:
        return {
            "auth_method_accessors": [TEST_ACCESSOR],
            "mfa_method_ids": [TEST_METHOD_ID],
            "identity_entity_ids": [],
            "identity_group_ids": [],
        }

    # -- cuentas y entidades --------------------------------------------------

    async def userpass_user_exists(self, username: str) -> bool:
        return username in self.users

    async def create_userpass_user(
        self, username: str, password: str, policies: list[str]
    ) -> None:
        self._guard()
        self.users[username] = {"password": password, "policies": list(policies)}

    async def set_userpass_password(self, username: str, password: str) -> None:
        self._guard()
        if username not in self.users:
            raise VaultNotFound("no existe esa cuenta")
        self.users[username]["password"] = password

    async def set_userpass_policies(self, username: str, policies: list[str]) -> None:
        self.users[username]["policies"] = list(policies)

    async def delete_userpass_user(self, username: str) -> None:
        self.users.pop(username, None)

    async def lookup_entity_by_alias(self, alias_name: str, accessor: str) -> str | None:
        self._guard()
        return self.aliases.get(alias_name)

    async def create_entity(self, name: str, metadata: dict[str, str]) -> str:
        self._guard()
        entity_id = str(uuid.uuid4())
        self.entities[entity_id] = {"name": name, "aliases": [], "disabled": False}
        return entity_id

    async def read_entity(self, entity_id: str) -> dict[str, Any]:
        if entity_id not in self.entities:
            raise VaultNotFound("no existe esa entidad")
        return self.entities[entity_id]

    async def create_entity_alias(
        self, alias_name: str, entity_id: str, accessor: str
    ) -> str:
        alias_id = str(uuid.uuid4())
        self.entities[entity_id]["aliases"].append(
            {"id": alias_id, "name": alias_name, "mount_accessor": accessor}
        )
        self.aliases[alias_name] = entity_id
        return alias_id

    async def update_entity_alias(
        self, alias_id: str, alias_name: str, entity_id: str, accessor: str
    ) -> None:
        for alias in self.entities[entity_id]["aliases"]:
            if alias["id"] == alias_id:
                self.aliases.pop(alias["name"], None)
                alias["name"] = alias_name
                self.aliases[alias_name] = entity_id

    async def set_entity_disabled(self, entity_id: str, disabled: bool) -> None:
        self._guard()
        if entity_id not in self.entities:
            raise VaultNotFound("no existe esa entidad")
        self.entities[entity_id]["disabled"] = disabled

    async def delete_entity(self, entity_id: str) -> None:
        entity = self.entities.pop(entity_id, None)
        if entity:
            for alias in entity["aliases"]:
                self.aliases.pop(alias["name"], None)
        self.totp_secrets.discard(entity_id)

    async def delete_entity_alias(self, alias_id: str) -> None:
        for entity in self.entities.values():
            entity["aliases"] = [a for a in entity["aliases"] if a["id"] != alias_id]

    # -- TOTP ------------------------------------------------------------------

    async def generate_totp(self, method_id: str, entity_id: str) -> str:
        self._guard()
        if entity_id in self.totp_secrets:
            raise VaultError("la entidad ya tiene semilla TOTP")
        self.totp_secrets.add(entity_id)
        return f"otpauth://totp/VPG%20Vault:{entity_id}?secret=FAKESEED&issuer=VPG"

    async def destroy_totp(self, method_id: str, entity_id: str) -> None:
        self._guard()
        self.totp_secrets.discard(entity_id)

    async def revoke_accessor(self, accessor: str) -> bool:
        return True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest_asyncio.fixture
async def engine():
    settings = get_settings()
    init_engine(settings)
    yield
    await dispose_engine()


@pytest_asyncio.fixture
async def clean_db(engine) -> AsyncIterator[None]:
    """Vacia el esquema antes de cada prueba, respetando las FK.

    Con DELETE y no TRUNCATE a proposito: la cuenta de ejecucion vpg_app NO
    tiene privilegio TRUNCATE (ni debe tenerlo), asi que las pruebas se limpian
    con las mismas operaciones que puede hacer el servicio en produccion.

    Orden: primero lo que referencia a users, luego users (que arrastra perfil,
    contactos y asignaciones por ON DELETE CASCADE), y al final los catalogos.
    """
    factory = get_session_factory()
    async with factory() as session:
        for tabla in (
            "vault_operations",
            "user_vault_identity",
            "users",
            "vault_auth_config",
            "roles",
        ):
            await session.execute(text(f"DELETE FROM employees.{tabla}"))
        await session.commit()
    yield


@pytest_asyncio.fixture
async def seeded(clean_db) -> dict[str, Any]:
    """Catalogo de roles, configuracion Vault y tres empleados de ejemplo."""
    factory = get_session_factory()
    data: dict[str, Any] = {}
    async with factory() as session:
        roles = {}
        for code, name in (
            ("admin", "Administrador"),
            ("manager", "Gestor"),
            ("employee", "Empleado"),
        ):
            role = Role(code=code, name=name)
            session.add(role)
            roles[code] = role
        await session.flush()

        config = VaultAuthConfig(
            userpass_path="userpass",
            userpass_accessor=TEST_ACCESSOR,
            totp_method_id=uuid.UUID(TEST_METHOD_ID),
            mfa_enforcement_name=TEST_ENFORCEMENT,
        )
        session.add(config)
        await session.flush()
        data["config_id"] = config.id

        for code, username in (
            ("admin", "ada.admin"),
            ("manager", "max.manager"),
            ("employee", "eva.employee"),
        ):
            user = User(username=username, auth_provider="vault", is_active=True)
            session.add(user)
            await session.flush()
            session.add(
                UserProfile(
                    user_id=user.id,
                    first_name=username.split(".")[0].capitalize(),
                    last_name_paternal="Ficticio",
                    birth_date=__import__("datetime").date(1990, 1, 15),
                )
            )
            session.add(UserRole(user_id=user.id, role_id=roles[code].id))
            entity_id = uuid.uuid4()
            session.add(
                UserVaultIdentity(
                    user_id=user.id,
                    vault_auth_config_id=config.id,
                    vault_username=username,
                    vault_entity_id=entity_id,
                    totp_status="pending",
                )
            )
            data[code] = {"id": user.id, "username": username, "entity_id": str(entity_id)}
        await session.commit()
    return data


@pytest_asyncio.fixture
async def vault(seeded) -> FakeVault:
    fake = FakeVault()
    for role in ("admin", "manager", "employee"):
        username = seeded[role]["username"]
        entity_id = seeded[role]["entity_id"]
        fake.users[username] = {"password": "contrasena-de-prueba", "policies": ["vpg-oidc-user"]}
        fake.entities[entity_id] = {
            "name": f"vpg-{username}",
            "aliases": [
                {"id": str(uuid.uuid4()), "name": username, "mount_accessor": TEST_ACCESSOR}
            ],
            "disabled": False,
        }
        fake.aliases[username] = entity_id
        fake.totp_secrets.add(entity_id)
    return fake


@pytest_asyncio.fixture
async def app(vault, seeded):
    """App con el estado que normalmente monta el ``lifespan``.

    El ``lifespan`` no se ejecuta: ASGITransport no lo dispara. Asi no se
    contacta con el Vault real ni se aborta por la precondicion de arranque.
    """
    settings = get_settings()
    application = create_app()
    factory = get_session_factory()

    application.state.settings = settings
    application.state.session_factory = factory
    application.state.vault = vault
    application.state.sessions = SessionStore(
        session_ttl_seconds=settings.session_ttl_seconds,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        max_sessions=settings.max_sessions,
        max_challenges=settings.max_challenges,
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

    readiness = ReadinessState(settings)
    readiness._report = ReadinessReport(  # noqa: SLF001 - estado listo para pruebas
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
async def client(app) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest_asyncio.fixture
def api(app):
    return get_settings().api_prefix


async def login_as(client: AsyncClient, prefix: str, username: str) -> str:
    """Login completo (contrasena + TOTP) contra el doble. Devuelve la sesion."""
    response = await client.post(
        f"{prefix}/auth/login",
        json={"username": username, "password": "contrasena-de-prueba"},
    )
    assert response.status_code == 200, response.text
    challenge = response.json()["challenge_id"]
    response = await client.post(
        f"{prefix}/auth/mfa/verify", json={"challenge_id": challenge, "code": GOOD_TOTP}
    )
    assert response.status_code == 200, response.text
    return response.json()["api_session"]


def auth(session_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {session_id}"}


@pytest_asyncio.fixture
async def admin_session(client, api) -> str:
    return await login_as(client, api, "ada.admin")


@pytest_asyncio.fixture
async def manager_session(client, api) -> str:
    return await login_as(client, api, "max.manager")


@pytest_asyncio.fixture
async def employee_session(client, api) -> str:
    return await login_as(client, api, "eva.employee")
