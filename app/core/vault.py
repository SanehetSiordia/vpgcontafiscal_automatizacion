"""Cliente HTTP asincrono de Vault.

FastAPI habla con Vault **por su API HTTP**. No ejecuta ``docker exec``, ni un
shell, ni ``vpg-auth-bootstrap`` por peticion.

Dos clases de credencial, deliberadamente separadas:

* **Sesion humana**: el token que Vault emite tras userpass + TOTP. Vive solo en
  memoria y se usa para lo que hace esa persona (p. ej. ``/vault/access-check``).
* **Cuenta tecnica (AppRole)**: token propio del servicio para provisionar
  cuentas, entidades y TOTP. Nunca es el Initial Root Token ni la contrasena del
  administrador humano, y nunca sustituye los permisos del usuario.

Nada de lo que pasa por aqui se registra: ni contrasenas, ni codigos TOTP, ni
tokens, ni URIs ``otpauth://``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import Settings

# --------------------------------------------------------------------------
# Errores
# --------------------------------------------------------------------------


class VaultError(RuntimeError):
    """Error de Vault ya saneado para poder mostrarse."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class VaultUnavailable(VaultError):
    """Vault no responde: red, DNS o proceso caido."""


class VaultSealed(VaultError):
    """Vault responde pero esta sellado o sin inicializar."""


class VaultPermissionDenied(VaultError):
    """403: el token carece de permisos. NO significa que el recurso no exista."""


class VaultNotFound(VaultError):
    """404 con cuerpo vacio: el recurso no existe."""


class VaultInvalidCredentials(VaultError):
    """Usuario o contrasena incorrectos."""


class VaultMFAFailed(VaultError):
    """El codigo TOTP no valido."""


# Patrones de valores que no deben aparecer nunca en un mensaje de error.
_REDACT_PATTERNS = (
    re.compile(r"\bhv[sb]\.[A-Za-z0-9_\-\.]+"),          # tokens de Vault
    re.compile(r"otpauth://[^\s\"']+", re.IGNORECASE),    # URIs de enrolamiento
    re.compile(r"\bsecret=[A-Za-z0-9]+", re.IGNORECASE),  # semillas en query
)


def sanitize_vault_message(raw: str, *, limit: int = 300) -> str:
    """Quita de un mensaje cualquier cosa que parezca un secreto."""
    text = " ".join(str(raw).split())
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub("[REDACTADO]", text)
    return text[:limit]


# --------------------------------------------------------------------------
# Resultados
# --------------------------------------------------------------------------


@dataclass(slots=True)
class VaultHealth:
    initialized: bool
    sealed: bool
    standby: bool
    version: str | None = None


@dataclass(slots=True)
class MFAChallenge:
    """Respuesta de un login userpass que Vault dejo pendiente de MFA."""

    mfa_request_id: str
    method_ids: tuple[str, ...]
    enforcement_names: tuple[str, ...]
    # True si Vault entrego un token con solo la contrasena: seria un fallo de
    # configuracion del enforcement y hay que tratarlo como tal.
    token_issued_without_mfa: bool


@dataclass(slots=True)
class VaultSession:
    """Token humano emitido tras completar el MFA. Solo vive en memoria."""

    client_token: str = field(repr=False)
    accessor: str = field(repr=False)
    entity_id: str
    policies: tuple[str, ...]
    display_name: str
    lease_duration: int

    def __str__(self) -> str:  # pragma: no cover - defensa contra logs
        return f"VaultSession(entity_id={self.entity_id}, policies={self.policies})"


# --------------------------------------------------------------------------
# Cliente
# --------------------------------------------------------------------------


class VaultClient:
    """Envoltorio sobre la API HTTP de Vault con timeouts explicitos."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.vault_addr,
            timeout=httpx.Timeout(settings.vault_timeout_seconds),
            follow_redirects=False,
        )
        # Token de la cuenta tecnica y su caducidad.
        self._tech_token: str | None = None
        self._tech_expires_at: dt.datetime | None = None
        self._tech_lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- transporte ---------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json: dict[str, Any] | None = None,
        allow_404: bool = False,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if token:
            headers["X-Vault-Token"] = token

        try:
            response = await self._client.request(
                method, f"/v1/{path.lstrip('/')}", headers=headers, json=json
            )
        except httpx.TimeoutException as exc:
            raise VaultUnavailable(
                f"Vault no respondio en {self._settings.vault_timeout_seconds}s ({path})"
            ) from exc
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc

        if response.status_code == 204 or not response.content:
            return {}

        try:
            payload: dict[str, Any] = response.json()
        except ValueError:
            payload = {}

        if response.is_success:
            return payload

        errors = payload.get("errors") or []
        detail = sanitize_vault_message("; ".join(str(e) for e in errors) or response.text)

        if response.status_code == 403:
            raise VaultPermissionDenied(
                f"Vault denego el acceso a {path}: {detail}. "
                "El recurso puede existir: no se concluye su inexistencia.",
                status_code=403,
            )
        if response.status_code == 404:
            if allow_404:
                return {}
            raise VaultNotFound(f"Vault no encontro {path}: {detail}", status_code=404)
        if response.status_code in (501, 503):
            raise VaultSealed(
                f"Vault no esta operativo (sellado o sin inicializar): {detail}",
                status_code=response.status_code,
            )
        raise VaultError(f"Vault devolvio {response.status_code} en {path}: {detail}",
                         status_code=response.status_code)

    # -- salud --------------------------------------------------------------

    async def health(self) -> VaultHealth:
        """``sys/health`` tolera todos los codigos: 200/429/501/503 son validos."""
        try:
            response = await self._client.get(
                "/v1/sys/health",
                params={"standbyok": "true", "sealedcode": "200", "uninitcode": "200"},
            )
        except httpx.HTTPError as exc:
            raise VaultUnavailable(
                f"no se pudo contactar con Vault: {sanitize_vault_message(str(exc))}"
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise VaultUnavailable("respuesta de sys/health ilegible") from exc

        return VaultHealth(
            initialized=bool(data.get("initialized")),
            sealed=bool(data.get("sealed")),
            standby=bool(data.get("standby")),
            version=data.get("version"),
        )

    # -- cuenta tecnica (AppRole) -------------------------------------------

    async def _login_approle(self) -> str:
        settings = self._settings
        if not settings.has_vault_technical_credentials:
            raise VaultError(
                "no hay credenciales tecnicas de Vault montadas. Ejecuta "
                "scripts/user_mgmt/vault-approle-bootstrap.sh y recrea el contenedor."
            )
        assert settings.vault_role_id is not None
        assert settings.vault_secret_id is not None

        payload = await self._request(
            "POST",
            f"auth/{settings.vault_approle_path}/login",
            json={
                "role_id": settings.vault_role_id.get_secret_value(),
                "secret_id": settings.vault_secret_id.get_secret_value(),
            },
        )
        auth = payload.get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise VaultError("AppRole no devolvio token")

        lease = int(auth.get("lease_duration") or 0)
        margin = settings.vault_token_renew_margin_seconds
        self._tech_token = token
        self._tech_expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(
            seconds=max(lease - margin, 30)
        )
        return token

    async def technical_token(self) -> str:
        """Token de la cuenta tecnica, reautenticando cuando va a caducar."""
        async with self._tech_lock:
            now = dt.datetime.now(dt.UTC)
            if (
                self._tech_token is not None
                and self._tech_expires_at is not None
                and now < self._tech_expires_at
            ):
                # Renovar es mas barato que reautenticar; si falla, reautentica.
                try:
                    payload = await self._request(
                        "POST", "auth/token/renew-self", token=self._tech_token
                    )
                    lease = int((payload.get("auth") or {}).get("lease_duration") or 0)
                    if lease:
                        self._tech_expires_at = now + dt.timedelta(
                            seconds=max(
                                lease - self._settings.vault_token_renew_margin_seconds, 30
                            )
                        )
                    return self._tech_token
                except VaultError:
                    self._tech_token = None

            return await self._login_approle()

    async def check_technical_credentials(self) -> tuple[str, ...]:
        """Comprueba que la credencial tecnica es valida. Devuelve sus politicas."""
        token = await self.technical_token()
        payload = await self._request("GET", "auth/token/lookup-self", token=token)
        data = payload.get("data") or {}
        return tuple(data.get("policies") or ())

    # -- autenticacion humana ------------------------------------------------

    async def userpass_login(self, username: str, password: str) -> MFAChallenge:
        """Paso 1: contrasena. Con MFA activo, Vault NO debe entregar token."""
        path = f"auth/{self._settings.vault_userpass_path}/login/{username}"
        try:
            payload = await self._request("POST", path, json={"password": password})
        except VaultPermissionDenied as exc:
            # userpass devuelve 400/403 ante credenciales malas; no es un
            # problema de permisos del servicio.
            raise VaultInvalidCredentials("usuario o contrasena incorrectos") from exc
        except VaultError as exc:
            if exc.status_code in (400, 401):
                raise VaultInvalidCredentials("usuario o contrasena incorrectos") from exc
            raise

        auth = payload.get("auth") or {}
        requirement = auth.get("mfa_requirement") or {}
        request_id = requirement.get("mfa_request_id")

        method_ids: list[str] = []
        enforcements: list[str] = []
        for name, constraint in (requirement.get("mfa_constraints") or {}).items():
            enforcements.append(str(name))
            for item in (constraint or {}).get("any") or []:
                if item.get("id"):
                    method_ids.append(str(item["id"]))

        return MFAChallenge(
            mfa_request_id=str(request_id or ""),
            method_ids=tuple(method_ids),
            enforcement_names=tuple(enforcements),
            token_issued_without_mfa=bool(auth.get("client_token")),
        )

    async def mfa_validate(
        self, mfa_request_id: str, method_id: str, passcode: str
    ) -> VaultSession:
        """Paso 2: valida el TOTP y obtiene el token de la sesion humana."""
        try:
            payload = await self._request(
                "POST",
                "sys/mfa/validate",
                json={
                    "mfa_request_id": mfa_request_id,
                    "mfa_payload": {method_id: [passcode]},
                },
            )
        except (VaultPermissionDenied, VaultError) as exc:
            message = getattr(exc, "message", str(exc))
            lowered = message.lower()
            if "maximum totp validation attempts" in lowered or "try again in" in lowered:
                raise VaultMFAFailed(
                    "se agotaron los intentos de validacion TOTP permitidos; "
                    "espera e intentalo de nuevo"
                ) from exc
            if "failed to validate totp passcode" in lowered or "validation failed" in lowered:
                raise VaultMFAFailed("codigo TOTP incorrecto") from exc
            if "not found" in lowered or "expired" in lowered:
                raise VaultMFAFailed("el desafio MFA caduco; repite el login") from exc
            raise

        auth = payload.get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise VaultMFAFailed("Vault no emitio token tras validar el MFA")

        return VaultSession(
            client_token=token,
            accessor=str(auth.get("accessor") or ""),
            entity_id=str(auth.get("entity_id") or ""),
            policies=tuple(auth.get("policies") or ()),
            display_name=str(auth.get("display_name") or ""),
            lease_duration=int(auth.get("lease_duration") or 0),
        )

    async def lookup_self(self, token: str) -> dict[str, Any]:
        payload = await self._request("GET", "auth/token/lookup-self", token=token)
        return dict(payload.get("data") or {})

    async def revoke_self(self, token: str) -> bool:
        try:
            await self._request("POST", "auth/token/revoke-self", token=token)
            return True
        except VaultError:
            return False

    async def capabilities_self(self, token: str, path: str) -> tuple[str, ...]:
        payload = await self._request(
            "POST", "sys/capabilities-self", token=token, json={"paths": [path]}
        )
        caps = payload.get("data", payload).get(path) or payload.get(path) or []
        return tuple(str(c) for c in caps)

    async def can_read_path(self, token: str, path: str) -> str:
        """Intenta leer una ruta y devuelve SOLO el resultado de autorizacion.

        Nunca devuelve ni registra los valores del secreto.
        """
        try:
            await self._request("GET", path, token=token)
        except VaultPermissionDenied:
            return "denegada_por_politica"
        except VaultNotFound:
            return "autorizada_pero_sin_datos"
        except VaultSealed:
            raise
        except VaultError as exc:
            raise VaultError(f"no se pudo evaluar la ruta: {exc.message}") from exc
        return "autorizada"

    # -- montaje userpass y configuracion MFA --------------------------------

    async def userpass_accessor(self, token: str | None = None) -> str:
        token = token or await self.technical_token()
        payload = await self._request(
            "GET", f"sys/auth/{self._settings.vault_userpass_path}", token=token
        )
        data = payload.get("data") or payload
        accessor = data.get("accessor")
        if not accessor:
            raise VaultError("Vault no devolvio el accessor del montaje userpass")
        return str(accessor)

    async def totp_method_id(self, token: str | None = None) -> str:
        """Busca el method_id del metodo TOTP por su NOMBRE."""
        token = token or await self.technical_token()
        listing = await self._request(
            "LIST", "identity/mfa/method/totp", token=token, allow_404=True
        )
        keys = ((listing.get("data") or {}).get("keys")) or []
        wanted = self._settings.vault_mfa_method_name
        for key in keys:
            payload = await self._request(
                "GET", f"identity/mfa/method/totp/{key}", token=token, allow_404=True
            )
            data = payload.get("data") or {}
            # Vault recibe method_name al crear y lo devuelve como name.
            if data.get("name") == wanted or data.get("method_name") == wanted:
                return str(key)
        raise VaultNotFound(f"no existe un metodo MFA TOTP llamado '{wanted}'")

    async def mfa_enforcement(self, token: str | None = None) -> dict[str, Any]:
        token = token or await self.technical_token()
        payload = await self._request(
            "GET",
            f"identity/mfa/login-enforcement/{self._settings.vault_mfa_enforcement}",
            token=token,
        )
        return dict(payload.get("data") or {})

    # -- cuentas userpass ----------------------------------------------------

    async def userpass_user_exists(self, username: str) -> bool:
        token = await self.technical_token()
        payload = await self._request(
            "GET",
            f"auth/{self._settings.vault_userpass_path}/users/{username}",
            token=token,
            allow_404=True,
        )
        return bool(payload)

    async def create_userpass_user(
        self, username: str, password: str, policies: list[str]
    ) -> None:
        token = await self.technical_token()
        await self._request(
            "POST",
            f"auth/{self._settings.vault_userpass_path}/users/{username}",
            token=token,
            json={
                "password": password,
                "token_policies": policies,
                "token_ttl": "1h",
                "token_max_ttl": "8h",
            },
        )

    async def set_userpass_password(self, username: str, password: str) -> None:
        token = await self.technical_token()
        await self._request(
            "POST",
            f"auth/{self._settings.vault_userpass_path}/users/{username}/password",
            token=token,
            json={"password": password},
        )

    async def set_userpass_policies(self, username: str, policies: list[str]) -> None:
        token = await self.technical_token()
        await self._request(
            "POST",
            f"auth/{self._settings.vault_userpass_path}/users/{username}/policies",
            token=token,
            json={"token_policies": policies},
        )

    async def delete_userpass_user(self, username: str) -> None:
        token = await self.technical_token()
        await self._request(
            "DELETE",
            f"auth/{self._settings.vault_userpass_path}/users/{username}",
            token=token,
            allow_404=True,
        )

    # -- entidades y alias ---------------------------------------------------

    async def lookup_entity_by_alias(self, alias_name: str, accessor: str) -> str | None:
        token = await self.technical_token()
        payload = await self._request(
            "POST",
            "identity/lookup/entity",
            token=token,
            json={"alias_name": alias_name, "alias_mount_accessor": accessor},
            allow_404=True,
        )
        data = payload.get("data") or {}
        entity_id = data.get("id")
        return str(entity_id) if entity_id else None

    async def create_entity(self, name: str, metadata: dict[str, str]) -> str:
        token = await self.technical_token()
        payload = await self._request(
            "POST", "identity/entity", token=token,
            json={"name": name, "metadata": metadata},
        )
        data = payload.get("data") or {}
        entity_id = data.get("id")
        if not entity_id:
            # Vault devuelve 204 si la entidad ya existia: hay que releerla.
            payload = await self._request("GET", f"identity/entity/name/{name}", token=token)
            entity_id = (payload.get("data") or {}).get("id")
        if not entity_id:
            raise VaultError("Vault no devolvio el id de la entidad creada")
        return str(entity_id)

    async def read_entity(self, entity_id: str) -> dict[str, Any]:
        token = await self.technical_token()
        payload = await self._request("GET", f"identity/entity/id/{entity_id}", token=token)
        return dict(payload.get("data") or {})

    async def create_entity_alias(
        self, alias_name: str, entity_id: str, accessor: str
    ) -> str:
        token = await self.technical_token()
        payload = await self._request(
            "POST", "identity/entity-alias", token=token,
            json={
                "name": alias_name,
                "canonical_id": entity_id,
                "mount_accessor": accessor,
            },
        )
        return str((payload.get("data") or {}).get("id") or "")

    async def update_entity_alias(
        self, alias_id: str, alias_name: str, entity_id: str, accessor: str
    ) -> None:
        token = await self.technical_token()
        await self._request(
            "POST", f"identity/entity-alias/id/{alias_id}", token=token,
            json={
                "name": alias_name,
                "canonical_id": entity_id,
                "mount_accessor": accessor,
            },
        )

    async def set_entity_disabled(self, entity_id: str, disabled: bool) -> None:
        """Deshabilitar una entidad bloquea TAMBIEN los tokens ya emitidos."""
        token = await self.technical_token()
        await self._request(
            "POST", f"identity/entity/id/{entity_id}", token=token,
            json={"disabled": disabled},
        )

    async def delete_entity(self, entity_id: str) -> None:
        token = await self.technical_token()
        await self._request(
            "DELETE", f"identity/entity/id/{entity_id}", token=token, allow_404=True
        )

    async def delete_entity_alias(self, alias_id: str) -> None:
        token = await self.technical_token()
        await self._request(
            "DELETE", f"identity/entity-alias/id/{alias_id}", token=token, allow_404=True
        )

    # -- TOTP por entidad ----------------------------------------------------

    async def generate_totp(self, method_id: str, entity_id: str) -> str:
        """Genera la semilla TOTP de UNA entidad y devuelve su URI otpauth.

        El valor devuelto es un secreto de un solo uso: se entrega al solicitante
        autorizado y no se registra, ni se guarda, ni se vuelve a mostrar.
        """
        token = await self.technical_token()
        payload = await self._request(
            "POST", "identity/mfa/method/totp/admin-generate", token=token,
            json={"method_id": method_id, "entity_id": entity_id},
        )
        url = (payload.get("data") or {}).get("url")
        if not url:
            raise VaultError(
                "Vault no genero una semilla TOTP nueva: la entidad ya tiene una. "
                "Usa el reset explicito de MFA si hay que sustituirla."
            )
        return str(url)

    async def destroy_totp(self, method_id: str, entity_id: str) -> None:
        """Destruye SOLO la semilla de esa entidad. El metodo es compartido."""
        token = await self.technical_token()
        await self._request(
            "POST", "identity/mfa/method/totp/admin-destroy", token=token,
            json={"method_id": method_id, "entity_id": entity_id},
        )

    # -- revocacion ----------------------------------------------------------

    async def revoke_accessor(self, accessor: str) -> bool:
        """Revoca un token concreto por su accessor. Nunca el montaje entero."""
        token = await self.technical_token()
        try:
            await self._request(
                "POST", "auth/token/revoke-accessor", token=token,
                json={"accessor": accessor},
            )
            return True
        except VaultError:
            return False
