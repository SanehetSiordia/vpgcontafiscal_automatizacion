"""Configuracion de vault-mgmt-service.

Mismas reglas que en la etapa 3, con prefijo propio ``VAULT_MGMT_``:

* Todo lo NO sensible llega por variables de entorno concretas. **No** se carga
  el ``.env`` del proyecto: ese archivo lleva la clave de unseal y el token
  inicial de Vault, y este proceso no tiene nada que hacer con ellos.
* Las credenciales llegan SIEMPRE por archivo montado como Compose secret:
  contrasena de PostgreSQL y credencial interna de la pasarela.
* La validacion ocurre al construir los ajustes, es decir al arrancar.

Lo que este servicio **no** tiene, a proposito:

* Credenciales de Vault propias para leer secretos. Las lecturas y escrituras
  humanas las ejecuta user-mgmt con el token de la persona. Aqui solo hay un
  cliente de Vault para `sys/health` (readiness) y para validar el token de una
  maquina en `/integrations/crawler/resolve`.
* Root token, claves de unseal o semillas.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Mismos alfabetos que los CHECK de las migraciones 003 y 004: lo que no pase
# por aqui tampoco entraria en PostgreSQL, y asi el error es 422 y no 500.
_MOUNT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_ROLE_PREFIX_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,32}")
_RECEIVER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,62}")


def _read_secret_file(path: str | None, *, label: str, required: bool) -> SecretStr | None:
    """Lee la primera linea de un archivo de secreto.

    No registra ni devuelve el valor en mensajes de error: solo la ruta.
    """
    if not path:
        if required:
            raise ValueError(f"falta la ruta del secreto de {label}")
        return None

    file_path = Path(path)
    if not file_path.is_file():
        if required:
            raise ValueError(
                f"no existe el archivo de secreto de {label}: {path}. "
                "Ejecuta scripts/vault_mgmt/prepare-internal-secret.sh y recrea "
                "los contenedores."
            )
        return None

    lines = file_path.read_text(encoding="utf-8").splitlines()
    value = lines[0].strip() if lines else ""
    if not value:
        if required:
            raise ValueError(f"el archivo de secreto de {label} esta vacio: {path}")
        return None
    return SecretStr(value)


class Settings(BaseSettings):
    """Ajustes del servicio. Prefijo ``VAULT_MGMT_``."""

    model_config = SettingsConfigDict(
        env_prefix="VAULT_MGMT_",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Identidad del servicio --------------------------------------------
    app_name: str = "VPG Contadores - vault-mgmt"
    api_prefix: str = "/vault_mgmt/v1"
    environment: Literal["local", "ci"] = "local"
    log_level: Literal["debug", "info", "warning", "error"] = "info"

    # --- PostgreSQL (catalogo y auditoria; nunca valores) -------------------
    postgres_host: str = "postgres-service"
    postgres_port: int = 5432
    postgres_db: str = "vpg_contadores"
    postgres_user: str = "vpg_app"
    # El catalogo vive en su propio esquema; employees se consulta para resolver
    # el actor humano, de ahi los dos en el search_path.
    postgres_schema: str = "vault_mgmt"
    postgres_employees_schema: str = "employees"
    postgres_password_file: str = "/run/secrets/postgres_app_password"
    postgres_pool_size: Annotated[int, Field(ge=1, le=20)] = 5
    postgres_pool_max_overflow: Annotated[int, Field(ge=0, le=20)] = 5
    postgres_pool_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 10.0
    postgres_statement_timeout_ms: Annotated[int, Field(ge=1000, le=60000)] = 15000

    # --- Vault (solo salud y validacion de tokens de maquina) ---------------
    vault_addr: str = "http://vault-service:8200"
    vault_timeout_seconds: Annotated[float, Field(gt=0, le=30)] = 10.0
    # Montaje KV v2 por defecto de las colecciones nuevas y prefijo gestionado.
    # Los prefijos data/metadata/delete/undelete/destroy son detalles del
    # cliente KV v2 y NO se configuran aqui.
    kv_mount: str = "secret"
    kv_prefix: str = "vpg-managed"

    # --- Pasarela interna de user-mgmt --------------------------------------
    user_mgmt_base_url: str = "http://user-mgmt-service:8000"
    user_mgmt_internal_prefix: str = "/internal/v1/vault-mgmt"
    user_mgmt_public_prefix: str = "/user_mgmt/v1"
    user_mgmt_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 15.0
    # Credencial interna independiente del Bearer humano. Solo por archivo.
    internal_credential_file: str = "/run/secrets/vault_mgmt_internal_token"
    internal_credential_header: str = "X-VPG-Internal-Credential"
    # Cabecera con la prueba breve de MFA reciente emitida por user-mgmt.
    mfa_proof_header: str = "X-VPG-MFA-Proof"

    # --- Entrega de secretos ------------------------------------------------
    # TTL del wrapping token de Vault. Corto a proposito: es un token de un solo
    # uso que el consumidor desenvuelve enseguida.
    wrap_ttl_seconds: Annotated[int, Field(ge=10, le=600)] = 60
    # `plain` solo se entrega si el lector autorizado lo pide de forma explicita.
    allow_plain_delivery: bool = True

    # --- Limites del modelo -------------------------------------------------
    max_fields_per_schema: Annotated[int, Field(ge=1, le=200)] = 50
    max_field_name_length: Annotated[int, Field(ge=1, le=128)] = 64
    max_string_value_length: Annotated[int, Field(ge=1, le=65536)] = 4096
    max_object_depth: Annotated[int, Field(ge=1, le=10)] = 4
    max_array_items: Annotated[int, Field(ge=1, le=1000)] = 100
    max_record_bytes: Annotated[int, Field(ge=512, le=262144)] = 65536
    # Tope de registros que una operacion de coleccion procesa de una vez.
    max_collection_batch: Annotated[int, Field(ge=1, le=1000)] = 100
    # Tope de versiones por operacion explicita de versiones.
    max_versions_per_request: Annotated[int, Field(ge=1, le=100)] = 20
    # Tope de registros por peticion del crawler.
    max_crawler_records: Annotated[int, Field(ge=1, le=100)] = 20

    # --- Paginacion ---------------------------------------------------------
    default_page_limit: Annotated[int, Field(ge=1, le=100)] = 20
    max_page_limit: Annotated[int, Field(ge=1, le=100)] = 100

    # --- Readiness ----------------------------------------------------------
    readiness_recheck_seconds: Annotated[int, Field(ge=2, le=300)] = 15

    # --- Rate limiting (en memoria, un solo worker) -------------------------
    rate_limit_session_per_minute: Annotated[int, Field(ge=1, le=10000)] = 120
    rate_limit_consumer_per_minute: Annotated[int, Field(ge=1, le=10000)] = 60
    rate_limit_global_per_minute: Annotated[int, Field(ge=1, le=100000)] = 600
    rate_limit_receiver_per_minute: Annotated[int, Field(ge=1, le=10000)] = 60

    # --- Aprovisionamiento de consumidores de maquina (etapa 4.6) -----------
    #
    # PERFIL LOCAL. El aprovisionador necesita un token administrativo de Vault
    # para crear la AppRole del consumidor y emitir su SecretID. En este entorno
    # se le monta en SOLO LECTURA el token inicial del proyecto.
    #
    # Esto es una simplificacion deliberada de desarrollo, no una configuracion
    # de produccion: ese token puede hacer cualquier cosa en Vault, y lo que lo
    # limita aqui es el CODIGO (approle_admin.py solo opera sobre el montaje y
    # los roles gestionados), no la ACL. La sustitucion es una identidad tecnica
    # propia con politica acotada, y por eso el proveedor esta separado en
    # app/vault_mgmt/core/vault_auth.py: se cambia el proveedor sin tocar ningun
    # endpoint. Si el archivo no esta montado, el aprovisionamiento queda
    # desactivado y se dice en readiness; el resto del servicio sigue operando.
    vault_token_file: str = "/run/secrets/vault_provisioner_token"
    # Montaje AppRole de los consumidores GESTIONADOS por esta API. Es el mismo
    # que usa el consumidor heredado de la etapa 4, pero cada consumidor tiene
    # su propio rol dentro de el.
    managed_approle_mount: str = "approle-crawler"
    # Politica de los consumidores gestionados. NO incluye lectura del prefijo
    # KV: su entrega es mediada (la lee el backend autorizado y la envuelve).
    managed_policy_name: str = "vpg-crawler-managed"
    managed_role_prefix: str = "vpg-managed-"
    crawler_token_ttl_seconds: Annotated[int, Field(ge=60, le=86400)] = 1200
    crawler_token_max_ttl_seconds: Annotated[int, Field(ge=60, le=604800)] = 3600
    crawler_secret_id_ttl_seconds: Annotated[int, Field(ge=60, le=604800)] = 604800
    # SecretID de un solo uso: el receptor lo canjea una vez por un token. Si se
    # reinicia y lo pierde, hay que REAPROVISIONAR (no se reutiliza), y el token
    # que obtuvo se renueva hasta su max_ttl. Esta documentado en la etapa 4.6.
    crawler_secret_id_num_uses: Annotated[int, Field(ge=1, le=10)] = 1

    # Receptores configurados: "<receptor>=<ruta del archivo>", separados por
    # comas. Texto plano y no JSON a proposito, para que se lea igual de bien en
    # .env, en compose.yaml y en un 'docker inspect'.
    #
    # El receptor no se identifica por consumer_id (que no es una contrasena)
    # sino por su credencial, que el servidor asocia al consumidor autorizado.
    receivers: str = "local=/run/secrets/crawler_receiver_local"
    receiver_credential_header: str = "X-VPG-Receiver-Credential"
    # TTL de la envoltura de APROVISIONAMIENTO (lleva el SecretID). Mas larga
    # que la de una entrega de datos porque el receptor puede estar arrancando.
    provisioning_wrap_ttl_seconds: Annotated[int, Field(ge=30, le=600)] = 120
    # Reintentos de claim sobre una misma entrega antes de darla por fallida.
    provisioning_max_claims: Annotated[int, Field(ge=1, le=50)] = 5

    # --- Worker de operaciones ----------------------------------------------
    worker_poll_seconds: Annotated[float, Field(gt=0, le=60)] = 2.0
    # Arrendamiento de una operacion. Caduca solo: un worker muerto no deja la
    # cola bloqueada para siempre.
    worker_lease_seconds: Annotated[int, Field(ge=10, le=600)] = 60
    worker_batch: Annotated[int, Field(ge=1, le=50)] = 5
    worker_max_attempts: Annotated[int, Field(ge=1, le=20)] = 3
    # Nombre del worker en el lease. Se rellena solo si no se declara.
    worker_name: str = ""

    # --- CORS ---------------------------------------------------------------
    # Lista explicita. Nunca '*' con credenciales: el navegador lo rechaza y,
    # peor, invita a desactivar la comprobacion.
    cors_allow_origins: list[str] = Field(default_factory=list)

    @field_validator("vault_addr", "user_mgmt_base_url")
    @classmethod
    def _check_http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("la URL debe empezar por http:// o https://")
        return value.rstrip("/")

    @field_validator("api_prefix", "user_mgmt_internal_prefix", "user_mgmt_public_prefix")
    @classmethod
    def _check_prefix(cls, value: str) -> str:
        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("el prefijo debe empezar por '/' y no acabar en '/'")
        return value

    @field_validator("kv_mount")
    @classmethod
    def _check_mount(cls, value: str) -> str:
        cleaned = value.strip().strip("/")
        if not cleaned or "/" in cleaned:
            raise ValueError(
                "VAULT_MGMT_KV_MOUNT es el nombre del montaje KV v2, sin barras "
                "ni los segmentos data/metadata"
            )
        if cleaned in ("data", "metadata"):
            raise ValueError(
                "'data' y 'metadata' son segmentos internos de KV v2, no el montaje"
            )
        return cleaned

    @field_validator("kv_prefix")
    @classmethod
    def _check_prefix_path(cls, value: str) -> str:
        cleaned = value.strip().strip("/")
        if not cleaned or ".." in cleaned:
            raise ValueError("VAULT_MGMT_KV_PREFIX no puede estar vacio ni contener '..'")
        return cleaned

    @field_validator("managed_approle_mount")
    @classmethod
    def _check_approle_mount(cls, value: str) -> str:
        cleaned = value.strip().strip("/")
        if not _MOUNT_RE.fullmatch(cleaned):
            raise ValueError(
                "VAULT_MGMT_MANAGED_APPROLE_MOUNT es el nombre del montaje "
                "AppRole, sin barras (letras minusculas, digitos, '_' y '-')"
            )
        return cleaned

    @field_validator("managed_role_prefix")
    @classmethod
    def _check_role_prefix(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or not _ROLE_PREFIX_RE.fullmatch(cleaned):
            raise ValueError(
                "VAULT_MGMT_MANAGED_ROLE_PREFIX debe empezar por letra o digito "
                "en minuscula y contener solo [a-z0-9._-]"
            )
        return cleaned

    @field_validator("receivers")
    @classmethod
    def _check_receivers(cls, value: str) -> str:
        seen: set[str] = set()
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            key, sep, path = entry.partition("=")
            if not sep or not key.strip() or not path.strip():
                raise ValueError(
                    "cada receptor se declara como '<receptor>=<ruta del archivo>' "
                    f"y se separan por comas; '{entry}' no lo cumple"
                )
            name = key.strip()
            if not _RECEIVER_RE.fullmatch(name):
                raise ValueError(
                    f"'{name}' no es un nombre de receptor valido "
                    "(minusculas, digitos, '.', '_' y '-')"
                )
            if name in seen:
                raise ValueError(
                    f"el receptor '{name}' esta declarado dos veces: una "
                    "credencial por receptor, y una sola"
                )
            seen.add(name)
        return value

    @field_validator("cors_allow_origins")
    @classmethod
    def _check_cors(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError(
                "CORS con '*' no es compatible con credenciales: declara los "
                "origenes de forma explicita"
            )
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> "Settings":
        if self.max_page_limit < self.default_page_limit:
            raise ValueError(
                "VAULT_MGMT_MAX_PAGE_LIMIT no puede ser menor que el limite por defecto"
            )
        if self.crawler_token_max_ttl_seconds < self.crawler_token_ttl_seconds:
            raise ValueError(
                "VAULT_MGMT_CRAWLER_TOKEN_MAX_TTL_SECONDS no puede ser menor que "
                "el TTL inicial: Vault rechazaria el rol"
            )
        return self

    # --- Secretos leidos de archivo ----------------------------------------
    @functools.cached_property
    def postgres_password(self) -> SecretStr:
        secret = _read_secret_file(
            self.postgres_password_file, label="PostgreSQL", required=True
        )
        assert secret is not None
        return secret

    @functools.cached_property
    def internal_credential(self) -> SecretStr | None:
        """Credencial de la pasarela interna. Puede faltar: readiness lo dice.

        No se inventa un valor por defecto: sin ella el servicio arranca pero
        ``/health/ready`` y las operaciones humanas responden 503.
        """
        return _read_secret_file(
            self.internal_credential_file, label="credencial interna", required=False
        )

    @property
    def has_internal_credential(self) -> bool:
        return self.internal_credential is not None

    # --- Etapa 4.6: token del aprovisionador y credenciales de receptor -----

    @property
    def receiver_entries(self) -> tuple[tuple[str, str], ...]:
        """Pares (receptor, ruta) ya separados del texto de configuracion."""
        pares: list[tuple[str, str]] = []
        for entry in self.receivers.split(","):
            entry = entry.strip()
            if not entry:
                continue
            name, _sep, path = entry.partition("=")
            pares.append((name.strip(), path.strip()))
        return tuple(pares)

    @functools.cached_property
    def receiver_credentials(self) -> dict[str, SecretStr]:
        """Credencial interna de cada receptor configurado.

        Un receptor sin archivo legible NO se registra: mejor que no pueda
        reclamar nada a que lo haga con una credencial vacia. Se avisa en el
        log del arranque, no aqui, porque leer configuracion no debe escribir.
        """
        resolved: dict[str, SecretStr] = {}
        for name, path in self.receiver_entries:
            secret = _read_secret_file(
                path, label=f"receptor '{name}'", required=False
            )
            if secret is not None:
                resolved[name] = secret
        return resolved

    @property
    def configured_receivers(self) -> tuple[str, ...]:
        """Receptores DECLARADOS, tengan o no su archivo presente."""
        return tuple(name for name, _path in self.receiver_entries)

    @functools.cached_property
    def vault_provisioner_token(self) -> SecretStr | None:
        """Token administrativo de Vault del PERFIL LOCAL, por archivo.

        Puede faltar: entonces el aprovisionamiento queda desactivado, el resto
        del servicio sigue operando y ``/health/ready`` lo refleja. No se
        inventa un valor por defecto y no se lee de ninguna variable de entorno.
        """
        return _read_secret_file(
            self.vault_token_file, label="token del aprovisionador", required=False
        )

    @property
    def provisioning_enabled(self) -> bool:
        """Hay con que aprovisionar: token del proveedor y algun receptor."""
        return self.vault_provisioner_token is not None

    def managed_role_name(self, consumer_name: str) -> str:
        """Rol AppRole de un consumidor gestionado, derivado de su nombre.

        Derivado y no elegido por el cliente: asi una peticion no puede apuntar
        a un rol ajeno ni salirse del montaje gestionado.
        """
        return f"{self.managed_role_prefix}{consumer_name}"

    @property
    def database_url(self) -> str:
        """DSN async. La contrasena NO se interpola aqui: va aparte."""
        return (
            f"postgresql+psycopg://{self.postgres_user}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def search_path(self) -> str:
        return f"{self.postgres_schema},{self.postgres_employees_schema}"


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
