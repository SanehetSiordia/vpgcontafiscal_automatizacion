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
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
