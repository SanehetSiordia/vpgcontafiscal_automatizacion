"""Configuracion de user-mgmt-service.

Todo lo NO sensible llega por variables ``USER_MGMT_*``. Las credenciales
(contrasena de PostgreSQL y credenciales tecnicas de Vault) llegan SIEMPRE por
archivo montado como Compose secret: nunca como valor de entorno, nunca
cargando el ``.env`` completo del proyecto.

La validacion ocurre al importar el modulo, es decir al arrancar: si falta algo
el proceso falla de inmediato y con un mensaje concreto, en vez de romper en la
primera peticion.
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
                "Ejecuta scripts/user_mgmt/prepare-secrets.sh y recrea el contenedor."
            )
        return None

    value = file_path.read_text(encoding="utf-8").splitlines()
    value = value[0].strip() if value else ""
    if not value:
        if required:
            raise ValueError(f"el archivo de secreto de {label} esta vacio: {path}")
        return None
    return SecretStr(value)


class Settings(BaseSettings):
    """Ajustes del servicio. Prefijo ``USER_MGMT_``."""

    model_config = SettingsConfigDict(
        env_prefix="USER_MGMT_",
        extra="ignore",          # el entorno del contenedor trae mas variables
        case_sensitive=False,
    )

    # --- Identidad del servicio -------------------------------------------
    app_name: str = "VPG Contadores - user-mgmt"
    api_prefix: str = "/user_mgmt/v1"
    environment: Literal["local", "ci"] = "local"
    log_level: Literal["debug", "info", "warning", "error"] = "info"

    # --- PostgreSQL --------------------------------------------------------
    postgres_host: str = "postgres-service"
    postgres_port: int = 5432
    postgres_db: str = "vpg_contadores"
    postgres_user: str = "vpg_app"
    postgres_schema: str = "employees"
    postgres_password_file: str = "/run/secrets/postgres_app_password"
    postgres_pool_size: Annotated[int, Field(ge=1, le=20)] = 5
    postgres_pool_max_overflow: Annotated[int, Field(ge=0, le=20)] = 5
    postgres_pool_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 10.0
    postgres_statement_timeout_ms: Annotated[int, Field(ge=1000, le=60000)] = 15000

    # --- Vault -------------------------------------------------------------
    vault_addr: str = "http://vault-service:8200"
    vault_userpass_path: str = "userpass"
    vault_mfa_method_name: str = "vpg-totp"
    vault_mfa_enforcement: str = "vpg-userpass-totp"
    vault_timeout_seconds: Annotated[float, Field(gt=0, le=30)] = 10.0

    # Cuenta tecnica de provisionamiento: AppRole, nunca el root token ni la
    # contrasena del administrador humano.
    vault_approle_path: str = "approle"
    vault_role_id_file: str = "/run/secrets/vault_role_id"
    vault_secret_id_file: str = "/run/secrets/vault_secret_id"
    # Margen para reautenticar antes de que caduque el token tecnico.
    vault_token_renew_margin_seconds: Annotated[int, Field(ge=30, le=3600)] = 300

    # Politicas que el servicio puede asignar a cuentas nuevas. Allowlist: el
    # cuerpo HTTP NUNCA elige la politica.
    vault_assignable_policies: list[str] = Field(default_factory=lambda: ["vpg-oidc-user"])
    # Politica por defecto de un empleado recien provisionado.
    vault_default_user_policy: str = "vpg-oidc-user"

    # Rutas logicas que /vault/access-check admite. Evita que el cliente
    # convierta el endpoint en un escaner de rutas arbitrarias.
    vault_access_check_paths: dict[str, str] = Field(
        default_factory=lambda: {
            "crawler_sat": "secret/data/crawler/sat",
            "sat_usuarios": "secret/data/sat/usuarios",
        }
    )

    # --- Sesiones API (solo en memoria) ------------------------------------
    session_ttl_seconds: Annotated[int, Field(ge=60, le=28800)] = 3600
    challenge_ttl_seconds: Annotated[int, Field(ge=30, le=600)] = 180
    max_sessions: Annotated[int, Field(ge=1, le=10000)] = 200
    max_challenges: Annotated[int, Field(ge=1, le=10000)] = 200
    # Antiguedad maxima del MFA para operaciones sensibles (reset TOTP, purga).
    sensitive_op_mfa_max_age_seconds: Annotated[int, Field(ge=60, le=3600)] = 900

    # --- Pasarela interna de vault-mgmt-service (etapa 4) -------------------
    # Credencial interna INDEPENDIENTE del Bearer humano, suministrada por
    # archivo de Compose secret. No sustituye la autorizacion de la persona:
    # ambas son obligatorias. La red de Docker por si sola no autentica a nadie.
    internal_credential_file: str = "/run/secrets/vault_mgmt_internal_token"
    internal_credential_header: str = "X-VPG-Internal-Credential"
    # Cabecera con la prueba breve de MFA reciente que emite el step-up.
    mfa_proof_header: str = "X-VPG-MFA-Proof"
    # Vida de esa prueba. Corta a proposito: autoriza UNA operacion registrada
    # sobre un conjunto cerrado de recursos, no acciones ilimitadas.
    mfa_proof_ttl_seconds: Annotated[int, Field(ge=30, le=900)] = 300
    max_mfa_proofs: Annotated[int, Field(ge=1, le=1000)] = 50
    # Esquema del catalogo compartido que la pasarela consulta en SOLO LECTURA
    # para resolver el path fisico de una coleccion o registro.
    catalog_schema: str = "vault_mgmt"
    # TTL del response wrapping con el que se entregan los valores.
    wrap_ttl_seconds: Annotated[int, Field(ge=10, le=600)] = 60
    # Tope de versiones por operacion explicita de versiones.
    max_versions_per_request: Annotated[int, Field(ge=1, le=100)] = 20
    # Tope de registros que un lote de coleccion procesa de una vez.
    max_collection_batch: Annotated[int, Field(ge=1, le=1000)] = 100

    # --- Readiness ----------------------------------------------------------
    readiness_recheck_seconds: Annotated[int, Field(ge=2, le=300)] = 15

    # --- Rate limiting (en memoria, un solo worker) ------------------------
    rate_limit_login_per_minute: Annotated[int, Field(ge=1, le=1000)] = 10
    rate_limit_mfa_per_minute: Annotated[int, Field(ge=1, le=1000)] = 10
    rate_limit_session_per_minute: Annotated[int, Field(ge=1, le=10000)] = 120
    rate_limit_global_per_minute: Annotated[int, Field(ge=1, le=100000)] = 600

    # --- Paginacion ---------------------------------------------------------
    default_page_limit: Annotated[int, Field(ge=1, le=100)] = 20
    max_page_limit: Annotated[int, Field(ge=1, le=100)] = 100

    @field_validator("vault_addr")
    @classmethod
    def _check_vault_addr(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("USER_MGMT_VAULT_ADDR debe empezar por http:// o https://")
        return value.rstrip("/")

    @field_validator("api_prefix")
    @classmethod
    def _check_prefix(cls, value: str) -> str:
        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("USER_MGMT_API_PREFIX debe empezar por '/' y no acabar en '/'")
        return value

    @model_validator(mode="after")
    def _check_policy_allowlist(self) -> "Settings":
        if self.vault_default_user_policy not in self.vault_assignable_policies:
            raise ValueError(
                "USER_MGMT_VAULT_DEFAULT_USER_POLICY debe estar dentro de "
                "USER_MGMT_VAULT_ASSIGNABLE_POLICIES"
            )
        if "vpg-admin" in self.vault_assignable_policies:
            # Defensa explicita: el rol de aplicacion 'admin' no debe traducirse
            # automaticamente en la politica total de Vault.
            raise ValueError(
                "'vpg-admin' no puede estar en USER_MGMT_VAULT_ASSIGNABLE_POLICIES: "
                "esa politica se asigna a mano, nunca por un rol de aplicacion"
            )
        if self.max_page_limit < self.default_page_limit:
            raise ValueError("USER_MGMT_MAX_PAGE_LIMIT no puede ser menor que el limite por defecto")
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

        No se inventa un valor por defecto. Sin ella, ``/internal/v1/...``
        rechaza toda peticion con 503 en vez de quedar abierto.
        """
        return _read_secret_file(
            self.internal_credential_file, label="credencial interna", required=False
        )

    @property
    def has_internal_credential(self) -> bool:
        return self.internal_credential is not None

    @functools.cached_property
    def vault_role_id(self) -> SecretStr | None:
        return _read_secret_file(self.vault_role_id_file, label="Vault role_id", required=False)

    @functools.cached_property
    def vault_secret_id(self) -> SecretStr | None:
        return _read_secret_file(
            self.vault_secret_id_file, label="Vault secret_id", required=False
        )

    @property
    def has_vault_technical_credentials(self) -> bool:
        return self.vault_role_id is not None and self.vault_secret_id is not None

    @property
    def database_url(self) -> str:
        """DSN async. La contrasena NO se interpola aqui: va aparte."""
        return (
            f"postgresql+psycopg://{self.postgres_user}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
