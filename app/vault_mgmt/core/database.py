"""Motor y sesiones de SQLAlchemy de vault-mgmt-service.

Modulo propio y no el de la etapa 3 a proposito: los globales del motor son por
proceso y los ajustes son de otro tipo. Las reglas son las mismas:

  * Una ``AsyncSession`` por peticion, nunca compartida entre tareas.
  * ``create_all()`` NUNCA se ejecuta: el esquema lo crea la migracion 003
    aplicada por la cuenta administrativa.
  * Pool limitado y ``pool_pre_ping``.
  * Ninguna transaccion permanece abierta mientras se llama por HTTP a Vault o
    a la pasarela interna.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.vault_mgmt.core.config import Settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings) -> AsyncEngine:
    """Crea el motor. Se llama una vez desde el ``lifespan``."""
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    _engine = create_async_engine(
        settings.database_url,
        echo=False,  # nunca True: imprimiria los parametros de cada sentencia
        pool_size=settings.postgres_pool_size,
        max_overflow=settings.postgres_pool_max_overflow,
        pool_timeout=settings.postgres_pool_timeout_seconds,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "password": settings.postgres_password.get_secret_value(),
            "options": (
                f"-c search_path={settings.search_path}"
                f" -c statement_timeout={settings.postgres_statement_timeout_ms}"
            ),
            "application_name": "vpg-vault-mgmt",
        },
    )
    _session_factory = async_sessionmaker(
        bind=_engine,
        expire_on_commit=False,
        autoflush=False,
    )
    return _engine


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("el motor de base de datos no esta inicializado")
    return _session_factory
