"""Motor y sesiones de SQLAlchemy 2.x sobre Psycopg 3 asincrono.

Reglas que se respetan aqui:
  * Una ``AsyncSession`` por peticion, nunca compartida entre tareas.
  * ``create_all()`` NUNCA se ejecuta: el esquema lo crean las migraciones SQL
    aplicadas por la cuenta administrativa.
  * Pool limitado y ``pool_pre_ping`` para no servir conexiones muertas tras
    reiniciar PostgreSQL.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings) -> AsyncEngine:
    """Crea el motor. Se llama una vez desde el ``lifespan``."""
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    _engine = create_async_engine(
        settings.database_url,
        echo=False,
        pool_size=settings.postgres_pool_size,
        max_overflow=settings.postgres_pool_max_overflow,
        pool_timeout=settings.postgres_pool_timeout_seconds,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "password": settings.postgres_password.get_secret_value(),
            # search_path al esquema de la aplicacion y tope de duracion de
            # sentencia: una consulta colgada no retiene una conexion del pool.
            "options": (
                f"-c search_path={settings.postgres_schema}"
                f" -c statement_timeout={settings.postgres_statement_timeout_ms}"
            ),
            "application_name": "vpg-user-mgmt",
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


async def session_scope() -> AsyncIterator[AsyncSession]:
    """Sesion con commit al salir bien y rollback ante cualquier excepcion."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
