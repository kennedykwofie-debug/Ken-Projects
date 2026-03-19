"""Async database engine and session factory."""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from src.db.models import Base

_DATABASE_URL = os.getenv("DATABASE_URL", "")

def _fix_url(url: str) -> str:
    if url.startswith("postgres://"): return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://"): return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url

DATABASE_URL = _fix_url(_DATABASE_URL)

engine = create_async_engine(DATABASE_URL, echo=False, poolclass=NullPool) if DATABASE_URL else None

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False, autocommit=False, autoflush=False,
) if engine else None


async def init_db():
    """Create all tables on startup."""
    if not engine: return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency - yields async DB session."""
    if not AsyncSessionLocal:
        raise RuntimeError("Database not configured - set DATABASE_URL")
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
