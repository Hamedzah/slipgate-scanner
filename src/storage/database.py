"""Async database access layer.

Wraps a SQLAlchemy async engine/session and exposes small repository
functions used by the rest of the pipeline. Host/port values are
encrypted at rest via `SecretBox` before being persisted, per the
project's security requirements.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.logging_config import get_logger
from src.security.crypto import SecretBox
from src.storage.models import Base, BroadcastLog, ConfigRecord, TestResultRecord

logger = get_logger(__name__)


def _ensure_async_driver(database_url: str) -> str:
    """Normalize a DATABASE_URL to guarantee an async-capable driver.

    Operators sometimes set DATABASE_URL to a bare `sqlite:///...` or
    `postgresql://...` (e.g. copied from a non-async tool). SQLAlchemy's
    asyncio extension requires an explicit async driver
    (`sqlite+aiosqlite://`, `postgresql+asyncpg://`), or it raises
    `InvalidRequestError: ... is not async`. Rather than crash on an easy
    mistake, upgrade the URL automatically and log that we did so.
    """
    if database_url.startswith("sqlite:///") and "+aiosqlite" not in database_url:
        fixed = database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        logger.warning("database_url_missing_async_driver", original=database_url, fixed=fixed)
        return fixed
    if database_url.startswith("postgresql://") and "+asyncpg" not in database_url:
        fixed = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        logger.warning("database_url_missing_async_driver", original=database_url, fixed=fixed)
        return fixed
    return database_url


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """Create the parent directory for a SQLite file DB if it doesn't exist yet.

    On a fresh GitHub Actions checkout, `data/` may not exist unless it was
    committed (e.g. via a `.gitkeep`); SQLite will not create missing
    parent directories on its own and instead fails with an obscure
    "unable to open database file" error.
    """
    if "sqlite" not in database_url:
        return
    # Strip the driver prefix and any leading slashes used for relative paths.
    path_part = database_url.split("///", 1)[-1]
    if not path_part or path_part == ":memory:":
        return
    Path(path_part).parent.mkdir(parents=True, exist_ok=True)


class Database:
    """Owns the engine/sessionmaker and exposes repository operations."""

    def __init__(self, database_url: str, secret_box: SecretBox) -> None:
        database_url = _ensure_async_driver(database_url)
        _ensure_sqlite_parent_dir(database_url)
        self._engine = create_async_engine(database_url, future=True)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)
        self._secret_box = secret_box

    async def init_models(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self._engine.dispose()

    def _session(self) -> AsyncSession:
        return self._sessionmaker()

    async def is_blacklisted(self, config_hash: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                select(ConfigRecord.is_blacklisted).where(ConfigRecord.config_hash == config_hash)
            )
            row = result.scalar_one_or_none()
            return bool(row)

    async def upsert_config_seen(
        self, config_hash: str, protocol: str, host: str, port: int, score: float
    ) -> None:
        encrypted_host = self._secret_box.encrypt(host)
        async with self._session() as session:
            existing = await session.execute(
                select(ConfigRecord).where(ConfigRecord.config_hash == config_hash)
            )
            record = existing.scalar_one_or_none()
            now = dt.datetime.utcnow()
            if record is None:
                session.add(
                    ConfigRecord(
                        config_hash=config_hash,
                        protocol=protocol,
                        host_encrypted=encrypted_host,
                        port=port,
                        first_seen_at=now,
                        last_seen_at=now,
                        last_score=score,
                    )
                )
            else:
                record.last_seen_at = now
                record.last_score = score
            await session.commit()

    async def record_test_result(
        self,
        config_hash: str,
        tcp_ok: bool,
        tunnel_ok: bool,
        avg_latency_ms: float | None,
        download_mbps: float | None,
        jitter_ms: float | None,
        packet_loss_pct: float,
        country_code: str,
        composite_score: float,
    ) -> None:
        async with self._session() as session:
            session.add(
                TestResultRecord(
                    config_hash=config_hash,
                    tcp_ok=tcp_ok,
                    tunnel_ok=tunnel_ok,
                    avg_latency_ms=avg_latency_ms,
                    download_mbps=download_mbps,
                    jitter_ms=jitter_ms,
                    packet_loss_pct=packet_loss_pct,
                    country_code=country_code,
                    composite_score=composite_score,
                )
            )
            await session.commit()

    async def blacklist(self, config_hash: str, reason: str) -> None:
        async with self._session() as session:
            await session.execute(
                update(ConfigRecord)
                .where(ConfigRecord.config_hash == config_hash)
                .values(is_blacklisted=True, blacklist_reason=reason)
            )
            await session.commit()

    async def log_broadcast(self, message_id: int, config_hashes: list[str]) -> None:
        async with self._session() as session:
            session.add(
                BroadcastLog(
                    message_id=message_id,
                    config_count=len(config_hashes),
                    config_hashes_csv=",".join(config_hashes),
                )
            )
            for h in config_hashes:
                await session.execute(
                    update(ConfigRecord)
                    .where(ConfigRecord.config_hash == h)
                    .values(times_broadcast=ConfigRecord.times_broadcast + 1)
                )
            await session.commit()
