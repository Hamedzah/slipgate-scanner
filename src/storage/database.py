"""Async database access layer.

Wraps a SQLAlchemy async engine/session and exposes small repository
functions used by the rest of the pipeline. Host/port values are
encrypted at rest via `SecretBox` before being persisted, per the
project's security requirements.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.security.crypto import SecretBox
from src.storage.models import Base, BroadcastLog, ConfigRecord, TestResultRecord


class Database:
    """Owns the engine/sessionmaker and exposes repository operations."""

    def __init__(self, database_url: str, secret_box: SecretBox) -> None:
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
