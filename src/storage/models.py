"""SQLAlchemy ORM models for history, blacklist, and test-result tracking."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ConfigRecord(Base):
    """One row per unique (deduplicated) config ever seen."""

    __tablename__ = "configs"
    __table_args__ = (UniqueConstraint("config_hash", name="uq_config_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    config_hash: Mapped[str] = mapped_column(String(64), index=True)
    protocol: Mapped[str] = mapped_column(String(32))
    host_encrypted: Mapped[str] = mapped_column(String(512))
    port: Mapped[int] = mapped_column(Integer)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    last_score: Mapped[float] = mapped_column(Float, default=0.0)
    times_broadcast: Mapped[int] = mapped_column(Integer, default=0)
    is_blacklisted: Mapped[bool] = mapped_column(Boolean, default=False)
    blacklist_reason: Mapped[str] = mapped_column(String(256), default="")


class TestResultRecord(Base):
    """One row per test run against a config."""

    __tablename__ = "test_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    config_hash: Mapped[str] = mapped_column(String(64), index=True)
    tested_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    tcp_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    tunnel_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    avg_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    download_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    jitter_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_pct: Mapped[float] = mapped_column(Float, default=100.0)
    country_code: Mapped[str] = mapped_column(String(4), default="XX")
    composite_score: Mapped[float] = mapped_column(Float, default=0.0)


class BroadcastLog(Base):
    """Audit log of every broadcast message sent."""

    __tablename__ = "broadcast_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sent_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    message_id: Mapped[int] = mapped_column(Integer)
    config_count: Mapped[int] = mapped_column(Integer)
    config_hashes_csv: Mapped[str] = mapped_column(String(4096))
