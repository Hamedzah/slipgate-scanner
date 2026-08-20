"""Centralized application configuration.

All runtime configuration is sourced exclusively from environment variables
(via a local `.env` file in development). No secret ever has a hard-coded
default in source control — required secrets have no default at all, which
causes pydantic to fail fast at startup if they are missing.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScoringWeights(BaseSettings):
    """Weights used by the composite scorer. Must sum to ~1.0."""

    latency: float = Field(default=0.25)
    speed: float = Field(default=0.25)
    stability: float = Field(default=0.20)
    geo: float = Field(default=0.15)
    protocol: float = Field(default=0.15)


class Settings(BaseSettings):
    """Top-level application settings, populated from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Telegram credentials (secret) ---
    tg_api_id: int = Field(..., alias="TG_API_ID")
    tg_api_hash: str = Field(..., alias="TG_API_HASH")
    tg_session_string: str = Field(default="", alias="TG_SESSION_STRING")

    # --- Channels (secret list, comma separated in env) ---
    source_channels_raw: str = Field(..., alias="SOURCE_CHANNELS")
    target_channel: str = Field(..., alias="TARGET_CHANNEL")
    own_channel_tag: str = Field(..., alias="OWN_CHANNEL_TAG")

    # --- Scoring ---
    score_threshold: float = Field(default=70.0, alias="SCORE_THRESHOLD")
    weight_latency: float = Field(default=0.25, alias="WEIGHT_LATENCY")
    weight_speed: float = Field(default=0.25, alias="WEIGHT_SPEED")
    weight_stability: float = Field(default=0.20, alias="WEIGHT_STABILITY")
    weight_geo: float = Field(default=0.15, alias="WEIGHT_GEO")
    weight_protocol: float = Field(default=0.15, alias="WEIGHT_PROTOCOL")

    # --- Testing ---
    test_concurrency: int = Field(default=25, alias="TEST_CONCURRENCY")
    test_rounds: int = Field(default=3, alias="TEST_ROUNDS")
    test_timeout_seconds: float = Field(default=10.0, alias="TEST_TIMEOUT_SECONDS")
    speed_test_min_bytes: int = Field(default=5 * 1024 * 1024, alias="SPEED_TEST_MIN_BYTES")
    speed_test_url: str = Field(
        default="https://speed.cloudflare.com/__down?bytes=5242880", alias="SPEED_TEST_URL"
    )
    iran_reference_lat: float = Field(default=35.6892, alias="IRAN_REFERENCE_LAT")
    iran_reference_lon: float = Field(default=51.3890, alias="IRAN_REFERENCE_LON")

    # --- Database ---
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/slipgate.db", alias="DATABASE_URL"
    )

    # --- Security ---
    encryption_key: str = Field(default="", alias="ENCRYPTION_KEY")

    # --- Rate limiting ---
    telegram_max_requests_per_minute: int = Field(
        default=20, alias="TELEGRAM_MAX_REQUESTS_PER_MINUTE"
    )
    broadcast_max_configs_per_message: int = Field(
        default=10, alias="BROADCAST_MAX_CONFIGS_PER_MESSAGE"
    )

    # --- Logging / environment ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    environment: str = Field(default="production", alias="ENVIRONMENT")

    # --- Metrics ---
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    metrics_port: int = Field(default=9090, alias="METRICS_PORT")

    # --- GeoIP ---
    geoip_db_path: str = Field(default="./data/GeoLite2-City.mmdb", alias="GEOIP_DB_PATH")

    @field_validator("score_threshold")
    @classmethod
    def _clamp_threshold(cls, v: float) -> float:
        return max(0.0, min(100.0, v))

    @property
    def source_channels(self) -> list[str]:
        """Parsed, whitespace-trimmed list of source channel identifiers."""
        return [c.strip() for c in self.source_channels_raw.split(",") if c.strip()]

    @property
    def scoring_weights(self) -> ScoringWeights:
        return ScoringWeights(
            latency=self.weight_latency,
            speed=self.weight_speed,
            stability=self.weight_stability,
            geo=self.weight_geo,
            protocol=self.weight_protocol,
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()  # type: ignore[call-arg]
