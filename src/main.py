"""Pipeline orchestrator: collect → parse → dedup → validate → test →
score → broadcast.

Entry point for both a single run (`python -m src.main --once`) and a
long-lived loop suitable for a container (`python -m src.main`), though
in this project's deployed form the loop is instead driven externally
by a scheduled GitHub Actions workflow running one cycle every 4 hours.
"""

from __future__ import annotations

import argparse
import asyncio
import time

import aiohttp

from src.broadcaster.message_formatter import RankedConfig, retag_uri
from src.broadcaster.telegram_broadcaster import TelegramBroadcaster
from src.collectors.telegram_collector import TelegramCollector
from src.config import Settings, get_settings
from src.logging_config import configure_logging, get_logger
from src.parsers.config_parser import ConfigParseError, ParsedConfig, extract_candidate_uris, parse_any
from src.scoring.scorer import compute_score
from src.security.crypto import SecretBox
from src.storage.database import Database
from src.testing.geo import OfflineGeoResolver, resolve_geo
from src.testing.network_tester import run_full_test
from src.testing.protocol_validator import validate
from src.utils.hashing import compute_config_hash
from src.utils.metrics import (
    configs_broadcast_total,
    configs_collected_total,
    configs_deduplicated_total,
    configs_tested_total,
    configs_validated_total,
    cycle_duration_seconds,
    last_cycle_success,
    start_metrics_server,
)
from src.utils.rate_limiter import TokenBucketRateLimiter

logger = get_logger(__name__)


async def collect_candidate_uris(settings: Settings, collector: TelegramCollector) -> list[str]:
    """Join all source channels and gather candidate proxy URIs from recent messages."""
    candidates: list[str] = []
    for channel in settings.source_channels:
        joined = await collector.ensure_joined(channel)
        if not joined:
            continue
        async for message in collector.iter_recent_messages(channel, limit=200):
            candidates.extend(extract_candidate_uris(message.text))
    return candidates


def parse_and_dedup(raw_uris: list[str]) -> dict[str, ParsedConfig]:
    """Parse raw URIs and deduplicate by SHA-256 of the normalized config."""
    seen: dict[str, ParsedConfig] = {}
    for uri in raw_uris:
        configs_collected_total.inc()
        try:
            config = parse_any(uri)
        except ConfigParseError as exc:
            logger.debug("parse_failed", error=str(exc))
            continue
        config_hash = compute_config_hash(config)
        if config_hash in seen:
            configs_deduplicated_total.inc()
            continue
        seen[config_hash] = config
    return seen


async def test_and_score(
    settings: Settings,
    configs_by_hash: dict[str, ParsedConfig],
    db: Database,
) -> list[RankedConfig]:
    """Run structural validation, network testing, geo lookup, and scoring."""
    weights = settings.scoring_weights
    offline_geo = OfflineGeoResolver(settings.geoip_db_path)
    ranked: list[RankedConfig] = []

    semaphore = asyncio.Semaphore(settings.test_concurrency)

    async with aiohttp.ClientSession() as http_session:

        async def process(config_hash: str, config: ParsedConfig) -> None:
            if await db.is_blacklisted(config_hash):
                return

            validation = validate(config)
            if not validation:
                logger.debug("validation_failed", protocol=config.protocol, reason=validation.reason)
                return
            configs_validated_total.inc()

            async with semaphore:
                result = await run_full_test(
                    config,
                    rounds=settings.test_rounds,
                    timeout=settings.test_timeout_seconds,
                    speed_test_url=settings.speed_test_url,
                    min_speed_test_bytes=settings.speed_test_min_bytes,
                )
            configs_tested_total.inc()

            if not result.is_usable:
                await db.blacklist(config_hash, reason=result.error or "unusable")
                return

            geo = await resolve_geo(http_session, config.host, offline_geo)
            score = compute_score(
                config,
                result,
                geo,
                weights,
                settings.iran_reference_lat,
                settings.iran_reference_lon,
            )

            await db.upsert_config_seen(
                config_hash, config.protocol, config.host, config.port, score.composite
            )
            await db.record_test_result(
                config_hash,
                result.tcp_ok,
                result.tunnel_ok,
                result.avg_latency_ms,
                result.download_mbps,
                result.jitter_ms,
                result.packet_loss_pct,
                geo.country_code,
                score.composite,
            )

            if score.composite < settings.score_threshold:
                return

            remark = f"{geo.flag} {geo.country_name} | {config.protocol.upper()}"
            retagged = retag_uri(config.raw_uri, remark + f" | {settings.own_channel_tag}")
            ranked.append(RankedConfig(config=config, score=score, geo=geo, retagged_uri=retagged))

        await asyncio.gather(*(process(h, c) for h, c in configs_by_hash.items()))

    ranked.sort(key=lambda rc: rc.score.composite, reverse=True)
    return ranked


async def run_cycle(settings: Settings) -> None:
    """Execute exactly one full collect → test → broadcast cycle."""
    start = time.perf_counter()
    secret_box = SecretBox(settings.encryption_key)
    db = Database(settings.database_url, secret_box)
    await db.init_models()

    telegram_rate_limiter = TokenBucketRateLimiter(settings.telegram_max_requests_per_minute, 60.0)

    try:
        async with TelegramCollector(
            settings.tg_api_id,
            settings.tg_api_hash,
            settings.tg_session_string,
            telegram_rate_limiter,
        ) as collector:
            raw_uris = await collect_candidate_uris(settings, collector)
            logger.info("collection_complete", candidate_count=len(raw_uris))

            configs_by_hash = parse_and_dedup(raw_uris)
            logger.info("dedup_complete", unique_configs=len(configs_by_hash))

            ranked = await test_and_score(settings, configs_by_hash, db)
            logger.info("testing_complete", passing_configs=len(ranked))

            if ranked:
                broadcaster = TelegramBroadcaster(
                    collector._client,  # reuse the authenticated client
                    settings.target_channel,
                    settings.own_channel_tag,
                    settings.broadcast_max_configs_per_message,
                    telegram_rate_limiter,
                )
                sent_ids = await broadcaster.broadcast(ranked)
                configs_broadcast_total.inc(len(ranked))
                await db.log_broadcast(
                    sent_ids[0] if sent_ids else 0,
                    [compute_config_hash(rc.config) for rc in ranked],
                )
                logger.info("broadcast_complete", messages_sent=len(sent_ids))

        last_cycle_success.set(1)
    except Exception:
        last_cycle_success.set(0)
        logger.exception("cycle_failed")
        raise
    finally:
        await db.dispose()
        cycle_duration_seconds.observe(time.perf_counter() - start)


async def main_async(run_once: bool, cycle_interval_seconds: float) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)

    if settings.metrics_enabled:
        start_metrics_server(settings.metrics_port)

    if run_once:
        await run_cycle(settings)
        return

    while True:
        await run_cycle(settings)
        await asyncio.sleep(cycle_interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="SlipGate proxy scanner & broadcaster")
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    parser.add_argument(
        "--interval", type=float, default=4 * 3600, help="Seconds between cycles in loop mode"
    )
    args = parser.parse_args()
    asyncio.run(main_async(run_once=args.once, cycle_interval_seconds=args.interval))


if __name__ == "__main__":
    main()
