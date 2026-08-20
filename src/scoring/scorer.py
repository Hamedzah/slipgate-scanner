"""Composite scoring for tested proxy configs.

The final score (0-100) is a weighted sum of five normalized
sub-scores. Weights are configurable via `.env` (see `ScoringWeights`)
and default to values reflecting general network-engineering priorities
for interactive + bulk-transfer usage:

- **Latency (25%)** — lower is better; interactive use (messaging,
  browsing) is latency-sensitive above almost everything else.
- **Speed (25%)** — download throughput; matters for media/file use.
- **Stability (20%)** — jitter + packet/round loss; a fast-but-flaky
  proxy is worse in practice than a slightly slower stable one.
- **Geo (15%)** — proximity to Iran and confirmed non-Iranian ISP;
  closer generally means lower latency headroom and better routing.
- **Protocol (15%)** — structural/security quality of the config
  itself (e.g. Reality > plain TLS > no TLS; strong AEAD cipher > weak).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.config import ScoringWeights
from src.parsers.config_parser import ParsedConfig
from src.testing.geo import GeoInfo, haversine_km
from src.testing.network_tester import TestResult

# Reference maximums used to normalize raw metrics into a 0-100 sub-score.
_MAX_ACCEPTABLE_LATENCY_MS = 800.0
_MAX_USEFUL_SPEED_MBPS = 50.0
_MAX_ACCEPTABLE_JITTER_MS = 200.0
_MAX_RELEVANT_DISTANCE_KM = 12000.0

_PROTOCOL_BASE_SCORE = {
    "reality": 100.0,
    "vless": 85.0,
    "vmess": 75.0,
    "trojan": 80.0,
    "shadowsocks": 70.0,
    "mtproto": 55.0,
}


@dataclass
class ScoreBreakdown:
    latency_score: float
    speed_score: float
    stability_score: float
    geo_score: float
    protocol_score: float
    composite: float

    def as_dict(self) -> dict[str, float]:
        return {
            "latency": round(self.latency_score, 1),
            "speed": round(self.speed_score, 1),
            "stability": round(self.stability_score, 1),
            "geo": round(self.geo_score, 1),
            "protocol": round(self.protocol_score, 1),
            "composite": round(self.composite, 1),
        }


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_latency(result: TestResult) -> float:
    latency = result.avg_latency_ms
    if latency is None:
        return 0.0
    return _clamp(100.0 * (1 - latency / _MAX_ACCEPTABLE_LATENCY_MS))


def score_speed(result: TestResult) -> float:
    if result.download_mbps is None:
        return 0.0
    return _clamp(100.0 * (result.download_mbps / _MAX_USEFUL_SPEED_MBPS))


def score_stability(result: TestResult) -> float:
    if result.rounds_attempted == 0:
        return 0.0
    loss_score = _clamp(100.0 - result.packet_loss_pct)
    jitter = result.jitter_ms or 0.0
    jitter_score = _clamp(100.0 * (1 - jitter / _MAX_ACCEPTABLE_JITTER_MS))
    return _clamp(0.6 * loss_score + 0.4 * jitter_score)


def score_geo(geo: GeoInfo, iran_lat: float, iran_lon: float) -> float:
    if geo.is_iranian_isp:
        # A proxy whose exit is itself inside an Iranian ISP provides no
        # circumvention value — score it at zero regardless of distance.
        return 0.0
    if geo.lat == 0.0 and geo.lon == 0.0:
        return 40.0  # unknown location: neutral-low score, not zero
    distance = haversine_km(iran_lat, iran_lon, geo.lat, geo.lon)
    # Moderate distance (regional neighbors, e.g. Turkey/UAE/Europe) tends to
    # offer the best latency/availability trade-off; extremely far exits
    # (e.g. South America) still score reasonably but not maximally.
    return _clamp(100.0 - 60.0 * (distance / _MAX_RELEVANT_DISTANCE_KM))


def score_protocol(config: ParsedConfig) -> float:
    key = "reality" if config.encryption == "reality" else config.protocol
    base = _PROTOCOL_BASE_SCORE.get(key, 50.0)
    if config.protocol in ("vmess", "vless", "trojan") and not config.tls and key != "reality":
        base -= 20.0  # no transport encryption beyond the protocol layer
    return _clamp(base)


def compute_score(
    config: ParsedConfig,
    result: TestResult,
    geo: GeoInfo,
    weights: ScoringWeights,
    iran_lat: float,
    iran_lon: float,
) -> ScoreBreakdown:
    """Compute the full weighted composite score for a tested config."""
    latency_score = score_latency(result)
    speed_score = score_speed(result)
    stability_score = score_stability(result)
    geo_score = score_geo(geo, iran_lat, iran_lon)
    protocol_score = score_protocol(config)

    composite = (
        weights.latency * latency_score
        + weights.speed * speed_score
        + weights.stability * stability_score
        + weights.geo * geo_score
        + weights.protocol * protocol_score
    )

    return ScoreBreakdown(
        latency_score=latency_score,
        speed_score=speed_score,
        stability_score=stability_score,
        geo_score=geo_score,
        protocol_score=protocol_score,
        composite=_clamp(composite),
    )
