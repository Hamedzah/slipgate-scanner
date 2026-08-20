from src.config import ScoringWeights
from src.parsers.config_parser import ParsedConfig
from src.scoring.scorer import compute_score, score_geo, score_protocol
from src.testing.geo import GeoInfo
from src.testing.network_tester import TestResult


def _weights() -> ScoringWeights:
    return ScoringWeights(latency=0.25, speed=0.25, stability=0.20, geo=0.15, protocol=0.15)


def test_score_geo_zero_for_iranian_isp():
    geo = GeoInfo(country_code="IR", lat=35.7, lon=51.4, is_iranian_isp=True)
    assert score_geo(geo, 35.6892, 51.3890) == 0.0


def test_score_geo_high_for_nearby_non_iranian():
    geo = GeoInfo(country_code="TR", lat=39.0, lon=35.0, is_iranian_isp=False)
    score = score_geo(geo, 35.6892, 51.3890)
    assert 70 <= score <= 100


def test_score_protocol_reality_beats_plain_vmess():
    reality = ParsedConfig(protocol="vless", host="h", port=443, encryption="reality", tls=True)
    plain_vmess = ParsedConfig(protocol="vmess", host="h", port=443, encryption="auto", tls=False)
    assert score_protocol(reality) > score_protocol(plain_vmess)


def test_compute_score_full_pipeline():
    config = ParsedConfig(
        protocol="vless", host="1.2.3.4", port=443, encryption="tls", tls=True, identifier="uuid"
    )
    result = TestResult(
        tcp_ok=True,
        tunnel_ok=True,
        tunnel_latency_ms=[100.0, 110.0, 105.0],
        download_mbps=25.0,
        rounds_attempted=3,
        rounds_succeeded=3,
        packet_loss_pct=0.0,
        jitter_ms=5.0,
    )
    geo = GeoInfo(country_code="DE", country_name="Germany", lat=52.5, lon=13.4)
    breakdown = compute_score(config, result, geo, _weights(), 35.6892, 51.3890)
    assert 0 <= breakdown.composite <= 100
    assert breakdown.composite > 50  # a solid config should score reasonably well


def test_compute_score_zero_when_untested():
    config = ParsedConfig(protocol="vmess", host="h", port=443)
    result = TestResult()  # no data at all
    geo = GeoInfo()
    breakdown = compute_score(config, result, geo, _weights(), 35.6892, 51.3890)
    assert breakdown.latency_score == 0.0
    assert breakdown.speed_score == 0.0
