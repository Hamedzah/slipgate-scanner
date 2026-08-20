"""Prometheus-style metrics for pipeline observability."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server

configs_collected_total = Counter(
    "slipgate_configs_collected_total", "Raw configs scraped from source channels"
)
configs_deduplicated_total = Counter(
    "slipgate_configs_deduplicated_total", "Configs dropped as duplicates"
)
configs_validated_total = Counter(
    "slipgate_configs_validated_total", "Configs passing structural validation"
)
configs_tested_total = Counter(
    "slipgate_configs_tested_total", "Configs that completed a full test cycle"
)
configs_broadcast_total = Counter(
    "slipgate_configs_broadcast_total", "Configs broadcast to the target channel"
)
test_duration_seconds = Histogram(
    "slipgate_test_duration_seconds", "Time spent testing a single config"
)
cycle_duration_seconds = Histogram(
    "slipgate_cycle_duration_seconds", "Time spent on one full collect-test-broadcast cycle"
)
last_cycle_success = Gauge(
    "slipgate_last_cycle_success", "1 if the last pipeline cycle completed without fatal error"
)


def start_metrics_server(port: int) -> None:
    """Start the Prometheus HTTP exporter in a background thread."""
    start_http_server(port)
