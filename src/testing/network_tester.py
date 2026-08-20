"""Multi-phase network quality testing for proxy configs.

Two layers of testing are performed:

1. **Direct reachability** — raw TCP connect + TLS handshake timing to
   the proxy's own listening port. Cheap, fast, and catches dead or
   filtered endpoints before we invest in a full tunnel test.
2. **Tunnel testing** — for configs that pass phase 1, we spin up a
   local `xray-core` instance (invoked directly as a subprocess, per
   this project's architecture decision — xray-knife's CLI has proven
   unstable across recent releases) exposing a local SOCKS5 inbound,
   then measure true end-to-end latency and download throughput
   *through* that tunnel via aiohttp + python-socks.

All results are aggregated over multiple rounds (`TEST_ROUNDS`) to
estimate jitter and timeout/packet-loss rate, which the scorer uses as
a stability signal.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import statistics
import tempfile
import time
import uuid as uuid_lib
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp

from src.logging_config import get_logger
from src.parsers.config_parser import ParsedConfig

logger = get_logger(__name__)


@dataclass
class TestResult:
    """Aggregated result of all test phases for a single config."""

    tcp_ok: bool = False
    tls_ok: bool = False
    tcp_connect_ms: float | None = None
    tls_handshake_ms: float | None = None

    tunnel_ok: bool = False
    tunnel_latency_ms: list[float] = field(default_factory=list)
    download_mbps: float | None = None
    upload_mbps: float | None = None

    rounds_attempted: int = 0
    rounds_succeeded: int = 0
    jitter_ms: float | None = None
    packet_loss_pct: float = 100.0

    error: str = ""

    @property
    def avg_latency_ms(self) -> float | None:
        return statistics.fmean(self.tunnel_latency_ms) if self.tunnel_latency_ms else None

    @property
    def is_usable(self) -> bool:
        return self.tcp_ok and self.rounds_succeeded > 0


async def tcp_handshake(host: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Attempt a raw TCP connect and time it."""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        elapsed_ms = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, elapsed_ms
    except (OSError, asyncio.TimeoutError):
        return False, None


async def tls_handshake(host: str, port: int, sni: str | None, timeout: float) -> tuple[bool, float | None]:
    """Attempt a TLS handshake on top of a TCP connect and time it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host),
            timeout=timeout,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, elapsed_ms
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False, None


def _build_xray_config(config: ParsedConfig, local_socks_port: int) -> dict:
    """Translate a ParsedConfig into a minimal xray-core JSON config.

    Only the fields needed to establish an outbound tunnel are set;
    logging is disabled to avoid leaking connection details to disk.
    """
    outbound: dict = {"tag": "proxy"}

    if config.protocol == "vmess":
        outbound["protocol"] = "vmess"
        outbound["settings"] = {
            "vnext": [
                {
                    "address": config.host,
                    "port": config.port,
                    "users": [
                        {
                            "id": config.identifier,
                            "alterId": int(config.extra.get("alterId", "0") or 0),
                            "security": config.encryption or "auto",
                        }
                    ],
                }
            ]
        }
    elif config.protocol == "vless":
        user: dict = {"id": config.identifier, "encryption": "none"}
        if config.extra.get("flow"):
            user["flow"] = config.extra["flow"]
        outbound["protocol"] = "vless"
        outbound["settings"] = {
            "vnext": [{"address": config.host, "port": config.port, "users": [user]}]
        }
    elif config.protocol == "trojan":
        outbound["protocol"] = "trojan"
        outbound["settings"] = {
            "servers": [{"address": config.host, "port": config.port, "password": config.identifier}]
        }
    elif config.protocol == "shadowsocks":
        outbound["protocol"] = "shadowsocks"
        outbound["settings"] = {
            "servers": [
                {
                    "address": config.host,
                    "port": config.port,
                    "method": config.encryption,
                    "password": config.identifier,
                }
            ]
        }
    else:
        raise ValueError(f"xray tunnel testing unsupported for protocol: {config.protocol}")

    stream_settings: dict = {"network": config.network_type or "tcp"}
    if config.tls:
        stream_settings["security"] = config.encryption if config.encryption == "reality" else "tls"
        if config.encryption == "reality":
            stream_settings["realitySettings"] = {
                "serverName": config.sni or config.host,
                "publicKey": config.extra.get("pbk", ""),
                "shortId": config.extra.get("sid", ""),
                "fingerprint": config.extra.get("fp", "chrome"),
            }
        else:
            stream_settings["tlsSettings"] = {"serverName": config.sni or config.host, "allowInsecure": True}
    if (config.network_type or "tcp") == "ws":
        stream_settings["wsSettings"] = {"path": config.path or "/"}
    outbound["streamSettings"] = stream_settings

    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


class XrayTunnelRunner:
    """Manages the lifecycle of a single local xray-core subprocess."""

    def __init__(self, xray_binary: str = "xray") -> None:
        self._xray_binary = xray_binary
        self._process: asyncio.subprocess.Process | None = None
        self._config_path: Path | None = None

    async def start(self, config: ParsedConfig, local_socks_port: int) -> bool:
        xray_config = _build_xray_config(config, local_socks_port)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="slipgate_xray_"
        )
        json.dump(xray_config, tmp)
        tmp.close()
        self._config_path = Path(tmp.name)

        try:
            self._process = await asyncio.create_subprocess_exec(
                self._xray_binary,
                "run",
                "-c",
                str(self._config_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            logger.error("xray_binary_not_found", binary=self._xray_binary)
            return False

        # Give the process a brief moment to bind its local SOCKS inbound.
        for _ in range(20):
            if self._process.returncode is not None:
                return False
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", local_socks_port), timeout=0.25
                )
                writer.close()
                return True
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.25)
        return False

    async def stop(self) -> None:
        if self._process is not None and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self._process.kill()
        if self._config_path is not None:
            self._config_path.unlink(missing_ok=True)

    async def __aenter__(self) -> "XrayTunnelRunner":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()


async def _measure_through_socks(
    local_socks_port: int, speed_test_url: str, min_bytes: int, timeout: float
) -> tuple[float | None, float | None]:
    """Measure latency (ms) and download throughput (Mbps) through a local SOCKS proxy."""
    try:
        from aiohttp_socks import ProxyConnector
    except ImportError:
        logger.warning("aiohttp_socks_not_installed")
        return None, None

    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_socks_port}")
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            start = time.perf_counter()
            async with session.get(
                speed_test_url, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                first_byte_ms = (time.perf_counter() - start) * 1000
                total_bytes = 0
                dl_start = time.perf_counter()
                async for chunk in resp.content.iter_chunked(65536):
                    total_bytes += len(chunk)
                    if total_bytes >= min_bytes:
                        break
                dl_elapsed = max(time.perf_counter() - dl_start, 1e-6)
                mbps = (total_bytes * 8 / 1_000_000) / dl_elapsed
                return first_byte_ms, mbps
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return None, None


async def run_full_test(
    config: ParsedConfig,
    *,
    rounds: int,
    timeout: float,
    speed_test_url: str,
    min_speed_test_bytes: int,
    xray_binary: str = "xray",
    local_socks_port: int = 0,
) -> TestResult:
    """Run the complete multi-phase test suite for one config.

    Args:
        config: Parsed proxy config under test.
        rounds: Number of tunnel-latency rounds for jitter/loss estimation.
        timeout: Per-attempt timeout in seconds.
        speed_test_url: URL used for the download throughput measurement.
        min_speed_test_bytes: Minimum bytes to pull for a valid speed sample.
        xray_binary: Path/name of the xray-core executable.
        local_socks_port: Local port for the ephemeral SOCKS inbound; 0
            lets the OS choose (resolved to an actual free port by the caller).

    Returns:
        A populated `TestResult`.
    """
    result = TestResult()

    if config.protocol == "mtproto":
        # MTProto has no TLS/HTTP tunnel semantics — validate via raw TCP only.
        ok, ms = await tcp_handshake(config.host, config.port, timeout)
        result.tcp_ok = ok
        result.tcp_connect_ms = ms
        result.rounds_attempted = 1
        result.rounds_succeeded = 1 if ok else 0
        result.packet_loss_pct = 0.0 if ok else 100.0
        if not ok:
            result.error = "tcp handshake failed"
        return result

    tcp_ok, tcp_ms = await tcp_handshake(config.host, config.port, timeout)
    result.tcp_ok = tcp_ok
    result.tcp_connect_ms = tcp_ms
    if not tcp_ok:
        result.error = "tcp handshake failed"
        return result

    if config.tls:
        tls_ok, tls_ms = await tls_handshake(config.host, config.port, config.sni, timeout)
        result.tls_ok = tls_ok
        result.tls_handshake_ms = tls_ms

    port = local_socks_port or _pick_free_port()
    async with XrayTunnelRunner(xray_binary=xray_binary) as runner:
        started = await runner.start(config, port)
        if not started:
            result.error = "xray tunnel failed to start"
            return result

        latencies: list[float] = []
        for round_idx in range(rounds):
            result.rounds_attempted += 1
            lat_ms, _ = await _measure_through_socks(port, speed_test_url, 1, timeout)
            if lat_ms is not None:
                latencies.append(lat_ms)
                result.rounds_succeeded += 1
            await asyncio.sleep(0.1)

        result.tunnel_latency_ms = latencies
        result.tunnel_ok = result.rounds_succeeded > 0
        result.packet_loss_pct = (
            100.0 * (result.rounds_attempted - result.rounds_succeeded) / result.rounds_attempted
            if result.rounds_attempted
            else 100.0
        )
        if len(latencies) >= 2:
            result.jitter_ms = statistics.pstdev(latencies)

        if result.tunnel_ok:
            _, mbps = await _measure_through_socks(
                port, speed_test_url, min_speed_test_bytes, timeout * 3
            )
            result.download_mbps = mbps

    return result


def _pick_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
