"""Parsers for V2Ray/Xray and MTProto proxy config URIs.

Supported schemes: vmess://, vless://, trojan://, ss://, and
tg://proxy / https://t.me/proxy (MTProto). Reality is represented as a
VLESS config carrying `security=reality` in its query string.

Each parser is defensive: malformed input raises `ConfigParseError`
rather than propagating an opaque exception, so the collector can skip
bad entries without crashing the pipeline.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit


class ConfigParseError(ValueError):
    """Raised when a raw config string cannot be parsed."""


@dataclass
class ParsedConfig:
    """Normalized representation of any supported proxy config."""

    protocol: str  # vmess | vless | trojan | shadowsocks | mtproto
    host: str
    port: int
    identifier: str | None = None  # uuid / password / secret
    encryption: str | None = None  # cipher method / vmess security
    network_type: str | None = None  # tcp / ws / grpc / etc.
    path: str | None = None
    tls: bool = False
    sni: str | None = None
    remark: str = ""
    raw_uri: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def _b64_decode(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode()).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ConfigParseError(f"invalid base64 payload: {exc}") from exc


def parse_vmess(uri: str) -> ParsedConfig:
    """Parse a `vmess://<base64-json>` URI."""
    if not uri.startswith("vmess://"):
        raise ConfigParseError("not a vmess URI")
    payload = uri[len("vmess://"):]
    try:
        data = json.loads(_b64_decode(payload))
    except json.JSONDecodeError as exc:
        raise ConfigParseError(f"invalid vmess json: {exc}") from exc

    try:
        host = str(data["add"])
        port = int(data["port"])
        uuid = str(data["id"])
    except (KeyError, ValueError) as exc:
        raise ConfigParseError(f"missing required vmess field: {exc}") from exc

    return ParsedConfig(
        protocol="vmess",
        host=host,
        port=port,
        identifier=uuid,
        encryption=str(data.get("scy", "auto")),
        network_type=str(data.get("net", "tcp")),
        path=str(data.get("path", "")) or None,
        tls=str(data.get("tls", "")).lower() == "tls",
        sni=str(data.get("sni", "")) or host,
        remark=str(data.get("ps", "")),
        raw_uri=uri,
        extra={"alterId": str(data.get("aid", "0")), "host_header": str(data.get("host", ""))},
    )


def parse_vless(uri: str) -> ParsedConfig:
    """Parse a `vless://uuid@host:port?params#remark` URI (Reality included)."""
    if not uri.startswith("vless://"):
        raise ConfigParseError("not a vless URI")
    parts = urlsplit(uri)
    if not parts.hostname or not parts.port or not parts.username:
        raise ConfigParseError("vless URI missing uuid/host/port")

    query = dict(parse_qsl(parts.query))
    security = query.get("security", "none")
    return ParsedConfig(
        protocol="vless",
        host=parts.hostname,
        port=parts.port,
        identifier=parts.username,
        encryption=security,
        network_type=query.get("type", "tcp"),
        path=query.get("path") or None,
        tls=security in ("tls", "reality"),
        sni=query.get("sni") or parts.hostname,
        remark=unquote(parts.fragment or ""),
        raw_uri=uri,
        extra={
            "flow": query.get("flow", ""),
            "pbk": query.get("pbk", ""),
            "sid": query.get("sid", ""),
            "fp": query.get("fp", ""),
        },
    )


def parse_trojan(uri: str) -> ParsedConfig:
    """Parse a `trojan://password@host:port?params#remark` URI."""
    if not uri.startswith("trojan://"):
        raise ConfigParseError("not a trojan URI")
    parts = urlsplit(uri)
    if not parts.hostname or not parts.port or not parts.username:
        raise ConfigParseError("trojan URI missing password/host/port")

    query = dict(parse_qsl(parts.query))
    return ParsedConfig(
        protocol="trojan",
        host=parts.hostname,
        port=parts.port,
        identifier=parts.username,
        encryption="tls",
        network_type=query.get("type", "tcp"),
        path=query.get("path") or None,
        tls=True,
        sni=query.get("sni") or parts.hostname,
        remark=unquote(parts.fragment or ""),
        raw_uri=uri,
    )


def parse_shadowsocks(uri: str) -> ParsedConfig:
    """Parse an `ss://` URI in either SIP002 or legacy base64 form."""
    if not uri.startswith("ss://"):
        raise ConfigParseError("not a shadowsocks URI")
    body = uri[len("ss://"):]
    remark = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        remark = unquote(frag)

    if "@" in body:
        # SIP002: ss://base64(method:password)@host:port or method:password@host:port
        userinfo, hostport = body.split("@", 1)
        try:
            userinfo = _b64_decode(userinfo)
        except ConfigParseError:
            pass  # userinfo may already be plaintext
        if ":" not in userinfo or ":" not in hostport:
            raise ConfigParseError("malformed shadowsocks SIP002 URI")
        method, password = userinfo.split(":", 1)
        host, port_str = hostport.split(":", 1)
        port_str = port_str.split("/")[0].split("?")[0]
    else:
        # Legacy: ss://base64(method:password@host:port)
        decoded = _b64_decode(body)
        if "@" not in decoded or ":" not in decoded:
            raise ConfigParseError("malformed legacy shadowsocks URI")
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port_str = hostport.split(":", 1)

    try:
        port = int(port_str)
    except ValueError as exc:
        raise ConfigParseError(f"invalid shadowsocks port: {port_str}") from exc

    return ParsedConfig(
        protocol="shadowsocks",
        host=host,
        port=port,
        identifier=password,
        encryption=method,
        network_type="tcp",
        remark=remark,
        raw_uri=uri,
    )


def parse_mtproto(uri: str) -> ParsedConfig:
    """Parse an MTProto proxy link: `tg://proxy?...` or `https://t.me/proxy?...`."""
    parts = urlsplit(uri)
    is_tg_scheme = parts.scheme == "tg" and parts.netloc == "proxy"
    is_https_scheme = parts.scheme == "https" and parts.netloc in ("t.me", "telegram.me")
    if not (is_tg_scheme or (is_https_scheme and parts.path in ("/proxy", "/proxy/"))):
        raise ConfigParseError("not an mtproto proxy URI")

    query = dict(parse_qsl(parts.query))
    host = query.get("server")
    port_str = query.get("port")
    secret = query.get("secret")
    if not host or not port_str or not secret:
        raise ConfigParseError("mtproto URI missing server/port/secret")

    try:
        port = int(port_str)
    except ValueError as exc:
        raise ConfigParseError(f"invalid mtproto port: {port_str}") from exc

    return ParsedConfig(
        protocol="mtproto",
        host=host,
        port=port,
        identifier=secret,
        raw_uri=uri,
    )


_SCHEME_DISPATCH = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "trojan://": parse_trojan,
    "ss://": parse_shadowsocks,
    "tg://proxy": parse_mtproto,
    "https://t.me/proxy": parse_mtproto,
    "https://telegram.me/proxy": parse_mtproto,
}


def parse_any(raw_uri: str) -> ParsedConfig:
    """Dispatch to the correct parser based on URI scheme.

    Args:
        raw_uri: A single-line proxy config URI scraped from a channel.

    Returns:
        A `ParsedConfig` instance.

    Raises:
        ConfigParseError: If the scheme is unrecognized or parsing fails.
    """
    raw_uri = raw_uri.strip()
    for prefix, parser in _SCHEME_DISPATCH.items():
        if raw_uri.startswith(prefix):
            return parser(raw_uri)
    raise ConfigParseError(f"unrecognized config scheme: {raw_uri[:20]!r}")


def extract_candidate_uris(text: str) -> list[str]:
    """Extract plausible config URIs from a raw message body.

    Channels often mix config lines with prose, emojis, and hashtags.
    This scans line-by-line and token-by-token for recognized schemes.
    """
    schemes = ("vmess://", "vless://", "trojan://", "ss://", "tg://proxy", "https://t.me/proxy")
    found: list[str] = []
    for line in text.splitlines():
        for token in line.split():
            token = token.strip().strip(",;")
            if token.startswith(schemes):
                found.append(token)
    return found
