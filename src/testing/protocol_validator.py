"""Protocol-specific structural validation of parsed configs.

This runs *before* any network test — it rejects configs that are
structurally invalid (bad UUID, empty password, unsupported cipher,
etc.) so we never waste a network round-trip on garbage.
"""

from __future__ import annotations

import re
import uuid as uuid_lib

from src.parsers.config_parser import ParsedConfig

_VALID_SS_METHODS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
}

_VALID_VMESS_SECURITY = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}

_HEX_SECRET_RE = re.compile(r"^(dd)?[0-9a-fA-F]{32,64}$")


class ValidationResult:
    """Outcome of protocol validation."""

    def __init__(self, is_valid: bool, reason: str = "") -> None:
        self.is_valid = is_valid
        self.reason = reason

    def __bool__(self) -> bool:
        return self.is_valid


def _valid_host_port(config: ParsedConfig) -> bool:
    return bool(config.host) and 0 < config.port <= 65535


def validate_vmess(config: ParsedConfig) -> ValidationResult:
    if not _valid_host_port(config):
        return ValidationResult(False, "invalid host/port")
    try:
        uuid_lib.UUID(str(config.identifier))
    except (ValueError, TypeError, AttributeError):
        return ValidationResult(False, "invalid UUID")
    if config.encryption not in _VALID_VMESS_SECURITY:
        return ValidationResult(False, f"unsupported security: {config.encryption}")
    return ValidationResult(True)


def validate_vless(config: ParsedConfig) -> ValidationResult:
    if not _valid_host_port(config):
        return ValidationResult(False, "invalid host/port")
    try:
        uuid_lib.UUID(str(config.identifier))
    except (ValueError, TypeError, AttributeError):
        return ValidationResult(False, "invalid UUID")
    if config.encryption == "reality" and not config.extra.get("pbk"):
        return ValidationResult(False, "reality config missing public key")
    return ValidationResult(True)


def validate_trojan(config: ParsedConfig) -> ValidationResult:
    if not _valid_host_port(config):
        return ValidationResult(False, "invalid host/port")
    if not config.identifier or len(config.identifier) < 4:
        return ValidationResult(False, "password too short or missing")
    return ValidationResult(True)


def validate_shadowsocks(config: ParsedConfig) -> ValidationResult:
    if not _valid_host_port(config):
        return ValidationResult(False, "invalid host/port")
    if not config.identifier:
        return ValidationResult(False, "missing password")
    if config.encryption and config.encryption.lower() not in _VALID_SS_METHODS:
        return ValidationResult(False, f"unsupported cipher: {config.encryption}")
    return ValidationResult(True)


def validate_mtproto(config: ParsedConfig) -> ValidationResult:
    if not _valid_host_port(config):
        return ValidationResult(False, "invalid host/port")
    if not config.identifier or not _HEX_SECRET_RE.match(config.identifier):
        return ValidationResult(False, "invalid mtproto secret format")
    return ValidationResult(True)


_VALIDATORS = {
    "vmess": validate_vmess,
    "vless": validate_vless,
    "trojan": validate_trojan,
    "shadowsocks": validate_shadowsocks,
    "mtproto": validate_mtproto,
}


def validate(config: ParsedConfig) -> ValidationResult:
    """Run the appropriate structural validator for a config's protocol."""
    validator = _VALIDATORS.get(config.protocol)
    if validator is None:
        return ValidationResult(False, f"no validator for protocol: {config.protocol}")
    return validator(config)
