"""Structured logging configuration.

Uses `structlog` to emit JSON logs in production and human-readable
console output in development. A processor strips known secret field
names so credentials can never leak into log output, even by accident.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_SECRET_KEYS = {
    "tg_api_hash",
    "tg_session_string",
    "api_hash",
    "session_string",
    "encryption_key",
    "password",
    "uuid",
    "token",
    "bot_token",
}


def _redact_secrets(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict.keys()):
        if key.lower() in _SECRET_KEYS:
            event_dict[key] = "***REDACTED***"
    return event_dict


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure structlog + stdlib logging for the whole process.

    Args:
        level: Standard logging level name, e.g. "INFO" or "DEBUG".
        fmt: Either "json" (production) or "console" (development).
    """
    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=getattr(logging, level.upper(), logging.INFO)
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        _redact_secrets,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if fmt == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
