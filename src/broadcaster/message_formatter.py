"""Formats tested/scored configs into polished Persian broadcast messages.

Design goals:
- Config links go in `<code>` blocks for one-tap copy in Telegram clients.
- Any foreign channel tag embedded in a config's remark is stripped and
  replaced with `OWN_CHANNEL_TAG` (configurable via `.env`).
- MTProto proxies get an inline "اتصال خودکار" (auto-connect) button
  using the `tg://proxy?...` deep link.
- Up to `BROADCAST_MAX_CONFIGS_PER_MESSAGE` configs per message; callers
  are responsible for paginating longer batches across messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from telethon.tl.types import KeyboardButtonRow, KeyboardButtonUrl, ReplyInlineMarkup

from src.parsers.config_parser import ParsedConfig
from src.scoring.scorer import ScoreBreakdown
from src.testing.geo import GeoInfo

_PROTOCOL_LABELS = {
    "vmess": "VMess",
    "vless": "VLESS",
    "trojan": "Trojan",
    "shadowsocks": "Shadowsocks",
    "mtproto": "MTProto",
}

# Matches common foreign remark/tag patterns so we can strip them, e.g.
# "@some_channel", "t.me/some_channel", "[Channel Name]".
_FOREIGN_TAG_RE = re.compile(r"(@[\w_]{4,32})|(\bt\.me/\S+)|(\[[^\]]{0,40}\])")


@dataclass
class RankedConfig:
    config: ParsedConfig
    score: ScoreBreakdown
    geo: GeoInfo
    retagged_uri: str


def strip_foreign_tags(text: str) -> str:
    """Remove any embedded channel tags / links from scraped remark text."""
    return _FOREIGN_TAG_RE.sub("", text).strip(" -|_")


def build_remark(config: ParsedConfig, geo: GeoInfo, latency_ms: float | None, own_tag: str) -> str:
    """Build the standardized remark: `🇩🇪 Germany | VLESS | 118ms | @OwnTag`."""
    label = _PROTOCOL_LABELS.get(config.protocol, config.protocol.upper())
    latency_part = f"{int(latency_ms)}ms" if latency_ms is not None else "N/A"
    return f"{geo.flag} {geo.country_name} | {label} | {latency_part} | {own_tag}"


def retag_uri(raw_uri: str, new_remark: str) -> str:
    """Replace a config URI's remark/fragment with our own standardized one.

    MTProto links have no remark fragment and are returned unchanged.
    """
    from urllib.parse import quote, urlsplit

    parts = urlsplit(raw_uri)
    if parts.scheme in ("tg",) or parts.netloc in ("proxy",):
        return raw_uri
    return parts._replace(fragment=quote(new_remark)).geturl()


def format_config_block(ranked: RankedConfig, index: int) -> str:
    """Format a single config's entry within a broadcast message."""
    label = _PROTOCOL_LABELS.get(ranked.config.protocol, ranked.config.protocol.upper())
    score = ranked.score.composite
    latency = ranked.score.as_dict()
    lines = [
        f"<b>{index}. {ranked.geo.flag} {ranked.geo.country_name} — {label}</b>",
        f"امتیاز کیفیت: <b>{score:.0f}/100</b> | تاخیر: {latency['latency']:.0f}%"
        f" | سرعت: {latency['speed']:.0f}%",
        f"<code>{ranked.retagged_uri}</code>",
    ]
    return "\n".join(lines)


def build_broadcast_message(
    ranked_configs: list[RankedConfig], own_tag: str, page: int, total_pages: int
) -> str:
    """Compose the full Persian message body for a batch of configs.

    Args:
        ranked_configs: Configs to include (already limited to the
            per-message batch size by the caller).
        own_tag: Channel tag to display in the footer.
        page: 1-indexed current page number.
        total_pages: Total number of pages in this broadcast cycle.
    """
    header = (
        "✨ <b>بهترین کانفیگ‌های تست‌شده</b> ✨\n"
        f"🕒 به‌روزرسانی خودکار | صفحه {page} از {total_pages}\n"
        "━━━━━━━━━━━━━━━"
    )
    blocks = [format_config_block(rc, idx + 1) for idx, rc in enumerate(ranked_configs)]
    footer = (
        "━━━━━━━━━━━━━━━\n"
        "📌 برای اتصال، روی کانفیگ ضربه بزنید تا کپی شود و در اپلیکیشن خود وارد کنید.\n"
        f"📡 منبع رسمی: {own_tag}"
    )
    return "\n\n".join([header, *blocks, footer])


def build_mtproto_button(ranked: RankedConfig) -> ReplyInlineMarkup:
    """Build an inline 'اتصال خودکار' (auto-connect) button for an MTProto proxy."""
    deep_link = (
        f"tg://proxy?server={ranked.config.host}&port={ranked.config.port}"
        f"&secret={ranked.config.identifier}"
    )
    button = KeyboardButtonUrl(text="⚡️ اتصال خودکار", url=deep_link)
    return ReplyInlineMarkup(rows=[KeyboardButtonRow(buttons=[button])])


def paginate(ranked_configs: list[RankedConfig], batch_size: int) -> list[list[RankedConfig]]:
    """Split a list of ranked configs into fixed-size batches for pagination."""
    return [
        ranked_configs[i : i + batch_size] for i in range(0, len(ranked_configs), batch_size)
    ]
