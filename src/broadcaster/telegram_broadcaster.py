"""Publishes ranked, formatted configs to the target Telegram channel."""

from __future__ import annotations

from telethon import TelegramClient

from src.broadcaster.message_formatter import (
    RankedConfig,
    build_broadcast_message,
    build_mtproto_button,
    paginate,
)
from src.logging_config import get_logger
from src.utils.rate_limiter import TokenBucketRateLimiter

logger = get_logger(__name__)


class TelegramBroadcaster:
    """Sends paginated broadcast messages to the configured target channel."""

    def __init__(
        self,
        client: TelegramClient,
        target_channel: str,
        own_tag: str,
        max_per_message: int,
        rate_limiter: TokenBucketRateLimiter,
    ) -> None:
        self._client = client
        self._target_channel = target_channel
        self._own_tag = own_tag
        self._max_per_message = max_per_message
        self._rate_limiter = rate_limiter

    async def broadcast(self, ranked_configs: list[RankedConfig]) -> list[int]:
        """Send one or more paginated messages for the given ranked configs.

        MTProto entries are sent as individual messages (each carrying its
        own inline auto-connect button) rather than batched, since inline
        buttons attach to a single message.

        Returns:
            List of sent message IDs, for audit logging.
        """
        sent_ids: list[int] = []

        mtproto = [rc for rc in ranked_configs if rc.config.protocol == "mtproto"]
        others = [rc for rc in ranked_configs if rc.config.protocol != "mtproto"]

        batches = paginate(others, self._max_per_message)
        total_pages = len(batches) or 1
        for page_idx, batch in enumerate(batches, start=1):
            text = build_broadcast_message(batch, self._own_tag, page_idx, total_pages)
            msg_id = await self._send(text)
            if msg_id is not None:
                sent_ids.append(msg_id)

        for rc in mtproto:
            text = build_broadcast_message([rc], self._own_tag, 1, 1)
            markup = build_mtproto_button(rc)
            msg_id = await self._send(text, buttons=markup)
            if msg_id is not None:
                sent_ids.append(msg_id)

        return sent_ids

    async def _send(self, text: str, buttons: object | None = None) -> int | None:
        await self._rate_limiter.acquire()
        try:
            message = await self._client.send_message(
                self._target_channel, text, parse_mode="html", buttons=buttons, link_preview=False
            )
            return message.id
        except Exception as exc:  # noqa: BLE001 - a single failed send shouldn't kill the cycle
            logger.error("broadcast_send_failed", error=str(exc))
            return None
