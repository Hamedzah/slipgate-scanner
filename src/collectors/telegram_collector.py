"""Telegram channel collector.

Connects using a pre-generated Telethon session string (see
`scripts/generate_session.py`), joins configured source channels
(public handles or private invite links), and yields recent messages
for downstream config extraction.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from telethon import TelegramClient
from telethon.errors import (
    FloodWaitError,
    InviteHashExpiredError,
    UserAlreadyParticipantError,
)
from telethon.tl.functions.messages import ImportChatInviteRequest
from telethon.tl.types import Message

from src.logging_config import get_logger
from src.utils.rate_limiter import TokenBucketRateLimiter

logger = get_logger(__name__)


class TelegramCollector:
    """Joins source channels and iterates their recent messages."""

    def __init__(
        self,
        api_id: int,
        api_hash: str,
        session_string: str,
        rate_limiter: TokenBucketRateLimiter,
    ) -> None:
        # StringSession keeps the session entirely in memory / env, never
        # writing a `.session` file that could leak credentials to disk.
        from telethon.sessions import StringSession

        self._client = TelegramClient(StringSession(session_string), api_id, api_hash)
        self._rate_limiter = rate_limiter

    async def __aenter__(self) -> "TelegramCollector":
        await self._client.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._client.disconnect()

    async def ensure_joined(self, channel_ref: str) -> bool:
        """Join a channel if not already a member.

        Supports both public handles (`@name`) and private invite links
        (`https://t.me/+hash` or `https://t.me/joinchat/hash`).

        Returns:
            True if we ended up joined (or already were), False otherwise.
        """
        await self._rate_limiter.acquire()
        try:
            if "joinchat/" in channel_ref or "/+" in channel_ref:
                invite_hash = channel_ref.rsplit("/", 1)[-1].lstrip("+")
                try:
                    await self._client(ImportChatInviteRequest(invite_hash))
                except UserAlreadyParticipantError:
                    pass
                except InviteHashExpiredError:
                    logger.warning("invite_link_expired", channel=_mask(channel_ref))
                    return False
            else:
                await self._client.get_entity(channel_ref)
            return True
        except FloodWaitError as exc:
            logger.warning("flood_wait_on_join", channel=_mask(channel_ref), seconds=exc.seconds)
            return False
        except Exception as exc:  # noqa: BLE001 - joining is best-effort per channel
            logger.warning("join_failed", channel=_mask(channel_ref), error=str(exc))
            return False

    async def iter_recent_messages(
        self, channel_ref: str, limit: int = 200
    ) -> AsyncIterator[Message]:
        """Yield recent messages from a channel, oldest first is not guaranteed."""
        await self._rate_limiter.acquire()
        try:
            async for message in self._client.iter_messages(channel_ref, limit=limit):
                if message is not None and message.text:
                    yield message
        except FloodWaitError as exc:
            logger.warning("flood_wait_on_fetch", channel=_mask(channel_ref), seconds=exc.seconds)
        except Exception as exc:  # noqa: BLE001
            logger.warning("fetch_failed", channel=_mask(channel_ref), error=str(exc))


def _mask(channel_ref: str) -> str:
    """Mask a channel reference for logs so private invite hashes never leak."""
    if "joinchat/" in channel_ref or "/+" in channel_ref:
        return "<private-invite-link>"
    return channel_ref
