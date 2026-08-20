"""One-time local helper to generate a Telethon StringSession.

Run this manually on your own machine (never in CI):

    python scripts/generate_session.py

It will prompt for your phone number and login code (and 2FA password
if enabled), then print a session string to paste into the
`TG_SESSION_STRING` GitHub Secret. The string is equivalent to a login
credential — treat it exactly like a password and never commit it.
"""

from __future__ import annotations

import asyncio
import os

from telethon import TelegramClient
from telethon.sessions import StringSession


async def main() -> None:
    api_id = int(os.environ.get("TG_API_ID") or input("API ID: ").strip())
    api_hash = os.environ.get("TG_API_HASH") or input("API Hash: ").strip()

    async with TelegramClient(StringSession(), api_id, api_hash) as client:
        session_string = client.session.save()
        print("\n=== Copy the line below into TG_SESSION_STRING (GitHub Secret) ===\n")
        print(session_string)
        print("\n====================================================================")
        print("WARNING: this string grants full account access. Store it only in")
        print("GitHub Secrets / your local .env — never commit it or paste it anywhere else.")


if __name__ == "__main__":
    asyncio.run(main())
