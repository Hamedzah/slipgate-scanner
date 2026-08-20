"""Symmetric encryption for sensitive data stored at rest (e.g. channel IDs).

Uses Fernet (AES-128-CBC + HMAC) from the `cryptography` package. The key
is never hard-coded — it must be supplied via `ENCRYPTION_KEY` in the
environment. If unset, a fresh key is generated at process start and a
warning is logged (data encrypted this way will not be readable across
restarts, so operators should always set a persistent key in production).
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from src.logging_config import get_logger

logger = get_logger(__name__)


class SecretBox:
    """Thin wrapper around Fernet for encrypting/decrypting small secrets."""

    def __init__(self, key: str | None) -> None:
        if not key:
            logger.warning(
                "encryption_key_missing",
                message="ENCRYPTION_KEY not set; generating an ephemeral key. "
                "Set ENCRYPTION_KEY in .env for persistent encrypted storage.",
            )
            key = Fernet.generate_key().decode()
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a UTF-8 string, returning a urlsafe base64 token."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        """Decrypt a token previously produced by `encrypt`.

        Raises:
            ValueError: If the token is invalid or was encrypted with a
                different key.
        """
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt: invalid token or wrong key") from exc

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet key suitable for ENCRYPTION_KEY."""
        return Fernet.generate_key().decode("utf-8")
