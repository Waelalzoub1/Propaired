"""Security helpers for startup configuration."""

from __future__ import annotations

import base64
from pathlib import Path

# Always set cookies as HTTPS-only to avoid leaking sessions over plain HTTP.
SESSION_COOKIE_SECURE = True


def _decode_secret(secret_text: str) -> bytes:
    """Decode a URL-safe base64 secret that may omit padding."""

    padding = "=" * (-len(secret_text) % 4)
    return base64.urlsafe_b64decode(secret_text + padding)


def load_session_secret(secret_path: Path) -> bytes:
    """Load the session secret from a file and enforce a 32-byte value."""

    if not secret_path.exists():
        raise RuntimeError(
            "HELPER_SESSION_SECRET file not found. Create one and restart the server."
        )

    secret_text = secret_path.read_text(encoding="utf-8").strip()
    if not secret_text:
        raise RuntimeError("HELPER_SESSION_SECRET file is empty.")

    try:
        secret = _decode_secret(secret_text)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("HELPER_SESSION_SECRET must be URL-safe base64.") from exc

    if len(secret) != 32:
        raise RuntimeError("HELPER_SESSION_SECRET must decode to 32 bytes.")

    return secret
