"""One-time code helpers for email verification and password reset."""

from __future__ import annotations

import hashlib
import secrets
import time

VERIFICATION_CODE_TTL_SECONDS = 60 * 30
RESET_CODE_TTL_SECONDS = 60 * 15


def _generate_numeric_code(length: int = 6) -> str:
    """Return a numeric code of the given length."""

    start = 10 ** (length - 1)
    end = (10 ** length) - 1
    return str(secrets.randbelow(end - start + 1) + start)


def hash_verification_code(code: str) -> str:
    """Hash a verification code so it can be stored safely."""

    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def generate_verification_code() -> tuple[str, str, int]:
    """Return a new verification code, its hash, and its expiry timestamp."""

    code = _generate_numeric_code()
    code_hash = hash_verification_code(code)
    expires_at = int(time.time()) + VERIFICATION_CODE_TTL_SECONDS
    return code, code_hash, expires_at


def generate_reset_code() -> tuple[str, str, int]:
    """Return a new password reset code, its hash, and its expiry timestamp."""

    code = _generate_numeric_code()
    code_hash = hash_verification_code(code)
    expires_at = int(time.time()) + RESET_CODE_TTL_SECONDS
    return code, code_hash, expires_at


def is_code_expired(expires_at: int | None) -> bool:
    """Return True if the expiry timestamp has passed."""

    if not expires_at:
        return True
    return int(time.time()) > int(expires_at)
