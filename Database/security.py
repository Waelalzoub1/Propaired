import base64
import hashlib
import hmac
import secrets

_PREFIX = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 200_000


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def is_password_hashed(stored: str) -> bool:
    return stored.startswith(f"{_PREFIX}$")


def hash_password(plain: str, iterations: int = _DEFAULT_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
    return f"{_PREFIX}${iterations}${_b64_encode(salt)}${_b64_encode(digest)}"


def verify_password(stored: str, provided: str) -> bool:
    if not stored:
        return False
    if not is_password_hashed(stored):
        return hmac.compare_digest(stored, provided)
    try:
        _, iterations, salt_b64, hash_b64 = stored.split("$", 3)
        rounds = int(iterations)
    except ValueError:
        return False
    salt = _b64_decode(salt_b64)
    expected = _b64_decode(hash_b64)
    digest = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(digest, expected)
