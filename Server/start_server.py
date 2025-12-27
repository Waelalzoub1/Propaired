"""Start the server with SMTP configuration prompts if needed."""

from __future__ import annotations

import os
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SERVER_DIR.parent
CERT_DIR = SERVER_DIR / "certs"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_verify.smtp_setup import CONFIG_PATH, load_env_file, run_setup

REQUIRED_VARS = [
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "APP_BASE_URL",
]


def _detect_cert_pair(cert_dir: Path) -> tuple[str | None, str | None]:
    if not cert_dir.exists():
        return None, None

    files = [path for path in cert_dir.iterdir() if path.is_file()]
    key_candidates: list[Path] = []
    cert_candidates: list[Path] = []
    for path in files:
        suffix = path.suffix.lower()
        name_lower = path.name.lower()
        if suffix == ".key":
            key_candidates.append(path)
            continue
        if suffix in {".pem", ".crt"}:
            if "key" in name_lower:
                key_candidates.append(path)
            else:
                cert_candidates.append(path)

    if not key_candidates or not cert_candidates:
        return None, None

    cert_by_stem = {path.stem: path for path in cert_candidates}

    def _normalize_key_stem(path: Path) -> str:
        stem = path.stem
        lower = stem.lower()
        for suffix in ("-key", "_key"):
            if lower.endswith(suffix):
                return stem[: -len(suffix)]
        return stem

    for key_path in sorted(key_candidates):
        base = _normalize_key_stem(key_path)
        if base in cert_by_stem:
            return str(cert_by_stem[base]), str(key_path)

    if len(cert_candidates) == 1 and len(key_candidates) == 1:
        return str(cert_candidates[0]), str(key_candidates[0])

    def pick(paths: list[Path]) -> Path:
        preferred = [path for path in paths if "localhost" in path.name.lower()]
        return sorted(preferred or paths)[0]

    return str(pick(cert_candidates)), str(pick(key_candidates))


def _missing_vars() -> list[str]:
    return [var for var in REQUIRED_VARS if not os.environ.get(var)]


def main() -> None:
    load_env_file(CONFIG_PATH)
    missing = _missing_vars()
    if missing:
        print("SMTP settings are missing:", ", ".join(missing))
        run_setup()
        load_env_file(CONFIG_PATH)
        missing = _missing_vars()
        if missing:
            raise SystemExit("SMTP configuration incomplete. Aborting.")

    cert_file = os.environ.get("SSL_CERT_FILE")
    key_file = os.environ.get("SSL_KEY_FILE")
    if not cert_file or not key_file:
        detected_cert, detected_key = _detect_cert_pair(CERT_DIR)
        cert_file = cert_file or detected_cert
        key_file = key_file or detected_key

    args = sys.argv[1:]
    if not args:
        args = ["main:app", "--reload", "--app-dir", str(SERVER_DIR)]

    if cert_file and key_file and "--ssl-certfile" not in args and "--ssl-keyfile" not in args:
        args += ["--ssl-certfile", cert_file, "--ssl-keyfile", key_file]

    os.execvp(sys.executable, [sys.executable, "-m", "uvicorn", *args])


if __name__ == "__main__":
    main()
