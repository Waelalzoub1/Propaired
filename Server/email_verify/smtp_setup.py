"""Interactive SMTP setup for local development."""

from __future__ import annotations

from pathlib import Path
import getpass
import os
import sys

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "smtp.env"


def load_env_file(path: Path = CONFIG_PATH) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def _prompt(label: str, default: str | None = None, required: bool = True) -> str:
    while True:
        if default:
            value = input(f"{label} [{default}]: ").strip()
            if not value:
                value = default
        else:
            value = input(f"{label}: ").strip()
        if value or not required:
            return value
        print("Value required. Please try again.")


def _prompt_yes_no(label: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def run_setup() -> Path:
    if not sys.stdin.isatty():
        raise SystemExit("SMTP setup requires an interactive terminal.")

    print("Configure SMTP settings for email verification.")
    host = _prompt("SMTP host (e.g. smtp.gmail.com)")
    port = _prompt("SMTP port", default="587")
    user = _prompt("SMTP username/email")
    password = getpass.getpass("SMTP password (input hidden): ").strip()
    while not password:
        print("Password required.")
        password = getpass.getpass("SMTP password (input hidden): ").strip()
    from_address = _prompt("From address", default=user)
    base_url = _prompt("Public app URL (e.g. https://your-domain.com)")

    use_ssl_default = port == "465"
    use_ssl = _prompt_yes_no("Use SSL (port 465)", default=use_ssl_default)
    use_tls_default = not use_ssl
    use_tls = _prompt_yes_no("Use TLS STARTTLS (port 587)", default=use_tls_default)

    lines = [
        f"SMTP_HOST={host}",
        f"SMTP_PORT={port}",
        f"SMTP_USER={user}",
        f"SMTP_PASSWORD={password}",
        f"SMTP_FROM={from_address}",
        f"SMTP_USE_TLS={'true' if use_tls else 'false'}",
        f"SMTP_USE_SSL={'true' if use_ssl else 'false'}",
        f"APP_BASE_URL={base_url}",
    ]

    CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except PermissionError:
        pass
    print(f"Saved SMTP configuration to {CONFIG_PATH}")
    return CONFIG_PATH


if __name__ == "__main__":
    run_setup()
