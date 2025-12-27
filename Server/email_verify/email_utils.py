"""SMTP email helpers."""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def _get_bool(env_value: str | None, default: bool = False) -> bool:
    if env_value is None:
        return default
    return env_value.strip().lower() in {"1", "true", "yes", "on"}


def send_verification_email(to_address: str, code: str, role: str) -> None:
    """Send a verification code email using SMTP settings from environment variables."""

    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        raise RuntimeError("SMTP_HOST is not configured.")

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    smtp_from = os.environ.get("SMTP_FROM") or smtp_user

    use_tls = _get_bool(os.environ.get("SMTP_USE_TLS"), default=True)
    use_ssl = _get_bool(os.environ.get("SMTP_USE_SSL"), default=False)

    subject = "Your verification code for The Helper"
    role_label = "helper" if role == "helper" else "customer"
    body = "\n".join(
        [
            "Hi there,",
            "",
            f"Please verify your email to activate your {role_label} account.",
            "Use this verification code:",
            code,
            "",
            "If you did not request this, you can ignore this email.",
        ]
    )

    if not smtp_from:
        raise RuntimeError("SMTP_FROM (or SMTP_USER) must be set.")

    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    if use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as client:
            if smtp_user:
                client.login(smtp_user, smtp_password)
            client.send_message(message)
        return

    with smtplib.SMTP(smtp_host, smtp_port) as client:
        if use_tls:
            client.starttls(context=ssl.create_default_context())
        if smtp_user:
            client.login(smtp_user, smtp_password)
        client.send_message(message)


def send_reset_email(to_address: str, code: str, role: str) -> None:
    """Send a password reset code email."""

    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        raise RuntimeError("SMTP_HOST is not configured.")

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    smtp_from = os.environ.get("SMTP_FROM") or smtp_user

    use_tls = _get_bool(os.environ.get("SMTP_USE_TLS"), default=True)
    use_ssl = _get_bool(os.environ.get("SMTP_USE_SSL"), default=False)

    role_label = "helper" if role == "helper" else "customer"
    subject = "Reset your password for The Helper"
    body = "\n".join(
        [
            "Hi there,",
            "",
            f"We received a request to reset your {role_label} account password.",
            "Use this password reset code:",
            code,
            "",
            "If you did not request this, you can ignore this email.",
        ]
    )

    if not smtp_from:
        raise RuntimeError("SMTP_FROM (or SMTP_USER) must be set.")

    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    if use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as client:
            if smtp_user:
                client.login(smtp_user, smtp_password)
            client.send_message(message)
        return

    with smtplib.SMTP(smtp_host, smtp_port) as client:
        if use_tls:
            client.starttls(context=ssl.create_default_context())
        if smtp_user:
            client.login(smtp_user, smtp_password)
        client.send_message(message)

