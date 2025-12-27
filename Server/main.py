"""The Helper web server.

This file defines every web page and API endpoint for the project.
If you are new to web development:
- Each @app.get or @app.post line creates a URL you can open in the browser.
- We use HTML templates for pages and JSON for data APIs.
- A signed cookie keeps users logged in between visits.
"""


from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import math
import os
import re
import sys
import time
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Annotated, Any, Dict, Optional
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel

# --- Project path setup ----------------------------------------------------
# We add the project root to sys.path so absolute imports keep working,
# even when this file is run directly (python main.py).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_ROOT = Path(__file__).resolve().parent
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load SMTP env file automatically for direct uvicorn/fastapi runs.
from email_verify.smtp_setup import CONFIG_PATH as SMTP_ENV_PATH, load_env_file

load_env_file(SMTP_ENV_PATH)
INTEGRATIONS_ENV_PATH = SERVER_ROOT / "config" / "integrations.env"
load_env_file(INTEGRATIONS_ENV_PATH)

# --- Database layer imports ------------------------------------------------
# These functions read and write our stored data (users, jobs, chats, etc.).
from Database.customer_database import (
    create_customer,
    create_job,
    delete_job,
    delete_customer,
    get_customer_auth_info,
    get_customer_password,
    get_customer_profile,
    has_customer_posted_job,
    get_job,
    get_job_payment,
    list_customers,
    list_all_jobs,
    list_jobs_for_customer,
    mark_customer_verified,
    search_jobs as search_customer_jobs,
    set_job_payment_intent,
    update_job_location_coords,
    update_job_payment_status,
    update_job_transfer,
    set_job_completion,
    set_customer_verification,
    set_customer_reset_code,
    update_customer_admin,
    update_customer_email,
    update_customer_full_name,
    update_customer_password,
    update_customer_reset_sent_at,
    update_customer_verification_sent_at,
    clear_customer_reset_code,
    update_job_status,
)
from Database.database import (
    append_chat_message,
    add_helper_credential,
    add_helper_image,
    create_user,
    delete_chat_record,
    delete_helper_credential,
    delete_helper_image,
    delete_helper_review,
    delete_user,
    get_chat,
    get_or_create_chat,
    get_user_auth_info,
    get_user_password,
    get_user_profile,
    get_user_stripe_info,
    get_last_sender_message_epoch,
    get_helper_background_check,
    set_helper_offline,
    touch_helper_last_seen,
    list_chat_messages,
    list_chats_for_user,
    list_helper_credentials,
    get_helper_image,
    list_helper_images,
    list_helper_reviews,
    list_reviews_by_customer,
    list_reviewed_job_ids,
    list_users,
    mark_user_verified,
    search_helpers,
    set_chat_status,
    set_user_verification,
    set_user_reset_code,
    update_user_admin,
    update_helper_profile,
    update_helper_status,
    update_user_email,
    update_user_password,
    update_user_reset_sent_at,
    update_user_verification_sent_at,
    update_user_stripe_info,
    clear_user_reset_code,
    upsert_helper_background_check,
    upsert_helper_review,
    user_has_chat_access,
)
from Database.fuzzy_search import matches_fuzzy
from Database.reserved_usernames import is_username_reserved
from Database.security import is_password_hashed, verify_password
from runtime.secure_runtime import load_session_secret
from email_verify.email_utils import send_reset_email, send_verification_email
from email_verify.email_verification import (
    generate_reset_code,
    generate_verification_code,
    hash_verification_code,
    is_code_expired,
)

# Toggle HTTPS vs HTTP cookie behavior.
# Set to False only when intentionally running on plain HTTP (e.g., port 80).
USE_HTTPS = True

SESSION_COOKIE_SECURE = USE_HTTPS

# --- App and template setup ------------------------------------------------
app = FastAPI()

# Jinja2 templates render HTML for each part of the app.
helper_templates = Jinja2Templates(directory=str(PROJECT_ROOT / "Helper" / "templates"))
customer_templates = Jinja2Templates(directory=str(PROJECT_ROOT / "Customer" / "templates"))
public_templates = Jinja2Templates(directory=str(PROJECT_ROOT / "Server" / "templates"))

# --- Session (login) configuration ----------------------------------------
# Logged-in users store a signed cookie in the browser.
SESSION_COOKIE_NAME = "helper_session"
SESSION_TTL_SECONDS = 60 * 60 * 24
SESSION_SECRET_FILE = Path(
    os.environ.get(
        "HELPER_SESSION_SECRET_FILE",
        str(PROJECT_ROOT / "Server" / "config" / "HELPER_SESSION_SECRET"),
    )
)
SESSION_SECRET = load_session_secret(SESSION_SECRET_FILE)
SESSION_SERIALIZER = URLSafeTimedSerializer(SESSION_SECRET, salt="helper-session-salt")
PENDING_JOB_COOKIE = "pending_job"
PENDING_CHAT_COOKIE = "pending_chat"
PENDING_JOB_TTL_SECONDS = 3600
PENDING_CHAT_TTL_SECONDS = 7 * 24 * 3600
CHAT_MESSAGE_MAX_LENGTH = 300
CHAT_MESSAGE_MIN_SECONDS = 1

# Admin usernames are configured by environment variable for convenience.
_default_admins = os.environ.get("HELPER_ADMIN_USERS", "admin")
ADMIN_USERNAMES = {name.strip() for name in _default_admins.split(",") if name.strip()} or {"admin"}

# Simple role labels so we can compare strings consistently.
ROLE_HELPER = "helper"
ROLE_CUSTOMER = "customer"

BACKGROUND_CHECK_VENDOR = os.environ.get("BACKGROUND_CHECK_VENDOR", "").strip()
BACKGROUND_CHECK_WEBHOOK_SECRET = os.environ.get("BACKGROUND_CHECK_WEBHOOK_SECRET", "").strip()

CHECKR_API_KEY = os.environ.get("CHECKR_API_KEY", "").strip()
CHECKR_PACKAGE_ID = os.environ.get("CHECKR_PACKAGE_ID", "").strip()
CHECKR_WEBHOOK_SECRET = os.environ.get("CHECKR_WEBHOOK_SECRET", "").strip()
CHECKR_BASE_URL = os.environ.get("CHECKR_BASE_URL", "https://api.checkr.com/v1").strip()

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
STRIPE_DEV_BYPASS = os.environ.get("STRIPE_DEV_BYPASS", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
STRIPE_CONNECT_TYPE = os.environ.get("STRIPE_CONNECT_TYPE", "express").strip().lower()
if STRIPE_CONNECT_TYPE not in {"express", "standard", "custom"}:
    STRIPE_CONNECT_TYPE = "express"
if STRIPE_CONNECT_TYPE == "standard":
    STRIPE_CONNECT_TYPE = "express"
STRIPE_API_BASE = "https://api.stripe.com/v1"
PLATFORM_FEE_PERCENT = float(os.environ.get("PLATFORM_FEE_PERCENT", "25"))
HELPER_FEE_PERCENT = float(os.environ.get("HELPER_FEE_PERCENT", str(PLATFORM_FEE_PERCENT)))
CUSTOMER_SERVICE_FEE_PERCENT = float(os.environ.get("CUSTOMER_SERVICE_FEE_PERCENT", "5"))
SALES_TAX_PERCENT = float(os.environ.get("SALES_TAX_PERCENT", "0"))
MIN_JOB_PAYMENT_CENTS = int(os.environ.get("MIN_JOB_PAYMENT_CENTS", "3500"))

# --- Data models for JSON requests ----------------------------------------
# Pydantic models describe the expected JSON data in POST requests.
class SessionData(BaseModel):
    """Data stored in the signed session cookie."""

    username: str
    role: str


class ChatCreateRequest(BaseModel):
    """Input data when a user starts a new chat."""

    target_username: str
    target_role: str = ROLE_HELPER
    job_id: Optional[int] = None


class ChatMessageRequest(BaseModel):
    """Input data when a user sends a chat message."""

    content: str


class ChatStatusUpdateRequest(BaseModel):
    """Input data when a user accepts or declines a chat."""

    action: str


class HelperProfileUpdateRequest(BaseModel):
    """Input data when a helper edits their pay or bio."""

    service_location: str = ""
    max_distance_miles: float = 0
    pay_type: str
    pay_rate: float
    bio: str
    availability_status: str = "active"


class HelperStatusUpdateRequest(BaseModel):
    """Input data when a helper updates availability."""

    availability_status: str


class JobPaymentRequest(BaseModel):
    """Input data when a customer starts a job payment."""

    amount_cents: int
    helper_username: str
    currency: str = "usd"


class JobCreateRequest(BaseModel):
    """Input data when a customer creates a new job post."""

    title: str
    description: str
    keywords: str = ""
    budget: str = ""
    location: str = ""


class PendingJobRequest(BaseModel):
    """Input data for a pre-signup job selection."""

    title: str
    description: str
    keywords: str = ""
    budget: str = ""
    location: str = ""
    helper_username: str


# --- Helper functions (small reusable pieces) -----------------------------
def _resolve_chat_counterpart(chat: Dict[str, Any], viewer: SessionData) -> Dict[str, str]:
    """Return the other person in a chat, given the current viewer."""

    if chat["participant_a"] == viewer.username and chat["participant_a_role"] == viewer.role:
        return {
            "other_username": chat["participant_b"],
            "other_role": chat["participant_b_role"],
        }
    return {
        "other_username": chat["participant_a"],
        "other_role": chat["participant_a_role"],
    }


def _has_active_chat_for_job(
    customer_username: str,
    helper_username: str,
    job_id: int,
) -> bool:
    """Return True if the customer has an active chat with the helper for this job."""

    clean_customer = normalize_username(customer_username)
    clean_helper = normalize_username(helper_username)
    if not clean_customer or not clean_helper:
        return False
    chats = list_chats_for_user(clean_customer, ROLE_CUSTOMER)
    for chat in chats:
        if chat.get("job_id") != job_id or chat.get("status") != "active":
            continue
        other = _resolve_chat_counterpart(chat, SessionData(username=clean_customer, role=ROLE_CUSTOMER))
        if other.get("other_username") == clean_helper:
            return True
    return False


EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"\b(?:https?://|www\.)\S+\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b[a-z0-9][a-z0-9.-]+\.(?:com|net|org|io|co|us|biz|info|app|dev|me|ai|gg|tv|ly|to|edu|gov|mil)\b",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]*)?(?:\(\s*\d{3}\s*\)|\d{3})[\s.-]*\d{3}[\s.-]*\d{4}(?!\d)"
)
PHONE_SEPARATORS = set(" -().")
OBFUSCATED_DIGIT_SEPARATORS = re.compile(r"(?<=\d)[\s.-]+(?=\d)")
SOCIAL_HANDLE_PATTERN = re.compile(r"(?:^|\s)@([a-z0-9._]{2,30})\b", re.IGNORECASE)
SOCIAL_TAG_PATTERN = re.compile(
    r"\b(?:ig|insta|instagram|facebook|fb|snap|snapchat|tiktok|whatsapp|telegram|discord|skype|x|twitter)\b\s*[:@]\s*[a-z0-9._]{2,30}\b",
    re.IGNORECASE,
)
ADDRESS_PATTERN = re.compile(
    r"\b\d{1,6}\s+[a-z0-9.\-']+(?:\s+[a-z0-9.\-']+){0,4}\s+"
    r"(?:st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|ct|court|pl|place|way|pkwy|parkway|"
    r"cir|circle|trl|trail|hwy|highway|ter|terrace|apt|apartment|unit|ste|suite)\b",
    re.IGNORECASE,
)
PO_BOX_PATTERN = re.compile(r"\bP\.?\s*O\.?\s*Box\s*\d+\b", re.IGNORECASE)


def _normalize_obfuscated_numbers(content: str) -> str:
    return OBFUSCATED_DIGIT_SEPARATORS.sub("", content)


def _looks_like_spaced_phone(content: str) -> bool:
    digits = 0
    separators = 0
    for ch in content:
        if ch.isdigit():
            digits += 1
            continue
        if ch in PHONE_SEPARATORS and digits:
            separators += 1
            continue
        if digits >= 10 and separators >= 1:
            return True
        digits = 0
        separators = 0
    return digits >= 10 and separators >= 1


def _content_policy_violations(content: str, allow_address: bool) -> list[str]:
    """Return policy violations for user-facing text."""

    violations: list[str] = []
    if EMAIL_PATTERN.search(content):
        violations.append("email address")
    if URL_PATTERN.search(content) or DOMAIN_PATTERN.search(content):
        violations.append("link")
    if PHONE_PATTERN.search(content) or _looks_like_spaced_phone(content):
        violations.append("phone number")

    no_email = EMAIL_PATTERN.sub(" ", content)
    if SOCIAL_HANDLE_PATTERN.search(no_email) or SOCIAL_TAG_PATTERN.search(no_email):
        violations.append("social handle")

    if not allow_address:
        normalized = _normalize_obfuscated_numbers(content)
        if (
            ADDRESS_PATTERN.search(content)
            or ADDRESS_PATTERN.search(normalized)
            or PO_BOX_PATTERN.search(content)
            or PO_BOX_PATTERN.search(normalized)
        ):
            violations.append("address")

    return violations


def _contact_violation_message(violations: list[str], allow_address: bool, context: str) -> str:
    """Build a user-facing message for blocked contact info."""

    clean = ", ".join(dict.fromkeys(violations))
    if "address" in violations and not allow_address:
        return f"Please remove {clean} from {context}. Addresses can be shared after payment."
    return f"Please remove {clean} from {context} and keep communication in-app."


def _recent_sender_messages(chat_id: int, sender: str, limit: int = 3) -> list[str]:
    """Return the most recent messages for a sender in a chat."""

    clean_sender = normalize_username(sender)
    if not clean_sender:
        return []
    messages = list_chat_messages(chat_id)
    if not messages:
        return []
    sender_messages = [
        message.get("message", "")
        for message in messages
        if message.get("sender") == clean_sender
    ]
    if not sender_messages:
        return []
    return sender_messages[-limit:]


def _chat_message_policy_error(
    chat_id: int,
    sender: str,
    content: str,
    allow_address: bool,
    limit: int = 5,
) -> Optional[str]:
    """Return an error if chat content violates communication rules."""

    direct_error = _ensure_safe_text(content, allow_address, "your message")
    if direct_error:
        return direct_error
    recent = _recent_sender_messages(chat_id, sender, limit)
    if not recent:
        return None
    combined = " ".join([*recent, content]).strip()
    if not combined:
        return None
    combined_violations = _content_policy_violations(combined, allow_address)
    if combined_violations:
        detail = _contact_violation_message(combined_violations, allow_address, "your recent messages")
        return f"{detail} Avoid splitting contact details across multiple messages."
    return None


def _ensure_safe_text(content: str, allow_address: bool, context: str) -> Optional[str]:
    """Return an error message if contact info is found in user text."""

    if not content:
        return None
    violations = _content_policy_violations(content, allow_address)
    if violations:
        return _contact_violation_message(violations, allow_address, context)
    return None


def _payment_releases_address(job_id: int) -> bool:
    """Return True when payment has been captured and the address can be shared."""

    payment = get_job_payment(job_id)
    if not payment:
        return False
    if payment.get("stripe_transfer_id"):
        return True
    status = (payment.get("stripe_payment_status") or "").lower()
    return status in {"succeeded", "transferred"}


def _payment_confirmed(job_id: int) -> bool:
    """Return True when payment is confirmed for a job."""

    payment = get_job_payment(job_id)
    if not payment:
        return False
    status = (payment.get("stripe_payment_status") or "").lower()
    if status in {"succeeded", "transferred"}:
        return True
    intent_id = payment.get("stripe_payment_intent_id") or ""
    if intent_id and STRIPE_SECRET_KEY:
        try:
            intent = _stripe_retrieve_payment_intent(intent_id)
            status = intent.get("status", "") or "unknown"
            update_job_payment_status(job_id, status)
            return status in {"succeeded", "transferred"}
        except RuntimeError:
            return False
    return False


def serialize_chat(chat: Dict[str, Any], viewer: SessionData) -> Dict[str, Any]:
    """Shape a chat record so the frontend has friendly field names."""

    counterpart = _resolve_chat_counterpart(chat, viewer)

    # Attach basic job info if this chat is tied to a job.
    job_snapshot = None
    if chat.get("job_id") is not None:
        job = get_job(chat["job_id"])
        if job:
            payment = get_job_payment(chat["job_id"]) or {}
            job_snapshot = {
                "id": chat["job_id"],
                "title": job.get("title"),
                "budget": job.get("budget"),
                "location": job.get("location"),
                "status": job.get("status"),
                "payment_status": payment.get("stripe_payment_status") or "",
                "payment_intent_id": payment.get("stripe_payment_intent_id") or "",
                "payment_amount_cents": payment.get("stripe_amount_cents"),
                "payment_currency": payment.get("stripe_currency") or "usd",
                "customer_completed": bool(job.get("customer_completed_at")),
                "helper_completed": bool(job.get("helper_completed_at")),
            }
            if viewer.role == ROLE_HELPER:
                if not _payment_releases_address(chat["job_id"]):
                    job_snapshot["location"] = None
                    job_snapshot["location_locked"] = True
                else:
                    job_snapshot["location_locked"] = False
            else:
                job_snapshot["location_locked"] = False

    return {
        "id": chat["id"],
        "status": chat.get("status", "pending"),
        "initiator_role": chat.get("initiator_role", ROLE_HELPER),
        "job": job_snapshot,
        "other_username": counterpart["other_username"],
        "other_role": counterpart["other_role"],
        "created_at": chat.get("created_at"),
        "last_message": chat.get("last_message"),
        "last_sender": chat.get("last_sender"),
        "last_timestamp": chat.get("last_timestamp"),
    }


def job_matches_profession(job: Dict[str, Any], profession: str) -> bool:
    """Return True if the job text matches the helper's profession."""

    if not profession:
        return True

    matched, _ = matches_fuzzy(
        profession,
        [
            job.get("title", ""),
            job.get("description", ""),
            job.get("keywords", ""),
            job.get("location", ""),
        ],
        threshold=0.5,
    )
    return matched


def _coerce_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _get_job_coordinates(job: Dict[str, Any]) -> Optional[tuple[float, float]]:
    lat = _coerce_float(job.get("location_lat"))
    lon = _coerce_float(job.get("location_lon"))
    if lat is not None and lon is not None:
        return lat, lon

    coords = _geocode_location(job.get("location", ""))
    if not coords:
        return None

    lat, lon = coords
    job_id = job.get("id")
    if isinstance(job_id, int):
        update_job_location_coords(job_id, lat, lon)
        job["location_lat"] = lat
        job["location_lon"] = lon
    return lat, lon


def _job_within_helper_range(job: Dict[str, Any], helper_profile: Dict[str, Any]) -> bool:
    max_distance = _coerce_float(helper_profile.get("max_distance_miles")) or 0.0
    helper_lat = _coerce_float(helper_profile.get("location_lat"))
    helper_lon = _coerce_float(helper_profile.get("location_lon"))
    if helper_lat is None or helper_lon is None or max_distance <= 0:
        return True

    coords = _get_job_coordinates(job)
    if not coords:
        return False

    job_lat, job_lon = coords
    return _distance_miles(helper_lat, helper_lon, job_lat, job_lon) <= max_distance


def _filter_helpers_by_coords(
    helpers: list[Dict[str, Any]],
    job_lat: float,
    job_lon: float,
) -> list[Dict[str, Any]]:
    filtered: list[Dict[str, Any]] = []
    for helper in helpers:
        helper_lat = _coerce_float(helper.get("location_lat"))
        helper_lon = _coerce_float(helper.get("location_lon"))
        max_distance = _coerce_float(helper.get("max_distance_miles")) or 0.0
        if helper_lat is None or helper_lon is None or max_distance <= 0:
            continue
        if _distance_miles(helper_lat, helper_lon, job_lat, job_lon) <= max_distance:
            filtered.append(helper)
    return filtered


def _filter_helpers_for_location(
    helpers: list[Dict[str, Any]],
    location: str,
) -> list[Dict[str, Any]]:
    coords = _geocode_location(location)
    if not coords:
        return helpers
    job_lat, job_lon = coords
    return _filter_helpers_by_coords(helpers, job_lat, job_lon)


def _count_helper_completed_jobs(helper_username: str) -> int:
    """Return the number of closed jobs linked to the helper's chats."""

    chats = list_chats_for_user(helper_username, ROLE_HELPER)
    job_ids = {
        chat.get("job_id")
        for chat in chats
        if chat.get("job_id") and chat.get("status") != "declined"
    }
    completed = 0
    for job_id in job_ids:
        if not isinstance(job_id, int):
            continue
        job = get_job(job_id)
        if job and job.get("status") == "closed":
            completed += 1
    return completed


def _list_helper_completed_jobs(helper_username: str) -> list[Dict[str, Any]]:
    """Return completed job records tied to the helper's chats."""

    chats = list_chats_for_user(helper_username, ROLE_HELPER)
    job_ids = {
        chat.get("job_id")
        for chat in chats
        if chat.get("job_id") and chat.get("status") != "declined"
    }
    jobs: list[Dict[str, Any]] = []
    for job_id in job_ids:
        if not isinstance(job_id, int):
            continue
        job = get_job(job_id)
        if job and job.get("status") == "closed":
            jobs.append(job)
    jobs.sort(key=lambda entry: entry.get("created_at") or "", reverse=True)
    return jobs


def create_session_token(username: str, role: str) -> str:
    """Create a signed token that can be stored in a browser cookie."""

    clean_username = normalize_username(username)
    return SESSION_SERIALIZER.dumps({"username": clean_username, "role": role})


def build_session_response(
    username: str,
    role: str,
    next_path: Optional[str] = None,
) -> RedirectResponse:
    """Send a redirect response that also sets the session cookie."""

    if role == ROLE_HELPER:
        touch_helper_last_seen(username)

    session_token = create_session_token(username, role)
    next_route = next_path or ("/helpers/home" if role == ROLE_HELPER else "/customers/home")
    response = RedirectResponse(url=next_route, status_code=303)

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        max_age=SESSION_TTL_SECONDS,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
    )
    return response


def require_admin(username: str) -> None:
    """Stop the request if the user is not an admin."""

    if username not in ADMIN_USERNAMES:
        raise HTTPException(status_code=403, detail="Admin access required")


def normalize_pay_type(pay_type: str) -> str:
    """Accept only known pay types and reject anything else."""

    normalized = pay_type.lower()
    if normalized not in {"hourly", "per_job"}:
        raise HTTPException(status_code=400, detail="Invalid pay type")
    return normalized


def normalize_availability_status(status: str) -> str:
    """Accept only known availability statuses and reject anything else."""

    normalized = status.strip().lower().replace("-", "_")
    if normalized not in {"active", "offline", "on_call"}:
        raise HTTPException(status_code=400, detail="Invalid availability status")
    return normalized


def normalize_username(username: str) -> str:
    """Normalize usernames to lowercase for storage and login."""

    return username.strip().lower()


def resolve_role_for_username(username: str) -> str:
    """Infer the role for a username when only one account exists."""

    helper = get_user_auth_info(username)
    customer = get_customer_auth_info(username)
    if helper and not customer:
        return ROLE_HELPER
    if customer and not helper:
        return ROLE_CUSTOMER
    return ""


def normalize_background_status(status: str) -> str:
    """Normalize incoming background check status values."""

    normalized = (status or "").strip().lower().replace(" ", "_")
    replacements = {
        "verified": "approved",
        "clear": "approved",
        "cleared": "approved",
        "pass": "approved",
        "passed": "approved",
        "consider": "pending",
        "fail": "rejected",
        "denied": "rejected",
    }
    normalized = replacements.get(normalized, normalized)
    if normalized not in {"unverified", "pending", "approved", "rejected"}:
        return "unverified"
    return normalized


def background_is_verified(status: str) -> bool:
    return normalize_background_status(status) == "approved"


def _stripe_request(
    method: str,
    path: str,
    data: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    if not STRIPE_SECRET_KEY:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured.")

    url = f"{STRIPE_API_BASE}{path}"
    headers = {
        "Authorization": f"Bearer {STRIPE_SECRET_KEY}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    body = None
    if data:
        body = urlencode(data, doseq=True).encode("utf-8")
    if method.upper() in {"GET", "DELETE"}:
        if data:
            url = f"{url}?{urlencode(data, doseq=True)}"
        body = None

    request = UrlRequest(url, data=body, headers=headers, method=method.upper())
    try:
        with urlopen(request, timeout=15) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        payload = exc.read().decode("utf-8")
        raise RuntimeError(f"Stripe API error: {payload}") from exc
    except URLError as exc:
        raise RuntimeError(f"Stripe API connection error: {exc}") from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Stripe API returned invalid JSON.") from exc


def _stripe_create_account(email: str) -> Dict[str, Any]:
    data = {
        "type": STRIPE_CONNECT_TYPE,
        "email": email,
        "capabilities[transfers][requested]": "true",
        "capabilities[card_payments][requested]": "true",
    }
    return _stripe_request("POST", "/accounts", data=data)


def _stripe_create_account_link(account_id: str, refresh_url: str, return_url: str) -> str:
    data = {
        "account": account_id,
        "type": "account_onboarding",
        "refresh_url": refresh_url,
        "return_url": return_url,
    }
    response = _stripe_request("POST", "/account_links", data=data)
    url = response.get("url")
    if not url:
        raise RuntimeError("Stripe account link response missing URL.")
    return url


def _stripe_create_login_link(account_id: str) -> str:
    response = _stripe_request("POST", f"/accounts/{account_id}/login_links")
    url = response.get("url")
    if not url:
        raise RuntimeError("Stripe login link response missing URL.")
    return url


def _stripe_retrieve_account(account_id: str) -> Dict[str, Any]:
    return _stripe_request("GET", f"/accounts/{account_id}")


def _stripe_create_payment_intent(
    amount_cents: int,
    currency: str,
    job_id: int,
    helper_username: str,
) -> Dict[str, Any]:
    data = {
        "amount": str(amount_cents),
        "currency": currency.lower(),
        "automatic_payment_methods[enabled]": "true",
        "metadata[job_id]": str(job_id),
        "metadata[helper_username]": helper_username,
    }
    return _stripe_request("POST", "/payment_intents", data=data, idempotency_key=f"job-{job_id}")


def _stripe_retrieve_payment_intent(intent_id: str) -> Dict[str, Any]:
    return _stripe_request("GET", f"/payment_intents/{intent_id}")


def _stripe_create_transfer(
    amount_cents: int,
    currency: str,
    destination: str,
    job_id: int,
    source_transaction: str | None = None,
) -> Dict[str, Any]:
    data = {
        "amount": str(amount_cents),
        "currency": currency.lower(),
        "destination": destination,
        "metadata[job_id]": str(job_id),
    }
    if source_transaction:
        data["source_transaction"] = source_transaction
    return _stripe_request("POST", "/transfers", data=data)


def _compute_payment_breakdown(base_cents: int) -> Dict[str, int]:
    """Return fee totals for customer + helper payout calculations."""

    helper_fee_cents = max(0, int(round(base_cents * (HELPER_FEE_PERCENT / 100.0))))
    service_fee_cents = max(
        0, int(round(base_cents * (CUSTOMER_SERVICE_FEE_PERCENT / 100.0)))
    )
    tax_cents = max(0, int(round(base_cents * (SALES_TAX_PERCENT / 100.0))))
    total_cents = base_cents + service_fee_cents + tax_cents
    payout_cents = max(0, base_cents - helper_fee_cents)
    platform_fee_cents = max(0, total_cents - payout_cents)
    return {
        "base_cents": base_cents,
        "service_fee_cents": service_fee_cents,
        "tax_cents": tax_cents,
        "total_cents": total_cents,
        "helper_fee_cents": helper_fee_cents,
        "payout_cents": payout_cents,
        "platform_fee_cents": platform_fee_cents,
    }


def _verify_stripe_signature(raw_body: bytes, signature_header: str) -> None:
    if not STRIPE_WEBHOOK_SECRET:
        return
    if not signature_header:
        raise HTTPException(status_code=403, detail="Missing Stripe signature")

    parts = {}
    for item in signature_header.split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            parts.setdefault(key.strip(), []).append(value.strip())

    timestamp = parts.get("t", [None])[0]
    signatures = parts.get("v1", [])
    if not timestamp or not signatures:
        raise HTTPException(status_code=403, detail="Invalid Stripe signature header")

    signed_payload = f"{timestamp}.{raw_body.decode('utf-8')}".encode("utf-8")
    digest = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    if digest not in signatures:
        raise HTTPException(status_code=403, detail="Invalid Stripe signature")


def _checkr_request(
    method: str,
    path: str,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not CHECKR_API_KEY:
        raise RuntimeError("CHECKR_API_KEY is not configured.")

    url = f"{CHECKR_BASE_URL}{path}"
    auth = base64.b64encode(f"{CHECKR_API_KEY}:".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = None
    if data:
        body = urlencode(data, doseq=True).encode("utf-8")
    if method.upper() == "GET":
        if data:
            url = f"{url}?{urlencode(data, doseq=True)}"
        body = None

    request = UrlRequest(url, data=body, headers=headers, method=method.upper())
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        payload = exc.read().decode("utf-8")
        raise RuntimeError(f"Checkr API error: {payload}") from exc
    except URLError as exc:
        raise RuntimeError(f"Checkr API connection error: {exc}") from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Checkr API returned invalid JSON.") from exc


def _checkr_create_invitation(
    helper_username: str,
    helper_email: str,
    redirect_url: str,
) -> Dict[str, Any]:
    if not CHECKR_PACKAGE_ID:
        raise RuntimeError("CHECKR_PACKAGE_ID is not configured.")
    data = {
        "package": CHECKR_PACKAGE_ID,
        "reference_id": helper_username,
        "candidate_email": helper_email,
        "redirect_url": redirect_url,
    }
    return _checkr_request("POST", "/invitations", data=data)


def _checkr_invitation_url(response: Dict[str, Any]) -> str:
    for key in ("invitation_url", "apply_url", "url"):
        url = response.get(key)
        if url:
            return url
    raise RuntimeError("Checkr invitation response missing URL.")


def _distance_miles(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the approximate distance in miles between two coordinate pairs."""

    radius_miles = 3958.8
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_miles * c


LOCATION_DATA_PATH = SERVER_ROOT / "location_data" / "us_places.csv"


@dataclass(frozen=True)
class USPlace:
    """Store a US city-level location entry for offline matching."""

    name: str
    state: str
    lat: float
    lon: float
    population: int
    display: str
    name_key: str
    display_key: str


def _normalize_place_key(text: str) -> str:
    """Normalize user input or place names for matching."""

    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _normalize_state_abbr(state: str) -> Optional[str]:
    """Normalize a state name or abbreviation into its 2-letter code."""

    if not state:
        return None
    clean = state.strip().replace(".", "")
    if len(clean) == 2 and clean.isalpha():
        return clean.upper()
    return US_STATE_ABBR.get(clean.title())


def _split_city_state(query: str) -> tuple[str, Optional[str]]:
    """Split a location query into city and state pieces when possible."""

    clean = query.strip()
    if not clean:
        return "", None
    if "," in clean:
        city, state = clean.split(",", 1)
        return city.strip(), state.strip()
    parts = clean.split()
    if len(parts) >= 2 and len(parts[-1]) == 2:
        return " ".join(parts[:-1]), parts[-1]
    return clean, None


def _load_us_places() -> tuple[list[USPlace], dict[str, list[USPlace]], dict[str, USPlace]]:
    """Load the US city dataset from disk for offline geocoding."""

    places: list[USPlace] = []
    by_city: dict[str, list[USPlace]] = {}
    by_key: dict[str, USPlace] = {}
    if not LOCATION_DATA_PATH.exists():
        return places, by_city, by_key

    with LOCATION_DATA_PATH.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            name = (row.get("city") or "").strip()
            state = (row.get("state") or "").strip().upper()
            if not name or not state:
                continue
            try:
                lat = float(row.get("lat") or "")
                lon = float(row.get("lon") or "")
            except (TypeError, ValueError):
                continue
            population_raw = row.get("population") or "0"
            try:
                population = int(float(population_raw))
            except (TypeError, ValueError):
                population = 0
            display = f"{name}, {state}"
            name_key = _normalize_place_key(name)
            display_key = _normalize_place_key(f"{name} {state}")
            place = USPlace(
                name=name,
                state=state,
                lat=lat,
                lon=lon,
                population=population,
                display=display,
                name_key=name_key,
                display_key=display_key,
            )
            places.append(place)
            by_city.setdefault(name_key, []).append(place)
            existing = by_key.get(display_key)
            if not existing or place.population > existing.population:
                by_key[display_key] = place

    for entries in by_city.values():
        entries.sort(key=lambda item: (-item.population, item.name, item.state))

    return places, by_city, by_key


US_PLACES, US_PLACES_BY_CITY, US_PLACES_BY_KEY = _load_us_places()


def _ensure_location_data_loaded() -> None:
    """Ensure the offline location dataset is available before using it."""

    if US_PLACES:
        return
    raise HTTPException(
        status_code=503,
        detail=(
            "Local location data is not configured. "
            "Run Server/location_data/fetch_us_places.py to build it."
        ),
    )


def _find_place(query: str) -> Optional[USPlace]:
    """Find the best matching place for a location query."""

    clean_query = query.strip()
    if not clean_query:
        return None

    city, state = _split_city_state(clean_query)
    city_key = _normalize_place_key(city)
    if not city_key:
        return None

    normalized_state = _normalize_state_abbr(state or "")
    if normalized_state:
        display_key = _normalize_place_key(f"{city} {normalized_state}")
        match = US_PLACES_BY_KEY.get(display_key)
        if match:
            return match
        for candidate in US_PLACES_BY_CITY.get(city_key, []):
            if candidate.state == normalized_state:
                return candidate
        return None

    candidates = US_PLACES_BY_CITY.get(city_key, [])
    if not candidates:
        display_key = _normalize_place_key(clean_query)
        return US_PLACES_BY_KEY.get(display_key)
    return max(candidates, key=lambda item: item.population)


def _suggest_places(query: str, limit: int = 5) -> list[str]:
    """Suggest US city/state pairs for an input query."""

    clean_query = _normalize_place_key(query)
    if not clean_query:
        return []

    matches: list[USPlace] = []
    for place in US_PLACES:
        if place.name_key.startswith(clean_query) or place.display_key.startswith(clean_query):
            matches.append(place)

    matches.sort(key=lambda item: (-item.population, item.name, item.state))
    suggestions: list[str] = []
    seen = set()
    for place in matches:
        if place.display in seen:
            continue
        seen.add(place.display)
        suggestions.append(place.display)
        if len(suggestions) >= limit:
            break
    return suggestions


def _reverse_geocode(lat: float, lon: float) -> Optional[str]:
    """Return the nearest city/state label for the given coordinates."""

    if not US_PLACES:
        return None
    nearest = None
    nearest_distance = None
    for place in US_PLACES:
        distance = _distance_miles(lat, lon, place.lat, place.lon)
        if nearest is None or distance < nearest_distance:
            nearest = place
            nearest_distance = distance
    return nearest.display if nearest else None


def _geocode_location(query: str) -> Optional[tuple[float, float]]:
    """Return (lat, lon) for a US location string using local data."""

    clean_query = query.strip()
    if not clean_query:
        return None
    if clean_query.lower() in {"remote", "online"}:
        return None
    if not US_PLACES:
        return None
    place = _find_place(clean_query)
    if not place:
        return None
    return place.lat, place.lon


US_STATE_ABBR = {
    "Alabama": "AL",
    "Alaska": "AK",
    "Arizona": "AZ",
    "Arkansas": "AR",
    "California": "CA",
    "Colorado": "CO",
    "Connecticut": "CT",
    "Delaware": "DE",
    "Florida": "FL",
    "Georgia": "GA",
    "Hawaii": "HI",
    "Idaho": "ID",
    "Illinois": "IL",
    "Indiana": "IN",
    "Iowa": "IA",
    "Kansas": "KS",
    "Kentucky": "KY",
    "Louisiana": "LA",
    "Maine": "ME",
    "Maryland": "MD",
    "Massachusetts": "MA",
    "Michigan": "MI",
    "Minnesota": "MN",
    "Mississippi": "MS",
    "Missouri": "MO",
    "Montana": "MT",
    "Nebraska": "NE",
    "Nevada": "NV",
    "New Hampshire": "NH",
    "New Jersey": "NJ",
    "New Mexico": "NM",
    "New York": "NY",
    "North Carolina": "NC",
    "North Dakota": "ND",
    "Ohio": "OH",
    "Oklahoma": "OK",
    "Oregon": "OR",
    "Pennsylvania": "PA",
    "Rhode Island": "RI",
    "South Carolina": "SC",
    "South Dakota": "SD",
    "Tennessee": "TN",
    "Texas": "TX",
    "Utah": "UT",
    "Vermont": "VT",
    "Virginia": "VA",
    "Washington": "WA",
    "West Virginia": "WV",
    "Wisconsin": "WI",
    "Wyoming": "WY",
    "District of Columbia": "DC",
}


def _load_signed_cookie(
    request: Request,
    cookie_name: str,
    max_age: int,
) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(cookie_name)
    if not token:
        return None
    try:
        data = SESSION_SERIALIZER.loads(token, max_age=max_age)
    except BadSignature:
        return None
    return data if isinstance(data, dict) else None


def _set_signed_cookie(
    response: Response,
    cookie_name: str,
    payload: Dict[str, Any],
    max_age: int,
) -> None:
    token = SESSION_SERIALIZER.dumps(payload)
    response.set_cookie(
        key=cookie_name,
        value=token,
        httponly=True,
        max_age=max_age,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
    )


def _clear_cookie(response: Response, cookie_name: str) -> None:
    response.delete_cookie(cookie_name)


def username_in_use(username: str) -> bool:
    """Return True if a helper or customer already has this username."""

    clean_username = normalize_username(username)
    return (
        is_username_reserved(clean_username)
        or get_user_auth_info(clean_username) is not None
        or get_customer_auth_info(clean_username) is not None
    )


def validate_pay_rate(pay_rate: float) -> float:
    """Check that a pay rate is a positive number."""

    if pay_rate is None or math.isnan(pay_rate) or pay_rate <= 0:
        raise HTTPException(status_code=400, detail="Pay rate must be positive")
    return pay_rate


def validate_max_distance(max_distance: float) -> float:
    """Check that a max distance is a positive number."""

    if max_distance is None or math.isnan(max_distance) or max_distance <= 0:
        raise HTTPException(status_code=400, detail="Max distance must be positive")
    if max_distance > 500:
        raise HTTPException(status_code=400, detail="Max distance must be 500 miles or less")
    return max_distance


def normalize_profession(profession: str) -> str:
    """Validate and clean the profession field for helpers."""

    clean = profession.strip()
    if (
        not clean
        or len(clean) > 35
        or not clean.isascii()
        or not any(ch.isalnum() for ch in clean)
        or not all(ch.isalnum() or ch in {" ", "_", "-"} for ch in clean)
    ):
        raise HTTPException(
            status_code=400,
            detail="Profession must be <=35 ASCII chars using letters, numbers, spaces, underscores, or hyphens",
        )
    return clean


def _create_job_and_chat_from_pending(
    customer_username: str,
    pending: Dict[str, Any],
) -> Optional[int]:
    helper_username = normalize_username(pending.get("helper_username", ""))
    if not helper_username:
        return None

    helper_profile = get_user_profile(helper_username)
    if not helper_profile:
        return None

    title = (pending.get("title") or "").strip()
    description = (pending.get("description") or "").strip()
    if not title or not description:
        return None
    keywords = (pending.get("keywords") or "").strip()
    location_text = (pending.get("location") or "").strip()
    for label, value in (
        ("job title", title),
        ("job description", description),
        ("job keywords", keywords),
        ("job location", location_text),
    ):
        message = _ensure_safe_text(value, allow_address=False, context=label)
        if message:
            return None
    coords = _geocode_location(location_text) if location_text else None
    location_lat, location_lon = coords if coords else (None, None)

    job = create_job(
        customer_username,
        title,
        description,
        keywords,
        (pending.get("budget") or "").strip(),
        location_text,
        location_lat,
        location_lon,
    )
    chat_id = get_or_create_chat(
        customer_username,
        ROLE_CUSTOMER,
        helper_username,
        ROLE_HELPER,
        job.get("id"),
        ROLE_CUSTOMER,
    )
    chat = get_chat(chat_id)
    if chat and chat.get("status") == "pending" and chat.get("initiator_role") == ROLE_CUSTOMER:
        set_chat_status(chat_id, "active")
    return chat_id


def admin_redirect(message: str) -> RedirectResponse:
    """Send admins back to the dashboard with a short message."""

    params = urlencode({"message": message}) if message else ""
    target = f"/helpers/admin?{params}" if params else "/helpers/admin"
    return RedirectResponse(url=target, status_code=303)


def admin_customers_redirect(message: str) -> RedirectResponse:
    """Send admins back to the customer dashboard with a short message."""

    params = urlencode({"message": message}) if message else ""
    target = f"/helpers/admin/customers?{params}" if params else "/helpers/admin/customers"
    return RedirectResponse(url=target, status_code=303)


def customer_profile_redirect(message: str = "", error: str = "") -> RedirectResponse:
    """Send customers back to their profile page with optional feedback."""

    params = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    query = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(url=f"/customers/profile{query}", status_code=303)


def helper_profile_redirect(message: str = "", error: str = "") -> RedirectResponse:
    """Send helpers back to their profile page with optional feedback."""

    params = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    query = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(url=f"/helpers/profile{query}", status_code=303)


def build_base_url(request: Request) -> str:
    """Return the public base URL for links in emails."""

    configured = os.environ.get("APP_BASE_URL")
    if configured:
        return configured.rstrip("/")
    return str(request.base_url).rstrip("/")


ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def _resolve_image_extension(filename: str, content_type: str | None) -> Optional[str]:
    """Return a safe image extension based on the upload metadata."""

    suffix = Path(filename).suffix.lower()
    if suffix in ALLOWED_IMAGE_EXTENSIONS:
        return suffix

    content_map = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
    }
    return content_map.get((content_type or "").lower())


async def _read_helper_image_upload(upload: UploadFile) -> tuple[str, str, bytes]:
    """Read an uploaded image into memory and return (name, content_type, bytes)."""

    extension = _resolve_image_extension(upload.filename or "", upload.content_type)
    if not extension:
        raise HTTPException(
            status_code=400,
            detail="Only JPG, JPEG, PNG, or WEBP images are allowed.",
        )

    filename = f"{uuid.uuid4().hex}{extension}"
    content_type = upload.content_type or "application/octet-stream"

    size = 0
    data = bytearray()
    try:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_IMAGE_BYTES:
                raise HTTPException(status_code=413, detail="Image exceeds 5 MB limit.")
            data.extend(chunk)
    finally:
        await upload.close()

    return filename, content_type, bytes(data)


def _build_image_url(image_id: int) -> str:
    """Create a public URL for a stored image."""

    return f"/helpers/images/{image_id}"


def _guess_content_type(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    if suffix in {".jpg", ".jpeg"}:
        return "image/jpeg"
    if suffix == ".png":
        return "image/png"
    if suffix == ".webp":
        return "image/webp"
    return "application/octet-stream"




def _average_rating(reviews: list[dict]) -> float:
    """Compute the average rating for a list of reviews."""

    if not reviews:
        return 0.0
    total = sum(int(review.get("rating", 0)) for review in reviews)
    return total / len(reviews)


def _reviewable_jobs_for_helper(
    customer_username: str,
    helper_username: str,
) -> list[Dict[str, Any]]:
    """Return completed jobs between a customer and helper that are reviewable."""

    clean_customer = normalize_username(customer_username)
    clean_helper = normalize_username(helper_username)
    chats = list_chats_for_user(clean_customer, ROLE_CUSTOMER)
    job_ids = set()
    for chat in chats:
        job_id = chat.get("job_id")
        if not job_id:
            continue
        if (
            chat.get("participant_a") == clean_customer
            and chat.get("participant_a_role") == ROLE_CUSTOMER
        ):
            other_username = chat.get("participant_b")
            other_role = chat.get("participant_b_role")
        else:
            other_username = chat.get("participant_a")
            other_role = chat.get("participant_a_role")
        if other_role != ROLE_HELPER or other_username != clean_helper:
            continue
        job_ids.add(job_id)

    jobs: list[Dict[str, Any]] = []
    for job_id in job_ids:
        job = get_job(job_id)
        if not job:
            continue
        if job.get("customer_username") != clean_customer:
            continue
        if job.get("status") != "closed":
            continue
        jobs.append(job)

    reviewed_ids = set(list_reviewed_job_ids(clean_helper, clean_customer))
    return [job for job in jobs if job.get("id") not in reviewed_ids]


def _get_reviewable_job(
    customer_username: str,
    helper_username: str,
    job_id: int,
) -> Optional[Dict[str, Any]]:
    """Return a completed job if it matches the helper and has not been reviewed yet."""

    if job_id <= 0:
        return None
    reviewable = _reviewable_jobs_for_helper(customer_username, helper_username)
    for job in reviewable:
        if job.get("id") == job_id:
            return job
    return None


def _record_job_completion(job_id: int, role: str) -> Optional[Dict[str, Any]]:
    """Record a completion marker and update the job status."""

    updated = set_job_completion(job_id, role)
    if not updated:
        return None
    job = get_job(job_id)
    if not job:
        return None
    if job.get("customer_completed_at") and job.get("helper_completed_at"):
        update_job_status(job_id, "closed")
    else:
        update_job_status(job_id, "pending_completion")
    return get_job(job_id)


def _release_job_payment(job_id: int) -> Optional[str]:
    job = get_job(job_id)
    if not job:
        return None
    if not (job.get("customer_completed_at") and job.get("helper_completed_at")):
        return None

    payment = get_job_payment(job_id)
    if not payment:
        return None

    intent_id = payment.get("stripe_payment_intent_id") or ""
    if not intent_id:
        return None
    if payment.get("stripe_transfer_id"):
        return payment.get("stripe_transfer_id")

    intent = _stripe_retrieve_payment_intent(intent_id)
    status = intent.get("status", "")
    update_job_payment_status(job_id, status or "unknown")
    if status != "succeeded":
        return None

    helper_username = payment.get("stripe_helper_username", "")
    if not helper_username:
        return None
    stripe_info = get_user_stripe_info(helper_username) or {}
    account_id = stripe_info.get("stripe_account_id", "")
    if not account_id or not stripe_info.get("stripe_onboarding_complete"):
        return None

    amount_cents = int(payment.get("stripe_amount_cents") or 0)
    currency = payment.get("stripe_currency") or "usd"
    fee_cents = int(payment.get("stripe_platform_fee_cents") or 0)
    payout_cents = amount_cents - fee_cents
    if payout_cents <= 0:
        return None

    source_transaction = intent.get("latest_charge")
    transfer = _stripe_create_transfer(
        payout_cents,
        currency,
        account_id,
        job_id,
        source_transaction=source_transaction,
    )
    transfer_id = transfer.get("id", "")
    if transfer_id:
        update_job_transfer(job_id, transfer_id)
        update_job_payment_status(job_id, "transferred")
        return transfer_id
    return None


def send_verification_code(
    role: str,
    username: str,
    email: str,
) -> None:
    """Generate and email a verification code, then store the code hash."""

    now = int(time.time())
    last_sent = 0
    if role == ROLE_HELPER:
        auth = get_user_auth_info(username)
        if auth:
            last_sent = int(auth.get("verification_sent_at") or 0)
    else:
        auth = get_customer_auth_info(username)
        if auth:
            last_sent = int(auth.get("verification_sent_at") or 0)

    if last_sent and now - last_sent < 30:
        remaining = 30 - (now - last_sent)
        raise RuntimeError(f"Please wait {remaining} seconds before resending.")

    code, code_hash, expires_at = generate_verification_code()
    if role == ROLE_HELPER:
        set_user_verification(username, email, code_hash, expires_at)
        update_user_email(username, email)
    else:
        set_customer_verification(username, email, code_hash, expires_at)
        update_customer_email(username, email)

    send_verification_email(email, code, role)

    if role == ROLE_HELPER:
        update_user_verification_sent_at(username, now)
    else:
        update_customer_verification_sent_at(username, now)


def send_reset_code(role: str, username: str, email: str) -> None:
    """Generate and email a password reset code, then store the code hash."""

    now = int(time.time())
    last_sent = 0
    if role == ROLE_HELPER:
        auth = get_user_auth_info(username)
        if auth:
            last_sent = int(auth.get("reset_sent_at") or 0)
    else:
        auth = get_customer_auth_info(username)
        if auth:
            last_sent = int(auth.get("reset_sent_at") or 0)

    if last_sent and now - last_sent < 30:
        remaining = 30 - (now - last_sent)
        raise RuntimeError(f"Please wait {remaining} seconds before resending.")

    code, code_hash, expires_at = generate_reset_code()
    if role == ROLE_HELPER:
        set_user_reset_code(username, code_hash, expires_at)
    else:
        set_customer_reset_code(username, code_hash, expires_at)

    send_reset_email(email, code, role)
    if role == ROLE_HELPER:
        update_user_reset_sent_at(username, now)
    else:
        update_customer_reset_sent_at(username, now)


def resolve_session_data(token: Optional[str]) -> Optional[SessionData]:
    """Decode the signed cookie token into a SessionData object."""

    if not token:
        return None
    try:
        data = SESSION_SERIALIZER.loads(token, max_age=SESSION_TTL_SECONDS)
    except BadSignature:
        return None

    username = data.get("username")
    if not username:
        return None
    role = data.get("role", ROLE_HELPER)
    return SessionData(username=normalize_username(username), role=role)


# --- Dependency helpers ----------------------------------------------------
# Dependencies are reusable checks that run before a route executes.
# They keep routes clean and make authentication consistent.
def _require_session(session_token: Optional[str], redirect_path: str) -> SessionData:
    """Ensure the user has a valid session, or redirect them to a login page."""

    session = resolve_session_data(session_token)
    if not session:
        raise HTTPException(
            status_code=303,
            detail="Not authenticated",
            headers={"Location": redirect_path},
        )
    if session.role == ROLE_HELPER:
        touch_helper_last_seen(session.username)
    return session


def require_any_user(
    session_token: Annotated[Optional[str], Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> SessionData:
    """Allow any logged-in user (helper or customer)."""

    return _require_session(session_token, "/helpers")


def require_helper_user(
    session_token: Annotated[Optional[str], Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> SessionData:
    """Allow only helpers to access a route."""

    session = _require_session(session_token, "/helpers")
    if session.role != ROLE_HELPER:
        raise HTTPException(status_code=403, detail="Helper access required")
    return session


def require_customer_user(
    session_token: Annotated[Optional[str], Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> SessionData:
    """Allow only customers to access a route."""

    session = _require_session(session_token, "/customers")
    if session.role != ROLE_CUSTOMER:
        raise HTTPException(
            status_code=303,
            detail="Customer access required",
            headers={"Location": "/customers"},
        )
    return session


@app.get("/helpers/images/{image_id}")
async def get_helper_image_route(
    image_id: int,
    session: SessionData = Depends(require_any_user),
):
    """Serve helper portfolio images from the database."""

    record = get_helper_image(image_id)
    if not record:
        raise HTTPException(status_code=404, detail="Image not found")

    file_bytes = record.get("file_bytes")
    file_name = record.get("file_name") or ""
    file_path = (record.get("file_path") or "").strip()
    content_type = record.get("content_type") or _guess_content_type(file_name or file_path)
    if file_bytes:
        return Response(content=file_bytes, media_type=content_type)

    if not file_path:
        raise HTTPException(status_code=404, detail="Image data missing")

    safe_path = file_path.lstrip("/").replace("\\", "/")
    legacy_root = SERVER_ROOT / "uploads"
    full_path = (legacy_root / safe_path).resolve()
    if legacy_root.resolve() not in full_path.parents or not full_path.exists():
        raise HTTPException(status_code=404, detail="Image file missing")

    return Response(content=full_path.read_bytes(), media_type=content_type)


def _extract_bearer_token(value: str) -> str:
    if not value:
        return ""
    lower = value.lower()
    if lower.startswith("bearer "):
        return value[7:].strip()
    return ""


def _require_background_webhook_secret(request: Request, raw_body: bytes) -> None:
    checkr_signature = request.headers.get("X-Checkr-Signature", "").strip()
    if CHECKR_WEBHOOK_SECRET and checkr_signature:
        digest = hmac.new(
            CHECKR_WEBHOOK_SECRET.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        digest_b64 = base64.b64encode(
            hmac.new(
                CHECKR_WEBHOOK_SECRET.encode("utf-8"),
                raw_body,
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        if checkr_signature in {digest, digest_b64}:
            return
        raise HTTPException(status_code=403, detail="Invalid Checkr webhook signature")

    if not BACKGROUND_CHECK_WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Webhook secret not configured")
    token = _extract_bearer_token(request.headers.get("Authorization", ""))
    if not token:
        token = request.headers.get("X-Helper-Webhook-Secret", "").strip()
    if token != BACKGROUND_CHECK_WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid webhook secret")


@app.post("/webhooks/background-check")
async def background_check_webhook(request: Request):
    """Receive background check decisions from a vendor."""

    raw_body = await request.body()
    _require_background_webhook_secret(request, raw_body)
    payload = json.loads(raw_body.decode("utf-8"))
    helper_username = normalize_username(
        payload.get("username") or payload.get("helper_username") or ""
    )
    if not helper_username:
        data = payload.get("data", {})
        obj = data.get("object", {}) if isinstance(data, dict) else {}
        helper_username = normalize_username(obj.get("reference_id") or "")
    if not helper_username:
        raise HTTPException(status_code=400, detail="username is required")

    obj = {}
    if isinstance(payload.get("data"), dict):
        obj = payload.get("data", {}).get("object", {}) or {}
    status = normalize_background_status(
        payload.get("status")
        or payload.get("result")
        or obj.get("result")
        or obj.get("status")
        or ""
    )
    vendor = (payload.get("vendor") or BACKGROUND_CHECK_VENDOR or "").strip()
    external_id = (
        payload.get("external_id")
        or payload.get("check_id")
        or (payload.get("data", {}) or {}).get("object", {}).get("id")
        or ""
    ).strip()
    upsert_helper_background_check(helper_username, status, vendor, external_id)
    return {"status": "ok"}


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Receive Stripe payment status updates."""

    raw_body = await request.body()
    signature = request.headers.get("Stripe-Signature", "")
    if STRIPE_WEBHOOK_SECRET:
        _verify_stripe_signature(raw_body, signature)

    payload = json.loads(raw_body.decode("utf-8"))
    event_type = payload.get("type", "")
    data = payload.get("data", {}).get("object", {})
    if event_type == "payment_intent.succeeded":
        intent_id = data.get("id", "")
        job_id = (data.get("metadata", {}) or {}).get("job_id")
        if job_id:
            try:
                update_job_payment_status(int(job_id), "succeeded")
                try:
                    _release_job_payment(int(job_id))
                except RuntimeError:
                    pass
            except (TypeError, ValueError):
                pass
    elif event_type == "payment_intent.payment_failed":
        job_id = (data.get("metadata", {}) or {}).get("job_id")
        if job_id:
            try:
                update_job_payment_status(int(job_id), "failed")
            except (TypeError, ValueError):
                pass
    return {"status": "ok"}


# --- Middleware ------------------------------------------------------------
# CORS lets the browser call our API from certain local dev URLs.
ALLOWED_ORIGINS = (
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8000",
)

LEGAL_DOCS = [
    ("terms-of-service", "Terms of Service", "terms_of_service.txt"),
    ("privacy-policy", "Privacy Policy", "privacy_policy.txt"),
    ("cookie-policy", "Cookie Policy", "cookie_policy.txt"),
    ("refund-dispute-policy", "Refund & Dispute Policy", "refund_dispute_policy.txt"),
    ("community-guidelines", "Community Guidelines", "community_guidelines.txt"),
    ("platform-disclaimer", "Platform Disclaimer", "platform_disclaimer.txt"),
    ("support-contact", "Support Contact", "support_contact.txt"),
]
LEGAL_DOC_INDEX = {
    slug: {"title": title, "file": filename} for slug, title, filename in LEGAL_DOCS
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _load_legal_doc(file_name: str) -> Optional[str]:
    path = SERVER_ROOT / "legal_work" / file_name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


# --- Public homepage -------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def public_homepage(
    request: Request,
    session_token: Annotated[Optional[str], Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    """Show the public homepage or redirect if the user is already logged in."""

    session = resolve_session_data(session_token)
    if session:
        next_route = "/helpers/home" if session.role == ROLE_HELPER else "/customers/home"
        return RedirectResponse(url=next_route, status_code=303)

    return public_templates.TemplateResponse("home.html", {"request": request})


# --- Legal pages -----------------------------------------------------------
@app.get("/legal", response_class=HTMLResponse)
async def legal_index(request: Request):
    """List legal pages so you can fill them before launch."""

    docs = [{"slug": slug, "title": title} for slug, title, _ in LEGAL_DOCS]
    return public_templates.TemplateResponse(
        "legal_index.html",
        {"request": request, "docs": docs},
    )


@app.get("/legal/{slug}", response_class=HTMLResponse)
async def legal_page(slug: str, request: Request):
    """Render a single legal document."""

    info = LEGAL_DOC_INDEX.get(slug)
    if not info:
        raise HTTPException(status_code=404, detail="Legal document not found")
    content = _load_legal_doc(info["file"])
    if content is None:
        raise HTTPException(status_code=404, detail="Legal document not found")
    return public_templates.TemplateResponse(
        "legal_page.html",
        {"request": request, "title": info["title"], "content": content},
    )


# --- Public APIs (no login required) --------------------------------------
@app.get("/public/helpers")
async def public_search_helpers(
    q: Optional[str] = Query(default="", max_length=100),
    location: Optional[str] = Query(default="", max_length=140),
):
    """Search helpers for the public homepage wizard."""

    helpers = search_helpers(q or "")
    if location:
        helpers = _filter_helpers_for_location(helpers, location)
    public_fields = []
    for helper in helpers:
        public_fields.append(
            {
                "username": helper.get("username", ""),
                "profession": helper.get("profession", ""),
                "pay_type": helper.get("pay_type", ""),
                "pay_rate": helper.get("pay_rate", 0),
                "bio": helper.get("bio", ""),
                "availability_status": helper.get("availability_status", "active"),
            }
        )
    return {"helpers": public_fields}


@app.get("/public/reverse-geocode")
async def public_reverse_geocode(
    lat: float = Query(...),
    lon: float = Query(...),
):
    """Reverse-geocode coordinates into a readable location."""

    _ensure_location_data_loaded()
    location = _reverse_geocode(lat, lon)
    if not location:
        raise HTTPException(status_code=502, detail="Reverse geocoding failed")
    return {"location": location}


@app.get("/public/location-suggest")
async def public_location_suggest(
    query: str = Query(..., min_length=2, max_length=120),
):
    """Suggest location names from a free-text query."""

    _ensure_location_data_loaded()
    suggestions = _suggest_places(query)
    return {"suggestions": suggestions}


@app.post("/public/pending-job")
async def public_pending_job(payload: PendingJobRequest):
    """Store a pending job + helper selection before signup."""

    title = payload.title.strip()
    description = payload.description.strip()
    keywords = payload.keywords.strip()
    location_text = payload.location.strip()
    helper_username = normalize_username(payload.helper_username)
    if not title or not description or not helper_username:
        raise HTTPException(status_code=400, detail="Missing required fields")

    if not get_user_profile(helper_username):
        raise HTTPException(status_code=404, detail="Helper not found")

    for label, value in (
        ("job title", title),
        ("job description", description),
        ("job keywords", keywords),
        ("job location", location_text),
    ):
        message = _ensure_safe_text(value, allow_address=False, context=label)
        if message:
            raise HTTPException(status_code=400, detail=message)

    response = JSONResponse({"redirect": "/customers?mode=signup"})
    _set_signed_cookie(
        response,
        PENDING_JOB_COOKIE,
        {
            "title": title,
            "description": description,
            "keywords": keywords,
            "budget": payload.budget.strip(),
            "location": location_text,
            "helper_username": helper_username,
        },
        PENDING_JOB_TTL_SECONDS,
    )
    return response


# --- Email verification ----------------------------------------------------
@app.get("/verify-email", response_class=HTMLResponse)
async def verify_email(role: Annotated[str, Query()] = ""):
    """Redirect old verification links to the code entry flow."""

    normalized_role = role.strip().lower()
    params = urlencode(
        {
            "role": normalized_role,
            "notice": "Verification links are no longer used. Enter the code from your email.",
        }
    )
    return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)


@app.post("/verify/confirm")
async def confirm_verification_code(
    request: Request,
    role: Annotated[str, Form()],
    username: Annotated[str, Form()],
    code: Annotated[str, Form()],
    auto_login: Annotated[Optional[str], Form()] = None,
):
    """Verify an email address using a code from the inbox."""

    normalized_role = role.strip().lower()
    clean_username = normalize_username(username)
    clean_code = code.strip().replace(" ", "")
    auto_login_value = auto_login or ""
    if not clean_username or not clean_code:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "Enter the verification code from your email.",
                "auto_login": auto_login_value,
            }
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        auth = get_user_auth_info(clean_username)
        login_url = "/helpers?verified=1"
        if not auth:
            params = urlencode(
                {
                    "role": normalized_role,
                    "error": "Account not found.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if auth.get("email_verified"):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "notice": "Your email is already verified.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if is_code_expired(auth.get("verification_expires_at")):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "That code has expired. Request a new one.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        expected_hash = auth.get("verification_token_hash", "")
    elif normalized_role == ROLE_CUSTOMER:
        auth = get_customer_auth_info(clean_username)
        login_url = "/customers?verified=1"
        if not auth:
            params = urlencode(
                {
                    "role": normalized_role,
                    "error": "Account not found.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if auth.get("email_verified"):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "notice": "Your email is already verified.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if is_code_expired(auth.get("verification_expires_at")):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "That code has expired. Request a new one.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        expected_hash = auth.get("verification_token_hash", "")
    else:
        params = urlencode({"error": "Unknown role."})
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    if not expected_hash:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "No active verification code found. Request a new one.",
                "auto_login": auto_login_value,
            }
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    if hash_verification_code(clean_code) != expected_hash:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "That code did not match. Please try again.",
                "auto_login": auto_login_value,
            }
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        mark_user_verified(clean_username)
    else:
        mark_customer_verified(clean_username)

    should_auto_login = str(auto_login or "").lower() in {"1", "true", "yes"}
    if should_auto_login:
        next_path = "/helpers/home" if normalized_role == ROLE_HELPER else "/customers/home"
        if normalized_role == ROLE_CUSTOMER:
            pending_chat = _load_signed_cookie(
                request,
                PENDING_CHAT_COOKIE,
                PENDING_CHAT_TTL_SECONDS,
            )
            if pending_chat and pending_chat.get("chat_id"):
                next_path = f"/customers/chats?chatId={pending_chat['chat_id']}"
        response = build_session_response(clean_username, normalized_role, next_path=next_path)
        _clear_cookie(response, PENDING_CHAT_COOKIE)
        return response

    return RedirectResponse(url=login_url, status_code=303)


@app.get("/reset", response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    role: Annotated[str, Query()] = "",
    username: Annotated[str, Query()] = "",
    notice: Annotated[Optional[str], Query()] = None,
    error: Annotated[Optional[str], Query()] = None,
):
    """Show the password reset form."""

    normalized_role = role.strip().lower()
    email = ""
    clean_username = normalize_username(username) if username else ""
    if clean_username and normalized_role == ROLE_HELPER:
        record = get_user_auth_info(clean_username)
        if record:
            email = record.get("email", "")
    elif clean_username and normalized_role == ROLE_CUSTOMER:
        record = get_customer_auth_info(clean_username)
        if record:
            email = record.get("contact_email", "")

    return public_templates.TemplateResponse(
        "password_reset.html",
        {
            "request": request,
            "role": normalized_role,
            "username": clean_username,
            "email": email,
            "notice": notice,
            "error": error,
        },
    )


@app.post("/reset/request")
async def request_password_reset(
    role: Annotated[str, Form()],
    username: Annotated[str, Form()],
    email: Annotated[str, Form()],
):
    """Send a password reset code to the account email."""

    normalized_role = role.strip().lower()
    clean_username = normalize_username(username)
    clean_email = email.strip()
    if not clean_username or not clean_email or "@" not in clean_email:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "Provide a valid username and email.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        auth = get_user_auth_info(clean_username)
        if not auth:
            params = urlencode({"role": normalized_role, "error": "Account not found."})
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        if auth.get("email", "").strip().lower() != clean_email.lower():
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "Email does not match this account.",
                }
            )
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
    elif normalized_role == ROLE_CUSTOMER:
        auth = get_customer_auth_info(clean_username)
        if not auth:
            params = urlencode({"role": normalized_role, "error": "Account not found."})
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        if auth.get("contact_email", "").strip().lower() != clean_email.lower():
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "Email does not match this account.",
                }
            )
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
    else:
        params = urlencode({"error": "Unknown role."})
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    try:
        send_reset_code(normalized_role, clean_username, clean_email)
    except RuntimeError as exc:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": str(exc),
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    params = urlencode(
        {
            "role": normalized_role,
            "username": clean_username,
            "notice": "Password reset code sent. Check your inbox.",
        }
    )
    return RedirectResponse(url=f"/reset?{params}", status_code=303)


@app.post("/reset/confirm")
async def confirm_password_reset(
    role: Annotated[str, Form()],
    username: Annotated[str, Form()],
    code: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
):
    """Confirm the reset code and set a new password."""

    clean_username = normalize_username(username)
    normalized_role = role.strip().lower()
    if normalized_role not in {ROLE_HELPER, ROLE_CUSTOMER}:
        normalized_role = resolve_role_for_username(clean_username)
    if normalized_role not in {ROLE_HELPER, ROLE_CUSTOMER}:
        params = urlencode(
            {
                "username": clean_username,
                "error": "Select helper or customer login for this username.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)
    clean_code = code.strip().replace(" ", "")
    if not clean_username or not clean_code:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "Enter the reset code from your email.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if new_password != confirm_password:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "New passwords do not match.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)
    if not new_password.strip():
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "New password cannot be empty.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        auth = get_user_auth_info(clean_username)
        login_url = "/helpers?notice=Password%20reset.%20Please%20log%20in."
        if not auth:
            params = urlencode({"role": normalized_role, "error": "Account not found."})
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        if is_code_expired(auth.get("reset_expires_at")):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "That code has expired. Request a new one.",
                }
            )
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        expected_hash = auth.get("reset_code_hash", "")
    elif normalized_role == ROLE_CUSTOMER:
        auth = get_customer_auth_info(clean_username)
        login_url = "/customers?notice=Password%20reset.%20Please%20log%20in."
        if not auth:
            params = urlencode({"role": normalized_role, "error": "Account not found."})
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        if is_code_expired(auth.get("reset_expires_at")):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "error": "That code has expired. Request a new one.",
                }
            )
            return RedirectResponse(url=f"/reset?{params}", status_code=303)
        expected_hash = auth.get("reset_code_hash", "")
    else:
        params = urlencode({"error": "Unknown role."})
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if not expected_hash:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "No active reset code found. Request a new one.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if hash_verification_code(clean_code) != expected_hash:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "That code did not match. Please try again.",
            }
        )
        return RedirectResponse(url=f"/reset?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        update_user_password(clean_username, new_password)
        clear_user_reset_code(clean_username)
    else:
        update_customer_password(clean_username, new_password)
        clear_customer_reset_code(clean_username)

    return RedirectResponse(url=login_url, status_code=303)


@app.get("/verify/resend", response_class=HTMLResponse)
async def resend_verification_page(
    request: Request,
    role: Annotated[str, Query()] = "",
    username: Annotated[str, Query()] = "",
    notice: Annotated[Optional[str], Query()] = None,
    error: Annotated[Optional[str], Query()] = None,
    auto_login: Annotated[Optional[str], Query()] = None,
):
    """Show the resend verification form."""

    normalized_role = role.strip().lower()
    clean_username = normalize_username(username) if username else ""
    email = ""
    if clean_username and normalized_role == ROLE_HELPER:
        record = get_user_auth_info(clean_username)
        if record:
            email = record.get("email", "")
    elif clean_username and normalized_role == ROLE_CUSTOMER:
        record = get_customer_auth_info(clean_username)
        if record:
            email = record.get("contact_email", "")

    return public_templates.TemplateResponse(
        "verification_resend.html",
        {
            "request": request,
            "role": normalized_role,
            "username": clean_username,
            "email": email,
            "notice": notice,
            "error": error,
            "auto_login": auto_login,
        },
    )


@app.post("/verify/resend", response_class=HTMLResponse)
async def resend_verification(
    request: Request,
    role: Annotated[str, Form()],
    username: Annotated[str, Form()],
    email: Annotated[str, Form()],
    auto_login: Annotated[Optional[str], Form()] = None,
):
    """Send another verification code to the user."""

    normalized_role = role.strip().lower()
    clean_username = normalize_username(username)
    clean_email = email.strip()
    auto_login_value = auto_login or ""

    if not clean_username:
        return RedirectResponse(
            url="/verify/resend?error=Missing%20username.",
            status_code=303,
        )
    if not clean_email or "@" not in clean_email:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": "Provide a valid email address.",
                "auto_login": auto_login_value,
            }
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    if normalized_role == ROLE_HELPER:
        auth = get_user_auth_info(clean_username)
        if not auth:
            params = urlencode(
                {
                    "error": "Account not found.",
                    "role": normalized_role,
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if auth.get("email_verified"):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "notice": "Your email is already verified.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        update_user_email(clean_username, clean_email)
    elif normalized_role == ROLE_CUSTOMER:
        auth = get_customer_auth_info(clean_username)
        if not auth:
            params = urlencode(
                {
                    "error": "Account not found.",
                    "role": normalized_role,
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        if auth.get("email_verified"):
            params = urlencode(
                {
                    "role": normalized_role,
                    "username": clean_username,
                    "notice": "Your email is already verified.",
                    "auto_login": auto_login_value,
                }
            )
            return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
        update_customer_email(clean_username, clean_email)
    else:
        return RedirectResponse(
            url="/verify/resend?error=Unknown%20role.",
            status_code=303,
        )

    try:
        send_verification_code(normalized_role, clean_username, clean_email)
    except RuntimeError as exc:
        params = urlencode(
            {
                "role": normalized_role,
                "username": clean_username,
                "error": str(exc),
                "auto_login": auto_login_value,
            }
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    params = urlencode(
        {
            "role": normalized_role,
            "username": clean_username,
            "notice": "Verification code sent. Check your inbox.",
            "auto_login": auto_login or "",
        }
    )
    return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)


# --- Session actions -------------------------------------------------------
@app.post("/logout")
async def logout(
    session_token: Annotated[Optional[str], Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> RedirectResponse:
    """Clear the login cookie and send the user back to the homepage."""

    session = resolve_session_data(session_token)
    if session and session.role == ROLE_HELPER:
        set_helper_offline(session.username)

    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    response.delete_cookie(PENDING_JOB_COOKIE)
    response.delete_cookie(PENDING_CHAT_COOKIE)
    return response


# --- Helper authentication -------------------------------------------------
@app.get("/helpers", response_class=HTMLResponse)
async def login_helpers(request: Request):
    """Render the helper login/signup page."""

    notice = request.query_params.get("notice")
    verified = request.query_params.get("verified")
    login_notice = notice
    if verified:
        login_notice = "Email verified. Please log in."
    return helper_templates.TemplateResponse(
        "login.html",
        {"request": request, "login_notice": login_notice},
    )


@app.post("/helpers/login")
async def load_helpers(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    """Authenticate helper credentials and start a session."""

    clean_username = normalize_username(username)
    auth = get_user_auth_info(clean_username)
    customer_auth = get_customer_auth_info(clean_username)
    if not auth and not customer_auth:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "User not found",
                "username": clean_username,
                "highlight_error": True,
            },
            status_code=404,
        )

    password_verified = False
    if auth:
        stored_password = auth.get("password", "")
        if verify_password(stored_password, password):
            password_verified = True
        elif customer_auth and verify_password(customer_auth.get("password", ""), password):
            if update_user_password(clean_username, password):
                auth = get_user_auth_info(clean_username)
                password_verified = True
        if not password_verified:
            return helper_templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Incorrect password",
                    "username": clean_username,
                    "highlight_error": True,
                },
                status_code=401,
            )
    else:
        stored_password = customer_auth.get("password", "") if customer_auth else ""
        if not customer_auth or not verify_password(stored_password, password):
            return helper_templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Incorrect password",
                    "username": clean_username,
                    "highlight_error": True,
                },
                status_code=401,
            )
        created = create_user(
            clean_username,
            password,
            "General Helper",
            "hourly",
            0.0,
            "",
            customer_auth.get("contact_email", "") if customer_auth else "",
            allow_reserved=True,
        )
        auth = get_user_auth_info(clean_username)
        password_verified = True
        if created and customer_auth and customer_auth.get("email_verified"):
            mark_user_verified(clean_username)
            auth = get_user_auth_info(clean_username)

    if not auth or not password_verified:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Unable to sign in. Please try again.",
                "username": clean_username,
                "highlight_error": True,
            },
            status_code=401,
        )

    if customer_auth and not verify_password(customer_auth.get("password", ""), password):
        update_customer_password(clean_username, password)

    if customer_auth:
        helper_email = (auth.get("email") or "").strip()
        customer_email = (customer_auth.get("contact_email") or "").strip()
        if not helper_email and customer_email:
            update_user_email(clean_username, customer_email)
            auth = get_user_auth_info(clean_username)
        if auth and not auth.get("email_verified") and customer_auth.get("email_verified"):
            mark_user_verified(clean_username)
            auth = get_user_auth_info(clean_username)

    stored_password = auth.get("password", "")
    if not is_password_hashed(stored_password):
        update_user_password(clean_username, password)

    if not auth.get("email_verified"):
        params = urlencode(
            {"role": ROLE_HELPER, "username": clean_username, "auto_login": "1"}
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    return build_session_response(clean_username, ROLE_HELPER)


@app.post("/helpers/signup")
async def signup_helper(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    email: Annotated[str, Form()],
    profession: Annotated[str, Form()],
    service_location: Annotated[str, Form()],
    max_distance_miles: Annotated[float, Form()],
    pay_type: Annotated[str, Form()],
    pay_rate: Annotated[float, Form()],
    bio: Annotated[str, Form()],
):
    """Create a helper account and send a verification code."""

    clean_username = normalize_username(username)
    clean_email = email.strip()
    if not clean_email or "@" not in clean_email:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": "Please provide a valid email address.",
                "username": clean_username,
                "highlight_error": True,
                "login_notice": "We need your email to verify your account.",
                "start_page": "signup",
            },
            status_code=400,
        )

    if username_in_use(clean_username):
        accept_header = request.headers.get("accept", "")
        message = "Username already in use. Please choose another."
        if "text/html" in accept_header:
            return helper_templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "username": clean_username,
                    "signup_error": message,
                    "start_page": "signup",
                },
                status_code=409,
            )

        return {"success": False, "message": message}

    clean_location = service_location.strip()
    if not clean_location:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": "Please enter where you want to work.",
                "start_page": "signup",
            },
            status_code=400,
        )

    location_message = _ensure_safe_text(clean_location, allow_address=False, context="your service location")
    if location_message:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": location_message,
                "username": clean_username,
                "highlight_error": True,
                "start_page": "signup",
            },
            status_code=400,
        )

    clean_bio = bio.strip()
    bio_message = _ensure_safe_text(clean_bio, allow_address=False, context="your bio")
    if bio_message:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": bio_message,
                "username": clean_username,
                "highlight_error": True,
                "start_page": "signup",
            },
            status_code=400,
        )

    normalized_pay_type = normalize_pay_type(pay_type)
    validate_pay_rate(pay_rate)
    clean_profession = normalize_profession(profession)
    max_distance = validate_max_distance(max_distance_miles)
    _ensure_location_data_loaded()
    coords = _geocode_location(clean_location)
    if not coords:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": "Service location not recognized. Use City, ST.",
                "start_page": "signup",
            },
            status_code=400,
        )
    location_lat, location_lon = coords

    created = create_user(
        clean_username,
        password,
        clean_profession,
        normalized_pay_type,
        pay_rate,
        clean_bio,
        clean_email,
        clean_location,
        max_distance,
        location_lat,
        location_lon,
    )
    if not created:
        accept_header = request.headers.get("accept", "")
        message = "Account already exists. Please log in instead."
        if "text/html" in accept_header:
            return helper_templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "username": clean_username,
                    "signup_error": message,
                    "start_page": "signup",
                },
                status_code=409,
            )

        return {"success": False, "message": message}

    try:
        send_verification_code(ROLE_HELPER, clean_username, clean_email)
    except RuntimeError as exc:
        return helper_templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "signup_error": str(exc),
                "username": clean_username,
                "login_notice": "Account created, but we could not send a verification code.",
                "start_page": "signup",
            },
            status_code=500,
        )

    params = urlencode(
        {
            "role": ROLE_HELPER,
            "username": clean_username,
            "notice": "Verification code sent. Enter it below to finish signup.",
            "auto_login": "1",
        }
    )
    return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)


# --- Customer authentication ----------------------------------------------
@app.get("/customers", response_class=HTMLResponse)
async def login_customers(request: Request):
    """Render the customer login/signup page."""

    mode = request.query_params.get("mode", "login")
    mode = mode if mode in {"login", "signup"} else "login"
    notice = request.query_params.get("notice")
    if request.query_params.get("verified"):
        notice = "Email verified. Please log in."
    return customer_templates.TemplateResponse(
        "customer_login.html",
        {"request": request, "mode": mode, "notice": notice},
    )


@app.post("/customers/login")
async def customer_login(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    """Authenticate customer credentials and start a session."""

    clean_username = normalize_username(username)
    auth = get_customer_auth_info(clean_username)
    helper_auth = get_user_auth_info(clean_username)
    if not auth and not helper_auth:
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": "Customer not found",
                "mode": "login",
                "username": clean_username,
            },
            status_code=404,
        )

    password_verified = False
    if auth:
        stored_password = auth.get("password", "")
        if verify_password(stored_password, password):
            password_verified = True
        elif helper_auth and verify_password(helper_auth.get("password", ""), password):
            if update_customer_password(clean_username, password):
                auth = get_customer_auth_info(clean_username)
                password_verified = True
        if not password_verified:
            return customer_templates.TemplateResponse(
                "customer_login.html",
                {
                    "request": request,
                    "error": "Incorrect password",
                    "mode": "login",
                    "username": clean_username,
                },
                status_code=401,
            )
    else:
        stored_password = helper_auth.get("password", "") if helper_auth else ""
        if not helper_auth or not verify_password(stored_password, password):
            return customer_templates.TemplateResponse(
                "customer_login.html",
                {
                    "request": request,
                    "error": "Incorrect password",
                    "mode": "login",
                    "username": clean_username,
                },
                status_code=401,
            )
        created = create_customer(
            clean_username,
            password,
            "",
            helper_auth.get("email", "") if helper_auth else "",
            allow_reserved=True,
        )
        auth = get_customer_auth_info(clean_username)
        password_verified = True
        if created and helper_auth and helper_auth.get("email_verified"):
            mark_customer_verified(clean_username)
            auth = get_customer_auth_info(clean_username)

    if not auth or not password_verified:
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": "Unable to sign in. Please try again.",
                "mode": "login",
                "username": clean_username,
            },
            status_code=401,
        )

    if helper_auth and not verify_password(helper_auth.get("password", ""), password):
        update_user_password(clean_username, password)

    if helper_auth:
        customer_email = (auth.get("contact_email") or "").strip()
        helper_email = (helper_auth.get("email") or "").strip()
        if not customer_email and helper_email:
            update_customer_email(clean_username, helper_email)
            auth = get_customer_auth_info(clean_username)
        if auth and not auth.get("email_verified") and helper_auth.get("email_verified"):
            mark_customer_verified(clean_username)
            auth = get_customer_auth_info(clean_username)

    stored_password = auth.get("password", "")
    if not is_password_hashed(stored_password):
        update_customer_password(clean_username, password)

    if not auth.get("email_verified"):
        params = urlencode(
            {"role": ROLE_CUSTOMER, "username": clean_username, "auto_login": "1"}
        )
        return RedirectResponse(url=f"/verify/resend?{params}", status_code=303)

    pending_chat = _load_signed_cookie(request, PENDING_CHAT_COOKIE, PENDING_CHAT_TTL_SECONDS)
    if pending_chat and pending_chat.get("chat_id"):
        response = build_session_response(
            clean_username,
            ROLE_CUSTOMER,
            next_path=f"/customers/chats?chatId={pending_chat['chat_id']}",
        )
        _clear_cookie(response, PENDING_CHAT_COOKIE)
        return response

    return build_session_response(clean_username, ROLE_CUSTOMER)


@app.post("/customers/signup")
async def customer_signup(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    contact_email: Annotated[str, Form()],
):
    """Create a customer account and send a verification code."""

    clean_username = normalize_username(username)
    clean_email = contact_email.strip()
    if not clean_email or "@" not in clean_email:
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": "Please provide a valid email address.",
                "mode": "signup",
                "username": clean_username,
            },
            status_code=400,
        )

    if username_in_use(clean_username):
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": "Username already in use. Please choose another.",
                "mode": "signup",
                "username": clean_username,
            },
            status_code=409,
        )

    created = create_customer(clean_username, password, full_name, clean_email)
    if not created:
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": "Account already exists",
                "mode": "signup",
                "username": clean_username,
            },
            status_code=409,
        )

    pending_job = _load_signed_cookie(request, PENDING_JOB_COOKIE, PENDING_JOB_TTL_SECONDS)
    pending_chat_id = None
    if pending_job:
        pending_chat_id = _create_job_and_chat_from_pending(clean_username, pending_job)

    try:
        send_verification_code(ROLE_CUSTOMER, clean_username, clean_email)
    except RuntimeError as exc:
        return customer_templates.TemplateResponse(
            "customer_login.html",
            {
                "request": request,
                "error": str(exc),
                "mode": "login",
                "username": clean_username,
                "notice": "Account created, but we could not send a verification code.",
            },
            status_code=500,
        )

    notice = "Check your email for the verification code."
    if pending_job and pending_chat_id:
        notice = (
            "Check your email for the verification code. "
            "We saved your request and will open the chat after you log in."
        )

    params = urlencode(
        {
            "role": ROLE_CUSTOMER,
            "username": clean_username,
            "notice": notice,
            "auto_login": "1",
        }
    )
    response = RedirectResponse(url=f"/verify/resend?{params}", status_code=303)
    if pending_job:
        _clear_cookie(response, PENDING_JOB_COOKIE)
    if pending_chat_id:
        _set_signed_cookie(
            response,
            PENDING_CHAT_COOKIE,
            {"chat_id": pending_chat_id},
            PENDING_CHAT_TTL_SECONDS,
        )
    return response


# --- Helper pages ----------------------------------------------------------
@app.get("/helpers/home", response_class=HTMLResponse)
async def helper_home_page(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Show the helper dashboard."""

    profile = get_user_profile(session.username)
    return helper_templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "username": session.username,
            "profile": profile,
        },
    )


@app.get("/helpers/chats", response_class=HTMLResponse)
async def helper_chats_page(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Show helper chat inbox."""

    return helper_templates.TemplateResponse(
        "helper_chats.html",
        {
            "request": request,
            "username": session.username,
        },
    )


@app.get("/helpers/profile", response_class=HTMLResponse)
async def helper_profile_page(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Show helper profile details."""

    profile = get_user_profile(session.username)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    auth = get_user_auth_info(session.username) or {}
    message = request.query_params.get("message")
    error = request.query_params.get("error")
    completed_jobs = _count_helper_completed_jobs(session.username)
    credentials = list_helper_credentials(session.username)
    images = [
        {
            **image,
            "url": _build_image_url(image["id"]),
        }
        for image in list_helper_images(session.username)
    ]
    background_check = get_helper_background_check(session.username) or {}
    background_status = normalize_background_status(background_check.get("status", "unverified"))
    background_verified = background_is_verified(background_status)

    return helper_templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "username": session.username,
            "profile": profile,
            "email": auth.get("email", ""),
            "email_verified": bool(auth.get("email_verified")),
            "completed_jobs": completed_jobs,
            "credentials": credentials,
            "images": images,
            "background_status": background_status,
            "background_verified": background_verified,
            "message": message,
            "error": error,
        },
    )


@app.post("/helpers/profile/email")
async def update_helper_email(
    email: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Update helper email and require re-verification."""

    clean_email = email.strip()
    if not clean_email or "@" not in clean_email:
        return helper_profile_redirect(error="Provide a valid email address.")

    auth = get_user_auth_info(session.username) or {}
    current_email = (auth.get("email") or "").strip()
    if current_email.lower() == clean_email.lower():
        if auth.get("email_verified"):
            return helper_profile_redirect(message="Your email is already verified.")
        try:
            send_verification_code(ROLE_HELPER, session.username, clean_email)
        except RuntimeError as exc:
            return helper_profile_redirect(error=str(exc))
        return helper_profile_redirect(message="Verification code resent. Check your inbox.")

    try:
        send_verification_code(ROLE_HELPER, session.username, clean_email)
    except RuntimeError as exc:
        return helper_profile_redirect(error=str(exc))

    return helper_profile_redirect(
        message="Email updated. Check your inbox to verify the new address."
    )


@app.post("/helpers/profile/credentials")
async def add_helper_credential_route(
    credential_title: Annotated[str, Form()],
    credential_issuer: Annotated[Optional[str], Form()] = None,
    credential_year: Annotated[Optional[str], Form()] = None,
    session: SessionData = Depends(require_helper_user),
):
    """Allow helpers to add credentials to their profile."""

    title = credential_title.strip()
    issuer = (credential_issuer or "").strip()
    year = (credential_year or "").strip()
    if not title:
        return helper_profile_redirect(error="Credential title is required.")

    for label, value in (("credential title", title), ("credential issuer", issuer)):
        message = _ensure_safe_text(value, allow_address=False, context=label)
        if message:
            return helper_profile_redirect(error=message)

    added = add_helper_credential(session.username, title, issuer, year)
    if not added:
        return helper_profile_redirect(error="Unable to add credential right now.")

    return helper_profile_redirect(message="Credential added.")


@app.post("/helpers/profile/credentials/delete")
async def delete_helper_credential_route(
    credential_id: Annotated[int, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow helpers to remove credentials from their profile."""

    deleted = delete_helper_credential(session.username, credential_id)
    if not deleted:
        return helper_profile_redirect(error="Unable to remove credential.")

    return helper_profile_redirect(message="Credential removed.")


@app.post("/helpers/profile/images")
async def upload_helper_images(
    images: list[UploadFile] = File(...),
    session: SessionData = Depends(require_helper_user),
):
    """Allow helpers to upload portfolio images."""

    if not images:
        return helper_profile_redirect(error="Select at least one image to upload.")

    for image in images:
        try:
            file_name, content_type, file_bytes = await _read_helper_image_upload(image)
        except HTTPException as exc:
            return helper_profile_redirect(error=str(exc.detail))

        saved = add_helper_image(session.username, file_name, content_type, file_bytes)
        if not saved:
            return helper_profile_redirect(error="Unable to save uploaded image.")

    return helper_profile_redirect(message="Portfolio images uploaded.")


@app.post("/helpers/profile/images/delete")
async def delete_helper_image_route(
    image_id: Annotated[int, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow helpers to remove portfolio images."""

    deleted = delete_helper_image(session.username, image_id)
    if not deleted:
        return helper_profile_redirect(error="Image not found.")

    return helper_profile_redirect(message="Image removed.")


@app.post("/helpers/profile/background-check/start")
async def start_background_check(
    request: Request,
    fcra_consent: Annotated[Optional[str], Form()] = None,
    session: SessionData = Depends(require_helper_user),
):
    """Mark a helper background check as started."""

    if not fcra_consent:
        return helper_profile_redirect(
            error="Please acknowledge the background check disclosure before continuing."
        )

    auth = get_user_auth_info(session.username) or {}
    email = (auth.get("email") or "").strip()
    if CHECKR_API_KEY and CHECKR_PACKAGE_ID and email:
        redirect_url = f"{build_base_url(request)}/helpers/profile"
        try:
            response = _checkr_create_invitation(session.username, email, redirect_url)
            invite_url = _checkr_invitation_url(response)
            external_id = response.get("id", "")
        except RuntimeError as exc:
            return helper_profile_redirect(error=str(exc))
        upsert_helper_background_check(
            session.username,
            "pending",
            "checkr",
            external_id,
        )
        return RedirectResponse(url=invite_url, status_code=303)

    upsert_helper_background_check(session.username, "pending", BACKGROUND_CHECK_VENDOR, "")
    return helper_profile_redirect(
        message="Background check requested. We will contact you with next steps."
    )


@app.get("/helpers/stripe/connect")
async def stripe_connect_account(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Start Stripe Connect onboarding for helpers."""

    auth = get_user_auth_info(session.username) or {}
    email = (auth.get("email") or "").strip()
    if not email:
        return helper_profile_redirect(error="Add an email address before connecting payouts.")

    stripe_info = get_user_stripe_info(session.username) or {}
    account_id = stripe_info.get("stripe_account_id") or ""
    if not account_id:
        try:
            account = _stripe_create_account(email)
        except RuntimeError as exc:
            return helper_profile_redirect(error=str(exc))
        account_id = account.get("id", "")
        if not account_id:
            return helper_profile_redirect(error="Stripe did not return an account ID.")
        update_user_stripe_info(session.username, account_id, False)

    base_url = build_base_url(request)
    refresh_url = f"{base_url}/helpers/stripe/connect"
    return_url = f"{base_url}/helpers/stripe/return"
    try:
        onboarding_url = _stripe_create_account_link(account_id, refresh_url, return_url)
    except RuntimeError as exc:
        return helper_profile_redirect(error=str(exc))

    return RedirectResponse(url=onboarding_url, status_code=303)


@app.get("/helpers/stripe/return")
async def stripe_connect_return(
    session: SessionData = Depends(require_helper_user),
):
    """Handle Stripe Connect return and refresh status."""

    stripe_info = get_user_stripe_info(session.username) or {}
    account_id = stripe_info.get("stripe_account_id") or ""
    if not account_id:
        return helper_profile_redirect(error="Stripe account not found.")

    try:
        account = _stripe_retrieve_account(account_id)
    except RuntimeError as exc:
        return helper_profile_redirect(error=str(exc))

    onboarding_complete = bool(account.get("details_submitted")) and bool(
        account.get("payouts_enabled")
    )
    update_user_stripe_info(session.username, account_id, onboarding_complete)
    if onboarding_complete:
        return helper_profile_redirect(message="Payouts connected.")
    return helper_profile_redirect(message="Stripe onboarding is still incomplete.")


@app.get("/helpers/stripe/dashboard")
async def stripe_connect_dashboard(
    session: SessionData = Depends(require_helper_user),
):
    """Open the Stripe Express dashboard for helpers."""

    stripe_info = get_user_stripe_info(session.username) or {}
    account_id = stripe_info.get("stripe_account_id") or ""
    if not account_id:
        return helper_profile_redirect(error="Stripe account not connected.")
    try:
        login_url = _stripe_create_login_link(account_id)
    except RuntimeError as exc:
        return helper_profile_redirect(error=str(exc))
    return RedirectResponse(url=login_url, status_code=303)


@app.get("/profession-change", response_class=HTMLResponse)
async def profession_change_page(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Allow helpers to change their profession."""

    profile = get_user_profile(session.username)
    return helper_templates.TemplateResponse(
        "profession_change.html",
        {
            "request": request,
            "username": session.username,
            "profile": profile,
        },
    )


@app.get("/helpers/job/{job_id}", response_class=HTMLResponse)
async def job_detail_page(
    request: Request,
    job_id: int,
    session: SessionData = Depends(require_helper_user),
):
    """Show full job details to helpers."""

    job = get_job(job_id)
    if not job or job.get("status") != "open":
        raise HTTPException(status_code=404, detail="Job not found")

    return helper_templates.TemplateResponse(
        "job_detail.html",
        {
            "request": request,
            "username": session.username,
            "job_id": job_id,
            "customer_username": job["customer_username"],
        },
    )


# --- Customer pages --------------------------------------------------------
@app.get("/customers/home", response_class=HTMLResponse)
async def customer_home(
    request: Request,
    session: SessionData = Depends(require_customer_user),
):
    """Show customer dashboard."""

    profile = get_customer_profile(session.username)
    return customer_templates.TemplateResponse(
        "customer_home.html",
        {
            "request": request,
            "username": session.username,
            "profile": profile,
        },
    )


@app.get("/customers/job-posted", response_class=HTMLResponse)
async def customer_job_posted(
    request: Request,
    session: SessionData = Depends(require_customer_user),
):
    """Show a confirmation page after the first job post."""

    return customer_templates.TemplateResponse(
        "job_posted.html",
        {
            "request": request,
            "username": session.username,
        },
    )


@app.get("/customers/helpers", response_class=HTMLResponse)
async def customer_helpers_page(
    request: Request,
    session: SessionData = Depends(require_customer_user),
):
    """Show helper search page for customers."""

    return customer_templates.TemplateResponse(
        "customer_helpers.html",
        {
            "request": request,
            "username": session.username,
        },
    )


@app.get("/customers/helpers/{helper_username}", response_class=HTMLResponse)
async def customer_helper_profile_page(
    request: Request,
    helper_username: str,
    session: SessionData = Depends(require_customer_user),
):
    """Show a helper profile to a customer."""

    profile = get_user_profile(helper_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Helper not found")

    completed_jobs = _count_helper_completed_jobs(helper_username)
    credentials = list_helper_credentials(helper_username)
    images = [
        {
            **image,
            "url": _build_image_url(image["id"]),
        }
        for image in list_helper_images(helper_username)
    ]
    reviews = list_helper_reviews(helper_username)
    average_rating = _average_rating(reviews)
    review_jobs = _reviewable_jobs_for_helper(session.username, helper_username)
    selected_job_id = request.query_params.get("job_id")
    try:
        selected_job_id_int = int(selected_job_id) if selected_job_id else None
    except (TypeError, ValueError):
        selected_job_id_int = None
    can_review = bool(review_jobs)
    message = request.query_params.get("message")
    error = request.query_params.get("error")
    background_status = normalize_background_status(
        (get_helper_background_check(helper_username) or {}).get("status", "unverified")
    )
    background_verified = background_is_verified(background_status)

    return customer_templates.TemplateResponse(
        "helper_profile.html",
        {
            "request": request,
            "username": session.username,
            "helper": profile,
            "completed_jobs": completed_jobs,
            "credentials": credentials,
            "images": images,
            "reviews": reviews,
            "average_rating": average_rating,
            "can_review": can_review,
            "review_jobs": review_jobs,
            "selected_job_id": selected_job_id_int,
            "background_status": background_status,
            "background_verified": background_verified,
            "message": message,
            "error": error,
        },
    )


@app.post("/customers/helpers/{helper_username}/reviews")
async def customer_submit_review(
    helper_username: str,
    job_id: Annotated[int, Form()],
    rating: Annotated[int, Form()],
    review_text: Annotated[Optional[str], Form()] = None,
    session: SessionData = Depends(require_customer_user),
):
    """Allow customers to leave a review for a helper."""

    profile = get_user_profile(helper_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Helper not found")

    review_job = _get_reviewable_job(session.username, helper_username, job_id)
    if not review_job:
        params = urlencode({"error": "Select a completed job with this helper before leaving a review."})
        return RedirectResponse(
            url=f"/customers/helpers/{helper_username}?{params}",
            status_code=303,
        )

    if rating < 1 or rating > 5:
        params = urlencode({"error": "Rating must be between 1 and 5."})
        return RedirectResponse(
            url=f"/customers/helpers/{helper_username}?{params}",
            status_code=303,
        )

    clean_review = (review_text or "").strip()
    review_message = _ensure_safe_text(clean_review, allow_address=False, context="your review")
    if review_message:
        params = urlencode({"error": review_message})
        return RedirectResponse(
            url=f"/customers/helpers/{helper_username}?{params}",
            status_code=303,
        )

    saved = upsert_helper_review(
        helper_username,
        session.username,
        review_job["id"],
        review_job.get("title") or "Completed job",
        rating,
        clean_review,
    )
    if not saved:
        params = urlencode({"error": "Unable to save review right now."})
        return RedirectResponse(
            url=f"/customers/helpers/{helper_username}?{params}",
            status_code=303,
        )

    params = urlencode({"message": "Review saved. Thank you!"})
    return RedirectResponse(
        url=f"/customers/helpers/{helper_username}?{params}",
        status_code=303,
    )


@app.post("/customers/helpers/{helper_username}/reviews/{review_id}/delete")
async def customer_delete_review(
    helper_username: str,
    review_id: int,
    session: SessionData = Depends(require_customer_user),
):
    """Allow customers to delete their own review for a helper."""

    profile = get_user_profile(helper_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Helper not found")

    deleted = delete_helper_review(review_id, helper_username, session.username)
    if not deleted:
        params = urlencode({"error": "Unable to delete that review."})
        return RedirectResponse(
            url=f"/customers/helpers/{helper_username}?{params}",
            status_code=303,
        )

    params = urlencode({"message": "Review deleted."})
    return RedirectResponse(
        url=f"/customers/helpers/{helper_username}?{params}",
        status_code=303,
    )


@app.get("/customers/chats", response_class=HTMLResponse)
async def customer_chats_page(
    request: Request,
    session: SessionData = Depends(require_customer_user),
):
    """Show customer chat inbox."""

    return customer_templates.TemplateResponse(
        "customer_chats.html",
        {
            "request": request,
            "username": session.username,
            "stripe_publishable_key": STRIPE_PUBLISHABLE_KEY,
            "customer_service_fee_percent": CUSTOMER_SERVICE_FEE_PERCENT,
            "sales_tax_percent": SALES_TAX_PERCENT,
            "min_job_payment_cents": MIN_JOB_PAYMENT_CENTS,
        },
    )


@app.get("/customers/profile", response_class=HTMLResponse)
async def customer_profile_page(
    request: Request,
    session: SessionData = Depends(require_customer_user),
):
    """Show the customer profile settings page."""

    profile = get_customer_profile(session.username)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    message = request.query_params.get("message")
    error = request.query_params.get("error")
    return customer_templates.TemplateResponse(
        "customer_profile.html",
        {
            "request": request,
            "username": session.username,
            "profile": profile,
            "message": message,
            "error": error,
        },
    )


@app.post("/customers/profile/display-name")
async def update_customer_display_name(
    display_name: Annotated[str, Form()],
    session: SessionData = Depends(require_customer_user),
):
    """Update the customer display name (full name)."""

    clean_name = display_name.strip()
    if not clean_name:
        return customer_profile_redirect(error="Display name cannot be empty.")
    updated = update_customer_full_name(session.username, clean_name)
    if not updated:
        return customer_profile_redirect(error="Unable to update display name.")
    return customer_profile_redirect(message="Display name updated.")


@app.post("/customers/profile/password")
async def update_customer_password_form(
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    session: SessionData = Depends(require_customer_user),
):
    """Update the customer password after validating the current password."""

    if new_password != confirm_password:
        return customer_profile_redirect(error="New passwords do not match.")
    if not new_password.strip():
        return customer_profile_redirect(error="New password cannot be empty.")
    stored_password = get_customer_password(session.username)
    if not verify_password(stored_password or "", current_password):
        return customer_profile_redirect(error="Current password is incorrect.")
    updated = update_customer_password(session.username, new_password)
    if not updated:
        return customer_profile_redirect(error="Unable to update password.")
    return customer_profile_redirect(message="Password updated.")


# --- Admin pages -----------------------------------------------------------
@app.get("/helpers/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Render the admin console for managing helpers."""

    require_admin(session.username)
    message = request.query_params.get("message")
    return helper_templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "username": session.username,
            "users": list_users(),
            "jobs": list_all_jobs(),
            "message": message,
        },
    )


@app.post("/helpers/admin/password")
async def admin_change_password(
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to change their own password."""

    require_admin(session.username)
    if new_password != confirm_password:
        return admin_redirect("New passwords do not match.")
    if not new_password.strip():
        return admin_redirect("New password cannot be empty.")

    stored_password = get_user_password(session.username)
    if not verify_password(stored_password or "", current_password):
        return admin_redirect("Current password is incorrect.")

    updated = update_user_password(session.username, new_password)
    if not updated:
        return admin_redirect("Unable to update password.")

    return admin_redirect("Password updated.")


@app.get("/helpers/admin/users/{target_username}", response_class=HTMLResponse)
async def admin_view_helper(
    request: Request,
    target_username: str,
    session: SessionData = Depends(require_helper_user),
):
    """Show a helper profile to the admin with credentials and images."""

    require_admin(session.username)
    profile = get_user_profile(target_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Helper not found")

    auth = get_user_auth_info(target_username) or {}
    credentials = list_helper_credentials(target_username)
    images = [
        {
            **image,
            "url": _build_image_url(image["id"]),
        }
        for image in list_helper_images(target_username)
    ]
    reviews = list_helper_reviews(target_username)
    completed_jobs = _list_helper_completed_jobs(target_username)
    message = request.query_params.get("message")

    return helper_templates.TemplateResponse(
        "admin_helper_detail.html",
        {
            "request": request,
            "username": session.username,
            "helper": profile,
            "email": auth.get("email", ""),
            "email_verified": bool(auth.get("email_verified")),
            "credentials": credentials,
            "images": images,
            "reviews": reviews,
            "completed_jobs": completed_jobs,
            "message": message,
        },
    )


@app.get("/helpers/admin/customers", response_class=HTMLResponse)
async def admin_customers_dashboard(
    request: Request,
    session: SessionData = Depends(require_helper_user),
):
    """Render the admin console for managing customers."""

    require_admin(session.username)
    message = request.query_params.get("message")
    return helper_templates.TemplateResponse(
        "admin_customers.html",
        {
            "request": request,
            "username": session.username,
            "customers": list_customers(),
            "message": message,
        },
    )


@app.get("/helpers/admin/customers/{target_username}", response_class=HTMLResponse)
async def admin_view_customer(
    request: Request,
    target_username: str,
    session: SessionData = Depends(require_helper_user),
):
    """Show a customer profile to the admin with jobs and reviews."""

    require_admin(session.username)
    profile = get_customer_profile(target_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Customer not found")

    auth = get_customer_auth_info(target_username) or {}
    all_jobs = list_jobs_for_customer(target_username)
    completed_jobs = [job for job in all_jobs if job.get("status") == "closed"]
    reviews = list_reviews_by_customer(target_username)
    message = request.query_params.get("message")

    return helper_templates.TemplateResponse(
        "admin_customer_detail.html",
        {
            "request": request,
            "username": session.username,
            "customer": profile,
            "contact_email": auth.get("contact_email", ""),
            "email_verified": bool(auth.get("email_verified")),
            "completed_jobs": completed_jobs,
            "reviews": reviews,
            "message": message,
        },
    )


@app.post("/helpers/admin/users")
async def admin_create_helper(
    request: Request,
    new_username: Annotated[str, Form(alias="username")],
    password: Annotated[str, Form()],
    email: Annotated[str, Form()],
    profession: Annotated[str, Form()],
    pay_type: Annotated[str, Form()],
    pay_rate: Annotated[float, Form()],
    bio: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to add new helper accounts."""

    require_admin(session.username)
    clean_username = normalize_username(new_username)
    normalized_pay_type = normalize_pay_type(pay_type)
    validate_pay_rate(pay_rate)
    clean_profession = normalize_profession(profession)

    clean_email = email.strip()
    if not clean_email or "@" not in clean_email:
        return admin_redirect("Provide a valid helper email address.")
    if username_in_use(clean_username):
        return admin_redirect("Username already in use.")

    clean_bio = bio.strip()
    bio_message = _ensure_safe_text(clean_bio, allow_address=False, context="helper bio")
    if bio_message:
        return admin_redirect(bio_message)

    created = create_user(
        clean_username,
        password,
        clean_profession,
        normalized_pay_type,
        pay_rate,
        clean_bio,
        clean_email,
    )
    if not created:
        return admin_redirect("User already exists.")

    try:
        send_verification_code(ROLE_HELPER, clean_username, clean_email)
    except RuntimeError as exc:
        return admin_redirect(f"User {clean_username} created, but email failed: {exc}")

    return admin_redirect(f"User {clean_username} created. Verification code sent.")


@app.post("/helpers/admin/users/update")
async def admin_update_helper(
    username: Annotated[str, Form()],
    email: Annotated[str, Form()],
    profession: Annotated[str, Form()],
    pay_type: Annotated[str, Form()],
    pay_rate: Annotated[float, Form()],
    bio: Annotated[str, Form()],
    email_verified: Annotated[Optional[str], Form()] = None,
    new_password: Annotated[Optional[str], Form()] = None,
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to edit helper account details."""

    require_admin(session.username)
    clean_username = normalize_username(username)
    normalized_pay_type = normalize_pay_type(pay_type)
    validate_pay_rate(pay_rate)
    clean_profession = normalize_profession(profession)
    clean_email = email.strip()
    if not clean_email or "@" not in clean_email:
        return admin_redirect("Provide a valid email address.")

    clean_bio = bio.strip()
    bio_message = _ensure_safe_text(clean_bio, allow_address=False, context="helper bio")
    if bio_message:
        return admin_redirect(bio_message)

    is_verified = str(email_verified or "").strip().lower() in {"1", "true", "yes", "on"}
    updated = update_user_admin(
        clean_username,
        clean_profession,
        normalized_pay_type,
        pay_rate,
        clean_bio,
        clean_email,
        is_verified,
    )
    if not updated:
        return admin_redirect("No matching helper to update.")

    if new_password and new_password.strip():
        password_updated = update_user_password(clean_username, new_password)
        if not password_updated:
            return admin_redirect("Helper updated, but password failed.")

    return admin_redirect(f"Updated {clean_username}.")


@app.post("/helpers/admin/delete")
async def admin_delete_helper(
    target_username: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to remove helper accounts."""

    require_admin(session.username)
    clean_username = normalize_username(target_username)
    if clean_username in ADMIN_USERNAMES:
        return admin_redirect("Cannot delete an admin account.")

    deleted = delete_user(clean_username)
    if deleted:
        return admin_redirect(f"Deleted {clean_username}.")

    return admin_redirect("No matching user to delete.")


@app.post("/helpers/admin/customers/update")
async def admin_update_customer(
    username: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    contact_email: Annotated[str, Form()],
    email_verified: Annotated[Optional[str], Form()] = None,
    new_password: Annotated[Optional[str], Form()] = None,
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to edit customer account details."""

    require_admin(session.username)
    clean_username = normalize_username(username)
    clean_email = contact_email.strip()
    if not clean_email or "@" not in clean_email:
        return admin_customers_redirect("Provide a valid email address.")

    is_verified = str(email_verified or "").strip().lower() in {"1", "true", "yes", "on"}
    updated = update_customer_admin(
        clean_username,
        full_name.strip(),
        clean_email,
        is_verified,
    )
    if not updated:
        return admin_customers_redirect("No matching customer to update.")

    if new_password and new_password.strip():
        password_updated = update_customer_password(clean_username, new_password)
        if not password_updated:
            return admin_customers_redirect("Customer updated, but password failed.")

    return admin_customers_redirect(f"Updated {clean_username}.")


@app.post("/helpers/admin/customers/delete")
async def admin_delete_customer(
    target_username: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to remove customer accounts."""

    require_admin(session.username)
    clean_username = normalize_username(target_username)
    deleted = delete_customer(clean_username)
    if deleted:
        return admin_customers_redirect(f"Deleted {clean_username}.")

    return admin_customers_redirect("No matching customer to delete.")


@app.post("/helpers/admin/customers")
async def admin_create_customer(
    request: Request,
    new_username: Annotated[str, Form(alias="username")],
    password: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    contact_email: Annotated[str, Form()],
    session: SessionData = Depends(require_helper_user),
):
    """Allow admins to add new customer accounts."""

    require_admin(session.username)
    clean_username = normalize_username(new_username)
    clean_email = contact_email.strip()
    if not clean_email or "@" not in clean_email:
        return admin_customers_redirect("Provide a valid customer email address.")
    if username_in_use(clean_username):
        return admin_customers_redirect("Username already in use.")

    created = create_customer(clean_username, password, full_name, clean_email)
    if not created:
        return admin_customers_redirect("Customer already exists.")

    try:
        send_verification_code(ROLE_CUSTOMER, clean_username, clean_email)
    except RuntimeError as exc:
        return admin_customers_redirect(
            f"Customer {clean_username} created, but email failed: {exc}"
        )

    return admin_customers_redirect(
        f"Customer {clean_username} created. Verification code sent."
    )


# --- Helper API (JSON data for the frontend) -------------------------------
@app.get("/helpers/api/jobs")
async def api_search_jobs(
    q: Optional[str] = Query(default="", max_length=100),
    session: SessionData = Depends(require_helper_user),
):
    """Search open jobs for helpers."""

    jobs = search_customer_jobs(q or "")
    profile = get_user_profile(session.username)
    profession = profile.get("profession") if profile else ""
    if profession:
        jobs = [job for job in jobs if job_matches_profession(job, profession)]
    if profile:
        jobs = [job for job in jobs if _job_within_helper_range(job, profile)]
    return {"jobs": jobs}


@app.get("/helpers/api/jobs/{job_id}")
async def api_get_job_detail(
    job_id: int,
    session: SessionData = Depends(require_helper_user),
):
    """Return job details as JSON."""

    job = get_job(job_id)
    if not job or job.get("status") != "open":
        raise HTTPException(status_code=404, detail="Job not found")
    profile = get_user_profile(session.username)
    if profile and not _job_within_helper_range(job, profile):
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/helpers/api/profile/me")
async def api_get_profile(session: SessionData = Depends(require_helper_user)):
    """Return the helper profile for the logged-in helper."""

    profile = get_user_profile(session.username)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@app.post("/helpers/api/profile/update")
async def api_update_profile(
    payload: HelperProfileUpdateRequest,
    session: SessionData = Depends(require_helper_user),
):
    """Update helper profile details."""

    clean_location = payload.service_location.strip()
    if not clean_location:
        raise HTTPException(status_code=400, detail="Service location is required")
    location_message = _ensure_safe_text(clean_location, allow_address=False, context="your service location")
    if location_message:
        raise HTTPException(status_code=400, detail=location_message)
    _ensure_location_data_loaded()
    max_distance = validate_max_distance(payload.max_distance_miles)
    coords = _geocode_location(clean_location)
    if not coords:
        raise HTTPException(status_code=400, detail="Service location not recognized")
    location_lat, location_lon = coords
    normalized_pay_type = normalize_pay_type(payload.pay_type)
    normalized_status = normalize_availability_status(payload.availability_status)
    pay_rate = validate_pay_rate(payload.pay_rate)
    clean_bio = payload.bio.strip()
    bio_message = _ensure_safe_text(clean_bio, allow_address=False, context="your bio")
    if bio_message:
        raise HTTPException(status_code=400, detail=bio_message)
    updated = update_helper_profile(
        session.username,
        normalized_pay_type,
        pay_rate,
        clean_bio,
        clean_location,
        max_distance,
        location_lat,
        location_lon,
        normalized_status,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile = get_user_profile(session.username)
    return {"success": True, "profile": profile}


@app.post("/helpers/api/status/update")
async def api_update_helper_status(
    payload: HelperStatusUpdateRequest,
    session: SessionData = Depends(require_helper_user),
):
    """Update the helper availability status only."""

    normalized_status = normalize_availability_status(payload.availability_status)
    updated = update_helper_status(session.username, normalized_status)
    if not updated:
        raise HTTPException(status_code=404, detail="Profile not found")
    if normalized_status in {"active", "on_call"}:
        touch_helper_last_seen(session.username)
    return {"success": True, "availability_status": normalized_status}


# --- Customer API (JSON data for the frontend) -----------------------------
@app.get("/customers/api/jobs")
async def api_list_customer_jobs(
    session: SessionData = Depends(require_customer_user),
):
    """Return all jobs for the logged-in customer."""

    return {"jobs": list_jobs_for_customer(session.username)}


@app.get("/customers/api/helpers")
async def api_search_helpers_for_customer(
    q: Optional[str] = Query(default="", max_length=100),
    job_id: Optional[int] = Query(default=None),
    session: SessionData = Depends(require_customer_user),
):
    """Search helper profiles for customers."""

    helpers = search_helpers(q or "")
    if job_id is not None:
        job = get_job(job_id)
        if job and normalize_username(job.get("customer_username", "")) == session.username:
            coords = _get_job_coordinates(job)
            if coords:
                helpers = _filter_helpers_by_coords(helpers, coords[0], coords[1])
    safe_helpers = []
    for helper in helpers:
        safe_helpers.append(
            {
                "username": helper.get("username", ""),
                "profession": helper.get("profession", ""),
                "pay_type": helper.get("pay_type", ""),
                "pay_rate": helper.get("pay_rate", 0),
                "bio": helper.get("bio", ""),
                "availability_status": helper.get("availability_status", "active"),
            }
        )
    return {"helpers": safe_helpers}


@app.get("/customers/api/helpers/{helper_username}")
async def api_get_helper_profile_for_customer(
    helper_username: str,
    session: SessionData = Depends(require_customer_user),
):
    """Return a helper profile with credentials, images, and reviews."""

    profile = get_user_profile(helper_username)
    if not profile:
        raise HTTPException(status_code=404, detail="Helper not found")

    credentials = list_helper_credentials(helper_username)
    images = [
        {
            **image,
            "url": _build_image_url(image["id"]),
        }
        for image in list_helper_images(helper_username)
    ]
    reviews = list_helper_reviews(helper_username)
    background_status = normalize_background_status(
        (get_helper_background_check(helper_username) or {}).get("status", "unverified")
    )
    background_verified = background_is_verified(background_status)
    return {
        "helper": profile,
        "credentials": credentials,
        "images": images,
        "reviews": reviews,
        "average_rating": _average_rating(reviews),
        "background_status": background_status,
        "background_verified": background_verified,
    }


@app.post("/customers/api/jobs")
async def api_create_customer_job(
    payload: JobCreateRequest,
    session: SessionData = Depends(require_customer_user),
):
    """Create a new job posting for a customer."""

    title = payload.title.strip()
    description = payload.description.strip()
    if not title or not description:
        raise HTTPException(status_code=400, detail="Title and description are required")

    keywords = payload.keywords.strip()
    location_text = payload.location.strip()
    for label, value in (
        ("job title", title),
        ("job description", description),
        ("job keywords", keywords),
        ("job location", location_text),
    ):
        message = _ensure_safe_text(value, allow_address=False, context=label)
        if message:
            raise HTTPException(status_code=400, detail=message)

    coords = _geocode_location(location_text) if location_text else None
    location_lat, location_lon = coords if coords else (None, None)
    has_prior_jobs = has_customer_posted_job(session.username)
    job = create_job(
        session.username,
        title,
        description,
        keywords,
        payload.budget.strip(),
        location_text,
        location_lat,
        location_lon,
    )
    return {"job": job, "first_job": not has_prior_jobs}


@app.post("/customers/api/jobs/{job_id}/payment-intent")
async def api_create_job_payment_intent(
    job_id: int,
    payload: JobPaymentRequest,
    session: SessionData = Depends(require_customer_user),
):
    """Create a Stripe PaymentIntent for a job."""

    job = get_job(job_id)
    if not job or job.get("customer_username") != session.username:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("status") == "closed":
        raise HTTPException(status_code=400, detail="Job is already completed")

    base_cents = int(payload.amount_cents or 0)
    if base_cents <= 0:
        raise HTTPException(status_code=400, detail="Payment amount must be positive")
    if base_cents < MIN_JOB_PAYMENT_CENTS:
        min_amount = f"${MIN_JOB_PAYMENT_CENTS / 100:.2f}"
        raise HTTPException(
            status_code=400,
            detail=f"Payment amount must be at least {min_amount}.",
        )

    helper_username = normalize_username(payload.helper_username)
    if not helper_username or not get_user_profile(helper_username):
        raise HTTPException(status_code=404, detail="Helper not found")
    if not _has_active_chat_for_job(session.username, helper_username, job_id):
        raise HTTPException(status_code=409, detail="Helper must accept the job before payment")

    stripe_info = get_user_stripe_info(helper_username) or {}
    if not stripe_info.get("stripe_account_id") and not STRIPE_DEV_BYPASS:
        raise HTTPException(status_code=400, detail="Helper payouts are not connected")

    existing = get_job_payment(job_id) or {}
    if existing.get("stripe_payment_intent_id"):
        intent_id = existing.get("stripe_payment_intent_id", "")
        if not intent_id:
            raise HTTPException(status_code=400, detail="Payment already started for this job")
        intent = _stripe_retrieve_payment_intent(intent_id)
        status = intent.get("status", "")
        update_job_payment_status(job_id, status or "unknown")
        if status in {"succeeded", "processing"}:
            raise HTTPException(status_code=400, detail="Payment already completed for this job")
        client_secret = intent.get("client_secret", "")
        if not client_secret:
            raise HTTPException(status_code=500, detail="Stripe did not return a client secret")
        return {"payment_intent_id": intent_id, "client_secret": client_secret}

    breakdown = _compute_payment_breakdown(base_cents)
    amount_cents = breakdown["total_cents"]
    fee_cents = breakdown["platform_fee_cents"]
    currency = payload.currency or "usd"
    try:
        intent = _stripe_create_payment_intent(
            amount_cents,
            currency,
            job_id,
            helper_username,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    intent_id = intent.get("id", "")
    client_secret = intent.get("client_secret", "")
    if not intent_id or not client_secret:
        raise HTTPException(status_code=500, detail="Stripe did not return a payment intent")

    set_job_payment_intent(
        job_id,
        intent_id,
        amount_cents,
        currency,
        helper_username,
        fee_cents,
    )
    return {
        "payment_intent_id": intent_id,
        "client_secret": client_secret,
        "base_amount_cents": breakdown["base_cents"],
        "service_fee_cents": breakdown["service_fee_cents"],
        "tax_cents": breakdown["tax_cents"],
        "total_cents": breakdown["total_cents"],
        "payout_cents": breakdown["payout_cents"],
        "platform_fee_cents": breakdown["platform_fee_cents"],
    }


@app.post("/customers/api/jobs/{job_id}/payment-refresh")
async def api_refresh_job_payment(
    job_id: int,
    session: SessionData = Depends(require_customer_user),
):
    """Refresh Stripe payment status for a job."""

    job = get_job(job_id)
    if not job or job.get("customer_username") != session.username:
        raise HTTPException(status_code=404, detail="Job not found")
    payment = get_job_payment(job_id) or {}
    intent_id = payment.get("stripe_payment_intent_id") or ""
    if not intent_id:
        raise HTTPException(status_code=404, detail="Payment not started")
    intent = _stripe_retrieve_payment_intent(intent_id)
    status = intent.get("status", "") or "unknown"
    update_job_payment_status(job_id, status)
    try:
        _release_job_payment(job_id)
    except RuntimeError:
        pass
    return {"status": status}


@app.post("/customers/api/jobs/{job_id}/close")
async def api_close_job(
    job_id: int,
    session: SessionData = Depends(require_customer_user),
):
    """Mark a customer job as closed."""

    job = get_job(job_id)
    if not job or job.get("customer_username") != session.username:
        raise HTTPException(status_code=404, detail="Job not found")
    if not _payment_confirmed(job_id):
        raise HTTPException(status_code=409, detail="Payment must be confirmed before completion.")
    updated_job = _record_job_completion(job_id, ROLE_CUSTOMER)
    if not updated_job:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        _release_job_payment(job_id)
    except RuntimeError:
        pass
    return {
        "job_id": job_id,
        "status": updated_job.get("status"),
        "customer_completed": bool(updated_job.get("customer_completed_at")),
        "helper_completed": bool(updated_job.get("helper_completed_at")),
    }


@app.post("/helpers/api/jobs/{job_id}/close")
async def api_close_job_helper(
    job_id: int,
    session: SessionData = Depends(require_helper_user),
):
    """Mark a job as completed by the helper."""

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    has_chat = False
    for chat in list_chats_for_user(session.username, ROLE_HELPER):
        if chat.get("job_id") == job_id and chat.get("status") == "active":
            has_chat = True
            break
    if not has_chat:
        raise HTTPException(status_code=403, detail="Chat access required")

    if not _payment_confirmed(job_id):
        raise HTTPException(status_code=409, detail="Payment must be confirmed before completion.")

    updated_job = _record_job_completion(job_id, ROLE_HELPER)
    if not updated_job:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        _release_job_payment(job_id)
    except RuntimeError:
        pass
    return {
        "job_id": job_id,
        "status": updated_job.get("status"),
        "customer_completed": bool(updated_job.get("customer_completed_at")),
        "helper_completed": bool(updated_job.get("helper_completed_at")),
    }


@app.delete("/customers/api/jobs/{job_id}")
async def api_delete_job(
    job_id: int,
    session: SessionData = Depends(require_customer_user),
):
    """Delete a customer job posting."""

    job = get_job(job_id)
    if not job or job.get("customer_username") != session.username:
        raise HTTPException(status_code=404, detail="Job not found")
    delete_job(job_id, session.username)
    return {"deleted": True}


# --- Chat API (shared by helpers and customers) ----------------------------
@app.post("/helpers/api/chats")
async def api_create_chat(
    payload: ChatCreateRequest,
    session: SessionData = Depends(require_any_user),
):
    """Start a chat between a helper and a customer."""

    target_username = normalize_username(payload.target_username)
    target_role = payload.target_role.strip().lower()
    if target_role not in {ROLE_HELPER, ROLE_CUSTOMER}:
        raise HTTPException(status_code=400, detail="Invalid target role")
    if not target_username:
        raise HTTPException(status_code=400, detail="Target is required")
    if target_username == session.username and target_role == session.role:
        raise HTTPException(status_code=400, detail="Cannot start a chat with yourself")

    # Confirm that the target user exists.
    if target_role == ROLE_HELPER:
        target_profile = get_user_profile(target_username)
    else:
        target_profile = get_customer_profile(target_username)

    if not target_profile:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate job ownership when the chat is tied to a specific job.
    job_id = payload.job_id
    if session.role == ROLE_CUSTOMER and target_role == ROLE_HELPER and job_id is None:
        raise HTTPException(status_code=400, detail="Select a job before inviting a helper")
    if job_id is not None:
        job = get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if session.role == ROLE_HELPER and job.get("customer_username") != target_username:
            raise HTTPException(status_code=400, detail="Job does not belong to the customer")
        if session.role == ROLE_CUSTOMER and job.get("customer_username") != session.username:
            raise HTTPException(status_code=403, detail="You do not own this job")

    # Create the chat, then load it so we can send a full response.
    chat_id = get_or_create_chat(
        session.username,
        session.role,
        target_username,
        target_role,
        job_id,
        session.role,
    )
    chat = get_chat(chat_id)

    # If a customer created the chat first, auto-accept it so helpers can reply.
    if chat and chat.get("status") == "pending" and chat.get("initiator_role") == ROLE_CUSTOMER:
        set_chat_status(chat_id, "active")
        chat = get_chat(chat_id)

    messages = list_chat_messages(chat_id)
    return {"chat_id": chat_id, "chat": serialize_chat(chat, session), "messages": messages}


@app.get("/helpers/api/chats/{chat_id}")
async def api_get_chat(chat_id: int, session: SessionData = Depends(require_any_user)):
    """Return a chat and its messages."""

    if not user_has_chat_access(chat_id, session.username, session.role):
        raise HTTPException(status_code=403, detail="Forbidden")

    chat = get_chat(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    messages = list_chat_messages(chat_id)
    return {"chat": serialize_chat(chat, session), "messages": messages}


@app.post("/helpers/api/chats/{chat_id}/messages")
async def api_send_chat_message(
    chat_id: int,
    payload: ChatMessageRequest,
    session: SessionData = Depends(require_any_user),
):
    """Append a new message to a chat."""

    if not user_has_chat_access(chat_id, session.username, session.role):
        raise HTTPException(status_code=403, detail="Forbidden")

    chat = get_chat(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    chat_status = chat.get("status", "pending")
    if chat_status == "declined":
        raise HTTPException(status_code=403, detail="Chat has been declined")
    if chat_status == "pending" and session.role != chat.get("initiator_role"):
        raise HTTPException(status_code=409, detail="Awaiting approval before you can reply")

    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    if len(content) > CHAT_MESSAGE_MAX_LENGTH:
        raise HTTPException(status_code=400, detail="Message is too long")

    last_sent = get_last_sender_message_epoch(chat_id, session.username)
    now = int(time.time())
    if last_sent is not None:
        elapsed = now - last_sent
        if elapsed < CHAT_MESSAGE_MIN_SECONDS:
            wait_seconds = CHAT_MESSAGE_MIN_SECONDS - elapsed
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {wait_seconds} seconds before sending another message.",
            )

    allow_address = False
    if chat.get("job_id") is not None:
        allow_address = _payment_releases_address(chat["job_id"])
    policy_error = _chat_message_policy_error(chat_id, session.username, content, allow_address)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    message = append_chat_message(chat_id, session.username, session.role, content)
    return {"message": message}


@app.get("/api/chats")
async def api_list_user_chats(session: SessionData = Depends(require_any_user)):
    """List all chats for the logged-in user."""

    chats = list_chats_for_user(session.username, session.role)
    summaries = [serialize_chat(chat, session) for chat in chats]
    return {"chats": summaries}


@app.post("/api/chats/{chat_id}/status")
async def api_update_chat_status(
    chat_id: int,
    payload: ChatStatusUpdateRequest,
    session: SessionData = Depends(require_any_user),
):
    """Accept or decline a chat invitation."""

    if not user_has_chat_access(chat_id, session.username, session.role):
        raise HTTPException(status_code=403, detail="Forbidden")

    chat = get_chat(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    action = payload.action.strip().lower()
    status = chat.get("status", "pending")
    if action == "accept":
        if status != "pending" or chat.get("initiator_role") != ROLE_HELPER or session.role != ROLE_CUSTOMER:
            raise HTTPException(status_code=403, detail="Only customers can accept pending helper requests")
        set_chat_status(chat_id, "active")
    elif action == "decline":
        if session.role != ROLE_CUSTOMER:
            raise HTTPException(status_code=403, detail="Only customers can decline helper requests")
        set_chat_status(chat_id, "declined")
    else:
        raise HTTPException(status_code=400, detail="Unknown action")

    updated = get_chat(chat_id)
    return {"chat": serialize_chat(updated, session)}


@app.delete("/api/chats/{chat_id}")
async def api_delete_chat(chat_id: int, session: SessionData = Depends(require_any_user)):
    """Delete a chat for all participants."""

    if not user_has_chat_access(chat_id, session.username, session.role):
        raise HTTPException(status_code=403, detail="Forbidden")
    deleted = delete_chat_record(chat_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"deleted": True}
