from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional

from Database.fuzzy_search import matches_fuzzy
from Database.reserved_usernames import is_username_reserved, reserve_username
from Database.security import hash_password

DB_PATH = Path(__file__).with_name("users.db")
HELPER_ACTIVE_WINDOW_SECONDS = 600


def _normalize_username(username: str) -> str:
    return username.strip().lower()


def _drop_columns(
    conn: sqlite3.Connection,
    table_name: str,
    columns_to_drop: set[str],
) -> None:
    """Drop columns from a SQLite table by rebuilding it."""

    if not columns_to_drop:
        return
    info = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    if not info:
        return

    existing = [row[1] for row in info]
    if not set(existing) & columns_to_drop:
        return

    keep_columns = [name for name in existing if name not in columns_to_drop]
    if not keep_columns:
        return

    column_defs: list[str] = []
    for _, name, col_type, not_null, default_value, is_pk in info:
        if name in columns_to_drop:
            continue
        identifier = f'"{name}"'
        col_def = f"{identifier} {col_type}".strip()
        if not_null:
            col_def += " NOT NULL"
        if default_value is not None:
            col_def += f" DEFAULT {default_value}"
        if is_pk:
            col_def += " PRIMARY KEY"
        column_defs.append(col_def)

    backup_table = f"{table_name}_old"
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute(f"ALTER TABLE {table_name} RENAME TO {backup_table}")
    conn.execute(f"CREATE TABLE {table_name} ({', '.join(column_defs)})")
    keep_csv = ", ".join(f'"{name}"' for name in keep_columns)
    conn.execute(
        f"INSERT INTO {table_name} ({keep_csv}) SELECT {keep_csv} FROM {backup_table}"
    )
    conn.execute(f"DROP TABLE {backup_table}")
    conn.execute("PRAGMA foreign_keys=ON")

def _coerce_timestamp(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _apply_helper_availability(user: Dict[str, Any]) -> None:
    status = (user.get("availability_status") or "active").strip().lower()
    if status not in {"active", "offline", "on_call"}:
        status = "active"

    last_seen = _coerce_timestamp(user.get("last_seen_at"))
    now = int(time.time())
    if status == "offline":
        user["availability_status"] = "offline"
    elif status == "on_call":
        user["availability_status"] = "on_call"
    elif last_seen is None or (now - last_seen) > HELPER_ACTIVE_WINDOW_SECONDS:
        user["availability_status"] = "offline"
    else:
        user["availability_status"] = "active"

    user.pop("last_seen_at", None)


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                profession TEXT NOT NULL DEFAULT '',
                pay_type TEXT NOT NULL DEFAULT 'hourly',
                pay_rate REAL NOT NULL DEFAULT 0,
                bio TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                stripe_account_id TEXT NOT NULL DEFAULT '',
                stripe_onboarding_complete INTEGER NOT NULL DEFAULT 0,
                availability_status TEXT NOT NULL DEFAULT 'active',
                last_seen_at INTEGER,
                email_verified INTEGER NOT NULL DEFAULT 0,
                verification_token_hash TEXT NOT NULL DEFAULT '',
                verification_expires_at INTEGER,
                verification_sent_at INTEGER,
                reset_code_hash TEXT NOT NULL DEFAULT '',
                reset_expires_at INTEGER,
                reset_sent_at INTEGER
            )
            """
        )
        _drop_columns(conn, "users", {"recovery_phone", "recovery_carrier"})
        _ensure_onboarding_columns(conn)
        _ensure_chat_tables(conn)
        _ensure_helper_profile_tables(conn)
        conn.executemany(
            """
            INSERT OR IGNORE INTO users (
                username,
                password,
                profession,
                pay_type,
                pay_rate,
                bio
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "admin",
                    hash_password("changeme"),
                    "General Helper",
                    "hourly",
                    25.0,
                    "Here to give you a hand.",
                ),
                (
                    "assistant",
                    hash_password("safepass"),
                    "Personal Assistant",
                    "hourly",
                    30.0,
                    "Organized, punctual, and friendly.",
                ),
            ],
        )
        _normalize_existing_usernames(conn)


def _ensure_onboarding_columns(conn: sqlite3.Connection) -> None:
    required_columns = {
        "profession": "TEXT NOT NULL DEFAULT ''",
        "pay_type": "TEXT NOT NULL DEFAULT 'hourly'",
        "pay_rate": "REAL NOT NULL DEFAULT 0",
        "bio": "TEXT NOT NULL DEFAULT ''",
        "email": "TEXT NOT NULL DEFAULT ''",
        "stripe_account_id": "TEXT NOT NULL DEFAULT ''",
        "stripe_onboarding_complete": "INTEGER NOT NULL DEFAULT 0",
        "availability_status": "TEXT NOT NULL DEFAULT 'active'",
        "last_seen_at": "INTEGER",
        "service_location": "TEXT NOT NULL DEFAULT ''",
        "location_lat": "REAL",
        "location_lon": "REAL",
        "max_distance_miles": "REAL NOT NULL DEFAULT 25",
        "email_verified": "INTEGER NOT NULL DEFAULT 0",
        "verification_token_hash": "TEXT NOT NULL DEFAULT ''",
        "verification_expires_at": "INTEGER",
        "verification_sent_at": "INTEGER",
        "reset_code_hash": "TEXT NOT NULL DEFAULT ''",
        "reset_expires_at": "INTEGER",
        "reset_sent_at": "INTEGER",
    }

    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }

    for column_name, ddl in required_columns.items():
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column_name} {ddl}")


def _ensure_chat_tables(conn: sqlite3.Connection) -> None:
    def _needs_reset() -> bool:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='chats'"
        )
        if not cursor.fetchone():
            return False
        columns = [row[1] for row in conn.execute("PRAGMA table_info(chats)")]
        required = {
            "participant_a_role",
            "participant_b_role",
            "job_id",
            "status",
            "initiator_role",
        }
        return any(col not in columns for col in required)

    if _needs_reset():
        conn.execute("DROP TABLE IF EXISTS chat_messages")
        conn.execute("DROP TABLE IF EXISTS chats")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            participant_a TEXT NOT NULL,
            participant_a_role TEXT NOT NULL,
            participant_b TEXT NOT NULL,
            participant_b_role TEXT NOT NULL,
            job_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            initiator_role TEXT NOT NULL DEFAULT 'helper',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            sender_role TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(chat_id) REFERENCES chats(id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_chats_participants
        ON chats(participant_a, participant_b)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_chat_messages_chat
        ON chat_messages(chat_id)
        """
    )


def _ensure_helper_profile_tables(conn: sqlite3.Connection) -> None:
    """Create helper profile tables (credentials, images, reviews) if missing."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            helper_username TEXT NOT NULL,
            title TEXT NOT NULL,
            issuer TEXT NOT NULL DEFAULT '',
            year TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_helper_credentials_user
        ON helper_credentials(helper_username)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            helper_username TEXT NOT NULL,
            file_name TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT '',
            file_bytes BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_helper_images_user
        ON helper_images(helper_username)
        """
    )
    _ensure_helper_images_columns(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            helper_username TEXT NOT NULL,
            customer_username TEXT NOT NULL,
            job_id INTEGER,
            job_title TEXT NOT NULL DEFAULT '',
            rating INTEGER NOT NULL,
            review_text TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(helper_username, customer_username, job_id),
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    _ensure_helper_reviews_schema(conn)
    _ensure_helper_verification_tables(conn)
    _ensure_helper_background_table(conn)
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_helper_reviews_user
        ON helper_reviews(helper_username)
        """
    )


def _ensure_helper_images_columns(conn: sqlite3.Connection) -> None:
    required_columns = {
        "file_name": "TEXT NOT NULL DEFAULT ''",
        "content_type": "TEXT NOT NULL DEFAULT ''",
        "file_bytes": "BLOB",
        "file_path": "TEXT NOT NULL DEFAULT ''",
    }

    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(helper_images)").fetchall()
    }

    for column_name, ddl in required_columns.items():
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE helper_images ADD COLUMN {column_name} {ddl}")


def _ensure_helper_reviews_schema(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(helper_reviews)").fetchall()}
    if "job_id" in columns and "job_title" in columns:
        return

    conn.execute("ALTER TABLE helper_reviews RENAME TO helper_reviews_old")
    conn.execute(
        """
        CREATE TABLE helper_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            helper_username TEXT NOT NULL,
            customer_username TEXT NOT NULL,
            job_id INTEGER,
            job_title TEXT NOT NULL DEFAULT '',
            rating INTEGER NOT NULL,
            review_text TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(helper_username, customer_username, job_id),
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    conn.execute(
        """
        INSERT INTO helper_reviews (id, helper_username, customer_username, rating, review_text, created_at)
        SELECT id, helper_username, customer_username, rating, review_text, created_at
        FROM helper_reviews_old
        """
    )
    conn.execute("DROP TABLE helper_reviews_old")


def _ensure_helper_verification_tables(conn: sqlite3.Connection) -> None:
    """Create helper verification tables if missing."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_verifications (
            helper_username TEXT PRIMARY KEY,
            verified INTEGER NOT NULL DEFAULT 0,
            id_type INTEGER,
            id_number_enc TEXT NOT NULL DEFAULT '',
            ai_partial INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_verification_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            helper_username TEXT NOT NULL,
            file_kind TEXT NOT NULL DEFAULT '',
            file_name TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT '',
            file_bytes BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_helper_verification_files_user
        ON helper_verification_files(helper_username)
        """
    )


def _ensure_helper_background_table(conn: sqlite3.Connection) -> None:
    """Create helper background check table if missing."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS helper_background_checks (
            helper_username TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'unverified',
            vendor TEXT NOT NULL DEFAULT '',
            external_id TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(helper_username) REFERENCES users(username)
        )
        """
    )


def _has_case_collisions(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cursor = conn.execute(
        f"""
        SELECT lower({column}) AS key
        FROM {table}
        GROUP BY lower({column})
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    )
    return cursor.fetchone() is not None


def _dedupe_helper_reviews(conn: sqlite3.Connection) -> None:
    """Remove duplicate reviews that differ only by username casing."""

    cursor = conn.execute(
        """
        SELECT lower(helper_username), lower(customer_username), COALESCE(job_id, -1), GROUP_CONCAT(id), COUNT(*)
        FROM helper_reviews
        GROUP BY lower(helper_username), lower(customer_username), COALESCE(job_id, -1)
        HAVING COUNT(*) > 1
        """
    )
    for row in cursor.fetchall():
        ids = [int(value) for value in row[3].split(",")]
        ids.sort()
        for review_id in ids[:-1]:
            conn.execute("DELETE FROM helper_reviews WHERE id = ?", (review_id,))


def _normalize_existing_usernames(conn: sqlite3.Connection) -> None:
    """Lowercase existing usernames for consistent matching."""

    if _has_case_collisions(conn, "users", "username"):
        return

    _dedupe_helper_reviews(conn)

    conn.execute(
        "UPDATE users SET username = lower(username) WHERE username != lower(username)"
    )
    conn.execute(
        """
        UPDATE helper_credentials
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_images
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_reviews
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_reviews
        SET customer_username = lower(customer_username)
        WHERE customer_username != lower(customer_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_verifications
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_verification_files
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE helper_background_checks
        SET helper_username = lower(helper_username)
        WHERE helper_username != lower(helper_username)
        """
    )
    conn.execute(
        """
        UPDATE chats
        SET participant_a = lower(participant_a)
        WHERE participant_a != lower(participant_a)
        """
    )
    conn.execute(
        """
        UPDATE chats
        SET participant_b = lower(participant_b)
        WHERE participant_b != lower(participant_b)
        """
    )
    conn.execute(
        """
        UPDATE chat_messages
        SET sender = lower(sender)
        WHERE sender != lower(sender)
        """
    )


def get_user_password(username: str) -> Optional[str]:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT password FROM users WHERE lower(username) = lower(?)",
            (normalized_username,),
        )
        row = cursor.fetchone()
        return row[0] if row else None


def create_user(
    username: str,
    password: str,
    profession: str,
    pay_type: str,
    pay_rate: float,
    bio: str,
    email: str = "",
    service_location: str = "",
    max_distance_miles: float = 25.0,
    location_lat: Optional[float] = None,
    location_lon: Optional[float] = None,
    availability_status: str = "active",
    allow_reserved: bool = False,
) -> bool:
    try:
        normalized_username = _normalize_username(username)
        if not allow_reserved and is_username_reserved(normalized_username):
            return False
        hashed_password = hash_password(password)
        with sqlite3.connect(DB_PATH) as conn:
            existing = conn.execute(
                "SELECT 1 FROM users WHERE lower(username) = lower(?)",
                (normalized_username,),
            ).fetchone()
            if existing:
                return False
            conn.execute(
                """
                INSERT INTO users (
                    username,
                    password,
                    profession,
                    pay_type,
                    pay_rate,
                    bio,
                    email,
                    service_location,
                    max_distance_miles,
                    location_lat,
                    location_lon,
                    availability_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_username,
                    hashed_password,
                    profession,
                    pay_type,
                    pay_rate,
                    bio,
                    email.strip(),
                    service_location.strip(),
                    max_distance_miles,
                    location_lat,
                    location_lon,
                    availability_status,
                ),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def update_user_password(username: str, new_password: str) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET password = ? WHERE lower(username) = lower(?)",
            (hash_password(new_password), normalized_username),
        )
        return cursor.rowcount > 0


def get_user_auth_info(username: str) -> Optional[Dict[str, Any]]:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, password, email, email_verified,
                   verification_token_hash, verification_expires_at, verification_sent_at,
                   reset_code_hash, reset_expires_at, reset_sent_at
            FROM users
            WHERE lower(username) = lower(?)
            """,
            (normalized_username,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        record["username"] = record["username"].lower()
        return record


def update_user_email(username: str, email: str) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET email = ? WHERE lower(username) = lower(?)",
            (email.strip(), normalized_username),
        )
        return cursor.rowcount > 0


def update_user_verification_sent_at(username: str, sent_at: int) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET verification_sent_at = ? WHERE lower(username) = lower(?)",
            (sent_at, normalized_username),
        )
        return cursor.rowcount > 0


def set_user_reset_code(username: str, code_hash: str, expires_at: int) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET reset_code_hash = ?,
                reset_expires_at = ?,
                reset_sent_at = NULL
            WHERE lower(username) = lower(?)
            """,
            (code_hash, expires_at, normalized_username),
        )
        return cursor.rowcount > 0


def update_user_reset_sent_at(username: str, sent_at: int) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET reset_sent_at = ? WHERE lower(username) = lower(?)",
            (sent_at, normalized_username),
        )
        return cursor.rowcount > 0


def clear_user_reset_code(username: str) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET reset_code_hash = '',
                reset_expires_at = NULL,
                reset_sent_at = NULL
            WHERE lower(username) = lower(?)
            """,
            (normalized_username,),
        )
        return cursor.rowcount > 0


def update_user_admin(
    username: str,
    profession: str,
    pay_type: str,
    pay_rate: float,
    bio: str,
    email: str,
    email_verified: bool,
) -> bool:
    normalized_username = _normalize_username(username)
    token_hash = "" if email_verified else None
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET profession = ?,
                pay_type = ?,
                pay_rate = ?,
                bio = ?,
                email = ?,
                email_verified = ?,
                verification_token_hash = COALESCE(?, verification_token_hash),
                verification_expires_at = CASE
                    WHEN ? IS NULL THEN verification_expires_at
                    ELSE NULL
                END
            WHERE lower(username) = lower(?)
            """,
            (
                profession,
                pay_type,
                pay_rate,
                bio.strip(),
                email.strip(),
                1 if email_verified else 0,
                token_hash,
                token_hash,
                normalized_username,
            ),
        )
        return cursor.rowcount > 0


def set_user_verification(
    username: str,
    email: str,
    token_hash: str,
    expires_at: int,
) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET email = ?,
                email_verified = 0,
                verification_token_hash = ?,
                verification_expires_at = ?
            WHERE lower(username) = lower(?)
            """,
            (email.strip(), token_hash, expires_at, normalized_username),
        )
        return cursor.rowcount > 0


def mark_user_verified(username: str) -> bool:
    normalized_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET email_verified = 1,
                verification_token_hash = '',
                verification_expires_at = NULL
            WHERE lower(username) = lower(?)
            """,
            (normalized_username,),
        )
        return cursor.rowcount > 0


def find_user_by_verification_token(token_hash: str) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, email, email_verified, verification_expires_at
            FROM users
            WHERE verification_token_hash = ?
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def list_users() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, profession, pay_type, pay_rate, bio, email, email_verified,
                   availability_status, last_seen_at
            FROM users
            ORDER BY username
            """
        )
        users = [dict(row) for row in cursor.fetchall()]
        for user in users:
            if user.get("username"):
                user["username"] = user["username"].lower()
            _apply_helper_availability(user)
        return users


def search_helpers(keyword: str) -> List[Dict[str, Any]]:
    """Search helpers by name, profession, or bio with fuzzy matching."""

    threshold = 0.55
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, profession, pay_type, pay_rate, bio,
                   service_location, location_lat, location_lon, max_distance_miles,
                   availability_status, last_seen_at
            FROM users
            WHERE lower(username) != 'admin'
            """
        )
        helpers = [dict(row) for row in cursor.fetchall()]

    if not keyword:
        for helper in helpers:
            if helper.get("username"):
                helper["username"] = helper["username"].lower()
            _apply_helper_availability(helper)
        return sorted(helpers, key=lambda helper: helper.get("username", ""))

    scored: List[Dict[str, Any]] = []
    for helper in helpers:
        if helper.get("username"):
            helper["username"] = helper["username"].lower()
        matched, score = matches_fuzzy(
            keyword,
            [
                helper.get("username", ""),
                helper.get("profession", ""),
                helper.get("bio", ""),
            ],
            threshold,
        )
        if matched:
            helper["_score"] = score
            scored.append(helper)

    scored.sort(key=lambda helper: (-helper.get("_score", 0.0), helper.get("username", "")))
    for helper in scored:
        helper.pop("_score", None)
        _apply_helper_availability(helper)
    return scored


def get_user_profile(username: str) -> Optional[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, profession, pay_type, pay_rate, bio,
                   service_location, location_lat, location_lon, max_distance_miles,
                   availability_status, last_seen_at,
                   stripe_account_id, stripe_onboarding_complete
            FROM users
            WHERE lower(username) = lower(?)
            """,
            (clean_username,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        profile = dict(row)
        if profile.get("username"):
            profile["username"] = profile["username"].lower()
        _apply_helper_availability(profile)
        return profile


def get_user_stripe_info(username: str) -> Optional[Dict[str, Any]]:
    """Return Stripe onboarding info for a helper."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT stripe_account_id, stripe_onboarding_complete
            FROM users
            WHERE lower(username) = lower(?)
            """,
            (clean_username,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def update_user_stripe_info(
    username: str,
    account_id: str,
    onboarding_complete: bool,
) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET stripe_account_id = ?,
                stripe_onboarding_complete = ?
            WHERE lower(username) = lower(?)
            """,
            (account_id.strip(), 1 if onboarding_complete else 0, clean_username),
        )
        return cursor.rowcount > 0


def get_helper_background_check(username: str) -> Optional[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT helper_username, status, vendor, external_id, created_at, updated_at
            FROM helper_background_checks
            WHERE lower(helper_username) = lower(?)
            """,
            (clean_username,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        if record.get("helper_username"):
            record["helper_username"] = record["helper_username"].lower()
        return record


def upsert_helper_background_check(
    username: str,
    status: str,
    vendor: str = "",
    external_id: str = "",
) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO helper_background_checks (
                helper_username,
                status,
                vendor,
                external_id
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(helper_username) DO UPDATE SET
                status = excluded.status,
                vendor = excluded.vendor,
                external_id = excluded.external_id,
                updated_at = CURRENT_TIMESTAMP
            """,
            (clean_username, status, vendor, external_id),
        )
        return True


def update_helper_profile(
    username: str,
    pay_type: str,
    pay_rate: float,
    bio: str,
    service_location: str,
    max_distance_miles: float,
    location_lat: Optional[float],
    location_lon: Optional[float],
    availability_status: str,
) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET pay_type = ?,
                pay_rate = ?,
                bio = ?,
                service_location = ?,
                max_distance_miles = ?,
                location_lat = ?,
                location_lon = ?,
                availability_status = ?
            WHERE lower(username) = lower(?)
            """,
            (
                pay_type,
                pay_rate,
                bio.strip(),
                service_location.strip(),
                max_distance_miles,
                location_lat,
                location_lon,
                availability_status,
                clean_username,
            ),
        )
        return cursor.rowcount > 0


def upsert_helper_verification(
    username: str,
    id_type: int,
    id_number_enc: str,
    verified: bool = False,
    ai_partial: bool = False,
) -> bool:
    """Create or update a helper verification record."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO helper_verifications (
                helper_username,
                verified,
                id_type,
                id_number_enc,
                ai_partial
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(helper_username) DO UPDATE SET
                verified = excluded.verified,
                id_type = excluded.id_type,
                id_number_enc = excluded.id_number_enc,
                ai_partial = excluded.ai_partial,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                clean_username,
                1 if verified else 0,
                id_type,
                id_number_enc,
                1 if ai_partial else 0,
            ),
        )
        return True


def update_helper_verification_status(
    username: str,
    verified: bool,
    ai_partial: bool,
) -> bool:
    """Update verification status after AI review."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE helper_verifications
            SET verified = ?,
                ai_partial = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE lower(helper_username) = lower(?)
            """,
            (1 if verified else 0, 1 if ai_partial else 0, clean_username),
        )
        return cursor.rowcount > 0


def get_helper_verification(username: str) -> Optional[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT helper_username, verified, id_type, id_number_enc, ai_partial, created_at, updated_at
            FROM helper_verifications
            WHERE lower(helper_username) = lower(?)
            """,
            (clean_username,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        if record.get("helper_username"):
            record["helper_username"] = record["helper_username"].lower()
        return record


def add_helper_verification_file(
    username: str,
    file_kind: str,
    file_name: str,
    content_type: str,
    file_bytes: bytes,
) -> Optional[int]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO helper_verification_files (
                helper_username,
                file_kind,
                file_name,
                content_type,
                file_bytes
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (clean_username, file_kind, file_name, content_type, file_bytes),
        )
        return cursor.lastrowid


def list_helper_verification_files(username: str) -> List[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, helper_username, file_kind, file_name, content_type, created_at
            FROM helper_verification_files
            WHERE lower(helper_username) = lower(?)
            ORDER BY created_at DESC, id DESC
            """,
            (clean_username,),
        )
        files = [dict(row) for row in cursor.fetchall()]
        for record in files:
            if record.get("helper_username"):
                record["helper_username"] = record["helper_username"].lower()
        return files


def get_helper_verification_file(file_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, helper_username, file_kind, file_name, content_type, file_bytes, created_at
            FROM helper_verification_files
            WHERE id = ?
            """,
            (file_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def update_helper_status(username: str, availability_status: str) -> bool:
    """Update only the helper availability status."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET availability_status = ?
            WHERE lower(username) = lower(?)
            """,
            (availability_status, clean_username),
        )
        return cursor.rowcount > 0


def touch_helper_last_seen(username: str) -> None:
    """Record when a helper was last active."""

    clean_username = _normalize_username(username)
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            UPDATE users
            SET last_seen_at = ?
            WHERE lower(username) = lower(?)
            """,
            (now, clean_username),
        )


def set_helper_offline(username: str) -> None:
    """Mark a helper as offline (used when logging out)."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            UPDATE users
            SET availability_status = 'offline'
            WHERE lower(username) = lower(?)
            """,
            (clean_username,),
        )


def list_helper_credentials(username: str) -> List[Dict[str, Any]]:
    """Return all saved credentials for a helper."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, title, issuer, year, created_at
            FROM helper_credentials
            WHERE lower(helper_username) = lower(?)
            ORDER BY created_at DESC, id DESC
            """,
            (clean_username,),
        )
        return [dict(row) for row in cursor.fetchall()]


def add_helper_credential(
    username: str,
    title: str,
    issuer: str,
    year: str,
) -> bool:
    """Store a new credential for a helper profile."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO helper_credentials (helper_username, title, issuer, year)
            VALUES (?, ?, ?, ?)
            """,
            (clean_username, title.strip(), issuer.strip(), year.strip()),
        )
        return cursor.rowcount > 0


def delete_helper_credential(username: str, credential_id: int) -> bool:
    """Remove a credential from a helper profile."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            DELETE FROM helper_credentials
            WHERE id = ? AND lower(helper_username) = lower(?)
            """,
            (credential_id, clean_username),
        )
        return cursor.rowcount > 0


def list_helper_images(username: str) -> List[Dict[str, Any]]:
    """Return the uploaded image list for a helper."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, file_name, content_type, created_at
            FROM helper_images
            WHERE lower(helper_username) = lower(?)
            ORDER BY created_at DESC, id DESC
            """,
            (clean_username,),
        )
        return [dict(row) for row in cursor.fetchall()]


def add_helper_image(
    username: str,
    file_name: str,
    content_type: str,
    file_bytes: bytes,
) -> bool:
    """Store a new image for a helper."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO helper_images (helper_username, file_name, content_type, file_bytes, file_path)
            VALUES (?, ?, ?, ?, '')
            """,
            (clean_username, file_name, content_type, file_bytes),
        )
        return cursor.rowcount > 0


def delete_helper_image(username: str, image_id: int) -> bool:
    """Delete an image record."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            DELETE FROM helper_images
            WHERE id = ? AND lower(helper_username) = lower(?)
            """,
            (image_id, clean_username),
        )
        return cursor.rowcount > 0


def get_helper_image(image_id: int) -> Optional[Dict[str, Any]]:
    """Fetch helper image bytes and metadata."""

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT helper_username, file_name, content_type, file_bytes, file_path
            FROM helper_images
            WHERE id = ?
            """,
            (image_id,),
        ).fetchone()
        if not row:
            return None
        image = dict(row)
        if image.get("helper_username"):
            image["helper_username"] = image["helper_username"].lower()
        return image


def list_helper_reviews(username: str) -> List[Dict[str, Any]]:
    """Return reviews left for a helper, newest first."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, customer_username, job_id, job_title, rating, review_text, created_at
            FROM helper_reviews
            WHERE lower(helper_username) = lower(?)
            ORDER BY created_at DESC, id DESC
            """,
            (clean_username,),
        )
        reviews: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            review = dict(row)
            if review.get("customer_username"):
                review["customer_username"] = review["customer_username"].lower()
            reviews.append(review)
        return reviews


def list_reviewed_job_ids(helper_username: str, customer_username: str) -> List[int]:
    """Return job IDs already reviewed by the customer for a helper."""

    clean_helper = _normalize_username(helper_username)
    clean_customer = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT job_id
            FROM helper_reviews
            WHERE lower(helper_username) = lower(?)
              AND lower(customer_username) = lower(?)
              AND job_id IS NOT NULL
            """,
            (clean_helper, clean_customer),
        )
        return [row[0] for row in cursor.fetchall() if row[0] is not None]


def upsert_helper_review(
    helper_username: str,
    customer_username: str,
    job_id: int,
    job_title: str,
    rating: int,
    review_text: str,
) -> bool:
    """Create or update a helper review for a specific job."""

    clean_helper = _normalize_username(helper_username)
    clean_customer = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO helper_reviews (
                helper_username,
                customer_username,
                job_id,
                job_title,
                rating,
                review_text
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(helper_username, customer_username, job_id)
            DO UPDATE SET rating = excluded.rating,
                          review_text = excluded.review_text,
                          job_title = excluded.job_title,
                          created_at = CURRENT_TIMESTAMP
            """,
            (clean_helper, clean_customer, job_id, job_title.strip(), rating, review_text.strip()),
        )
        return cursor.rowcount > 0


def delete_helper_review(review_id: int, helper_username: str, customer_username: str) -> bool:
    """Delete a helper review belonging to the customer."""

    clean_helper = _normalize_username(helper_username)
    clean_customer = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            DELETE FROM helper_reviews
            WHERE id = ?
              AND lower(helper_username) = lower(?)
              AND lower(customer_username) = lower(?)
            """,
            (review_id, clean_helper, clean_customer),
        )
        return cursor.rowcount > 0


def list_reviews_by_customer(customer_username: str) -> List[Dict[str, Any]]:
    """Return reviews submitted by a customer."""

    clean_username = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT helper_username, job_id, job_title, rating, review_text, created_at
            FROM helper_reviews
            WHERE lower(customer_username) = lower(?)
            ORDER BY created_at DESC, id DESC
            """,
            (clean_username,),
        )
        reviews: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            review = dict(row)
            if review.get("helper_username"):
                review["helper_username"] = review["helper_username"].lower()
            reviews.append(review)
        return reviews


def delete_user(username: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        clean_username = _normalize_username(username)
        cursor = conn.execute(
            "DELETE FROM users WHERE lower(username) = lower(?)",
            (clean_username,),
        )
        deleted = cursor.rowcount > 0
        if deleted:
            reserve_username(clean_username)
        return deleted


def _find_chat(
    conn: sqlite3.Connection,
    user_a: str,
    role_a: str,
    user_b: str,
    role_b: str,
    job_id: Optional[int],
) -> Optional[int]:
    clean_user_a = _normalize_username(user_a)
    clean_user_b = _normalize_username(user_b)
    cursor = conn.execute(
        """
        SELECT id FROM chats
        WHERE (
                lower(participant_a) = lower(?)
            AND participant_a_role = ?
            AND lower(participant_b) = lower(?)
            AND participant_b_role = ?
            AND ((job_id IS NULL AND ? IS NULL) OR job_id = ?)
        )
           OR (
                lower(participant_a) = lower(?)
            AND participant_a_role = ?
            AND lower(participant_b) = lower(?)
            AND participant_b_role = ?
            AND ((job_id IS NULL AND ? IS NULL) OR job_id = ?)
        )
        LIMIT 1
        """,
        (
            clean_user_a,
            role_a,
            clean_user_b,
            role_b,
            job_id,
            job_id,
            clean_user_b,
            role_b,
            clean_user_a,
            role_a,
            job_id,
            job_id,
        ),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def get_or_create_chat(
    user_a: str,
    role_a: str,
    user_b: str,
    role_b: str,
    job_id: Optional[int],
    initiator_role: str,
) -> int:
    clean_user_a = _normalize_username(user_a)
    clean_user_b = _normalize_username(user_b)
    with sqlite3.connect(DB_PATH) as conn:
        existing = _find_chat(conn, clean_user_a, role_a, clean_user_b, role_b, job_id)
        if existing:
            return existing
        cursor = conn.execute(
            """
            INSERT INTO chats (
                participant_a,
                participant_a_role,
                participant_b,
                participant_b_role,
                job_id,
                status,
                initiator_role
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clean_user_a,
                role_a,
                clean_user_b,
                role_b,
                job_id,
                "pending",
                initiator_role,
            ),
        )
        return cursor.lastrowid


def get_chat(chat_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM chats WHERE id = ?", (chat_id,))
        row = cursor.fetchone()
        if not row:
            return None
        chat = dict(row)
        if chat.get("participant_a"):
            chat["participant_a"] = chat["participant_a"].lower()
        if chat.get("participant_b"):
            chat["participant_b"] = chat["participant_b"].lower()
        return chat


def list_chat_messages(chat_id: int) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT id, sender, sender_role, message, created_at
            FROM chat_messages
            WHERE chat_id = ?
            ORDER BY created_at ASC
            """,
            (chat_id,),
        )
        messages: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            message = dict(row)
            if message.get("sender"):
                message["sender"] = message["sender"].lower()
            messages.append(message)
        return messages


def get_last_sender_message_epoch(chat_id: int, sender: str) -> Optional[int]:
    clean_sender = _normalize_username(sender)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT strftime('%s', created_at)
            FROM chat_messages
            WHERE chat_id = ? AND sender = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (chat_id, clean_sender),
        )
        row = cursor.fetchone()
    if not row or row[0] is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


def append_chat_message(chat_id: int, sender: str, sender_role: str, message: str) -> Dict[str, Any]:
    clean_sender = _normalize_username(sender)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO chat_messages (chat_id, sender, sender_role, message)
            VALUES (?, ?, ?, ?)
            """,
            (chat_id, clean_sender, sender_role, message),
        )
        inserted_id = cursor.lastrowid
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, sender, sender_role, message, created_at
            FROM chat_messages
            WHERE id = ?
            """,
            (inserted_id,),
        ).fetchone()
        if not row:
            return None
        entry = dict(row)
        if entry.get("sender"):
            entry["sender"] = entry["sender"].lower()
        return entry


def user_has_chat_access(chat_id: int, username: str, role: str) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT 1 FROM chats
            WHERE id = ? AND (
                (lower(participant_a) = lower(?) AND participant_a_role = ?)
                OR (lower(participant_b) = lower(?) AND participant_b_role = ?)
            )
            LIMIT 1
            """,
            (chat_id, clean_username, role, clean_username, role),
        )
        return cursor.fetchone() is not None


def list_chats_for_user(username: str, role: str) -> List[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT
                c.*,
                (
                    SELECT message
                    FROM chat_messages m
                    WHERE m.chat_id = c.id
                    ORDER BY m.created_at DESC, m.id DESC
                    LIMIT 1
                ) AS last_message,
                (
                    SELECT sender
                    FROM chat_messages m
                    WHERE m.chat_id = c.id
                    ORDER BY m.created_at DESC, m.id DESC
                    LIMIT 1
                ) AS last_sender,
                (
                    SELECT created_at
                    FROM chat_messages m
                    WHERE m.chat_id = c.id
                    ORDER BY m.created_at DESC, m.id DESC
                    LIMIT 1
                ) AS last_timestamp
            FROM chats c
            WHERE (lower(participant_a) = lower(?) AND participant_a_role = ?)
               OR (lower(participant_b) = lower(?) AND participant_b_role = ?)
            ORDER BY created_at DESC
            """,
            (clean_username, role, clean_username, role),
        )
        chats: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            chat = dict(row)
            if chat.get("participant_a"):
                chat["participant_a"] = chat["participant_a"].lower()
            if chat.get("participant_b"):
                chat["participant_b"] = chat["participant_b"].lower()
            if chat.get("last_sender"):
                chat["last_sender"] = chat["last_sender"].lower()
            chats.append(chat)
        return chats


def set_chat_status(chat_id: int, status: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE chats SET status = ? WHERE id = ?",
            (status.strip().lower(), chat_id),
        )
        return cursor.rowcount > 0


def delete_chat_record(chat_id: int) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM chat_messages WHERE chat_id = ?", (chat_id,))
        cursor = conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
        return cursor.rowcount > 0


init_db()
