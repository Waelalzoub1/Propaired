from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional

from Database.fuzzy_search import matches_fuzzy
from Database.reserved_usernames import is_username_reserved, reserve_username
from Database.security import hash_password

DB_PATH = Path(__file__).with_name("customers.db")


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


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL DEFAULT '',
                contact_email TEXT NOT NULL DEFAULT '',
                has_posted_job INTEGER NOT NULL DEFAULT 0,
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
        _drop_columns(conn, "customers", {"recovery_phone", "recovery_carrier"})
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_username TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                keywords TEXT NOT NULL DEFAULT '',
                budget TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                location_lat REAL,
                location_lon REAL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(customer_username) REFERENCES customers(username)
            )
            """
        )
        _ensure_customer_columns(conn)
        _ensure_job_columns(conn)
        _sync_job_posted_flags(conn)
        _normalize_existing_usernames(conn)


def _ensure_customer_columns(conn: sqlite3.Connection) -> None:
    required_columns = {
        "contact_email": "TEXT NOT NULL DEFAULT ''",
        "has_posted_job": "INTEGER NOT NULL DEFAULT 0",
        "email_verified": "INTEGER NOT NULL DEFAULT 0",
        "verification_token_hash": "TEXT NOT NULL DEFAULT ''",
        "verification_expires_at": "INTEGER",
        "verification_sent_at": "INTEGER",
        "reset_code_hash": "TEXT NOT NULL DEFAULT ''",
        "reset_expires_at": "INTEGER",
        "reset_sent_at": "INTEGER",
    }

    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(customers)").fetchall()
    }

    for column_name, ddl in required_columns.items():
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE customers ADD COLUMN {column_name} {ddl}")


def _ensure_job_columns(conn: sqlite3.Connection) -> None:
    required_columns = {
        "location_lat": "REAL",
        "location_lon": "REAL",
        "stripe_payment_intent_id": "TEXT NOT NULL DEFAULT ''",
        "stripe_payment_status": "TEXT NOT NULL DEFAULT ''",
        "stripe_amount_cents": "INTEGER",
        "stripe_currency": "TEXT NOT NULL DEFAULT 'usd'",
        "stripe_helper_username": "TEXT NOT NULL DEFAULT ''",
        "stripe_platform_fee_cents": "INTEGER",
        "stripe_transfer_id": "TEXT NOT NULL DEFAULT ''",
        "customer_completed_at": "INTEGER",
        "helper_completed_at": "INTEGER",
    }

    existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    for column_name, ddl in required_columns.items():
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE jobs ADD COLUMN {column_name} {ddl}")


def _sync_job_posted_flags(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE customers
        SET has_posted_job = 1
        WHERE lower(username) IN (
            SELECT DISTINCT lower(customer_username) FROM jobs
        )
        """
    )


def _has_case_collisions(conn: sqlite3.Connection) -> bool:
    cursor = conn.execute(
        """
        SELECT lower(username)
        FROM customers
        GROUP BY lower(username)
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    )
    return cursor.fetchone() is not None


def _normalize_existing_usernames(conn: sqlite3.Connection) -> None:
    """Lowercase existing usernames for consistent matching."""

    if _has_case_collisions(conn):
        return

    conn.execute(
        "UPDATE customers SET username = lower(username) WHERE username != lower(username)"
    )
    conn.execute(
        """
        UPDATE jobs
        SET customer_username = lower(customer_username)
        WHERE customer_username != lower(customer_username)
        """
    )


def get_customer_password(username: str) -> Optional[str]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT password FROM customers WHERE lower(username) = lower(?)",
            (clean_username,),
        )
        row = cursor.fetchone()
        return row[0] if row else None


def create_customer(
    username: str,
    password: str,
    full_name: str,
    contact_email: str,
    allow_reserved: bool = False,
) -> bool:
    clean_username = _normalize_username(username)
    try:
        if not allow_reserved and is_username_reserved(clean_username):
            return False
        hashed_password = hash_password(password)
        with sqlite3.connect(DB_PATH) as conn:
            existing = conn.execute(
                "SELECT 1 FROM customers WHERE lower(username) = lower(?) LIMIT 1",
                (clean_username,),
            ).fetchone()
            if existing:
                return False
            conn.execute(
                """
                INSERT INTO customers (username, password, full_name, contact_email)
                VALUES (?, ?, ?, ?)
                """
                ,
                (clean_username, hashed_password, full_name.strip(), contact_email.strip()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_customer_profile(username: str) -> Optional[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, full_name, contact_email
            FROM customers
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
        return profile


def update_customer_full_name(username: str, full_name: str) -> bool:
    """Update the display name for a customer account."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE customers SET full_name = ? WHERE lower(username) = lower(?)",
            (full_name.strip(), clean_username),
        )
        return cursor.rowcount > 0


def update_customer_password(username: str, new_password: str) -> bool:
    """Replace the stored password for a customer account."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE customers SET password = ? WHERE lower(username) = lower(?)",
            (hash_password(new_password), clean_username),
        )
        return cursor.rowcount > 0


def get_customer_auth_info(username: str) -> Optional[Dict[str, Any]]:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, password, contact_email, email_verified,
                   verification_token_hash, verification_expires_at, verification_sent_at,
                   reset_code_hash, reset_expires_at, reset_sent_at
            FROM customers
            WHERE lower(username) = lower(?)
            """
            ,
            (clean_username,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        auth = dict(row)
        if auth.get("username"):
            auth["username"] = auth["username"].lower()
        return auth


def has_customer_posted_job(username: str) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT has_posted_job FROM customers WHERE lower(username) = lower(?)",
            (clean_username,),
        )
        row = cursor.fetchone()
        return bool(row[0]) if row else False


def update_customer_email(username: str, contact_email: str) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE customers SET contact_email = ? WHERE lower(username) = lower(?)",
            (contact_email.strip(), clean_username),
        )
        return cursor.rowcount > 0


def update_customer_verification_sent_at(username: str, sent_at: int) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE customers SET verification_sent_at = ? WHERE lower(username) = lower(?)",
            (sent_at, clean_username),
        )
        return cursor.rowcount > 0


def set_customer_reset_code(username: str, code_hash: str, expires_at: int) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE customers
            SET reset_code_hash = ?,
                reset_expires_at = ?,
                reset_sent_at = NULL
            WHERE lower(username) = lower(?)
            """,
            (code_hash, expires_at, clean_username),
        )
        return cursor.rowcount > 0


def update_customer_reset_sent_at(username: str, sent_at: int) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE customers SET reset_sent_at = ? WHERE lower(username) = lower(?)",
            (sent_at, clean_username),
        )
        return cursor.rowcount > 0


def clear_customer_reset_code(username: str) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE customers
            SET reset_code_hash = '',
                reset_expires_at = NULL,
                reset_sent_at = NULL
            WHERE lower(username) = lower(?)
            """,
            (clean_username,),
        )
        return cursor.rowcount > 0


def update_customer_admin(
    username: str,
    full_name: str,
    contact_email: str,
    email_verified: bool,
) -> bool:
    token_hash = "" if email_verified else None
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE customers
            SET full_name = ?,
                contact_email = ?,
                email_verified = ?,
                verification_token_hash = COALESCE(?, verification_token_hash),
                verification_expires_at = CASE
                    WHEN ? IS NULL THEN verification_expires_at
                    ELSE NULL
                END
            WHERE lower(username) = lower(?)
            """,
            (
                full_name.strip(),
                contact_email.strip(),
                1 if email_verified else 0,
                token_hash,
                token_hash,
                clean_username,
            ),
        )
        return cursor.rowcount > 0


def set_customer_verification(
    username: str,
    contact_email: str,
    token_hash: str,
    expires_at: int,
) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE customers
            SET contact_email = ?,
                email_verified = 0,
                verification_token_hash = ?,
                verification_expires_at = ?
            WHERE lower(username) = lower(?)
            """
            ,
            (contact_email.strip(), token_hash, expires_at, clean_username),
        )
        return cursor.rowcount > 0


def mark_customer_verified(username: str) -> bool:
    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE customers
            SET email_verified = 1,
                verification_token_hash = '',
                verification_expires_at = NULL
            WHERE lower(username) = lower(?)
            """
            ,
            (clean_username,),
        )
        return cursor.rowcount > 0


def find_customer_by_verification_token(token_hash: str) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, contact_email, email_verified, verification_expires_at
            FROM customers
            WHERE verification_token_hash = ?
            """
            ,
            (token_hash,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        info = dict(row)
        if info.get("username"):
            info["username"] = info["username"].lower()
        return info


def create_job(
    customer_username: str,
    title: str,
    description: str,
    keywords: str,
    budget: str,
    location: str,
    location_lat: Optional[float] = None,
    location_lon: Optional[float] = None,
) -> Dict[str, Any]:
    clean_username = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO jobs (
                customer_username,
                title,
                description,
                keywords,
                budget,
                location,
                location_lat,
                location_lon
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            ,
            (
                clean_username,
                title.strip(),
                description.strip(),
                keywords.strip(),
                budget.strip(),
                location.strip(),
                location_lat,
                location_lon,
            ),
        )
        conn.execute(
            "UPDATE customers SET has_posted_job = 1 WHERE lower(username) = lower(?)",
            (clean_username,),
        )
        job_id = cursor.lastrowid
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
        job = dict(row)
        if job.get("customer_username"):
            job["customer_username"] = job["customer_username"].lower()
        return job


def list_jobs_for_customer(customer_username: str) -> List[Dict[str, Any]]:
    clean_username = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT * FROM jobs
            WHERE lower(customer_username) = lower(?)
            ORDER BY created_at DESC
            """
            ,
            (clean_username,),
        )
        jobs: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            job = dict(row)
            if job.get("customer_username"):
                job["customer_username"] = job["customer_username"].lower()
            jobs.append(job)
        return jobs


def list_all_jobs() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC, id DESC"
        )
        jobs: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            job = dict(row)
            if job.get("customer_username"):
                job["customer_username"] = job["customer_username"].lower()
            jobs.append(job)
        return jobs


def list_customers() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT username, full_name, contact_email, email_verified
            FROM customers
            ORDER BY lower(username)
            """
        )
        customers: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            customer = dict(row)
            if customer.get("username"):
                customer["username"] = customer["username"].lower()
            customers.append(customer)
        return customers


def search_jobs(keyword: str) -> List[Dict[str, Any]]:
    """Search open jobs with fuzzy matching on title, description, and keywords."""

    threshold = 0.5
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT * FROM jobs
            WHERE status = 'open'
            ORDER BY created_at DESC
            """
        )
        jobs = [dict(row) for row in cursor.fetchall()]
        for job in jobs:
            if job.get("customer_username"):
                job["customer_username"] = job["customer_username"].lower()

    if not keyword:
        return jobs

    scored: List[Dict[str, Any]] = []
    for job in jobs:
        matched, score = matches_fuzzy(
            keyword,
            [
                job.get("title", ""),
                job.get("description", ""),
                job.get("keywords", ""),
                job.get("location", ""),
            ],
            threshold,
        )
        if matched:
            job["_score"] = score
            scored.append(job)

    scored.sort(key=lambda job: (-job.get("_score", 0.0), job.get("created_at", "")))
    for job in scored:
        job.pop("_score", None)
    return scored


def get_job(job_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM jobs WHERE id = ?",
            (job_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        job = dict(row)
        if job.get("customer_username"):
            job["customer_username"] = job["customer_username"].lower()
        return job


def get_job_payment(job_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT stripe_payment_intent_id, stripe_payment_status, stripe_amount_cents,
                   stripe_currency, stripe_helper_username, stripe_platform_fee_cents,
                   stripe_transfer_id
            FROM jobs
            WHERE id = ?
            """,
            (job_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        if record.get("stripe_helper_username"):
            record["stripe_helper_username"] = record["stripe_helper_username"].lower()
        return record


def set_job_payment_intent(
    job_id: int,
    payment_intent_id: str,
    amount_cents: int,
    currency: str,
    helper_username: str,
    platform_fee_cents: int,
) -> bool:
    clean_helper = _normalize_username(helper_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            UPDATE jobs
            SET stripe_payment_intent_id = ?,
                stripe_payment_status = 'created',
                stripe_amount_cents = ?,
                stripe_currency = ?,
                stripe_helper_username = ?,
                stripe_platform_fee_cents = ?
            WHERE id = ?
            """,
            (
                payment_intent_id,
                amount_cents,
                currency.lower(),
                clean_helper,
                platform_fee_cents,
                job_id,
            ),
        )
        return cursor.rowcount > 0


def update_job_payment_status(job_id: int, status: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE jobs SET stripe_payment_status = ? WHERE id = ?",
            (status.strip().lower(), job_id),
        )
        return cursor.rowcount > 0


def update_job_transfer(job_id: int, transfer_id: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE jobs SET stripe_transfer_id = ? WHERE id = ?",
            (transfer_id, job_id),
        )
        return cursor.rowcount > 0


def set_job_completion(job_id: int, role: str) -> bool:
    column = "customer_completed_at" if role == "customer" else "helper_completed_at"
    timestamp = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            f"UPDATE jobs SET {column} = ? WHERE id = ?",
            (timestamp, job_id),
        )
        return cursor.rowcount > 0


def update_job_status(job_id: int, status: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE jobs SET status = ? WHERE id = ?",
            (status.strip().lower(), job_id),
        )
        return cursor.rowcount > 0


def update_job_location_coords(job_id: int, location_lat: float, location_lon: float) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE jobs SET location_lat = ?, location_lon = ? WHERE id = ?",
            (location_lat, location_lon, job_id),
        )
        return cursor.rowcount > 0


def delete_job(job_id: int, customer_username: str) -> bool:
    clean_username = _normalize_username(customer_username)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM jobs WHERE id = ? AND lower(customer_username) = lower(?)",
            (job_id, clean_username),
        )
        return cursor.rowcount > 0


def delete_customer(username: str) -> bool:
    """Delete a customer account and all related jobs."""

    clean_username = _normalize_username(username)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM jobs WHERE lower(customer_username) = lower(?)",
            (clean_username,),
        )
        cursor = conn.execute(
            "DELETE FROM customers WHERE lower(username) = lower(?)",
            (clean_username,),
        )
        deleted = cursor.rowcount > 0
        if deleted:
            reserve_username(clean_username)
        return deleted


init_db()
