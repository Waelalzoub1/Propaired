from pathlib import Path
import sqlite3

DB_PATH = Path(__file__).with_name("reserved_usernames.db")


def _normalize_username(username: str) -> str:
    return username.strip().lower()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reserved_usernames (
                username TEXT PRIMARY KEY,
                reserved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def is_username_reserved(username: str) -> bool:
    clean_username = _normalize_username(username)
    if not clean_username:
        return False
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM reserved_usernames WHERE lower(username) = lower(?)",
            (clean_username,),
        ).fetchone()
        return row is not None


def reserve_username(username: str) -> bool:
    clean_username = _normalize_username(username)
    if not clean_username:
        return False
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO reserved_usernames (username) VALUES (?)",
            (clean_username,),
        )
        return True


init_db()
