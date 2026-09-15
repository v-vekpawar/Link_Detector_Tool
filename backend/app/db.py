"""
SQLite connection helper for the Link & Navigation Audit Tool.

Usage:
    from app.db import get_connection, init_db

    init_db()  # run once (or safely re-run) to create tables

    conn = get_connection()
    conn.execute("INSERT INTO scans (...) VALUES (...)")
    conn.commit()
"""

import sqlite3
from pathlib import Path

from app.config import DATABASE_PATH as _CONFIGURED_DATABASE_PATH

APP_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = APP_DIR / "schema.sql"

# config.py's DATABASE_PATH is normally just a bare filename ("link_audit.db").
# sqlite3.connect() resolves a relative path against the process's current
# working directory *at connect time* — NOT this module's location — so
# the .db file's actual location has silently depended on wherever the
# server (or a test run) happened to be launched from (observed: it ended
# up under backend/tests/ instead of backend/app/ depending on cwd).
# Anchoring a relative DATABASE_PATH to APP_DIR here — same as SCHEMA_PATH
# already does — makes the location stable regardless of cwd. An absolute
# path in config.py (if set explicitly later) is left untouched.
_configured_path = Path(_CONFIGURED_DATABASE_PATH)
DATABASE_PATH = str(_configured_path if _configured_path.is_absolute() else APP_DIR / _configured_path)


def get_connection() -> sqlite3.Connection:
    """
    Returns a new SQLite connection with:
    - row_factory set to sqlite3.Row (access columns by name)
    - foreign key enforcement turned on (SQLite defaults it off per-connection)
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """
    Creates the scans / findings / login_configs tables if they don't already
    exist. Safe to call every time the app starts — CREATE TABLE IF NOT
    EXISTS means it's a no-op on an already-initialized database.
    """
    schema_sql = SCHEMA_PATH.read_text()
    conn = get_connection()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    # Allows manual initialization: `python -m app.db` from backend/
    init_db()
    print(f"Database initialized at: {Path(DATABASE_PATH).resolve()}")