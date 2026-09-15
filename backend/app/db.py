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

from app.config import DATABASE_PATH

APP_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = APP_DIR / "schema.sql"


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