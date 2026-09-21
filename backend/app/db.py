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


def _migrate_login_configs_drop_auto(conn: sqlite3.Connection) -> None:
    """
    login_configs.mode used to allow 'auto' before auto-fill login was
    removed. CREATE TABLE IF NOT EXISTS in schema.sql is a no-op on an
    already-existing table, so an existing database's CHECK constraint
    doesn't pick up the tightened ('recorded'-only) definition just by
    re-running init_db() — SQLite has no ALTER TABLE ... ALTER CHECK, so
    tightening a CHECK constraint means rebuilding the table. This does
    that rebuild:
      - is a no-op on a database that either doesn't have the table yet
        (schema.sql's CREATE TABLE will make it fresh, already
        'recorded'-only) or has already been migrated — checked by
        reading the table's stored CREATE TABLE text from sqlite_master,
        so re-running init_db() on an already-migrated DB does nothing.
      - drops any saved mode='auto' row outright: an auto-login config is
        dead data now — nothing in the app can act on mode='auto'
        anymore (main.py's _resolve_login_plan no longer has an 'auto'
        branch), so keeping it around would just be a config no scan
        could ever use again.
      - preserves every mode='recorded' row untouched.

    Only login_configs is rebuilt this way. scans.login_used deliberately
    keeps 'auto' as a legal value in schema.sql — that column is a
    historical record of what a *past* scan actually used, not a
    currently-selectable mode, so an old scan row that used auto-login
    should keep saying so rather than being rewritten or rejected.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='login_configs'"
    ).fetchone()
    if row is None or "'auto'" not in row["sql"]:
        return  # table doesn't exist yet, or already migrated — nothing to do

    conn.executescript(
        """
        ALTER TABLE login_configs RENAME TO login_configs_pre_migration;

        CREATE TABLE login_configs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip       TEXT NOT NULL UNIQUE,
            mode            TEXT NOT NULL CHECK (mode IN ('recorded')),
            login_url       TEXT,
            recorded_steps  TEXT,
            created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO login_configs (id, target_ip, mode, login_url, recorded_steps, created_at, updated_at)
        SELECT id, target_ip, mode, login_url, recorded_steps, created_at, updated_at
        FROM login_configs_pre_migration
        WHERE mode = 'recorded';

        DROP TABLE login_configs_pre_migration;
        """
    )
    conn.commit()


def init_db() -> None:
    """
    Creates the scans / findings / login_configs tables if they don't already
    exist. Safe to call every time the app starts — CREATE TABLE IF NOT
    EXISTS means it's a no-op on an already-initialized database.

    Also runs _migrate_login_configs_drop_auto(), which handles the one
    schema change CREATE TABLE IF NOT EXISTS can't: tightening
    login_configs.mode's CHECK constraint on a database that already has
    the table. Safe/idempotent to re-run on every startup — see that
    function's docstring.
    """
    schema_sql = SCHEMA_PATH.read_text()
    conn = get_connection()
    try:
        conn.executescript(schema_sql)
        conn.commit()
        _migrate_login_configs_drop_auto(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    # Allows manual initialization: `python -m app.db` from backend/
    init_db()
    print(f"Database initialized at: {Path(DATABASE_PATH).resolve()}")