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


def _migrate_login_configs_add_captcha_answer(conn: sqlite3.Connection) -> None:
    """
    Adds login_configs.captcha_answer (fixed captcha value for a target's
    recorded login flow, if it has one) to a database created before this
    column existed. Unlike the mode-CHECK migration above, this is a plain
    additive column, so ALTER TABLE ... ADD COLUMN is enough — no rebuild
    needed. Checked against PRAGMA table_info so re-running init_db() on an
    already-migrated DB is a no-op, same as the rest of this module.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(login_configs)")}
    if "captcha_answer" in columns:
        return  # already migrated (or a fresh DB where schema.sql already created it)
    conn.execute("ALTER TABLE login_configs ADD COLUMN captcha_answer TEXT")
    conn.commit()


def _migrate_login_configs_add_logout_fields(conn: sqlite3.Connection) -> None:
    """
    Adds login_configs.logout_url and login_configs.logout_steps (both TEXT,
    nullable) to databases created before item #1 of the planned changes was
    implemented. Additive columns only — no table rebuild needed. Idempotent:
    re-running init_db() on an already-migrated DB does nothing.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(login_configs)")}
    added = False
    if "logout_url" not in columns:
        conn.execute("ALTER TABLE login_configs ADD COLUMN logout_url TEXT")
        added = True
    if "logout_steps" not in columns:
        conn.execute("ALTER TABLE login_configs ADD COLUMN logout_steps TEXT")
        added = True
    if added:
        conn.commit()


def _migrate_login_configs_add_logout_start_url(conn: sqlite3.Connection) -> None:
    """
    Adds login_configs.logout_start_url (TEXT, nullable): the page the
    recorded logout steps were performed on. Scan-end logout replay must
    return to THAT page — the authed home carrying the logout control — not
    the scan target, which for many sites is the bare login form (every
    logout selector used to fail "matched 0 elements" there). Additive
    column, so ALTER TABLE ... ADD COLUMN is enough (same pattern as
    captcha_answer). Idempotent like the rest of this module.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(login_configs)")}
    if "logout_start_url" in columns:
        return  # already migrated (or a fresh DB where schema.sql already created it)
    conn.execute("ALTER TABLE login_configs ADD COLUMN logout_start_url TEXT")
    conn.commit()


def _migrate_scans_add_stopped_status(conn: sqlite3.Connection) -> None:
    """
    Adds 'stopped' to scans.status CHECK (cooperative scan-stop feature).
    CREATE TABLE IF NOT EXISTS in schema.sql is a no-op on an already-existing
    table, and SQLite has no ALTER TABLE ... ALTER CHECK, so — like
    _migrate_login_configs_drop_auto above — this rebuilds the table.

    Unlike that migration, findings.scan_id REFERENCES scans(id), so a plain
    ALTER TABLE scans RENAME is unsafe here: SQLite rewrites the child's
    REFERENCES clause to the backup name (verified on this project's SQLite),
    leaving it dangling after the backup is dropped. Instead the new table is
    built under a temp name, data copied, old table dropped, temp renamed —
    a sequence that never renames the referenced table, so findings keeps
    pointing at scans throughout. Wrapped in one transaction; verified
    afterwards with PRAGMA foreign_key_check. Idempotent: re-running on an
    already-migrated DB (or a fresh DB) does nothing.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()
    if row is None or "'stopped'" in (row["sql"] or ""):
        return  # table doesn't exist yet, or already migrated — nothing to do

    # FK enforcement OFF first: dropping the parent with it ON would cascade
    # the drop into findings and wipe every stored finding (verified). The
    # temp-name sequence never renames the referenced table itself, so the
    # child's REFERENCES scans(id) survives the rebuild untouched.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("BEGIN")
    try:
        conn.execute(
            """
            CREATE TABLE scans_new (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url           TEXT NOT NULL,
                target_ip            TEXT,
                site_type            TEXT NOT NULL CHECK (site_type IN ('static', 'dynamic')),
                login_used           TEXT NOT NULL DEFAULT 'none' CHECK (login_used IN ('none', 'auto', 'recorded')),
                started_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at         DATETIME,
                status               TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'stopped')),
                pages_crawled        INTEGER,
                total_links_checked  INTEGER,
                duration_seconds     INTEGER
            )
            """
        )
        conn.execute(
            """INSERT INTO scans_new (id, target_url, target_ip, site_type, login_used, started_at,
                                      completed_at, status, pages_crawled, total_links_checked, duration_seconds)
               SELECT id, target_url, target_ip, site_type, login_used, started_at,
                      completed_at, status, pages_crawled, total_links_checked, duration_seconds
               FROM scans"""
        )
        conn.execute("DROP TABLE scans")
        conn.execute("ALTER TABLE scans_new RENAME TO scans")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")

    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise sqlite3.IntegrityError(
            f"scans status migration left dangling foreign keys: {violations}"
        )


def _migrate_screenshot_shots_add_two_panel(conn: sqlite3.Connection) -> None:
    """
    Adds screenshot_shots.two_panel (whether the proof stitches a
    same-host target-result panel) to databases created after the
    screenshots feature landed but before two-panel proofs existed.
    Additive column only — idempotent like the other _migrate_* functions.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(screenshot_shots)")}
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "screenshot_shots" not in tables:
        return  # screenshots tables don't exist yet — schema.sql creates them fresh
    if "two_panel" in columns:
        return
    conn.execute("ALTER TABLE screenshot_shots ADD COLUMN two_panel INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def init_db() -> None:
    """
    Creates the scans / findings / login_configs tables if they don't already
    exist. Safe to call every time the app starts — CREATE TABLE IF NOT
    EXISTS means it's a no-op on an already-initialized database.

    Also runs all _migrate_* functions, which handle schema
    changes that CREATE TABLE IF NOT EXISTS can't apply to an already-existing
    table. Safe/idempotent to re-run on every startup — see each function's
    docstring.
    """
    schema_sql = SCHEMA_PATH.read_text()
    conn = get_connection()
    try:
        conn.executescript(schema_sql)
        conn.commit()
        _migrate_scans_add_stopped_status(conn)
        _migrate_screenshot_shots_add_two_panel(conn)
        _migrate_login_configs_drop_auto(conn)
        _migrate_login_configs_add_captcha_answer(conn)
        _migrate_login_configs_add_logout_fields(conn)
        _migrate_login_configs_add_logout_start_url(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    # Allows manual initialization: `python -m app.db` from backend/
    init_db()
    print(f"Database initialized at: {Path(DATABASE_PATH).resolve()}")