"""
Persistence for recorded login flows — Step 7b of BUILD_ORDER.md
(login_configs table, per DATA_MODEL.md).

Recorded steps are stored as JSON, keyed by target_ip. The table has
UNIQUE(target_ip) — per DATA_MODEL.md, a login config is a single saved
mechanism per target, so recording again for the same IP overwrites the
previous one (matches "replay on subsequent scans of the same target").

Only the login *mechanism* is ever persisted here — never credentials.
login_recorder.py already guarantees recorded_steps never contain
password/username values (only selectors + field_type tags); this module
just stores/retrieves whatever list it's given as-is.
"""

import json
from typing import Any, Dict, List, Optional

from app.db import get_connection


def get_login_config(target_ip: str) -> Optional[Dict[str, Any]]:
    """
    Look up a saved login config for this target IP.

    Returns None if none exists, otherwise:
        {"mode": "recorded", "login_url": "..." | None, "recorded_steps": [...]}
    (recorded_steps is parsed back into a Python list.)
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT mode, login_url, recorded_steps FROM login_configs WHERE target_ip = ?",
            (target_ip,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    recorded_steps = json.loads(row["recorded_steps"]) if row["recorded_steps"] else None
    return {
        "mode": row["mode"],
        "login_url": row["login_url"],
        "recorded_steps": recorded_steps,
    }


def save_recorded_login_config(
    target_ip: str,
    recorded_steps: List[Dict[str, Any]],
    login_url: Optional[str] = None,
) -> None:
    """
    Save (or overwrite) the recorded login flow for a target IP.

    Uses SQLite's upsert (ON CONFLICT) against the UNIQUE(target_ip)
    constraint: re-recording for a target you've already recorded replaces
    the old script rather than erroring out or creating a duplicate row.
    """
    steps_json = json.dumps(recorded_steps)
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO login_configs (target_ip, mode, login_url, recorded_steps, updated_at)
            VALUES (?, 'recorded', ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(target_ip) DO UPDATE SET
                mode = 'recorded',
                login_url = excluded.login_url,
                recorded_steps = excluded.recorded_steps,
                updated_at = CURRENT_TIMESTAMP
            """,
            (target_ip, login_url, steps_json),
        )
        conn.commit()
    finally:
        conn.close()


def delete_login_config(target_ip: str) -> None:
    """Remove a saved login config (e.g. so the user can re-record it)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM login_configs WHERE target_ip = ?", (target_ip,))
        conn.commit()
    finally:
        conn.close()