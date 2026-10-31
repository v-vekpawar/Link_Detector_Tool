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

Item #1 adds logout_url and logout_steps to the same row: a target may
optionally have either a logout URL (navigate there at scan end) or a
recorded logout click sequence (replayed at scan end), or neither.
logout_start_url accompanies recorded steps: the page (origin + path) the
logout was performed on — replay navigates back there first, since the
logout control lives on the authed home, which is often not the URL being
scanned.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from app.db import get_connection

logger = logging.getLogger("link_audit.login_config_store")


def get_login_config(target_ip: str) -> Optional[Dict[str, Any]]:
    """
    Look up a saved login config for this target IP.

    Returns None if none exists, otherwise:
        {"mode": "recorded", "login_url": "..." | None, "recorded_steps": [...],
         "captcha_answer": "..." | None,
         "logout_url": "..." | None, "logout_steps": [...] | None,
         "logout_start_url": "..." | None}
    (recorded_steps and logout_steps are parsed back into Python lists.)
    """
    conn = get_connection()
    try:
        row = conn.execute(
            """SELECT mode, login_url, recorded_steps, captcha_answer,
                      logout_url, logout_steps, logout_start_url
               FROM login_configs WHERE target_ip = ?""",
            (target_ip,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        logger.info("get_login_config(%r) — no config found", target_ip)
        return None

    recorded_steps = json.loads(row["recorded_steps"]) if row["recorded_steps"] else None
    logout_steps = json.loads(row["logout_steps"]) if row["logout_steps"] else None
    logger.info(
        "get_login_config(%r) — found config: mode=%r login_url=%r steps=%d "
        "has_captcha_answer=%s logout_url=%r logout_steps=%d",
        target_ip, row["mode"], row["login_url"],
        len(recorded_steps) if recorded_steps else 0,
        row["captcha_answer"] is not None,
        row["logout_url"],
        len(logout_steps) if logout_steps else 0,
    )
    return {
        "mode": row["mode"],
        "login_url": row["login_url"],
        "recorded_steps": recorded_steps,
        "captcha_answer": row["captcha_answer"],
        "logout_url": row["logout_url"],
        "logout_steps": logout_steps,
        "logout_start_url": row["logout_start_url"],
    }


def save_recorded_login_config(
    target_ip: str,
    recorded_steps: List[Dict[str, Any]],
    login_url: Optional[str] = None,
    captcha_answer: Optional[str] = None,
) -> None:
    """
    Save (or overwrite) the recorded login flow for a target IP.

    Uses SQLite's upsert (ON CONFLICT) against the UNIQUE(target_ip)
    constraint: re-recording for a target you've already recorded replaces
    the old script rather than erroring out or creating a duplicate row.

    Logout fields (logout_url / logout_steps) are NOT touched by this call —
    they are managed separately via save_logout_config(), so re-recording
    the login flow doesn't wipe a previously configured logout.
    """
    steps_json = json.dumps(recorded_steps)
    logger.info(
        "save_recorded_login_config(%r) — saving %d steps, login_url=%r, has_captcha_answer=%s",
        target_ip, len(recorded_steps), login_url, captcha_answer is not None,
    )
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO login_configs (target_ip, mode, login_url, recorded_steps, captcha_answer, updated_at)
            VALUES (?, 'recorded', ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(target_ip) DO UPDATE SET
                mode = 'recorded',
                login_url = excluded.login_url,
                recorded_steps = excluded.recorded_steps,
                captcha_answer = excluded.captcha_answer,
                updated_at = CURRENT_TIMESTAMP
            """,
            (target_ip, login_url, steps_json, captcha_answer),
        )
        conn.commit()
        logger.info("save_recorded_login_config(%r) — saved successfully", target_ip)
    except Exception as exc:
        logger.error("save_recorded_login_config(%r) — DB error: %s", target_ip, exc)
        raise
    finally:
        conn.close()


def save_logout_config(
    target_ip: str,
    logout_url: Optional[str] = None,
    logout_steps: Optional[List[Dict[str, Any]]] = None,
    logout_start_url: Optional[str] = None,
) -> None:
    """
    Save (or clear) the logout configuration for a target IP.

    At least one of the target's login rows must already exist (created by
    save_recorded_login_config) — this only updates the logout fields, it
    never creates a new row. Passing logout_url=None and logout_steps=None
    clears all logout fields (disabling logout for this target).

    Only one mechanism is expected to be active at a time: if logout_url is
    provided, logout_steps is cleared, and vice versa (enforced here to
    avoid ambiguity at replay time).

    logout_start_url is the page (query/fragment-stripped) the recorded
    logout steps were performed on — replay returns there first, because the
    logout control lives on the authed home, which often is NOT the scan
    target (many targets scan the bare login form). Only meaningful with
    logout_steps; the URL mechanism navigates directly, so it's stored as
    NULL in that case (and when no logout_start_url is supplied).
    """
    if logout_url and logout_steps:
        # Both provided — URL takes precedence, discard steps to avoid ambiguity.
        logger.warning(
            "save_logout_config(%r) — both logout_url and logout_steps provided; "
            "keeping logout_url, discarding logout_steps",
            target_ip,
        )
        logout_steps = None
    if logout_url:
        logout_start_url = None

    steps_json = json.dumps(logout_steps) if logout_steps else None
    start_url = (logout_start_url or "").strip() or None
    logger.info(
        "save_logout_config(%r) — logout_url=%r, logout_steps=%d step(s), logout_start_url=%r",
        target_ip, logout_url,
        len(logout_steps) if logout_steps else 0,
        start_url,
    )
    conn = get_connection()
    try:
        conn.execute(
            """UPDATE login_configs
               SET logout_url = ?, logout_steps = ?, logout_start_url = ?,
                   updated_at = CURRENT_TIMESTAMP
               WHERE target_ip = ?""",
            (logout_url, steps_json, start_url, target_ip),
        )
        conn.commit()
        logger.info("save_logout_config(%r) — saved successfully", target_ip)
    except Exception as exc:
        logger.error("save_logout_config(%r) — DB error: %s", target_ip, exc)
        raise
    finally:
        conn.close()


def delete_login_config(target_ip: str) -> None:
    """Remove a saved login config (e.g. so the user can re-record it)."""
    logger.info("delete_login_config(%r) — removing config", target_ip)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM login_configs WHERE target_ip = ?", (target_ip,))
        conn.commit()
        logger.info("delete_login_config(%r) — done", target_ip)
    except Exception as exc:
        logger.error("delete_login_config(%r) — DB error: %s", target_ip, exc)
        raise
    finally:
        conn.close()