"""
In-memory registry for in-progress login-flow recording sessions
(Step 7d of BUILD_ORDER.md).

POST /api/login/record/start kicks off a headed Playwright recording
session (login_recorder.py) in a background thread — so the HTTP request
returns immediately with a session_id instead of blocking for however
long a human takes to click through a login flow. This module tracks
that session's status/result so POST /api/login/record/save can fetch
the finished step list once the user has clicked "Finish Recording" in
the browser window.

Sessions are transient, in-memory only, and single-process — they exist
just long enough to get the recorded steps into login_configs (see
login_config_store.py) via the save endpoint, then get dropped.
"""

import threading
import uuid
from typing import Any, Dict, Optional

from app.login_recorder import record_login_flow

_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def start_recording_session(target_url: str) -> str:
    """Launches a headed recording session in the background, returns its session_id immediately."""
    session_id = str(uuid.uuid4())
    with _lock:
        _sessions[session_id] = {
            "status": "running",  # "running" | "done" | "error"
            "target_url": target_url,
            "steps": None,
            "error": None,
        }

    def _worker():
        try:
            steps = record_login_flow(target_url)
            with _lock:
                _sessions[session_id]["status"] = "done"
                _sessions[session_id]["steps"] = steps
        except Exception as e:
            with _lock:
                _sessions[session_id]["status"] = "error"
                _sessions[session_id]["error"] = str(e)

    threading.Thread(target=_worker, daemon=True).start()
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        session = _sessions.get(session_id)
        return dict(session) if session is not None else None


def pop_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Removes and returns a session's data — used once its steps have been saved."""
    with _lock:
        return _sessions.pop(session_id, None)