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

from app.login_recorder import FlowRecordingSession, LoginRecordingSession

import logging
logger = logging.getLogger("link_audit.login_record_sessions")

_flows: Dict[str, Dict[str, Any]] = {}

_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def start_recording_session(target_url: str) -> str:
    """Launches a headed recording session in the background, returns its session_id immediately."""
    session_id = str(uuid.uuid4())
    rec_session = LoginRecordingSession()
    with _lock:
        _sessions[session_id] = {
            "status": "running",  # "running" | "done" | "error"
            "target_url": target_url,
            "instance": rec_session,
            "steps": None,
            "error": None,
        }

    def _worker():
        try:
            steps = rec_session.run(target_url)
            with _lock:
                _sessions[session_id]["status"] = "done"
                _sessions[session_id]["steps"] = steps
        except Exception as e:
            logger.exception("single-shot recording for %r failed", target_url)
            with _lock:
                _sessions[session_id]["status"] = "error"
                _sessions[session_id]["error"] = str(e)

    threading.Thread(target=_worker, daemon=True).start()
    return session_id


def finish_recording_session(session_id: str) -> bool:
    """Signals the recording session's browser to finish and close."""
    with _lock:
        session = _sessions.get(session_id)
        if session is None:
            return False
        instance = session.get("instance")
        if instance is not None:
            instance.finish()
            return True
        return False


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        session = _sessions.get(session_id)
        if session is None:
            return None
        # Return a copy without internal instance object
        data = dict(session)
        data.pop("instance", None)
        return data


def pop_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Removes and returns a session's data — used once its steps have been saved."""
    with _lock:
        data = _sessions.pop(session_id, None)
        if data is not None:
            data.pop("instance", None)
        return data


# ---------------------------------------------------------------------------
# Phased login→logout flows (one shared Chromium window per flow).
# Unlike single-shot sessions above, the browser stays open across phases
# until the flow is saved (or the window is closed / times out).
# ---------------------------------------------------------------------------

def start_flow_session(target_url: str) -> str:
    """Opens a headed flow window in the background, returns its flow_id immediately."""
    flow_id = str(uuid.uuid4())
    flow = FlowRecordingSession(target_url)
    with _lock:
        _flows[flow_id] = {"flow": flow, "target_url": target_url}

    def _worker():
        try:
            flow.run()
        except Exception:
            logger.exception("flow recording window for %r died", target_url)

    threading.Thread(target=_worker, daemon=True).start()
    return flow_id


def start_logout_only_session(target_url: str, login_bundle: Dict[str, Any]) -> str:
    """
    Standalone logout recording: opens the window, auto-replays the SAVED
    login with the given bundle, then captures logout clicks in the same
    window. Saved login steps are never touched by this flow.
    """
    flow_id = str(uuid.uuid4())
    flow = FlowRecordingSession(target_url, logout_only=True)
    with _lock:
        _flows[flow_id] = {"flow": flow, "target_url": target_url}

    def _worker():
        try:
            flow.run(auto_login=login_bundle)
        except Exception:
            logger.exception("logout-only recording window for %r died", target_url)

    threading.Thread(target=_worker, daemon=True).start()
    return flow_id


def get_flow(flow_id: str) -> Optional[FlowRecordingSession]:
    """Returns the live flow session, or None when unknown/finished-and-popped."""
    with _lock:
        entry = _flows.get(flow_id)
        return entry["flow"] if entry is not None else None


def pop_flow(flow_id: str) -> Optional[FlowRecordingSession]:
    """Removes and returns a flow session — used once its flow has been saved."""
    with _lock:
        entry = _flows.pop(flow_id, None)
        return entry["flow"] if entry is not None else None