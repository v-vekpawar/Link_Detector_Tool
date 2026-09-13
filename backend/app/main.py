"""
FastAPI backend (Steps 5–8 of BUILD_ORDER.md).

/api/scan/start does cheap, synchronous validation only (site_type value,
login mode/site_type compatibility, required login fields present, and —
for "recorded" mode — that a saved login_config actually exists for this
target). It creates the scan's DB row and returns scan_id immediately.
Everything that touches the network (starting the Tier 2 browser, logging
in, and the crawl itself) runs in a background thread — see
_run_scan_worker() below. Live progress from that thread is tracked in
app.scan_sessions and streamed via GET /api/scan/{id}/progress (SSE).

Both site_type values are wired up: "static" runs Tier 1 only; "dynamic"
spins up a Tier 2 DynamicSession (Playwright) for login + JS rendering,
handing rendered HTML back to the same Tier 1 extractor/crawler.

Login modes for a dynamic scan:
  - "auto": auto-fills a detected password field + nearby username field.
  - "recorded": replays a previously-recorded click/fill flow (see
    login_recorder.py / login_config_store.py). Requires having already
    recorded one for this target via /api/login/record/start + /save.

Run from backend/ with the venv active:
    uvicorn app.main:app --reload
"""

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import scan_sessions
from app.config import extract_reference_ip
from app.crawler import crawl_site
from app.db import get_connection, init_db
from app.export import build_pdf_bytes, build_xlsx_bytes
from app.login_config_store import get_login_config, save_recorded_login_config
from app.login_record_sessions import get_session, pop_session, start_recording_session
from app.renderer import DynamicSession

app = FastAPI(title="Link & Navigation Audit Tool")

# Poll interval for the SSE progress stream. crawl_site's progress_callback
# fires once per page, which can be much faster or slower than this — the
# stream just samples whatever scan_sessions has at each tick, it doesn't
# need to fire in lockstep with page completions.
SSE_POLL_INTERVAL_SECONDS = 1.0


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class LoginConfig(BaseModel):
    mode: str  # "auto" | "recorded"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ScanStartRequest(BaseModel):
    target_url: str
    site_type: str  # "static" | "dynamic"
    login: Optional[LoginConfig] = None


class ScanStartResponse(BaseModel):
    scan_id: int


class RecordStartRequest(BaseModel):
    target_url: str


class RecordStartResponse(BaseModel):
    session_id: str


class RecordSaveRequest(BaseModel):
    session_id: str
    target_ip: str


class RecordSaveResponse(BaseModel):
    saved: bool


class LoginConfigResponse(BaseModel):
    exists: bool
    mode: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FINDING_CATEGORY_KEYS = ("broken", "inactive", "ip_based", "internet")


def _row_to_scan_dict(row) -> dict:
    return {
        "id": row["id"],
        "target_url": row["target_url"],
        "target_ip": row["target_ip"],
        "site_type": row["site_type"],
        "status": row["status"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "pages_crawled": row["pages_crawled"],
        "total_links_checked": row["total_links_checked"],
        "duration_seconds": row["duration_seconds"],
    }


def _summarize(findings: list) -> dict:
    summary = {key: 0 for key in FINDING_CATEGORY_KEYS}
    for finding in findings:
        for category in finding["category"].split(","):
            if category in summary:
                summary[category] += 1
    return summary


def _build_results_payload(scan_id: int):
    conn = get_connection()
    try:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan_row is None:
            return None
        finding_rows = conn.execute(
            """SELECT found_on_page, link, category, code_snippet, evidence, element_location
               FROM findings WHERE scan_id = ?""",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    findings = [dict(row) for row in finding_rows]
    return {
        "scan": _row_to_scan_dict(scan_row),
        "summary": _summarize(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Background scan execution (Step 8)
# ---------------------------------------------------------------------------

def _resolve_login_plan(payload: ScanStartRequest, reference_ip: str) -> Optional[Dict[str, Any]]:
    """
    Synchronous, network-free validation of the requested login mode.
    Raises HTTPException(400) for anything wrong with the request shape or
    an unresolvable "recorded" reference — this is exactly the validation
    that used to happen inline before the network calls, just pulled out
    so it can run before the background thread starts.

    Returns a plan dict the background worker can act on without touching
    the DB or request payload again, or None if no login is configured.
    """
    if payload.login is None:
        return None

    if payload.login.mode == "auto":
        if not (payload.login.login_url and payload.login.username and payload.login.password):
            raise HTTPException(
                status_code=400,
                detail="login mode 'auto' requires login_url, username, and password.",
            )
        return {
            "mode": "auto",
            "login_url": payload.login.login_url,
            "username": payload.login.username,
            "password": payload.login.password,
        }

    if payload.login.mode == "recorded":
        if not (payload.login.username and payload.login.password):
            raise HTTPException(
                status_code=400,
                detail="login mode 'recorded' requires username and password — credentials are "
                       "never stored, only the click/fill mechanism, so they must be supplied fresh "
                       "each scan.",
            )
        saved_config = get_login_config(reference_ip)
        if saved_config is None or saved_config["mode"] != "recorded":
            raise HTTPException(
                status_code=400,
                detail=f"No recorded login flow found for {reference_ip}. Record one first via "
                       f"/api/login/record/start.",
            )
        start_url = payload.login.login_url or saved_config["login_url"]
        if not start_url:
            raise HTTPException(
                status_code=400,
                detail="No login URL available to replay against — the saved recording doesn't "
                       "have one and none was provided in this request.",
            )
        return {
            "mode": "recorded",
            "start_url": start_url,
            "recorded_steps": saved_config["recorded_steps"],
            "username": payload.login.username,
            "password": payload.login.password,
        }

    raise HTTPException(status_code=400, detail=f"Unknown login mode: {payload.login.mode!r}")


def _run_scan_worker(scan_id: int, target_url: str, site_type: str, reference_ip: str,
                      login_plan: Optional[Dict[str, Any]]) -> None:
    """
    Runs entirely in a background thread, started by start_scan() right
    after it returns scan_id to the caller. Owns everything that touches
    the network: Tier 2 startup + login (if dynamic), the crawl itself,
    and writing the final results back to SQLite. Reports live progress
    via app.scan_sessions so GET /api/scan/{id}/progress can stream it.

    Any exception here — a login failure, a crawl blowing up, whatever —
    is caught and turned into status='failed' on the scan row plus an
    error message on the progress entry, rather than being allowed to
    kill the thread silently.
    """
    session = requests.Session()
    page_html_fetcher = None
    dyn_session = None
    login_used = "none"
    conn = get_connection()

    try:
        try:
            if site_type == "dynamic":
                dyn_session = DynamicSession().start()
                page_html_fetcher = dyn_session.render

                if login_plan is not None:
                    if login_plan["mode"] == "auto":
                        logged_in = dyn_session.auto_login(
                            login_plan["login_url"], login_plan["username"], login_plan["password"]
                        )
                        if not logged_in:
                            raise RuntimeError(
                                "Could not find a password field on the login page — auto-login failed."
                            )
                        session.cookies.update(dyn_session.cookies_for_requests())
                        login_used = "auto"

                    elif login_plan["mode"] == "recorded":
                        html, replay_ok = dyn_session.replay_login(
                            login_plan["start_url"], login_plan["recorded_steps"],
                            login_plan["username"], login_plan["password"],
                        )
                        if not replay_ok:
                            raise RuntimeError(
                                "Recorded login replay failed — the target's login page may have changed "
                                "since recording. Consider re-recording the flow."
                            )
                        session.cookies.update(dyn_session.cookies_for_requests())
                        login_used = "recorded"

            conn.execute("UPDATE scans SET login_used = ? WHERE id = ?", (login_used, scan_id))
            conn.commit()

            def progress_callback(**kwargs):
                scan_sessions.update_progress(scan_id, **kwargs)

            start_time = time.monotonic()
            result = crawl_site(
                target_url,
                reference_ip,
                session=session,
                page_html_fetcher=page_html_fetcher,
                progress_callback=progress_callback,
            )
            duration_seconds = int(time.monotonic() - start_time)

            for finding in result["findings"]:
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, found_on_page, link, category, code_snippet, evidence, element_location)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        finding["found_on_page"],
                        finding["link"],
                        finding["category"],
                        finding.get("code_snippet"),
                        finding.get("evidence"),
                        finding.get("element_location"),
                    ),
                )

            conn.execute(
                """UPDATE scans
                   SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                       pages_crawled = ?, total_links_checked = ?, duration_seconds = ?
                   WHERE id = ?""",
                (result["pages_crawled"], result["total_links_checked"], duration_seconds, scan_id),
            )
            conn.commit()
            scan_sessions.finish_progress(scan_id, "completed")

        except Exception as e:
            conn.execute(
                "UPDATE scans SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (scan_id,),
            )
            conn.commit()
            scan_sessions.finish_progress(scan_id, "failed", error=str(e))
    finally:
        conn.close()
        if dyn_session is not None:
            dyn_session.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan/start", response_model=ScanStartResponse)
def start_scan(payload: ScanStartRequest):
    if payload.site_type not in ("static", "dynamic"):
        raise HTTPException(status_code=400, detail="site_type must be 'static' or 'dynamic'.")

    if payload.login is not None and payload.login.mode == "recorded" and payload.site_type != "dynamic":
        raise HTTPException(
            status_code=400,
            detail="login mode 'recorded' requires site_type='dynamic' (replay uses the Tier 2 browser engine).",
        )

    reference_ip = extract_reference_ip(payload.target_url)
    if not reference_ip:
        raise HTTPException(status_code=400, detail="Could not determine a reference IP from target_url.")

    # Cheap, network-free validation only — raises HTTPException(400) for
    # anything wrong with the request itself. Anything that actually talks
    # to the target happens later, in the background thread.
    login_plan = _resolve_login_plan(payload, reference_ip)

    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO scans (target_url, target_ip, site_type, login_used, status)
               VALUES (?, ?, ?, 'none', 'running')""",
            (payload.target_url, reference_ip, payload.site_type),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    finally:
        conn.close()

    scan_sessions.start_progress(scan_id)

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(scan_id, payload.target_url, payload.site_type, reference_ip, login_plan),
        daemon=True,
    )
    thread.start()

    return ScanStartResponse(scan_id=scan_id)


@app.get("/api/scan/{scan_id}/progress")
def stream_scan_progress(scan_id: int):
    """
    SSE stream of live progress, per API_SPEC.md. Samples app.scan_sessions
    once per SSE_POLL_INTERVAL_SECONDS and pushes a JSON event each time,
    ending with a final event carrying status "completed" or "failed".

    If scan_id isn't in the in-memory registry (already finished and
    dropped, or the process restarted), falls back to the scans table so a
    late-connecting or reconnecting client still gets a sensible final
    event instead of nothing.
    """

    def event_stream():
        while True:
            snapshot = scan_sessions.get_progress(scan_id)

            if snapshot is None:
                conn = get_connection()
                try:
                    row = conn.execute(
                        """SELECT status, pages_crawled, total_links_checked, duration_seconds
                           FROM scans WHERE id = ?""",
                        (scan_id,),
                    ).fetchone()
                finally:
                    conn.close()

                if row is None:
                    fallback_payload = {"status": "not_found"}
                else:
                    fallback_payload = {
                        "pages_crawled": row["pages_crawled"] or 0,
                        "links_checked": row["total_links_checked"] or 0,
                        "elapsed_seconds": row["duration_seconds"] or 0,
                        "estimated_remaining_seconds": 0,
                        "status": row["status"],
                    }
                yield f"data: {json.dumps(fallback_payload)}\n\n"
                return

            payload = {
                "pages_crawled": snapshot["pages_crawled"],
                "links_checked": snapshot["links_checked"],
                "elapsed_seconds": round(snapshot["elapsed_seconds"]),
                "estimated_remaining_seconds": snapshot["estimated_remaining_seconds"],
                "status": snapshot["status"],
            }
            if snapshot["status"] == "failed" and snapshot.get("error"):
                payload["error"] = snapshot["error"]

            yield f"data: {json.dumps(payload)}\n\n"

            if snapshot["status"] in ("completed", "failed"):
                scan_sessions.drop_progress(scan_id)
                return

            time.sleep(SSE_POLL_INTERVAL_SECONDS)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/scan/{scan_id}/results")
def get_scan_results(scan_id: int):
    payload = _build_results_payload(scan_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return payload


_EXPORT_CONTENT_TYPES = {
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pdf": "application/pdf",
}


@app.get("/api/scan/{scan_id}/export")
def export_scan(scan_id: int, format: str):
    """
    Streams a generated export file for a completed (or in-progress) scan.
    `format` must be "xlsx" or "pdf" per API_SPEC.md. Building happens
    synchronously here — export.py's builders are pure and fast (no
    network calls), so there's no need for the background-thread pattern
    used for scans themselves.
    """
    if format not in _EXPORT_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="format must be 'xlsx' or 'pdf'.")

    payload = _build_results_payload(scan_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if format == "xlsx":
        file_bytes = build_xlsx_bytes(payload["scan"], payload["findings"])
    else:
        file_bytes = build_pdf_bytes(payload["scan"], payload["findings"])

    filename = f"scan_{scan_id}_findings.{format}"
    return Response(
        content=file_bytes,
        media_type=_EXPORT_CONTENT_TYPES[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/last")
def get_last_scan():
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="No scans yet.")
    return _build_results_payload(row["id"])


@app.post("/api/login/record/start", response_model=RecordStartResponse)
def start_login_recording(payload: RecordStartRequest):
    """
    Launches a headed Playwright window against payload.target_url for the
    user to manually click through their login flow. Returns immediately —
    the actual recording happens in a background thread and can take as
    long as the user needs; call /api/login/record/save once they've
    clicked "Finish Recording" in that window.
    """
    session_id = start_recording_session(payload.target_url)
    return RecordStartResponse(session_id=session_id)


@app.post("/api/login/record/save", response_model=RecordSaveResponse)
def save_login_recording(payload: RecordSaveRequest):
    session = get_session(payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="No recording session found for this session_id.")
    if session["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="Recording is still in progress — finish it in the browser window "
                   "(click 'Finish Recording') before saving.",
        )
    if session["status"] == "error":
        raise HTTPException(status_code=500, detail=f"Recording session failed: {session['error']}")

    save_recorded_login_config(payload.target_ip, session["steps"], login_url=session["target_url"])
    pop_session(payload.session_id)
    return RecordSaveResponse(saved=True)


@app.get("/api/login-config", response_model=LoginConfigResponse)
def check_login_config(target_ip: str):
    config = get_login_config(target_ip)
    if config is None:
        return LoginConfigResponse(exists=False)
    return LoginConfigResponse(exists=True, mode=config["mode"])


# ---------------------------------------------------------------------------
# Frontend (Step 9) — served from the same process so the VM only needs to
# run one command. Resolved as an absolute path from this file's location
# rather than a path relative to the working directory, so it works
# whether uvicorn is launched from backend/ or elsewhere. Mounted last so
# it never shadows an /api/* route registered above.
# ---------------------------------------------------------------------------

_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")