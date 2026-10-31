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
  - "recorded": replays a previously-recorded click/fill flow (see
    login_recorder.py / login_config_store.py). Requires having already
    recorded one for this target via /api/login/record/start + /save.
    (Auto-fill login was removed — recorded-flow login is more robust
    and accurate against real login forms, so it's the only mode now.)

Run from backend/ with the venv active:
    uvicorn app.main:app --reload
"""

import json
import logging
import logging.handlers
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import scan_sessions
from app import screenshots as screenshots_mod
from app.config import MAX_MID_CRAWL_RELOGINS, MAX_PAGES_PER_SCAN, extract_reference_host, resolve_scan_options
from app.crawler import _normalize_url, crawl_site
from app.db import get_connection, init_db
from app.export import (
    COMMENT_COLUMN_HEADERS,
    LINK_COLUMN_HEADERS,
    apply_unique,
    build_docx_bytes,
    build_pdf_bytes,
    build_xlsx_bytes,
    parse_column_param,
)
from app.login_config_store import get_login_config, save_logout_config, save_recorded_login_config
from app.login_record_sessions import finish_recording_session, get_flow, get_session, pop_flow, pop_session, start_flow_session, start_logout_only_session, start_recording_session
from app.renderer import DynamicSession

# ---------------------------------------------------------------------------
# Logging — writes to console (visible in the backend terminal window) AND
# to a rotating log file (link_audit.log, 5 MB per file, 3 backups kept).
# All sub-modules use getLogger(__name__) so their records flow here too.
# ---------------------------------------------------------------------------
_LOG_FILE = Path(__file__).resolve().parent.parent / "link_audit.log"

_file_handler = logging.handlers.RotatingFileHandler(
    str(_LOG_FILE),
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding="utf-8",
)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)-8s] %(name)s: %(message)s")
)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)-8s] %(name)s: %(message)s")
)

logging.basicConfig(level=logging.INFO, handlers=[_console_handler, _file_handler])
logger = logging.getLogger("link_audit.main")

app = FastAPI(title="Link & Navigation Audit Tool")

# Poll interval for the SSE progress stream. crawl_site's progress_callback
# fires once per page, which can be much faster or slower than this — the
# stream just samples whatever scan_sessions has at each tick, it doesn't
# need to fire in lockstep with page completions.
SSE_POLL_INTERVAL_SECONDS = 1.0


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("=== Link & Navigation Audit Tool started. Log file: %s ===", _LOG_FILE)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class LoginConfig(BaseModel):
    mode: str  # "recorded" — the only login mode (auto-fill login was removed)
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    extra_fields: Optional[Dict[str, str]] = None
    captcha_answer: Optional[str] = None  # scan-time override for the dedicated captcha input


class ScanOptions(BaseModel):
    """Per-scan overrides from the settings popover (Feature C). All
    optional; absent/null entries fall back to config defaults.
    Validated by config.resolve_scan_options (400 on violation)."""
    max_pages: Optional[int] = None
    max_depth: Optional[int] = None
    timeout_seconds: Optional[float] = None
    delay_seconds: Optional[float] = None
    headless: Optional[bool] = None  # dynamic scan rendering only; recording stays headed
    excluded_domains: Optional[List[str]] = None
    only_on_ui: bool = False  # dynamic only: broken rows gated to visible UI links + uncapped broken/inactive shots


class ScanStartRequest(BaseModel):
    target_url: str
    site_type: str  # "static" | "dynamic"
    login: Optional[LoginConfig] = None
    options: Optional[ScanOptions] = None


class ScanStartResponse(BaseModel):
    scan_id: int


class RecordStartRequest(BaseModel):
    target_url: str


class RecordStartResponse(BaseModel):
    session_id: str


class RecordSaveRequest(BaseModel):
    session_id: str
    target_ip: str
    captcha_answer: Optional[str] = None  # fixed captcha value for this target, if its login flow has one


class RecordSaveResponse(BaseModel):
    saved: bool


class LoginConfigResponse(BaseModel):
    exists: bool
    mode: Optional[str] = None
    has_captcha: bool = False     # True if the saved recording includes a legacy captcha step
    has_logout_url: bool = False  # True if a logout URL is configured for this target
    has_logout_steps: bool = False  # True if a recorded logout flow is configured
    logout_url: Optional[str] = None  # the saved logout URL itself (prefilled, editable)
    captcha_default: Optional[str] = None  # prefill for the dedicated captcha input (saved answer, else recorded code)
    extra_fields: List[Dict[str, Any]] = []  # Extra input fields detected in the recorded flow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FINDING_CATEGORY_KEYS = ("broken", "inactive", "ip_based", "internet", "data_uri")
COMMENT_CATEGORY_KEYS = (
    "commented_link",
    "internal_css",
    "inline_css",
    "internal_js",
    "inline_js",
)
ALL_CATEGORY_KEYS = FINDING_CATEGORY_KEYS + COMMENT_CATEGORY_KEYS

# Per-category severity. Links: internet (reaches outside the private
# network — the whole point of this tool per BUILD_PLAN.md) is the most
# consequential category, so HIGH; broken and data_uri (malformed embedded data)
# are MEDIUM; inactive (a "#" placeholder — a known no-op, not a mistake) and
# ip_based (a working link, just to a different VM — informational, not
# a defect on this site) are both LOW.
#
# Commented Code has no live status to weigh, so this is a judgment call
# on information-exposure risk rather than user-facing breakage:
# commented_link is a full leftover page reference (a concrete path an
# attacker on the network could try) so it's ranked HIGH, same tier as
# Internet; the *_js categories can reveal endpoint/logic
# details and are ranked MEDIUM; the *_css categories are
# purely cosmetic (asset paths, not logic) and are ranked LOW.
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
SEVERITY_MAP = {
    "internet": "high",
    "broken": "medium",
    "data_uri": "medium",
    "inactive": "low",
    "ip_based": "low",
    "commented_link": "high",
    "internal_js": "medium",
    "inline_js": "medium",
    "internal_css": "low",
    "inline_css": "low",
}


def _severity_for(category_string: str) -> str:
    """A finding's category can be comma-combined (e.g. 'internet,broken'
    on a Links row — see classifier.py); this takes the highest-severity
    tag present. Defaults to 'low' for any unrecognized/empty category
    rather than raising, since severity is a display concern that
    shouldn't be able to break the results payload."""
    best = None
    best_rank = 0
    for tag in (category_string or "").split(","):
        sev = SEVERITY_MAP.get(tag.strip())
        if sev and SEVERITY_RANK[sev] > best_rank:
            best = sev
            best_rank = SEVERITY_RANK[sev]
    return best or "low"


def _row_to_scan_dict(row) -> dict:
    return {
        "id": row["id"],
        "target_url": row["target_url"],
        "target_ip": row["target_ip"],
        "site_type": row["site_type"],
        "login_used": row["login_used"],
        "status": row["status"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "pages_crawled": row["pages_crawled"],
        "total_links_checked": row["total_links_checked"],
        "duration_seconds": row["duration_seconds"],
    }


def _summarize(findings: list) -> dict:
    summary = {key: 0 for key in ALL_CATEGORY_KEYS}
    for finding in findings:
        for category in finding["category"].split(","):
            if category in summary:
                summary[category] += 1
    return summary


def _build_results_payload(scan_id: int):
    """
    Findings are split into two result-section buckets here, at the API
    layer, rather than in the frontend: "findings" (the Links tab — every
    live, status-checked URL: broken/inactive/ip_based/internet/data_uri,
    whether embedded in HTML or inside a same-host .css/.js file) and
    "commented_findings" (the Code Findings tab — the five
    COMMENT_CATEGORY_KEYS entries: commented_link plus internal/inline CSS/JS
    presence, informational only, no status check). Same underlying findings
    table/rows either way — this is just how the payload groups them for
    display, and lets the frontend offer per-category filtering within
    each tab independently.
    """
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

    all_findings = [dict(row) for row in finding_rows]
    for f in all_findings:
        f["severity"] = _severity_for(f["category"])
    commented_findings = [
        f for f in all_findings if any(c in COMMENT_CATEGORY_KEYS for c in f["category"].split(","))
    ]
    findings = [
        f for f in all_findings if not any(c in COMMENT_CATEGORY_KEYS for c in f["category"].split(","))
    ]

    return {
        "scan": _row_to_scan_dict(scan_row),
        "summary": _summarize(all_findings),
        "findings": findings,
        "commented_findings": commented_findings,
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
            "extra_fields": payload.login.extra_fields,
            # Scan-time captcha input overrides the saved answer when given;
            # blank falls back to the saved/recorded value via replay.
            "captcha_answer": payload.login.captcha_answer or saved_config.get("captcha_answer"),
            # Logout fields — either or both may be None if not configured.
            "logout_url": saved_config.get("logout_url"),
            "logout_steps": saved_config.get("logout_steps"),
            # Page the logout steps were recorded on (the authed home) —
            # replay must return THERE before stepping, not to the scan
            # target (frequently the bare login form). Falls back to the
            # target when absent (pre-fix recordings).
            "logout_start_url": saved_config.get("logout_start_url"),
        }

    raise HTTPException(status_code=400, detail=f"Unknown login mode: {payload.login.mode!r}")


def _run_scan_worker(scan_id: int, target_url: str, site_type: str, reference_ip: str,
                      login_plan: Optional[Dict[str, Any]], scan_options: Optional[Dict[str, Any]] = None) -> None:
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
    logger.info("[scan:%d] Starting — target=%s site_type=%s", scan_id, target_url, site_type)

    session = requests.Session()
    session.verify = False  # target VMs use self-signed certs; disable SSL verification
    page_html_fetcher = None
    dyn_session = None
    login_used = "none"
    conn = get_connection()
    stop_event = scan_sessions.get_stop_event(scan_id) or threading.Event()
    # Feature C: snapshot for this scan only — a mid-scan settings edit
    # in the UI never disturbs a running crawl.
    scan_options = resolve_scan_options(scan_options)
    # "Only on UI" (dynamic scans only): broken findings are kept only for
    # URLs a visible <a href> points at on the page they were found on, and
    # broken/inactive proof shots run uncapped. Static passes are untouched.
    only_on_ui = bool(scan_options.get("only_on_ui")) and site_type == "dynamic"
    if only_on_ui:
        logger.info("[scan:%d] Only on UI enabled — broken rows gate to visible anchors, "
                    "broken/inactive shots uncapped", scan_id)
    # page_url → set of visible anchor hrefs on that rendered page. Filled by
    # the dynamic fetch wrapper; consulted by the crawler's gate (and rebuilt
    # naturally when phase 2 re-renders the same page authenticated).
    ui_visibility: Dict[str, set] = {}

    try:
        try:
            pre_login_findings: List[Dict[str, Any]] = []
            pre_login_links_checked = 0
            pre_login_pages_crawled = 0

            def progress_callback(**kwargs):
                scan_sessions.update_progress(scan_id, **kwargs)
                if kwargs.get("pages_crawled", 0) % 10 == 0 and kwargs.get("pages_crawled", 0) > 0:
                    logger.info(
                        "[scan:%d] Progress — pages_crawled=%d links_checked=%d frontier=%d",
                        scan_id,
                        kwargs.get("pages_crawled", 0),
                        kwargs.get("links_checked", 0),
                        kwargs.get("frontier_size", 0),
                    )

            # Static-safe defaults: no browser, so no sync/verdict/capture.
            # Dynamic branch overrides all three below.
            def _make_syncing(fetcher):
                return fetcher

            _browser_verdict = None
            _capture_drainer = None

            if site_type == "dynamic":
                logger.info("[scan:%d] Launching Playwright DynamicSession", scan_id)
                dyn_session = DynamicSession().start(headless=scan_options["headless"])
                page_html_fetcher = dyn_session.render

                def _sync_cookies():
                    try:
                        session.cookies.update(dyn_session.cookies_for_requests())
                    except Exception:
                        pass

                def _make_syncing(fetcher):
                    def _wrapper(page_url):
                        res = fetcher(page_url)
                        _sync_cookies()
                        if only_on_ui:
                            # Snapshot the rendered page's visible anchor URLs
                            # alongside the HTML — the crawler's Only-on-UI
                            # gate keys broken rows on this set. Best-effort:
                            # a probe failure recorded as an empty set just
                            # suppresses broken rows for that page.
                            try:
                                anchors = dyn_session.last_visible_anchors
                            except Exception:
                                anchors = []
                            try:
                                ui_visibility[page_url] = set(anchors or [])
                            except Exception:
                                pass
                        return res
                    return _wrapper

                def _browser_verdict(url: str, found_on: str):
                    """Live-session arbitration for residual same-host 400s.

                    Returns True (clean), False (confirmed broken), None
                    (ambiguous — keep original). Never raises. Never navigates
                    off-host / logout / excluded; redirects (incl. landing on
                    a login page) keep the original verdict to avoid
                    false-clearing dead links.
                    """
                    try:
                        from urllib.parse import urlparse as _up
                        from app.config import classify_host as _ch, is_logout_url as _lo, is_excluded_domain as _ex
                        h = _up(url).hostname or ""
                        if _ch(h, reference_ip) != "same":
                            return None
                        if _lo(url):
                            return None
                        if _ex(h, reference_ip, frozenset((scan_options.get("excluded_domains") or ()))):
                            return None
                        status, final_url = dyn_session.verdict_navigate(url)
                        if status is None:
                            return None
                        if status < 400:
                            return True
                        if status in (400, 401, 403, 404):
                            return False
                        return None
                    except Exception:
                        return None

                def _capture_drainer():
                    try:
                        return dyn_session.drain_captures()
                    except Exception:
                        return []

                if login_plan is not None:
                    # Fix 3: full unauthenticated crawl BEFORE login replay runs.
                    # The old single-page render of target_url missed every other
                    # unauthenticated page (e.g. a public landing page linking to
                    # /about when the post-login redirect lands on /dashboard).
                    # The browser context is still clean here (no cookies), and
                    # `session` has no auth cookies yet, so this whole phase is
                    # genuinely unauthenticated.
                    logger.info("[scan:%d] Phase 1: full unauthenticated crawl of %s", scan_id, target_url)
                    unauth_result = crawl_site(
                        target_url,
                        reference_ip,
                        max_pages=scan_options["max_pages"],
                        max_crawl_depth=scan_options["max_depth"],
                        session=session,
                        page_html_fetcher=_make_syncing(page_html_fetcher),
                        progress_callback=progress_callback,
                        stop_event=stop_event,
                        timeout=scan_options["timeout_seconds"],
                        delay=scan_options["delay_seconds"],
                        excluded_domains=scan_options["excluded_domains"],
                        browser_verdict=_browser_verdict,
                        browser_capture_drainer=_capture_drainer,
                        only_on_ui=only_on_ui,
                        ui_visibility=ui_visibility,
                    )
                    pre_login_findings = unauth_result["findings"]
                    pre_login_links_checked = unauth_result["total_links_checked"]
                    pre_login_pages_crawled = unauth_result["pages_crawled"]
                    logger.info(
                        "[scan:%d] Phase 1 finished: pages=%d links=%d findings=%d",
                        scan_id,
                        pre_login_pages_crawled,
                        pre_login_links_checked,
                        len(pre_login_findings),
                    )

                    if stop_event.is_set():
                        # Stopped during phase 1 — skip the login replay (no
                        # point authenticating a scan that's already ending)
                        # and phase 2; phase-1 partials are kept below.
                        logger.info("[scan:%d] Stop requested during phase 1 — skipping login and phase 2", scan_id)
                        result = {
                            "pages_crawled": 0,
                            "total_links_checked": 0,
                            "total_commented_found": 0,
                            "findings": [],
                            "visited_pages": [],
                            "stopped": True,
                        }
                    elif login_plan["mode"] == "recorded":
                        logger.info(
                            "[scan:%d] Replaying recorded login against %s",
                            scan_id, login_plan["start_url"],
                        )
                        html, replay_ok, login_form_url, replay_reason = dyn_session.replay_login(
                            login_plan["start_url"], login_plan["recorded_steps"],
                            login_plan["username"], login_plan["password"],
                            captcha_answer=login_plan.get("captcha_answer"),
                            extra_fields=login_plan.get("extra_fields"),
                        )
                        if not replay_ok:
                            detail = f" ({replay_reason})" if replay_reason else ""
                            raise RuntimeError(
                                f"Recorded login replay failed{detail} — the target's login page may have "
                                "changed since recording. Consider re-recording the flow."
                            )
                        session.cookies.update(dyn_session.cookies_for_requests())
                        login_used = "recorded"
                        logger.info("[scan:%d] Login replay succeeded", scan_id)

                        # Mid-crawl re-login guard: if a later page fetch lands
                        # back on the login form (session killed mid-scan), replay
                        # the saved login, refresh the requests cookies, and retry
                        # the page once — at most MAX_MID_CRAWL_RELOGINS times per
                        # scan, then fail loudly instead of silently scanning the
                        # login form as if it were authenticated content.
                        relogins_used = 0
                        base_fetcher = page_html_fetcher

                        def guarding_fetcher(page_url):
                            nonlocal relogins_used
                            result = base_fetcher(page_url)
                            html, success, final_url = (
                                result if len(result) == 3 else (result[0], result[1], None)
                            )
                            if not success or not html or not final_url:
                                return html, success, final_url
                            form_url = login_form_url or login_plan["start_url"]
                            if (_normalize_url(final_url) == _normalize_url(form_url)
                                    and _normalize_url(page_url) != _normalize_url(form_url)):
                                if relogins_used >= MAX_MID_CRAWL_RELOGINS:
                                    raise RuntimeError(
                                        "Session expired mid-scan and re-login budget "
                                        f"({MAX_MID_CRAWL_RELOGINS}) is exhausted — aborting "
                                        "instead of scanning the login page as content."
                                    )
                                relogins_used += 1
                                logger.warning(
                                    "[scan:%d] Landed on login page at %s (re-login %d/%d) — replaying",
                                    scan_id, page_url, relogins_used, MAX_MID_CRAWL_RELOGINS,
                                )
                                _, ok, _, relog_reason = dyn_session.replay_login(
                                    login_plan["start_url"], login_plan["recorded_steps"],
                                    login_plan["username"], login_plan["password"],
                                    captcha_answer=login_plan.get("captcha_answer"),
                                    extra_fields=login_plan.get("extra_fields"),
                                )
                                if not ok:
                                    detail = f" ({relog_reason})" if relog_reason else ""
                                    raise RuntimeError(
                                        "Session expired mid-scan and re-login replay failed"
                                        f"{detail} — the target's login page may have changed "
                                        "since recording."
                                    )
                                session.cookies.update(dyn_session.cookies_for_requests())
                                result = base_fetcher(page_url)
                                html, success, final_url = (
                                    result if len(result) == 3 else (result[0], result[1], None)
                                )
                                if success and html and final_url and (
                                        _normalize_url(final_url) == _normalize_url(form_url)
                                        and _normalize_url(page_url) != _normalize_url(form_url)):
                                    raise RuntimeError(
                                        "Re-login succeeded but the page still serves the login "
                                        "form — aborting instead of scanning it as content."
                                    )
                            return html, success, final_url

                        page_html_fetcher = _make_syncing(guarding_fetcher)

            conn.execute("UPDATE scans SET login_used = ? WHERE id = ?", (login_used, scan_id))
            conn.commit()

            # Phase 2 (or the only phase when no login): authenticated crawl.
            # Offsets keep the SSE progress line monotonic across phases, and
            # the remaining page budget keeps the MAX_PAGES_PER_SCAN safety cap
            # applying to the scan as a whole rather than per phase.
            phase2_pages_budget = max(0, scan_options["max_pages"] - pre_login_pages_crawled)

            def phase2_progress_callback(**kwargs):
                progress_callback(
                    pages_crawled=pre_login_pages_crawled + kwargs.get("pages_crawled", 0),
                    links_checked=pre_login_links_checked + kwargs.get("links_checked", 0),
                    frontier_size=kwargs.get("frontier_size", 0),
                )

            start_time = time.monotonic()
            _phase2_fetcher = page_html_fetcher if login_plan is not None else _make_syncing(page_html_fetcher)
            # When login was used, page_html_fetcher is already a syncing
            # guarding fetcher; otherwise wrap the plain render now so the
            # no-login dynamic jar still rides the browser session.
            result = crawl_site(
                target_url,
                reference_ip,
                max_pages=phase2_pages_budget,
                max_crawl_depth=scan_options["max_depth"],
                session=session,
                page_html_fetcher=_phase2_fetcher,
                progress_callback=phase2_progress_callback,
                stop_event=stop_event,
                timeout=scan_options["timeout_seconds"],
                delay=scan_options["delay_seconds"],
                excluded_domains=scan_options["excluded_domains"],
                browser_verdict=_browser_verdict,
                browser_capture_drainer=_capture_drainer,
                only_on_ui=only_on_ui,
                ui_visibility=ui_visibility,
            )
            duration_seconds = int(time.monotonic() - start_time)

            total_findings = pre_login_findings + result["findings"]
            total_pages = result["pages_crawled"] + pre_login_pages_crawled
            total_links = result["total_links_checked"] + pre_login_links_checked

            for finding in total_findings:
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

            # Counts are durable now, so the results table can render
            # mid-stream (see stream_scan_progress): pages/links land here,
            # status/completed_at stay 'running' until teardown finishes.
            conn.execute(
                """UPDATE scans
                   SET pages_crawled = ?, total_links_checked = ?
                   WHERE id = ?""",
                (total_pages, total_links, scan_id),
            )
            conn.commit()

            # Screenshots feature (two-stage): findings are saved, proof
            # shots capture next with the browser still open, and the
            # existing logout in `finally` runs last as always. Stop-aware
            # between shots; failures degrade to partial, never fail this.
            shot_targets = screenshots_mod.select_shot_targets(
                total_findings, uncapped_broken_inactive=only_on_ui)
            if stop_event.is_set() or not shot_targets:
                scan_sessions.set_screenshots_state(
                    scan_id, screenshots_mod.SHOT_STATE_STOPPED if shot_targets
                    else screenshots_mod.SHOT_STATE_NONE)
            else:
                screenshots_mod.STORE.create(scan_id, shot_targets)
                scan_sessions.set_screenshots_state(scan_id, screenshots_mod.SHOT_STATE_CAPTURING)
                shot_page = dyn_session.page if dyn_session is not None else None
                shot_browser = None
                if shot_page is None:
                    # Static scan: no browser yet — launch headless purely
                    # for shots (nothing for a human to watch).
                    from app.renderer import DynamicSession as ShotSession
                    try:
                        shot_session = ShotSession().start(headless=True)
                        shot_browser = shot_session
                        shot_page = shot_session.page
                    except Exception as exc:
                        logger.warning("[scan:%d] screenshot browser unavailable — %s: %s",
                                       scan_id, type(exc).__name__, exc)
                        shot_page = None
                if shot_page is None:
                    scan_sessions.set_screenshots_state(scan_id, screenshots_mod.SHOT_STATE_FAILED)
                    screenshots_mod.STORE.finish(scan_id, screenshots_mod.SHOT_STATE_FAILED)
                else:
                    try:
                        final_state = screenshots_mod.run_capture_phase(
                            shot_page, scan_id, shot_targets, screenshots_mod.STORE,
                            stop_event, uncapped_broken_inactive=only_on_ui)
                    finally:
                        if shot_browser is not None:
                            try:
                                shot_browser.close()
                            except Exception:
                                pass
                    scan_sessions.set_screenshots_state(scan_id, final_state)

            stopped = stop_event.is_set() or result.get("stopped", False)
            status = "stopped" if stopped else "completed"
            conn.execute(
                """UPDATE scans
                   SET status = ?, completed_at = CURRENT_TIMESTAMP,
                       pages_crawled = ?, total_links_checked = ?, duration_seconds = ?
                   WHERE id = ?""",
                (status, total_pages, total_links, duration_seconds, scan_id),
            )
            conn.commit()
            scan_sessions.finish_progress(scan_id, status)
            logger.info(
                "[scan:%d] %s — pages=%d links=%d findings=%d duration=%ds",
                scan_id,
                "Stopped" if stopped else "Completed",
                total_pages,
                total_links,
                len(total_findings),
                duration_seconds,
            )

        except Exception as e:
            logger.error(
                "[scan:%d] FAILED — %s\n%s",
                scan_id, e, traceback.format_exc(),
            )
            try:
                # A crash between store creation and terminal state would
                # otherwise leave the gallery polling 'capturing' forever.
                screenshots_mod.STORE.finish(scan_id, screenshots_mod.SHOT_STATE_FAILED)
            except Exception:
                pass
            conn.execute(
                "UPDATE scans SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (scan_id,),
            )
            conn.commit()
            scan_sessions.finish_progress(scan_id, "failed", error=str(e))
    finally:
        conn.close()
        if dyn_session is not None:
            # Logout before closing — even if the crawl failed, so the
            # server-side session doesn't stay locked and block the next scan.
            if login_plan is not None:
                logout_url = login_plan.get("logout_url")
                logout_steps = login_plan.get("logout_steps")
                if logout_url or logout_steps:
                    logger.info("[scan:%d] Attempting logout before close", scan_id)
                    dyn_session.replay_logout(
                        logout_url=logout_url,
                        logout_steps=logout_steps,
                        # Recordings made before the logout-start page was
                        # stored fall back to the scan target (old behavior).
                        start_url=(login_plan.get("logout_start_url") or target_url),
                    )
            logger.info("[scan:%d] Closing DynamicSession", scan_id)
            dyn_session.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/settings/defaults")
def get_settings_defaults():
    """Effective defaults + bounds for the settings popover (Feature C).
    Read-only; the dialog refetches on open so values never drift from
    backend constants. Nothing is stored — refresh resets the dialog."""
    from app.config import scan_options_defaults
    return scan_options_defaults()


@app.post("/api/scan/start", response_model=ScanStartResponse)
def start_scan(payload: ScanStartRequest):
    if payload.site_type not in ("static", "dynamic"):
        raise HTTPException(status_code=400, detail="site_type must be 'static' or 'dynamic'.")

    if payload.login is not None and payload.login.mode == "recorded" and payload.site_type != "dynamic":
        raise HTTPException(
            status_code=400,
            detail="login mode 'recorded' requires site_type='dynamic' (replay uses the Tier 2 browser engine).",
        )

    reference_host = extract_reference_host(payload.target_url)
    if not reference_host:
        raise HTTPException(status_code=400, detail="Could not determine a reference host from target_url.")

    # Cheap, network-free validation only — raises HTTPException(400) for
    # anything wrong with the request itself. Anything that actually talks
    # to the target happens later, in the background thread.
    login_plan = _resolve_login_plan(payload, reference_host)
    try:
        raw_options = None
        if payload.options is not None:
            raw_options = {
                key: getattr(payload.options, key, None)
                for key in ("max_pages", "max_depth", "timeout_seconds",
                            "delay_seconds", "headless", "excluded_domains", "only_on_ui")
            }
        scan_options = resolve_scan_options(raw_options)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO scans (target_url, target_ip, site_type, login_used, status)
               VALUES (?, ?, ?, 'none', 'running')""",
            (payload.target_url, reference_host, payload.site_type),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    finally:
        conn.close()

    scan_sessions.start_progress(scan_id)

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(scan_id, payload.target_url, payload.site_type, reference_host, login_plan, scan_options),
        daemon=True,
    )
    thread.start()

    return ScanStartResponse(scan_id=scan_id)


@app.get("/api/scan/{scan_id}/progress")
def stream_scan_progress(scan_id: int):
    """
    SSE stream of live progress, per API_SPEC.md. Samples app.scan_sessions
    once per SSE_POLL_INTERVAL_SECONDS and pushes a JSON event each time,
    ending with a final event carrying status "completed", "failed", or "stopped".

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
                "screenshots": snapshot.get("screenshots"),
            }
            if snapshot["status"] == "failed" and snapshot.get("error"):
                payload["error"] = snapshot["error"]

            yield f"data: {json.dumps(payload)}\n\n"

            if snapshot["status"] in ("completed", "failed", "stopped"):
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
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@app.get("/api/scan/{scan_id}/screenshots")
def get_scan_screenshots(scan_id: int):
    """Proof-screenshot gallery metadata (screenshots feature). 404 when
    the scan has no shots (none taken, evicted, or server restarted)."""
    entry = screenshots_mod.STORE.get(scan_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="No screenshots available for this scan.")
    return {"scan_id": scan_id, "status": entry["status"],
            "targets": entry.get("targets", 0), "shots": entry["shots"]}


@app.get("/api/scan/{scan_id}/screenshots/{shot_id}")
def get_scan_screenshot_png(scan_id: int, shot_id: str):
    """One shot\u2019s PNG bytes for gallery thumbnails."""
    png = screenshots_mod.STORE.png(scan_id, shot_id)
    if png is None:
        raise HTTPException(status_code=404, detail="Screenshot no longer available.")
    return Response(content=png, media_type="image/png")


@app.get("/api/scan/{scan_id}/screenshots.zip")
def download_scan_screenshots(scan_id: int):
    """ZIP download (numbered PNGs + captions.json), built on the fly
    like the Excel/PDF export. 404 when nothing is stored."""
    data = screenshots_mod.build_screenshots_zip(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="No screenshots available for this scan.")
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_screenshots.zip"'},
    )


@app.get("/api/scan/{scan_id}/export")
def export_scan(
    scan_id: int,
    format: str,
    tabs: str = "both",
    tab: str = "links",
    category: Optional[str] = None,
    unique: bool = False,
    link_columns: Optional[str] = None,
    code_columns: Optional[str] = None,
):
    """
    Streams a generated export file for a completed (or in-progress) scan.
    Without view params this exports both tabs with all columns. View params
    mirror the frontend state: tabs="active" exports only tab ("links" or
    "commented"); category filters that tab; unique=1 collapses same-LINK
    rows (first occurrence kept, ×N occurrences marked); link_columns/
    code_columns are visible-column index lists ("0,1,4").
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

    if tabs not in ("active", "both"):
        raise HTTPException(status_code=400, detail="tabs must be 'active' or 'both'.")
    if tab not in ("links", "commented"):
        raise HTTPException(status_code=400, detail="tab must be 'links' or 'commented'.")
    include = ("links", "commented") if tabs == "both" else (tab,)

    findings = list(payload["findings"])
    commented = list(payload["commented_findings"])
    if tabs == "active" and category:
        # Multi-select (Feature B): comma-separated list, OR semantics —
        # same membership rule as the frontend badges; ignored for "both"
        # (a category from one tab is meaningless in the other). Unknown
        # tags match nothing, as with the old single value.
        selected = [c.strip() for c in category.split(",") if c.strip()]
        if tab == "links":
            findings = [f for f in findings if any(c in f["category"].split(",") for c in selected)]
        else:
            commented = [f for f in commented if any(c in f["category"].split(",") for c in selected)]
    if unique:
        if "links" in include:
            findings = apply_unique(findings)
        if "commented" in include:
            commented = apply_unique(commented)

    try:
        link_cols = parse_column_param(link_columns, len(LINK_COLUMN_HEADERS)) if "links" in include else None
        code_cols = parse_column_param(code_columns, len(COMMENT_COLUMN_HEADERS)) if "commented" in include else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Exports include each included bucket as its own section — see
    # own section — see export.py's module docstring for why they're
    # kept separate rather than merged into one table.
    if format == "xlsx":
        file_bytes = build_xlsx_bytes(
            payload["scan"], findings, commented,
            link_columns=link_cols, code_columns=code_cols, include_tabs=include,
        )
    else:
        # The Word/PDF exports embed proof screenshots as appendices —
        # pull this scan's shots (with PNG bytes) from the store.
        shot_rows = screenshots_mod.STORE.shots_with_bytes(scan_id)
        try:
            if format == "docx":
                file_bytes = build_docx_bytes(
                    payload["scan"], findings, commented,
                    link_columns=link_cols, code_columns=code_cols, include_tabs=include,
                    shots=shot_rows,
                )
            else:
                file_bytes = build_pdf_bytes(
                    payload["scan"], findings, commented,
                    link_columns=link_cols, code_columns=code_cols, include_tabs=include,
                    shots=shot_rows,
                )
        except ImportError as exc:
            # python-docx is an optional export dependency: never let a
            # missing package take the whole endpoint down.
            if format == "docx" and "docx" in str(exc).lower():
                raise HTTPException(
                    status_code=400,
                    detail="DOCX export needs the python-docx package on the server "
                           "(pip install python-docx). Excel/PDF exports are unaffected.",
                )
            raise

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


class StopScanResponse(BaseModel):
    stopped: bool
    status: str


@app.post("/api/scan/{scan_id}/stop", response_model=StopScanResponse)
def stop_scan(scan_id: int):
    """
    Requests cooperative stop of a running scan. The worker notices between
    crawled pages (an in-flight page still finishes first), runs normal
    teardown — logout replay for dynamic+login, browser close — keeps
    partial results, and finishes the scan as 'stopped'. Idempotent.
    Returns stopped=False with the durable status when the scan isn't
    running anymore; 404 when the scan doesn't exist at all.
    """
    if scan_sessions.request_stop(scan_id):
        return StopScanResponse(stopped=True, status="running")
    conn = get_connection()
    try:
        row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return StopScanResponse(stopped=False, status=row["status"])


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


class RecordFinishRequest(BaseModel):
    session_id: str


class RecordFinishResponse(BaseModel):
    finished: bool


@app.post("/api/login/record/finish", response_model=RecordFinishResponse)
def finish_recording(payload: RecordFinishRequest):
    """
    Signals the recording browser session (login or logout) to finish and close.
    Triggered from the tool's own UI rather than an in-page overlay button.
    """
    session = get_session(payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="No recording session found for this session_id.")
    if session["status"] == "running":
        finish_recording_session(payload.session_id)
    return RecordFinishResponse(finished=True)


@app.post("/api/login/record/save", response_model=RecordSaveResponse)
def save_login_recording(payload: RecordSaveRequest):
    session = get_session(payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="No recording session found for this session_id.")
    if session["status"] == "running":
        finish_recording_session(payload.session_id)
        for _ in range(40):
            time.sleep(0.1)
            session = get_session(payload.session_id)
            if session and session["status"] != "running":
                break
        if session and session["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="Recording is still finishing in the browser window — please try saving again in a moment.",
            )
    if session["status"] == "error":
        raise HTTPException(status_code=500, detail=f"Recording session failed: {session['error']}")

    save_recorded_login_config(
        payload.target_ip, session["steps"],
        login_url=session["target_url"],
        captcha_answer=payload.captcha_answer,
    )
    pop_session(payload.session_id)
    return RecordSaveResponse(saved=True)


@app.get("/api/login-config", response_model=LoginConfigResponse)
def check_login_config(target_ip: str):
    config = get_login_config(target_ip)
    if config is None:
        return LoginConfigResponse(exists=False)
    recorded = config["recorded_steps"] or []
    has_captcha = any(step.get("field_type") == "captcha" for step in recorded)
    # Dedicated captcha input prefill: explicit saved answer wins, else the
    # code captured at recording time. Captcha steps never surface as extra
    # inputs (single captcha field, no duplicates).
    captcha_default = config.get("captcha_answer")
    if captcha_default is None:
        for step in recorded:
            if step.get("field_type") == "captcha":
                captcha_default = step.get("value", "")
                break
    extra_fields = []
    for step in recorded:
        if step.get("field_type") == "extra":
            label = step.get("label") or step.get("placeholder") or step.get("name") or step.get("selector") or "Extra field"
            extra_fields.append({
                "selector": step.get("selector"),
                "name": step.get("name"),
                "placeholder": step.get("placeholder"),
                "label": label,
                "default_value": step.get("value", ""),
            })
    return LoginConfigResponse(
        exists=True,
        mode=config["mode"],
        has_captcha=has_captcha,
        has_logout_url=bool(config.get("logout_url")),
        has_logout_steps=bool(config.get("logout_steps")),
        logout_url=config.get("logout_url"),
        captcha_default=captcha_default,
        extra_fields=extra_fields,
    )


class LogoutUrlSaveRequest(BaseModel):
    target_ip: str
    logout_url: Optional[str] = None  # pass None or empty to clear the logout URL


class LogoutRecordSaveRequest(BaseModel):
    session_id: str
    target_ip: str


@app.post("/api/login/logout-config", response_model=RecordSaveResponse)
def save_logout_url_config(payload: LogoutUrlSaveRequest):
    """
    Saves (or clears) the logout URL for a target. Clears any existing
    recorded logout steps when a URL is provided, since only one logout
    mechanism is active at a time.

    Requires an existing login config for this target_ip (login flow must
    be recorded first before a logout can be configured).
    """
    config = get_login_config(payload.target_ip)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"No login config found for {payload.target_ip}. Record a login flow first.",
        )
    logout_url = (payload.logout_url or "").strip() or None
    save_logout_config(payload.target_ip, logout_url=logout_url, logout_steps=None)
    return RecordSaveResponse(saved=True)


@app.post("/api/login/logout-record/start", response_model=RecordStartResponse)
def start_logout_recording(payload: RecordStartRequest):
    """
    Launches a headed Playwright window against payload.target_url so the
    user can manually log in and then click through their logout flow. The
    recorded steps are saved as the target's logout_steps. Uses the same
    recording mechanism as the login flow recorder.
    """
    session_id = start_recording_session(payload.target_url)
    return RecordStartResponse(session_id=session_id)


@app.post("/api/login/logout-record/save", response_model=RecordSaveResponse)
def save_logout_recording(payload: LogoutRecordSaveRequest):
    """
    Saves the logout recording steps captured by the browser session
    started via /api/login/logout-record/start. Requires an existing login
    config for this target_ip.
    """
    session = get_session(payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="No recording session found for this session_id.")
    if session["status"] == "running":
        finish_recording_session(payload.session_id)
        for _ in range(40):
            time.sleep(0.1)
            session = get_session(payload.session_id)
            if session and session["status"] != "running":
                break
        if session and session["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="Recording is still finishing in the browser window — please try saving again in a moment.",
            )
    if session["status"] == "error":
        raise HTTPException(status_code=500, detail=f"Recording session failed: {session['error']}")

    config = get_login_config(payload.target_ip)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"No login config found for {payload.target_ip}. Record a login flow first.",
        )
    save_logout_config(payload.target_ip, logout_url=None, logout_steps=session["steps"])
    pop_session(payload.session_id)
    return RecordSaveResponse(saved=True)


# ---------------------------------------------------------------------------
# Phased login→logout flow (one shared Chromium window).
# Buttons: Start/Finish Login Record, Start/Finish Logout Record, Save Record.
# Finish Login freezes + saves login steps (window stays open); Finish Logout
# freezes + saves logout steps; Save finalizes (captcha + optional logout URL,
# with a visual navigate-to-URL check in the open window) and closes it.
# ---------------------------------------------------------------------------

class FlowStartRequest(BaseModel):
    target_url: str


class FlowStartResponse(BaseModel):
    flow_id: str


class FlowIdRequest(BaseModel):
    flow_id: str


class FlowFinishLoginRequest(BaseModel):
    flow_id: str
    target_ip: str


class FlowSaveRequest(BaseModel):
    flow_id: str
    target_ip: str
    captcha_answer: Optional[str] = None
    logout_url: Optional[str] = None


class FlowSaveResponse(BaseModel):
    saved: bool
    warning: Optional[str] = None


class FlowStatusResponse(BaseModel):
    alive: bool
    login_frozen: bool
    error: Optional[str] = None


def _flow_or_404(flow_id: str):
    flow = get_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="No recording flow found for this flow_id.")
    return flow


def _upsert_flow_login(
    target_ip: str, flow, captcha_answer: Optional[str] = None, preserve_captcha: bool = True
) -> None:
    """
    Persists the flow's frozen login slice. With preserve_captcha (Finish
    Login), a None captcha keeps any already-saved value so finishing never
    wipes it; Save passes preserve_captcha=False so a blank captcha clears,
    exactly like the standalone endpoint does today.
    """
    if preserve_captcha and captcha_answer is None:
        existing = get_login_config(target_ip)
        if existing is not None:
            captcha_answer = existing.get("captcha_answer")
    save_recorded_login_config(
        target_ip, flow.frozen_login_steps(),
        login_url=flow.target_url,
        captcha_answer=captcha_answer,
    )


@app.get("/api/login/flow/{flow_id}/status", response_model=FlowStatusResponse)
def flow_status(flow_id: str):
    """Liveness probe for the recording window (did it die instantly?)."""
    flow = _flow_or_404(flow_id)
    return FlowStatusResponse(alive=flow.is_alive, login_frozen=flow.login_frozen, error=flow.error)


@app.post("/api/login/flow/start", response_model=FlowStartResponse)
def start_login_flow(payload: FlowStartRequest):
    """Opens the shared headed window at target_url and starts login capture."""
    return FlowStartResponse(flow_id=start_flow_session(payload.target_url))


class FlowLogoutOnlyRequest(BaseModel):
    target_url: str
    username: str
    password: str


@app.post("/api/login/flow/start-logout-only", response_model=FlowStartResponse)
def start_logout_only_flow(payload: FlowLogoutOnlyRequest):
    """
    Standalone logout recording for a target with a SAVED login: opens the
    window, auto-replays the saved login with the given scan-form credentials,
    then captures logout clicks. Never writes login steps. Fails (after the
    window closes itself) when no login is saved or the replay fails.
    """
    if not (payload.username and payload.password):
        raise HTTPException(
            status_code=400,
            detail="Username and password are required to sign the recording window in.",
        )
    config = get_login_config(extract_reference_host(payload.target_url))
    if config is None or config["mode"] != "recorded" or not config["recorded_steps"]:
        raise HTTPException(
            status_code=404,
            detail="No recorded login flow found for this target. Record a login flow first.",
        )
    bundle = {
        "steps": config["recorded_steps"],
        "username": payload.username,
        "password": payload.password,
        "captcha_answer": config.get("captcha_answer"),
    }
    return FlowStartResponse(
        flow_id=start_logout_only_session(payload.target_url, bundle)
    )


@app.post("/api/login/flow/finish-login", response_model=RecordSaveResponse)
def finish_flow_login(payload: FlowFinishLoginRequest):
    """Freezes login steps, saves them now, window stays open and logged in."""
    flow = _flow_or_404(payload.flow_id)
    flow.finish_login()
    steps = flow.frozen_login_steps()
    if not steps:
        raise HTTPException(
            status_code=409,
            detail="No login actions were captured — perform the login in the browser window first.",
        )
    _upsert_flow_login(payload.target_ip, flow)
    return RecordSaveResponse(saved=True)


@app.post("/api/login/flow/rerecord-login", response_model=RecordSaveResponse)
def rerecord_flow_login(payload: FlowIdRequest):
    """
    Resets capture in the same window: cookies cleared, back to the logged-out
    target, so the user can log in again. Previously saved login steps are
    replaced on the next finish-login; saved logout steps are left alone.
    """
    flow = _flow_or_404(payload.flow_id)
    try:
        flow.request_rerecord()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=f"{exc} Start a new flow instead.")
    except TimeoutError:
        raise HTTPException(status_code=409, detail="Recording window did not respond — it may have been closed.")
    return RecordSaveResponse(saved=True)


@app.post("/api/login/flow/start-logout", response_model=RecordSaveResponse)
def start_flow_logout(payload: FlowIdRequest):
    """Begins logout capture in the same logged-in window. Requires login frozen."""
    flow = _flow_or_404(payload.flow_id)
    if not flow.login_frozen:
        raise HTTPException(status_code=409, detail="Finish the login recording first.")
    flow.begin_logout()
    return RecordSaveResponse(saved=True)


@app.post("/api/login/flow/finish-logout", response_model=RecordSaveResponse)
def finish_flow_logout(payload: FlowFinishLoginRequest):
    """Freezes logout steps and saves them now. Window stays open for Save."""
    flow = _flow_or_404(payload.flow_id)
    if not flow.finish_logout():
        raise HTTPException(status_code=409, detail="Logout recording was never started.")
    if not flow.frozen_logout_steps():
        raise HTTPException(
            status_code=409,
            detail="No logout actions were captured — perform the logout clicks in the browser window first.",
        )
    config = get_login_config(payload.target_ip)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"No login config found for {payload.target_ip}. Finish the login recording first.",
        )
    save_logout_config(
        payload.target_ip,
        logout_url=None,
        logout_steps=flow.frozen_logout_steps(),
        logout_start_url=flow.logout_start_url(),
    )
    return RecordSaveResponse(saved=True)


@app.post("/api/login/flow/save", response_model=FlowSaveResponse)
def save_login_flow(payload: FlowSaveRequest):
    """
    Finalizes the flow: optional logout URL is loaded in the open window as a
    visual check (warn-only on failure — still saved), captcha stored with the
    login config, then the window closes. A logout URL wins over recorded
    logout steps (same precedence as the standalone endpoints). In a
    standalone logout-only flow the saved login (and captcha) is never
    touched — only logout config is written.
    """
    flow = _flow_or_404(payload.flow_id)
    if flow.logout_only:
        if not flow.logout_finished:
            raise HTTPException(status_code=409, detail="Finish the logout recording first.")
    else:
        if not flow.login_frozen:
            raise HTTPException(status_code=409, detail="Finish the login recording first.")
    warnings: List[str] = []
    logout_url = (payload.logout_url or "").strip() or None
    if logout_url:
        navigated = False
        if flow.is_alive:
            try:
                navigated = flow.request_navigate(logout_url)
            except Exception:
                navigated = False
        if not navigated:
            warnings.append(f"Logout URL did not load in the recording window ({logout_url}); saved anyway.")
        if flow.logout_finished:
            warnings.append("Freshly recorded logout steps were discarded — a logout URL wins over recorded steps.")
        save_logout_config(payload.target_ip, logout_url=logout_url, logout_steps=None)
    elif flow.logout_finished:
        pass  # steps already saved by finish-logout; nothing more to do
    else:
        existing = get_login_config(payload.target_ip)
        if existing and existing.get("logout_url"):
            warnings.append("Logout URL field was empty — kept the saved logout URL.")
    if not flow.logout_only:
        _upsert_flow_login(payload.target_ip, flow, captcha_answer=payload.captcha_answer, preserve_captcha=False)
    flow.request_close()
    pop_flow(payload.flow_id)
    return FlowSaveResponse(saved=True, warning=" ".join(warnings) or None)


# ---------------------------------------------------------------------------
# Frontend (Step 9) — served from the same process so the VM only needs to
# run one command. Resolved as an absolute path from this file's location
# rather than a path relative to the working directory, so it works
# whether uvicorn is launched from backend/ or elsewhere. Mounted last so
# it never shadows an /api/* route registered above.
# ---------------------------------------------------------------------------

_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")