"""
Tier 2 (dynamic) engine — Playwright-based rendering and login.

Used only for (per ARCHITECTURE.md):
  1. Logging in (replaying a recorded flow — see replay_login())
  2. Rendering a page fully (JS executed) so links injected client-side are
     present in the DOM before Tier 1's extractor runs against the
     resulting HTML.

Broken-link checking and BFS orchestration stay in Tier 1 (requests-based) —
this module just hands rendered HTML back to the same extractor/classifier/
crawler used for Static scans. See crawler.py's `page_html_fetcher` param.
"""

import os
from typing import Any, Dict, List, Optional, Tuple

import logging
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from app.config import REQUEST_TIMEOUT_SECONDS
from app.login_replay import ReplayError, replay_login_steps, replay_logout_steps
from app.login_replay import _summarize_playwright_error

logger = logging.getLogger("link_audit.renderer")

# Rendering (navigation + JS execution) is slower than a plain HTTP GET,
# so this gets a more generous budget than Tier 1's REQUEST_TIMEOUT_SECONDS.
RENDER_TIMEOUT_MS = REQUEST_TIMEOUT_SECONDS * 1000 * 2

# Frames+shadow probe for the "Only on UI" broken-link gate (Phase A/B).
# Runs in the page context right after a render settles and drives TWO
# exclusions: an <a href> only survives as a broken finding when it is
# ACTUALLY visible in the rendered UI, and a frame/iframe src counts as
# visible when its frame box renders (a 404-ing frame src is a real,
# user-visible hole). Walks every OPEN shadow root (Playwright cannot see
# inside closed ones — a shown-but-closed shadow link stays hall unknown;
# closed-root content is also invisible to querySelectorAll by design).
# javascript: hrefs are skipped — they aren't navigable targets, and
# manual raw-value/inline-style checks run first for speed since they
# cover the common cases.
_VISIBLE_FRAME_JS = r"""
() => {
  const out = [];
  const isShown = (el) => {
    try {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
    } catch (e) { return false; }
    return true;
  };
  const push = (u) => {
    if (u && !u.startsWith('javascript:') && out.indexOf(u) === -1) out.push(u);
  };
  const visit = (root) => {
    for (const a of root.querySelectorAll('a[href]')) {
      if (!isShown(a)) continue;
      if (a.getClientRects().length === 0) continue;
      push(a.href || '');
    }
    for (const f of root.querySelectorAll('iframe[src], frame[src]')) {
      if (!isShown(f)) continue;
      if (f.getClientRects().length === 0) continue;
      push(f.src || '');
    }
    // Descend into open shadow roots (composed tree — regular
    // querySelectorAll never crosses this boundary).
    for (const el of root.querySelectorAll('*')) {
      const sr = el.shadowRoot;
      if (sr) visit(sr);
    }
  };
  visit(document);
  return out;
}
"""

# Fallback for <this module's older behavior>: main-document-only probe.
# Kept for reference/testing parity; render() now runs the piercing probe
# in EVERY frame and merges, so a frameset's own document and each frame's
# anchors all contribute to the visible set.
_VISIBLE_ANCHORS_JS = _VISIBLE_FRAME_JS

# Bounded settle wait before the FIRST recorded step runs in replay_login().
# Sites routinely bounce themselves right after `load` — auth-key round
# trips, session checks, SSO hops — and replay used to start firing steps
# ~130ms after load, straight into that dance (real failure: goto() declared
# the page loaded, the first fill raced a redirect, everything died on a
# stale element). Pages that never go idle (long polling) proceed after the
# timeout with whatever has rendered, exactly like render()'s networkidle.
REPLAY_SETTLE_TIMEOUT_MS = 8000

# fetch()-POST logins (SPA-style) complete the HTTP request and only THEN
# `location.href` to the app home — a JS navigation that is NOT yet in
# flight when networkidle resolves. Reading the page back at that instant
# returns the still-open login form, so the success check can false-fail.
# After the post-step networkidle, watch briefly for the URL to leave the
# login form's URL; in-place logins (no redirect) simply fall through after
# this short timeout.
REPLAY_POST_NAV_WATCH_MS = 2500


def _url_base(url: str) -> str:
    """Query- and fragment-stripped path for landing comparisons."""
    base = (url or "").split("#", 1)[0].split("?", 1)[0]
    return base.rstrip("/")

# Shared browser-context options for every headed Chromium this tool opens
# (DynamicSession scans + LoginRecordingSession recorder).
# Fix 4: no_viewport=True lets the page viewport follow the OS window instead
# of Playwright's fixed 1280x720 emulation (which trips responsive breakpoints
# and ignores manual maximize — note viewport=None does NOT disable it, it
# just falls back to the default). device_scale_factor is deliberately left
# unset: Playwright rejects it alongside a null viewport, and unset means the
# page scales like a regular Chrome on the same machine.
BROWSER_CONTEXT_KWARGS = {
    "ignore_https_errors": True,
    "no_viewport": True,
}

# Phrases that indicate the login page rejected our attempt because another
# session for this account is already active on the target. Matched
# case-insensitively against the page's visible body text inside
# _login_succeeded(). Extend this list as real sites reveal their own wording.
SESSION_ALREADY_ACTIVE_MARKERS = [
    "already logged in",
    "already signed in",
    "session already active",
    "account is in use",
    "logged in elsewhere",
    "signed in on another",
    "maximum sessions",
    "concurrent session",
    "another session",
    "login from another",
    "you are already logged",
    "account already logged",
]


class DynamicSession:
    """
    Wraps one headless Chromium browser context for the duration of a
    dynamic scan. Reused across every page render so login cookies persist
    automatically — Playwright's BrowserContext carries cookies across
    navigations within itself.

    A single Page is created once in start() and reused for every
    navigation (login + every render() call) — pages are only opened and
    closed once per scan, not once per URL. Opening/closing a page per
    call was the cause of the browser window visibly closing and
    reopening on every single page of a crawl in headed (non-headless)
    mode: with only one page ever open, closing it after each call closed
    the whole OS window, and the next call had to spawn a new one.

    Usage:
        with DynamicSession() as dyn:
            dyn.replay_login(start_url, recorded_steps, username, password)
            html, ok = dyn.render(some_page_url)
            cookies = dyn.cookies_for_requests()  # hand off to a requests.Session
    """

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        # Visible-anchor snapshot of the most recent render() page: every
        # <a href> that passed a real visibility check (display != none,
        # visibility not hidden, non-empty client rects), as resolved
        # absolute hrefs. Feeds the "Only on UI" broken-link gate — empty
        # for failed renders. Refreshed at the START of every render().
        self._last_visible_anchors: list = []
        # Runtime request capture (off-host discovery for dynamic scans).
        # Bounded, best-effort: request/response taps record every http(s)
        # URL the browser actually fetches (XHR, fetch(), constructed
        # routes) — the extractor never sees these. Drained per-page by
        # the crawler; same-host entries are ignored there.
        self._req_captures: list = []
        self._resp_status: dict = {}
        self._capture_max = 5000

    def _capture_on_request(self, req) -> None:
        try:
            url = req.url or ""
            if not url.lower().startswith(("http://", "https://")):
                return
            if len(self._req_captures) >= self._capture_max:
                return
            try:
                trigger = self._page.url if self._page else ""
            except Exception:
                trigger = ""
            self._req_captures.append({"url": url, "found_on": trigger})
        except Exception:
            pass

    def _capture_on_response(self, resp) -> None:
        try:
            url = resp.url or ""
            if not url.lower().startswith(("http://", "https://")):
                return
            try:
                self._resp_status[url] = int(resp.status)
            except Exception:
                pass
        except Exception:
            pass

    def drain_captures(self) -> list:
        """Returns captured requests since the last drain, then clears.

        Each entry: {url, status|None, found_on}. Never raises.
        """
        try:
            out = []
            for entry in self._req_captures:
                url = entry.get("url") or ""
                out.append({
                    "url": url,
                    "status": self._resp_status.get(url),
                    "found_on": entry.get("found_on") or "",
                })
            self._req_captures = []
            # Bound status map growth: keep only recent URLs.
            if len(self._resp_status) > self._capture_max:
                keys = list(self._resp_status.keys())[-self._capture_max:]
                self._resp_status = {k: self._resp_status[k] for k in keys}
            return out
        except Exception:
            return []

    def verdict_navigate(self, url: str, timeout_ms: int = 15000):
        """Fast verdict navigation on the shared scan page.

        Returns (status|None, final_url|None). None status means ambiguous
        (connection failure, timeout) — caller must keep the original
        verdict. Uses domcontentloaded (no networkidle wait) so each
        residual check costs ~1s, not full render time.
        """
        try:
            resp = self._page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            try:
                final_url = self._page.url or url
            except Exception:
                final_url = url
            status = None
            try:
                status = int(resp.status) if resp is not None else None
            except Exception:
                status = None
            return status, final_url
        except Exception:
            return None, None

    def start(self, headless: bool = False) -> "DynamicSession":
        logger.info("DynamicSession.start() — launching %s Chromium", "headless" if headless else "headed")
        self._playwright = sync_playwright().start()
        # Optional launch channel override (LINK_AUDIT_PLAYWRIGHT_CHANNEL,
        # e.g. "chrome" on machines without the bundled Chromium build).
        # Absent env var → bundled Chromium, exactly as before.
        launch_kwargs: dict = {}
        channel = (os.environ.get("LINK_AUDIT_PLAYWRIGHT_CHANNEL") or "").strip()
        if channel:
            launch_kwargs["channel"] = channel
        self._browser = self._playwright.chromium.launch(headless=headless, args=["--start-maximized"], **launch_kwargs)
        self._context = self._browser.new_context(**BROWSER_CONTEXT_KWARGS)
        self._page = self._context.new_page()
        try:
            self._page.on("request", self._capture_on_request)
            self._page.on("response", self._capture_on_response)
        except Exception:
            pass
        logger.info("DynamicSession.start() — browser context ready (viewport follows window, scale locked 100%)")
        return self

    @property
    def page(self):
        """The shared scan page (reused for proof screenshots pre-logout)."""
        return self._page

    @property
    def last_visible_anchors(self) -> "List[str]":
        """Visible <a href>/frame-src URLs (absolute, all frames incl. open
        shadow trees) of the most recent render().
        Refreshed at the start of every render(); empty when navigation
        failed or the DOM probe didn't run."""
        return self._last_visible_anchors

    def close(self) -> None:
        if self._page:
            self._page.close()
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    def __enter__(self) -> "DynamicSession":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def render(self, url: str) -> Tuple[Optional[str], bool, Optional[str]]:
        """
        Loads `url` in the shared page (cookies from login carry over
        automatically) and returns (html, success, final_url). final_url is
        page.url after navigation (after redirects, e.g. /public -> /public/),
        so the caller can resolve relative links like the browser does.
        html is None and success is False if navigation failed outright.

        Also snapshots the page's visible <a href> URLs into
        `last_visible_anchors` (reset first, so a failed navigation never
        leaves the previous page's anchors behind).
        """
        self._last_visible_anchors = []
        try:
            self._page.goto(url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            try:
                self._page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass  # some pages never go fully idle (polling/websockets) — use what's loaded
            try:
                final_url = self._page.url or url
            except Exception:
                final_url = url
            # Visible-link probe for the Only-on-UI gate — run in EVERY
            # frame (main document first) and merged: a frameset page's
            # rules live in child documents, so single-document probes
            # used to see nothing (Phase A). Any per-frame failure is
            # skipped; total failure leaves the empty list set above.
            anchors: List[str] = []
            try:
                frames = list(self._page.frames)
            except Exception:
                frames = []
            for frame in frames:
                try:
                    got = frame.evaluate(_VISIBLE_ANCHORS_JS) or []
                except Exception as exc:
                    logger.debug(
                        "visible-link probe failed for %s (frame %s) — %s: %s",
                        url, getattr(frame, "url", "?"), type(exc).__name__, exc,
                    )
                    got = []
                for u in got:
                    if u and u not in anchors:
                        anchors.append(u)
            self._last_visible_anchors = anchors
            return self._page.content(), True, final_url
        except PlaywrightTimeoutError:
            logger.warning("render() timed out navigating to: %s", url)
            return None, False, None
        except Exception as exc:
            logger.error("render() failed for %s — %s: %s", url, type(exc).__name__, exc)
            return None, False, None

    def _login_succeeded(self, login_url: str) -> bool:
        """
        Best-effort check that a login attempt actually authenticated us,
        instead of just trusting that a password field existed and got
        submitted. Returns False (failure) if any of:
          - the page text contains a "session already active" marker phrase
            (site thinks the account is already logged in elsewhere — a
            false-positive pass would let the crawl proceed on an invalid
            session; see SESSION_ALREADY_ACTIVE_MARKERS above), OR
        Returns True (success) if any of:
          - the page navigated away from the login URL, or
          - the password field is no longer present (form replaced/gone), or
          - the context picked up at least one cookie during the attempt.
        False means the attempt should be treated as failed rather than
        letting the crawl proceed on an unauthenticated session.

        Frames A/B: the login form (and its rejection text) may live in ANY
        frame — an SSO widget iframe, a frameset panel — or inside an open
        shadow root, so the text merge and the password probe both walk
        every frame and open shadow tree.
        """
        # Session-conflict check runs first: even if the page navigated away
        # and cookies were set, a "already logged in elsewhere" page is not a
        # real authenticated session — it's the site blocking us. Merged over
        # all frames because the stop block can render inside the frame
        # hosting the login form.
        page_text = ""
        try:
            for frame in list(self._page.frames):
                try:
                    page_text += " " + frame.inner_text("body").lower()
                except Exception:
                    pass  # non-HTML or already-detached frame
        except Exception:
            pass  # inner_text() can fail (e.g. non-HTML page); fall through to other signals
        for marker in SESSION_ALREADY_ACTIVE_MARKERS:
            if marker in page_text:
                logger.warning(
                    "_login_succeeded(): detected session-conflict marker %r — "
                    "treating login as failed to avoid false positive",
                    marker,
                )
                return False

        navigated_away = self._page.url.rstrip("/") != login_url.rstrip("/")
        password_gone = self._password_gone()
        has_cookies = len(self._context.cookies()) > 0
        return navigated_away or password_gone or has_cookies

    def _password_gone(self) -> bool:
        """True when no except-either visible password input stands anywhere in
        any frame (open shadow roots included). Probe errors count as
        present (fail safe toward logged-out)."""
        probe_js = r"""
() => {
  const found = (root) => {
    for (const el of root.querySelectorAll('input[type="password"]')) {
      const cs = getComputedStyle(el);
      if (!(cs.display === 'none' || cs.visibility === 'hidden')) return true;
      if (el.getClientRects().length > 0) return true;
    }
    for (const h of root.querySelectorAll('*')) {
      const sr = h.shadowRoot;
      if (sr && found(sr)) return true;
    }
    return false;
  };
  return found(document);
}
"""
        for frame in list(self._page.frames):
            try:
                if frame.evaluate(probe_js):
                    return False  # a password field is still up somewhere
            except Exception:
                return False  # probe failed openly — assume logged out (page replaced?)
        return True

    def cookies_for_requests(self) -> dict:
        """
        Returns {name: value} from the browser context's cookie jar, so
        Tier 1's broken-link checks (plain `requests`) can be authenticated
        too via session.cookies.update(this dict).
        """
        return {c["name"]: c["value"] for c in self._context.cookies()}

    def replay_login(
        self,
        start_url: str,
        recorded_steps: List[Dict[str, Any]],
        username: str,
        password: str,
        captcha_answer: Optional[str] = None,
        extra_fields: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[str], bool, Optional[str], Optional[str]]:
        """
        Replays a previously-recorded login flow (login_recorder.py /
        login_config_store.py — Step 7) against `start_url` (the URL that
        was open when recording began). The actual step-by-step player
        lives in login_replay.replay_login_steps — this just manages the
        page lifecycle around it and matches render()'s
        (html, success, final_url) return shape, plus the login form's URL.

        Returns a 4-tuple: (html, success, form_url, reason). `reason` is
        None on success; otherwise a one-line failure detail — the stopping
        step, its selector, and the summarized Playwright cause — which the
        caller includes in the surfaced scan error. The per-step detail used
        to reach only the backend log, which the person watching the UI
        couldn't see (they only got a generic "replay failed" line).

        Returns (None, False, None, reason) if the target's markup has
        drifted enough since recording that a step's selector no longer
        resolves, or if the replay completed but doesn't look like it
        actually authenticated us (see _login_succeeded) — both are a real
        "this recording no longer works" signal the caller should surface,
        not silently swallow.
        """
        page = self._page
        try:
            page.goto(start_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            # Post-load bounce/settle window (see REPLAY_SETTLE_TIMEOUT_MS):
            # sites that hop to an auth-key endpoint right after `load` must
            # finish that dance before the first recorded step fires.
            try:
                page.wait_for_load_state("networkidle", timeout=REPLAY_SETTLE_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass
            form_url_box: List[str] = []
            pre_step_url = ""
            try:
                pre_step_url = page.url
            except Exception:
                pre_step_url = start_url
            replay_login_steps(
                page, recorded_steps, username=username, password=password,
                captcha_answer=captcha_answer, extra_fields=extra_fields,
                form_url_box=form_url_box,
            )
            try:
                page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass
            # Post-step JS-redirect watch (see REPLAY_POST_NAV_WATCH_MS).
            try:
                page.wait_for_url(
                    lambda u: _url_base(u) != _url_base(pre_step_url),
                    timeout=REPLAY_POST_NAV_WATCH_MS,
                )
            except PlaywrightTimeoutError:
                pass
            if not self._login_succeeded(start_url):
                reason = ("replay completed but the page still looks logged out "
                          "(the login form is still present, or a session-conflict "
                          "phrase matched)")
                logger.warning("replay_login() completed but login check failed — treating as unsuccessful")
                return None, False, None, reason
            logger.info("replay_login() succeeded for %s", start_url)
            return page.content(), True, (form_url_box[0] if form_url_box else None), None
        except ReplayError as exc:
            logger.error("replay_login() ReplayError for %s — %s", start_url, exc)
            return None, False, None, str(exc)
        except PlaywrightTimeoutError as exc:
            logger.error("replay_login() timed out for %s — %s", start_url, exc)
            return None, False, None, f"navigation or step timed out ({_summarize_playwright_error(exc)})"

    def replay_logout(
        self,
        logout_url: Optional[str] = None,
        logout_steps: Optional[List[Dict[str, Any]]] = None,
        start_url: Optional[str] = None,
    ) -> None:
        """
        Performs logout at scan end using whichever mechanism was configured
        for this target. If logout_url is provided, navigates there. If
        logout_steps are provided (and no URL), first navigates back to
        start_url (the scan target's authed home, which carries the logout
        control) and then replays the recorded step sequence — replaying on
        whatever random page the crawl ended on (a public page, a download,
        a 404) leaves selectors unresolvable and the session alive.
        If neither is provided, this is a no-op.

        Any failure here is logged as a warning but not re-raised — a logout
        failure means the server-side session may stay alive (the problem
        this is meant to fix) but is not itself a new scan blocker.
        """
        if not logout_url and not logout_steps:
            return

        try:
            if logout_url:
                logger.info("replay_logout(): navigating to logout URL %s", logout_url)
                self._page.goto(logout_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
                try:
                    self._page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
                except PlaywrightTimeoutError:
                    pass
                logger.info("replay_logout(): logout URL navigation complete")
            else:
                if start_url:
                    try:
                        logger.info("replay_logout(): returning to %s before replaying steps", start_url)
                        self._page.goto(start_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
                    except PlaywrightTimeoutError as exc:
                        logger.warning(
                            "replay_logout(): positioning navigation to %s failed (%s) — attempting steps anyway",
                            start_url, exc,
                        )
                logger.info(
                    "replay_logout(): replaying %d logout step(s) from %s",
                    len(logout_steps), self._page.url,
                )
                replay_logout_steps(self._page, logout_steps)
                try:
                    self._page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
                except PlaywrightTimeoutError:
                    pass
                logger.info("replay_logout(): logout steps complete")
        except Exception as exc:
            logger.warning(
                "replay_logout() failed (server-side session may still be active) — %s: %s",
                type(exc).__name__, exc,
            )