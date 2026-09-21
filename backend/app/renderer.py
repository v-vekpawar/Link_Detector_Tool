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

from typing import Any, Dict, List, Optional, Tuple

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from app.config import REQUEST_TIMEOUT_SECONDS
from app.login_replay import ReplayError, replay_login_steps

# Rendering (navigation + JS execution) is slower than a plain HTTP GET,
# so this gets a more generous budget than Tier 1's REQUEST_TIMEOUT_SECONDS.
RENDER_TIMEOUT_MS = REQUEST_TIMEOUT_SECONDS * 1000 * 2


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

    def start(self) -> "DynamicSession":
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=False)
        self._context = self._browser.new_context(ignore_https_errors=True)
        self._page = self._context.new_page()
        return self

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

    def render(self, url: str) -> Tuple[Optional[str], bool]:
        """
        Loads `url` in the shared page (cookies from login carry over
        automatically) and returns (html, success). html is None and
        success is False if navigation failed outright (matches the
        (html, success) shape crawler.py's page_html_fetcher expects).
        """
        try:
            self._page.goto(url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            try:
                self._page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass  # some pages never go fully idle (polling/websockets) — use what's loaded
            return self._page.content(), True
        except PlaywrightTimeoutError:
            return None, False
        except Exception:
            return None, False

    def _login_succeeded(self, login_url: str) -> bool:
        """
        Best-effort check that a login attempt actually authenticated us,
        instead of just trusting that a password field existed and got
        submitted. True if any of:
          - the page navigated away from the login URL, or
          - the password field is no longer present (form replaced/gone), or
          - the context picked up at least one cookie during the attempt
            (covers session-cookie-based auth where the URL/form might not
            visibly change right away).
        False means the attempt should be treated as failed rather than
        letting the crawl proceed on an unauthenticated session.
        """
        navigated_away = self._page.url.rstrip("/") != login_url.rstrip("/")
        password_gone = self._page.query_selector('input[type="password"]') is None
        has_cookies = len(self._context.cookies()) > 0
        return navigated_away or password_gone or has_cookies

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
    ) -> Tuple[Optional[str], bool]:
        """
        Replays a previously-recorded login flow (login_recorder.py /
        login_config_store.py — Step 7) against `start_url` (the URL that
        was open when recording began). The actual step-by-step player
        lives in login_replay.replay_login_steps — this just manages the
        page lifecycle around it and matches render()'s
        (html, success) return shape.

        Returns (None, False) if the target's markup has drifted enough
        since recording that a step's selector no longer resolves, or if
        the replay completed but doesn't look like it actually
        authenticated us (see _login_succeeded) — both are a real "this
        recording no longer works" signal the caller should surface, not
        silently swallow.
        """
        page = self._page
        try:
            page.goto(start_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            replay_login_steps(page, recorded_steps, username=username, password=password)
            try:
                page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass
            if not self._login_succeeded(start_url):
                return None, False
            return page.content(), True
        except (ReplayError, PlaywrightTimeoutError):
            return None, False