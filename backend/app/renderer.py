"""
Tier 2 (dynamic) engine — Playwright-based rendering and login.

Used only for (per ARCHITECTURE.md):
  1. Logging in (auto-fill here; replaying a recorded flow is Step 7)
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

    Usage:
        with DynamicSession() as dyn:
            dyn.auto_login(login_url, username, password)
            html, ok = dyn.render(some_page_url)
            cookies = dyn.cookies_for_requests()  # hand off to a requests.Session
    """

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._context = None

    def start(self) -> "DynamicSession":
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(ignore_https_errors=True)
        return self

    def close(self) -> None:
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
        Loads `url` in the shared context (cookies from login carry over
        automatically) and returns (html, success). html is None and
        success is False if navigation failed outright (matches the
        (html, success) shape crawler.py's page_html_fetcher expects).
        """
        page = self._context.new_page()
        try:
            page.goto(url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            try:
                page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass  # some pages never go fully idle (polling/websockets) — use what's loaded
            return page.content(), True
        except PlaywrightTimeoutError:
            return None, False
        except Exception:
            return None, False
        finally:
            page.close()

    def cookies_for_requests(self) -> dict:
        """
        Returns {name: value} from the browser context's cookie jar, so
        Tier 1's broken-link checks (plain `requests`) can be authenticated
        too via session.cookies.update(this dict).
        """
        return {c["name"]: c["value"] for c in self._context.cookies()}

    def auto_login(self, login_url: str, username: str, password: str) -> bool:
        """
        Loads the login page, finds the first password-type input, finds a
        username/email-like input in the same form, fills both, and submits.
        Returns True if a password field was found and login was attempted,
        False if no password field could be located at all.
        """
        page = self._context.new_page()
        try:
            page.goto(login_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")

            password_el = page.query_selector('input[type="password"]')
            if password_el is None:
                return False

            form_handle = password_el.evaluate_handle("el => el.closest('form')")
            form_el = form_handle.as_element()

            username_selector = 'input[type="text"], input[type="email"], input:not([type])'
            username_el = (form_el or page).query_selector(username_selector)

            if username_el is not None:
                username_el.fill(username)
            password_el.fill(password)

            if form_el is not None:
                form_el.evaluate("form => form.requestSubmit ? form.requestSubmit() : form.submit()")
            else:
                password_el.press("Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass

            return True
        finally:
            page.close()

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
        page lifecycle around it and matches render()/auto_login()'s
        (html, success) return shape.

        Returns (None, False) if the target's markup has drifted enough
        since recording that a step's selector no longer resolves —
        that's a real "this recording no longer works" signal the caller
        should surface, not silently swallow.
        """
        page = self._context.new_page()
        try:
            page.goto(start_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
            replay_login_steps(page, recorded_steps, username=username, password=password)
            try:
                page.wait_for_load_state("networkidle", timeout=RENDER_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass
            return page.content(), True
        except (ReplayError, PlaywrightTimeoutError):
            return None, False
        finally:
            page.close()