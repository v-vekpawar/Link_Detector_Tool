"""
Login Flow Recorder (Step 7 of BUILD_ORDER.md, the "Option 3" opt-in path
described in ARCHITECTURE.md).

Opens a HEADED (visible) Playwright browser window pointed at the target.
The user manually clicks/fills their way through the login flow however
many steps it takes. Every click and form-field change is captured via an
injected JS listener and reported back to Python through an exposed
context binding. The user signals "I'm done" by clicking a small overlay
button we inject into every page of the session.

Credential safety (per DATA_MODEL.md / ARCHITECTURE.md): actual values
typed into password fields, and the first non-password text/email field
in a fill (treated as the username/email field), are NEVER recorded —
only the fact that "this selector is the password field" / "this selector
is the username field". Real credentials get substituted in at replay
time (see login_replay.py, Step 7's replay half). Any other form control
(checkbox, radio, select, etc.) is not credential material, so its value
IS recorded, to reproduce things like a "Remember me" checkbox faithfully.

Output shape — a list of step dicts, JSON-serializable as-is for storage
in login_configs.recorded_steps:
    {"action": "click", "selector": "..."}
    {"action": "fill", "selector": "...", "field_type": "password"}
    {"action": "fill", "selector": "...", "field_type": "username"}
    {"action": "fill", "selector": "...", "field_type": "other", "value": ...}
"""

import threading
from typing import Any, Dict, List, Optional

from playwright.sync_api import sync_playwright

from app.renderer import RENDER_TIMEOUT_MS, ensure_windows_subprocess_support

# Safety cap: if the user never clicks "Finish Recording" and never closes
# the window, give up after this long so a script/API call can't hang
# forever waiting on a human.
MAX_RECORDING_SECONDS = 600

FINISH_BUTTON_ID = "__link_audit_finish_btn__"

# Injected into every page (including ones reached via navigation/redirect
# mid-flow) via context.add_init_script, so recording survives multi-page
# login flows (e.g. a "Log in" link -> separate login page -> redirect back).
_RECORDER_INIT_SCRIPT = r"""
(() => {
  if (window.__linkAuditRecorderInstalled) return;
  window.__linkAuditRecorderInstalled = true;

  function cssSelector(el) {
    if (!(el instanceof Element)) return null;
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name.replace(/"/g, '\\"') + '"]';
    const path = [];
    let node = el;
    while (node && node.nodeType === Node.ELEMENT_NODE && path.length < 8) {
      let selector = node.tagName.toLowerCase();
      if (node.parentElement) {
        const siblings = Array.from(node.parentElement.children).filter(
          (c) => c.tagName === node.tagName
        );
        if (siblings.length > 1) {
          selector += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
        }
      }
      path.unshift(selector);
      node = node.parentElement;
    }
    return path.join(' > ');
  }

  function fieldRole(el) {
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (type === 'password') return 'password';
    if (type === 'checkbox' || type === 'radio') return 'other';
    if (el.tagName === 'SELECT') return 'other';
    if (type === '' || type === 'text' || type === 'email') return 'username';
    return 'other';
  }

  document.addEventListener('click', (e) => {
    const el = e.target.closest('a, button, input[type="submit"], input[type="button"], [role="button"]');
    if (!el || el.id === '""" + FINISH_BUTTON_ID + r"""') return;
    window.__recordAction({ action: 'click', selector: cssSelector(el) });
  }, true);

  document.addEventListener('change', (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLSelectElement)) return;
    const role = fieldRole(el);
    if (role === 'other') {
      const value = (el.type === 'checkbox' || el.type === 'radio') ? el.checked : el.value;
      window.__recordAction({ action: 'fill', selector: cssSelector(el), field_type: 'other', value: value });
    } else {
      window.__recordAction({ action: 'fill', selector: cssSelector(el), field_type: role });
    }
  }, true);

  function injectFinishButton() {
    if (document.getElementById('""" + FINISH_BUTTON_ID + r"""')) return;
    const btn = document.createElement('button');
    btn.id = '""" + FINISH_BUTTON_ID + r"""';
    btn.textContent = 'Finish Recording';
    btn.style.cssText =
      'position:fixed;top:12px;right:12px;z-index:2147483647;' +
      'background:#c0392b;color:#fff;border:none;padding:10px 16px;' +
      'font:14px sans-serif;border-radius:4px;cursor:pointer;' +
      'box-shadow:0 2px 6px rgba(0,0,0,0.4);';
    btn.addEventListener('click', () => window.__finishRecording());
    (document.body || document.documentElement).appendChild(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectFinishButton);
  } else {
    injectFinishButton();
  }

  // Some login flows swap DOM content in place (SPA-style) rather than
  // navigating to a new document, which would otherwise wipe out our
  // injected button without triggering add_init_script again. Watch for
  // that and re-inject so "Finish Recording" stays available throughout.
  new MutationObserver(() => {
    if (!document.getElementById('""" + FINISH_BUTTON_ID + r"""')) injectFinishButton();
  }).observe(document, { childList: true, subtree: true });
})();
"""


class LoginRecordingSession:
    """
    One headed-browser recording session. Call `run(target_url)` to launch
    the window, block until the user clicks "Finish Recording" (or closes
    the window, or the safety timeout expires), and get back the ordered
    list of recorded steps.
    """

    def __init__(self):
        self._steps: List[Dict[str, Any]] = []
        self._finished = threading.Event()
        self._lock = threading.Lock()

    def _on_record_action(self, source, data: Dict[str, Any]) -> None:
        with self._lock:
            self._steps.append(data)

    def _on_finish(self, source) -> None:
        self._finished.set()

    def run(
        self,
        target_url: str,
        headless: bool = False,
        extra_launch_args: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        ensure_windows_subprocess_support()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, args=list(extra_launch_args or []))
            try:
                context = browser.new_context(ignore_https_errors=True)
                context.expose_binding(
                    "__recordAction", lambda source, data: self._on_record_action(source, data)
                )
                context.expose_binding("__finishRecording", lambda source: self._on_finish(source))
                context.add_init_script(_RECORDER_INIT_SCRIPT)
                context.on("close", lambda: self._finished.set())

                page = context.new_page()
                page.goto(target_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")

                # IMPORTANT: don't block on a plain threading.Event().wait() here.
                # Playwright's sync API is driven by a greenlet-based dispatcher —
                # incoming messages (like the browser reporting our exposed
                # binding was called) are only processed when the calling thread
                # makes another Playwright call that yields to that dispatcher.
                # A bare Python-level wait never yields, so a real click in the
                # visible window would sit unprocessed forever. Polling via an
                # actual Playwright call (wait_for_timeout) keeps pumping the
                # dispatcher so bindings fire promptly.
                poll_ms = 250
                elapsed_ms = 0
                while not self._finished.is_set() and elapsed_ms < MAX_RECORDING_SECONDS * 1000:
                    try:
                        page.wait_for_timeout(poll_ms)
                    except Exception:
                        break  # window/context/browser was closed out from under us
                    elapsed_ms += poll_ms

                try:
                    context.close()
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

        with self._lock:
            return list(self._steps)


def record_login_flow(target_url: str, headless: bool = False) -> List[Dict[str, Any]]:
    """Convenience entry point — see LoginRecordingSession for details."""
    return LoginRecordingSession().run(target_url, headless=headless)