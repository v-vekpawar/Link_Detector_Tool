"""
Login Flow Recorder (Step 7 of BUILD_ORDER.md, the "Option 3" opt-in path
described in ARCHITECTURE.md).

Two session flavors live here:
- LoginRecordingSession: the original single-shot recorder. Opens a headed
  window, captures until finished (tool-UI endpoint, window close, or safety
  timeout), then closes the browser and returns the steps.
- FlowRecordingSession: the phased login→logout flow. ONE headed window stays
  open across phases — login capture, frozen login, logout capture — and only
  closes when the flow is saved (or the window is closed / times out). Phase
  boundaries are indices over a single raw-event list, so clicks between
  Finish-Login and Start-Logout belong to neither phase.

Credential safety (per DATA_MODEL.md / ARCHITECTURE.md): actual values
typed into password fields, and the first non-password text/email field
in a fill (treated as the username/email field), are NEVER recorded —
only the fact that "this selector is the password field" / "this selector
is the username field". Real credentials get substituted in at replay
time (see login_replay.py, Step 7's replay half). Any other form control
(checkbox, radio, select, etc.) is not credential material, so its value
IS recorded, to reproduce things like a "Remember me" checkbox faithfully.

Credential safety (per DATA_MODEL.md / ARCHITECTURE.md): actual values
typed into password fields, and the first non-password text/email field
in a fill (treated as the username/email field), are NEVER recorded —
only the fact that "this selector is the password field" / "this selector
is the username field". Real credentials get substituted in at replay
time (see login_replay.py, Step 7's replay half). Any other form control
(checkbox, radio, select, etc.) is not credential material, so its value
IS recorded, to reproduce things like a "Remember me" checkbox faithfully.

Captcha fields (fixed/static captcha on the target site — not a real
solved-per-attempt captcha): a text/email field is classified as
"captcha" instead of "username" when either (a) its name/id/placeholder
contains "captcha", or (b) the username field has already been seen
earlier in this recording, so it's some other text field (per the
"first non-password text/email field is username" rule above). Like the
"other" case, a captcha field's typed value IS recorded — it's not
credential material, and since it's fixed, replaying the recorded value
verbatim is correct (see login_replay.py). If a target instead uses a
checkbox-style captcha ("I'm not a robot"), no special handling is
needed — it already falls under "other" and its checked state is
recorded/replayed like any checkbox.

Output shape — a list of step dicts, JSON-serializable as-is for storage
in login_configs.recorded_steps:
    {"action": "click", "selector": "..."}
    {"action": "fill", "selector": "...", "field_type": "password"}
    {"action": "fill", "selector": "...", "field_type": "username"}
    {"action": "fill", "selector": "...", "field_type": "captcha", "value": ...}
    {"action": "fill", "selector": "...", "field_type": "other", "value": ...}
    {"action": "hover", "selector": "..."}

"hover" steps are recorded when the pointer dwells ~300ms on a non-form
element (menu triggers get deliberately hovered to reveal their menus;
pointer-in-transit never dwells). Replay performs them best-effort before
the click that depends on them — see login_replay.py. Recordings made
before hover capture existed have no hover steps and replay unchanged,
so hover-gated sites need one re-record.

New recordings also carry "fingerprint": {"tag", "text", "aria", "role"}
(Order 7) — an identity snapshot replay uses to refuse a silently-changed
target instead of clicking/filling the wrong element. Steps recorded before
fingerprints existed have no such key and replay exactly as before.
"""

import threading
from typing import Any, Dict, List, Optional

import logging

from playwright.sync_api import sync_playwright

from app.login_replay import replay_login_steps
from app.renderer import BROWSER_CONTEXT_KWARGS, RENDER_TIMEOUT_MS

logger = logging.getLogger("link_audit.login_recorder")

# Safety cap: if the window is never closed/finished, give up after this long
# so a script/API call can't hang forever waiting on a human.
MAX_RECORDING_SECONDS = 600

# Injected into every page (including ones reached via navigation/redirect
# mid-flow) via context.add_init_script, so recording survives multi-page
# login flows (e.g. a "Log in" link -> separate login page -> redirect back).
_RECORDER_INIT_SCRIPT = r"""
(() => {
  if (window.__linkAuditRecorderInstalled) return;
  window.__linkAuditRecorderInstalled = true;

  function singleMatch(sel) {
    try {
      return document.querySelectorAll(sel).length === 1;
    } catch (e) {
      return false;
    }
  }

  // The element the interaction actually landed on, revealed through any
  // shadow DOM boundary: document-level events keep composed listeners out
  // of shadow trees, and e.target is RETARGETED to the host element when a
  // listener outside a shadow tree sees a composed event land inside one.
  // Without composedPath, recording a login form rendered inside an open
  // shadow root would store the HOST's selector and replay would click the
  // host — never the button inside it.
  function eventEl(e) {
    const path = (typeof e.composedPath === 'function') ? e.composedPath() : [e.target];
    for (const n of path) {
      if (n instanceof Element) return n;
    }
    return null;
  }

  function cssSelector(el) {
    if (!(el instanceof Element)) return null;
    // Stable forms first (each used only when it names exactly this
    // element — Order 7: survives React re-renders that positional paths
    // don't), positional path last as the always-unique fallback.
    // Shadow-internal elements skip the stable forms entirely:
    // document.querySelectorAll cannot see them (they would return 0 and
    // every check would "pass as non-unique"), so their selector is the
    // composed positional path — head light-DOM segment space-joined to
    // open-shadow-internal segments, which Playwright's css engine
    // matches through shadow boundaries implicitly (probe-verified).
    const inShadow = el.getRootNode() instanceof ShadowRoot;
    if (!inShadow) {
      if (el.id && singleMatch('#' + CSS.escape(el.id))) return '#' + CSS.escape(el.id);
      for (const attr of ['data-testid', 'data-test', 'aria-label']) {
        const val = el.getAttribute(attr);
        if (val) {
          const sel = '[' + attr + '="' + CSS.escape(val) + '"]';
          if (singleMatch(sel)) return sel;
        }
      }
      const name = el.getAttribute('name');
      if (name) {
        const sel = el.tagName.toLowerCase() + '[name="' + CSS.escape(name) + '"]';
        if (singleMatch(sel)) return sel;
      }
      const tag = el.tagName.toLowerCase();
      for (const cls of el.classList) {
        const sel = tag + '.' + CSS.escape(cls);
        if (singleMatch(sel)) return sel;
      }
    }
    return positionalPath(el);
  }

  function positionalPath(el) {
    // Positional path that crosses OPEN shadow-root boundaries. Each
    // segment is the ordinary within-tree positional path (same rules as
    // before for light-DOM elements); at a boundary the next segment is
    // built inside the shadow host's OWNER tree (the light document).
    // Segments join by SPACES (descendant combinator) — Playwright's css
    // engine pierces open shadow boundaries for implicit css, and its
    // locator string parser treats '>' chains WITHOUT the engine prefix
    // as chaining, so a full ' > ' path is safe here but '>>>' is never
    // used (it would split as a locator chain).
    const segs = [];
    let node = el;
    for (let depth = 0; depth < 4 && node instanceof Element; depth++) {
      const path = [];
      let cur = node;
      // Same as above: a ShadowRoot parent is not an Element, but its
      // children list still gives exact :nth-of-type positions.
      while (cur && cur.nodeType === Node.ELEMENT_NODE && path.length < 8) {
        const par = cur.parentElement || (cur.parentNode && cur.parentNode.host ? cur.parentNode : null);
        let selector = cur.tagName.toLowerCase();
        if (par) {
          const siblings = Array.from(par.children).filter(
            (c) => c.tagName === cur.tagName
          );
          if (siblings.length > 1) {
            selector += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
          }
        }
        path.unshift(selector);
        cur = par;
      }
      segs.unshift(path.join(' > '));
      const root = node.getRootNode();
      if (root instanceof ShadowRoot) {
        node = root.host;
      } else {
        break;
      }
    }
    return segs.join(' ');
  }

  function fingerprint(el) {
    // Identity snapshot for replay-time verification (Order 7): tag +
    // collapsed visible text + accessible name + role. No values — safe to
    // persist alongside redacted credential fields.
    if (!(el instanceof Element)) return null;
    const collapse = (s) => (s || '').replace(/\s+/g, ' ').trim().slice(0, 80);
    return {
      tag: el.tagName.toLowerCase(),
      text: collapse(el.textContent),
      aria: el.getAttribute('aria-label') || '',
      role: el.getAttribute('role') || ''
    };
  }

  document.addEventListener('click', (e) => {
    const el = eventEl(e);
    if (!el) return;
    const target = el.closest('a, button, input[type="submit"], input[type="button"], [role="button"]');
    if (!target) return;
    const selector = cssSelector(target);
    if (!selector) return;
    window.__recordAction({ action: 'click', selector: selector, fingerprint: fingerprint(target),
                            frame_url: (window === window.top) ? null : location.href,
                            page_url: location.origin + location.pathname });
  }, true);
  // Hover recording (hover-revealed menus): the click listener above only
  // sees the final button, never the avatar/menu-parent hover that revealed
  // it — so replay had nothing to open the menu with and its click timed
  // out on the invisible target ("element is not visible"). A hover STEP is
  // recorded when the pointer DWELLS ~300ms on a non-form element; pointer
  // movement in transit keeps firing mouseover on successive elements and
  // resetting the timer, so only a deliberate pause lands a step — exactly
  // the intent that opens CSS (:hover) or JS (mouseover) menus. Hovers on
  // inputs/textarea/select are noise before a fill, not menu triggers —
  // skipped. Same-element repeats are deduped by selector.
  let hoverTimer = null;
  let lastHoverSel = null;
  document.addEventListener('mouseover', (e) => {
    // Cancel any pending dwell FIRST — even when this mouseover lands on a
    // skipped form field, otherwise a stale dwell from an earlier transit
    // element would fire mid-typing and record a phantom hover.
    if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
    const t = eventEl(e);
    if (!t || !(t instanceof Element)) return;
    if (t.closest('input, textarea, select')) return;
    // Shadow-detached nodes stay recordable: isConnected is true for
    // shadow-internal nodes (document.contains would return false there).
    if (!t.isConnected) return;
    const tag = t.tagName.toLowerCase();
    if (tag === 'html' || tag === 'body') return;
    hoverTimer = setTimeout(() => {
      hoverTimer = null;
      if (!t.isConnected) return;
      const rect = t.getBoundingClientRect();
      if (rect.width < 4 || rect.height < 4) return;
      const selector = cssSelector(t);
      if (!selector || selector === lastHoverSel) return;
      lastHoverSel = selector;
      window.__recordAction({ action: 'hover', selector: selector, fingerprint: fingerprint(t),
                              frame_url: (window === window.top) ? null : location.href,
                              page_url: location.origin + location.pathname });
    }, 300);
  }, true);

  // Change recording = form fills. Unlike click/mouseover, `change` events
  // are NOT composed: one fired inside an open shadow root stops at that
  // shadow root, so a listener on the document never sees it — a login
  // widget rendered in a shadow tree would record NOTHING (no fills), and
  // replay would have no fields to type into. So the handler must be
  // attached to EVERY open shadow root that exists or appears later: the
  // initial walk below plus a MutationObserver (page scripts typically
  // attach their shadow roots AFTER this init script runs).
  function handleChange(e) {
    const el = eventEl(e);
    if (!el) return;
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLSelectElement) && !(el instanceof HTMLTextAreaElement)) return;
    const type = (el.getAttribute('type') || '').toLowerCase();
    const isPassword = type === 'password';
    const isChoice = type === 'checkbox' || type === 'radio' || el.tagName.toLowerCase() === 'select';
    const val = (type === 'checkbox' || type === 'radio') ? el.checked : el.value;
    const name = el.getAttribute('name') || '';
    const placeholder = el.getAttribute('placeholder') || '';
    const label = el.getAttribute('aria-label') || el.id || name || '';

    window.__recordAction({
      action: 'fill',
      selector: cssSelector(el),
      fingerprint: fingerprint(el),
      input_type: type,
      is_password: isPassword,
      is_choice: isChoice,
      name: name,
      placeholder: placeholder,
      label: label,
      value: (isPassword ? '' : val),
      frame_url: (window === window.top) ? null : location.href,
      page_url: location.origin + location.pathname,
    });
  }

  function attachChange(root) {
    try {
      root.addEventListener('change', handleChange, true);
    } catch (err) { /* detached root */ }
    try {
      for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) {
          attachChange(el.shadowRoot);
        }
      }
    } catch (err) { /* detached tree mid-walk */ }
  }

  attachChange(document);

  // Re-attach on a beat. Page scripts call attachShadow() AFTER this init
  // script runs, and attachShadow adds NO node to the light document — a
  // MutationObserver on `document` never sees shadow-tree mutations either,
  // so the only reliable way to cover roots that appear later is to re-walk.
  // addEventListener dedupes identical (type, callback, capture) calls, so
  // re-attaching to an already-covered root is a no-op.
  try {
    setInterval(function () {
      const walk = (root) => {
        for (const el of root.querySelectorAll('*')) {
          if (el.shadowRoot) {
            attachChange(el.shadowRoot);
            walk(el.shadowRoot);
          }
        }
      };
      try {
        walk(document);
      } catch (err) { /* document detached */ }
    }, 400);
  } catch (err) { /* timers unavailable — the initial walk still ran */ }
})();
"""


def _looks_like_captcha(step: Dict[str, Any]) -> bool:
    """True when a fill step targets a captcha field (name, placeholder,
    label, or selector mentions one), case-insensitively."""
    for key in ("name", "placeholder", "label", "selector"):
        if "captcha" in (step.get(key) or "").lower():
            return True
    return False


def _process_recorded_steps(raw_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Classifies filled form fields based strictly on input type and recording order (Item #5),
    plus captcha naming:
      - type="password": password field (value redacted)
      - A field mentioning "captcha": captcha field (value preserved — fixed
        captchas replay verbatim; never a username candidate)
      - The text/email field filled immediately before the password field: username field (value redacted)
      - Checkboxes, radios, selects: other (value preserved)
      - Any other filled text/input fields: extra fields (selector, label, name, placeholder, default value preserved)
    """
    processed = []
    fill_step_indices = [
        i for i, step in enumerate(raw_steps)
        if step.get("action") == "fill" and not step.get("is_choice")
    ]

    password_indices = [
        i for i in fill_step_indices
        if raw_steps[i].get("is_password") or raw_steps[i].get("input_type") == "password"
    ]

    username_index = None
    if password_indices:
        first_pw = password_indices[0]
        prior_fills = [
            i for i in fill_step_indices
            if i < first_pw
            and not raw_steps[i].get("is_password")
            and not _looks_like_captcha(raw_steps[i])
        ]
        if prior_fills:
            username_index = prior_fills[-1]
    elif fill_step_indices:
        # If no password field was filled, treat the first text field as username
        non_captcha = [i for i in fill_step_indices if not _looks_like_captcha(raw_steps[i])]
        username_index = non_captcha[0] if non_captcha else fill_step_indices[0]

    # A re-edit of the username field after the password (typo fix, autofill
    # refire) has the same selector — it is still the username, not an extra
    # field. Without this it was classified "extra" and its typed value was
    # preserved, surfacing a duplicate prefilled username input at scan time.
    username_selector = (
        raw_steps[username_index].get("selector")
        if username_index is not None else None
    )

    extra_count = 1
    for i, step in enumerate(raw_steps):
        action = step.get("action")
        selector = step.get("selector")
        # Frame-of-origin key (Frames Phase A): None/absent = the main
        # document (every recording made before this change replays
        # unchanged); otherwise the absolute URL of the frame the step
        # landed in, so replay can route it to the right document even
        # when the same selectors exist in several frames.
        frame_url = step.get("frame_url") or None
        frame_extra = {"frame_url": frame_url} if frame_url else {}
        # Fingerprint (Order 7) passes through untouched when present;
        # pre-fingerprint recordings simply have no such key.
        fp = step.get("fingerprint")
        fp_extra = {"fingerprint": fp} if fp is not None else {}
        if action == "hover":
            # Enabler step for hover-revealed menus, captured with a dwell
            # debounce (see _RECORDER_INIT_SCRIPT). Passes through with its
            # fingerprint like clicks; replay treats it as best-effort
            # (skipped with a warning if it no longer resolves), so a stale
            # hover never aborts a flow that would otherwise still work.
            processed.append({"action": "hover", "selector": step.get("selector"), **fp_extra, **frame_extra})
        elif action == "click":
            processed.append({"action": "click", "selector": step.get("selector"), **fp_extra, **frame_extra})
        elif action == "fill":
            selector = step.get("selector")
            if step.get("is_choice"):
                processed.append({
                    "action": "fill",
                    "selector": selector,
                    "field_type": "other",
                    "value": step.get("value"),
                    **fp_extra, **frame_extra,
                })
            elif i in password_indices:
                processed.append({
                    "action": "fill",
                    "selector": selector,
                    "field_type": "password",
                    **fp_extra, **frame_extra,
                })
            elif _looks_like_captcha(step):
                processed.append({
                    "action": "fill",
                    "selector": selector,
                    "field_type": "captcha",
                    "label": step.get("label") or step.get("placeholder") or step.get("name"),
                    "name": step.get("name"),
                    "placeholder": step.get("placeholder"),
                    "value": step.get("value"),
                    **fp_extra, **frame_extra,
                })
            elif i == username_index or (username_selector and selector == username_selector):
                processed.append({
                    "action": "fill",
                    "selector": selector,
                    "field_type": "username",
                    **fp_extra, **frame_extra,
                })
            else:
                label = step.get("label") or step.get("placeholder") or step.get("name") or f"Extra field {extra_count}"
                extra_count += 1
                processed.append({
                    "action": "fill",
                    "selector": selector,
                    "field_type": "extra",
                    "label": label,
                    "name": step.get("name"),
                    "placeholder": step.get("placeholder"),
                    "value": step.get("value"),
                    **fp_extra, **frame_extra,
                })

    return processed


class LoginRecordingSession:
    """
    One headed-browser recording session. Call `run(target_url)` to launch
    the window, block until the user finishes recording (via UI endpoint,
    closing window, or safety timeout), and get back the ordered list of
    recorded steps.
    """

    def __init__(self):
        self._steps: List[Dict[str, Any]] = []
        self._finished = threading.Event()
        self._lock = threading.Lock()

    def finish(self) -> None:
        """Signals this recording session to complete and close."""
        self._finished.set()

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
        launch_args = ["--start-maximized"] + list(extra_launch_args or [])
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, args=launch_args)
            try:
                context = browser.new_context(**BROWSER_CONTEXT_KWARGS)
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
            return _process_recorded_steps(self._steps)


def record_login_flow(target_url: str, headless: bool = False) -> List[Dict[str, Any]]:
    """Convenience entry point — see LoginRecordingSession for details."""
    return LoginRecordingSession().run(target_url, headless=headless)


class FlowRecordingSession:
    """
    Phased login→logout recording inside ONE headed browser window.

    Lifecycle (driven by HTTP endpoints, all cross-thread safe):
      start (worker thread opens window, captures from here)
        -> finish_login()   freeze + process login steps (window stays open)
        -> rerecord_login() reset state in-window: clear cookies, back to
           target, capture restarts (frozen login replaced on next finish)
        -> begin_logout()   mark logout capture start (requires login frozen)
        -> finish_logout()  freeze + process logout steps (window stays open)
        -> request_navigate(url)  drive the open window (logout-URL check)
        -> request_close()   teardown browser, end worker

    Raw click/fill events stream into one list for the whole flow; phases are
    index boundaries over it (login = raw[:login_end],
    logout = raw[logout_start:logout_end]). Anything captured between
    Finish-Login and Start-Logout belongs to neither phase. Every raw event
    also carries page_url (origin + path, query dropped) — the logout phase's
    page is persisted as logout_start_url (see logout_start_url()), so
    scan-end logout replay returns to the authed home that carries the
    logout control rather than the scan target (often the bare login form).
    Closing the
    window manually (or the safety timeout) ends capture but keeps whatever
    was recorded so far — frozen slices stay usable.
    """

    def __init__(self, target_url: str, logout_only: bool = False):
        self.target_url = target_url
        # Standalone logout flow: reuses the SAVED login (auto-replayed) and
        # must never persist login steps — only logout config is written.
        self.logout_only = logout_only
        self.error: Optional[str] = None  # worker failure reason, if the window died
        self._raw: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._login_end: Optional[int] = None
        self._logout_start: Optional[int] = None
        self._logout_end: Optional[int] = None
        self._commands: List[Any] = []
        self._close_requested = False
        self._exited = threading.Event()
        self._window_gone = False

    # -- capture (worker thread via JS binding) ---------------------------

    def _on_record_action(self, source, data: Dict[str, Any]) -> None:
        with self._lock:
            self._raw.append(data)

    # -- phase boundaries (HTTP threads) -----------------------------------

    def finish_login(self) -> int:
        """Freeze the login slice. Idempotent — first freeze wins."""
        with self._lock:
            if self._login_end is None:
                self._login_end = len(self._raw)
            return self._login_end

    @property
    def login_frozen(self) -> bool:
        with self._lock:
            return self._login_end is not None

    @property
    def logout_finished(self) -> bool:
        """True once finish_logout() froze a logout slice in this flow run."""
        with self._lock:
            return self._logout_end is not None

    def begin_logout(self) -> bool:
        """Mark logout capture start. Needs frozen login, unless this is a
        standalone logout-only flow (saved login is replayed instead)."""
        with self._lock:
            if self._login_end is None and not self.logout_only:
                return False
            if self._logout_start is None:
                self._logout_start = len(self._raw)
            return True

    def finish_logout(self) -> bool:
        """Freeze the logout slice. False when logout never started."""
        with self._lock:
            if self._logout_start is None:
                return False
            if self._logout_end is None:
                self._logout_end = len(self._raw)
            return True

    def frozen_login_steps(self) -> List[Dict[str, Any]]:
        if self.logout_only:
            return []  # standalone logout never persists login steps
        with self._lock:
            end = self._login_end if self._login_end is not None else len(self._raw)
            raw = list(self._raw[:end])
        return _process_recorded_steps(raw)

    def frozen_logout_steps(self) -> List[Dict[str, Any]]:
        with self._lock:
            if self._logout_start is None:
                return []
            end = self._logout_end if self._logout_end is not None else len(self._raw)
            raw = list(self._raw[self._logout_start:end])
        return _process_recorded_steps(raw)

    def logout_start_url(self) -> Optional[str]:
        """The page URL (query/fragment-stripped by the init script) where the
        first recorded LOGOUT action happened.

        Scan-end logout replay must return to THAT page — the authed home
        carrying the logout control — not the scan target. For many sites the
        scan target IS the bare login form (login navigates away to a
        different app home), and replaying logout steps there left every
        selector unresolvable ("matched 0 elements"). Returns None when no
        logout steps were recorded (or pre-page_url recordings): the caller
        falls back to the scan target, the pre-fix behavior.
        """
        with self._lock:
            if self._logout_start is None:
                return None
            end = self._logout_end if self._logout_end is not None else len(self._raw)
            raw = list(self._raw[self._logout_start:end])
        for step in raw:
            url = (step.get("page_url") or "").strip()
            if url:
                return url
        return None

    @property
    def is_alive(self) -> bool:
        return not self._exited.is_set()

    # -- window commands (queued for the worker thread) ---------------------
    # Playwright calls must run on the worker thread that owns the sync API
    # dispatcher, so HTTP threads queue commands and wait for an ack.

    def _queue_command(self, name: str, payload: Any = None, timeout: float = 30.0) -> Any:
        ack = threading.Event()
        box: Dict[str, Any] = {}
        with self._lock:
            if self._window_gone:
                raise RuntimeError("recording window is closed")
            self._commands.append((name, payload, ack, box))
        if not ack.wait(timeout):
            raise TimeoutError(f"recording window did not respond to {name!r}")
        if isinstance(box.get("error"), Exception):
            raise box["error"]
        return box.get("result")

    def request_navigate(self, url: str) -> bool:
        """Drive the open window to `url`. Returns False (warn-only) on failure."""
        return bool(self._queue_command("navigate", url, timeout=RENDER_TIMEOUT_MS / 1000 + 15))

    def request_rerecord(self) -> bool:
        """Reset capture state in-window and return to the logged-out target."""
        return bool(self._queue_command("rerecord", None, timeout=RENDER_TIMEOUT_MS / 1000 + 15))

    def request_close(self) -> None:
        try:
            self._queue_command("close", None, timeout=15.0)
        except Exception:
            pass  # already gone — teardown is idempotent
        self._exited.wait(15.0)

    def _auto_login_ok(self, page, context) -> bool:
        """Best-effort authenticated check mirroring renderer._login_succeeded."""
        try:
            password_gone = page.query_selector('input[type="password"]') is None
        except Exception:
            password_gone = False
        try:
            moved = page.url.rstrip("/") != self.target_url.rstrip("/")
        except Exception:
            moved = False
        try:
            has_cookies = len(context.cookies()) > 0
        except Exception:
            has_cookies = False
        return moved or password_gone or has_cookies

    def _drain_commands(self, page, context) -> bool:
        """Run queued window commands. Returns False when asked to close."""
        with self._lock:
            pending = self._commands
            self._commands = []
        for name, payload, ack, box in pending:
            try:
                if name == "navigate":
                    try:
                        page.goto(payload, timeout=RENDER_TIMEOUT_MS, wait_until="load")
                        box["result"] = True
                    except Exception:
                        box["result"] = False
                elif name == "rerecord":
                    try:
                        context.clear_cookies()
                        with self._lock:
                            self._raw = []
                            self._login_end = None
                            self._logout_start = None
                            self._logout_end = None
                        page.goto(self.target_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")
                        box["result"] = True
                    except Exception as exc:
                        box["error"] = exc
                elif name == "close":
                    box["result"] = True
                    ack.set()
                    return False
            except Exception as exc:  # never let a command kill the loop silently
                box["error"] = exc
            finally:
                if not ack.is_set():
                    ack.set()
        return True

    def run(self, headless: bool = False, extra_launch_args: Optional[List[str]] = None,
            auto_login: Optional[Dict[str, Any]] = None) -> None:
        """
        Worker entry point: opens the window, captures until closed. With
        auto_login ({steps, username, password, captcha_answer}), the saved
        login is replayed first (standalone logout flow): replay-polluted
        events are dropped, logout capture starts clean, and a failed replay
        closes the window with .error set instead of capturing garbage.
        """
        launch_args = ["--start-maximized"] + list(extra_launch_args or [])
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless, args=launch_args)
                try:
                    context = browser.new_context(**BROWSER_CONTEXT_KWARGS)
                    context.expose_binding(
                        "__recordAction", lambda source, data: self._on_record_action(source, data)
                    )
                    context.add_init_script(_RECORDER_INIT_SCRIPT)
                    page = context.new_page()
                    page.goto(self.target_url, timeout=RENDER_TIMEOUT_MS, wait_until="load")

                    if auto_login is not None:
                        try:
                            replay_login_steps(
                                page, auto_login["steps"],
                                username=auto_login["username"], password=auto_login["password"],
                                captcha_answer=auto_login.get("captcha_answer"),
                            )
                        except Exception as exc:
                            self.error = f"auto-login failed: {type(exc).__name__}: {exc}"
                            return
                        if not self._auto_login_ok(page, context):
                            self.error = ("auto-login did not authenticate "
                                          "(check the username/password) — record a fresh login flow instead")
                            return
                        with self._lock:
                            self._raw.clear()
                            if self.logout_only:
                                self._logout_start = 0

                    # Same dispatcher-pumping rule as LoginRecordingSession:
                    # poll via a real Playwright call so bindings keep firing.
                    poll_ms = 250
                    elapsed_ms = 0
                    keep_open = True
                    while keep_open and not self._close_requested and elapsed_ms < MAX_RECORDING_SECONDS * 1000:
                        try:
                            page.wait_for_timeout(poll_ms)
                        except Exception:
                            break  # window/context/browser closed out from under us
                        elapsed_ms += poll_ms
                        try:
                            keep_open = self._drain_commands(page, context)
                        except Exception as exc:
                            # Unexpected: per-command failures are contained
                            # inside _drain_commands, so reaching here means the
                            # loop itself broke — record it instead of dying silent.
                            self.error = f"recorder loop failed: {type(exc).__name__}: {exc}"
                            logger.exception("flow recorder loop for %r broke", self.target_url)
                            break

                    try:
                        context.close()
                    except Exception:
                        pass
                finally:
                    try:
                        browser.close()
                    except Exception:
                        pass
        except Exception as exc:
            # Surfaced via .error (status endpoint) — never silent: an instant
            # open-and-close means the failure details are the whole diagnosis.
            self.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            with self._lock:
                self._window_gone = True
            self._exited.set()