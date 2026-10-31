"""
Login Flow Replay (Step 7c of BUILD_ORDER.md — the other half of the
Login Flow Recorder feature described in ARCHITECTURE.md).

Takes a recorded step list (as produced by login_recorder.py and persisted
in login_configs.recorded_steps) plus the REAL credentials supplied at
scan time, and replays it against a live Playwright page:

- "click" steps are replayed as-is.
- "fill" steps tagged field_type="username" / "password" get the real
  credentials substituted in — the recorded step itself never carried a
  value, only the fact that this selector IS the username/password field.
- "fill" steps tagged field_type="other" (checkboxes, selects, and any
  other non-credential control) get the literal value that was recorded,
  since that's not credential material and needs no substitution.
- "fill" steps tagged field_type="captcha" (a fixed/static captcha field
  on the target) get the target's saved captcha_answer, falling back to
  the literal value recorded during the session if no captcha_answer was
  supplied — same "not credential material, no substitution needed"
  reasoning as "other".
- "hover" steps (recorded with a dwell debounce by login_recorder's
  init script) are replayed best-effort BEFORE the click that depends on
  them: mouse menus that reveal a control only while hovering the parent
  (logout buttons behind avatar menus) stay closed for Playwright's
  otherwise-blind click. A hover step that no longer resolves is logged
  and skipped, never fatal — the following click/fill remains the loud
  checkpoint. Recordings made before hover capture existed have no
  hover steps and replay unchanged.

Anti-autofill readonly inputs: some login forms keep the username field
readonly until a real user focuses it; Playwright's fill checks
editability BEFORE its own focus, so it can never trip that unlock and
times out on "element is not editable". Each fill therefore clears a
readonly attribute first (attribute-only — nothing else changes).

This is intentionally a thin, linear player — it doesn't try to be clever
about waiting for navigations beyond what Playwright's own auto-waiting
already gives each action (click/fill/check/select_option all wait for
the target to become actionable before acting).

Before each action, the recorded selector must resolve to exactly one
element whose tag/text/aria/role still match the recorded fingerprint
(Order 7) — otherwise replay refuses loudly instead of acting on the
wrong element. Pre-fingerprint recordings skip the fingerprint half.
Raw Playwright timeout errors are multi-line call logs; they are
summarized into one actionable cause line ("element is not editable",
...) for UI surfacing — see _summarize_playwright_error.

Frames (Phase A): steps can be recorded inside a login iframe. Each
recorded step carries a frame_url when its capture document was not the
main one; _resolve_step_context routes the action to that frame (bounded
wait, unique-suffix fallback for redirected frames, loud refusal when
gone). Steps without the key replay on the main frame exactly as before.

Shadow DOM (Phase B): selectors recorded from content rendered inside an
open shadow root are composed positional chains (light-DOM head segment
space-joined to the shadow-internal segments); Playwright's css engine
matches them through the shadow boundary implicitly, so no separate
piercing syntax is needed and the same fingerprint check still applies.
"""

from typing import Any, Dict, List, Optional

import logging
import time
from playwright.sync_api import Page
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger("link_audit.login_replay")


class ReplayError(Exception):
    """Raised when a recorded step can't be replayed against the live page."""


# Bounded wait for a recorded step's frame to appear (iframes settle after
# the page; a step fired right after navigation may otherwise race the
# frame's first navigation).
_FRAME_RESOLVE_WAIT_MS = 2500


# Lines a Playwright timeout/print error carries when an element fails its
# actionability check — the last such state in the call log is the real
# reason the step stopped ("element is not editable", "element is not
# visible", ...). Matched against any position so dump format drift
# doesn't silently empty the summary.
_PLAYWRIGHT_STATE_MARKERS = (
    "element is not visible",
    "element is not editable",
    "element is disabled",
    "element is outside of the viewport",
    "element is detached",
    "element is hidden",
    "element does not receive pointer events",
    "element is covered by",
)


def _summarize_playwright_error(exc: Exception, limit: int = 160) -> str:
    """One actionable line from Playwright's multi-line call-log errors.

    Without this, the scan error the user sees is either the first line of
    the dump ("Page.fill: Timeout 10000ms exceeded.") or nothing — neither
    says WHY. The last actionability state line in the call log is the
    real cause; the exception's own first line is the fallback.
    """
    lines = [line.strip().lstrip("-").strip() for line in str(exc).splitlines() if line.strip()]
    cause = next(
        (line for line in reversed(lines) if any(marker in line for marker in _PLAYWRIGHT_STATE_MARKERS)),
        None,
    )
    result = cause or (lines[0] if lines else str(exc))
    return result if len(result) <= limit else result[: limit - 1] + "…"


# Anti-autofill login forms keep the username field readonly until a real
# user interacts with it; the attribute is cleared on focus by the site's
# own JS. Playwright's fill() checks editability BEFORE its own focus, so
# it can never trip that unlock — the only way through is clearing the
# attribute explicitly. Attribute-only: nothing about the form's submit
# behavior changes, and fields without the attribute are untouched.
_READONLY_CLEAR_JS = (
    "el => { if (el.hasAttribute('readonly')) { el.removeAttribute('readonly'); return true; } return false; }"
)


def _ensure_fill_editable(ctx: Any, selector: str, step_no: int) -> None:
    """Clears a `readonly` attribute on a fill target before fill().

    Probe failures are non-fatal — fill() raises its own, properly
    summarized error if something is genuinely wrong. `ctx` is a Page or a
    Frame (Frames Phase A); both share the locator surface.
    """
    try:
        cleared = ctx.locator(selector).first.evaluate(_READONLY_CLEAR_JS)
        if cleared:
            logger.info("  step %d: cleared readonly on %r before fill (anti-autofill field)", step_no, selector)
    except Exception:
        pass


def _normalized_frame_url(url: Optional[str]) -> str:
    """Frame-URL comparison key: fragment stripped, trimmed."""
    return (url or "").split("#", 1)[0].strip()


def _resolve_step_context(page: Page, step: Dict[str, Any], step_no: int) -> Any:
    """
    Frames Phase A: picks the document a recorded step should run against.

    frame_url None/absent → the page itself (every pre-frames recording
    replays unchanged). Otherwise finds the live frame by its recorded
    URL — exact-normalized first, then a bounded unique-suffix match for
    frames that redirected or gained a query string since recording —
    waiting briefly for the frame to appear/load (iframes settle after
    the page). A frame that is simply gone is a loud ReplayError, never
    a silent main-frame reroute.
    """
    frame_url = step.get("frame_url")
    if not frame_url:
        return page
    want = _normalized_frame_url(frame_url)

    def candidates(ctxs: List[Any]) -> List[Any]:
        exact, suffixed = [], []
        for f in ctxs:
            u = _normalized_frame_url(getattr(f, "url", "") or "")
            if not u:
                continue
            if u == want:
                exact.append(f)
            elif want.endswith(u) or u.endswith(want):
                suffixed.append(f)
        return exact or suffixed

    deadline = time.time() + _FRAME_RESOLVE_WAIT_MS / 1000
    while True:
        ctxs = candidates(list(page.frames))
        if ctxs:
            chosen = ctxs[0]
            if len(ctxs) > 1:
                logger.warning(
                    "step %d: frame %r matches %d live frames — using the first (%s)",
                    step_no, want, len(ctxs), _normalized_frame_url(getattr(chosen, "url", "")),
                )
            return chosen
        if time.time() >= deadline:
            raise ReplayError(
                f"Step {step_no}: frame {want!r} is not present on {page.url} — "
                "the page structure changed since recording, re-record the flow."
            )
        try:
            page.wait_for_timeout(250)
        except Exception as exc:
            raise ReplayError(
                f"Step {step_no}: page closed while waiting for frame {want!r}."
            ) from exc


def assert_target_matches(ctx: Any, step: Dict[str, Any], step_no: int) -> None:
    """
    Order 7: refuses a silently-changed target. Resolves step['selector']
    against the STEP's context (page or frame) and requires exactly one
    match whose tag/text/aria-label/role still equal the recorded
    fingerprint. Anything else raises ReplayError (loud, with re-record
    guidance) instead of clicking/filling the wrong element.

    Steps recorded before fingerprints existed have no 'fingerprint' key:
    only the count is checked, and the action proceeds exactly as before.
    """
    selector = step.get("selector")
    locator = ctx.locator(selector)
    try:
        count = locator.count()
    except Exception as exc:
        raise ReplayError(
            f"Step {step_no}: selector {selector!r} could not be resolved "
            f"({type(exc).__name__}: {exc}) — re-record the flow."
        )
    fp = step.get("fingerprint")
    if count != 1:
        want = "recorded <%s>" % ((fp or {}).get("tag") or "?")
        raise ReplayError(
            f"Step {step_no}: selector {selector!r} matched {count} elements, "
            f"expected the {want} — the page changed, re-record the flow."
        )
    if not fp:
        return
    try:
        actual = locator.first.evaluate(
            "el => ({tag: (el.tagName || '').toLowerCase(), "
            "text: ((el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 80)), "
            "aria: el.getAttribute('aria-label') || '', "
            "role: el.getAttribute('role') || ''})"
        )
    except Exception as exc:
        raise ReplayError(
            f"Step {step_no}: could not read back element for selector {selector!r} "
            f"({type(exc).__name__}: {exc}) — re-record the flow."
        )
    for key in ("tag", "text", "aria", "role"):
        if (fp.get(key) or "") != (actual.get(key) or ""):
            raise ReplayError(
                f"Step {step_no}: element for selector {selector!r} no longer matches "
                f"the recording ({key}: recorded {fp.get(key)!r} vs live {actual.get(key)!r}) "
                f"— the page changed, re-record the flow."
            )


def replay_login_steps(
    page: Page,
    steps: List[Dict[str, Any]],
    username: str,
    password: str,
    captcha_answer: Optional[str] = None,
    extra_fields: Optional[Dict[str, str]] = None,
    action_timeout_ms: int = 10000,
    form_url_box: Optional[List[str]] = None,
) -> None:
    """
    Replays recorded steps. When form_url_box (a list) is given, the page URL
    in effect right before the first credential fill (username/password/
    captcha) is appended to it — that is the login form's URL, used by the
    scan worker's mid-crawl re-login guard to recognize an unexpected landing
    on the login page.

    Step kinds: click / fill (curated, credential-substituted), and hover —
    a best-effort enabler recorded with a dwell debounce (see
    login_recorder._RECORDER_INIT_SCRIPT). Playwright action failures are
    re-raised as ReplayError carrying the step number, selector, and the
    summarized cause, so the scan error tells the user exactly where and
    why replay stopped.
    """
    logger.info("replay_login_steps: replaying %d step(s)", len(steps))
    for i, step in enumerate(steps):
        action = step.get("action")
        selector = step.get("selector")
        if not selector:
            raise ReplayError(f"Recorded step is missing a selector: {step}")
        ctx = _resolve_step_context(page, step, i + 1)

        if action == "hover":
            # Best-effort enabler for hover-revealed menus: the pointer must
            # be brought back to the recorded trigger so the target control
            # exists/becomes visible for the click that follows. A stale or
            # unmatched hover step only warns — it never aborts the flow.
            try:
                assert_target_matches(ctx, step, i + 1)
                logger.info("  step %d: hover selector=%r frame=%r", i + 1, selector, step.get("frame_url"))
                ctx.hover(selector, timeout=action_timeout_ms)
            except Exception as exc:
                logger.warning(
                    "  step %d: hover of %r skipped (enabler only) — %s: %s",
                    i + 1, selector, type(exc).__name__, exc,
                )
            continue

        assert_target_matches(ctx, step, i + 1)

        try:
            if action == "click":
                logger.info("  step %d: click selector=%r frame=%r", i + 1, selector, step.get("frame_url"))
                ctx.click(selector, timeout=action_timeout_ms)

            elif action == "fill":
                field_type = step.get("field_type")
                logger.info("  step %d: fill selector=%r field_type=%r frame=%r",
                            i + 1, selector, field_type, step.get("frame_url"))

                if field_type in ("username", "password", "captcha") and form_url_box is not None and not form_url_box:
                    try:
                        # Frame-hosted login forms report their own frame
                        # URL — the mid-crawl guard keys on the form's
                        # document, which is exactly what a frame step
                        # knows. Top-document steps keep the page URL.
                        form_url_box.append(ctx.url or page.url)
                    except Exception:
                        pass

                _ensure_fill_editable(ctx, selector, i + 1)

                if field_type == "username":
                    ctx.fill(selector, username, timeout=action_timeout_ms)

                elif field_type == "password":
                    ctx.fill(selector, "<redacted>", timeout=action_timeout_ms)  # never log the real value
                    ctx.fill(selector, password, timeout=action_timeout_ms)

                elif field_type == "other":
                    value = step.get("value")
                    locator = ctx.locator(selector).first
                    tag = locator.evaluate("el => el.tagName.toLowerCase()")
                    input_type = locator.evaluate("el => (el.getAttribute('type') || '').toLowerCase()")

                    if tag == "select":
                        ctx.select_option(selector, value=str(value), timeout=action_timeout_ms)
                    elif input_type in ("checkbox", "radio"):
                        if value:
                            ctx.check(selector, timeout=action_timeout_ms)
                        else:
                            ctx.uncheck(selector, timeout=action_timeout_ms)
                    else:
                        ctx.fill(selector, "" if value is None else str(value), timeout=action_timeout_ms)

                elif field_type == "extra":
                    # Look up dynamically provided extra field value, or fall back to recorded value
                    val = None
                    if extra_fields:
                        val = (
                            extra_fields.get(selector)
                            or (step.get("name") and extra_fields.get(step["name"]))
                            or (step.get("label") and extra_fields.get(step["label"]))
                        )
                    if val is None:
                        val = step.get("value", "")
                    ctx.fill(selector, "" if val is None else str(val), timeout=action_timeout_ms)

                elif field_type == "captcha":
                    # Legacy compatibility: check extra_fields, then saved captcha_answer, then recorded value
                    val = None
                    if extra_fields:
                        val = (
                            extra_fields.get(selector)
                            or (step.get("name") and extra_fields.get(step["name"]))
                            or (step.get("label") and extra_fields.get(step["label"]))
                            or extra_fields.get("captcha")
                        )
                    if val is None:
                        val = captcha_answer if captcha_answer is not None else step.get("value")
                    if val is None:
                        raise ReplayError(
                            f"Step {i + 1} needs a captcha answer but none is available — no "
                            "captcha_answer was supplied and none was recorded for this field."
                        )
                    ctx.fill(selector, str(val), timeout=action_timeout_ms)

                else:
                    raise ReplayError(f"Recorded step has an unrecognized field_type: {step}")

            else:
                raise ReplayError(f"Recorded step has an unrecognized action: {step}")
        except PlaywrightTimeoutError as exc:
            raise ReplayError(
                f"Step {i + 1} ({action} {selector!r}) timed out after {action_timeout_ms}ms — "
                f"{_summarize_playwright_error(exc)}"
            ) from exc

    logger.info("replay_login_steps: all %d step(s) completed", len(steps))


def replay_logout_steps(
    page: Page,
    steps: List[Dict[str, Any]],
    action_timeout_ms: int = 10000,
) -> None:
    """
    Replays a recorded logout step sequence against `page`.

    Mirrors replay_login_steps: click/fill plus best-effort hover steps
    (hover-revealed logout menus), readonly cleared before fills, and
    Playwright action timeouts surfaced as ReplayError with the stopping
    step and summarized cause. If a step turns out to have field_type
    username/password/captcha, that's a recording mistake and we raise
    ReplayError rather than silently ignoring it, since substituting a
    credential into a logout form would be wrong.
    """
    logger.info("replay_logout_steps: replaying %d step(s)", len(steps))
    for i, step in enumerate(steps):
        action = step.get("action")
        selector = step.get("selector")
        if not selector:
            raise ReplayError(f"Logout step is missing a selector: {step}")

        if action == "hover":
            # Same best-effort enabler semantics as login replay: skip with
            # a warning when it no longer resolves; the real boundary is the
            # click that follows.
            try:
                ctx = _resolve_step_context(page, step, i + 1)
                assert_target_matches(ctx, step, i + 1)
                logger.info("  logout step %d: hover selector=%r frame=%r", i + 1, selector, step.get("frame_url"))
                ctx.hover(selector, timeout=action_timeout_ms)
            except Exception as exc:
                logger.warning(
                    "  logout step %d: hover of %r skipped (enabler only) — %s: %s",
                    i + 1, selector, type(exc).__name__, exc,
                )
            continue

        ctx = _resolve_step_context(page, step, i + 1)
        assert_target_matches(ctx, step, i + 1)

        try:
            if action == "click":
                logger.info("  logout step %d: click selector=%r frame=%r", i + 1, selector, step.get("frame_url"))
                ctx.click(selector, timeout=action_timeout_ms)

            elif action == "fill":
                field_type = step.get("field_type", "other")
                logger.info("  logout step %d: fill selector=%r field_type=%r frame=%r",
                            i + 1, selector, field_type, step.get("frame_url"))
                if field_type in ("username", "password", "captcha"):
                    raise ReplayError(
                        f"Logout step {i + 1} has field_type={field_type!r} — "
                        "logout recordings must not contain credential fields."
                    )
                _ensure_fill_editable(ctx, selector, i + 1)
                value = step.get("value")
                locator = ctx.locator(selector).first
                tag = locator.evaluate("el => el.tagName.toLowerCase()")
                input_type = locator.evaluate("el => (el.getAttribute('type') || '').toLowerCase()")
                if tag == "select":
                    ctx.select_option(selector, value=str(value), timeout=action_timeout_ms)
                elif input_type in ("checkbox", "radio"):
                    if value:
                        ctx.check(selector, timeout=action_timeout_ms)
                    else:
                        ctx.uncheck(selector, timeout=action_timeout_ms)
                else:
                    ctx.fill(selector, "" if value is None else str(value), timeout=action_timeout_ms)

            else:
                raise ReplayError(f"Logout step has an unrecognized action: {step}")
        except PlaywrightTimeoutError as exc:
            raise ReplayError(
                f"Logout step {i + 1} ({action} {selector!r}) timed out after {action_timeout_ms}ms — "
                f"{_summarize_playwright_error(exc)}"
            ) from exc

    logger.info("replay_logout_steps: all %d step(s) completed", len(steps))