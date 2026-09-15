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

This is intentionally a thin, linear player — it doesn't try to be clever
about waiting for navigations beyond what Playwright's own auto-waiting
already gives each action (click/fill/check/select_option all wait for
the target to become actionable before acting).
"""

from typing import Any, Dict, List

from playwright.sync_api import Page


class ReplayError(Exception):
    """Raised when a recorded step can't be replayed against the live page."""


def replay_login_steps(
    page: Page,
    steps: List[Dict[str, Any]],
    username: str,
    password: str,
    action_timeout_ms: int = 10000,
) -> None:
    for step in steps:
        action = step.get("action")
        selector = step.get("selector")
        if not selector:
            raise ReplayError(f"Recorded step is missing a selector: {step}")

        if action == "click":
            page.click(selector, timeout=action_timeout_ms)

        elif action == "fill":
            field_type = step.get("field_type")

            if field_type == "username":
                page.fill(selector, username, timeout=action_timeout_ms)

            elif field_type == "password":
                page.fill(selector, password, timeout=action_timeout_ms)

            elif field_type == "other":
                value = step.get("value")
                locator = page.locator(selector).first
                tag = locator.evaluate("el => el.tagName.toLowerCase()")
                input_type = locator.evaluate("el => (el.getAttribute('type') || '').toLowerCase()")

                if tag == "select":
                    page.select_option(selector, value=str(value), timeout=action_timeout_ms)
                elif input_type in ("checkbox", "radio"):
                    if value:
                        page.check(selector, timeout=action_timeout_ms)
                    else:
                        page.uncheck(selector, timeout=action_timeout_ms)
                else:
                    page.fill(selector, "" if value is None else str(value), timeout=action_timeout_ms)

            else:
                raise ReplayError(f"Recorded step has an unrecognized field_type: {step}")

        else:
            raise ReplayError(f"Recorded step has an unrecognized action: {step}")