"""
Broken-link checking for the Tier 1 engine.

A link is "broken" if: HTTP 4xx/5xx, a timeout, a connection/DNS failure,
or a 200 response whose body matches a known soft-404 marker phrase.
"""

from typing import Optional

import datetime
import email.utils
import html as _html
import json
import re
import time

import requests
import urllib3
import logging

# Target VMs commonly use self-signed certificates.  Disable SSL verification
# globally for all requests made by this tool and silence the warning that
# urllib3 would otherwise print on every single request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.config import (
    REQUEST_TIMEOUT_SECONDS,
    CRAWL_USER_AGENT,
    SOFT_404_MARKERS,
    CRAWL_REQUEST_DELAY_SECONDS,
    RATE_LIMIT_MAX_RETRIES,
    RATE_LIMIT_DEFAULT_WAIT_SECONDS,
    RATE_LIMIT_MAX_WAIT_SECONDS,
)

logger = logging.getLogger("link_audit.link_checker")

ERROR_MESSAGE_MAX_LENGTH = 150

# Only the head of an error body is ever inspected — real error pages state
# their message up front, and this bounds work on huge responses.
ERROR_BODY_SCAN_LIMIT = 16384


def _clean_message(text: str) -> str:
    """Collapses whitespace, drops control characters, unescapes entities,
    truncates for table cells."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text or "")
    text = _html.unescape(re.sub(r"\s+", " ", text).strip())
    if len(text) > ERROR_MESSAGE_MAX_LENGTH:
        return text[: ERROR_MESSAGE_MAX_LENGTH - 1] + "…"
    return text


def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text or "")


def extract_error_message(body: str) -> Optional[str]:
    """
    Best-effort human message from a 4xx/5xx response body, or None when the
    body carries nothing readable. Priority: HTML <title>/<h1>, then a JSON
    message/error/detail field, then the first text line.
    """
    head = (body or "")[:ERROR_BODY_SCAN_LIMIT]
    if not head.strip():
        return None
    if "\x00" in head:
        return None  # binary payload — no readable message in it

    for pattern in (r"<title[^>]*>(.*?)</title>", r"<h1[^>]*>(.*?)</h1>"):
        match = re.search(pattern, head, re.IGNORECASE | re.DOTALL)
        if match:
            message = _clean_message(_strip_tags(match.group(1)))
            if message:
                return message

    stripped = head.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        # A JSON body speaks through its message fields, if it has any —
        # never dump the raw payload as the message.
        try:
            data = json.loads(stripped)
        except Exception:
            data = None
        if isinstance(data, dict):
            for key in ("message", "error", "detail", "msg"):
                value = data.get(key)
                if isinstance(value, dict):
                    for nested in ("message", "error", "detail"):
                        if isinstance(value.get(nested), str) and value[nested].strip():
                            return _clean_message(value[nested])
                if isinstance(value, str) and value.strip():
                    return _clean_message(value)
        return None

    for line in _strip_tags(head).splitlines():
        line = line.strip()
        if line and re.search(r"[A-Za-z0-9]", line):
            return _clean_message(line)

    return None


def _request_error_result(exc: Exception, effective_timeout: int, url: str) -> dict:
    """Shapes a requests exception as a broken-link result (same evidence
    strings as the inline handlers this replaced)."""
    if isinstance(exc, requests.exceptions.Timeout):
        logger.warning("Timeout after %ss checking: %s", effective_timeout, url)
        return {"broken": True, "evidence": f"Timeout after {effective_timeout}s", "status_code": None, "response_text": None}
    if isinstance(exc, requests.exceptions.SSLError):
        # SSLError subclasses ConnectionError — checked first on purpose.
        logger.error("SSL certificate error checking %s — %s", url, exc)
        return {"broken": True, "evidence": f"SSL error ({exc.__class__.__name__})", "status_code": None, "response_text": None}
    if isinstance(exc, requests.exceptions.ConnectionError):
        logger.warning("Connection failed for %s — %s: %s", url, type(exc).__name__, exc)
        return {"broken": True, "evidence": f"Connection failed ({exc.__class__.__name__})", "status_code": None, "response_text": None}
    logger.warning("Request failed for %s — %s: %s", url, type(exc).__name__, exc)
    return {"broken": True, "evidence": f"Request failed ({exc.__class__.__name__})", "status_code": None, "response_text": None}


def _retry_after_seconds(value: Optional[str]) -> float:
    """Waits before a 429 retry: the response's Retry-After (delta-seconds
    or HTTP-date), else RATE_LIMIT_DEFAULT_WAIT_SECONDS. Capped at
    RATE_LIMIT_MAX_WAIT_SECONDS; never negative."""
    if value:
        text = value.strip()
        try:
            return max(0.0, min(float(text), RATE_LIMIT_MAX_WAIT_SECONDS))
        except ValueError:
            pass
        try:
            when = email.utils.parsedate_to_datetime(text)
            if when is not None:
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
                delta = (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                return max(0.0, min(delta, RATE_LIMIT_MAX_WAIT_SECONDS))
        except (ValueError, TypeError, OverflowError):
            pass
    return RATE_LIMIT_DEFAULT_WAIT_SECONDS


def check_link_status(url: str, session: Optional[requests.Session] = None, timeout: Optional[int] = None, referer: Optional[str] = None, delay: Optional[float] = None) -> dict:
    """
    Returns:
        {
            "broken": bool,
            "evidence": str,              # human-readable reason
            "status_code": int | None,
            "response_text": str | None,  # None if the request itself failed
        }

    `referer` (Order 5) is sent as the Referer header — the found-on page.
    Harmless everywhere, required by hotlink/session-style gates. The caller
    (classifier → crawler) passes the page or asset URL the link was found on.

    `delay` (Order 6) pauses before each HTTP request attempt. None means
    CRAWL_REQUEST_DELAY_SECONDS; 0 disables (today's speed).
    """
    sess = session or requests
    effective_timeout = timeout if timeout is not None else REQUEST_TIMEOUT_SECONDS
    effective_delay = CRAWL_REQUEST_DELAY_SECONDS if delay is None else delay
    headers = {"User-Agent": CRAWL_USER_AGENT}
    if referer:
        headers["Referer"] = referer

    def _fetch_once():
        if effective_delay > 0:
            time.sleep(effective_delay)
        return sess.get(url, headers=headers, timeout=effective_timeout, allow_redirects=True, verify=False)

    def _fetch_with_rate_limit():
        """One logical fetch: up to 1 + RATE_LIMIT_MAX_RETRIES HTTP tries,
        honoring Retry-After on 429. Returns (resp, None), or
        (None, error_result) when the target stays limited or the request
        itself fails."""
        resp = None
        for attempt in range(1 + RATE_LIMIT_MAX_RETRIES):
            try:
                resp = _fetch_once()
            except requests.exceptions.RequestException as exc:
                return None, _request_error_result(exc, effective_timeout, url)
            if resp.status_code != 429 or attempt == RATE_LIMIT_MAX_RETRIES:
                break
            wait = _retry_after_seconds(resp.headers.get("Retry-After"))
            logger.info("HTTP 429 for %s — honoring Retry-After, waiting %.1fs (retry %d/%d)",
                        url, wait, attempt + 1, RATE_LIMIT_MAX_RETRIES)
            time.sleep(wait)
        if resp.status_code == 429:
            return None, {"broken": True, "evidence": "HTTP 429 — Rate limit exceeded (retried)",
                          "status_code": 429, "response_text": resp.text}
        return resp, None

    resp, err = _fetch_with_rate_limit()
    if err is not None:
        return err

    if resp.status_code in (400, 404):
        # Order 5: ONE recheck with full context (live session jar + Referer)
        # before filing Broken — narrows the extract→check decay window for
        # short-lived checksums/tokens. A repeated 400/404 still files Broken:
        # no special-casing that would mask real 404s.
        resp, err = _fetch_with_rate_limit()
        if err is not None:
            return err

    if resp.status_code >= 400:
        body_text = resp.text or ""
        detail = extract_error_message(body_text)
        if detail:
            evidence = f"HTTP {resp.status_code} — {detail}"
        elif body_text.strip():
            evidence = f"HTTP {resp.status_code}"
        else:
            evidence = f"HTTP {resp.status_code} — empty response body"
        return {"broken": True, "evidence": evidence, "status_code": resp.status_code, "response_text": resp.text}

    body_lower = resp.text.lower()
    for marker in SOFT_404_MARKERS:
        if marker in body_lower:
            return {
                "broken": True,
                "evidence": f'Soft-404 marker matched: "{marker}"',
                "status_code": resp.status_code,
                "response_text": resp.text,
            }

    return {"broken": False, "evidence": f"HTTP {resp.status_code} OK", "status_code": resp.status_code, "response_text": resp.text}