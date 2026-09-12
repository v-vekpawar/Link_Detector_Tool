"""
Broken-link checking for the Tier 1 engine.

A link is "broken" if: HTTP 4xx/5xx, a timeout, a connection/DNS failure,
or a 200 response whose body matches a known soft-404 marker phrase.
"""

from typing import Optional

import requests

from app.config import (
    REQUEST_TIMEOUT_SECONDS,
    CRAWL_USER_AGENT,
    SOFT_404_MARKERS,
)


def check_link_status(url: str, session: Optional[requests.Session] = None, timeout: Optional[int] = None) -> dict:
    """
    Returns:
        {
            "broken": bool,
            "evidence": str,              # human-readable reason
            "status_code": int | None,
            "response_text": str | None,  # None if the request itself failed
        }
    """
    sess = session or requests
    effective_timeout = timeout if timeout is not None else REQUEST_TIMEOUT_SECONDS
    headers = {"User-Agent": CRAWL_USER_AGENT}

    try:
        resp = sess.get(url, headers=headers, timeout=effective_timeout, allow_redirects=True)
    except requests.exceptions.Timeout:
        return {"broken": True, "evidence": f"Timeout after {effective_timeout}s", "status_code": None, "response_text": None}
    except requests.exceptions.ConnectionError as e:
        return {"broken": True, "evidence": f"Connection failed ({e.__class__.__name__})", "status_code": None, "response_text": None}
    except requests.exceptions.RequestException as e:
        return {"broken": True, "evidence": f"Request failed ({e.__class__.__name__})", "status_code": None, "response_text": None}

    if resp.status_code >= 400:
        return {"broken": True, "evidence": f"HTTP {resp.status_code}", "status_code": resp.status_code, "response_text": resp.text}

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