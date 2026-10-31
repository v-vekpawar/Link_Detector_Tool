"""
Classification logic for the Tier 1 engine.

Applies the four category rules from BUILD_PLAN.md #5-#6 to a single
extracted link element, and returns a dict shaped like a `findings` row
(minus scan_id/found_on_page, which the caller already knows), or None if
the link is clean.

Design note: if a link is classified as "inactive" (any href ending with "#"), the
broken-status fetch is skipped — a trailing "#" is a no-op placeholder, not
a real navigation target, so there's nothing meaningful to fetch.

Design note: internet links (external hostnames) also skip the broken check.
They are external to the private network being audited and are expected to be
unreachable from the scan host, so a "broken" tag on them would be misleading.
IP-based links (different VM on the internal network) still get the broken check.
"""

import base64
import binascii
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

from app.config import EXCLUDED_SCHEMES, is_inactive_href, classify_host, is_logout_url
from app.extractor import LinkElement
from app.link_checker import check_link_status

# Only these tags represent user navigation — inactive-by-"#" only makes
# sense for something a user would click to go somewhere. frame/iframe are
# deliberately NOT here: a frame src is a document load, not a click
# target, so an "#" frame src has no business being tagged inactive.
# (crawler.py keeps the navigation twin of this tuple WITH frame/iframe.) 
ANCHOR_LIKE_TAGS = ("a", "area")


def validate_data_uri(uri: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a data: URI structurally per RFC 2397.
    Returns (is_valid, error_reason).
    """
    if not uri.lower().startswith("data:"):
        return False, "Not a data: URI"

    rest = uri[5:]
    if "," not in rest:
        return False, "Malformed data URI: missing comma separating metadata from payload"

    meta, data = rest.split(",", 1)
    meta_parts = [p.strip() for p in meta.split(";") if p.strip()]

    is_b64 = False
    if meta_parts and meta_parts[-1].lower() == "base64":
        is_b64 = True
        meta_parts = meta_parts[:-1]

    media_type = meta_parts[0].lower() if meta_parts else ""
    if media_type:
        if "/" not in media_type and not media_type.startswith("charset="):
            return False, f"Malformed media type in data URI: '{media_type}'"

    if is_b64:
        try:
            clean_data = re.sub(r"\s+", "", data)
            decoded = base64.b64decode(clean_data, validate=True)
            if media_type == "image/png" and len(decoded) >= 8:
                if decoded[:8] != b"\x89PNG\r\n\x1a\n":
                    return False, "Data URI declared image/png but header does not match PNG signature"
            elif media_type in ("image/jpeg", "image/jpg") and len(decoded) >= 2:
                if decoded[:2] != b"\xff\xd8":
                    return False, "Data URI declared image/jpeg but header does not match JPEG signature"
            elif media_type == "image/gif" and len(decoded) >= 6:
                if decoded[:6] not in (b"GIF87a", b"GIF89a"):
                    return False, "Data URI declared image/gif but header does not match GIF signature"
        except (binascii.Error, ValueError) as e:
            return False, f"Malformed base64 payload in data URI: {e}"

    return True, None


def classify_link(
    element: LinkElement,
    reference_ip: str,
    session: Optional[requests.Session] = None,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    delay: Optional[float] = None,
) -> Optional[Dict]:
    """
    Returns a dict with keys: link, category, code_snippet, evidence,
    element_location — or None if the element has no issues.

    `category` is comma-separated when multiple tags apply (e.g. an
    internet-hosted link that's also unreachable: "internet,broken").

    `referer` (Order 5) is the found-on page, forwarded as the Referer
    header on the status check. `timeout`/`delay` (Feature C) override the
    checker defaults; None means the configured default.
    """
    # Non-network schemes (blob:/mailto:/tel:/javascript:) are in-memory or
    # client-only — never a network-checkable resource. Dropped entirely so
    # urlparse's empty hostname can't fall through to "internet".
    # Defense-in-depth: extractor already filters these, but classifier must
    # not misclassify them if one ever arrives directly.
    if element.absolute_url.lower().startswith(EXCLUDED_SCHEMES):
        return None

    # Logout links are never reported: checking/following one would destroy
    # the scan's own authenticated session (see config.is_logout_url).
    if is_logout_url(element.absolute_url):
        return None

    # Item #3: Data URLs contain inline data rather than a network address.
    # Validate structurally; only surface as a finding when malformed.
    if element.absolute_url.lower().startswith("data:"):
        is_valid, error_reason = validate_data_uri(element.absolute_url)
        if not is_valid:
            display_link = (
                element.absolute_url
                if len(element.absolute_url) <= 120
                else element.absolute_url[:120] + "… [data truncated]"
            )
            return {
                "link": display_link,
                "category": "data_uri",
                "code_snippet": element.code_snippet,
                "evidence": error_reason or "malformed data URI",
                "element_location": element.element_location,
            }
        return None

    categories = []
    evidence_parts = []

    is_inactive = element.tag in ANCHOR_LIKE_TAGS and is_inactive_href(element.raw_value)
    if is_inactive:
        categories.append("inactive")
        evidence_parts.append("href ends with #")

    host = urlparse(element.absolute_url).hostname or ""
    host_class = classify_host(host, reference_ip)
    if host_class == "ip_based":
        categories.append("ip_based")
        evidence_parts.append(f"resolves to {host} (differs from reference IP {reference_ip})")
    elif host_class == "internet":
        categories.append("internet")
        evidence_parts.append(f"references external hostname {host}")

    if not is_inactive and host_class != "internet":
        # Internet links are always external to this private network and are
        # expected to be unreachable from the scan host — skip the broken
        # check so they never get tagged "internet,broken" just because the
        # VM can't reach the public web. IP-based links are on the internal
        # network so they still get checked.
        result = check_link_status(element.absolute_url, session=session, referer=referer, timeout=timeout, delay=delay)
        if result["broken"]:
            categories.append("broken")
            evidence_parts.append(result["evidence"])

    if not categories:
        return None

    return {
        "link": element.absolute_url,
        "category": ",".join(categories),
        "code_snippet": element.code_snippet,
        "evidence": "; ".join(evidence_parts),
        "element_location": element.element_location,
    }