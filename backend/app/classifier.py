"""
Classification logic for the Tier 1 engine.

Applies the four category rules from BUILD_PLAN.md #5-#6 to a single
extracted link element, and returns a dict shaped like a `findings` row
(minus scan_id/found_on_page, which the caller already knows), or None if
the link is clean.

Design note: if a link is classified as "inactive" (bare trailing "#"), the
broken-status fetch is skipped — a trailing "#" is a no-op placeholder, not
a real navigation target, so there's nothing meaningful to fetch. Flagging
this as an assumption worth confirming, not a silent default.
"""

from typing import Optional, Dict
from urllib.parse import urlparse

import requests

from app.config import is_inactive_href, classify_host, is_excluded_domain
from app.extractor import LinkElement
from app.link_checker import check_link_status

# Only these tags represent user navigation — inactive-by-"#" only makes
# sense for something a user would click to go somewhere.
ANCHOR_LIKE_TAGS = ("a", "area")


def classify_link(
    element: LinkElement,
    reference_ip: str,
    session: Optional[requests.Session] = None,
) -> Optional[Dict]:
    """
    Returns a dict with keys: link, category, code_snippet, evidence,
    element_location — or None if the element has no issues.

    `category` is comma-separated when multiple tags apply (e.g. an
    internet-hosted link that's also unreachable: "internet,broken").
    """
    categories = []
    evidence_parts = []

    is_inactive = element.tag in ANCHOR_LIKE_TAGS and is_inactive_href(element.raw_value)
    if is_inactive:
        categories.append("inactive")
        evidence_parts.append("href ends with #")

    host = urlparse(element.absolute_url).hostname or ""
    host_class = classify_host(host, reference_ip)
    # An excluded domain is known-fine on the private network — just not
    # reachable from here. Suppress only the "internet" tag for it (scope
    # per config.py's is_excluded_domain docstring); ip_based classification
    # is untouched.
    excluded = host_class == "internet" and is_excluded_domain(host)

    if not excluded:
        if host_class == "ip_based":
            categories.append("ip_based")
            evidence_parts.append(f"resolves to {host} (differs from reference IP {reference_ip})")
        elif host_class == "internet":
            categories.append("internet")
            evidence_parts.append(f"references external hostname {host}")

    # Skip the broken-status fetch too when excluded — there's no point
    # checking reachability for a host we already know isn't reachable
    # from this network by design, and doing so would just add a
    # meaningless "broken" tag to a link that's actually fine.
    if not is_inactive and not excluded:
        result = check_link_status(element.absolute_url, session=session)
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