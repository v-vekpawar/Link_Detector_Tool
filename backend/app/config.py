"""
Central configuration for the Link & Navigation Audit Tool.

Anything here is a tunable default, not a hard architectural decision —
adjust freely as real target sites reveal edge cases.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference host handling
# ---------------------------------------------------------------------------
# The "reference host" for a scan is derived from the target_url the user
# enters at scan setup. It can be a literal IPv4 address (e.g. "10.0.0.1")
# OR a hostname (e.g. "portal.company.local"). Classification logic
# elsewhere calls into this module to determine how a discovered link
# relates to the scan target.

IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def is_literal_ip(host: str) -> bool:
    """True if `host` is a literal IPv4 address (not a hostname)."""
    if not host:
        return False
    match = IPV4_PATTERN.match(host)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _parent_domain(host: str) -> str:
    """Return the parent domain of a hostname (everything after the first label).
    e.g. 'abc.company.local' -> 'company.local', 'company.local' -> 'company.local'.
    For a single-label host or an IP, returns the host itself."""
    parts = host.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else host


def extract_reference_host(target_url: str) -> str:
    """
    Derive the reference host from the user-supplied target URL.
    Works for both IP-based targets (e.g. https://10.0.0.1) and
    hostname-based targets (e.g. http://portal.company.local).
    """
    return urlparse(target_url).hostname or ""


# Keep the old name as an alias so any external callers aren't broken.
extract_reference_ip = extract_reference_host


def classify_host(host: str, reference_host: str) -> str:
    """
    Returns one of: "same" | "ip_based" | "internet"

    When the reference host is a literal IP:
      - same IP        → "same"
      - different IP   → "ip_based"
      - any hostname   → "internet"

    When the reference host is a hostname (e.g. "abc.company.local"):
      - same hostname OR same parent domain ("*.company.local") → "same"
      - any literal IP                                           → "ip_based"
      - any other hostname                                       → "internet"
    """
    host = host.lower()
    ref = reference_host.lower()

    if is_literal_ip(ref):
        # Reference is an IP — original behaviour unchanged.
        if is_literal_ip(host):
            return "same" if host == ref else "ip_based"
        return "internet"

    # Reference is a hostname.
    if is_literal_ip(host):
        # Literal IP links are always a different machine.
        return "ip_based"
    # Same hostname, or same parent domain (e.g. ref="abc.company.local",
    # host="other.company.local" → both share "company.local").
    ref_parent = _parent_domain(ref)
    host_parent = _parent_domain(host)
    if host == ref or (ref_parent == host_parent and len(ref_parent.split(".")) >= 2):
        return "same"
    return "internet"


# ---------------------------------------------------------------------------
# Inactive-link rule
# ---------------------------------------------------------------------------
# Any href that ends with a literal "#" is treated as inactive — it signals
# a placeholder/no-op navigation intent. "#section" (a real in-page anchor)
# is NOT inactive because the fragment is non-empty.
# Note: even though "page.html#" is flagged inactive, the crawler will still
# enqueue the base page (page.html) for crawling when it's a different URL.

def is_inactive_href(href: str) -> bool:
    if href is None:
        return False
    return href.strip().endswith("#")


# ---------------------------------------------------------------------------
# Soft-404 detection
# ---------------------------------------------------------------------------
# Matched case-insensitively against the text content of a page that returned
# HTTP 200 but is actually a generic error/placeholder page. This is a
# starting list — extend it as real target sites reveal their own phrasing.
SOFT_404_MARKERS = [
    "page not found",
    "404 not found",
    "404 error",
    "page does not exist",
    "page you requested could not be found",
    "the page you are looking for",
    "content not found",
    "resource not found",
    "we couldn't find that page",
    "this page doesn't exist",
    "oops! that page can't be found",
]

# If a candidate error page's visible text is shorter than this, and it
# matches a marker above, we treat it as a soft-404 with higher confidence
# (avoids false-flagging a long, legitimate page that happens to mention
# "not found" in passing, e.g. a search results page with zero hits).
SOFT_404_MAX_BODY_LENGTH_FOR_HIGH_CONFIDENCE = 2000


# ---------------------------------------------------------------------------
# Network / crawl defaults
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = 10
CRAWL_USER_AGENT = "LinkAuditTool/1.0 (+internal pre-deployment vetting)"

# Excluded link schemes — not web navigation links, excluded from all four
# categories per BUILD_PLAN.md #5.
EXCLUDED_SCHEMES = ("mailto:", "tel:", "javascript:")

# Domains to completely exclude from scan results and crawling.
# Any link whose host (or parent domain) matches an entry here is silently
# skipped — no finding generated, not enqueued for crawling, not counted.
EXCLUDED_DOMAINS: set = {
    "army.mil",
}


def is_excluded_domain(host: str, reference_host: str = "") -> bool:
    """
    True if `host` or any of its parent domains are in EXCLUDED_DOMAINS.

    The `reference_host` (the scan target) is always exempt — even if a
    parent domain of the target is in EXCLUDED_DOMAINS, links to the target
    itself must never be excluded or the crawl would skip its own pages.
    """
    if not host:
        return False
    host = host.lower().rstrip(".")
    # The target host is always trusted — never exclude it.
    if reference_host and host == reference_host.lower():
        return False
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in EXCLUDED_DOMAINS:
            return True
    return False

# Safety cap on total pages crawled in a single scan, to avoid a runaway
# crawl on a target with e.g. an infinite calendar widget. Adjustable.
MAX_PAGES_PER_SCAN = 2000

# Progress-estimate warm-up window (BUILD_PLAN.md #14): number of pages
# crawled before the rolling time estimate starts being shown.
PROGRESS_WARMUP_PAGES = 8

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
DATABASE_PATH = "link_audit.db"

# Populated at deploy time on the offline VM after `playwright install
# chromium` has been run on an internet-connected machine and the browser
# cache copied over.
PLAYWRIGHT_BROWSERS_PATH_ENV_VAR = "PLAYWRIGHT_BROWSERS_PATH"
