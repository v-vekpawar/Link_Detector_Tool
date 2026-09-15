"""
Central configuration for the Link & Navigation Audit Tool.

Anything here is a tunable default, not a hard architectural decision —
adjust freely as real target sites reveal edge cases.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference IP handling
# ---------------------------------------------------------------------------
# The "reference IP" for a scan is derived from the target_url the user enters
# at scan setup (one VM = one app, per BUILD_PLAN.md #3). It is NOT hardcoded
# here — it's computed per-scan in the crawler — but the helpers and rules
# for recognizing/comparing IPs live in one place so classification logic
# elsewhere just calls into this module.

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


def extract_reference_ip(target_url: str) -> str:
    """
    Derive the reference IP from the user-supplied target URL.
    Assumes the user enters the target as an IP (e.g. https://10.0.0.1),
    consistent with "one VM = one app, port 443 only" (BUILD_PLAN.md #3).
    """
    host = urlparse(target_url).hostname or ""
    return host


# ---------------------------------------------------------------------------
# Excluded domains
# ---------------------------------------------------------------------------
# Hostnames that are valid/working on the private network but simply aren't
# reachable from this VM (or any machine on the public-facing side of the
# network) — e.g. an internal-only service the target site happens to
# reference. These should NOT be flagged as "internet" links, and are
# omitted from the findings entirely (not just re-labeled), since they're
# known-fine, not an issue to report.
#
# Exact hostname match only (no wildcard/subdomain matching). Edit this set
# per deployment as real target sites reveal domains that need excluding.
#
# Example: EXCLUDED_DOMAINS = {"xyz.abc", "internal-crm.corp"}
EXCLUDED_DOMAINS: set = set()


def is_excluded_domain(host: str) -> bool:
    """True if `host` is an exact (case-insensitive) match in EXCLUDED_DOMAINS."""
    if not host:
        return False
    return host.strip().lower() in {d.lower() for d in EXCLUDED_DOMAINS}


def classify_host(host: str, reference_ip: str) -> str:
    """
    Returns one of: "same" | "ip_based" | "internet"
    - same: host matches the reference target (normal internal link, keep crawling)
    - ip_based: host is a literal IP, but different from reference_ip
    - internet: host is a real hostname (not an IP), and isn't the reference target itself

    The tool's designed usage is a literal-IP reference target (one VM = one
    app, per BUILD_PLAN.md #3) — that's the `is_literal_ip(host)` branch
    below, unchanged. The hostname-equality check right after it is a
    convenience addition for testing against a real domain (e.g.
    lumen5.com) instead of an internal VM's IP: without it, EVERY same-site
    link on a hostname target gets misclassified "internet" (since it's
    never a literal IP) and is never followed, so the crawl can't get past
    the first page. This doesn't change literal-IP behavior at all — a
    hostname link still can't equal a literal-IP reference_ip.
    """
    if is_literal_ip(host):
        return "same" if host == reference_ip else "ip_based"
    if host.lower() == (reference_ip or "").lower():
        return "same"
    return "internet"


# ---------------------------------------------------------------------------
# Inactive-link rule
# ---------------------------------------------------------------------------
# href ends with a literal "#" -> inactive. "#section" (real anchor) is NOT
# inactive. Trailing whitespace is stripped before the check.

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