"""
Central configuration for the Link & Navigation Audit Tool.

Anything here is a tunable default, not a hard architectural decision —
adjust freely as real target sites reveal edge cases.
"""

import re
from urllib.parse import urljoin, urlparse

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


def normalize_backslashes_for_url(raw_value: str, base_url: str) -> str:
    """
    WHATWG URL Standard leniency: for http/https base URLs, a backslash
    ("\\") is treated the same as a forward slash ("/").

    Real targets author Windows-style relative hrefs (e.g.
    "..\\School HQ\\Comdt.html"). Real browsers silently resolve those to
    "../School HQ/Comdt.html" before joining; Python's urljoin does not,
    gluing the raw string on as a literal filename (e.g.
    "/About School/..\\School HQ\\Comdt.html") which 404s and — when the
    404 page itself contains the same navbar — explodes the crawl into
    hundreds/thousands of garbage pages.

    Applied only when the base URL is http/https. raw_value is returned
    unchanged for other schemes (or when there is nothing to fix), and
    the original raw string is always preserved by callers in
    raw_value/code_snippet — only the resolved absolute URL is normalized.
    """
    if not raw_value or "\\" not in raw_value:
        return raw_value
    try:
        scheme = urlparse(base_url).scheme.lower()
    except Exception:
        return raw_value
    if scheme in ("http", "https"):
        return raw_value.replace("\\", "/")
    return raw_value


def normalize_absolute_url(url: str) -> str:
    """
    Same WHATWG rule applied to an already-absolute URL (e.g. a user
    supplied start_url like "https://host\\path\\page", or a redirect
    Location). For http/https URLs, backslashes become forward slashes.
    """
    if not url or "\\" not in url:
        return url
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        return url
    if scheme in ("http", "https"):
        return url.replace("\\", "/")
    return url


def resolve_url(base_url: str, raw_value: str) -> str:
    """
    WHATWG-lenient urljoin: normalize backslashes first, then join.
    This is the only URL-resolution entry point extractor/crawler/
    comment_scanner should use, so the leniency can't be forgotten on
    one code path.
    """
    return urljoin(base_url, normalize_backslashes_for_url(raw_value, base_url))


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

# ---------------------------------------------------------------------------
# Politeness + rate-limit handling (Order 6)
# ---------------------------------------------------------------------------
# Back-to-back bulk checking trips rate limiting on real targets, and every
# 429 used to file as Broken (self-inflicted). Two knobs:
#   CRAWL_REQUEST_DELAY_SECONDS — pause before each check request.
#     Default 0.2s; 0 disables (today's speed). Applied per HTTP request
#     (initial attempt, Order-5 recheck, 429 retries alike).
#   RATE_LIMIT_MAX_RETRIES — how many times to retry a 429 after honoring
#     Retry-After. Default 2 (up to 3 attempts). Still limited afterwards →
#     Broken with evidence "HTTP 429 — Rate limit exceeded (retried)".
#   RATE_LIMIT_DEFAULT_WAIT_SECONDS — wait before a 429 retry when the
#     response carries no (parseable) Retry-After. Default 1.0s.
#   RATE_LIMIT_MAX_WAIT_SECONDS — cap for an absurd Retry-After so one
#     hostile header can't stall a scan for hours. Default 60s.
# Tradeoff: the default delay costs ~+10 min worst case at ~2900 links.
CRAWL_REQUEST_DELAY_SECONDS = 0.2
RATE_LIMIT_MAX_RETRIES = 2
RATE_LIMIT_DEFAULT_WAIT_SECONDS = 1.0
RATE_LIMIT_MAX_WAIT_SECONDS = 60.0

# ---------------------------------------------------------------------------
# Per-scan options (Feature C: settings popover, no persistence)
# ---------------------------------------------------------------------------
# The dialog sends only what the user touched; everything absent falls back
# to the module constants above. resolve_scan_options() validates + fills
# defaults (main.py turns ValueError into HTTP 400). Bounds keep a typo from
# launching a 100k-page crawl or stalling on absurd timeouts. Refresh-safe
# by design: nothing here is stored anywhere.
SCAN_OPTION_BOUNDS = {
    "max_pages": (1, 10000),
    "max_depth": (1, 50),
    "timeout_seconds": (1, 120),
    "delay_seconds": (0.0, 10.0),
}


def _coerce_scan_number(name: str, value, lo, hi):
    """Validates one numeric option: None/absent means the default for that
    option; otherwise must be a real number inside [lo, hi]."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between {lo} and {hi}.")
    number = float(value)
    if not (lo <= number <= hi):
        raise ValueError(f"{name} must be between {lo} and {hi} (got {value}).")
    return number


def _coerce_domain_list(value) -> list:
    """One domain per entry (list) or comma/whitespace-separated text.
    Each must be dot-separated labels of alphanumerics/hyphens. Subdomains
    are covered automatically — "example.com" already excludes
    "sub.example.com" via parent-domain matching, so no wildcards."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [part for part in value.replace(",", " ").split() if part]
    if not isinstance(value, (list, tuple)):
        raise ValueError("excluded_domains must be a list of domains or comma-separated text.")
    cleaned = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError(f"excluded domain must be text, got {entry!r}.")
        host = entry.strip().lower().rstrip(".")
        labels = host.split(".") if host else []
        if not labels or any(
            len(part) == 0 or len(part) > 63 or part.startswith("-") or part.endswith("-")
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in part)
            for part in labels
        ):
            raise ValueError(f"excluded domain looks invalid: {entry!r}.")
        if host not in cleaned:
            cleaned.append(host)
    return sorted(cleaned)


def scan_options_defaults() -> dict:
    """Effective defaults + bounds for the settings popover (GET endpoint)."""
    return {
        "values": {
            "max_pages": MAX_PAGES_PER_SCAN,
            "max_depth": MAX_CRAWL_DEPTH,
            "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
            "delay_seconds": CRAWL_REQUEST_DELAY_SECONDS,
            "headless": False,
            "excluded_domains": sorted(EXCLUDED_DOMAINS),
        },
        "bounds": {
            "max_pages": list(SCAN_OPTION_BOUNDS["max_pages"]),
            "max_depth": list(SCAN_OPTION_BOUNDS["max_depth"]),
            "timeout_seconds": list(SCAN_OPTION_BOUNDS["timeout_seconds"]),
            "delay_seconds": list(SCAN_OPTION_BOUNDS["delay_seconds"]),
        },
    }


def resolve_scan_options(raw) -> dict:
    """Validates a scan-start options object into effective settings.

    `raw` is a dict (or None) with any of: max_pages, max_depth,
    timeout_seconds, delay_seconds, headless, excluded_domains, only_on_ui.
    Absent or null entries fall back to defaults. Raises ValueError on
    anything out of bounds — callers surface it as HTTP 400.
    """
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("scan options must be an object.")
    bounds = SCAN_OPTION_BOUNDS
    max_pages = _coerce_scan_number("max_pages", raw.get("max_pages"), *bounds["max_pages"])
    max_depth = _coerce_scan_number("max_depth", raw.get("max_depth"), *bounds["max_depth"])
    timeout = _coerce_scan_number("timeout_seconds", raw.get("timeout_seconds"), *bounds["timeout_seconds"])
    delay = _coerce_scan_number("delay_seconds", raw.get("delay_seconds"), *bounds["delay_seconds"])
    headless = raw.get("headless", False)
    if headless is None:
        headless = False
    if not isinstance(headless, bool):
        raise ValueError("headless must be true or false.")
    only_on_ui = raw.get("only_on_ui", False)
    if only_on_ui is None:
        only_on_ui = False
    if not isinstance(only_on_ui, bool):
        raise ValueError("only_on_ui must be true or false.")
    return {
        "max_pages": int(max_pages) if max_pages is not None else MAX_PAGES_PER_SCAN,
        "max_depth": int(max_depth) if max_depth is not None else MAX_CRAWL_DEPTH,
        "timeout_seconds": int(timeout) if timeout is not None else REQUEST_TIMEOUT_SECONDS,
        "delay_seconds": float(delay) if delay is not None else float(CRAWL_REQUEST_DELAY_SECONDS),
        "headless": headless,
        "excluded_domains": _coerce_domain_list(raw.get("excluded_domains")),
        "only_on_ui": only_on_ui,
    }

# Excluded link schemes — not web navigation links, excluded from all four
# categories per BUILD_PLAN.md #5 and Item #3.
EXCLUDED_SCHEMES = ("mailto:", "tel:", "javascript:", "blob:")

# Logout-link exclusion — following (or even status-checking) a logout URL
# destroys the very session the scan runs under: many logouts, including this
# test site's /logout, are plain GET links, so a GET check alone logs the scan
# out and every later page lands on the login form. Like EXCLUDED_SCHEMES,
# these produce no finding at all — a working logout is none of
# broken/inactive/ip_based/internet, and checking it would be self-sabotage.
# Matched case-insensitively against any path segment (extension stripped).
LOGOUT_PATH_SEGMENTS = frozenset({
    "logout", "log-out", "log_out",
    "logoff", "log-off", "log_off",
    "signout", "sign-out", "sign_out",
})


def is_logout_url(url: str) -> bool:
    """True if any path segment of `url` names a logout endpoint."""
    if not url:
        return False
    try:
        segments = [seg for seg in urlparse(url).path.split("/") if seg]
    except Exception:
        return False
    for segment in segments:
        if segment.split(".")[0].lower() in LOGOUT_PATH_SEGMENTS:
            return True
    return False

# Domains to completely exclude from scan results and crawling.
# Any link whose host (or parent domain) matches an entry here is silently
# skipped — no finding generated, not enqueued for crawling, not counted.
EXCLUDED_DOMAINS: set = {
    "xyz.com",
}


def is_excluded_domain(host: str, reference_host: str = "", extra=frozenset()) -> bool:
    """
    True if `host` or any of its parent domains are in EXCLUDED_DOMAINS.

    The `reference_host` (the scan target) is always exempt — even if a
    parent domain of the target is in EXCLUDED_DOMAINS, links to the target
    itself must never be excluded or the crawl would skip its own pages.

    `extra` (Feature C) unions per-scan additions from the settings popover
    with the builtins — scans can only exclude more, never un-exclude.
    """
    if not host:
        return False
    host = host.lower().rstrip(".")
    # The target host is always trusted — never exclude it.
    if reference_host and host == reference_host.lower():
        return False
    blocked = set(EXCLUDED_DOMAINS) | {str(d).lower() for d in (extra or ())}
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in blocked:
            return True
    return False

# ---------------------------------------------------------------------------
# Resource URLs — check, never crawl into (Order 3)
# ---------------------------------------------------------------------------
# File-sourced elements (live URLs inside external .css/.js) are always
# resource-only (see comment_scanner.is_file_sourced tagging + crawler gate).
# This set covers the same rule by URL shape: any URL whose path ends with
# one of these extensions is status-checked like any other link but never
# enqueued as a crawl page and never becomes a visited_page.
#
# Categories: images, fonts, audio/video/media, archives/docs, plus css/js
# source files themselves (an <a href="app.js"> is a download, not a page).
# Deliberately NOT included: .html/.htm/.xhtml and extensionless routes
# (CASE 6: /products/cloud, /docs/api, /view/detail) plus server-rendered
# pages (.php/.asp/.aspx/.jsp) — those remain crawlable.
RESOURCE_EXTENSIONS = frozenset({
    # images
    "png", "jpg", "jpeg", "jpe", "gif", "webp", "svg", "svgz", "ico",
    "bmp", "tif", "tiff", "avif", "heic", "heif",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot", "sfnt",
    # audio
    "mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "mid", "midi",
    "weba", "opus",
    # video / media
    "mp4", "webm", "ogv", "avi", "mov", "mpeg", "mpg", "mpe", "flv",
    "wmv", "m4v", "3gp", "3g2", "mkv", "ts", "m3u8", "mpd",
    # archives
    "zip", "tar", "gz", "tgz", "bz2", "xz", "rar", "7z", "jar", "war",
    # documents
    "pdf", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "csv",
    "txt", "rtf", "odt", "ods", "odp",
    # code assets (a direct <a> to one is a download, not a page)
    "css", "js", "mjs", "map",
})


def is_resource_url(url: str) -> bool:
    """True if `url` points at a non-HTML resource by file extension.

    Such URLs are still link-checked (broken 404s still flag) but must
    never be enqueued for crawling and must never appear in visited_pages.
    Returns False for extensionless routes, .html pages, non-http(s)
    schemes (data:/blob:/mailto:/...), and unparseable input.
    Query strings and fragments are ignored: /font.woff2?v=1 counts.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        return False
    path = parsed.path or ""
    # Last path segment only — query/fragment already split off by urlparse.
    segment = path.rsplit("/", 1)[-1]
    if "." not in segment:
        return False
    ext = segment.rsplit(".", 1)[-1].lower()
    return ext in RESOURCE_EXTENSIONS

# ---------------------------------------------------------------------------
# XML namespace identifiers — boilerplate, not links (Order 4)
# ---------------------------------------------------------------------------
# Documents and JS bundles repeat identifiers like
# `http://www.w3.org/2000/svg` as xmlns values or string constants. They
# look like URLs but are never fetched or navigated to.
#
# w3.org is a REAL host, so there is deliberately no blanket host skip.
# The skip is shape + context (enforced in extractor.py and
# comment_scanner.py):
#   shape   = w3.org-family host AND a year-style path (/2000/svg,
#             /1999/xhtml, /1999/xlink, /2000/xmlns/, ...). A genuine
#             reference link like https://www.w3.org/TR/... has no year
#             path and never matches.
#   context = non-navigable code only — external-file live URLs and
#             JS/CSS-string heuristics. A real <a>/<area> href is never
#             skipped, even if its shape matches.
XML_NAMESPACE_HOST_SUFFIX = ".w3.org"
XML_NAMESPACE_YEAR_PATH_RE = re.compile(r"^/(?:19|20)\d{2}/[^/\s]+")


def is_xml_namespace_url(url: str) -> bool:
    """True if `url` has the shape of an XML namespace identifier.

    Matches http(s) URLs on a w3.org-family host whose path starts with a
    year segment (/2000/svg, /1999/xhtml, ...). Returns False for anything
    else — including genuine w3.org reference links (/TR/...) and
    non-http(s) schemes (data:/blob:/...).
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if not (host == "w3.org" or host.endswith(XML_NAMESPACE_HOST_SUFFIX)):
        return False
    return bool(XML_NAMESPACE_YEAR_PATH_RE.match(parsed.path or ""))


# ---------------------------------------------------------------------------
# APEX dynamic-action session endpoints — framework calls, not links
# ---------------------------------------------------------------------------
# APEX pages embed strings like `.../mgs106/2?session=12174141027161`
# inside dynamic-action boilerplate (apex.da.initDaEventList/gEventList).
# They are AJAX endpoints that only work inside their event context — a bare
# GET 404s in both engines — so filing them as Broken Pages is a false
# positive (same class as namespace boilerplate and router globs). The skip
# is context-gated like the namespace one: it applies to non-navigable
# sources only (js-url/css-url heuristics, file-live URLs, non-anchor
# attributes) and never to a real <a>/<area> href.
APEX_SESSION_PATH_RE = re.compile(r"/\d+/?$")
APEX_SESSION_PARAM_RE = re.compile(r"(?:^|[?&])session=\d+(?:&|$)", re.IGNORECASE)


def is_apex_session_url(url: str) -> bool:
    """True if `url` looks like an APEX dynamic-action session endpoint.

    Shape: http(s) URL whose path ends with a numeric segment (e.g.
    `/ords/.../mgs106/2`) and whose query carries a numeric `session=`
    parameter. Returns False for anything else — including genuine page
    URLs that merely contain the word "session" elsewhere.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not APEX_SESSION_PATH_RE.search(parsed.path or ""):
        return False
    return bool(APEX_SESSION_PARAM_RE.search("?" + (parsed.query or "")))

# Safety cap on total pages crawled in a single scan, to avoid a runaway
# crawl on a target with e.g. an infinite calendar widget. Adjustable.
MAX_PAGES_PER_SCAN = 2000

# Maximum crawl depth (distance in hops from the start URL) to prevent
# runaway crawling down deeply nested/cyclical paths (Item #2).
MAX_CRAWL_DEPTH = 15

# Maximum mid-crawl re-logins per dynamic+login scan. When the session dies
# mid-scan and a page fetch lands back on the login form, the worker replays
# the saved login and retries the page — at most this many times, then fails
# loudly instead of silently scanning the login form as authenticated content.
MAX_MID_CRAWL_RELOGINS = 2

# Session, cache-buster, and tracking query parameters stripped during
# URL normalization to prevent crawler duplication loops (Item #2).
STRIPPED_QUERY_PARAMS: set = {
    "sessionid",
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "sid",
    "token",
    "auth_token",
    "access_token",
    "timestamp",
    "ts",
    "_",
    "v",
    "ver",
    "version",
    "cb",
    "cachebuster",
    "nocache",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "_gl",
}

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

# ---------------------------------------------------------------------------
# Server port
# ---------------------------------------------------------------------------
# Port the uvicorn server listens on. Using a non-default port (not 8000)
# so this tool doesn't conflict with other tools on the same VM.
# IMPORTANT: if you change this, also update the port in the launcher
# scripts (start.bat / start.sh) to the same value.
SERVER_PORT = 8765
