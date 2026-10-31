"""
BFS crawl loop for the Tier 1 engine.

Scoped to pages on the reference IP only (per BUILD_PLAN.md: one VM = one
app). Links to other hosts (ip_based / internet) are recorded as findings
but never followed.

Design notes (flagging as decisions, not silent defaults):
- Logout links (any path segment naming a logout endpoint — see
  config.is_logout_url) are skipped entirely: not counted, never fetched,
  never followed, no finding. Touching one would destroy the scan's own
  authenticated session mid-crawl, after which every later page lands on
  the login form.
- A link already classified "inactive" (bare trailing "#") is not enqueued
  for crawling — same reasoning as classifier.py: it's a no-op placeholder,
  not a real navigation target.
- A link already classified "broken" (from the classify_link check done
  while processing its parent page) is not enqueued either — no point
  trying to crawl into a page we already know doesn't resolve.
- The visited/queued set is keyed on the URL with its fragment stripped, so
  "page.html", "page.html#section1", and "page.html#other" all count as the
  same page for crawl purposes.
- Every page also gets comment-scanned (HTML comments, plus the presence
  of its own <style>/<script> blocks and inline style=""/on*="" attributes,
  plus commented-out markup inside all of those) via comment_scanner.py.
  Those go into `findings` too, tagged commented_link / internal_css /
  inline_css / internal_js / inline_js — presence and dead code only (no
  status check), so the API layer (main.py) splits them out into a separate
  "Code Findings" bucket rather than mixing them into the live Links results.
- Any external .css/.js file referenced from a page (same-host only, like
  everything else this crawler follows) gets fetched once per scan and split
  in two: commented-out markup becomes commented_link findings, and every
  live URL inside becomes a Links-tab element (status-checked like embedded
  links, found_on_page = the asset URL, never crawled into — Order 3
  resource-only). File-sourced elements and resource-extension URLs
  (config.is_resource_url) are checked but never enqueued, so they never
  appear in visited_pages; embedded onclick/inline-script navigation
  (CASE 7) stays crawlable.
"""

from collections import deque
import hashlib
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import logging
logger = logging.getLogger("link_audit.crawler")

from app.config import (
    MAX_PAGES_PER_SCAN,
    MAX_CRAWL_DEPTH,
    CRAWL_USER_AGENT,
    STRIPPED_QUERY_PARAMS,
    classify_host,
    is_excluded_domain,
    is_inactive_href,
    is_logout_url,
    is_resource_url,
    normalize_absolute_url,
)
from app.classifier import classify_link
from app.extractor import extract_link_elements
from app.comment_scanner import extract_page_comment_findings, fetch_external_asset_split

# Tags whose link attribute makes the URL a navigation target the crawl
# may follow into (anchors/areas, plus <frame>/<iframe> src — frame-based
# intranet apps render their chrome and content through frame documents,
# and those srcs are the ONLY way into them).
ANCHOR_LIKE_TAGS = ("a", "area", "frame", "iframe")

# Extractor tags used for elements that came from embedded/inline CSS or
# JS rather than a literal href/src attribute — see extractor.py.
JS_URL_ATTRIBUTES = ("css-url", "js-url")

# Residual statuses eligible for live-browser arbitration (dynamic scans).
# Only same-host 400/401/403/404 after check+recheck go to the browser:
# off-host never (session rule), logout/excluded never, timeouts/429s keep
# their existing paths.
_VERDICT_STATUSES = ("400", "401", "403", "404")


def _verdict_eligible(finding: Optional[Dict], absolute_url: str, reference_ip: str, extra_excluded) -> bool:
    """True when a Broken finding qualifies for browser arbitration."""
    if not finding or not browser_verdict_eligible_category(finding):
        return False
    try:
        host = urlparse(absolute_url).hostname or ""
        if classify_host(host, reference_ip) != "same":
            return False
        if is_logout_url(absolute_url):
            return False
        if is_excluded_domain(host, reference_ip, extra_excluded):
            return False
        evidence = finding.get("evidence") or ""
        return any(s in evidence for s in _VERDICT_STATUSES)
    except Exception:
        return False


def browser_verdict_eligible_category(finding: Dict) -> bool:
    try:
        return "broken" in (finding.get("category") or "").split(",")
    except Exception:
        return False


def _is_navigable(element) -> bool:
    """
    True if this element represents an in-page navigation link worth
    following during the crawl, as opposed to a resource reference (img
    src, script src, link href, form action) that only gets a
    broken-link check, never crawled into.

    Order 3 — resource-only gates (checked first, before tag logic):
    - file-sourced elements (live URLs from external .css/.js,
      is_file_sourced=True) are never navigable — status-checked only.
    - URLs ending in a resource extension (config.is_resource_url:
      font/image/audio/video/archive/doc/css/js) are never navigable,
      regardless of tag — an <a href="report.pdf"> is still checked
      for 404 but never crawled into as a page.

    Real anchors/areas are navigable by tag, as before. Elements whose
    only link came from extractor.py's heuristics — an inline event
    handler (onclick, onload, ...), an internal/inline CSS url(...), or
    an internal <script> block — are navigable too, regardless of what
    tag they're written on. Per spec, these count as full citizens: they
    get status-checked (like any other link) and followed into if they
    resolve to a same-host page. Embedded (non-file) heuristics keep
    crawling (CASE 7: onclick -> /services).
    """
    if getattr(element, "is_file_sourced", False):
        return False
    try:
        if is_resource_url(getattr(element, "absolute_url", "")):
            return False
    except Exception:
        pass
    if element.tag in ANCHOR_LIKE_TAGS:
        return True
    if element.attribute.startswith("on"):
        return True
    if element.attribute in JS_URL_ATTRIBUTES:
        return True
    return False


def _external_asset_url(element) -> Optional[str]:
    """
    If `element` is a reference to an external .css/.js file (a <link
    href> stylesheet or a <script src>), returns its absolute URL so the
    caller can fetch it and comment-scan its contents. Returns None for
    everything else (page navigation links, images, forms, ...) — those
    aren't assets whose *text* we'd scan.
    """
    if element.tag == "link" and element.attribute == "href":
        return element.absolute_url
    if element.tag == "script" and element.attribute == "src":
        return element.absolute_url
    return None


def _comment_finding_dict(cf) -> Dict:
    """
    Shapes a comment_scanner.CommentFinding as a findings-table row.
    category is one of comment_scanner's five constants (commented_link /
    internal_css / inline_css / internal_js / inline_js), so the frontend
    can offer per-category filtering within the Code Findings tab, the same
    way it filters Links by broken/inactive/etc.
    """
    return {
        "found_on_page": cf.source_url,
        "link": cf.absolute_url,
        "category": cf.category,
        "code_snippet": cf.code_snippet,
        "evidence": f"found in {cf.category.replace('_', ' ')} (raw: {cf.raw_value})",
        "element_location": cf.element_location,
    }


def _normalize_url(url: str) -> str:
    """
    Normalizes a URL for deduplication and crawling (Item #2):
      0. WHATWG leniency: backslashes become forward slashes for
         http/https URLs (defense-in-depth — extractor already resolves
         this way, but start_url/redirects/edge paths must converge too).
      1. Strips fragment (#...).
      2. Lowercases scheme and hostname.
      3. Normalizes path (collapses consecutive slashes, removes trailing slash unless root /).
      4. Strips tracking / session / cache-buster query parameters (STRIPPED_QUERY_PARAMS).
      5. Sorts remaining query parameters alphabetically by key and value.
    """
    if not url:
        return ""
    url = normalize_absolute_url(url)
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    filtered_params = []
    if parsed.query:
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            k_lower = k.lower()
            if k_lower in STRIPPED_QUERY_PARAMS or k_lower.startswith("utm_"):
                continue
            filtered_params.append((k, v))
        filtered_params.sort(key=lambda item: (item[0], item[1]))

    normalized_query = urlencode(filtered_params) if filtered_params else ""

    return urlunparse((scheme, netloc, path, parsed.params, normalized_query, ""))


def _content_fingerprint(html: str, elements: List[Any]) -> str:
    """
    Computes a content fingerprint to detect duplicate pages served under
    different URLs (e.g. aliases, session token variants). Uses the sorted
    canonical set of target links extracted from the page.
    """
    links = sorted(set(e.absolute_url for e in elements))
    link_data = "\n".join(links)
    if not link_data:
        link_data = html[:2000]
    return hashlib.sha256(link_data.encode("utf-8", errors="ignore")).hexdigest()


def _broken_visible_on_page(
    element_absolute_url: str,
    finding: Dict[str, Any],
    page_url: str,
    only_on_ui: bool,
    ui_visibility: Optional[Dict[str, set]],
) -> bool:
    """
    "Only on UI" gate — returns True when this finding row should SURVIVE.

    Non-broken classifications always survive (the gate exists purely to
    keep broken rows out unless the link is visible in the rendered UI).
    With only_on_ui on, a broken-class row survives only when the page's
    visible-anchor set (ui_visibility[page_url]) contains the element's
    resolved URL — normalized on both sides, so browser-resolved hrefs and
    extractor-urljoin values compare equal. A page with no visibility entry
    (external css/js file findings, runtime captures) has no visible
    anchors by definition → suppressed.
    """
    if not only_on_ui:
        return True
    if "broken" not in (finding.get("category") or "").split(","):
        return True
    if not ui_visibility:
        return False
    visible = ui_visibility.get(page_url)
    if not visible:
        return False
    visible_norm = {_normalize_url(u) for u in visible if u}
    target = _normalize_url(element_absolute_url or "")
    if not target:
        return False
    return target in visible_norm


def crawl_site(
    start_url: str,
    reference_ip: str,
    max_pages: int = MAX_PAGES_PER_SCAN,
    max_crawl_depth: int = MAX_CRAWL_DEPTH,
    session: Optional[requests.Session] = None,
    progress_callback=None,
    page_html_fetcher=None,
    stop_event=None,
    timeout: Optional[int] = None,
    delay: Optional[float] = None,
    excluded_domains=None,
    browser_verdict=None,
    browser_capture_drainer=None,
    only_on_ui: bool = False,
    ui_visibility: Optional[Dict[str, set]] = None,
) -> Dict:
    """
    Runs a breadth-first crawl starting at `start_url`, following only
    same-host navigation links, and returns:
        {
            "pages_crawled": int,
            "total_links_checked": int,
            "total_commented_found": int,
            "findings": [ {found_on_page, link, category, code_snippet,
                            evidence, element_location}, ... ],
            "visited_pages": [str, ...],
            "stopped": bool (True if a stop was requested mid-crawl — the
                             findings/pages above are then partial)
        }

    When stop_event (a threading.Event) is set, the loop breaks between
    pages at the next opportunity — an in-flight page fetch or link check
    still runs to completion first.

    only_on_ui / ui_visibility implement the "Only on UI" gate for dynamic
    scans: finding rows carrying the `broken` tag are kept only when a
    VISIBLE <a href> on the same page resolves to the finding's link URL
    (ui_visibility maps page_url → set of visible anchor hrefs, filled by
    the renderer). Off-UI sources — inline script strings, comments, hidden
    elements, runtime captures, file-sourced assets — stay excluded, while
    inactive/ip_based/internet/data_uri classifications are unchanged. The
    check itself still runs for every URL (verdicts feed the other
    categories); only which broken ROWS surface is gated, and the enqueue
    logic still sees the original broken verdict.
    """
    logger.info(
        "Crawl starting — start_url=%s reference=%s max_pages=%d max_depth=%d",
        start_url, reference_ip, max_pages, max_crawl_depth,
    )

    sess = session or requests.Session()
    # Order 5: this ONE session serves both page fetches and link checks, so
    # cookies set by the target's own responses (session/checksum jars) are
    # automatically present on every check. Do not split fetching and
    # checking across sessions. Cookies set by JavaScript (document.cookie)
    # never enter this jar — such targets need a dynamic scan (see README).
    # Feature C: per-scan extras union with the builtins (never un-exclude).
    extra_excluded = frozenset(d.lower() for d in (excluded_domains or ()))

    # WHATWG leniency for the entry point too: a user-pasted start URL
    # with Windows separators must fetch/crawl as its slash form.
    start_url = normalize_absolute_url(start_url)

    visited_pages = set()
    visited_fingerprints = set()
    queue = deque([(start_url, 0)])
    queued_normalized = {_normalize_url(start_url)}
    scanned_assets = set()  # dedupe: fetch+scan each external .css/.js file once per scan
    seen_captured = set()  # normalized runtime off-host URLs already filed
    existing_keys = set()  # (link, found_on_page) already filed via extractor

    all_findings: List[Dict] = []
    total_links_checked = 0
    total_commented_found = 0
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        if stop_event is not None and stop_event.is_set():
            logger.info(
                "Stop requested — ending crawl early at pages=%d links=%d",
                pages_crawled, total_links_checked,
            )
            break
        page_url, depth = queue.popleft()
        normalized_page = _normalize_url(page_url)
        if normalized_page in visited_pages:
            continue
        if is_resource_url(page_url):
            # Order 8: asset-extension URLs are never pages — absent from
            # visited_pages and never counted. Normally unreachable (the
            # enqueue gate already blocks them; only a resource start_url
            # lands here, bypassing the gate). Still link-checked: that
            # happens at extraction time, not here.
            continue
        visited_pages.add(normalized_page)

        if page_html_fetcher is not None:
            fetch_result = page_html_fetcher(page_url)
            # page_html_fetcher is DynamicSession.render: (html, success) or
            # (html, success, final_url). Prefer final_url as extraction base
            # so relative links resolve like the browser does after redirects.
            if len(fetch_result) == 3:
                html, success, final_url = fetch_result
                base_url = final_url if isinstance(final_url, str) and final_url else page_url
            else:
                html, success = fetch_result
                base_url = page_url
            pages_crawled += 1
            if not success or html is None:
                # Render failed outright — nothing to extract, can't recurse further.
                logger.warning("Render failed (returned None/False) for page: %s", page_url)
                continue
        else:
            try:
                resp = sess.get(page_url, timeout=10, headers={"User-Agent": CRAWL_USER_AGENT}, verify=False)
            except requests.exceptions.RequestException as exc:
                # Page itself unreachable — nothing to extract, can't recurse further.
                logger.warning("Page fetch failed for %s — %s: %s", page_url, type(exc).__name__, exc)
                pages_crawled += 1
                continue

            pages_crawled += 1

            content_type = resp.headers.get("Content-Type", "")
            looks_like_html = "html" in content_type or resp.text.strip().lower().startswith(("<!doctype", "<html"))
            if not looks_like_html:
                # Order 3 non-HTML skip: an extensionless, embedded URL the
                # enqueue gate could not judge (e.g. /api/v1/data returning
                # JSON — CASE 20d) is not a page. Evict it so visited_pages
                # holds pages only (Order 3 verify). It stays counted as an
                # attempt in pages_crawled and stays link-checked; page-count
                # rules are Order 8's track. Re-fetch is still prevented by
                # queued_normalized, which retains the URL.
                visited_pages.discard(normalized_page)
                continue
            html = resp.text
            # Use final URL after redirects (e.g. /public -> /public/) as the
            # base for relative resolution — matches browser behavior. A bare
            # /public base would otherwise resolve "win/..." to /win/... .
            base_url = getattr(resp, "url", None) or page_url
            if not isinstance(base_url, str):
                base_url = page_url

        elements = extract_link_elements(html, base_url)

        # Content fingerprint check: if this page's link structure matches an
        # already-visited page, record its findings but skip re-enqueuing its links
        # to avoid duplicate branch exploration (Item #2).
        page_fp = _content_fingerprint(html, elements)
        is_duplicate_fp = (len(elements) > 0 and page_fp in visited_fingerprints)
        if not is_duplicate_fp and elements:
            visited_fingerprints.add(page_fp)
        elif is_duplicate_fp:
            logger.info(
                "Page %s matches content fingerprint of an already-visited page — skipping link re-enqueue",
                page_url,
            )

        can_enqueue_children = (not is_duplicate_fp) and (depth < max_crawl_depth)
        if depth >= max_crawl_depth:
            logger.info("Max crawl depth (%d) reached at %s — skipping further link enqueuing", max_crawl_depth, page_url)

        def _try_enqueue(abs_url: str, raw_value: str, finding: Optional[Dict], current_url: str) -> None:
            """
            Shared enqueue gate for page elements and external-asset live links.
            Inactive ("#" hrefs) enqueue only a different same-host base page;
            broken targets never enqueue; off-host targets never enqueue.
            Order 3: resource-extension URLs never enqueue (checked, not crawled).
            File-sourced elements never reach here (_is_navigable blocks them).
            """
            try:
                if is_resource_url(abs_url):
                    return
            except Exception:
                pass
            if is_inactive_href(raw_value):
                # The href is inactive (ends with "#"), so we don't follow it
                # as a navigation target. However, if the base URL (fragment
                # stripped) points to a *different* same-host page, enqueue
                # that page so any issues on it are still discovered.
                base_normalized = _normalize_url(abs_url)
                current_normalized = _normalize_url(current_url)
                if base_normalized != current_normalized:
                    base_host = urlparse(abs_url).hostname or ""
                    if (classify_host(base_host, reference_ip) == "same"
                            and base_normalized not in visited_pages
                            and base_normalized not in queued_normalized):
                        queued_normalized.add(base_normalized)
                        queue.append((abs_url, depth + 1))
                return

            if finding and "broken" in finding["category"].split(","):
                return

            host = urlparse(abs_url).hostname or ""
            if classify_host(host, reference_ip) != "same":
                return

            target_normalized = _normalize_url(abs_url)
            if target_normalized in visited_pages or target_normalized in queued_normalized:
                return
            queued_normalized.add(target_normalized)
            queue.append((abs_url, depth + 1))

        for element in elements:
            # Skip links to excluded domains — but never exclude the target host itself
            elem_host = urlparse(element.absolute_url).hostname or ""
            if is_excluded_domain(elem_host, reference_ip, extra_excluded):
                continue
            # Skip logout links entirely (not counted, never fetched or
            # followed): touching one would destroy the scan's own session.
            if is_logout_url(element.absolute_url):
                continue

            total_links_checked += 1
            finding = classify_link(element, reference_ip, session=sess, referer=page_url, timeout=timeout, delay=delay)
            if finding and _verdict_eligible(finding, element.absolute_url, reference_ip, extra_excluded) and browser_verdict is not None:
                try:
                    verdict = browser_verdict(element.absolute_url, page_url)
                except Exception:
                    verdict = None
                if verdict is True:
                    logger.info("Browser verdict clean for %s — dropping Broken", element.absolute_url)
                    finding = None
                elif verdict is False:
                    finding = dict(finding, evidence=(finding.get("evidence") or "") + " (live-browser recheck confirms)")
                # None/ambiguous: keep original verdict untouched.
            if finding:
                if _broken_visible_on_page(
                    element.absolute_url, finding, page_url, only_on_ui, ui_visibility
                ):
                    finding = dict(finding, found_on_page=page_url)
                    all_findings.append(finding)
                    try:
                        existing_keys.add((finding["link"], finding["found_on_page"]))
                    except Exception:
                        pass
                # else: "Only on UI" gate — the check itself ran (its verdict
                # feeds enqueue logic below and the non-broken categories);
                # no visible <a> on this page points at the URL, so the
                # broken row stays out of the results.

            asset_url = _external_asset_url(element)
            if asset_url is not None:
                asset_normalized = _normalize_url(asset_url)
                asset_host = urlparse(asset_url).hostname or ""
                if asset_normalized not in scanned_assets and classify_host(asset_host, reference_ip) == "same":
                    scanned_assets.add(asset_normalized)
                    asset_comments, asset_live = fetch_external_asset_split(asset_url, session=sess)
                    for cf in asset_comments:
                        total_commented_found += 1
                        all_findings.append(_comment_finding_dict(cf))
                    # Live URLs inside the file are Links-tab citizens:
                    # status-checked, found_on_page = the file, never crawled
                    # into (Order 3 resource-only: _is_navigable blocks
                    # is_file_sourced elements).
                    for live_el in asset_live:
                        live_host = urlparse(live_el.absolute_url).hostname or ""
                        if is_excluded_domain(live_host, reference_ip, extra_excluded):
                            continue
                        if is_logout_url(live_el.absolute_url):
                            continue
                        total_links_checked += 1
                        live_finding = classify_link(live_el, reference_ip, session=sess, referer=asset_url, timeout=timeout, delay=delay)
                        if live_finding and _broken_visible_on_page(
                            live_el.absolute_url, live_finding, asset_url,
                            only_on_ui, ui_visibility,
                        ):
                            live_finding = dict(live_finding, found_on_page=asset_url)
                            all_findings.append(live_finding)
                        if not can_enqueue_children or not _is_navigable(live_el):
                            continue
                        _try_enqueue(live_el.absolute_url, live_el.raw_value, live_finding, asset_url)

            if not can_enqueue_children or not _is_navigable(element):
                continue

            _try_enqueue(element.absolute_url, element.raw_value, finding, page_url)

        for cf in extract_page_comment_findings(html, page_url):
            total_commented_found += 1
            all_findings.append(_comment_finding_dict(cf))

        if browser_capture_drainer is not None:
            try:
                captures = browser_capture_drainer() or []
            except Exception:
                captures = []
            for cap in captures:
                try:
                    url = (cap.get("url") or "").strip()
                    if not url.lower().startswith(("http://", "https://")):
                        continue
                    if "*" in url:
                        continue
                    host = urlparse(url).hostname or ""
                    host_class = classify_host(host, reference_ip)
                    if host_class == "same":
                        continue
                    if is_logout_url(url):
                        continue
                    if is_excluded_domain(host, reference_ip, extra_excluded):
                        continue
                    norm = _normalize_url(url)
                    if norm in seen_captured:
                        continue
                    if (url, page_url) in existing_keys:
                        seen_captured.add(norm)
                        continue
                    seen_captured.add(norm)
                    status = cap.get("status")
                    if host_class == "internet":
                        ev = f"references external hostname {host}"
                        if isinstance(status, int):
                            ev += f" (browser HTTP {status})"
                        total_links_checked += 1
                        cf = {
                            "found_on_page": page_url,
                            "link": url,
                            "category": "internet",
                            "code_snippet": "",
                            "evidence": ev,
                            "element_location": "Runtime network request",
                        }
                        all_findings.append(cf)
                        existing_keys.add((url, page_url))
                    elif host_class == "ip_based":
                        if not isinstance(status, int):
                            continue
                        total_links_checked += 1
                        if status >= 400:
                            cf = {
                                "found_on_page": page_url,
                                "link": url,
                                "category": "ip_based,broken",
                                "code_snippet": "",
                                "evidence": f"resolves to {host} (differs from reference IP {reference_ip}); browser HTTP {status}",
                                "element_location": "Runtime network request",
                            }
                        else:
                            cf = {
                                "found_on_page": page_url,
                                "link": url,
                                "category": "ip_based",
                                "code_snippet": "",
                                "evidence": f"resolves to {host} (differs from reference IP {reference_ip}); browser HTTP {status}",
                                "element_location": "Runtime network request",
                            }
                        if _broken_visible_on_page(
                            url, cf, page_url, only_on_ui, ui_visibility
                        ):
                            all_findings.append(cf)
                            existing_keys.add((url, page_url))
                except Exception:
                    continue

        if progress_callback:
            progress_callback(
                pages_crawled=pages_crawled,
                links_checked=total_links_checked,
                frontier_size=len(queue),
            )

    logger.info(
        "Crawl finished — pages=%d links=%d findings=%d commented=%d",
        pages_crawled, total_links_checked, len(all_findings), total_commented_found,
    )
    return {
        "pages_crawled": pages_crawled,
        "total_links_checked": total_links_checked,
        "total_commented_found": total_commented_found,
        "findings": all_findings,
        "visited_pages": sorted(visited_pages),
        "stopped": stop_event is not None and stop_event.is_set(),
    }