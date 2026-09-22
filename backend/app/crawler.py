"""
BFS crawl loop for the Tier 1 engine.

Scoped to pages on the reference IP only (per BUILD_PLAN.md: one VM = one
app). Links to other hosts (ip_based / internet) are recorded as findings
but never followed.

Design notes (flagging as decisions, not silent defaults):
- A link already classified "inactive" (bare trailing "#") is not enqueued
  for crawling — same reasoning as classifier.py: it's a no-op placeholder,
  not a real navigation target.
- A link already classified "broken" (from the classify_link check done
  while processing its parent page) is not enqueued either — no point
  trying to crawl into a page we already know doesn't resolve.
- The visited/queued set is keyed on the URL with its fragment stripped, so
  "page.html", "page.html#section1", and "page.html#other" all count as the
  same page for crawl purposes.
- Every page also gets comment-scanned (HTML comments, plus JS/CSS
  comments inside its own <style>/<script> blocks and inline
  style=""/on*="" attributes) via comment_scanner.py. Those go into
  `findings` too, tagged with one of comment_scanner's category
  constants (commented_link / internal_css_comment / etc.) — they're
  informational (no status check, never enqueued for crawling), so the
  API layer (main.py) splits them out into a separate "Commented Code"
  bucket rather than mixing them into the live Links results.
- Any external .css/.js file referenced from a page (same-host only, like
  everything else this crawler follows) gets fetched once per scan and
  comment-scanned too — comment scanning is the one thing that reaches
  into external files; live link extraction deliberately does not
  (see extractor.py's module docstring).
"""

from collections import deque
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests

from app.config import MAX_PAGES_PER_SCAN, CRAWL_USER_AGENT, classify_host, is_excluded_domain, is_inactive_href
from app.classifier import classify_link
from app.extractor import extract_link_elements
from app.comment_scanner import extract_page_comment_findings, fetch_and_scan_external_asset

ANCHOR_LIKE_TAGS = ("a", "area")

# Extractor tags used for elements that came from embedded/inline CSS or
# JS rather than a literal href/src attribute — see extractor.py.
JS_URL_ATTRIBUTES = ("css-url", "js-url")


def _is_navigable(element) -> bool:
    """
    True if this element represents an in-page navigation link worth
    following during the crawl, as opposed to a resource reference (img
    src, script src, link href, form action) that only gets a
    broken-link check, never crawled into.

    Real anchors/areas are navigable by tag, as before. Elements whose
    only link came from extractor.py's heuristics — an inline event
    handler (onclick, onload, ...), an internal/inline CSS url(...), or
    an internal <script> block — are navigable too, regardless of what
    tag they're written on. Per spec, these count as full citizens: they
    get status-checked (like any other link) and followed into if they
    resolve to a same-host page.
    """
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
    category is already one of comment_scanner's seven category constants
    (commented_link / internal_css_comment / inline_css_comment /
    external_css_comment / internal_js_comment / inline_js_comment /
    external_js_comment), so the frontend can offer per-category
    filtering within the Commented Code tab, the same way it filters
    Links by broken/inactive/etc.
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
    """Strip the fragment so '#'-variants of the same page dedup to one entry."""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))


def crawl_site(
    start_url: str,
    reference_ip: str,
    max_pages: int = MAX_PAGES_PER_SCAN,
    session: Optional[requests.Session] = None,
    progress_callback=None,
    page_html_fetcher=None,
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
                          # category="commented" entries are informational
                          # (comment_scanner.py) and mixed into this same
                          # list; main.py splits them into a separate
                          # "Commented Code" bucket for the API response.
            "visited_pages": [str, ...]   # normalized URLs, for inspection/tests
        }

    `progress_callback`, if given, is called after each page finishes
    processing as progress_callback(pages_crawled=int, links_checked=int,
    frontier_size=int) — frontier_size is the number of pages still queued
    but not yet crawled at that moment, used by Step 8's rolling time
    estimate (avg_time_per_page * frontier_size, per ARCHITECTURE.md).

    `page_html_fetcher`, if given, is a callable(url) -> (html, success)
    used instead of a plain `requests` GET to fetch each page's HTML for
    *parsing/extraction* — this is the Tier 2 (Playwright) hand-off for
    Dynamic site scans, so JS-injected links are present before extraction
    runs. Per-link broken-status checks still always go through Tier 1
    (`requests`, via classify_link) regardless of site type — only the
    initial page fetch-for-parsing is swapped out. Defaults to None
    (plain `requests`, i.e. Static site behavior, unchanged from Step 4).
    """
    sess = session or requests.Session()

    visited_pages = set()
    queue = deque([start_url])
    queued_normalized = {_normalize_url(start_url)}
    scanned_assets = set()  # dedupe: fetch+scan each external .css/.js file once per scan

    all_findings: List[Dict] = []
    total_links_checked = 0
    total_commented_found = 0
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        page_url = queue.popleft()
        normalized_page = _normalize_url(page_url)
        if normalized_page in visited_pages:
            continue
        visited_pages.add(normalized_page)

        if page_html_fetcher is not None:
            html, success = page_html_fetcher(page_url)
            pages_crawled += 1
            if not success or html is None:
                # Render failed outright — nothing to extract, can't recurse further.
                continue
        else:
            try:
                resp = sess.get(page_url, timeout=10, headers={"User-Agent": CRAWL_USER_AGENT})
            except requests.exceptions.RequestException:
                # Page itself unreachable — nothing to extract, can't recurse further.
                # (If it was reached via a link, that link's own broken-check already
                # produced a finding on its parent page.)
                pages_crawled += 1
                continue

            pages_crawled += 1

            content_type = resp.headers.get("Content-Type", "")
            looks_like_html = "html" in content_type or resp.text.strip().lower().startswith(("<!doctype", "<html"))
            if not looks_like_html:
                continue
            html = resp.text

        elements = extract_link_elements(html, page_url)
        for element in elements:
            # Skip links to excluded domains — but never exclude the target host itself
            elem_host = urlparse(element.absolute_url).hostname or ""
            if is_excluded_domain(elem_host, reference_ip):
                continue

            total_links_checked += 1
            finding = classify_link(element, reference_ip, session=sess)
            if finding:
                finding = dict(finding, found_on_page=page_url)
                all_findings.append(finding)

            asset_url = _external_asset_url(element)
            if asset_url is not None:
                asset_normalized = _normalize_url(asset_url)
                asset_host = urlparse(asset_url).hostname or ""
                if asset_normalized not in scanned_assets and classify_host(asset_host, reference_ip) == "same":
                    scanned_assets.add(asset_normalized)
                    for cf in fetch_and_scan_external_asset(asset_url, session=sess):
                        total_commented_found += 1
                        all_findings.append(_comment_finding_dict(cf))

            if not _is_navigable(element):
                continue
            if is_inactive_href(element.raw_value):
                # The href is inactive (ends with "#"), so we don't follow it
                # as a navigation target. However, if the base URL (fragment
                # stripped) points to a *different* same-host page, enqueue
                # that page so any issues on it are still discovered.
                # A bare "#" strips to the current page's URL — nothing new to enqueue.
                base_normalized = _normalize_url(element.absolute_url)
                current_normalized = _normalize_url(page_url)
                if base_normalized != current_normalized:
                    base_host = urlparse(element.absolute_url).hostname or ""
                    if (classify_host(base_host, reference_ip) == "same"
                            and base_normalized not in visited_pages
                            and base_normalized not in queued_normalized):
                        queued_normalized.add(base_normalized)
                        queue.append(element.absolute_url)
                continue
            if finding and "broken" in finding["category"].split(","):
                continue

            host = urlparse(element.absolute_url).hostname or ""
            if classify_host(host, reference_ip) != "same":
                continue

            target_normalized = _normalize_url(element.absolute_url)
            if target_normalized in visited_pages or target_normalized in queued_normalized:
                continue
            queued_normalized.add(target_normalized)
            queue.append(element.absolute_url)

        for cf in extract_page_comment_findings(html, page_url):
            total_commented_found += 1
            all_findings.append(_comment_finding_dict(cf))

        if progress_callback:
            progress_callback(
                pages_crawled=pages_crawled,
                links_checked=total_links_checked,
                frontier_size=len(queue),
            )

    return {
        "pages_crawled": pages_crawled,
        "total_links_checked": total_links_checked,
        "total_commented_found": total_commented_found,
        "findings": all_findings,
        "visited_pages": sorted(visited_pages),
    }