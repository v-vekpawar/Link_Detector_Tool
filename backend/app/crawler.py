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
"""

from collections import deque
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests

from app.config import MAX_PAGES_PER_SCAN, classify_host, is_inactive_href
from app.classifier import classify_link
from app.extractor import extract_link_elements

ANCHOR_LIKE_TAGS = ("a", "area")


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
            "findings": [ {found_on_page, link, category, code_snippet,
                            evidence, element_location}, ... ],
            "visited_pages": [str, ...]   # normalized URLs, for inspection/tests
        }

    `progress_callback`, if given, is called after each page finishes
    processing as progress_callback(pages_crawled=int, links_checked=int) —
    used later to drive the SSE progress line (Step 8).

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

    all_findings: List[Dict] = []
    total_links_checked = 0
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
                resp = sess.get(page_url, timeout=10)
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
            total_links_checked += 1
            finding = classify_link(element, reference_ip, session=sess)
            if finding:
                finding = dict(finding, found_on_page=page_url)
                all_findings.append(finding)

            if element.tag not in ANCHOR_LIKE_TAGS:
                continue
            if is_inactive_href(element.raw_value):
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

        if progress_callback:
            progress_callback(pages_crawled=pages_crawled, links_checked=total_links_checked)

    return {
        "pages_crawled": pages_crawled,
        "total_links_checked": total_links_checked,
        "findings": all_findings,
        "visited_pages": sorted(visited_pages),
    }