"""
Comment-code scanner — feeds the "Commented Code" result tab.

Five categories only:
  commented_link — dead markup left in a comment of any HTML, CSS, or JS file
  internal_css   — presence of an internal <style> block (one finding per block)
  inline_css     — presence of an inline style="" attribute (one per attribute)
  internal_js    — presence of an internal <script> block without src (one per block)
  inline_js      — presence of an inline on* handler attribute (one per attribute)

Live URLs are NEVER reported here — not from embedded code and not from
external files. Every live URL (href/src/action, JS call, CSS url(), whether
embedded or inside a same-host .css/.js file) goes to the Links tab via the
extractor/classifier pipeline, where it gets a real status check
(broken/inactive/ip_based/internet). The *_css/*_js presence entries above
fire once per block/attribute even when it contains zero URLs.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup, Comment

from app.config import CRAWL_USER_AGENT, EXCLUDED_SCHEMES, REQUEST_TIMEOUT_SECONDS, normalize_backslashes_for_url, resolve_url, is_apex_session_url
from app.extractor import (
    LINK_BEARING_ATTRS,
    LinkElement,
    _build_css_path,
    _document_order_map,
    _position_label,
    extract_base_url,
    find_css_urls,
    find_js_urls,
    strip_css_comments,
    strip_js_comments,
)

JS_LINE_COMMENT = re.compile(r"(?<!:)//([^\n]*)")
BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.DOTALL)

COMMENTED_LINK = "commented_link"
INTERNAL_CSS = "internal_css"
INLINE_CSS = "inline_css"
INTERNAL_JS = "internal_js"
INLINE_JS = "inline_js"


@dataclass
class CommentFinding:
    source_url: str         # page the finding was found in
    category: str           # one of the category constants above
    raw_value: str
    absolute_url: str
    code_snippet: str
    element_location: str


def _normalize_backslashes(raw_value: str, source_url: str) -> str:
    """Backward-compat alias for config.normalize_backslashes_for_url."""
    return normalize_backslashes_for_url(raw_value, source_url)


def _clean(raw_value):
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if not raw_value:
        return None
    if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
        return None
    if "*" in raw_value:
        # Order 4 (file-URL path): router globs (/*, ...) are not real URLs.
        return None
    return raw_value


def _markup_links_in_text(text: str, source_url: str, base_url: str = None) -> List[CommentFinding]:
    findings: List[CommentFinding] = []
    try:
        frag = BeautifulSoup(text, "lxml")
    except Exception:
        return findings
    effective_base = base_url or source_url
    for tag_name, attr_name in LINK_BEARING_ATTRS:
        for tag in frag.find_all(tag_name):
            cleaned = _clean(tag.get(attr_name))
            if cleaned is None:
                continue
            findings.append(
                CommentFinding(
                    source_url=source_url,
                    category=COMMENTED_LINK,
                    raw_value=cleaned,
                    absolute_url=resolve_url(effective_base, cleaned),
                    code_snippet=str(tag)[:300],
                    element_location="comment",
                )
            )
    return findings


BARE_URL_IN_COMMENT = re.compile(r"https?://[^\s'\"<>]+")
_BARE_URL_TRAILING = ".,;:!?)]}\"'"


def _bare_url_comment_findings(text: str, source_url: str, base_url: str = None) -> List[CommentFinding]:
    """Bare URL strings inside comment text (-> commented_link).

    License headers and doc strings (e.g. http://jquery.org/license) are
    plain text with no markup tags, so the markup pass above never fires
    for them — without this they land nowhere (comments are stripped
    before live-URL extraction, so the Links tab never sees them either).
    Informational only; comment content is never status-checked.
    """
    findings: List[CommentFinding] = []
    if not text:
        return findings
    effective_base = base_url or source_url
    seen = set()
    for match in BARE_URL_IN_COMMENT.finditer(text):
        raw = match.group(0).rstrip(_BARE_URL_TRAILING).strip()
        if not raw or raw in seen:
            continue
        if any(raw.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
            continue
        if "*" in raw:
            # Router globs are not real URLs (same rule as _clean).
            continue
        seen.add(raw)
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=COMMENTED_LINK,
                raw_value=raw,
                absolute_url=resolve_url(effective_base, raw),
                code_snippet=text.strip()[:300],
                element_location="comment",
            )
        )
    return findings


def _commented_links_in_css_text(css_text: str, source_url: str, base_url: str = None) -> List[CommentFinding]:
    """Dead markup inside CSS `/* ... */` comments (-> commented_link only)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(css_text):
        text = block.group(1)
        marked = _markup_links_in_text(text, source_url, base_url)
        findings.extend(marked)
        have = {f.absolute_url for f in marked}
        for f in _bare_url_comment_findings(text, source_url, base_url):
            if f.absolute_url not in have:
                findings.append(f)
    return findings


def _commented_links_in_js_text(js_text: str, source_url: str, base_url: str = None) -> List[CommentFinding]:
    """Dead markup inside JS `//` and `/* ... */` comments (-> commented_link only)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(js_text):
        text = block.group(1)
        marked = _markup_links_in_text(text, source_url, base_url)
        findings.extend(marked)
        have = {f.absolute_url for f in marked}
        for f in _bare_url_comment_findings(text, source_url, base_url):
            if f.absolute_url not in have:
                findings.append(f)
    for line_match in JS_LINE_COMMENT.finditer(js_text):
        text = line_match.group(1)
        marked = _markup_links_in_text(text, source_url, base_url)
        findings.extend(marked)
        have = {f.absolute_url for f in marked}
        for f in _bare_url_comment_findings(text, source_url, base_url):
            if f.absolute_url not in have:
                findings.append(f)
    return findings


def extract_external_asset_live_link_elements(
    asset_text: str, asset_url: str, is_css: bool
) -> List[LinkElement]:
    """
    Live URLs inside a fetched external .css/.js file, as Links-tab elements.
    Comments are stripped first so commented-out URLs never become live Links
    (they surface as commented_link via fetch_and_scan_external_asset instead).
    found_on_page for these is the asset URL itself — set by the caller.

    Order 3: every element here is tagged is_file_sourced=True — resource-only
    (status-checked, never enqueued for crawling). Embedded onclick /
    inline-script navigation from extractor.py keeps is_file_sourced=False
    and stays crawlable (CASE 7).
    """
    live_text = strip_css_comments(asset_text) if is_css else strip_js_comments(asset_text)
    raw_urls = find_css_urls(live_text) if is_css else find_js_urls(live_text)
    elements: List[LinkElement] = []
    seen = set()
    for raw in raw_urls:
        cleaned = _clean(raw)
        if cleaned is None or cleaned in seen:
            continue
        seen.add(cleaned)
        absolute_url = resolve_url(asset_url, cleaned)
        if is_apex_session_url(absolute_url):
            # APEX dynamic-action session endpoints are framework calls,
            # never links — drop them (never a finding). Namespace shapes
            # are deliberately kept: live file URLs file as internet findings.
            continue
        elements.append(
            LinkElement(
                tag="css" if is_css else "js",
                attribute="css-url" if is_css else "js-url",
                raw_value=cleaned,
                absolute_url=absolute_url,
                code_snippet=asset_text.strip()[:300],
                element_location="external file",
                is_file_sourced=True,
            )
        )
    return elements


def extract_html_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """HTML comments anywhere in the page — checked for commented-out markup (-> commented_link)."""
    soup = BeautifulSoup(html, "lxml")
    base_url = extract_base_url(soup, page_url)
    findings: List[CommentFinding] = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment)
        marked = _markup_links_in_text(text, page_url, base_url)
        findings.extend(marked)
        have = {f.absolute_url for f in marked}
        for f in _bare_url_comment_findings(text, page_url, base_url):
            if f.absolute_url not in have:
                findings.append(f)
    return findings


def extract_css_text_comment_findings(
    css_text: str,
    source_url: str,
    category: str = INTERNAL_CSS,
    code_snippet: Optional[str] = None,
    element_location: Optional[str] = None,
    base_url: str = None,
) -> List[CommentFinding]:
    """CSS presence + comment scanner. Commented-out markup in `/* ... */`
    becomes commented_link; the block/attribute itself always yields one
    presence finding (-> category), even with zero URLs. Live URLs are NOT
    reported here — they go to the Links tab via the extractor/classifier."""
    findings: List[CommentFinding] = _commented_links_in_css_text(css_text, source_url, base_url)
    if css_text.strip():
        snip = code_snippet or css_text.strip()[:300]
        loc = element_location or category.replace("_", " ")
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=strip_css_comments(css_text).strip()[:100] or css_text.strip()[:100],
                absolute_url=source_url,
                code_snippet=snip,
                element_location=loc,
            )
        )
    return findings


def extract_js_text_comment_findings(
    js_text: str,
    source_url: str,
    category: str = INTERNAL_JS,
    code_snippet: Optional[str] = None,
    element_location: Optional[str] = None,
    base_url: str = None,
) -> List[CommentFinding]:
    """JS presence + comment scanner. Commented-out markup in `//` and
    `/* ... */` becomes commented_link; the block/handler itself always yields
    one presence finding (-> category), even with zero URLs. Live URLs are NOT
    reported here — they go to the Links tab via the extractor/classifier."""
    findings: List[CommentFinding] = _commented_links_in_js_text(js_text, source_url, base_url)
    if js_text.strip():
        snip = code_snippet or js_text.strip()[:300]
        loc = element_location or category.replace("_", " ")
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=strip_js_comments(js_text).strip()[:100] or js_text.strip()[:100],
                absolute_url=source_url,
                code_snippet=snip,
                element_location=loc,
            )
        )
    return findings


def extract_embedded_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """Active code and commented links inside <style>/<script> blocks and inline style=""/on*="" attributes."""
    soup = BeautifulSoup(html, "lxml")
    base_url = extract_base_url(soup, page_url)
    findings: List[CommentFinding] = []
    order, total = _document_order_map(soup)

    def _loc(tag) -> str:
        return _build_css_path(tag, _position_label(order.get(id(tag)), total))

    for tag in soup.find_all("style"):
        loc = _loc(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_css_text_comment_findings(
                tag.get_text() or "", page_url, INTERNAL_CSS, code_snippet=snip, element_location=loc,
                base_url=base_url,
            )
        )

    for tag in soup.find_all(style=True):
        loc = _loc(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_css_text_comment_findings(
                tag.get("style") or "", page_url, INLINE_CSS, code_snippet=snip, element_location=loc,
                base_url=base_url,
            )
        )

    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue  # external — excluded
        loc = _loc(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_js_text_comment_findings(
                tag.get_text() or "", page_url, INTERNAL_JS, code_snippet=snip, element_location=loc,
                base_url=base_url,
            )
        )

    for tag in soup.find_all(True):
        for attr_name, attr_value in list(tag.attrs.items()):
            if not attr_name.lower().startswith("on"):
                continue
            if not isinstance(attr_value, str):
                continue
            loc = _loc(tag)
            snip = str(tag)[:300]
            findings.extend(
                extract_js_text_comment_findings(
                    attr_value, page_url, INLINE_JS, code_snippet=snip, element_location=loc,
                    base_url=base_url,
                )
            )

    return findings


def extract_page_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """All code and comment findings from HTML page markup."""
    return extract_html_comment_findings(html, page_url) + extract_embedded_comment_findings(html, page_url)


def fetch_external_asset_text(
    url: str, session: Optional[requests.Session] = None
) -> tuple:
    """
    Fetches a same-host external .css/.js file once.
    Returns (text, is_css) — (None, False) when unfetchable, error status,
    or unrecognized type. Shared by the comment scan (commented links only)
    and the live-Link extraction below so the file is fetched exactly once.
    """
    sess = session or requests.Session()
    try:
        resp = sess.get(
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"User-Agent": CRAWL_USER_AGENT},
            verify=False,
        )
        if resp.status_code >= 400:
            return None, False
        text = resp.text
    except Exception:
        return None, False

    parsed_path = urlparse(url).path.lower()
    content_type = resp.headers.get("Content-Type", "").lower()

    is_css = parsed_path.endswith(".css") or "css" in content_type
    is_js = parsed_path.endswith(".js") or "javascript" in content_type or "ecmascript" in content_type

    if not is_css and not is_js:
        if ".css" in parsed_path:
            is_css = True
        elif ".js" in parsed_path:
            is_js = True

    if not is_css and not is_js:
        return None, False
    return text, is_css


def fetch_external_asset_split(
    url: str, session: Optional[requests.Session] = None
) -> tuple:
    """
    Fetches a same-host external .css/.js file once and splits it for the
    two result tabs: ([commented_link findings], [live LinkElements]).
    Live elements go through classify_link in the crawler so they land in
    the Links tab with a real status (broken/inactive/ip_based/internet).
    """
    fetched = fetch_external_asset_text(url, session=session)
    text, is_css = fetched
    if text is None:
        return [], []
    if is_css:
        comments = _commented_links_in_css_text(text, url)
    else:
        comments = _commented_links_in_js_text(text, url)
    live = extract_external_asset_live_link_elements(text, url, is_css)
    return comments, live


def fetch_and_scan_external_asset(
    url: str, session: Optional[requests.Session] = None
) -> List[CommentFinding]:
    """
    Commented links inside a same-host external .css/.js file
    (-> commented_link only). Live URLs in the file are NOT reported here —
    use fetch_external_asset_split for the Links-tab elements.
    """
    comments, _live = fetch_external_asset_split(url, session=session)
    return comments
