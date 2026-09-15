"""
Comment-code scanner — feeds the "Commented Code" result tab.

Finds URLs left behind in dead code:
- HTML comments (<!-- ... -->) anywhere in the page, including commented-out
  markup like `<!-- <a href="/deprecated-page">Deprecated</a> -->`.
- CSS comments (/* ... */) inside <style> blocks, inline style="" text, and
  external .css files.
- JS comments (// ... and /* ... */) inside <script> blocks and external
  .js files.

Per agreed scope: comment scanning covers *all* files, including external
.css/.js assets (unlike extractor.py's live-code scan, which is
deliberately limited to code embedded directly in the HTML — see its
module docstring). Fetching those external files is this module's job
(fetch_and_scan_external_asset); crawler.py decides which external
assets are in scope (same-host only) and calls it once per unique file.

These are reported separately from extractor.py's live findings because
they're not executing — there's no broken/ip_based/internet status to
check (fetching a URL that only exists in a comment doesn't tell you
anything), and they're never fed into the crawl queue — following a link
out of commented-out code would mean crawling into a page nothing on the
live site can actually reach. They're informational: "here's a link
still sitting in dead code, might be worth deleting."

Known limitation, flagged rather than hidden: this is regex pattern
matching against comment text, not a real HTML/CSS/JS parser. JS
line-comment detection in particular can't perfectly distinguish an
actual `//` comment from `//` inside a string literal — same caveat as
extractor.py's onclick/script scan, just applied to comment bodies
instead of live code.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment

from app.config import EXCLUDED_SCHEMES, REQUEST_TIMEOUT_SECONDS
from app.extractor import LINK_BEARING_ATTRS, find_css_urls, find_js_urls

# JS line comments: same ':'-lookbehind guard as extractor.py, so the
# "//" in "http://..." inside a block comment's text isn't mistaken for
# the start of a nested line comment.
JS_LINE_COMMENT = re.compile(r"(?<!:)//([^\n]*)")
BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.DOTALL)


@dataclass
class CommentFinding:
    source_url: str         # page (or external asset) the comment was found in
    comment_type: str       # "html" | "css" | "js"
    raw_value: str
    absolute_url: str
    code_snippet: str
    element_location: str


def _clean(raw_value):
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if not raw_value:
        return None
    if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
        return None
    return raw_value


def _markup_links_in_text(text: str, source_url: str, comment_type: str = "html") -> List[CommentFinding]:
    """Re-parses `text` as an HTML fragment and reuses the normal
    href/src/action attribute list — catches commented-out real markup
    wherever it shows up, not just inside an HTML comment: a JS or CSS
    comment can just as easily contain a leftover
    `<a href="/old-page">...</a>` someone pasted in as a TODO note (the
    test site does exactly this), so this is called from all three
    comment-type scanners below, not only extract_html_comment_findings."""
    findings: List[CommentFinding] = []
    try:
        frag = BeautifulSoup(text, "lxml")
    except Exception:
        return findings
    for tag_name, attr_name in LINK_BEARING_ATTRS:
        for tag in frag.find_all(tag_name):
            cleaned = _clean(tag.get(attr_name))
            if cleaned is None:
                continue
            findings.append(
                CommentFinding(
                    source_url=source_url,
                    comment_type=comment_type,
                    raw_value=cleaned,
                    absolute_url=urljoin(source_url, cleaned),
                    code_snippet=str(tag)[:300],
                    element_location=f"{comment_type} comment",
                )
            )
    return findings


def _call_links_in_text(text: str, source_url: str, comment_type: str) -> List[CommentFinding]:
    findings: List[CommentFinding] = []
    for raw in find_js_urls(text):
        cleaned = _clean(raw)
        if cleaned is None:
            continue
        findings.append(
            CommentFinding(
                source_url=source_url,
                comment_type=comment_type,
                raw_value=cleaned,
                absolute_url=urljoin(source_url, cleaned),
                code_snippet=text.strip()[:300],
                element_location=f"{comment_type} comment",
            )
        )
    return findings


def _css_links_in_text(text: str, source_url: str, comment_type: str) -> List[CommentFinding]:
    findings: List[CommentFinding] = []
    for raw in find_css_urls(text):
        cleaned = _clean(raw)
        if cleaned is None:
            continue
        findings.append(
            CommentFinding(
                source_url=source_url,
                comment_type=comment_type,
                raw_value=cleaned,
                absolute_url=urljoin(source_url, cleaned),
                code_snippet=text.strip()[:300],
                element_location=f"{comment_type} comment",
            )
        )
    return findings


def extract_html_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """HTML comments anywhere in the page — checked for commented-out
    markup, plus JS/CSS call patterns in case a comment holds raw JS/CSS
    text rather than markup (e.g. a whole `<script>...</script>` block
    commented out with `<!-- -->`)."""
    soup = BeautifulSoup(html, "lxml")
    findings: List[CommentFinding] = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment)
        findings.extend(_markup_links_in_text(text, page_url))
        findings.extend(_call_links_in_text(text, page_url, "html"))
        findings.extend(_css_links_in_text(text, page_url, "html"))
    return findings


def extract_css_text_comment_findings(css_text: str, source_url: str) -> List[CommentFinding]:
    """CSS `/* ... */` comments in raw CSS text (an internal <style>
    block's contents, or a whole external .css file)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(css_text):
        body = block.group(1)
        findings.extend(_markup_links_in_text(body, source_url, "css"))
        findings.extend(_css_links_in_text(body, source_url, "css"))
    return findings


def extract_js_text_comment_findings(js_text: str, source_url: str) -> List[CommentFinding]:
    """JS `//` and `/* ... */` comments in raw JS text (an internal
    <script> block's contents, or a whole external .js file)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(js_text):
        body = block.group(1)
        findings.extend(_markup_links_in_text(body, source_url, "js"))
        findings.extend(_call_links_in_text(body, source_url, "js"))
    for line_match in JS_LINE_COMMENT.finditer(js_text):
        body = line_match.group(1)
        findings.extend(_markup_links_in_text(body, source_url, "js"))
        findings.extend(_call_links_in_text(body, source_url, "js"))
    return findings


def extract_embedded_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """Comments living *inside* a page's own <style>/<script> blocks —
    distinct from HTML comments (extract_html_comment_findings) and from
    external .css/.js files (fetch_and_scan_external_asset)."""
    soup = BeautifulSoup(html, "lxml")
    findings: List[CommentFinding] = []
    for tag in soup.find_all("style"):
        findings.extend(extract_css_text_comment_findings(tag.get_text() or "", page_url))
    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue  # external — handled by fetch_and_scan_external_asset
        findings.extend(extract_js_text_comment_findings(tag.get_text() or "", page_url))
    return findings


def extract_page_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """All comment-derived findings from one HTML page's own markup: HTML
    comments anywhere, plus comments inside that page's own embedded
    <style>/<script> blocks. Does not fetch anything — external .css/.js
    files linked from the page are handled separately by
    fetch_and_scan_external_asset, since that needs a network request."""
    return extract_html_comment_findings(html, page_url) + extract_embedded_comment_findings(html, page_url)


def fetch_and_scan_external_asset(
    url: str, session: Optional[requests.Session] = None
) -> List[CommentFinding]:
    """
    Fetches an external .css/.js file and scans it for comment-only
    links. Returns [] on any fetch failure or unrecognized content type —
    a fetch failure here isn't itself reported as a finding; the file's
    own broken-link status is already checked separately, by
    classify_link, via the <link href>/<script src> element that pointed
    to it.
    """
    sess = session or requests.Session()
    try:
        resp = sess.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        return []

    path = urlparse(url).path.lower()
    content_type = resp.headers.get("Content-Type", "").lower()

    if path.endswith(".css") or "css" in content_type:
        return extract_css_text_comment_findings(resp.text, url)
    if path.endswith(".js") or "javascript" in content_type:
        return extract_js_text_comment_findings(resp.text, url)
    return []