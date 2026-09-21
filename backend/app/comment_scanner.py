"""
Comment-code scanner — feeds the "Commented Code" result tab.

Finds commented links and active inline/internal CSS and JS.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment

from app.config import EXCLUDED_SCHEMES, REQUEST_TIMEOUT_SECONDS
from app.extractor import (
    LINK_BEARING_ATTRS,
    _build_css_path,
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


def _clean(raw_value):
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if not raw_value:
        return None
    if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
        return None
    return raw_value


def _markup_links_in_text(text: str, source_url: str) -> List[CommentFinding]:
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
                    category=COMMENTED_LINK,
                    raw_value=cleaned,
                    absolute_url=urljoin(source_url, cleaned),
                    code_snippet=str(tag)[:300],
                    element_location="comment",
                )
            )
    return findings


def _call_links_in_text(text: str, source_url: str, category: str) -> List[CommentFinding]:
    findings: List[CommentFinding] = []
    for raw in find_js_urls(text):
        cleaned = _clean(raw)
        if cleaned is None:
            continue
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=cleaned,
                absolute_url=urljoin(source_url, cleaned),
                code_snippet=text.strip()[:300],
                element_location=category.replace("_", " "),
            )
        )
    return findings


def _css_links_in_text(text: str, source_url: str, category: str) -> List[CommentFinding]:
    findings: List[CommentFinding] = []
    for raw in find_css_urls(text):
        cleaned = _clean(raw)
        if cleaned is None:
            continue
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=cleaned,
                absolute_url=urljoin(source_url, cleaned),
                code_snippet=text.strip()[:300],
                element_location=category.replace("_", " "),
            )
        )
    return findings


def extract_html_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """HTML comments anywhere in the page — checked for commented-out markup (-> commented_link)."""
    soup = BeautifulSoup(html, "lxml")
    findings: List[CommentFinding] = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment)
        findings.extend(_markup_links_in_text(text, page_url))
    return findings


def extract_css_text_comment_findings(
    css_text: str,
    source_url: str,
    category: str = INTERNAL_CSS,
    code_snippet: Optional[str] = None,
    element_location: Optional[str] = None,
) -> List[CommentFinding]:
    """CSS text scanner. Checks comments (`/* ... */`) for commented-out
    markup (-> commented_link), and active CSS code for CSS call patterns or
    style declarations (-> category)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(css_text):
        body = block.group(1)
        findings.extend(_markup_links_in_text(body, source_url))
    live_css = strip_css_comments(css_text)
    css_urls = _css_links_in_text(live_css, source_url, category)
    if css_urls:
        findings.extend(css_urls)
    elif live_css.strip():
        snip = code_snippet or css_text.strip()[:300]
        loc = element_location or category.replace("_", " ")
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=live_css.strip()[:100],
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
) -> List[CommentFinding]:
    """JS text scanner. Checks comments (`//` and `/* ... */`) for commented-out
    markup (-> commented_link), and active JS code for JS call patterns or
    code declarations (-> category)."""
    findings: List[CommentFinding] = []
    for block in BLOCK_COMMENT.finditer(js_text):
        body = block.group(1)
        findings.extend(_markup_links_in_text(body, source_url))
    for line_match in JS_LINE_COMMENT.finditer(js_text):
        body = line_match.group(1)
        findings.extend(_markup_links_in_text(body, source_url))
    live_js = strip_js_comments(js_text)
    js_urls = _call_links_in_text(live_js, source_url, category)
    if js_urls:
        findings.extend(js_urls)
    elif live_js.strip():
        snip = code_snippet or js_text.strip()[:300]
        loc = element_location or category.replace("_", " ")
        findings.append(
            CommentFinding(
                source_url=source_url,
                category=category,
                raw_value=live_js.strip()[:100],
                absolute_url=source_url,
                code_snippet=snip,
                element_location=loc,
            )
        )
    return findings


def extract_embedded_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """Active code and commented links inside <style>/<script> blocks and inline style=""/on*="" attributes."""
    soup = BeautifulSoup(html, "lxml")
    findings: List[CommentFinding] = []

    for tag in soup.find_all("style"):
        loc = _build_css_path(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_css_text_comment_findings(
                tag.get_text() or "", page_url, INTERNAL_CSS, code_snippet=snip, element_location=loc
            )
        )

    for tag in soup.find_all(style=True):
        loc = _build_css_path(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_css_text_comment_findings(
                tag.get("style") or "", page_url, INLINE_CSS, code_snippet=snip, element_location=loc
            )
        )

    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue  # external — excluded
        loc = _build_css_path(tag)
        snip = str(tag)[:300]
        findings.extend(
            extract_js_text_comment_findings(
                tag.get_text() or "", page_url, INTERNAL_JS, code_snippet=snip, element_location=loc
            )
        )

    for tag in soup.find_all(True):
        for attr_name, attr_value in list(tag.attrs.items()):
            if not attr_name.lower().startswith("on"):
                continue
            if not isinstance(attr_value, str):
                continue
            loc = _build_css_path(tag)
            snip = str(tag)[:300]
            findings.extend(
                extract_js_text_comment_findings(
                    attr_value, page_url, INLINE_JS, code_snippet=snip, element_location=loc
                )
            )

    return findings


def extract_page_comment_findings(html: str, page_url: str) -> List[CommentFinding]:
    """All code and comment findings from HTML page markup."""
    return extract_html_comment_findings(html, page_url) + extract_embedded_comment_findings(html, page_url)


def fetch_and_scan_external_asset(
    url: str, session: Optional[requests.Session] = None
) -> List[CommentFinding]:
    """External asset scanning is excluded."""
    return []
