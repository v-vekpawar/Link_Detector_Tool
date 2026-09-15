"""
Source-code scan for the Link & Navigation Audit Tool.

A separate check from link validity (classifier.py / crawler.py): this
inventories things a human should review before deployment — commented-out
link/anchor markup left in HTML, CSS, or JS, plus inline and internal
CSS/JS usage. There is no pass/fail here, only "for your review" findings.

Design notes (flagging as decisions, not silent defaults):
- Runs against whatever HTML the page already has in hand at scan time —
  raw fetched HTML for Static scans, rendered HTML for Dynamic scans (the
  same HTML the crawler already passes to extract_link_elements). For a
  Dynamic scan this means source-scan sees post-render markup, including
  anything JS injected — broader coverage, not strictly "as originally
  served by the server." Flagging this as an assumption, not a silent
  default — revisit if you want strictly pre-render source only.
- "Commented link" detection covers HTML comments (<!-- -->), CSS comments
  (/* */ inside <style> blocks), and JS comments (// and /* */ inside
  <script> blocks) — per explicit request to check "entire page source
  (html, css, js)", not just literal HTML comments.
- JS line-comment detection ("//") is a best-effort regex, not a real JS
  parser: it treats "//" as a comment start unless immediately preceded by
  ":" (so "http://"/"https://" aren't misread as comments). This can still
  misfire on other edge cases (e.g. "//" inside an unrelated string
  literal) — acceptable for an inventory/review tool, not exhaustive.
- Commented links are NOT classified (broken/inactive/etc.) — just flagged
  for human review, per explicit scope decision (Phase 1, may change later).
- Inline/internal CSS and JS are pure inventory: one finding per
  occurrence, no judgment about whether the usage is a problem.
- element_location for comment findings is a best-effort line number
  (comments aren't DOM nodes, so the CSS-path locator used elsewhere
  doesn't apply); for inline/internal CSS & JS findings, the existing
  CSS-path locator (extractor.py's build_css_path) is reused so location
  format is consistent with the Links results.
"""

import re
from typing import Dict, List, Tuple

from bs4 import BeautifulSoup, Tag

from app.extractor import build_css_path

SNIPPET_MAX_LENGTH = 300

# Loosely matches "this text contains something link/anchor-like" — an <a
# tag, an href attribute, or a bare URL. Intentionally permissive: this is
# a "flag for review" heuristic, not a strict parser, per explicit scope
# decision not to classify commented links for now.
LINK_LIKE_PATTERN = re.compile(r"<a\b[^>]*>|href\s*=|https?://|www\.\S+\.\S+", re.IGNORECASE)

HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
STYLE_BLOCK_PATTERN = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
# CSS and JS block comments share the same /* ... */ syntax.
BLOCK_COMMENT_PATTERN = re.compile(r"/\*(.*?)\*/", re.DOTALL)
# JS line comment: "//" not immediately preceded by ":" (avoids http://, https://).
JS_LINE_COMMENT_PATTERN = re.compile(r"(?<!:)//[^\n]*")

# Attributes that fire inline JS (event handler attributes: onclick, onload, ...).
INLINE_JS_ATTR_PREFIX = "on"


def _truncate(text: str, max_length: int = SNIPPET_MAX_LENGTH) -> str:
    text = (text or "").strip()
    return text if len(text) <= max_length else text[:max_length] + "…"


def _line_number(html: str, index: int) -> int:
    """1-based line number of `index` within `html` — best-effort locator for comment findings."""
    if index < 0:
        return 1
    return html.count("\n", 0, index) + 1


def _find_commented_links_in_html(html: str) -> List[Dict]:
    findings = []
    for match in HTML_COMMENT_PATTERN.finditer(html):
        if LINK_LIKE_PATTERN.search(match.group(1)):
            findings.append({
                "category": "commented_link",
                "code_snippet": _truncate(match.group(0)),
                "evidence": "Commented-out HTML containing a link/anchor",
                "element_location": f"line {_line_number(html, match.start())} (HTML comment)",
            })
    return findings


def _find_commented_links_in_css(html: str) -> List[Dict]:
    findings = []
    for style_match in STYLE_BLOCK_PATTERN.finditer(html):
        css_content = style_match.group(1)
        css_start = style_match.start(1)
        for comment_match in BLOCK_COMMENT_PATTERN.finditer(css_content):
            if LINK_LIKE_PATTERN.search(comment_match.group(1)):
                absolute_index = css_start + comment_match.start()
                findings.append({
                    "category": "commented_link",
                    "code_snippet": _truncate(comment_match.group(0)),
                    "evidence": "Commented-out CSS containing a link",
                    "element_location": f"line {_line_number(html, absolute_index)} (CSS comment in <style>)",
                })
    return findings


def _find_commented_links_in_js(html: str, script_blocks: List[Tuple[Tag, str, int]]) -> List[Dict]:
    findings = []
    for _tag, content, content_start in script_blocks:
        for comment_match in BLOCK_COMMENT_PATTERN.finditer(content):
            if LINK_LIKE_PATTERN.search(comment_match.group(1)):
                absolute_index = content_start + comment_match.start()
                findings.append({
                    "category": "commented_link",
                    "code_snippet": _truncate(comment_match.group(0)),
                    "evidence": "Commented-out JS containing a link",
                    "element_location": f"line {_line_number(html, absolute_index)} (JS block comment in <script>)",
                })
        for line_match in JS_LINE_COMMENT_PATTERN.finditer(content):
            if LINK_LIKE_PATTERN.search(line_match.group(0)):
                absolute_index = content_start + line_match.start()
                findings.append({
                    "category": "commented_link",
                    "code_snippet": _truncate(line_match.group(0)),
                    "evidence": "Commented-out JS containing a link",
                    "element_location": f"line {_line_number(html, absolute_index)} (JS line comment in <script>)",
                })
    return findings


def _internal_script_blocks(soup: BeautifulSoup, html: str) -> List[Tuple[Tag, str, int]]:
    """
    Returns (tag, content, best-effort start-index-in-html) for every
    <script> block WITHOUT a src attribute (i.e. internal/inline JS, not a
    reference to an external file). start-index is best-effort: located by
    a plain substring search of the extracted content back in the original
    HTML, which can misfire (falls back to 0 / "line 1") if BeautifulSoup's
    serialization doesn't byte-match the original — acceptable for a
    best-effort line-number locator, not load-bearing elsewhere.
    """
    blocks = []
    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue
        content = tag.string or tag.get_text() or ""
        if not content.strip():
            continue
        start_index = html.find(content)
        blocks.append((tag, content, start_index))
    return blocks


def scan_source_code(html: str, page_url: str) -> List[Dict]:
    """
    Returns a list of finding dicts shaped like a `findings` row (minus
    scan_id/found_on_page, which the caller adds): link (always None —
    these findings aren't about a specific link target), category,
    code_snippet, evidence, element_location.

    Categories produced: commented_link, inline_css, internal_css,
    inline_js, internal_js.
    """
    findings: List[Dict] = []
    soup = BeautifulSoup(html, "lxml")

    script_blocks = _internal_script_blocks(soup, html)

    # --- Commented links: HTML, CSS (inside <style>), JS (inside <script>) ---
    findings.extend(_find_commented_links_in_html(html))
    findings.extend(_find_commented_links_in_css(html))
    findings.extend(_find_commented_links_in_js(html, script_blocks))

    # --- Internal CSS: one finding per <style> block ---
    for style_match in STYLE_BLOCK_PATTERN.finditer(html):
        findings.append({
            "category": "internal_css",
            "code_snippet": _truncate(style_match.group(0)),
            "evidence": "Internal <style> block found",
            "element_location": f"line {_line_number(html, style_match.start())}",
        })

    # --- Internal JS: one finding per inline <script> block ---
    for tag, _content, _start in script_blocks:
        findings.append({
            "category": "internal_js",
            "code_snippet": _truncate(str(tag)),
            "evidence": "Internal <script> block found",
            "element_location": build_css_path(tag),
        })

    # --- Inline CSS: one finding per style="" attribute ---
    for tag in soup.find_all(style=True):
        if not (tag.get("style") or "").strip():
            continue
        findings.append({
            "category": "inline_css",
            "code_snippet": _truncate(str(tag)),
            "evidence": "Inline style attribute found",
            "element_location": build_css_path(tag),
        })

    # --- Inline JS: one finding per event-handler attribute (onclick, onload, ...) ---
    for tag in soup.find_all(True):
        for attr_name in tag.attrs:
            if attr_name.lower().startswith(INLINE_JS_ATTR_PREFIX):
                findings.append({
                    "category": "inline_js",
                    "code_snippet": _truncate(str(tag)),
                    "evidence": f"Inline event handler attribute '{attr_name}' found",
                    "element_location": build_css_path(tag),
                })

    for finding in findings:
        finding["link"] = None

    return findings