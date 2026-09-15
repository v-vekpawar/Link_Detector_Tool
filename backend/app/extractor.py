"""
HTML link extraction for the Tier 1 (static) engine.

Pulls every link-bearing attribute out of a page's HTML, resolves it to an
absolute URL against the page's own URL, and records enough context
(raw HTML snippet, rough CSS location) to put in a findings row later.

Beyond the fixed href/src/action attributes, this also does a best-effort
heuristic scan (regex against JS/CSS text, not real execution) for links
that never show up as a plain attribute at all:

- Inline JS: any `on*` event-handler attribute (onclick, onload,
  onmouseover, ...) on any tag, e.g.
  `<span onclick="window.location.href='/x'">`, `<li onload="go('/x')">`.
- Internal JS: `<script>` blocks with no `src` (i.e. embedded in the page,
  not an external file) - scanned for the same call patterns.
- Internal CSS: `<style>` blocks - scanned for `url(...)`/`@import`.
- Inline CSS: `style="..."` attributes - same `url(...)` scan.

External .css/.js files (loaded via `<link href>`/`<script src>`) are
*not* scanned here for live links - only for comments, which is handled
separately in comment_scanner.py per the agreed scope: live extraction
stays limited to code embedded directly in the HTML.

Known limitation, flagged rather than hidden: this is regex pattern
matching against JS/CSS text, not a real parser/interpreter. It will
miss anything that doesn't match one of the known call shapes - URLs
built dynamically at runtime, handlers attached only via
addEventListener with no inline attribute, etc.
"""

import re
from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from app.config import EXCLUDED_SCHEMES, is_inactive_href

# (tag name, attribute holding the URL) — per ARCHITECTURE.md's extraction list
LINK_BEARING_ATTRS = [
    ("a", "href"),
    ("area", "href"),
    ("form", "action"),
    ("img", "src"),
    ("script", "src"),
    ("link", "href"),
]

# Heuristic patterns for pulling navigation URLs out of JS text (inline
# event-handler attributes, and internal <script> blocks). Every pattern
# is tried and every match is kept (deduped), not just the first —
# unlike a single attribute value, a <script> block can legitimately
# contain several distinct calls worth reporting.
#   1. location(.href)? = '...'          e.g. window.location.href='/services'
#   2. location.assign('...') / .replace('...')
#   3. window.open('...')
#   4. XHR-style .open('GET', '...')
#   5. any call whose argument is an absolute http(s) URL, e.g. fetch('https://...')
#   6. any call whose argument is a path, e.g. go('/about'), fetch('/api/x')
# (5)/(6) are intentionally the widest nets — they exist to catch
# site-specific helper functions and common patterns (fetch/axios/$.ajax/
# custom helpers) without having to enumerate every library — so they're
# kept last and only match arguments that already look like a URL.
JS_CALL_URL_PATTERNS = [
    re.compile(r"location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"location\.(?:assign|replace)\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"window\.open\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"\.open\(\s*['\"]\w+['\"]\s*,\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"\(\s*['\"](https?://[^'\"]+)['\"]"),
    re.compile(r"\(\s*['\"](/[^'\"]*)['\"]"),
]

# Same idea for CSS text (internal <style> blocks and inline style="").
CSS_URL_PATTERNS = [
    re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)"),
    re.compile(r"@import\s+['\"]([^'\"]+)['\"]"),
]

# Used to strip comments out before scanning for *live* code, so a URL
# that only exists inside a comment doesn't get double-reported as a
# live finding here (it's handled separately, as a comment finding, by
# comment_scanner.py). The JS line-comment pattern has a negative
# lookbehind on ':' specifically so it doesn't treat the "//" in
# "http://..." as the start of a comment.
JS_LINE_COMMENT = re.compile(r"(?<!:)//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


@dataclass
class LinkElement:
    tag: str
    attribute: str
    raw_value: str          # exactly what was in the HTML attribute, stripped
    absolute_url: str       # resolved against the page's own URL
    code_snippet: str       # raw HTML of the element (truncated for sanity)
    element_location: str   # best-effort CSS-ish path, e.g. "html > body > nav > a:nth-of-type(2)"


def strip_js_comments(text: str) -> str:
    text = BLOCK_COMMENT.sub(" ", text)
    text = JS_LINE_COMMENT.sub("", text)
    return text


def strip_css_comments(text: str) -> str:
    return BLOCK_COMMENT.sub(" ", text)


def find_js_urls(text: str) -> List[str]:
    """Every distinct URL-looking match in `text` from JS_CALL_URL_PATTERNS,
    in the order first seen, deduped."""
    found: List[str] = []
    seen = set()
    for pattern in JS_CALL_URL_PATTERNS:
        for match in pattern.finditer(text):
            url = match.group(1).strip()
            if url and url not in seen:
                seen.add(url)
                found.append(url)
    return found


def find_css_urls(text: str) -> List[str]:
    """Every distinct URL-looking match in `text` from CSS_URL_PATTERNS,
    in the order first seen, deduped."""
    found: List[str] = []
    seen = set()
    for pattern in CSS_URL_PATTERNS:
        for match in pattern.finditer(text):
            url = match.group(1).strip()
            if url and url not in seen:
                seen.add(url)
                found.append(url)
    return found


def _build_css_path(tag: Tag) -> str:
    """Best-effort locator: walk up parents, tagging repeated siblings with :nth-of-type."""
    parts = []
    node = tag
    while node is not None and getattr(node, "name", None) not in (None, "[document]"):
        if node.parent is not None:
            siblings = node.parent.find_all(node.name, recursive=False)
        else:
            siblings = [node]
        if len(siblings) > 1:
            index = siblings.index(node) + 1
            parts.append(f"{node.name}:nth-of-type({index})")
        else:
            parts.append(node.name)
        node = node.parent
    return " > ".join(reversed(parts))


def _clean_or_none(raw_value):
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if not raw_value:
        return None
    if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
        return None
    return raw_value


def _extract_inline_js_elements(soup: BeautifulSoup) -> List[LinkElement]:
    """Any `on*` event-handler attribute on any tag — see module docstring."""
    elements: List[LinkElement] = []
    for tag in soup.find_all(True):
        for attr_name, attr_value in list(tag.attrs.items()):
            if not attr_name.lower().startswith("on"):
                continue
            if not isinstance(attr_value, str):
                continue
            for raw_value in find_js_urls(attr_value):
                cleaned = _clean_or_none(raw_value)
                if cleaned is None:
                    continue
                elements.append(
                    LinkElement(
                        tag=tag.name,
                        attribute=attr_name.lower(),
                        raw_value=cleaned,
                        absolute_url=cleaned,  # placeholder, resolved by caller
                        code_snippet=str(tag)[:300],
                        element_location=_build_css_path(tag),
                    )
                )
    return elements


def _extract_style_and_script_elements(soup: BeautifulSoup) -> List[LinkElement]:
    """Internal <style> blocks, inline style="" attributes, and internal
    <script> blocks (no src) — see module docstring."""
    elements: List[LinkElement] = []

    for tag in soup.find_all("style"):
        text = tag.get_text() or ""
        live_text = strip_css_comments(text)
        for raw_value in find_css_urls(live_text):
            cleaned = _clean_or_none(raw_value)
            if cleaned is None:
                continue
            elements.append(
                LinkElement(
                    tag="style",
                    attribute="css-url",
                    raw_value=cleaned,
                    absolute_url=cleaned,  # placeholder, resolved by caller
                    code_snippet=text.strip()[:300],
                    element_location=_build_css_path(tag),
                )
            )

    for tag in soup.find_all(style=True):
        style_value = tag.get("style") or ""
        for raw_value in find_css_urls(style_value):
            cleaned = _clean_or_none(raw_value)
            if cleaned is None:
                continue
            elements.append(
                LinkElement(
                    tag=tag.name,
                    attribute="css-url",
                    raw_value=cleaned,
                    absolute_url=cleaned,  # placeholder, resolved by caller
                    code_snippet=str(tag)[:300],
                    element_location=_build_css_path(tag),
                )
            )

    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue  # external script — already covered by LINK_BEARING_ATTRS
        text = tag.get_text() or ""
        live_text = strip_js_comments(text)
        for raw_value in find_js_urls(live_text):
            cleaned = _clean_or_none(raw_value)
            if cleaned is None:
                continue
            elements.append(
                LinkElement(
                    tag="script",
                    attribute="js-url",
                    raw_value=cleaned,
                    absolute_url=cleaned,  # placeholder, resolved by caller
                    code_snippet=text.strip()[:300],
                    element_location=_build_css_path(tag),
                )
            )

    return elements


def extract_link_elements(html: str, page_url: str) -> List[LinkElement]:
    """
    Parses `html` (as fetched from `page_url`) and returns every link-bearing
    element found, with absolute URLs resolved relative to `page_url`.

    Excludes mailto:/tel:/javascript: targets (not web navigation links,
    per BUILD_PLAN.md #5) and empty/missing attribute values.

    Covers, in order: the fixed href/src/action attributes (LINK_BEARING_ATTRS);
    inline event-handler attributes (onclick, onload, ...); internal <style>
    blocks and inline style="" attributes; internal <script> blocks with no
    src. See module docstring for what's deliberately out of scope
    (external .css/.js file contents — comment_scanner.py handles those).
    """
    soup = BeautifulSoup(html, "lxml")
    elements: List[LinkElement] = []

    for tag_name, attr_name in LINK_BEARING_ATTRS:
        for tag in soup.find_all(tag_name):
            raw_value = tag.get(attr_name)
            cleaned = _clean_or_none(raw_value)
            if cleaned is None:
                continue

            absolute_url = urljoin(page_url, cleaned)
            if is_inactive_href(cleaned) and not absolute_url.endswith("#"):
                absolute_url += "#"

            elements.append(
                LinkElement(
                    tag=tag_name,
                    attribute=attr_name,
                    raw_value=cleaned,
                    absolute_url=absolute_url,
                    code_snippet=str(tag)[:300],
                    element_location=_build_css_path(tag),
                )
            )

    for element in _extract_inline_js_elements(soup) + _extract_style_and_script_elements(soup):
        element.absolute_url = urljoin(page_url, element.raw_value)
        elements.append(element)

    return elements