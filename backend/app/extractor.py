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
- Srcset: `img`/`source` `srcset` candidates — one element per URL token,
  descriptors (`480w`, `2x`) dropped, data: URIs kept intact for validation.

External .css/.js files (loaded via `<link href>`/`<script src>`) are
*not* scanned here for live links — the crawler fetches each same-host
file once and reports its live URLs to the Links tab (see
comment_scanner.extract_external_asset_live_link_elements), while its
comments surface as commented_link findings.

Known limitation, flagged rather than hidden: this is regex pattern
matching against JS/CSS text, not a real parser/interpreter. It will
miss anything that doesn't match one of the known call shapes - URLs
built dynamically at runtime, handlers attached only via
addEventListener with no inline attribute, etc.
"""

import re
from dataclasses import dataclass
from typing import List, Optional

from bs4 import BeautifulSoup, Tag

from app.config import EXCLUDED_SCHEMES, is_inactive_href, resolve_url, normalize_backslashes_for_url, is_xml_namespace_url, is_apex_session_url


def _normalize_backslashes(raw_value: str, page_url: str) -> str:
    """Backward-compat alias for config.normalize_backslashes_for_url."""
    return normalize_backslashes_for_url(raw_value, page_url)


def extract_base_url(soup: BeautifulSoup, page_url: str) -> str:
    """
    Effective base URL for resolving relative references on a page.
    The first `<base href>` in tree order wins (matches browsers); a
    missing or empty href is ignored. The base href itself may be relative,
    so it is resolved against the page URL. Falls back to page_url.
    """
    for base_tag in soup.find_all("base"):
        href = base_tag.get("href")
        if href and href.strip():
            return resolve_url(page_url, href.strip())
    return page_url

# (tag name, attribute holding the URL) — per ARCHITECTURE.md's extraction list
LINK_BEARING_ATTRS = [
    ("a", "href"),
    ("area", "href"),
    ("form", "action"),
    ("img", "src"),
    ("script", "src"),
    ("link", "href"),
    # Frame documents are loads, not just references: a frameset app's
    # content lives behind these srcs, so they're link-checked AND
    # followed into (crawler._is_navigable treats them like anchors).
    ("frame", "src"),
    ("iframe", "src"),
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
    absolute_url: str       # resolved against the page's effective base URL
    code_snippet: str       # raw HTML of the element (truncated for sanity)
    element_location: str   # friendly locator, e.g. Products menu › "Deleted Product"
    is_file_sourced: bool = False  # True for live URLs from external .css/.js (Order 3: resource-only)


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


def _shorten(text: str, limit: int = 40) -> str:
    """Collapses whitespace and truncates for display in element locations."""
    text = re.sub(r"\s+", " ", (text or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Everyday-breadcrumb element locations (Order 9)
# ---------------------------------------------------------------------------
# Non-technical readers get `{position} → {landmark} → {item} [{tag}]`,
# e.g. `Top of page → Page header menu (header) → NEWS link (a)`.
# - position: document-order thirds — top third "Top of page", bottom third
#   "Page bottom", middle third clean (no prefix).
# - landmark: nearest landmark ancestor, translated (tag kept in brackets
#   for technicians). Dropped when it duplicates the position
#   ("Page bottom (footer)" at page bottom → just "Page bottom").
# - item: link text / img alt / input label / aria-label + kind + (tag).
# Raw CSS paths (`html > ...`, `nth-of-type`) are never emitted. Whole
# locator capped ~120 chars.

TOP_OF_PAGE = "Top of page"
PAGE_BOTTOM = "Page bottom"
LOCATOR_MAX_LENGTH = 120

LANDMARK_NAMES = {
    "header": "Page header",
    "nav": "Menu",
    "footer": "Page bottom",
    "main": "Main content",
    "form": "Form",
    "table": "Table",
    "aside": "Sidebar",
    "section": "Section",
    "article": "Article",
}

ELEMENT_KINDS = {
    "a": "link",
    "area": "link",
    "img": "image",
    "input": "field",
    "select": "field",
    "textarea": "field",
    "button": "button",
    "script": "script",
    "style": "styles",
    "link": "stylesheet",
    "source": "source",
    "form": "form",
}


def _document_order_map(soup: BeautifulSoup):
    """Maps id(tag) → document-order index, plus the total tag count.

    Built once per parsed page and shared by every element described from
    it (keys are safe while the soup is alive — all tags stay reachable).
    """
    order = {}
    tags = soup.find_all(True)
    for i, tag in enumerate(tags):
        order[id(tag)] = i
    return order, len(tags)


def _position_label(idx, total) -> Optional[str]:
    """Document-order thirds: top → TOP_OF_PAGE, bottom → PAGE_BOTTOM,
    middle → None (middle stays clean)."""
    if idx is None or total is None or total <= 0:
        return None
    fraction = idx / total
    if fraction < 1 / 3:
        return TOP_OF_PAGE
    if fraction >= 2 / 3:
        return PAGE_BOTTOM
    return None


def _input_label_text(tag: Tag) -> str:
    """Inputs are named by their associated <label>, else placeholder/name."""
    label_text = ""
    label = None
    if tag.get("id"):
        soup = tag
        while getattr(soup, "name", None) not in (None, "[document]"):
            soup = soup.parent
        if soup is not None and hasattr(soup, "find"):
            label = soup.find("label", {"for": tag.get("id")})
    if label is None:
        node = tag.parent
        while node is not None and getattr(node, "name", None) not in (None, "[document]"):
            if getattr(node, "name", None) == "label":
                label = node
                break
            node = node.parent
    if label is not None:
        label_text = _shorten(label.get_text(" ", strip=True))
    if not label_text:
        label_text = _shorten(tag.get("placeholder") or tag.get("name") or tag.get("aria-label") or "")
    return label_text


def _item_label(tag: Tag) -> str:
    """Best human label for the element itself (no kind, no tag)."""
    name = tag.name or "element"
    if name in ("img", "area"):
        alt = _shorten(tag.get("alt") or "")
        if alt:
            return alt
    if name == "input":
        label = _input_label_text(tag)
        if label:
            return label
    text = _shorten(tag.get_text(" ", strip=True), 60)
    if text:
        return text
    if name in ("a", "button", "area"):
        # Links/buttons whose only content is an image/icon borrow its name.
        inner = tag.find("img")
        if inner is not None:
            alt = _shorten(inner.get("alt") or "")
            if alt:
                return alt
        inner_icon = tag.find(["svg", "i"])
        if inner_icon is not None:
            icon_label = _shorten(inner_icon.get("aria-label") or inner_icon.get("title") or "")
            if icon_label:
                return icon_label
    label = _shorten(tag.get("aria-label") or tag.get("title") or "")
    if label:
        return label
    if name in ("script", "link", "source"):
        src = (tag.get("src") or tag.get("href") or "").split("?")[0].rstrip("/").split("/")[-1]
        if src:
            return src
    for attr in ("name", "value", "title"):
        val = tag.get(attr)
        if isinstance(val, str) and val.strip():
            return _shorten(val)
    return ""


def _landmark_name_and_tag(tag: Tag):
    """Nearest landmark ancestor → (translated name, tag), or (None, None)."""
    node = tag.parent
    while node is not None and getattr(node, "name", None) not in (None, "[document]"):
        landmark = LANDMARK_NAMES.get(getattr(node, "name", ""))
        if landmark:
            return landmark, node.name
        node = node.parent
    return None, None


def _describe_element(tag: Tag, position: Optional[str] = None) -> str:
    """
    Everyday breadcrumb replacing the old CSS path
    (html > body > nav > a:nth-of-type(2)).

    `{position} → {landmark} → {item} [{tag}]` — position from
    document-order thirds (top/bottom only), landmark translated with the
    real tag in brackets (dropped when it duplicates the position), item
    from link text / img alt / input label / aria-label with kind + tag.
    Capped ~120 chars.
    """
    name = tag.name or "element"
    kind = ELEMENT_KINDS.get(name, name)
    label = _item_label(tag)
    if label and label.lower() != kind and not label.lower().endswith(" " + kind):
        item = f"{label} {kind} ({name})"
    elif label:
        item = f"{label} ({name})"
    else:
        item = f"{kind.capitalize()} ({name})"

    parts: List[str] = []
    if position:
        parts.append(position)
    landmark, landmark_tag = _landmark_name_and_tag(tag)
    if landmark and landmark != position:
        parts.append(f"{landmark} ({landmark_tag})")
    parts.append(item)
    locator = " → ".join(parts)
    if len(locator) > LOCATOR_MAX_LENGTH:
        locator = locator[: LOCATOR_MAX_LENGTH - 1] + "…"
    return locator


def _build_css_path(tag: Tag, position: Optional[str] = None) -> str:
    """Backward-compat alias — now returns the everyday breadcrumb."""
    return _describe_element(tag, position)


def _clean_or_none(raw_value):
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if not raw_value:
        return None
    if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
        return None
    if "*" in raw_value:
        # Order 4: router globs and wildcards (/*, /$..., *.) are route
        # definitions, not real URLs — real URLs essentially never contain
        # a raw `*`. Dropped before resolution on every extraction path.
        return None
    return raw_value


def _is_protected_nav(tag: str, attribute: str) -> bool:
    """True only for a real navigation link: <a>/<area> href.

    Order 4's namespace skip never applies here — a genuine reference link
    (e.g. <a href="https://www.w3.org/TR/...">) must still flag Internet.
    Every other source (form/img/script/link/src, srcset, on* handlers,
    js-url/css-url heuristics) is droppable when its shape matches.
    """
    return tag in ("a", "area") and attribute == "href"


def _split_srcset_candidates(value: str) -> List[str]:
    """
    Split a srcset attribute value into raw candidate strings, keeping
    data: URIs (whose metadata/data comma must not split) intact.
    Descriptors (480w, 2x, …) stay attached here and are stripped later.
    """
    candidates: List[str] = []
    buf = ""
    for chunk in value.split(","):
        buf = chunk if not buf else buf + "," + chunk
        stripped = buf.strip()
        if stripped.lower().startswith("data:") and "," not in stripped[5:]:
            continue  # metadata comma not seen yet
        if stripped:
            candidates.append(stripped)
        buf = ""
    if buf.strip():
        candidates.append(buf.strip())
    return candidates


def _extract_srcset_elements(soup: BeautifulSoup, positions=None) -> List[LinkElement]:
    """
    img/source srcset candidates — one LinkElement per URL token, descriptors
    dropped. data: URIs survive splitting intact (validated downstream like
    any other data: URL); mailto:/blob:/etc. are excluded as usual.
    """
    order, total = positions if positions is not None else ({}, 0)
    elements: List[LinkElement] = []
    for tag in soup.find_all(["img", "source"]):
        srcset = tag.get("srcset")
        if not isinstance(srcset, str) or not srcset.strip():
            continue
        seen = set()
        for candidate in _split_srcset_candidates(srcset):
            parts = candidate.split()
            if not parts:
                continue
            cleaned = _clean_or_none(parts[0])
            if cleaned is None or cleaned in seen:
                continue
            seen.add(cleaned)
            elements.append(
                LinkElement(
                    tag=tag.name,
                    attribute="srcset",
                    raw_value=cleaned,
                    absolute_url=cleaned,  # placeholder, resolved by caller
                    code_snippet=str(tag)[:300],
                    element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
                )
            )
    return elements


def _extract_inline_js_elements(soup: BeautifulSoup, positions=None) -> List[LinkElement]:
    """Any `on*` event-handler attribute on any tag — see module docstring."""
    order, total = positions if positions is not None else ({}, 0)
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
                        element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
                    )
                )
    return elements


def _extract_style_and_script_elements(soup: BeautifulSoup, positions=None) -> List[LinkElement]:
    """Internal <style> blocks, inline style="" attributes, and internal
    <script> blocks (no src) — see module docstring."""
    order, total = positions if positions is not None else ({}, 0)
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
                    element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
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
                    element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
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
                    element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
                )
            )

    return elements


def extract_link_elements(html: str, page_url: str) -> List[LinkElement]:
    """
    Parses `html` (as fetched from `page_url`) and returns every link-bearing
    element found, with absolute URLs resolved relative to the page's
    effective base URL (first `<base href>` wins, else `page_url`).

    Excludes mailto:/tel:/javascript: targets (not web navigation links,
    per BUILD_PLAN.md #5) and empty/missing attribute values.

    Covers, in order: the fixed href/src/action attributes (LINK_BEARING_ATTRS);
    img/source srcset candidates (descriptors dropped, data: URIs kept intact);
    inline event-handler attributes (onclick, onload, ...); internal <style>
    blocks and inline style="" attributes; internal <script> blocks with no
    src. See module docstring for what's deliberately out of scope
    (external .css/.js file contents — comment_scanner.py handles those).
    """
    soup = BeautifulSoup(html, "lxml")
    base_url = extract_base_url(soup, page_url)
    elements: List[LinkElement] = []
    positions = _document_order_map(soup)
    order, total = positions

    for tag_name, attr_name in LINK_BEARING_ATTRS:
        for tag in soup.find_all(tag_name):
            raw_value = tag.get(attr_name)
            cleaned = _clean_or_none(raw_value)
            if cleaned is None:
                continue

            # WHATWG leniency: backslashes resolve as forward slashes.
            # raw_value keeps the original backslashes for evidence;
            # only absolute_url is normalized.
            absolute_url = resolve_url(base_url, cleaned)
            if not _is_protected_nav(tag_name, attr_name) and (
                is_xml_namespace_url(absolute_url) or is_apex_session_url(absolute_url)
            ):
                # Order 4: XML namespace identifiers in non-navigable
                # attributes (img/src, script/src, ...) are boilerplate.
                # APEX dynamic-action session endpoints (.../2?session=...)
                # are framework calls, never links. <a>/<area> href is
                # exempt from both (see _is_protected_nav).
                continue
            if is_inactive_href(cleaned) and not absolute_url.endswith("#"):
                absolute_url += "#"

            elements.append(
                LinkElement(
                    tag=tag_name,
                    attribute=attr_name,
                    raw_value=cleaned,
                    absolute_url=absolute_url,
                    code_snippet=str(tag)[:300],
                    element_location=_build_css_path(tag, _position_label(order.get(id(tag)), total)),
                )
            )

    for element in _extract_inline_js_elements(soup, positions) + _extract_style_and_script_elements(soup, positions) + _extract_srcset_elements(soup, positions):
        # Same WHATWG leniency for the heuristic-extraction path.
        element.absolute_url = resolve_url(base_url, element.raw_value)
        if not _is_protected_nav(element.tag, element.attribute) and is_apex_session_url(element.absolute_url):
            # APEX dynamic-action session endpoints (.../2?session=...) from
            # JS/CSS-string heuristics (on* handlers, internal script/style
            # blocks, srcset) are framework calls, never links. <a>/<area>
            # href is exempt (see above). Namespace shapes are deliberately
            # kept here: live strings file as internet findings.
            continue
        elements.append(element)

    return elements