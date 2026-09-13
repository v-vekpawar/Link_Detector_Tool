"""
HTML link extraction for the Tier 1 (static) engine.

Pulls every link-bearing attribute out of a page's HTML, resolves it to an
absolute URL against the page's own URL, and records enough context
(raw HTML snippet, rough CSS location) to put in a findings row later.
"""

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


@dataclass
class LinkElement:
    tag: str
    attribute: str
    raw_value: str          # exactly what was in the HTML attribute, stripped
    absolute_url: str       # resolved against the page's own URL
    code_snippet: str       # raw HTML of the element (truncated for sanity)
    element_location: str   # best-effort CSS-ish path, e.g. "html > body > nav > a:nth-of-type(2)"


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


def extract_link_elements(html: str, page_url: str) -> List[LinkElement]:
    """
    Parses `html` (as fetched from `page_url`) and returns every link-bearing
    element found, with absolute URLs resolved relative to `page_url`.

    Excludes mailto:/tel:/javascript: targets (not web navigation links,
    per BUILD_PLAN.md #5) and empty/missing attribute values.
    """
    soup = BeautifulSoup(html, "lxml")
    elements: List[LinkElement] = []

    for tag_name, attr_name in LINK_BEARING_ATTRS:
        for tag in soup.find_all(tag_name):
            raw_value = tag.get(attr_name)
            if raw_value is None:
                continue
            raw_value = raw_value.strip()
            if not raw_value:
                continue
            if any(raw_value.lower().startswith(scheme) for scheme in EXCLUDED_SCHEMES):
                continue

            absolute_url = urljoin(page_url, raw_value)
            if is_inactive_href(raw_value) and not absolute_url.endswith("#"):
                absolute_url += "#"

            elements.append(
                LinkElement(
                    tag=tag_name,
                    attribute=attr_name,
                    raw_value=raw_value,
                    absolute_url=absolute_url,
                    code_snippet=str(tag)[:300],
                    element_location=_build_css_path(tag),
                )
            )

    return elements