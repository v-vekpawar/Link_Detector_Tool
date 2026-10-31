"""
Proof screenshots for scan findings (screenshots feature).

Two-stage flow: after the crawl saves its findings, up to two findings per
link category become composed proof cards — amber banner + red title over
the marked page shot(s), and a same-host target-result panel beside the
link context for broken links — then logout runs as usual. Results render
as soon as the crawl completes; the gallery fills in when shots are ready.
Marks (element ellipse, faithful status bubble for genuine links, one thin
connector) are drawn live in the page and cleaned right after each shot;
the composite only frames them under the banner (zero new dependencies).

Safety rules (non-negotiable):
- Only already-visited same-host pages are ever loaded — the found-on page,
  plus a broken link's same-host target (an error page by definition).
  Off-host targets are never navigated to: no session cookies leak out and
  dead externals can't hang the phase.
- Revealing collapsed menus uses hover only, never clicks — clicking an
  unknown element could navigate away or trip a logout.
- Every shot is best-effort with a bounded budget. Anything unresolved is
  skipped and counted ("N of M captured"); a shot failure can delay
  completion but never fails the scan.

PNG bytes live in the screenshot_shots table (schema.sql) with per-scan
state in screenshot_scan_state, retained for the two newest scans (the UI
only ever reaches the last one). The ZIP is built on the fly per download.
"""

import io
import json
import logging
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger("link_audit.screenshots")

# Top-level category tags eligible for proof shots, in gallery order.
SHOT_CATEGORIES = ("broken", "inactive", "ip_based", "internet")

MAX_SHOTS_PER_CATEGORY = 2
MAX_SHOTS_PER_SCAN = 8

# "Only on UI" scans lift the shot caps for broken + inactive links (the
# user wants a proof shot for every visible broken/inactive link), while
# ip_based/internet keep the normal budgets. UNCAPPED is a sentinel cap —
# no real scan reaches 10**9 shots.
UNCAPPED = 10 ** 9
UNCAPPED_SHOT_CATEGORIES = ("broken", "inactive")


def category_cap(category: str, uncapped_broken_inactive: bool = False) -> int:
    """Effective shot budget for one category under the Only-on-UI mode."""
    if uncapped_broken_inactive and category in UNCAPPED_SHOT_CATEGORIES:
        return UNCAPPED
    return MAX_SHOTS_PER_CATEGORY


def scan_cap(uncapped_broken_inactive: bool = False) -> int:
    """Effective per-scan shot budget under the Only-on-UI mode."""
    return UNCAPPED if uncapped_broken_inactive else MAX_SHOTS_PER_SCAN

# Retention: the UI only ever reaches the last scan, so shots for all but
# the two newest scans are purged on finish (see ScreenshotStore.finish).

# How many ancestor levels to try hover-revealing through.
REVEAL_ANCESTOR_LEVELS = 3

# Terminal screenshot states (mirrored to the progress snapshot + API).
SHOT_STATE_CAPTURING = "capturing"
SHOT_STATE_READY = "ready"
SHOT_STATE_PARTIAL = "partial"
SHOT_STATE_STOPPED = "stopped"
SHOT_STATE_FAILED = "failed"
SHOT_STATE_NONE = "none"


def _slugify_link(link: str, limit: int = 40) -> str:
    """Short filesystem-safe slug from a link's path for ZIP filenames."""
    try:
        path = urlparse(link).path or "root"
    except Exception:
        path = "link"
    slug = re.sub(r"[^A-Za-z0-9]+", "-", path.strip("/")).strip("-").lower()
    return (slug or "link")[:limit]


def _snippet_tag_and_text(code_snippet: str) -> Dict[str, str]:
    """Best-effort {tag, text, alt} parsed from a finding's stored HTML
    snippet (truncated at 300 chars upstream — matching tolerates cuts)."""
    tag = ""
    match = re.match(r"\s*<\s*([a-zA-Z][a-zA-Z0-9]*)", code_snippet or "")
    if match:
        tag = match.group(1).lower()
    text, alt = "", ""
    try:
        frag = BeautifulSoup(code_snippet or "", "lxml")
        el = frag.find(tag) if tag else None
        if el is not None:
            text = re.sub(r"\s+", " ", el.get_text(" ", strip=True))[:80]
            alt = (el.get("alt") or "")[:80]
    except Exception:
        pass
    return {"tag": tag, "text": text, "alt": alt}


def _is_asset_found_on(found_on_page: str) -> bool:
    """True when the found-on location is itself a file (.css/.js/...) —
    nothing frameable, so no shot is attempted there."""
    from app.config import is_resource_url
    return is_resource_url(found_on_page or "")


def select_shot_targets(
    findings: List[Dict[str, Any]],
    uncapped_broken_inactive: bool = False,
) -> List[Dict[str, Any]]:
    """Picks up to two findings per SHOT_CATEGORIES entry for proof shots.

    First two per category, preferring distinct found-on pages; identical
    links are shot once and referenced under every matching category.
    File-URL found-ons and data_uri rows are skipped (nothing to frame).
    With `uncapped_broken_inactive` (the "Only on UI" mode), broken and
    inactive candidates get NO shot cap — every distinct link is targeted —
    while ip_based/internet keep the normal budgets.
    Returns target dicts: {categories, link, found_on_page, breadcrumb,
    evidence, tag_hint, text_hint, alt_hint}.
    """
    def _cat_cap(category: str) -> int:
        return category_cap(category, uncapped_broken_inactive)

    scan_limit = scan_cap(uncapped_broken_inactive)
    by_category: Dict[str, List[Dict[str, Any]]] = {c: [] for c in SHOT_CATEGORIES}
    for finding in findings or []:
        tags = set((finding.get("category") or "").split(","))
        if _is_asset_found_on(finding.get("found_on_page") or ""):
            continue
        for category in SHOT_CATEGORIES:
            if category in tags:
                by_category[category].append(finding)
    chosen: Dict[str, Dict[str, Any]] = {}

    def _category_count(category: str) -> int:
        return sum(1 for t in chosen.values() if category in t["categories"])

    def _take(finding: Dict[str, Any], category: str) -> None:
        link = finding.get("link") or ""
        if link in chosen:
            return
        hint = _snippet_tag_and_text(finding.get("code_snippet") or "")
        chosen[link] = {
            "categories": [category],
            "link": link,
            "found_on_page": finding.get("found_on_page") or "",
            "breadcrumb": finding.get("element_location") or "",
            "evidence": finding.get("evidence") or "",
            "tag_hint": hint["tag"],
            "text_hint": hint["text"],
            "alt_hint": hint["alt"],
        }

    def _merge_shared(finding: Dict[str, Any], category: str) -> None:
        link = finding.get("link") or ""
        if link in chosen and category not in chosen[link]["categories"]:
            chosen[link]["categories"].append(category)

    for category in SHOT_CATEGORIES:
        if len(chosen) >= scan_limit:
            break
        # Pass 1: distinct found-on pages (spread the proof around).
        used_pages = {t["found_on_page"] for t in chosen.values() if category in t["categories"]}
        for finding in by_category[category]:
            if _category_count(category) >= _cat_cap(category) or len(chosen) >= scan_limit:
                break
            link = finding.get("link") or ""
            page = finding.get("found_on_page") or ""
            if link in chosen:
                _merge_shared(finding, category)
                continue
            if page in used_pages:
                continue  # same page waits for pass 2
            _take(finding, category)
            used_pages.add(page)
        # Pass 2: fill up to two from any page — a second same-page proof
        # beats no second proof.
        for finding in by_category[category]:
            if _category_count(category) >= _cat_cap(category) or len(chosen) >= scan_limit:
                break
            link = finding.get("link") or ""
            if link in chosen:
                continue  # already merged (or counted) in pass 1
            _take(finding, category)
    picked = {c: sorted({t["link"] for t in chosen.values() if c in t["categories"]}) for c in SHOT_CATEGORIES}
    seen = {c: len(by_category[c]) for c in SHOT_CATEGORIES}
    logger.info("shot selection picked/seen per category: %s",
                {c: f"{len(picked[c])}/{seen[c]}" for c in SHOT_CATEGORIES})
    return list(chosen.values())[:scan_limit]


# ---------------------------------------------------------------------------
# Injected browser script: re-identify + measure + mark.
# ---------------------------------------------------------------------------
# resolveTarget({link, tag, text, alt}) → descriptor for Python to act on:
#   {matched, selector, rect|x/y/w/h, visible, ancestors:[{sel,tag}],
#    containerSel, containerRect, matchHow}
# - Candidates share the hinted tag family; URLs resolve against
#   document.baseURI (native <base> handling). Exact URL match wins;
#   snippet-text match among clickables is the fallback.
# - Phase B: candidates AND the fallback clickables are collected through
#   every OPEN shadow root (recursion into el.shadowRoot) — regular
#   querySelectorAll can't cross that boundary, which would make shadow-
#   rendered links unmatchable.
# - `selector`/`ancestors` use #id when present else tag+index paths —
#   computed fresh per page, used immediately, never persisted. For an
#   element inside a shadow root the path is a single PLAYWRIGHT CSS
#   chain (light-DOM head segment space-joined to the shadow-internal
#   segments): Playwright's css engine pierces open shadow boundaries
#   implicitly for descendant paths, so `page.locator(sel)` resolves.
# - When the match is hidden, containerSel names the nearest visible
#   ancestor for the captioned fallback shot.
REID_JS = r"""
(hint) => {
  const collapse = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const base = document.baseURI;
  const fam = { a: 'a,area', area: 'a,area', img: 'img', source: 'img,source',
                form: 'form', button: 'button',
                iframe: 'iframe,frame', frame: 'iframe,frame' };
  const urlAttr = (el) => el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('action') || '';
  const resolveUrl = (raw) => { try { return new URL(raw, base).href; } catch (e) { return ''; } };
  const textOf = (el) => collapse(el.textContent).slice(0, 80);
  const rectOf = (el) => {
    try {
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, w: r.width, h: r.height };
    } catch (e) { return { x: 0, y: 0, w: 0, h: 0 }; }
  };
  const isVisibleRect = (r) => r.w > 0 && r.h > 0;
  // Positional path WITHIN the element's own tree (shadow root or
  // document) — identical rules on both sides of the boundary. At the
  // rootmost level the parent may be a ShadowRoot (not an Element), so
  // siblings are read from the fragment to keep :nth-of-type exact.
  const treePath = (el) => {
    if (!(el instanceof Element)) return '';
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && node.tagName.toLowerCase() !== 'html' && parts.length < 6) {
      const par = node.parentElement || (node.parentNode && node.parentNode.host ? node.parentNode : null);
      const siblings = Array.from((par && par.children) || []).filter(
        (c) => c.tagName === node.tagName);
      let part = node.tagName.toLowerCase();
      if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      parts.unshift(part);
      node = par;
    }
    return parts.join(' > ');
  };
  // Composed path ACROSS open shadow boundaries: light-DOM head segment
  // and shadow-internal segments joined by plain descendant spaces, which
  // Playwright's css engine matches through shadow boundaries implicitly.
  const pathOf = (el) => {
    if (!(el instanceof Element)) return '';
    if (el.id && !(el.getRootNode() instanceof ShadowRoot)) return '#' + CSS.escape(el.id);
    const segs = [];
    let node = el;
    for (let depth = 0; depth < 4 && node instanceof Element; depth++) {
      let inner = node;
      if (inner.id) { segs.unshift('#' + CSS.escape(inner.id)); break; }
      segs.unshift(treePath(inner));
      const root = node.getRootNode();
      if (root instanceof ShadowRoot) {
        node = root.host;
      } else {
        // cross into the light DOM up except that the FIRST segment may
        // legitimately fall back before reaching <html> — keep as is.
        break;
      }
    }
    return segs.join(' ');
  };
  // Candidates through every open shadow root.
  const deepCandidates = (selector) => {
    const out = [];
    const visit = (root) => {
      try {
        for (const el of root.querySelectorAll(selector)) out.push(el);
      } catch (e) { /* bad selector — skip level */ }
      try {
        for (const h of root.querySelectorAll('*')) {
          const sr = h.shadowRoot;
          if (sr) visit(sr);
        }
      } catch (e) { /* detached midwalk */ }
    };
    visit(document);
    return out;
  };

  const family = (fam[(hint.tag || '').toLowerCase()] || hint.tag || 'a,area,button').toLowerCase();
  const hintText = collapse(hint.text || '');
  let el = null, how = '';
  for (const c of deepCandidates(family)) {
    if (resolveUrl(urlAttr(c)) === hint.link) { el = c; how = 'url'; break; }
  }
  if (!el && hintText) {
    for (const c of deepCandidates('a,area,button,input,[role="button"]')) {
      const t = textOf(c);
      if (t && (t.includes(hintText) || hintText.includes(t))) { el = c; how = 'text'; break; }
    }
  }
  if (!el && (hint.alt || '')) {
    for (const c of deepCandidates('img,source')) {
      if ((c.getAttribute('alt') || '') === hint.alt) { el = c; how = 'alt'; break; }
    }
  }
  if (!el) return { matched: false, shadow: false };

  const inShadow = el.getRootNode() instanceof ShadowRoot;
  const rect = rectOf(el);
  const out = { matched: true, selector: pathOf(el), rect: rect,
                visible: isVisibleRect(rect), matchHow: how, ancestors: [],
                containerSel: '', containerRect: null, shadow: inShadow };
  let node = el.parentElement, levels = 0;
  // Ancestor walk stays INSIDE the element's tree; crossing upward into
  // the host would hover the host document instead — the composed selector
  // already carries that context through the light-DOM head segment.
  while (node && node.nodeType === 1 && node.tagName && levels < 6) {
    const nr = rectOf(node);
    out.ancestors.push({ sel: pathOf(node), tag: node.tagName.toLowerCase(), vis: isVisibleRect(nr) });
    if (isVisibleRect(nr) && !out.containerSel) {
      out.containerSel = pathOf(node);
      out.containerRect = nr;
    }
    node = node.parentElement;
    levels += 1;
  }
  return out;
}
"""

# ---------------------------------------------------------------------------
# In-page proof marks (drawn live, cleaned immediately after the shot).
# ---------------------------------------------------------------------------
# One overlay pass per page: element ellipse + faithful status bubble.
# The bubble appears ONLY for genuine links (a[href]/area[href]) — exactly
# where a real browser shows it (bottom-left) with the freshly resolved
# href — plus its own ellipse and one thin connector to the element mark.
# Everything is tagged data-proof-mark for one-shot cleanup; the scan page
# is never left dirty for the next target.
PROOF_MARK_JS = r"""
(args) => {
  const clear = () => document.querySelectorAll('[data-proof-mark]').forEach((n) => n.remove());
  clear();
  const pad = 16;
  const result = { bubble: null };
  const rect = args.rect;
  if (rect && rect.w > 0 && rect.h > 0) {
    const e = document.createElement('div');
    e.setAttribute('data-proof-mark', 'ellipse');
    e.style.cssText = 'position:fixed;left:' + (rect.x - pad) + 'px;top:' + (rect.y - pad) + 'px;'
      + 'width:' + (rect.w + pad * 2) + 'px;height:' + (rect.h + pad * 2) + 'px;'
      + 'border:4px solid #D92D20;border-radius:50%;z-index:2147483647;pointer-events:none;box-sizing:border-box;';
    document.body.appendChild(e);
  }
  // The bubble URL arrives pre-resolved from Python (read through the
  // element's own locator — frames and shadow trees included), so this
  // overlay never needs a main-document querySelector, which could not
  // reach frame or shadow content anyway.
  let url = String(args.bubble_url || '');
  if (!url) return result;
  const bub = document.createElement('div');
  bub.setAttribute('data-proof-mark', 'bubble');
  bub.textContent = url;
  bub.style.cssText = 'position:fixed;left:0;bottom:0;z-index:2147483647;pointer-events:none;'
    + 'background:#202124;color:#ffffff;font:14px system-ui,sans-serif;padding:5px 12px;'
    + 'border-top-right-radius:8px;white-space:nowrap;max-width:60vw;overflow:hidden;text-overflow:ellipsis;';
  document.body.appendChild(bub);
  const b = bub.getBoundingClientRect();
  result.bubble = { x: b.x, y: b.y, w: b.width, h: b.height, url: url };
  const bp = 10;
  const be = document.createElement('div');
  be.setAttribute('data-proof-mark', 'bubble-ellipse');
  be.style.cssText = 'position:fixed;left:' + (b.x - bp) + 'px;top:' + (b.y - bp) + 'px;'
    + 'width:' + (b.width + bp * 2) + 'px;height:' + (b.height + bp * 2) + 'px;'
    + 'border:4px solid #D92D20;border-radius:50%;z-index:2147483647;pointer-events:none;box-sizing:border-box;';
  document.body.appendChild(be);
  if (rect && rect.w > 0 && rect.h > 0) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('data-proof-mark', 'connector');
    svg.style.cssText = 'position:fixed;left:0;top:0;width:' + window.innerWidth + 'px;height:'
      + window.innerHeight + 'px;z-index:2147483647;pointer-events:none;';
    const defs = document.createElementNS(svgNS, 'defs');
    defs.innerHTML = '<marker id="proofConnHead" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">'
      + '<polygon points="0 0, 8 3, 0 6" fill="#D92D20"/></marker>';
    svg.appendChild(defs);
    const fromBelow = (rect.y + rect.h / 2) < (b.y + b.height / 2);
    const line = document.createElementNS(svgNS, 'line');
    line.setAttribute('x1', rect.x + rect.w / 2);
    line.setAttribute('y1', fromBelow ? (rect.y + rect.h + pad) : (rect.y - pad));
    line.setAttribute('x2', b.x + b.width / 2);
    line.setAttribute('y2', fromBelow ? (b.y - bp) : (b.y + b.height + bp));
    line.setAttribute('stroke', '#D92D20');
    line.setAttribute('stroke-width', '2');
    line.setAttribute('marker-end', 'url(#proofConnHead)');
    svg.appendChild(line);
    document.body.appendChild(svg);
  }
  return result;
}
"""

CLEAR_MARKS_JS = r"""
() => {
  (window.__proofForced || []).forEach((item) => {
    try {
      const el = document.querySelector(item.sel);
      if (!el) return;
      if (item.display) el.style.display = item.display; else el.style.removeProperty('display');
      if (item.visibility) el.style.visibility = item.visibility; else el.style.removeProperty('visibility');
    } catch (err) { /* best effort */ }
  });
  delete window.__proofForced;
  document.querySelectorAll('[data-proof-mark]').forEach((n) => n.remove());
  return true;
}
"""


# ---------------------------------------------------------------------------
# Proof composition (no new dependencies).
# ---------------------------------------------------------------------------
# Raw captures already carry their marks (element ellipse, status bubble).
# The composite only adds the amber banner and stitches panels side by
# side — gallery ≡ ZIP pixel-for-pixel, with real system fonts throughout.
PANEL_DISPLAY_W = 960
BANNER_H = 96

# Scrollbars photograph as gray strips that can cover the bottom-left
# status bubble — suppressed for every capture shot (page navigations wipe
# injected styles, so it is re-applied after each goto). Covers inner
# scrollable divs too, not just the root scrollers. Overflow is set hidden
# via JS as well: with no_viewport the headed window ignores viewport
# resizes, so CSS alone cannot guarantee a scrollbar-free viewport shot.
SCROLLBAR_HIDE_CSS = (
    "*{scrollbar-width:none!important;}"
    "*::-webkit-scrollbar{display:none!important;width:0!important;height:0!important;}"
    "html,body{overflow:hidden!important;}"
)

_SUPPRESS_OVERFLOW_JS = (
    "() => { try {"
    " document.documentElement.style.setProperty('overflow', 'hidden', 'important');"
    " document.body.style.setProperty('overflow', 'hidden', 'important');"
    " } catch (e) {} return true; }"
)

# Fixed capture viewport so proof cards are deterministic regardless of the
# OS window size the headed scan ran in (no_viewport follows the window).
SHOT_VIEWPORT = {"width": 1366, "height": 768}


def _hide_scrollbars(page) -> None:
    try:
        page.add_style_tag(content=SCROLLBAR_HIDE_CSS)
    except Exception:
        pass
    try:
        page.evaluate(_SUPPRESS_OVERFLOW_JS)
    except Exception:
        pass


def _lock_shot_viewport(page) -> None:
    try:
        page.set_viewport_size(SHOT_VIEWPORT)
    except Exception:
        pass


def png_size(png: bytes):
    """(width, height) from a PNG header, or None. Ten lines of struct."""
    import struct
    if not png or png[:8] != b"\x89PNG\r\n\x1a\n" or len(png) < 24:
        return None
    try:
        return struct.unpack(">II", png[16:24])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Shot registry (persisted, last-2-scans retention).
# ---------------------------------------------------------------------------
# PNG bytes live in the screenshot_shots table (schema.sql); per-scan phase
# state in screenshot_scan_state. Retention: the UI only ever reaches the
# last scan, so finish() purges every scan but the two newest — bounded
# growth (~16MB worst case), no manual cleanup, restart-safe.
# Threading: one short-lived connection per method (same pattern as the
# rest of main.py's worker threads).

SHOTS_KEPT_SCANS = 2


class ScreenshotStore:
    """scan_id → {status, shots}. Same interface as the original in-memory
    store, so worker/endpoints are untouched — only the backing changed."""

    def _conn(self):
        from app.db import get_connection
        return get_connection()

    def create(self, scan_id: int, targets: List[Dict[str, Any]]) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO screenshot_scan_state (scan_id, status, targets, updated_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (scan_id, SHOT_STATE_CAPTURING, len(targets)),
            )
            conn.commit()
        finally:
            conn.close()

    def append_shot(self, scan_id: int, shot: Dict[str, Any]) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO screenshot_shots "
                "(scan_id, shot_id, categories, link, found_on_page, breadcrumb, evidence, note, two_panel, png) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, shot.get("id"), json.dumps(shot.get("categories") or []),
                 shot.get("link") or "", shot.get("found_on_page") or "",
                 shot.get("breadcrumb") or "", shot.get("evidence") or "",
                 shot.get("note") or "", 1 if shot.get("two_panel") else 0,
                 shot.get("png") or b""),
            )
            conn.commit()
        finally:
            conn.close()

    def finish(self, scan_id: int, status: str) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO screenshot_scan_state (scan_id, status, targets, updated_at) "
                "VALUES (?, ?, COALESCE((SELECT targets FROM screenshot_scan_state WHERE scan_id = ?), 0), CURRENT_TIMESTAMP)",
                (scan_id, status, scan_id),
            )
            # Last-2-scans retention: anything older is unreachable in the UI.
            conn.execute(
                "DELETE FROM screenshot_shots WHERE scan_id NOT IN "
                "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                (SHOTS_KEPT_SCANS,),
            )
            conn.execute(
                "DELETE FROM screenshot_scan_state WHERE scan_id NOT IN "
                "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                (SHOTS_KEPT_SCANS,),
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, scan_id: int) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            state = conn.execute(
                "SELECT status, targets FROM screenshot_scan_state WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if state is None:
                return None
            rows = conn.execute(
                "SELECT shot_id, categories, link, found_on_page, breadcrumb, evidence, note, two_panel "
                "FROM screenshot_shots WHERE scan_id = ? ORDER BY shot_id",
                (scan_id,),
            ).fetchall()
            shots = [{
                "id": r["shot_id"],
                "categories": json.loads(r["categories"] or "[]"),
                "link": r["link"],
                "found_on_page": r["found_on_page"],
                "breadcrumb": r["breadcrumb"],
                "evidence": r["evidence"],
                "note": r["note"],
                "two_panel": bool(r["two_panel"]),
            } for r in rows]
            return {"status": state["status"], "targets": state["targets"], "shots": shots}
        finally:
            conn.close()

    def png(self, scan_id: int, shot_id: str) -> Optional[bytes]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT png FROM screenshot_shots WHERE scan_id = ? AND shot_id = ?",
                (scan_id, shot_id),
            ).fetchone()
            return bytes(row["png"]) if row and row["png"] is not None else None
        finally:
            conn.close()

    def shots_with_bytes(self, scan_id: int) -> Optional[List[Dict[str, Any]]]:
        meta = self.get(scan_id)
        if meta is None:
            return None
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT shot_id, categories, link, found_on_page, breadcrumb, evidence, note, two_panel, png "
                "FROM screenshot_shots WHERE scan_id = ? ORDER BY shot_id",
                (scan_id,),
            ).fetchall()
            return [{
                "id": r["shot_id"],
                "categories": json.loads(r["categories"] or "[]"),
                "link": r["link"],
                "found_on_page": r["found_on_page"],
                "breadcrumb": r["breadcrumb"],
                "evidence": r["evidence"],
                "note": r["note"],
                "two_panel": bool(r["two_panel"]),
                "png": bytes(r["png"]) if r["png"] is not None else b"",
            } for r in rows]
        finally:
            conn.close()


STORE = ScreenshotStore()


def build_screenshots_zip(scan_id: int, store: Optional[ScreenshotStore] = None) -> Optional[bytes]:
    """ZIPs one scan's shots: numbered PNGs + captions.json. None when the
    entry is gone (evicted/restarted) or holds no shots."""
    store = store or STORE
    shots = store.shots_with_bytes(scan_id)
    if not shots:
        return None
    captions = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i, shot in enumerate(shots, 1):
            filename = f"{i:02d}-{shot['categories'][0]}-{_slugify_link(shot['link'])}.png"
            zf.writestr(filename, shot.get("png") or b"")
            captions.append({
                "file": filename,
                "categories": shot["categories"],
                "link": shot["link"],
                "found_on_page": shot["found_on_page"],
                "breadcrumb": shot["breadcrumb"],
                "evidence": shot.get("evidence") or "",
                "note": shot.get("note") or "",
                "two_panel": bool(shot.get("two_panel")),
            })
        zf.writestr("captions.json", json.dumps(captions, indent=2))
    return buf.getvalue()


def _measure(page, target: Dict[str, Any]) -> "Tuple[Any, Dict[str, Any]]":
    """Runs the re-id script across every frame, main document first; the
    first frame where the target matches wins, and `ctx` (the Page or that
    Frame) is returned alongside the descriptor so every later locator/
    evaluate operation runs in the element's own document (frame-based
    intranet apps keep their chrome inside frame documents). Always
    returns a (descriptor, ctx) pair — descriptor is {matched: False} when
    no frame matches and ctx is then the page."""
    arg = {
        "link": target["link"],
        "tag": target.get("tag_hint") or "",
        "text": target.get("text_hint") or "",
        "alt": target.get("alt_hint") or "",
    }
    ctx = page  # fallback even on failure
    try:
        ctx = page
        desc = page.evaluate(REID_JS, arg)
        if isinstance(desc, dict) and desc.get("matched"):
            return desc, ctx
    except Exception as exc:
        logger.debug("re-id evaluate (main frame) failed for %s — %s: %s",
                     target["link"], type(exc).__name__, exc)
        desc = {"matched": False}
    try:
        frames = [f for f in page.frames if f is not page.main_frame]
    except Exception:
        frames = []
    for frame in frames:
        try:
            fdesc = frame.evaluate(REID_JS, arg)
        except Exception as exc:
            continue
        if isinstance(fdesc, dict) and fdesc.get("matched"):
            return fdesc, frame
    logger.warning("re-id evaluate found no frame match for %s", target["link"])
    return (desc if isinstance(desc, dict) else {"matched": False}), ctx


# Tags that never render (head metadata): not visible on any page, so no
# hover-reveal is attempted — instant skip with a clear note instead of
# burning hover timeouts.
HEAD_ONLY_TAGS = frozenset({"link", "script", "meta", "base", "style", "title"})


FORCE_REVEAL_JS = r"""
(el) => {
  // Deterministic fallback when hover can't land (stale React nodes,
  // headless quirks): force ONE hidden ancestor open via inline styles.
  // Python records the element handle side and restores afterwards
  // (works inside open shadow roots too — locator handles pierce).
  if (!(el instanceof Element)) return { ok: false };
  const origDisplay = el.style.getPropertyValue('display');
  const origVisibility = el.style.getPropertyValue('visibility');
  const r = el.getBoundingClientRect();
  el.style.setProperty('display', 'block', 'important');
  el.style.setProperty('visibility', 'visible', 'important');
  return {
    ok: true,
    display: origDisplay || null,
    visibility: origVisibility || null,
    was_visible: r.width > 0 && r.height > 0,
  };
}
"""

RESTORE_JS = r"""
(el, st) => {
  if (!(el instanceof Element)) return false;
  if (st.display) el.style.setProperty('display', st.display);
  else el.style.removeProperty('display');
  if (st.visibility) el.style.setProperty('visibility', st.visibility);
  else el.style.removeProperty('visibility');
  return true;
}
"""


def _hover_trigger(ctx, ancestor: Dict[str, Any]) -> bool:
    """Hovers one reveal candidate; True when the hover landed.

    `ctx` is a Page (main frame) or a Frame — shadow-piercing and
    frame-local selectors resolve the same way on both."""
    try:
        ctx.locator(ancestor["sel"]).first.hover(timeout=3000)
    except Exception as exc:
        logger.info("reveal hover missed %s — %s", ancestor.get("sel"), type(exc).__name__)
        return False
    try:
        ctx.wait_for_timeout(300)
    except Exception:
        pass
    return True


def _try_reveal(ctx, descriptor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hover-reveals a hidden match (hover only — never clicks, so nothing
    can navigate away). Tries the nearest *visible* non-control ancestor
    first — hovering a hidden node can only time out. Returns the hovered
    ancestor for a post-scroll second chance, else None."""
    for ancestor in (descriptor.get("ancestors") or [])[:REVEAL_ANCESTOR_LEVELS]:
        if (ancestor.get("tag") or "") in ("a", "area", "button", "input"):
            continue  # hovering a control could navigate — skip it
        if not ancestor.get("vis"):
            continue  # hidden nodes can't receive hover — skip without the timeout
        if _hover_trigger(ctx, ancestor):
            logger.info("reveal hover landed on %s", ancestor.get("sel"))
            return ancestor
    return None


def _force_open(ctx, descriptor: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Runs the FORCE_REVEAL fallback on hidden ancestors of an
    unhoverable match: opens them via inline styles and returns the Python
    restore list for _restore_forced(). Best-effort, never raises."""
    restore: List[Dict[str, Any]] = []
    for ancestor in (descriptor.get("ancestors") or [])[:REVEAL_ANCESTOR_LEVELS]:
        if ancestor.get("vis"):
            continue  # already open — nothing to force
        try:
            loc = ctx.locator(ancestor.get("sel") or "").first
            got = loc.evaluate(FORCE_REVEAL_JS)
        except Exception as exc:
            logger.info("force-open missed %s — %s", ancestor.get("sel"), type(exc).__name__)
            continue
        if got and got.get("ok"):
            restore.append({
                "sel": ancestor.get("sel") or "",
                "display": got.get("display"),
                "visibility": got.get("visibility"),
            })
    return restore


def _restore_forced(ctx, restore: List[Dict[str, Any]]) -> None:
    """Best-effort undo of the inline styles _force_open set."""
    for item in restore or []:
        try:
            ctx.locator(item["sel"]).first.evaluate(RESTORE_JS, item)
        except Exception:
            pass


HEADING_RECT_JS = r"""
() => {
  const els = Array.from(document.querySelectorAll('h1,h2'));
  for (const el of els) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0) return { x: r.x, y: r.y, w: r.width, h: r.height };
  }
  return null;
}
"""


def capture_shot(page, target: Dict[str, Any], shot_no: int) -> Dict[str, Any]:
    """Loads the found-on page, draws proof marks (element ellipse +
    faithful status bubble for genuine links), and takes the marked
    viewport PNG, plus the same-host target's page for broken links.
    Returns raw assets for compose_proof(), or ok=False + note. Never raises."""
    del shot_no  # numbering happens at compose time
    link, found_on = target["link"], target["found_on_page"]
    _lock_shot_viewport(page)
    try:
        resp = page.goto(found_on, timeout=30000, wait_until="load")
    except Exception as exc:
        return {"ok": False, "note": f"found-on page did not load ({type(exc).__name__})"}
    if resp is not None and resp.status >= 400:
        return {"ok": False, "note": f"found-on page did not load (HTTP {resp.status})"}
    _hide_scrollbars(page)
    try:
        page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass  # polling pages never idle — shoot what's there

    desc, ctx = _measure(page, target)
    note = ""
    trigger = None
    forced: List[Dict[str, Any]] = []
    if (target.get("tag_hint") or "").lower() in HEAD_ONLY_TAGS:
        # Stylesheet/script/metadata references never render — no hover
        # sequence can reveal them. Skip fast with a clear note.
        return {"ok": False, "note": "invisible head element (stylesheet/script reference)"}
    try_ = desc  # readability alias
    if try_.get("matched") and not try_.get("visible"):
        trigger = _try_reveal(ctx, try_)
        desc, ctx = _measure(page, target)
        if desc.get("matched") and desc.get("visible"):
            note = "revealed from a collapsed menu"
    if not desc.get("visible"):
        # Deterministic fallback: force hidden ancestors open (covers stale
        # React nodes too — this re-measure finds their replacements).
        desc, ctx = _measure(page, target)
        if desc.get("matched"):
            try:
                forced = _force_open(ctx, desc)
                # Re-measure to pick up the reopened geometry.
                desc, ctx = _measure(page, target)
            except Exception:
                pass
        if desc.get("matched") and desc.get("visible"):
            note = "menu force-opened for the shot"
        elif not desc.get("matched"):
            return {"ok": False, "note": "link element not found on the page"}
        else:
            return {"ok": False, "note": "link hidden after reveal attempts"}

    # Locator rect (main-frame-viewport coordinates for ALL frames and
    # shadow trees) — one authoritative source for the top-document
    # proof overlays, whatever document the element lives in.
    selector = desc.get("selector") or ""
    loc = ctx.locator(selector).first
    rect = desc.get("rect") or {}
    try:
        # Center the element so the bottom-left status bubble never sits
        # under an edge/scrollbar; fallback to Playwright's scroll helper.
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
            page.wait_for_timeout(400)
        except Exception:
            page.locator(selector).first.scroll_into_view_if_needed(timeout=5000)
            page.wait_for_timeout(400)
    except Exception as exc:
        return {"ok": False, "note": f"scroll failed ({type(exc).__name__})"}
    try:
        fresh = loc.bounding_box()
        if fresh and fresh.get("width") and fresh.get("height"):
            rect = {"x": fresh["x"], "y": fresh["y"],
                    "w": fresh["width"], "h": fresh["height"]}
        elif trigger is not None:
            # Scrolling can slide the element out from under the hover point
            # and collapse the menu again — one re-hover, then shoot
            # without scrolling a second time.
            _hover_trigger(ctx, trigger)
            desc, ctx = _measure(page, target)
            if desc.get("matched") and desc.get("visible"):
                rect = desc.get("rect") or rect
                if not note:
                    note = "revealed from a collapsed menu"
            else:
                return {"ok": False, "note": "link hidden after reveal attempts"}
    except Exception:
        pass
    # Status bubble URL: read the live element's resolved href through its
    # own locator (frames + open shadow roots included) rather than a
    # main-document querySelector, which can never reach either.
    bubble_url = ""
    try:
        bubble_url = loc.evaluate(
            "el => (el.matches && el.matches('a[href],area[href],iframe[src],frame[src]')) "
            "? String(el.href || el.src || '') : ''"
        ) or ""
    except Exception:
        bubble_url = ""
    # Proof marks: element ellipse + faithful status bubble for genuine
    # links + thin connector, drawn in the TOP document so they cover
    # elements rendered inside frames or shadow trees too.
    bubble_shown = False
    try:
        drawn = page.evaluate(PROOF_MARK_JS, {"rect": rect, "bubble_url": bubble_url})
        bubble_shown = bool((drawn or {}).get("bubble"))
    except Exception:
        pass
    _hide_scrollbars(page)
    try:
        context_png = page.screenshot()
    except Exception as exc:
        try:
            _restore_forced(ctx, forced)
        except Exception:
            pass
        try:
            page.evaluate(CLEAR_MARKS_JS)
        except Exception:
            pass
        return {"ok": False, "note": f"screenshot failed ({type(exc).__name__})"}
    try:
        if forced:
            _restore_forced(ctx, forced)
    except Exception:
        pass
    try:
        page.evaluate(CLEAR_MARKS_JS)
    except Exception:
        pass
    if bubble_shown:
        note = ((note + "; ") if note else "") + "link URL shown in status bubble"
    assets: Dict[str, Any] = {
        "ok": True, "note": note,
        "context_png": context_png, "result_png": None, "two_panel": False,
    }

    # Broken same-host targets get a second panel: the target's own result
    # page (an error page by definition — safe to load, same host keeps the
    # session rule intact). Anything off-host stays single-panel, always.
    same_host = False
    try:
        same_host = (urlparse(link).hostname or "").lower() == (urlparse(found_on).hostname or "").lower()
    except Exception:
        same_host = False
    if "broken" in (target.get("categories") or []) and same_host:
        # Any HTTP status (including the expected 404) renders something
        # shootable; only connection-level failure skips the panel.
        try:
            page.goto(link, timeout=30000, wait_until="load")
        except Exception as exc:
            assets["note"] = ((note + "; ") if note else "") + f"result page did not load ({type(exc).__name__})"
            return assets
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        try:
            heading = page.evaluate(HEADING_RECT_JS)
        except Exception:
            heading = None
        if heading:
            # Circle the result heading in-page (same overlay pass style).
            try:
                page.evaluate(PROOF_MARK_JS, {"rect": heading, "selector": ""})
            except Exception:
                pass
        _hide_scrollbars(page)
        try:
            assets["result_png"] = page.screenshot()
            assets["two_panel"] = True
            if not heading:
                assets["note"] = ((note + "; ") if note else "") + "result has no heading to circle"
        except Exception as exc:
            assets["note"] = ((note + "; ") if note else "") + f"result shot failed ({type(exc).__name__})"
        finally:
            try:
                page.evaluate(CLEAR_MARKS_JS)
            except Exception:
                pass
    return assets


def compose_proof_html(target: Dict[str, Any], assets: Dict[str, Any]) -> tuple:
    """Builds the proof-card HTML (banner + panels) and its exact canvas
    size. All marks already live in the raw pixels — the composite only
    frames them. Returns (html, width, height)."""
    import base64
    category = (target.get("categories") or ["broken"])[0]
    title = f"{category.upper()} LINK"
    panels = []
    for key in ("context_png", "result_png"):
        raw = assets.get(key)
        if not raw:
            continue
        size = png_size(raw) or (PANEL_DISPLAY_W, 400)
        panels.append({"png": raw, "w": size[0], "h": size[1]})
    stage_h = max([round(p["h"] * PANEL_DISPLAY_W / p["w"]) for p in panels if p["w"]] or [0])
    total_w = PANEL_DISPLAY_W * len(panels) + (6 * (len(panels) - 1))
    total_h = BANNER_H + stage_h

    imgs = ""
    for i, panel in enumerate(panels):
        b64 = base64.b64encode(panel["png"]).decode("ascii")
        imgs += (('<div class="divider"></div>' if i else "")
                 + f'<div class="panel"><img src="data:image/png;base64,{b64}"></div>')
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
html,body{{margin:0;padding:0;background:#ffffff;}}
.banner{{height:{BANNER_H}px;display:flex;align-items:center;justify-content:center;
background:#FFC533;color:#D92D20;font:700 44px/1 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
border-bottom:4px solid #111111;}}
.stage{{display:flex;}}
.panel{{position:relative;width:{PANEL_DISPLAY_W}px;}}
.panel img{{display:block;width:{PANEL_DISPLAY_W}px;height:auto;}}
.divider{{width:6px;background:#111111;}}
</style>
</head>
<body>
<div class="banner">{title}</div>
<div class="stage">{imgs}</div>
</body>
</html>"""
    return html, total_w, total_h


def compose_proof(page, target: Dict[str, Any], assets: Dict[str, Any]) -> Dict[str, Any]:
    """Screenshots the composite proof card on a throwaway sibling page
    (the scan page is never disturbed — including its viewport, which later
    raw shots depend on). Returns {png, width, height}."""
    html, total_w, total_h = compose_proof_html(target, assets)
    shot_page = None
    try:
        shot_page = page.context.browser.new_page()
        try:
            shot_page.set_viewport_size({"width": total_w, "height": total_h})
        except Exception:
            pass
        shot_page.set_content(html, wait_until="load")
        shot_page.wait_for_timeout(250)
        # Full-page capture: headed runs ignore viewport resizes
        # (no_viewport), so a viewport shot of a wider-than-window composite
        # photographs the window scrollbars. Full-page renders the content
        # without scrollbar chrome.
        try:
            png = shot_page.screenshot(full_page=True)
        except Exception:
            png = shot_page.screenshot()
        return {"png": png, "width": total_w, "height": total_h}
    finally:
        if shot_page is not None:
            try:
                shot_page.close()
            except Exception:
                pass


# Bound on attempts per category: with quota 2, up to 4 tries keeps a
# single stubborn target from eating the phase while still giving each
# category a fair chance to fill from later candidates.
ATTEMPTS_PER_CATEGORY = 4


def _attempt_target(page, target: Dict[str, Any]) -> tuple:
    """One full proof attempt (capture + compose). Returns
    (png_or_None, note, two_panel). Never raises."""
    try:
        result = capture_shot(page, target, 0)
    except Exception as exc:  # never let one target kill the phase
        return None, f"capture failed ({type(exc).__name__})", False
    if not result.get("ok"):
        return None, result.get("note") or "", False
    try:
        composed = compose_proof(page, target, result)
    except Exception as exc:  # composition must not kill the phase
        return None, f"compose failed ({type(exc).__name__})", False
    return composed.get("png"), result.get("note") or "", bool(result.get("two_panel"))


def run_capture_phase(page, scan_id: int, targets: List[Dict[str, Any]],
                      store: Optional[ScreenshotStore] = None,
                      stop_event=None,
                      uncapped_broken_inactive: bool = False) -> str:
    """Shoots targets until every category holds two proofs (or attempts run
    out); stop-aware between shots. Records each PNG into the store and
    returns the terminal state. Never raises.

    With `uncapped_broken_inactive` ("Only on UI"), broken/inactive targets
    ignore the per-category and per-scan caps AND their attempt budget —
    every distinct target gets a shot attempt."""
    store = store or STORE
    from collections import Counter
    offered: Counter = Counter()
    for target in targets:
        for category in target.get("categories") or []:
            offered[category] += 1
    made: Counter = Counter()
    tried: Counter = Counter()
    shot_no = 0
    try:
        for target in targets:
            if stop_event is not None and stop_event.is_set():
                logger.info("[scan:%d] Stop during screenshots — keeping %d shot(s), going to logout",
                            scan_id, shot_no)
                store.finish(scan_id, SHOT_STATE_STOPPED)
                return SHOT_STATE_STOPPED
            needed = [c for c in (target.get("categories") or [])
                      if made[c] < category_cap(c, uncapped_broken_inactive)
                      and (tried[c] < ATTEMPTS_PER_CATEGORY
                           or category_cap(c, uncapped_broken_inactive) > MAX_SHOTS_PER_CATEGORY)]
            if not needed:
                continue
            for category in target.get("categories") or []:
                tried[category] += 1
            shot_no += 1
            png, note, two_panel = _attempt_target(page, target)
            if png is None:
                logger.info("[scan:%d] shot skipped (%s on %s): %s",
                            scan_id, target["categories"][0], target["link"], note)
                continue
            for category in needed:
                made[category] += 1
            store.append_shot(scan_id, {
                "id": f"shot-{shot_no}",
                "categories": target["categories"],
                "link": target["link"],
                "found_on_page": target["found_on_page"],
                "breadcrumb": target.get("breadcrumb") or "",
                "evidence": target.get("evidence") or "",
                "note": note,
                "two_panel": two_panel,
                "png": png,
            })
    except Exception as exc:
        logger.warning("[scan:%d] capture phase failed — %s: %s", scan_id, type(exc).__name__, exc)
        store.finish(scan_id, SHOT_STATE_FAILED)
        return SHOT_STATE_FAILED
    short = {c: f"{made[c]}/{min(category_cap(c, uncapped_broken_inactive), offered[c])}"
             for c in offered if made[c] < min(category_cap(c, uncapped_broken_inactive), offered[c])}
    status = SHOT_STATE_READY if not short else SHOT_STATE_PARTIAL
    logger.info("[scan:%d] capture phase %s (made/offered per category: %s)",
                scan_id, status,
                {c: f"{made[c]}/{offered[c]}" for c in offered})
    store.finish(scan_id, status)
    return status
