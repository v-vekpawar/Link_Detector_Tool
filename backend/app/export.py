"""
Export generation for scan results (Step 10 of BUILD_ORDER.md).

Both build_xlsx_bytes() and build_pdf_bytes() take the same three
inputs — a `scan` dict (as returned by _row_to_scan_dict in main.py),
the "Links" findings list, and the "Commented Code" findings list (the
same two buckets _build_results_payload in main.py already splits
results into for the UI) — and return raw bytes ready to stream back
over HTTP. Nothing here touches the DB or FastAPI; that keeps this
module trivially unit-testable and reusable if a future module needs the
same export shape.

Links and Code Findings are rendered as separate sections (two sheets in
xlsx) rather than one merged table, because they're different kinds of
data: Links entries carry a checked status
(broken/inactive/ip_based/internet/data_uri) with an Evidence/Reason column
that explains *why* it was flagged; Code Findings entries carry no status —
they're commented-out links plus inline/internal CSS/JS presence (which of
the five code categories) plus a Details column (the raw snippet) and the
DOM location.

The PDF follows a different, A4-portrait layout: the Links findings are
split into four per-category tables (Broken / Inactive / IP-based /
Internet — data-URI rows join Internet), each followed by proof-screenshot
appendices (one appendix letter per row, two appendix blocks per page).
Code Findings keeps the XLSX-shaped section. The frontend's Unique toggle
(and the export equivalent) collapses rows by LINK ONLY — first occurrence
kept, later ones counted as "(×N occurrences)" — regardless of page or
category spread.

Results table columns, per DATA_MODEL.md / API_SPEC.md (code snippets stay in
the DB but are excluded from display and exports):
    Found on Page, Link, Category, Severity, Evidence/Reason (Links) or
    Details (Code Findings), Element Location
"""

import io
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from xml.sax.saxutils import escape as _xml_escape

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

LINK_COLUMN_HEADERS = [
    "Found on Page",
    "Link",
    "Category",
    "Severity",
    "Evidence / Reason",
    "Element Location",
]

# Code Findings mirror the Links column set (6 columns) so the frontend's
# shared table renderer and export visibility toggles stay in lockstep —
# a 5-column export rejected the UI's 0–5 indices with "columns must be
# 0–4". Details carries the evidence/raw snippet for the finding.
COMMENT_COLUMN_HEADERS = [
    "Found On Page",
    "Extracted Value / Target",
    "Finding Type",
    "Severity",
    "Details",
    "DOM Location",
]

CATEGORY_LABELS = {
    "broken": "Broken",
    "inactive": "Inactive",
    "ip_based": "IP-based",
    "internet": "Internet",
    "data_uri": "Malformed Data URI",
}

COMMENT_CATEGORY_LABELS = {
    "commented_link": "Commented Link",
    "internal_css": "Internal CSS",
    "inline_css": "Inline CSS",
    "internal_js": "Internal JS",
    "inline_js": "Inline JS",
}

SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _format_category(category_string: str, labels: Dict[str, str]) -> str:
    """Turns a stored comma-separated category tag ('internet,broken') into a display string ('Internet, Broken')."""
    if not category_string:
        return ""
    tags = [labels.get(tag.strip(), tag.strip()) for tag in category_string.split(",") if tag.strip()]
    return ", ".join(tags)


def _display_path(url: str) -> str:
    """Found-on-page display: path (+ query) only — '/public' not the full
    URL, root as '/'. Non-http(s) values pass through unchanged."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if (parsed.scheme or "").lower() not in ("http", "https"):
            return url
        return (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    except Exception:
        return url


def parse_column_param(value: Optional[str], size: int) -> Optional[List[int]]:
    """
    Parses a columns= query value ("0,1,4") into sorted indices, or None for
    all columns (missing/blank). Raises ValueError on garbage or an empty
    selection — the endpoint turns that into HTTP 400.
    """
    if value is None or not value.strip():
        return None
    indices = sorted({int(part) for part in value.split(",") if part.strip() != ""})
    if not indices or any(i < 0 or i >= size for i in indices):
        raise ValueError(f"columns must be 0–{size - 1}")
    return indices


def apply_unique(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapses rows that share the same LINK — regardless of page or category
    — keeping the first occurrence (table order) and counting extras as
    " (×N occurrences)" appended to its evidence. This is the export mirror
    of the frontend Unique toggle (link-only dedup, marker carries the total
    count across all occurrences). Copies, never mutates.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for finding in rows:
        key = finding.get("link") or ""
        entry = seen.get(key)
        if entry is not None:
            entry["n"] += 1
        else:
            copy = dict(finding)
            seen[key] = {"row": copy, "n": 1}
            out.append(copy)
    for entry in seen.values():
        if entry["n"] > 1:
            evidence = entry["row"].get("evidence") or ""
            entry["row"]["evidence"] = (
                f"{evidence} (×{entry['n']} occurrences)" if evidence else f"×{entry['n']} occurrences"
            )
    return out


def _select(items: List, columns: Optional[List[int]]) -> List:
    """Keeps all items, or only the indexed ones (headers, rows, widths)."""
    if columns is None:
        return items
    return [items[i] for i in columns]


def _link_finding_row(finding: Dict[str, Any]) -> List[str]:
    return [
        _display_path(finding.get("found_on_page") or ""),
        finding.get("link") or "",
        _format_category(finding.get("category") or "", CATEGORY_LABELS),
        SEVERITY_LABELS.get(finding.get("severity") or "", ""),
        finding.get("evidence") or "",
        finding.get("element_location") or "",
    ]


def _comment_finding_row(finding: Dict[str, Any]) -> List[str]:
    return [
        _display_path(finding.get("found_on_page") or ""),
        finding.get("link") or "",
        _format_category(finding.get("category") or "", COMMENT_CATEGORY_LABELS),
        SEVERITY_LABELS.get(finding.get("severity") or "", ""),
        finding.get("evidence") or "",
        finding.get("element_location") or "",
    ]


def _summary_lines(scan: Dict[str, Any]) -> List[str]:
    return [
        f"Target URL: {scan.get('target_url') or ''}",
        f"Target IP: {scan.get('target_ip') or ''}",
        f"Site type: {scan.get('site_type') or ''}",
        f"Started: {scan.get('started_at') or ''}",
        f"Completed: {scan.get('completed_at') or ''}",
        f"Pages crawled: {scan.get('pages_crawled') if scan.get('pages_crawled') is not None else '—'}",
        f"Total links checked: {scan.get('total_links_checked') if scan.get('total_links_checked') is not None else '—'}",
    ]


# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------

def _write_xlsx_sheet(ws, title_line: str, summary_lines: List[str], headers: List[str],
                       rows: List[List[str]], empty_message: str, column_widths: List[int]) -> None:
    bold = Font(bold=True)
    row_index = 1

    ws.cell(row=row_index, column=1, value=title_line).font = Font(bold=True, size=14)
    row_index += 1

    for line in summary_lines:
        ws.cell(row=row_index, column=1, value=line)
        row_index += 1

    row_index += 1  # blank spacer row before the table

    header_row = row_index
    for col_index, header in enumerate(headers, start=1):
        cell = ws.cell(row=header_row, column=col_index, value=header)
        cell.font = bold
        cell.alignment = Alignment(horizontal="left", vertical="top")
    row_index += 1

    if rows:
        for row in rows:
            for col_index, value in enumerate(row, start=1):
                cell = ws.cell(row=row_index, column=col_index, value=value)
                cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            row_index += 1
    else:
        ws.cell(row=row_index, column=1, value=empty_message)
        row_index += 1

    for col_index, width in enumerate(column_widths, start=1):
        ws.column_dimensions[get_column_letter(col_index)].width = width

    ws.freeze_panes = ws.cell(row=header_row + 1, column=1).coordinate


def build_xlsx_bytes(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    commented_findings: List[Dict[str, Any]],
    link_columns: Optional[List[int]] = None,
    code_columns: Optional[List[int]] = None,
    include_tabs: tuple = ("links", "commented"),
) -> bytes:
    """
    Builds an .xlsx workbook — one sheet per included tab ("Links" and/or
    "Code Findings"), each with its own summary block and column set.
    link_columns/code_columns are visible-column indices (None = all).
    Returns the workbook as raw bytes (nothing written to disk).
    """
    wb = Workbook()
    first = True

    if "links" in include_tabs:
        links_ws = wb.active if first else wb.create_sheet("Links")
        first = False
        links_ws.title = "Links"
        _write_xlsx_sheet(
            links_ws,
            f"Scan #{scan.get('id')} — Links",
            _summary_lines(scan),
            _select(LINK_COLUMN_HEADERS, link_columns),
            [_select(_link_finding_row(f), link_columns) for f in findings],
            "No issues found — every link checked out clean.",
            column_widths=_select([40, 40, 18, 12, 45, 30], link_columns),
        )

    if "commented" in include_tabs:
        comments_ws = wb.active if first else wb.create_sheet("Code Findings")
        comments_ws.title = "Code Findings"
        _write_xlsx_sheet(
            comments_ws,
            f"Scan #{scan.get('id')} — Code Findings",
            _summary_lines(scan),
            _select(COMMENT_COLUMN_HEADERS, code_columns),
            [_select(_comment_finding_row(f), code_columns) for f in commented_findings],
            "No issues found in comments or internal/inline CSS/JS.",
            column_widths=_select([40, 40, 18, 12, 45, 30], code_columns),
        )

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

# The PDF's Links findings are split per category, in the user-agreed order.
# data_uri rows join the Internet table (they're external-scheme references,
# just malformed).
PDF_LINK_BUCKETS = (
    ("broken", "Broken Links Findings"),
    ("inactive", "Inactive Links Findings"),
    ("ip_based", "IP-based Links Findings"),
    ("internet", "Internet Links Findings"),
)

# Appendix image caps (points). Two appendix blocks must fit on one A4
# portrait page: 2 × (heading ~18 + spacer 4 + image ≤330 + spacer 12)
# ≈ 728pt against an 784pt usable height, comfortably.
_PDF_IMAGE_MAX_W = 480.0
_PDF_IMAGE_MAX_H = 330.0

# Column widths for the per-category table. A4 portrait usable width is
# ~7.47in; the full set sums to 6.42in so hidden columns leave slack.
_PDF_BUCKET_WIDTHS = {
    "sno": 0.45 * inch,
    "link": 2.05 * inch,
    "found": 1.55 * inch,
    "location": 1.75 * inch,
    "appendix": 0.62 * inch,
}


def _pdf_letter(n: int) -> str:
    """1 → A, 2 → B ... 26 → Z, 27 → AA (Excel-style ordinal letters)."""
    if n <= 0:
        return "A"
    n0 = n - 1
    out = ""
    while True:
        out = chr(ord("A") + (n0 % 26)) + out
        n0 = n0 // 26 - 1
        if n0 < 0:
            return out


def _bucket_tag(tag: str, category: str) -> bool:
    """Bucket membership: the tag is one of the finding's comma-separated
    category tags; data_uri rows additionally join the internet bucket."""
    tags = [t.strip() for t in (category or "").split(",") if t.strip()]
    if tag in tags:
        return True
    return tag == "internet" and "data_uri" in tags


def _pdf_scaled_image(png: bytes) -> Image:
    """Builds an Image flowable for a screenshot PNG, scaled to honor the
    appendix caps while preserving aspect (never upscaled)."""
    png = bytes(png or b"")
    width = _PDF_IMAGE_MAX_W
    height = _PDF_IMAGE_MAX_H
    try:
        native_w, native_h = ImageReader(io.BytesIO(png)).getSize()
        scale = min(_PDF_IMAGE_MAX_W / max(1.0, float(native_w)),
                    _PDF_IMAGE_MAX_H / max(1.0, float(native_h)),
                    1.0)
        width = max(1.0, float(native_w) * scale)
        height = max(1.0, float(native_h) * scale)
    except Exception:
        pass  # unknown size → fall back to the caps as-is
    return Image(io.BytesIO(png), width=width, height=height)


def _pdf_section(elements: List, title: str, summary_lines: List[str], headers: List[str],
                  rows: List[List[str]], empty_message: str, col_widths: List[float],
                  styles) -> None:
    title_style = styles["section"]
    summary_style = styles["summary"]
    cell_style = styles["cell"]
    header_style = styles["header"]

    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 6))
    for line in summary_lines:
        elements.append(Paragraph(line, summary_style))
    elements.append(Spacer(1, 10))

    if rows:
        table_data = [[Paragraph(h, header_style) for h in headers]]
        for row in rows:
            # Paragraph treats its text as a small XML/HTML-like markup
            # language, so raw code snippets (e.g. '<a href="...">x</a>')
            # must be escaped first or the tags get silently swallowed
            # instead of displayed.
            table_data.append([Paragraph(_xml_escape(str(value)), cell_style) for value in row])

        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2b2b")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
                ]
            )
        )
        elements.append(table)
    else:
        elements.append(Paragraph(empty_message, summary_style))

    elements.append(Spacer(1, 18))


def _pdf_bucket_section(
    elements: List,
    title: str,
    rows: List[Dict[str, Any]],
    show_link: bool,
    show_found: bool,
    show_location: bool,
    shots_by_link: Dict[str, Dict[str, Any]],
    styles,
) -> int:
    """
    One per-category Links section: a heading + its S.No.-ordered table +
    that table's screenshot appendices (light, echoing the old table style).
    Returns how many appendix blocks were emitted so the caller can track
    two-per-page packing across sections.
    """
    cell_style = styles["cell"]
    header_style = styles["header"]

    elements.append(Paragraph(title, styles["section"]))
    elements.append(Spacer(1, 6))

    if not rows:
        elements.append(Paragraph("No issues found in this category.", styles["summary"]))
        elements.append(Spacer(1, 14))
        return 0

    blocks: List = []  # (letter, png) per row that has a proof shot
    table_data: List[List] = []
    headers: List[str] = ["S.No."]
    widths: List[float] = [_PDF_BUCKET_WIDTHS["sno"]]
    if show_link:
        headers.append("Link")
        widths.append(_PDF_BUCKET_WIDTHS["link"])
    if show_found:
        headers.append("Found on Page")
        widths.append(_PDF_BUCKET_WIDTHS["found"])
    if show_location:
        headers.append("Location")
        widths.append(_PDF_BUCKET_WIDTHS["location"])
    headers.append("Appendix")
    widths.append(_PDF_BUCKET_WIDTHS["appendix"])
    table_data.append([Paragraph(h, header_style) for h in headers])

    for ordinal, finding in enumerate(rows, start=1):
        letter = _pdf_letter(ordinal)
        shot = shots_by_link.get(finding.get("link") or "")
        appendix_text = f"Appendix {letter}" if shot is not None else "—"
        if shot is not None and shot.get("png"):
            blocks.append((letter, shot["png"]))
        row: List = [Paragraph(_xml_escape(str(ordinal)), cell_style)]
        if show_link:
            row.append(Paragraph(_xml_escape(finding.get("link") or ""), cell_style))
        if show_found:
            row.append(Paragraph(_xml_escape(_display_path(finding.get("found_on_page") or "")), cell_style))
        if show_location:
            row.append(Paragraph(_xml_escape(finding.get("element_location") or ""), cell_style))
        row.append(Paragraph(_xml_escape(appendix_text), cell_style))
        table_data.append(row)

    table = Table(table_data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2b2b")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
            ]
        )
    )
    elements.append(table)
    elements.append(Spacer(1, 14))

    # Appendix blocks: centered "Appendix X" heading over that row's proof
    # screenshot, with an explicit page break after every second block —
    # exactly two appendices per page (the caller prunes any trailing break).
    for index, (letter, png) in enumerate(blocks, start=1):
        elements.append(Paragraph(f"Appendix {letter}", styles["appendix"]))
        elements.append(Spacer(1, 6))
        try:
            elements.append(_pdf_scaled_image(png))
        except Exception:
            # A corrupt/unreadable PNG must not kill the export — show the
            # "no screenshot materialized" form instead.
            pass
        elements.append(Spacer(1, 12))
        if index % 2 == 0:
            elements.append(PageBreak())
    return len(blocks)


def build_pdf_bytes(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    commented_findings: List[Dict[str, Any]],
    link_columns: Optional[List[int]] = None,
    code_columns: Optional[List[int]] = None,
    include_tabs: tuple = ("links", "commented"),
    shots: Optional[List[Dict[str, Any]]] = None,
) -> bytes:
    """
    Builds an A4-portrait PDF:

        Scan title + summary block (once)
        Broken Links Findings      → table → this table's appendices
        Inactive Links Findings    → table → appendices
        IP-based Links Findings    → table → appendices
        Internet Links Findings    → table → appendices (data-URI rows here)
        Code Findings              → XLSX-shaped section (optional tab)

    Per-category tables carry S.No. | Link | Found on Page | Location |
    Appendix — S.No. and Appendix are fixed columns; Link/Found/Location
    honor the same Link-column visibility indices the XLSX uses (old column
    order: 0=Found on Page, 1=Link, 5=Element Location). Appendix letters
    restart per section and equal the row's S.No. in letter form; every
    shot-backed row gets a centered "Appendix X" heading plus its screenshot,
    two appendix blocks per page. Rows without a shot show "—". Long cell
    text is wrapped via Paragraph.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=0.4 * inch,
        rightMargin=0.4 * inch,
        topMargin=0.4 * inch,
        bottomMargin=0.4 * inch,
    )

    base_styles = getSampleStyleSheet()
    styles = {
        "title": base_styles["Title"],
        "section": ParagraphStyle(
            "section",
            parent=base_styles["Heading2"],
            spaceBefore=6,
            spaceAfter=2,
        ),
        "summary": base_styles["Normal"],
        "appendix": ParagraphStyle(
            "appendix",
            parent=base_styles["Normal"],
            alignment=1,  # TA_CENTER
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            spaceBefore=10,
        ),
        "cell": ParagraphStyle(
            "cell",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            wordWrap="CJK",  # forces breaks on long unbroken strings like URLs
        ),
        "header": ParagraphStyle(
            "header",
            parent=base_styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.white,
            fontName="Helvetica-Bold",
        ),
    }

    # Visible-column set (old column indices): 0=Found on Page, 1=Link,
    # 5=Element Location. None = all visible.
    show_link = link_columns is None or 1 in link_columns
    show_found = link_columns is None or 0 in link_columns
    show_location = link_columns is None or 5 in link_columns

    shots_by_link: Dict[str, Dict[str, Any]] = {}
    for shot in shots or []:
        link = shot.get("link") or ""
        if link and shot.get("png"):
            shots_by_link.setdefault(link, shot)

    elements: List = []
    summary_lines = _summary_lines(scan)

    if "links" in include_tabs:
        elements.append(Paragraph(
            f"Scan #{scan.get('id')} — Link &amp; Navigation Audit", styles["title"]))
        for line in summary_lines:
            elements.append(Paragraph(line, styles["summary"]))
        elements.append(Spacer(1, 12))

    shown = {"links": False, "commented": False}

    # A category with no findings contributes no section at all — the
    # report only lists the tables that actually have rows (user: "if
    # there is no ip-based or any other finding then it should not be
    # added in pdf report").
    for tag, heading in PDF_LINK_BUCKETS:
        rows = [f for f in findings if _bucket_tag(tag, f.get("category") or "")]
        if not rows:
            continue
        shown["links"] = True
        _pdf_bucket_section(
            elements, heading, rows,
            show_link=show_link, show_found=show_found, show_location=show_location,
            shots_by_link=shots_by_link, styles=styles,
        )

    # Code Findings keeps the XLSX-shaped 6-column section; summary lines
    # already appear once at the top of the doc. Empty → omitted entirely.
    if "commented" in include_tabs and commented_findings:
        shown["commented"] = True
        _pdf_section(
            elements,
            "Code Findings",
            [],
            _select(COMMENT_COLUMN_HEADERS, code_columns),
            [_select(_comment_finding_row(f), code_columns) for f in commented_findings],
            "No issues found in comments or internal/inline CSS/JS.",
            col_widths=_select([1.35 * inch, 1.25 * inch, 0.7 * inch, 0.55 * inch, 1.75 * inch, 1.87 * inch], code_columns),
            styles=styles,
        )

    # Prune a trailing page break so two-pages-of-appendices never leave a
    # blank final page behind.
    while elements and isinstance(elements[-1], PageBreak):
        elements.pop()

    if not any(shown.values()):
        # Everything empty (e.g. a clean scan) — say so once instead of
        # shipping a summary-only page.
        elements.append(Paragraph("No issues found in this scan.", styles["summary"]))

    doc.build(elements)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Word (DOCX) export — editable mirror of the PDF layout
# ---------------------------------------------------------------------------

_DOCX_PAGE_WIDTH_CM = 21.0      # A4 portrait
_DOCX_PAGE_HEIGHT_CM = 29.7
_DOCX_MARGIN_CM = 1.02          # 0.4in, same as the PDF

# Appendix image caps (inches) — mirrors the PDF's 480x330pt caps.
_DOCX_IMAGE_MAX_W_IN = 6.5
_DOCX_IMAGE_MAX_H_IN = 4.5

_DOCX_BUCKET_WIDTHS_IN = (0.45, 2.05, 1.55, 1.75, 0.62)
_DOCX_CODE_WIDTHS_IN = (1.35, 1.25, 0.7, 0.55, 1.75, 1.87)


def _docx_image_size(png: bytes) -> Optional[tuple]:
    """(scale-fitted width, height) in inches honoring both caps, or None
    when the size can't be determined (no PIL / unreadable image) — callers
    then let Word auto-size by width only."""
    try:
        from PIL import Image as PILImage
        with PILImage.open(io.BytesIO(bytes(png or b""))) as im:
            native_w, native_h = float(im.width), float(im.height)
        scale = min(_DOCX_IMAGE_MAX_W_IN / max(1.0, native_w),
                    _DOCX_IMAGE_MAX_H_IN / max(1.0, native_h),
                    1.0)
        return (max(0.5, native_w * scale), max(0.5, native_h * scale))
    except Exception:
        return None


def _docx_build_table(doc, headers: List[str], widths_in: List[tuple],
                      rows: List[List[str]]) -> None:
    """docx table with the PDF's dark-header grid look. `widths_in` carries
    one (width_in,) per column; the header row is shaded and bold."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.autofit = False

    def _fill_cell(cell, text, *, header=False, width=None):
        if width is not None:
            cell.width = Inches(width)
        if header:
            tc_pr = cell._tc.get_or_add_tcPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:fill"), "2B2B2B")
            tc_pr.append(shd)
        para = cell.paragraphs[0]
        para.paragraph_format.space_before = Pt(1)
        para.paragraph_format.space_after = Pt(1)
        run = para.add_run(str(text))
        run.bold = header
        run.font.size = Pt(8.5 if header else 7.5)
        if header:
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for i, header in enumerate(headers):
        _fill_cell(table.rows[0].cells[i], header, header=True, width=widths_in[i][0])
    for row in rows:
        cells = table.add_row().cells
        for i, value in enumerate(row):
            _fill_cell(cells[i], value, width=widths_in[i][0])


def build_docx_bytes(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    commented_findings: List[Dict[str, Any]],
    link_columns: Optional[List[int]] = None,
    code_columns: Optional[List[int]] = None,
    include_tabs: tuple = ("links", "commented"),
    shots: Optional[List[Dict[str, Any]]] = None,
) -> bytes:
    """
    Builds a Word (.docx) export that mirrors the PDF layout: A4 portrait,
    doc title + summary once, then one section per non-empty Links category
    (Broken / Inactive / IP-based / Internet, with data-URI rows joining
    Internet) as an S.No. table — columns honoring the Link-column
    checkboxes — followed by that table's "Appendix X" headings and proof
    screenshots (page break after every second block). Code Findings keeps
    the XLSX-shaped section. Empty categories are omitted entirely; a fully
    empty export says "No issues found in this scan." once.
    Requires the python-docx package (function-level import so a server
    without it still serves Excel/PDF). Returns raw .docx bytes.
    """
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Cm, Inches, Pt

    doc = Document()
    section = doc.sections[0]
    section.page_width = Cm(_DOCX_PAGE_WIDTH_CM)
    section.page_height = Cm(_DOCX_PAGE_HEIGHT_CM)
    section.top_margin = section.bottom_margin = Cm(_DOCX_MARGIN_CM)
    section.left_margin = section.right_margin = Cm(_DOCX_MARGIN_CM)

    def _para(text, *, bold=False, size=9, align=None, space_after=2):
        p = doc.add_paragraph()
        if align is not None:
            p.alignment = align
        p.paragraph_format.space_after = Pt(space_after)
        run = p.add_run(text)
        run.bold = bold
        run.font.size = Pt(size)
        return p

    shown = {"links": False, "commented": False}

    if "links" in include_tabs:
        _para(f"Scan #{scan.get('id')} — Link & Navigation Audit", bold=True, size=16, space_after=6)
        for line in _summary_lines(scan):
            _para(line)

    # Same Link-column index mapping as the PDF (old column order:
    # 0=Found on Page, 1=Link, 5=Element Location).
    show_link = link_columns is None or 1 in link_columns
    show_found = link_columns is None or 0 in link_columns
    show_location = link_columns is None or 5 in link_columns

    shots_by_link: Dict[str, Dict[str, Any]] = {}
    for shot in shots or []:
        link = shot.get("link") or ""
        if link and shot.get("png"):
            shots_by_link.setdefault(link, shot)

    docx_appendix_total = 0
    for tag, _heading in PDF_LINK_BUCKETS:
        docx_appendix_total += sum(
            1 for f in findings
            if _bucket_tag(tag, f.get("category") or "") and (shots_by_link.get(f.get("link") or "") or {}).get("png")
        )

    global_appendix_index = 0
    for tag, heading in PDF_LINK_BUCKETS:
        rows = [f for f in findings if _bucket_tag(tag, f.get("category") or "")]
        if not rows:
            continue
        shown["links"] = True

        _para(heading, bold=True, size=13, space_after=4)

        headers = ["S.No."]
        widths = [(w,) for w in _DOCX_BUCKET_WIDTHS_IN]
        row_spec = []  # (include, extractor) mirrored to header/width slices
        if show_link:
            headers.append("Link")
            row_spec.append(lambda f: f.get("link") or "")
        if show_found:
            headers.append("Found on Page")
            row_spec.append(lambda f: _display_path(f.get("found_on_page") or ""))
        if show_location:
            headers.append("Location")
            row_spec.append(lambda f: f.get("element_location") or "")
        headers.append("Appendix")
        table_rows = []
        for ordinal, finding in enumerate(rows, start=1):
            shot = shots_by_link.get(finding.get("link") or "")
            letter = _pdf_letter(ordinal)
            appendix_text = f"Appendix {letter}" if shot is not None else "—"
            tr = [str(ordinal)]
            for extract in row_spec:
                tr.append(extract(finding))
            tr.append(appendix_text)
            table_rows.append(tr)
        _docx_build_table(doc, headers, widths, table_rows)
        _para("", space_after=2)

        # Appendix blocks: letter heading (centered) + screenshot.
        for ordinal, finding in enumerate(rows, start=1):
            shot = shots_by_link.get(finding.get("link") or "")
            if shot is None or not shot.get("png"):
                continue
            global_appendix_index += 1
            letter = _pdf_letter(ordinal)
            _para(f"Appendix {letter}", bold=True, size=11,
                  align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
            try:
                size = _docx_image_size(shot["png"])
                pic_par = doc.add_paragraph()
                pic_par.alignment = WD_ALIGN_PARAGRAPH.CENTER
                pic_run = pic_par.add_run()
                if size is not None:
                    pic_run.add_picture(
                        io.BytesIO(bytes(shot["png"])),
                        width=Inches(size[0]), height=Inches(size[1]))
                else:
                    pic_run.add_picture(
                        io.BytesIO(bytes(shot["png"])), width=Inches(_DOCX_IMAGE_MAX_W_IN))
            except Exception:
                # A corrupt/unreadable PNG must not kill the export.
                _para("(screenshot unavailable)", size=8,
                      align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
            _para("", space_after=4)
            if global_appendix_index % 2 == 0 and global_appendix_index < docx_appendix_total:
                doc.add_page_break()

    if "commented" in include_tabs and commented_findings:
        shown["commented"] = True
        _para("Code Findings", bold=True, size=13, space_after=4)
        # Column visibility via code_columns (None = all six).
        keep = set(range(6)) if code_columns is None else set(code_columns)
        headers = [c for i, c in enumerate(COMMENT_COLUMN_HEADERS) if i in keep]
        widths = [(w,) for i, w in enumerate(_DOCX_CODE_WIDTHS_IN) if i in keep]
        docx_rows = []
        for f in commented_findings:
            row = _comment_finding_row(f)
            docx_rows.append([row[i] for i in sorted(keep)])
        _docx_build_table(doc, headers, widths, docx_rows)

    if not any(shown.values()):
        _para("No issues found in this scan.", size=10)

    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()
