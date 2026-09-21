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

Links and Commented Code are rendered as two separate sections (two
sheets in xlsx, two tables in pdf) rather than one merged table, because
they're different kinds of data: Links entries carry a checked status
(broken/inactive/ip_based/internet) with an Evidence/Reason column that
explains *why* it was flagged; Commented Code entries carry no status —
they're a location tag (which of the seven comment categories) plus the
raw snippet, and don't need a "reason" column at all.

Results table columns, per DATA_MODEL.md / API_SPEC.md:
    Found on Page, Link, Category, Code Snippet, Evidence/Reason, Element Location
"""

import io
from typing import Any, Dict, List
from xml.sax.saxutils import escape as _xml_escape

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
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
    "Code Snippet",
    "Evidence / Reason",
    "Element Location",
]

# Commented Code has no checked status, so no Evidence/Reason column —
# the raw snippet plus location tag already say everything a status
# check would (there's nothing to "reason" about a link that's dead
# code, per comment_scanner.py's module docstring).
COMMENT_COLUMN_HEADERS = [
    "Found On Page",
    "Extracted Value / Target",
    "Finding Type",
    "Severity",
    "Code Snippet",
    "DOM Location",
]

CATEGORY_LABELS = {
    "broken": "Broken",
    "inactive": "Inactive",
    "ip_based": "IP-based",
    "internet": "Internet",
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


def _link_finding_row(finding: Dict[str, Any]) -> List[str]:
    return [
        finding.get("found_on_page") or "",
        finding.get("link") or "",
        _format_category(finding.get("category") or "", CATEGORY_LABELS),
        SEVERITY_LABELS.get(finding.get("severity") or "", ""),
        finding.get("code_snippet") or "",
        finding.get("evidence") or "",
        finding.get("element_location") or "",
    ]


def _comment_finding_row(finding: Dict[str, Any]) -> List[str]:
    return [
        finding.get("found_on_page") or "",
        finding.get("link") or "",
        _format_category(finding.get("category") or "", COMMENT_CATEGORY_LABELS),
        SEVERITY_LABELS.get(finding.get("severity") or "", ""),
        finding.get("code_snippet") or "",
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
) -> bytes:
    """
    Builds an .xlsx workbook with two sheets — "Links" and "Commented
    Code" — each with its own summary block and column set. Returns the
    workbook as raw bytes (nothing written to disk).
    """
    wb = Workbook()

    links_ws = wb.active
    links_ws.title = "Links"
    _write_xlsx_sheet(
        links_ws,
        f"Scan #{scan.get('id')} — Links",
        _summary_lines(scan),
        LINK_COLUMN_HEADERS,
        [_link_finding_row(f) for f in findings],
        "No issues found — every link checked out clean.",
        column_widths=[40, 40, 18, 12, 45, 30, 30],
    )

    comments_ws = wb.create_sheet("Code Findings")
    _write_xlsx_sheet(
        comments_ws,
        f"Scan #{scan.get('id')} — Code Findings",
        _summary_lines(scan),
        COMMENT_COLUMN_HEADERS,
        [_comment_finding_row(f) for f in commented_findings],
        "No issues found in comments or internal/inline CSS/JS.",
        column_widths=[40, 40, 18, 12, 55, 30],
    )

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

def _pdf_section(elements: List, title: str, summary_lines: List[str], headers: List[str],
                  rows: List[List[str]], empty_message: str, col_widths: List[float],
                  styles) -> None:
    title_style = styles["title"]
    summary_style = styles["summary"]
    cell_style = styles["cell"]
    header_style = styles["header"]

    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 4))
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


def build_pdf_bytes(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    commented_findings: List[Dict[str, Any]],
) -> bytes:
    """
    Builds a landscape-letter PDF with two sections in sequence — Links,
    then Commented Code — each with its own heading, summary block, and
    column set sized for its own data. Long cell text (URLs, code
    snippets) is wrapped via Paragraph so it doesn't overflow the page.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=0.4 * inch,
        rightMargin=0.4 * inch,
        topMargin=0.4 * inch,
        bottomMargin=0.4 * inch,
    )

    base_styles = getSampleStyleSheet()
    styles = {
        "title": base_styles["Title"],
        "summary": base_styles["Normal"],
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

    elements: List = []
    summary_lines = _summary_lines(scan)

    # Links: URL-bearing columns get the most room, category/severity the
    # least. Usable width in landscape letter is ~10.2in.
    _pdf_section(
        elements,
        f"Scan #{scan.get('id')} — Link &amp; Navigation Audit: Links",
        summary_lines,
        LINK_COLUMN_HEADERS,
        [_link_finding_row(f) for f in findings],
        "No issues found — every link checked out clean.",
        col_widths=[1.6 * inch, 1.6 * inch, 0.85 * inch, 0.7 * inch, 2.15 * inch, 1.65 * inch, 1.65 * inch],
        styles=styles,
    )

    # Code Findings: one fewer column than Links (no Evidence/Reason),
    # so the Code Snippet column gets the freed-up width instead.
    _pdf_section(
        elements,
        f"Scan #{scan.get('id')} — Link &amp; Navigation Audit: Code Findings",
        summary_lines,
        COMMENT_COLUMN_HEADERS,
        [_comment_finding_row(f) for f in commented_findings],
        "No issues found in comments or internal/inline CSS/JS.",
        col_widths=[1.9 * inch, 1.9 * inch, 1.1 * inch, 0.8 * inch, 2.9 * inch, 1.7 * inch],
        styles=styles,
    )

    doc.build(elements)
    return buffer.getvalue()
