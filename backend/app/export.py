"""
Export generation for scan results (Step 10 of BUILD_ORDER.md).

Both build_xlsx_bytes() and build_pdf_bytes() take the same two inputs —
a `scan` dict (as returned by _row_to_scan_dict in main.py) and a list of
`findings` dicts (as stored in the findings table) — and return raw bytes
ready to stream back over HTTP. Nothing here touches the DB or FastAPI;
that keeps this module trivially unit-testable and reusable if a future
module needs the same export shape.

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

COLUMN_HEADERS = [
    "Found on Page",
    "Link",
    "Category",
    "Code Snippet",
    "Evidence / Reason",
    "Element Location",
]

CATEGORY_LABELS = {
    "broken": "Broken",
    "inactive": "Inactive",
    "ip_based": "IP-based",
    "internet": "Internet",
}


def _format_category(category_string: str) -> str:
    """Turns a stored comma-separated category tag ('internet,broken') into a display string ('Internet, Broken')."""
    if not category_string:
        return ""
    labels = [CATEGORY_LABELS.get(tag.strip(), tag.strip()) for tag in category_string.split(",") if tag.strip()]
    return ", ".join(labels)


def _finding_row(finding: Dict[str, Any]) -> List[str]:
    return [
        finding.get("found_on_page") or "",
        finding.get("link") or "",
        _format_category(finding.get("category") or ""),
        finding.get("code_snippet") or "",
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

def build_xlsx_bytes(scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
    """
    Builds an .xlsx file with a summary block at the top of the sheet
    followed by the results table (header row + one row per finding).
    Returns the workbook as raw bytes (nothing written to disk).
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"

    bold = Font(bold=True)
    row_index = 1

    ws.cell(row=row_index, column=1, value=f"Scan #{scan.get('id')} — Link & Navigation Audit").font = Font(bold=True, size=14)
    row_index += 1

    for line in _summary_lines(scan):
        ws.cell(row=row_index, column=1, value=line)
        row_index += 1

    row_index += 1  # blank spacer row before the table

    header_row = row_index
    for col_index, header in enumerate(COLUMN_HEADERS, start=1):
        cell = ws.cell(row=header_row, column=col_index, value=header)
        cell.font = bold
        cell.alignment = Alignment(horizontal="left", vertical="top")
    row_index += 1

    if findings:
        for finding in findings:
            for col_index, value in enumerate(_finding_row(finding), start=1):
                cell = ws.cell(row=row_index, column=col_index, value=value)
                cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            row_index += 1
    else:
        ws.cell(row=row_index, column=1, value="No issues found — every link checked out clean.")
        row_index += 1

    # Reasonable fixed column widths — findings data (URLs, snippets) is
    # long and variable-length, so autosize would be unreliable; these
    # widths keep the sheet readable without per-cell measurement.
    column_widths = [40, 40, 18, 45, 30, 30]
    for col_index, width in enumerate(column_widths, start=1):
        ws.column_dimensions[get_column_letter(col_index)].width = width

    ws.freeze_panes = ws.cell(row=header_row + 1, column=1).coordinate

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

def build_pdf_bytes(scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
    """
    Builds a landscape-letter PDF: a title + summary block, then the
    results table. Long cell text (URLs, code snippets) is wrapped via
    Paragraph so it doesn't overflow the page. Returns raw PDF bytes.
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

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    summary_style = styles["Normal"]
    cell_style = ParagraphStyle(
        "cell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        wordWrap="CJK",  # forces breaks on long unbroken strings like URLs
    )
    header_style = ParagraphStyle(
        "header",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.white,
        fontName="Helvetica-Bold",
    )

    elements = [
        Paragraph(f"Scan #{scan.get('id')} — Link &amp; Navigation Audit", title_style),
        Spacer(1, 6),
    ]
    for line in _summary_lines(scan):
        elements.append(Paragraph(line, summary_style))
    elements.append(Spacer(1, 12))

    if findings:
        table_data = [[Paragraph(h, header_style) for h in COLUMN_HEADERS]]
        for finding in findings:
            # Paragraph treats its text as a small XML/HTML-like markup
            # language, so raw code snippets (e.g. '<a href="...">x</a>')
            # must be escaped first or the tags get silently swallowed
            # instead of displayed.
            table_data.append(
                [Paragraph(_xml_escape(str(value)), cell_style) for value in _finding_row(finding)]
            )

        # Column widths sized for landscape letter (usable width ~10.2in):
        # URL-bearing columns get the most room, category the least.
        col_widths = [1.7 * inch, 1.7 * inch, 0.9 * inch, 2.3 * inch, 1.8 * inch, 1.8 * inch]
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
        elements.append(Paragraph("No issues found — every link checked out clean.", summary_style))

    doc.build(elements)
    return buffer.getvalue()