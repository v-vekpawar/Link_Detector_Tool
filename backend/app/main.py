"""
FastAPI backend skeleton (Step 5 of BUILD_ORDER.md).

Wires /api/scan/start, /api/scan/{id}/results, /api/scan/last to the Tier 1
engine SYNCHRONOUSLY — the HTTP request blocks until the whole crawl
finishes. This is deliberately simple, just to confirm the plumbing works
end-to-end. Async orchestration + SSE progress streaming come in Step 8.

Only site_type="static" is wired up here — "dynamic" (Tier 2 / Playwright)
lands in Step 6, and is rejected with a 400 for now.

Run from backend/ with the venv active:
    uvicorn app.main:app --reload
"""

import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.config import extract_reference_ip
from app.crawler import crawl_site
from app.db import get_connection, init_db

app = FastAPI(title="Link & Navigation Audit Tool")


@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class ScanStartRequest(BaseModel):
    target_url: str
    site_type: str  # "static" | "dynamic" — only "static" is wired up so far


class ScanStartResponse(BaseModel):
    scan_id: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FINDING_CATEGORY_KEYS = ("broken", "inactive", "ip_based", "internet")


def _row_to_scan_dict(row) -> dict:
    return {
        "id": row["id"],
        "target_url": row["target_url"],
        "target_ip": row["target_ip"],
        "site_type": row["site_type"],
        "status": row["status"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "pages_crawled": row["pages_crawled"],
        "total_links_checked": row["total_links_checked"],
        "duration_seconds": row["duration_seconds"],
    }


def _summarize(findings: list) -> dict:
    summary = {key: 0 for key in FINDING_CATEGORY_KEYS}
    for finding in findings:
        for category in finding["category"].split(","):
            if category in summary:
                summary[category] += 1
    return summary


def _build_results_payload(scan_id: int):
    conn = get_connection()
    try:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan_row is None:
            return None
        finding_rows = conn.execute(
            """SELECT found_on_page, link, category, code_snippet, evidence, element_location
               FROM findings WHERE scan_id = ?""",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    findings = [dict(row) for row in finding_rows]
    return {
        "scan": _row_to_scan_dict(scan_row),
        "summary": _summarize(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan/start", response_model=ScanStartResponse)
def start_scan(payload: ScanStartRequest):
    if payload.site_type != "static":
        raise HTTPException(
            status_code=400,
            detail="Only site_type='static' is wired up so far — dynamic (Tier 2/Playwright) lands in Step 6.",
        )

    reference_ip = extract_reference_ip(payload.target_url)
    if not reference_ip:
        raise HTTPException(status_code=400, detail="Could not determine a reference IP from target_url.")

    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO scans (target_url, target_ip, site_type, login_used, status)
               VALUES (?, ?, ?, 'none', 'running')""",
            (payload.target_url, reference_ip, payload.site_type),
        )
        conn.commit()
        scan_id = cursor.lastrowid

        start_time = time.monotonic()
        try:
            result = crawl_site(payload.target_url, reference_ip)
        except Exception as e:
            conn.execute(
                "UPDATE scans SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (scan_id,),
            )
            conn.commit()
            raise HTTPException(status_code=502, detail=f"Scan failed: {e}") from e
        duration_seconds = int(time.monotonic() - start_time)

        for finding in result["findings"]:
            conn.execute(
                """INSERT INTO findings
                   (scan_id, found_on_page, link, category, code_snippet, evidence, element_location)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding["found_on_page"],
                    finding["link"],
                    finding["category"],
                    finding.get("code_snippet"),
                    finding.get("evidence"),
                    finding.get("element_location"),
                ),
            )

        conn.execute(
            """UPDATE scans
               SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                   pages_crawled = ?, total_links_checked = ?, duration_seconds = ?
               WHERE id = ?""",
            (result["pages_crawled"], result["total_links_checked"], duration_seconds, scan_id),
        )
        conn.commit()
    finally:
        conn.close()

    return ScanStartResponse(scan_id=scan_id)


@app.get("/api/scan/{scan_id}/results")
def get_scan_results(scan_id: int):
    payload = _build_results_payload(scan_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return payload


@app.get("/api/scan/last")
def get_last_scan():
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="No scans yet.")
    return _build_results_payload(row["id"])