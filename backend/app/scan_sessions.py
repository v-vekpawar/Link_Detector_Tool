"""
In-memory registry for live scan progress (Step 8 of BUILD_ORDER.md).

POST /api/scan/start does cheap, synchronous request validation (site_type
value, required login fields present, mode/site_type compatibility, a
recorded login_config actually existing) and creates the scan's DB row —
then hands off anything that touches the network (dyn_session.start(),
auto-login / replay, the crawl itself) to a background thread and returns
the scan_id immediately.

This module tracks that background thread's live progress so
GET /api/scan/{id}/progress (SSE) can stream it without hitting SQLite on
every tick. Sessions are transient, in-memory, single-process — same
pattern as login_record_sessions.py. The durable record of a finished scan
lives in the `scans`/`findings` tables (via /api/scan/{id}/results), not
here — this registry only needs to survive for the lifetime of one running
scan.

Rolling time estimate (per ARCHITECTURE.md):
- Total page count isn't known upfront (BFS), so no estimate is shown
  during an initial warm-up window (PROGRESS_WARMUP_PAGES pages).
- After warm-up: estimated_remaining_seconds = avg_time_per_page *
  current_frontier_size, recomputed on every progress tick so it tightens
  as the crawl proceeds. This is an estimate, not a promise — pages behind
  broken/slow links can make it swing.
"""

import threading
import time
from typing import Any, Dict, Optional

from app.config import PROGRESS_WARMUP_PAGES

_progress: Dict[int, Dict[str, Any]] = {}
_lock = threading.Lock()


def start_progress(scan_id: int) -> None:
    """Registers a new running scan. Call this right before starting its background thread."""
    with _lock:
        _progress[scan_id] = {
            "status": "running",  # "running" | "completed" | "failed"
            "pages_crawled": 0,
            "links_checked": 0,
            "elapsed_seconds": 0.0,
            "estimated_remaining_seconds": None,  # None while still in the warm-up window
            "error": None,
            "_start_time": time.monotonic(),
        }


def update_progress(scan_id: int, *, pages_crawled: int, links_checked: int, frontier_size: int) -> None:
    """
    Called as crawl_site's progress_callback, from the background thread,
    after each page finishes. Updates counts and recomputes the rolling
    estimate.
    """
    with _lock:
        entry = _progress.get(scan_id)
        if entry is None:
            return  # not tracked (e.g. progress already dropped) — nothing to update

        elapsed = time.monotonic() - entry["_start_time"]
        entry["pages_crawled"] = pages_crawled
        entry["links_checked"] = links_checked
        entry["elapsed_seconds"] = elapsed

        if pages_crawled >= PROGRESS_WARMUP_PAGES:
            avg_time_per_page = elapsed / pages_crawled
            entry["estimated_remaining_seconds"] = round(avg_time_per_page * frontier_size)
        else:
            entry["estimated_remaining_seconds"] = None


def finish_progress(scan_id: int, status: str, error: Optional[str] = None) -> None:
    """status: 'completed' or 'failed'. Marks the final state for the SSE stream's closing event."""
    with _lock:
        entry = _progress.get(scan_id)
        if entry is None:
            return
        entry["status"] = status
        entry["error"] = error
        entry["elapsed_seconds"] = time.monotonic() - entry["_start_time"]
        if status == "completed":
            entry["estimated_remaining_seconds"] = 0


def get_progress(scan_id: int) -> Optional[Dict[str, Any]]:
    """Returns a snapshot dict (internal bookkeeping keys stripped), or None if not tracked."""
    with _lock:
        entry = _progress.get(scan_id)
        if entry is None:
            return None
        snapshot = dict(entry)
    snapshot.pop("_start_time", None)
    return snapshot


def drop_progress(scan_id: int) -> None:
    """Cleanup once a client has consumed the final SSE event. Safe to call even if already gone."""
    with _lock:
        _progress.pop(scan_id, None)