-- Link & Navigation Audit Tool — SQLite schema
-- Matches DATA_MODEL.md. Safe to re-run (CREATE TABLE IF NOT EXISTS).

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url           TEXT NOT NULL,
    target_ip            TEXT,
    site_type            TEXT NOT NULL CHECK (site_type IN ('static', 'dynamic')),
    login_used           TEXT NOT NULL DEFAULT 'none' CHECK (login_used IN ('none', 'auto', 'recorded')),  -- 'auto' kept here for old scan rows recorded before auto-login was removed; new scans never write it
    started_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at         DATETIME,
    status               TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'stopped')),
    pages_crawled        INTEGER,
    total_links_checked  INTEGER,
    duration_seconds     INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    found_on_page     TEXT NOT NULL,
    link              TEXT NOT NULL,
    category          TEXT NOT NULL,   -- comma-separated if multi-tag, e.g. "internet,broken"
    code_snippet      TEXT,
    evidence          TEXT,
    element_location  TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);

CREATE TABLE IF NOT EXISTS login_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip       TEXT NOT NULL UNIQUE,
    mode            TEXT NOT NULL CHECK (mode IN ('recorded')),  -- 'auto' removed; recorded-flow login is the only supported mode now
    login_url       TEXT,
    recorded_steps  TEXT,   -- JSON, used when mode = 'recorded'
    captcha_answer  TEXT,   -- fixed captcha value for this target, if the recorded flow has a captcha field; NULL if none
    logout_url      TEXT,   -- optional URL to navigate to at scan end to log out
    logout_steps    TEXT,   -- JSON, optional recorded logout click/fill sequence; replayed at scan end
    logout_start_url TEXT,  -- page (origin+path) the logout steps were performed on; replay returns there first
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Proof screenshots (screenshots feature): one row per shot, PNG bytes
-- inline. Retention is last-2-scans (the UI only ever reaches the last
-- scan) — older shots are purged on finish, so growth stays bounded
-- (~16MB worst case). New table: CREATE IF NOT EXISTS applies to
-- pre-existing databases on next startup, no migration needed.
CREATE TABLE IF NOT EXISTS screenshot_shots (
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    shot_id         TEXT NOT NULL,
    categories      TEXT NOT NULL,   -- JSON list, e.g. ["broken","ip_based"]
    link            TEXT NOT NULL,
    found_on_page   TEXT NOT NULL,
    breadcrumb      TEXT,
    evidence        TEXT,
    note            TEXT,
    png             BLOB NOT NULL,
    two_panel       INTEGER NOT NULL DEFAULT 0,   -- 1 when the proof stitches a same-host target-result panel
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scan_id, shot_id)
);

CREATE INDEX IF NOT EXISTS idx_screenshot_shots_scan_id ON screenshot_shots(scan_id);

-- Per-scan screenshot phase state (capturing/ready/partial/stopped/failed/none).
CREATE TABLE IF NOT EXISTS screenshot_scan_state (
    scan_id         INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    targets         INTEGER NOT NULL DEFAULT 0,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);