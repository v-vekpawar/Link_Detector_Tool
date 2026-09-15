-- Link & Navigation Audit Tool — SQLite schema
-- Matches DATA_MODEL.md. Safe to re-run (CREATE TABLE IF NOT EXISTS).

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url           TEXT NOT NULL,
    target_ip            TEXT,
    site_type            TEXT NOT NULL CHECK (site_type IN ('static', 'dynamic')),
    login_used           TEXT NOT NULL DEFAULT 'none' CHECK (login_used IN ('none', 'auto', 'recorded')),
    started_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at         DATETIME,
    status               TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    pages_crawled        INTEGER,
    total_links_checked  INTEGER,
    duration_seconds     INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    found_on_page     TEXT NOT NULL,
    link              TEXT,             -- NULL for source-code-scan findings (inline/internal css/js) which aren't about a specific link
    category          TEXT NOT NULL,   -- comma-separated if multi-tag, e.g. "internet,broken"
    code_snippet      TEXT,
    evidence          TEXT,
    element_location  TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);

CREATE TABLE IF NOT EXISTS login_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip       TEXT NOT NULL UNIQUE,
    mode            TEXT NOT NULL CHECK (mode IN ('auto', 'recorded')),
    login_url       TEXT,
    recorded_steps  TEXT,   -- JSON, used when mode = 'recorded'
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);