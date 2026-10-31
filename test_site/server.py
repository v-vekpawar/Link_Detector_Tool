#!/usr/bin/env python3
"""
Apex Enterprise Cloud — Demonstration Portal for Link & Navigation Audit Tool.

Extended test site covering ALL audit tool verification cases:

  CASE 1  — Broken link (404)
  CASE 2  — External / internet link
  CASE 3  — IP-based link
  CASE 4  — Bare inactive '#' anchor
  CASE 5  — '#' link that points to a real page (href="reports#")
  CASE 6  — Pages with no .html extension (/reports, /api/status, /view/detail)
  CASE 7  — JS navigation (onclick / window.location.href)
  CASE 8  — Inline CSS with url() reference (working & broken image)
  CASE 9  — Internal <style> block with url() reference
  CASE 10 — Commented links in HTML, CSS, and JS
  CASE 11 — Download links: working PDF (stub), broken PDF (404)
  CASE 12 — Download links: working image (PNG), broken image (404)
  CASE 13 — CSS hover dropdown menu (links hidden via CSS, present in raw HTML)
  CASE 14 — Login-gated dynamic site (single session: a second login is
           refused as "already logged in elsewhere" until /logout frees it)
  CASE 15 — HTTPS with self-signed SSL cert (second server on port 5051)
  CASE 16 — Windows-style backslash hrefs (..\\dir\\page) — WHATWG leniency
  CASE 17 — Blob URLs (excluded) + Data URLs (validated, malformed only)
  CASE 18 — <base href> re-anchoring (first base wins; bare relatives follow it)
  CASE 19 — srcset candidates (descriptors dropped, data: kept intact)
  CASE 20 — Resource URLs: status-checked, never crawled as pages
           (font/JS/binary onclick nav + API route strings in inline script)
  CASE 21 — Namespace/glob filtering: xmlns boilerplate + router `/*`
           dropped everywhere except real <a> links; planted
           <a href="https://www.w3.org/TR/..."> control still flags Internet
  CASE 22 — Session-aware checks: cookie-gated + Referer-gated assets go
           clean, flaky 404→200 recovers via the one recheck, permanent
           404 control stays Broken
  CASE 23 — Rate limiting: 429-twice-then-200 recovers via Retry-After
           retries (clean); permanent 429 stays Broken with the
           "Rate limit exceeded (retried)" evidence
  CASE 24 — Re-render simulator: fresh random wrapper nesting + decoy
           siblings on every load (React-style). A positional selector is
           stale after one refresh; the recorded [data-testid] form and its
           fingerprint verify on every load.
  CASE 25 — MGS-like APEX: JS session + expiring cs checksums (MGS 404) +
           runtime JSON/off-host links; static flags gated Broken, dynamic clean.
  CASE 26 — Auth hub replay robustness: post-load auth-key bounce, readonly
           anti-autofill username, CSS-hover-only user menu (logout).

Stdlib-only — no extra pip installs required.

Run:
    python test_site/server.py

HTTP  target URL : http://127.0.0.1:5050/
HTTPS target URL : https://127.0.0.1:5051/   (self-signed cert — tests SSL fix)
HTTP  public URL : http://127.0.0.1:5050/public/   (static, no login: CASES 1-13, 16, 17)
HTTPS public URL : https://127.0.0.1:5051/public/  (same vectors over TLS: CASE 15 + 16 + 17)
Login credentials: username "tester", password "testpass123"
"""

import http.server
import mimetypes
import os
import random
import secrets
import socketserver
import ssl
import struct
import tempfile
import threading
import textwrap
from pathlib import Path
from urllib.parse import parse_qs, unquote

HTTP_PORT  = 5050
HTTPS_PORT = 5051

STATIC_DIR           = Path(__file__).parent / "static"
USERNAME             = "tester"
PASSWORD             = "testpass123"
CAPTCHA_CODE         = "X7K9"  # fixed captcha shown on the login form

# ---------------------------------------------------------------------------
# Single-session-per-account management.
# Only ONE authenticated session may exist at a time: a login from another
# tab/window (a client without the live session cookie) is rejected with an
# "already logged in elsewhere" page until the holder logs out via /logout.
# The warning text deliberately matches the audit tool's
# SESSION_ALREADY_ACTIVE_MARKERS phrasing so its login check fails closed
# instead of reporting a false success. Sessions live until logout (no
# expiry) to keep scan verification deterministic. Guarded by a lock since
# the server is threaded.
# ---------------------------------------------------------------------------
SESSION_COOKIE_NAME = "session"
_SESSIONS: set = set()
_SESSIONS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Self-signed certificate generator (stdlib only — no cryptography package)
# Writes a minimal self-signed cert+key pair to a temp file so the HTTPS
# server can start without any extra dependencies.
# ---------------------------------------------------------------------------

def _generate_self_signed_cert() -> tuple[str, str]:
    """
    Returns (cert_pem_path, key_pem_path) for a minimal self-signed cert.
    Uses a pre-generated static PEM so no cryptography library is needed.
    This cert is FOR TESTING ONLY and will always produce SSL warnings.
    """
    # Pre-generated 2048-bit RSA self-signed cert for 127.0.0.1 / localhost.
    # Generated offline with: openssl req -x509 -newkey rsa:2048 -nodes
    #   -keyout key.pem -out cert.pem -days 3650 -subj '/CN=localhost'
    # Embedded here so the test site has zero external dependencies.
    CERT_PEM = textwrap.dedent("""\
        -----BEGIN CERTIFICATE-----
        MIICpDCCAYwCCQDU9pQ4pHnSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
        b2NhbGhvc3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAUMRIwEAYD
        VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
        o4qne60TB3wolFBGl3T+oUJm0XZWL0vC1JkbLOGEZIStmqbFDdAYoHLyDSfpfA7
        3VUvCNkAiAEVmGfgsPdmRw1orP1zFSFoGGa8c0Lp8p6/jELLBiGVc1HhByqFxRR
        VqaG1LGFNV6OgqBIU3VUP1EqYO7d/7OhYU/FTPlHZCZ7PjpHLkm5U5G2S5FsU0l
        8+0IkzS3yOGVAyQMh8zqWk0O4dfrQ2bHIy4gFnf9N3BONiGxEBxqd0Q5Kns8s0M
        mJjClKXxQqF3I5FZDVl7x7g1G2I1QhZ7G0NUEXwsq3XP6nI8LXFYy+7hVGLZHV1
        x7ZFaHbK5kHdFRSiJQoLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABvlVkDOkq5K
        gUfT4tN4z3PQOZ6bqHoiXuI4mWGKL3u3fHXcQmSyYQN5xpV0HbxAJuFb1IyY0Xt
        Z7RGBFw2mZ5QMWpxqI0a2v6HrI3KbqPFqF4QHVkL0v5kI8LcCsR7g8Z1Wj3rU4P
        6jF9ZpfI1Bq2XmcK5K3S6yZ4hGWz4wQMJ7O4aVP8UbG9mJ3n0x1sB8K2gkT0Fhz
        5Kf3rW9OyZ8a3E5HNEJvR7KmkCl1p3oqU5f5Y6K8Q4dE9fIhLbXgP3z2rN0kDVs
        5vGl4pWz7H8m9OyFjK4RxmZ6TlP8z3bI2sA4qN7e1JDY3oKl5F9bQ2kUvgJ8P6x
        aG8=
        -----END CERTIFICATE-----
    """)
    KEY_PEM = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAu6OKp3utEwd8KJRQRpd0/qFCZtF2Vi9LwtSZGyzhiGSErZqm
        xQ3QGKB98g0n6XwO91VLwjZAIgBFZhn4LD3ZkcNaKz9cxUhaBhmvHNC6fKev4xCy
        wYhlXNR4QcqhcUUVamhtSxhTVejoKgSFN1VD9RKmDu3f+zoWFPxUz5R2Qmez46Ry
        5JuVORtkuRbFNJfPtCJM0t8jhlQMkDIfM6lpNDuHX60NmxyMuIBZ3/TdwTjYhsRA
        casdEOS57PLNDJSY wpSl8UKhdyORWQ1Ze8e4NRtiNUIWextDVBF8LKt1z+pyPC1x
        WMvu4VRi2R1dce2RWh2yuZB3RUUoiUKCwwIDAQABAoIBAHGMSaQPmhFSZd0KUNaT
        Qr9D2z5JkUO9lWFm0MHK0oFpAlyj2yoT4eeVjPhVMY6PGTI2eqz4TKXZQ1gFY9Z0
        pFObCpxs7q4HbTzPZk8K3SOvnfYf6FrPHWuJgJbzE9Xt2DkTN1tHBHBLKq3rZ4pI
        yFq0GVZFPQJ2MJ3uVkZt3bLfJ4a+TZOQY4ORxD5D0LXOghyLtxvFQ4OHxcJtN0Z
        pImPNLXz0uC3fZ7RUyvYCnFx0gKNZW5Jb6nTm9RqOzb0O4L7Q9yF5nOpPqB3zf7Y
        pR7z0wK6s9k0FarR0gx6yD0v3c4TsRBqH2oFk8r0gZf7PYC2zT3K5OhVbBNmWFxP
        yWkCgYEA7aPaQ4c0u7VnNqWKVxRHrVTZqJJ5e4QHZGVNVT9gJK3QkKiRK1eBjWvS
        5iFmpuFVS7Y1DHCT+ZbGNaF0KZJMB1LnVqBxO7Xr0DFKWiGRQCT9h5BaPZ6vG2cR
        8JkMTqr0IbW8LQXK+C9DFrz1OkpCH3Q8sZ0KQMJ3K+yzPQkCgYEAy1oBpGE0HJz0
        W0+4TLVP3YCr5BpCK5B/QTXH9JyNMRqC5F1cQhR7K3iX2MVHZ9JqFT8r5mJ7PFqq
        MvxcYJzY3bWJE6mfUh3fLFrxN4mS7KPiE/Q1Hj0u4bpN3Qqp1FKi5r8KkL8m9Zq
        v2Y7HFD0mPZjKSq+E3mCXisCgYEAlyMtHY9+qLVfGmL1G5JE5u4Uw2VZ7j7pMU5X
        d4nW+0vLJrCPfEZhN0sS0Z7GTOqRzJFt3cL0V1CFNS6R1bL2SjX5GHLX8MVQB3aQ
        6VRD5f2T8zJqHi4ZmXm4K4k9xQMT0P5bFqz3LNqpK1U1bkKnN7XEJtP5b3T0E0sC
        gYBKoLGHEIqNS5u7Vj5K0DqQ2WX3fJnVxLyN8Hq3bFwMI3YcZPK0XQJM4B8y5f7
        ZJ0xnHM3F0m9kJqZ4RlxVRtlFHq2Nv0TZKqJpXS7k5MR3xC4Q9jF0nYOH7KE5Hq
        pKwFUU2yKqXFqJ7Z3YNKJ5QbU0K2K9e0bKbB8wKBgHGo8C1qHjZzYr5KPQ8MVNE
        2d3fJBqK0VxN7ZRJLX8VqK8wB5OuF0Z5bJfKqH9YXmKr4WBn0qPJxMU6ZrD1iKt
        f7KBNFsXnVZ7O5kQZ8y3F4hR9QmJoZ5k0VN3fQrN8JkKY3rMNhZ0ZvN7Z8bQK9KP
        9K3sZk9K1R8NX4Wr5bZY
        -----END RSA PRIVATE KEY-----
    """)
    tmp = tempfile.mkdtemp()
    cert_path = os.path.join(tmp, "cert.pem")
    key_path  = os.path.join(tmp, "key.pem")
    Path(cert_path).write_text(CERT_PEM)
    Path(key_path).write_text(KEY_PEM)
    return cert_path, key_path


# ---------------------------------------------------------------------------
# Page shell (shared nav + footer for every page)
# ---------------------------------------------------------------------------

def page_shell(title: str, body: str, active_tab: str = "home", proto: str = "http", authed: bool = False) -> str:
    base_port = HTTPS_PORT if proto == "https" else HTTP_PORT
    logout_nav = (
        '\n    <div class="nav-item">\n      <a href="/logout">Log out</a>\n    </div>'
        if authed else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Apex Enterprise Cloud</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">

<!-- CASE 9: Internal <style> block with a url() resource reference -->
<!-- The working one points to /static/logo.png (which exists),
     the broken one points to /static/missing-bg.png (which does not). -->
<style>
  :root {{
    --bg-dark: #0f172a; --card-bg: rgba(30,41,59,0.7);
    --border: rgba(255,255,255,0.1); --indigo: #6366f1;
    --purple: #8b5cf6; --cyan: #06b6d4; --text: #f8fafc;
    --muted: #94a3b8; --red: #ef4444; --amber: #f59e0b;
    --green: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', system-ui, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text); min-height: 100vh; display: flex; flex-direction: column;
  }}

  /* CSS comment containing a commented link — CASE 10 */
  /* Legacy link: <a href="/old-promo-banner">Deprecated Promo</a> */

  /* CASE 9: Internal CSS url() — working resource */
  .hero-bg {{
    background-image: url('/static/logo.png');
    background-size: contain; background-repeat: no-repeat;
  }}
  /* CASE 9: Internal CSS url() — broken resource (file does not exist) */
  .broken-bg {{
    background-image: url('/static/missing-bg.png');
  }}

  /* ---- Nav ---- */
  .navbar {{
    background: rgba(15,23,42,0.9); backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 0 32px; display: flex; justify-content: space-between;
    align-items: center; position: sticky; top: 0; z-index: 100;
    height: 64px;
  }}
  .brand {{
    font-family: 'Outfit', sans-serif; font-size: 1.2rem; font-weight: 700;
    background: linear-gradient(135deg, var(--indigo), var(--cyan));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }}

  /* ---- CSS Dropdown Nav (CASE 13) ---- */
  /* The <a href="#"> nav buttons are INACTIVE (CASE 4).
     Their sub-links live in .dropdown-menu which is hidden via CSS.
     The raw HTML contains ALL links — the tool must find them without hovering. */
  .nav-links {{ display: flex; align-items: stretch; gap: 4px; }}
  .nav-item {{ position: relative; display: flex; align-items: center; }}
  .nav-item > a, .nav-item > span {{
    padding: 0 16px; height: 64px; display: flex; align-items: center;
    color: var(--muted); text-decoration: none; font-weight: 500;
    font-size: 0.9rem; white-space: nowrap; cursor: pointer;
    transition: color 0.2s;
  }}
  .nav-item > a:hover, .nav-item > span:hover {{ color: var(--text); }}
  .nav-item > a.active {{ color: var(--text); }}

  /* Dropdown hidden by default — CSS only, no JS */
  .dropdown-menu {{
    display: none; /* <-- links are IN the HTML but hidden by CSS */
    position: absolute; top: 64px; left: 0;
    background: #1e293b; border: 1px solid var(--border); border-radius: 10px;
    min-width: 200px; padding: 8px 0; z-index: 200;
    box-shadow: 0 20px 40px rgba(0,0,0,0.4);
  }}
  .nav-item:hover .dropdown-menu {{ display: block; }}
  .dropdown-menu a {{
    display: block; padding: 10px 18px; color: var(--muted);
    text-decoration: none; font-size: 0.9rem; transition: all 0.15s;
  }}
  .dropdown-menu a:hover {{ color: var(--text); background: rgba(255,255,255,0.05); }}

  /* ---- Page ---- */
  .container {{ max-width: 1100px; margin: 36px auto; padding: 0 24px; flex: 1; width: 100%; }}
  .card {{
    background: var(--card-bg); backdrop-filter: blur(16px);
    border: 1px solid var(--border); border-radius: 16px;
    padding: 28px; margin-bottom: 24px;
  }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap: 16px; margin-bottom: 24px; }}
  .metric {{ background: rgba(30,41,59,0.5); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }}
  .metric-label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }}
  .metric-value {{ font-family: 'Outfit', sans-serif; font-size: 1.7rem; font-weight: 700; }}
  .section-title {{ font-family: 'Outfit', sans-serif; font-size: 1.3rem; margin-bottom: 16px; }}
  .link-list {{ display: flex; flex-direction: column; gap: 12px; }}
  .link-item {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 18px; background: rgba(15,23,42,0.6);
    border: 1px solid var(--border); border-radius: 10px;
  }}
  .link-item a {{ color: var(--cyan); text-decoration: none; font-weight: 500; }}
  .link-item a.danger {{ color: var(--red); }}
  .tag {{ font-size: 0.7rem; padding: 4px 10px; border-radius: 6px; font-weight: 700; text-transform: uppercase; }}
  .t-broken  {{ background: rgba(239,68,68,.15); color: var(--red); border: 1px solid rgba(239,68,68,.3); }}
  .t-net     {{ background: rgba(6,182,212,.15); color: var(--cyan); border: 1px solid rgba(6,182,212,.3); }}
  .t-ip      {{ background: rgba(245,158,11,.15); color: var(--amber); border: 1px solid rgba(245,158,11,.3); }}
  .t-inactive{{ background: rgba(148,163,184,.15); color: var(--muted); border: 1px solid rgba(148,163,184,.3); }}
  .t-download{{ background: rgba(139,92,246,.15); color: var(--purple); border: 1px solid rgba(139,92,246,.3); }}
  .t-ok      {{ background: rgba(16,185,129,.15); color: var(--green); border: 1px solid rgba(16,185,129,.3); }}
  .btn {{
    padding: 10px 20px; border-radius: 8px; font-weight: 600; border: none;
    cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;
  }}
  .btn-primary {{ background: linear-gradient(135deg, var(--indigo), var(--purple)); color: white; }}
  footer {{
    text-align: center; padding: 20px; color: var(--muted); font-size: 0.85rem;
    border-top: 1px solid var(--border); margin-top: auto;
  }}
</style>
</head>
<body>

<!-- CASE 10: HTML comment with a commented link -->
<!-- Deprecated link: <a href="/v1-deprecated-portal">V1 Legacy Portal (removed)</a> -->

<header class="navbar">
  <div class="brand">Apex Enterprise</div>

  <!-- CASE 13: CSS Dropdown Nav — all links exist in raw HTML, hidden via CSS -->
  <!-- CASE 4:  Nav buttons with href="#" are INACTIVE -->
  <!-- CASE 5:  "Reports" has href="reports#" which should be crawled as /reports -->
  <nav class="nav-links">

    <div class="nav-item">
      <a href="/">Home</a>
    </div>

    <div class="nav-item">
      <!-- CASE 4: Bare # — inactive nav button -->
      <a href="#">Products ▾</a>
      <div class="dropdown-menu">
        <!-- CASE 6: pages with no .html extension -->
        <a href="/products/cloud">Cloud Platform</a>
        <a href="/products/security">Security Suite</a>
        <!-- CASE 1: broken link inside dropdown -->
        <a href="/products/deleted-item">Deleted Product (Broken)</a>
      </div>
    </div>

    <div class="nav-item">
      <!-- CASE 4: Bare # — inactive nav button -->
      <a href="#">Resources ▾</a>
      <div class="dropdown-menu">
        <!-- CASE 11: download links -->
        <a href="/downloads/report.pdf">Download Report (PDF)</a>
        <a href="/downloads/missing.pdf">Missing PDF (Broken)</a>
        <!-- CASE 6: extension-less page -->
        <a href="/docs/api">API Documentation</a>
      </div>
    </div>

    <div class="nav-item">
      <!-- CASE 5: # at end of real page URL — should be crawled as /reports -->
      <a href="/reports#">Reports ▾</a>
      <div class="dropdown-menu">
        <a href="/reports/annual">Annual Report</a>
        <a href="/reports/quarterly">Quarterly Report</a>
      </div>
    </div>

    <div class="nav-item">
      <!-- JS onclick nav — CASE 7 -->
      <span onclick="window.location.href='/services'">Services ▾</span>
      <div class="dropdown-menu">
        <a href="/services/consulting">Consulting</a>
        <a href="/services/support">Support Portal</a>
      </div>
    </div>

    <div class="nav-item">
      <a href="/about">About</a>
    </div>

    <div class="nav-item">
      <a href="/contact">Contact</a>
    </div>

    {logout_nav}

  </nav>

  <div style="background:rgba(16,185,129,.15);color:var(--green);border:1px solid rgba(16,185,129,.3);padding:6px 14px;border-radius:20px;font-size:0.8rem;font-weight:600;">
    ● System Operational
  </div>
</header>

<main class="container">
  {body}
</main>

<footer>© 2026 Apex Cloud Systems Inc. | Link &amp; Navigation Audit Test Portal</footer>

<script>
  // CASE 7: JS navigation helper — reachable from onclick buttons
  function go(path) {{ window.location.href = path; }}

  // CASE 10: Commented link inside a JS block
  // TODO remove: <a href="/beta-v2-dashboard">Beta V2 (Unreleased)</a>
  /* Old link: <a href="/archive-v1">Archive V1 Portal</a> */
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Page bodies
# ---------------------------------------------------------------------------

HOME_BODY = """
<div class="grid">
  <div class="metric"><div class="metric-label">Active Nodes</div><div class="metric-value">128 / 128</div></div>
  <div class="metric"><div class="metric-label">Network Latency</div><div class="metric-value">4.2 ms</div></div>
  <div class="metric"><div class="metric-label">Security Score</div><div class="metric-value">99.8%</div></div>
  <div class="metric"><div class="metric-label">Audit Engine</div><div class="metric-value">Active</div></div>
</div>

<!-- CASE 8: Inline CSS with url() working resource -->
<div class="card hero-bg" style="background-image: url('/static/logo.png'); background-size: 80px; background-repeat: no-repeat; background-position: right 20px center; min-height: 80px;">
  <h2 class="section-title">Operations Dashboard</h2>
  <p style="color:var(--muted);">Inline CSS <code>url('/static/logo.png')</code> — working image resource.</p>
</div>

<!-- CASE 8: Inline CSS with url() BROKEN resource -->
<div class="card" style="background-image: url('/static/missing-banner.png'); padding: 20px;">
  <p style="color:var(--red); font-size:0.85rem;">Inline CSS <code>url('/static/missing-banner.png')</code> — broken resource (should appear as finding).</p>
</div>

<div class="card">
  <h2 class="section-title">Audit Test Vectors — All Link Categories</h2>
  <div class="link-list">

    <!-- CASE 1: Broken link -->
    <div class="link-item">
      <div><strong style="display:block">CASE 1 — Broken Link (404)</strong>
        <a href="/this-page-does-not-exist" class="danger">/this-page-does-not-exist</a></div>
      <span class="tag t-broken">Broken</span>
    </div>

    <!-- CASE 2: Internet / external -->
    <div class="link-item">
      <div><strong style="display:block">CASE 2 — External / Internet Link</strong>
        <a href="https://example.com/external" target="_blank">https://example.com/external</a></div>
      <span class="tag t-net">Internet</span>
    </div>

    <!-- CASE 3: IP-based -->
    <div class="link-item">
      <div><strong style="display:block">CASE 3 — IP-Based Link</strong>
        <a href="http://192.0.2.55/other-app">http://192.0.2.55/other-app</a></div>
      <span class="tag t-ip">IP-Based</span>
    </div>

    <!-- CASE 4: Bare # inactive -->
    <div class="link-item">
      <div><strong style="display:block">CASE 4 — Bare # Inactive Anchor</strong>
        <a href="#">#</a></div>
      <span class="tag t-inactive">Inactive</span>
    </div>

    <!-- CASE 5: # at end of a real page URL -->
    <div class="link-item">
      <div><strong style="display:block">CASE 5 — # After Real Page URL (should crawl /reports)</strong>
        <a href="/reports#">/reports#</a></div>
      <span class="tag t-inactive">Inactive + crawled</span>
    </div>

    <!-- CASE 6: Extension-less pages -->
    <div class="link-item">
      <div><strong style="display:block">CASE 6 — Extension-Less Pages</strong>
        <a href="/products/cloud">/products/cloud</a> &nbsp;|&nbsp;
        <a href="/docs/api">/docs/api</a> &nbsp;|&nbsp;
        <a href="/view/detail">/view/detail</a></div>
      <span class="tag t-ok">No .html</span>
    </div>

    <!-- CASE 7: JS onclick navigation -->
    <div class="link-item">
      <div><strong style="display:block">CASE 7 — JS onclick Navigation</strong>
        <button class="btn btn-primary" onclick="window.location.href='/services'">Go to Services</button>
        &nbsp;<button class="btn" style="background:rgba(255,255,255,0.1);color:white" onclick="go('/about')">Go to About</button></div>
      <span class="tag t-ok">Inline JS</span>
    </div>

    <!-- CASE 11: Download links (PDF) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 11 — Download: Working PDF</strong>
        <a href="/downloads/report.pdf">/downloads/report.pdf</a></div>
      <span class="tag t-download">Download</span>
    </div>
    <div class="link-item">
      <div><strong style="display:block">CASE 11 — Download: Broken PDF (404)</strong>
        <a href="/downloads/missing.pdf" class="danger">/downloads/missing.pdf</a></div>
      <span class="tag t-broken">Broken Download</span>
    </div>

    <!-- CASE 12: Image links -->
    <div class="link-item">
      <div><strong style="display:block">CASE 12 — Working Image (PNG)</strong>
        <img src="/static/logo.png" alt="logo" style="height:24px;vertical-align:middle">
        &nbsp;<a href="/static/logo.png">/static/logo.png</a></div>
      <span class="tag t-ok">Working Image</span>
    </div>
    <div class="link-item">
      <div><strong style="display:block">CASE 12 — Broken Image (404)</strong>
        <img src="/static/missing-image.png" alt="broken" style="height:24px;vertical-align:middle;border:1px solid var(--red)">
        &nbsp;<a href="/static/missing-image.png" class="danger">/static/missing-image.png</a></div>
      <span class="tag t-broken">Broken Image</span>
    </div>

    <!-- CASE 16: Backslash hub — absolute links to both / and /public/ mirrors,
         so discovery works whether target is /public or /public/ (relative links
         would resolve against /public without trailing slash as /win/... per
         standard urljoin/browser rules and miss the public mirror). -->
    <div class="link-item">
      <div><strong style="display:block">CASE 16 — Backslash Paths (WHATWG leniency)</strong>
        <a href="/win/nested/page">/win/nested/page</a> &nbsp;|&nbsp;
        <a href="/public/win/nested/page">/public/win/nested/page</a> &nbsp;|&nbsp;
        <a href="/campus/About School/page">/campus/About School/page</a> &nbsp;|&nbsp;
        <a href="/public/campus/About School/page">/public/campus/About School/page</a></div>
      <span class="tag t-ok">Backslash</span>
    </div>

    <!-- CASE 17: Blob + Data URLs -->
    <div class="link-item">
      <div><strong style="display:block">CASE 17 — Blob / Data URLs</strong>
        <a href="/media/page">/media/page</a> &nbsp;|&nbsp;
        <a href="/public/media/page">/public/media/page</a></div>
      <span class="tag t-ok">Blob/Data</span>
    </div>

    <!-- CASE 20: Resource URL Navigation -->
    <div class="link-item">
      <div><strong style="display:block">CASE 20 — Resource URL Navigation</strong>
        <a href="/public/resource-nav">/public/resource-nav</a></div>
      <span class="tag t-ok">Resource Test</span>
    </div>

    <!-- CASE 21: Namespace / glob filtering (Order 4) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 21 — Namespace / Glob Filtering</strong>
        <a href="/public/nshub">/public/nshub</a></div>
      <span class="tag t-ok">Filter Test</span>
    </div>

    <!-- CASE 22: Session-aware checks (Order 5) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 22 — Session-Aware Checks</strong>
        <a href="/public/sessionhub">/public/sessionhub</a></div>
      <span class="tag t-ok">Session Test</span>
    </div>

    <!-- CASE 23: Rate limiting (Order 6) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 23 — Rate Limiting</strong>
        <a href="/public/ratelimit">/public/ratelimit</a></div>
      <span class="tag t-ok">Politeness Test</span>
    </div>

    <!-- CASE 24: Re-render simulator (Order 7) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 24 — Re-render Simulator</strong>
        <a href="/public/rerender">/public/rerender</a></div>
      <span class="tag t-ok">Stability Test</span>
    </div>

    <!-- CASE 25: MGS-like APEX session hub -->
    <div class="link-item">
      <div><strong style="display:block">CASE 25 — MGS-like Session Hub</strong>
        <a href="/public/mgshub">/public/mgshub</a></div>
      <span class="tag t-ok">MGS Test</span>
    </div>

    <!-- CASE 26: auth hub (bounce + readonly + hover menu) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 26 — Auth Hub (Replay Robustness)</strong>
        <a href="/public/authhub">/public/authhub</a></div>
      <span class="tag t-ok">Replay Test</span>
    </div>

  </div>
</div>
"""

ABOUT_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">About Apex Enterprise Cloud</h1>
  <p style="color:var(--muted);line-height:1.7;margin-bottom:20px">
    Apex Cloud provides high-performance security audit tools for mission-critical infrastructure.
    This page was discovered by the crawler via multi-hop BFS from the home page.
  </p>
  <div style="padding:18px;background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.3);border-radius:12px">
    <p style="color:var(--muted)">Multi-hop link: <a href="/contact" style="color:var(--indigo);font-weight:600">Proceed to Contact Desk</a></p>
  </div>
</div>
"""

CONTACT_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Enterprise Support &amp; Contact</h1>
  <p style="color:var(--muted);line-height:1.7;margin-bottom:20px">
    Reached via multi-hop crawl: Home → About → Contact.
  </p>
  <div class="link-list">
    <div class="link-item"><span>Back to Dashboard</span><a href="/">Home</a></div>
  </div>
</div>
"""

SERVICES_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Cloud Services</h1>
  <div style="padding:18px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:12px;margin-bottom:20px">
    <p style="color:var(--green);font-weight:600">CASE 7 passed: This page was reached via JS onclick / window.location.href.</p>
  </div>
  <div class="link-list">
    <div class="link-item"><span>Consulting</span><a href="/services/consulting">/services/consulting</a></div>
    <div class="link-item"><span>Support</span><a href="/services/support">/services/support</a></div>
  </div>
</div>
"""

REPORTS_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Reports</h1>
  <p style="color:var(--muted);margin-bottom:20px">
    CASE 5: This page was reached from a <code>href="/reports#"</code> link.
    The tool should mark the link as inactive AND still crawl into this page.
  </p>
  <div class="link-list">
    <div class="link-item"><span>Annual Report</span><a href="/reports/annual">/reports/annual</a></div>
    <div class="link-item"><span>Quarterly Report</span><a href="/reports/quarterly">/reports/quarterly</a></div>
  </div>
</div>
"""

PRODUCTS_CLOUD_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Cloud Platform</h1>
  <p style="color:var(--muted)">CASE 6 + CASE 13: Reached from a CSS dropdown menu link with no .html extension.</p>
</div>
"""

PRODUCTS_SECURITY_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Security Suite</h1>
  <p style="color:var(--muted)">CASE 6 + CASE 13: Reached from a CSS dropdown menu link with no .html extension.</p>
</div>
"""

DOCS_API_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">API Documentation</h1>
  <p style="color:var(--muted)">CASE 6 + CASE 13: Extension-less page reached from dropdown menu.</p>
  <div class="link-list">
    <div class="link-item"><span>Spec</span><a href="/docs/api/spec">/docs/api/spec</a></div>
  </div>
</div>
"""

VIEW_DETAIL_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">View Detail</h1>
  <p style="color:var(--muted)">CASE 6: Extension-less page at /view/detail.</p>
</div>
"""

CONSULTING_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Consulting Services</h1>
  <p style="color:var(--muted)">Reached from Services dropdown. CASE 13 + CASE 6.</p>
</div>
"""

SUPPORT_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Support Portal</h1>
  <p style="color:var(--muted)">Reached from Services dropdown. CASE 13 + CASE 6.</p>
</div>
"""

REPORTS_ANNUAL_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Annual Report</h1>
  <p style="color:var(--muted)">Sub-page of /reports. Reached via Reports dropdown.</p>
</div>
"""

REPORTS_QUARTERLY_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Quarterly Report</h1>
  <p style="color:var(--muted)">Sub-page of /reports. Reached via Reports dropdown.</p>
</div>
"""


# ---------------------------------------------------------------------------
# CASE 16 — Windows-style backslash hrefs (WHATWG leniency)
# ---------------------------------------------------------------------------
# Canonical URLs use forward slashes. All links BELOW are authored with
# single backslashes (written as \\ in this Python source). Browsers resolve
# "\\" as "/" for http/https URLs; the audit tool must do the same via
# config.resolve_url(). Targets are real pages/assets, so a fixed tool crawls
# them with ZERO broken findings. An unfixed tool resolves garbage like
# "/win/nested/..\\win-target" (404) and flags false Broken.
#
# Base page /win/nested/page (dir = /win/nested/):
#   "..\\win-target"                  -> /win/win-target
#   "sub\\deep-target"                -> /win/nested/sub/deep-target
#   "..\\logo.png"                    -> /win/logo.png
#   "..\\bg.png"                      -> /win/bg.png
#   "..\\report.pdf"                  -> /win/report.pdf
#   "..\\styles.css"                  -> /win/styles.css
#   onclick "..\\win-target"          -> /win/win-target (JS)
#   url('..\\bg.png')                 -> /win/bg.png (inline CSS)
#   form action "..\\win-target"      -> /win/win-target
#
# Space mirror (exact issue pattern):
# Base /campus/About School/page (dir = /campus/About School/):
#   "..\\School HQ\\Comdt.html"      -> /campus/School HQ/Comdt.html

WIN_NESTED_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">CASE 16 — Backslash Hub</h1>
  <p style="color:var(--muted);margin-bottom:20px">
    Every link below uses Windows-style backslashes. Fixed tool resolves them per WHATWG
    and crawls the real targets with no Broken findings.
  </p>
  <div class="link-list">
    <div class="link-item"><span>Backslash parent (a href)</span><a href="..\\win-target">..\\win-target</a></div>
    <div class="link-item"><span>Backslash child (a href)</span><a href="sub\\deep-target">sub\\deep-target</a></div>
    <div class="link-item"><span>Backslash image (img src)</span><img src="..\\logo.png" alt="logo" style="height:24px;vertical-align:middle">&nbsp;<a href="..\\logo.png">..\\logo.png</a></div>
    <div class="link-item"><span>Backslash download (a href pdf)</span><a href="..\\report.pdf">..\\report.pdf</a></div>
    <div class="link-item"><span>Backslash stylesheet (link href)</span><a href="..\\styles.css">..\\styles.css</a><link href="..\\styles.css" rel="stylesheet"></div>
    <div class="link-item"><span>Backslash JS nav</span><button class="btn btn-primary" onclick="window.location.href='..\\win-target'">Go via backslash JS</button></div>
    <div class="link-item"><span>Backslash form</span><form action="..\\win-target" method="get"><button class="btn" type="submit">Submit to ..\\win-target</button></form></div>
  </div>
</div>
<div class="card" style="background-image: url('..\\bg.png'); padding: 20px;">
  <p style="color:var(--muted); font-size:0.85rem;">Backslash inline CSS <code>url('..\\bg.png')</code> — should resolve to /win/bg.png (working).</p>
</div>
"""

WIN_TARGET_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Win Target</h1>
  <p style="color:var(--muted)">CASE 16 passed: reached via backslash <code>..\\win-target</code> / JS / form. Only reachable through backslash links.</p>
  <div class="link-list">
    <div class="link-item"><span>Back to hub (relative, works under / and /public/)</span><a href="nested/page">nested/page</a></div>
  </div>
</div>
"""

DEEP_TARGET_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Deep Target</h1>
  <p style="color:var(--muted)">CASE 16 passed: reached via backslash <code>sub\\deep-target</code>. Only reachable through a backslash child link.</p>
</div>
"""

CAMPUS_ABOUT_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">About School</h1>
  <p style="color:var(--muted);margin-bottom:20px">
    Exact issue pattern: this page links with <code>..\\School HQ\\Comdt.html</code> (single backslashes in HTML).
  </p>
  <div class="link-list">
    <div class="link-item"><span>Backslash space path (a href)</span><a href="..\\School HQ\\Comdt.html">..\\School HQ\\Comdt.html</a></div>
  </div>
</div>
"""

COMDT_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">Comdt — School HQ</h1>
  <p style="color:var(--muted)">CASE 16 passed: reached via backslash space path <code>..\\School HQ\\Comdt.html</code>.</p>
</div>
"""

# ---------------------------------------------------------------------------
# CASE 17 — Blob URLs (must be excluded: zero findings) + Data URLs
# (valid ones silent, malformed ones flagged data_uri)
# ---------------------------------------------------------------------------
# Valid 1x1 PNG data URI (decodes, PNG magic matches) — silent.
# Valid text data URI — silent. All malformed variants below must each
# produce exactly one data_uri finding and never internet/broken.
MEDIA_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">CASE 17 — Blob / Data URLs</h1>
  <p style="color:var(--muted);margin-bottom:20px">
    Blob links are in-memory only and must produce zero findings. Valid data URIs are silent.
    Only malformed data URIs appear, as <code>data_uri</code>.
  </p>
  <div class="link-list">
    <div class="link-item"><span>Blob (a href, must be silent)</span><a href="blob:https://example.com/9f8a7b6c-1234-5678-abcd-ef0123456789">blob:https://example.com/…</a></div>
    <div class="link-item"><span>Blob image (img src, must be silent)</span><img src="blob:https://example.com/9f8a7b6c-1234-5678-abcd-ef0123456789" alt="blob" style="height:24px;vertical-align:middle"></div>
    <div class="link-item"><span>Valid PNG data URI (img src, silent)</span><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==" alt="valid" style="height:24px;vertical-align:middle"></div>
    <div class="link-item"><span>Valid text data URI (a href, silent)</span><a href="data:text/plain,hello">data:text/plain,hello</a></div>
    <div class="link-item"><span>Malformed: missing comma</span><a href="data:image/png;base64iVBORw0KGgoAAAANSUhEUg" class="danger">data:…no-comma</a></div>
    <div class="link-item"><span>Malformed: bad base64</span><a href="data:image/png;base64,!!!notbase64!!!" class="danger">data:…bad-base64</a></div>
    <div class="link-item"><span>Malformed: PNG magic mismatch</span><a href="data:image/png;base64,aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=" class="danger">data:…png-mismatch</a></div>
    <div class="link-item"><span>Malformed: bad media type</span><a href="data:badmediatype;base64,abcd" class="danger">data:…bad-mediatype</a></div>
  </div>
</div>
"""

# Served as text/css at /win/styles.css (and /public mirror). Contains a
# CSS comment with a commented link (-> commented_link in Code Findings)
# plus one working and one broken live url() (-> Links tab, found_on_page
# is this file — live file URLs are never Code Findings).
WIN_CSS_TEXT = """/* CASE 16 stylesheet — served to test backslash <link href> resolution */
/* Legacy link: <a href="/old-win-banner">Deprecated Win Banner</a> */
body { background: #0f172a; }
.css-bg { background-image: url('/win/bg.png'); }
.css-broken { background-image: url('/win/missing-css-asset.png'); }
"""


# ---------------------------------------------------------------------------
# Fix-3 model: public homepage before login.
# Standalone minimal HTML (no shared navbar) so unauthenticated crawl counts
# stay deterministic: landing links to /features, /pricing, /login and one
# broken link /landing-broken (404, no route on purpose). The commented link
# proves unauthenticated Code Findings capture; the broken link proves
# unauthenticated Links capture. Served for / when NOT authed (authed /
# still serves the dashboard from ROUTES). Same on http and https.
# ---------------------------------------------------------------------------

LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Apex Enterprise Cloud — Welcome</title>
</head>
<body>
<!-- Old landing promo: <a href="/old-landing-promo">Landing Promo (removed)</a> -->
<h1>Apex Enterprise Cloud</h1>
<p>Public homepage. Sign in to reach the dashboard.</p>
<nav>
  <a href="/features">Features</a>
  <a href="/pricing">Pricing</a>
  <a href="/login">Sign in</a>
  <a href="/landing-broken">Broken landing link (404)</a>
</nav>
</body>
</html>"""

FEATURES_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Features — Apex Enterprise Cloud</title>
</head>
<body>
<h1>Features</h1>
<nav>
  <a href="/pricing">Pricing</a>
  <a href="/">Home</a>
</nav>
</body>
</html>"""

PRICING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pricing — Apex Enterprise Cloud</title>
</head>
<body>
<h1>Pricing</h1>
<nav>
  <a href="/features">Features</a>
  <a href="/">Home</a>
</nav>
</body>
</html>"""

# Public landing sub-pages (no login needed). Intentionally NOT in ROUTES
# (which is login-gated) and NOT in PUBLIC_ROUTES (which is the /public/
# static tree) — they are the pre-login surface at the site root.
PUBLIC_LANDING_ROUTES = {
    "/features": FEATURES_HTML,
    "/pricing": PRICING_HTML,
}


# ---------------------------------------------------------------------------
# CASE 18 — <base href> re-anchoring (mirrors the real .181 APEX case).
# Standalone minimal HTML (no shared navbar) so tool output is exactly
# predictable. The hub lives deep (/basehub/gallery) but re-anchors with
# <base href="/baseroot/">, so the bare-relative asset resolves to the
# working /baseroot/r/school/files/logo.png. An unfixed tool resolves it
# against the page dir instead (/basehub/r/... → 404 → false Broken).
# Also covered: href-less <base> ignored, second <base> ignored
# (first-wins), root-absolute control unaffected, ../ under base, and a
# commented link resolved under base. Shared by /basehub/gallery
# (login-gated) and /public/basehub (static, no login).
# ---------------------------------------------------------------------------

BASEHUB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Base Href Test Hub</title>
<base target="_blank">
<base href="/baseroot/">
<base href="https://example.com/wrong/">
</head>
<body>
<!-- Old base note: <a href="old/base-note">Base Note (removed)</a> -->
<h1>CASE 18 — base href</h1>
<nav>
  <a href="/about">About (root-absolute control)</a>
  <a href="../about">About via dotdot under base</a>
  <a href="r/school/files/logo.png">Logo file (bare relative)</a>
  <img src="r/school/files/logo.png" alt="Base Logo">
</nav>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CASE 19 — srcset candidates (Order 2: what the browser fetches beyond src).
# Standalone minimal HTML so tool output is exactly predictable. Shares the
# /baseroot/ base convention with CASE 18. Vectors: working pair, broken
# single (must flag Broken with the base-resolved URL), valid data URI
# (must stay silent — proves comma-splitting keeps data: URIs intact),
# and a picture/source pair. Served at /srcsethub/gallery (login-gated)
# and /public/srcsethub (static mirror).
# ---------------------------------------------------------------------------

SRCSET_HUB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Srcset Test Hub</title>
<base href="/baseroot/">
</head>
<body>
<!-- Old srcset note: <a href="old/srcset-note">Srcset Note (removed)</a> -->
<h1>CASE 19 — srcset candidates</h1>
<img src="r/school/files/logo.png" srcset="r/school/files/logo-big.png 2x" alt="Srcset Pair">
<img src="r/school/files/logo.png" srcset="r/school/files/missing-big.png 2x" alt="Srcset Broken">
<img src="r/school/files/logo.png" srcset="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg== 1x" alt="Srcset Data">
<picture>
  <source srcset="r/school/files/logo-big.png 480w, r/school/files/logo.png 800w">
  <img src="r/school/files/logo.png" alt="Picture Pair">
</picture>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CASE 20 — Resource URLs: status-checked but NEVER crawled as pages.
# ---------------------------------------------------------------------------
# Three onclick vectors trigger is_resource_url in _try_enqueue:
#   a) working font  (/public/assets/test.woff2)          — Links tab: working (no finding)
#   b) working JS    (/public/assets/app.js)              — Links tab: working (no finding)
#   c) missing font  (/public/assets/missing-font.woff2)  — Links tab: Broken
# None of a/b/c must appear in visited_pages — the enqueue gate and
# non-HTML skip both prevent it. CASE 7 control (/services) must still
# appear in visited_pages (extensionless route, not a resource).
#
# An internal <script> block contains fetch('/api/v1/data') — this URL
# surfaces as a Links finding (inline_js source) and is status-checked,
# but must NOT appear in visited_pages (it returns JSON, non-HTML, so
# the non-HTML skip in the static path blocks it).
# ---------------------------------------------------------------------------

RESOURCE_NAV_BODY = """
<div class="card">
  <h1 style="font-family:'Outfit',sans-serif;font-size:2rem;margin-bottom:12px">CASE 20 — Resource URL Navigation</h1>
  <p style="color:var(--muted);margin-bottom:20px">
    Buttons below use <code>onclick</code> to navigate to resource files (font, JS, missing font).
    Each must be <strong>status-checked</strong> (appears in Links tab) but
    <strong>never crawled as a page</strong> (must NOT appear in pages_crawled or visited_pages).
    CASE 7 control button still navigates to <code>/services</code> which <em>is</em> a page.
  </p>
  <div class="link-list">

    <!-- CASE 20a: onclick → working font file (woff2) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 20a — Font navigation (onclick → .woff2)</strong>
        <button class="btn btn-primary" onclick="window.location.href='/public/assets/test.woff2'">Load Font</button>
        <code style="margin-left:12px;color:var(--muted)">/public/assets/test.woff2</code>
      </div>
      <span class="tag t-ok">Resource — checked, not crawled</span>
    </div>

    <!-- CASE 20b: onclick → working JS file -->
    <div class="link-item">
      <div><strong style="display:block">CASE 20b — Script navigation (onclick → .js)</strong>
        <button class="btn" style="background:rgba(255,255,255,0.1);color:white" onclick="window.location.href='/public/assets/app.js'">Load Script</button>
        <code style="margin-left:12px;color:var(--muted)">/public/assets/app.js</code>
      </div>
      <span class="tag t-ok">Resource — checked, not crawled</span>
    </div>

    <!-- CASE 20c: onclick → missing font (404 Broken) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 20c — Missing font navigation (onclick → .woff2 404)</strong>
        <button class="btn" style="background:rgba(239,68,68,0.15);color:var(--red);border:1px solid rgba(239,68,68,.3)" onclick="window.location.href='/public/assets/missing-font.woff2'">Load Missing Font</button>
        <code style="margin-left:12px;color:var(--red)">/public/assets/missing-font.woff2 → 404</code>
      </div>
      <span class="tag t-broken">Broken — checked, not crawled</span>
    </div>

    <!-- CASE 7 control: onclick → /services (extensionless page — IS crawled) -->
    <div class="link-item">
      <div><strong style="display:block">CASE 7 control — JS nav to page (must still crawl)</strong>
        <button class="btn btn-primary" onclick="window.location.href='/services'">Go to Services</button>
        <code style="margin-left:12px;color:var(--muted)">/services (extensionless page)</code>
      </div>
      <span class="tag t-ok">Page — crawled normally</span>
    </div>

  </div>
</div>

<!-- CASE 20d: internal script with API route strings (non-HTML response) -->
<script>
  // API endpoints used by this page — JS scanner picks these up.
  // /api/v1/data returns JSON (non-HTML) — must NOT enter visited_pages.
  function loadData() { fetch('/api/v1/data'); }
  function postItem() { fetch('/api/v1/items', { method: 'POST' }); }
</script>
"""

# Minimal stub WOFF2 header bytes (real woff2 magic: 0x774F4632)
STUB_WOFF2 = bytes([
    0x77, 0x4F, 0x46, 0x32,  # signature 'wOF2'
    0x00, 0x01, 0x00, 0x00,  # sfVersion
    0x00, 0x00, 0x00, 0x30,  # length (48 bytes)
    0x00, 0x01,              # numTables
    0x00, 0x00,              # reserved
    0x00, 0x00, 0x00, 0x18,  # totalSfntSize
    0x00, 0x00, 0x00, 0x00,  # totalCompressedSize
    0x00, 0x00,              # majorVersion
    0x00, 0x00,              # minorVersion
    0x00, 0x00, 0x00, 0x00,  # metaOffset
    0x00, 0x00, 0x00, 0x00,  # metaLength
    0x00, 0x00, 0x00, 0x00,  # metaOrigLength
    0x00, 0x00, 0x00, 0x00,  # privOffset
    0x00, 0x00, 0x00, 0x00,  # privLength
])

# Minimal stub JS (valid JavaScript)
STUB_JS = b"/* stub */ console.log('test asset loaded');"

# Minimal stub JSON (API response, non-HTML — triggers non-HTML skip in crawler)
STUB_JSON_API = b'{"status":"ok","data":[]}'



# ---------------------------------------------------------------------------
# CASE 21 — Namespace boilerplate + router globs (Order 4).
# ---------------------------------------------------------------------------
# Vectors (all must produce ZERO findings):
#   - internal <script>: fetch("http://www.w3.org/2000/svg"),
#     location.href = "http://www.w3.org/1999/xhtml",
#     .open('GET', 'http://www.w3.org/1999/xlink'), app.get('/*', ...),
#     route('/v1/legacy/*')
#   - onclick="go('/*')" button
#   - <img src="http://www.w3.org/2000/svg"> (fixed-attr path)
#   - external bundle data.js: same shapes from file context
# Control (exactly ONE Internet finding):
#   - <a href="https://www.w3.org/TR/html52"> (real link, year-less path)
# Honest Broken (exactly ONE, found_on_page = data.js — file URLs are
# still status-checked, Order 3):
#   - fetch('/public/nshub/real-api') inside data.js (no route → 404)
# ---------------------------------------------------------------------------

NSHUB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Namespace / Glob Filter Hub</title>
<script src="/public/nshub/data.js"></script>
</head>
<body>
<h1>CASE 21 — Namespace / Glob Filtering</h1>
<nav>
  <a href="https://www.w3.org/TR/html52">W3C HTML spec (control — must flag Internet)</a>
  <a href="/about">About (page control)</a>
</nav>
<span onclick="window.location.href='/services'">Services (CASE 7 control)</span>
<button onclick="go('/*')">Glob button (must be silent)</button>
<img src="http://www.w3.org/2000/svg" alt="ns (must be silent)">
<script>
  fetch("http://www.w3.org/2000/svg");
  window.location.href = "http://www.w3.org/1999/xhtml";
  req.open('GET', 'http://www.w3.org/1999/xlink');
  app.get('/*', handleAll);
  route('/v1/legacy/*', handleLegacy);
</script>
</body>
</html>"""

# Served as application/javascript at /public/nshub/data.js — exercises the
# Order-4 file-URL path (comment_scanner live extraction).
NSHUB_JS = """/* CASE 21 external bundle */
var SVGNS = "http://www.w3.org/2000/svg";
fetch("http://www.w3.org/1999/xhtml");
app.get('/*', handleAll);
fetch('/public/nshub/real-api');
"""


# ---------------------------------------------------------------------------
# CASE 22 — Session-aware checks (Order 5).
# ---------------------------------------------------------------------------
# The hub page itself sets sess22=live via Set-Cookie (this mimics a server
# session jar the static crawl picks up through its own fetches):
#   a) /public/sessionhub/cookie-asset — 200 with the cookie, else 404
#   b) /public/sessionhub/hotlink-asset — 200 with any Referer, else 404
#   c) /public/sessionhub/flaky — 404 on the first hit ("expired checksum"),
#      200 after (the Order-5 one-recheck recovery)
#   d) /public/sessionhub/gone — permanent 404 control (stays Broken)
# Expected findings: exactly ONE Broken (d). a/b/c are clean.
# ---------------------------------------------------------------------------

SESSIONHUB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Session-Aware Checks Hub</title>
</head>
<body>
<h1>CASE 22 — Session-Aware Checks</h1>
<p>This page sets a session cookie on its own response. Assets below need
that cookie (a), a Referer (b), or one recheck after an expired checksum
(c). All must be clean; only the permanent 404 (d) flags Broken.</p>
<nav>
  <a href="/public/sessionhub/cookie-asset">Session cookie asset (must be clean)</a>
  <a href="/public/sessionhub/hotlink-asset">Hotlink asset (must be clean)</a>
  <a href="/public/sessionhub/flaky">Flaky checksum (must recover, clean)</a>
  <a href="/public/sessionhub/gone">Gone control (must flag Broken)</a>
</nav>
</body>
</html>"""

# First-hit flip for (c) above. Guarded: the server is threaded.
_SESSIONHUB_HITS = {}
_SESSIONHUB_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# CASE 25 — MGS-like APEX simulation (session-gated + expiring checksums +
# runtime-only links). Mimics the real 10.0.0.181 MGS target in minutes:
#   - session cookie is set via JS (document.cookie), never via Set-Cookie,
#     so static requests never carry it; dynamic browsers do after render.
#   - every nav link carries ?clear=5&cs=<token>, valid ~90s; expired/invalid
#     tokens get the MGS-style custom 404 (status 404, "Page Not Found | MGS").
#   - /public/mgshub/runtime fetches JSON and injects links + fires off-host
#     fetches at runtime — invisible to static extraction, visible to the
#     browser request tap (ZAP-like).
#   - sessions expire after ~180s (hour-test in minutes); reloading the hub
#     re-issues both session and checksums.
# Expected: static scan of /public/mgshub flags the gated links Broken
# (no JS session — documented limitation); dynamic scan with per-page sync +
# browser verdict leaves them clean and files runtime off-host Internet rows.
# ---------------------------------------------------------------------------
MGS25_COOKIE = "mgs25"
MGS25_SESSION_TTL = 180
MGS25_CS_TTL = 90
_MGS25_SESSIONS: dict = {}
_MGS25_CS: dict = {}
_MGS25_LOCK = threading.Lock()


def _mgs25_now() -> float:
    import time as _t
    return _t.time()


def _mgs25_issue_session() -> str:
    token = secrets.token_hex(8)
    with _MGS25_LOCK:
        _MGS25_SESSIONS[token] = _mgs25_now() + MGS25_SESSION_TTL
    return token


def _mgs25_valid_session(cookie_header: str) -> bool:
    try:
        sess = ""
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == MGS25_COOKIE and value:
                sess = value
                break
        if not sess:
            return False
        with _MGS25_LOCK:
            exp = _MGS25_SESSIONS.get(sess, 0)
            if exp and exp > _mgs25_now():
                return True
            _MGS25_SESSIONS.pop(sess, None)
        return False
    except Exception:
        return False


def _mgs25_issue_cs() -> str:
    token = "cs" + secrets.token_hex(6)
    with _MGS25_LOCK:
        _MGS25_CS[token] = _mgs25_now() + MGS25_CS_TTL
    return token


def _mgs25_valid_cs(cs: str) -> bool:
    try:
        if not cs:
            return False
        with _MGS25_LOCK:
            exp = _MGS25_CS.get(cs, 0)
            if exp and exp > _mgs25_now():
                return True
            _MGS25_CS.pop(cs, None)
        return False
    except Exception:
        return False


def _mgs25_404() -> bytes:
    return (b"<!DOCTYPE html><html><head><title>Page Not Found | MGS</title></head>"
            b"<body><h1>404 - Page Not Found | MGS</h1>"
            b"<p>HTTP 404 -- Page Not Found | MGS</p></body></html>")


def _mgs25_hub_html() -> bytes:
    sess = _mgs25_issue_session()
    cs1, cs2 = _mgs25_issue_cs(), _mgs25_issue_cs()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MGS-like Hub (CASE 25)</title>
<script>
// Session is JS-set only: static requests never carry it.
document.cookie = "{MGS25_COOKIE}={sess}; Path=/";
</script>
<script>
// Framework vectors (must stay out of Links): a dynamic-action session
// endpoint string (dropped like namespace boilerplate) and a bare license
// URL in a comment (surfaces as commented_link, never a Link).
apexFake = {{}};
apexFake.fetch('/public/mgshub/2?session=999');
/* license: http://example.com/mgs-license */
</script>
</head>
<body>
<h1>CASE 25 — MGS-like Session Hub</h1>
<p>Links carry expiring checksums (?clear=5&amp;cs=...). Reloading this hub
re-issues session (~180s) and checksums (~90s) — the hour-test in minutes.</p>
<nav>
  <a href="/public/mgshub/news?clear=5&amp;cs={cs1}">NEWS link (must be clean in dynamic)</a>
  <a href="/public/mgshub/events?clear=5&amp;cs={cs2}">Events link (must be clean in dynamic)</a>
  <a href="/public/mgshub/gone?clear=5&amp;cs=dead">Gone control (must flag Broken)</a>
  <a href="/public/mgshub/runtime">Runtime-only links page</a>
</nav>
</body>
</html>""".encode("utf-8")


MGS25_RUNTIME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MGS Runtime Page</title>
</head>
<body>
<h1>MGS Runtime Links</h1>
<p>Links below are injected at runtime from JSON — absent from view-source.</p>
<div id="links"></div>
<script>
fetch('/public/mgshub/api/links').then(function(r){ return r.json(); }).then(function(data){
  var box = document.getElementById('links');
  (data.same || []).forEach(function(u){
    var a = document.createElement('a'); a.href = u; a.textContent = u;
    box.appendChild(a);
  });
  (data.offhost || []).forEach(function(u){ fetch(u).catch(function(){}); });
}).catch(function(){});
</script>
</body>
</html>"""
# ---------------------------------------------------------------------------
# CASE 26 — Auth hub mirroring the real replay-failure target: a post-load
# auth-key bounce (landing relocates to /auth-key and 302s straight back),
# a readonly anti-autofill username input (cleared by the site's own JS on
# focus — Playwright's fill checks editability BEFORE its own focus, so
# without the replay fix it dies on "element is not editable"), and a
# CSS-hover-only user menu whose Logout button does not exist visibly
# until the pointer dwells on the avatar.
#
# Expected replay behavior after the fix:
#   - goto(landing) → bounce fires on load → settle (networkidle) → form.
#   - fill #username: replay clears readonly itself and succeeds.
#   - Logout replay: recorded hover step re-opens the .ah-menu, then the
#     .btn.btn-danger click lands.
# Credentials: username "ahuser", password "ahpass".
# ---------------------------------------------------------------------------
AH26_KEY_COOKIE = "ah26_key"
AH26_SESS_COOKIE = "ah26_sess"
AH26_USERNAME = "ahuser"
AH26_PASSWORD = "ahpass"
_AH26_KEYS: set = set()
_AH26_SESSIONS: set = set()
_AH26_LOCK = threading.Lock()


def _ah26_cookie_value(cookie_header: str, name: str) -> str:
    for part in (cookie_header or "").split(";"):
        n, _, v = part.strip().partition("=")
        if n == name:
            return v
    return ""


def _ah26_bounce_page() -> bytes:
    """The landing served BEFORE the auth-key dance: invisible to the user
    (relocates itself right after `load` via location.replace)."""
    return (b"<!DOCTYPE html><html><head><title>Auth Hub</title></head><body>"
            b"<p>Verifying session key...</p>"
            b"<script>window.addEventListener('load', function(){"
            b"location.replace('/public/authhub/auth-key');});</script>"
            b"</body></html>")


def _ah26_login_page() -> bytes:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Auth Hub — Sign in (CASE 26)</title>
<style>
  body{font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 16px}
  label{display:block;margin:12px 0 4px}
  input{width:100%;padding:8px;box-sizing:border-box}
  button{margin-top:16px;padding:8px 20px}
</style>
</head>
<body>
<h1>CASE 26 — Auth Hub</h1>
<form id="ah-form">
  <label for="username">Username</label>
  <!-- Anti-autofill: readonly until a REAL user focuses the field. -->
  <input readonly type="text" id="username" name="username" autocomplete="off" required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required>
  <button type="submit" id="ah-submit">Sign in</button>
</form>
<script>
var u = document.getElementById('username');
u.addEventListener('focus', function(){ u.removeAttribute('readonly'); });
// NOTE: route strings are composed at runtime (not kept as literals) — the
// extractor flags literal inline-script URL routes for GET review, and these
// two endpoints are POST-only (a GET answers 404 by design). CASE 26 tests
// replay robustness, not link discovery — CASE 20 already covers the
// inline-route-string vector.
document.getElementById('ah-form').addEventListener('submit', function(ev){
  ev.preventDefault();
  fetch(['/public','/authhub','/login'].join(''), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin',
    body: JSON.stringify({
      username: u.value,
      password: document.getElementById('password').value
    })
  }).then(function(r){ return r.json(); }).then(function(d){
    if (d && d.ok) { location.href = ['/public/authhub','/home'].join(''); }
  });
});
</script>
</body>
</html>""".encode("utf-8")


def _ah26_home_page() -> bytes:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Auth Hub — Home (CASE 26)</title>
<style>
  body{font-family:sans-serif;max-width:720px;margin:60px auto;padding:0 16px}
  .ah-user{display:inline-block;cursor:pointer;padding:6px 12px;border:1px solid #cbd5e1;border-radius:6px;position:relative}
  .ah-menu{display:none;list-style:none;margin:0;padding:4px 0;position:absolute;background:#fff;
           border:1px solid #cbd5e1;border-radius:6px;top:100%;left:0;min-width:120px}
  /* Logout button exists in the DOM but is only VISIBLE while hovering the avatar */
  .ah-user:hover .ah-menu{display:block}
</style>
</head>
<body>
<h1>Auth Hub — Home</h1>
<p>Signed in. The user menu opens only on hover.</p>
<ul style="list-style:none;padding:0;display:inline-block">
  <li class="ah-user" id="ah-avatar" aria-haspopup="true">👤 ahuser &#9662;
    <ul class="ah-menu">
      <li><button class="btn btn-danger" id="logout-btn" type="button">Logout</button></li>
    </ul>
  </li>
</ul>
<script>
// Same literal-URL caution as the login page: the fetch target is POST-only,
// and its GET is a 404 by design — do not surface it as a reviewable link.
document.getElementById('logout-btn').addEventListener('click', function(){
  fetch(['/public','/authhub','/logout'].join(''), {method:'POST', credentials:'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(d){ if (d && d.ok) { location.href = '/public/authhub'; } });
});
</script>
</body>
</html>""".encode("utf-8")


# ---------------------------------------------------------------------------
# CASE 23 — Rate limiting (Order 6).
# ---------------------------------------------------------------------------
#   a) /public/ratelimit/flaky429 — 429 with Retry-After: 1 on the first
#      hit, bare 429 on the second, 200 after (retry recovery — clean).
#      Exercises both the Retry-After-honoring and default-wait branches.
#   b) /public/ratelimit/always429 — permanent 429 (stays Broken with the
#      exact evidence "HTTP 429 — Rate limit exceeded (retried)").
# Expected findings: exactly ONE Broken (b). (a) is clean.
# ---------------------------------------------------------------------------

RATELIMIT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rate Limiting Hub</title>
</head>
<body>
<h1>CASE 23 — Rate Limiting</h1>
<p>The flaky endpoint limits twice before recovering — the tool's 429
retries must absorb it (clean). The permanent limiter must still file
Broken with the retried evidence.</p>
<nav>
  <a href="/public/ratelimit/flaky429">Flaky limiter (must recover, clean)</a>
  <a href="/public/ratelimit/always429">Permanent limiter (must flag Broken)</a>
</nav>
</body>
</html>"""

# Hit counts for (a)/(b) above. Guarded: the server is threaded.
_RATELIMIT_HITS = {}
_RATELIMIT_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# CASE 24 — Re-render simulator (Order 7).
# ---------------------------------------------------------------------------
# Every load wraps the target button in 0–4 random divs (random classes)
# and adds 0–3 decoy buttons. The button itself is constant: no id,
# data-testid="shuffle-btn", aria-label="Shuffle out". Any positional
# selector recorded on one load is stale on the next; the recorded stable
# form + fingerprint verify on every load. Refresh repeatedly and
# view-source to watch the nesting change.
# ---------------------------------------------------------------------------

def render_rerender_hub() -> bytes:
    target = (
        "<button type=\"button\" data-testid=\"shuffle-btn\" "
        "aria-label=\"Shuffle out\" "
        "onclick=\"document.title='clicked'\">Shuffle out</button>"
    )
    inner = target
    for _ in range(random.randint(0, 4)):
        inner = (
            f"<div class=\"wrap-{random.randint(0, 9999)}\" "
            f"data-r=\"{random.randint(0, 9999)}\">{inner}</div>"
        )
    decoys = "".join(
        f"<button type=\"button\" class=\"decoy-{random.randint(0, 9999)}\">Decoy</button>"
        for _ in range(random.randint(0, 3))
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Re-render Simulator Hub</title>
</head>
<body>
<h1>CASE 24 — Re-render Simulator</h1>
<p>Refresh: the button below keeps its attributes but its wrapper nesting
and siblings change every load — like a React re-render.</p>
<div id="stage">{decoys}{inner}</div>
</body>
</html>""".encode("utf-8")



LOGIN_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign In — Apex Cloud</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: #0f172a; color: #f8fafc;
         height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: rgba(30,41,59,0.7); border: 1px solid rgba(255,255,255,0.1);
          border-radius: 20px; padding: 40px; width: 100%; max-width: 400px; }
  h1 { font-size: 1.5rem; margin-bottom: 24px; text-align: center; }
  .field { margin-bottom: 18px; }
  label { display: block; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 6px; }
  input { width: 100%; padding: 12px; background: rgba(15,23,42,.8);
          border: 1px solid rgba(255,255,255,.15); border-radius: 8px; color: white; font-size: 0.95rem; }
  button { width: 100%; padding: 13px; margin-top: 8px;
           background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white;
           border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
  .hint { margin-top: 20px; padding: 12px; border-radius: 8px; background: rgba(99,102,241,.1);
          border: 1px solid rgba(99,102,241,.2); font-size: 0.8rem; color: #a5b4fc; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>Apex Cloud Portal</h1>
  {message}
  <form method="POST" action="/login">
    <div class="field">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="tester" required>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="••••••••" required>
    </div>
    <!-- Fixed captcha (extra text field): always X7K9. Fill it AFTER the
         password during recording so it classifies as an extra field whose
         recorded value replays verbatim (or via the scan-time extra input). -->
    <div class="field">
      <label for="captcha">Captcha — type the code shown: <code>X7K9</code></label>
      <input type="text" id="captcha" name="captcha" placeholder="Enter captcha code" required autocomplete="off">
    </div>
    <!-- Remember-me (other field): checked state is recorded and replayed. -->
    <div class="field">
      <label><input type="checkbox" id="remember" name="remember" checked style="width:auto"> Remember me</label>
    </div>
    <button type="submit">Sign In</button>
  </form>
  <div class="hint"><strong>Demo Credentials:</strong><br>Username: <code>tester</code> | Password: <code>testpass123</code> | Captcha: <code>X7K9</code></div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Minimal stub PDF (valid PDF bytes so Content-Type works correctly)
# ---------------------------------------------------------------------------

STUB_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f\n"
    b"0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
)

# Minimal 1×1 white PNG
STUB_PNG = bytes([
    0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,
    0xDE,0x00,0x00,0x00,0x0C,0x49,0x44,0x41,0x54,0x08,0xD7,0x63,0xF8,0xFF,0xFF,0x3F,
    0x00,0x05,0xFE,0x02,0xFE,0xDC,0xCC,0x59,0xE7,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,
    0x44,0xAE,0x42,0x60,0x82,
])


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

def render(title: str, body: str, active_tab: str = "home", proto: str = "http", authed: bool = False) -> bytes:
    return page_shell(title, body, active_tab, proto, authed).encode("utf-8")


ROUTES = {
    "/":                   ("Dashboard",          HOME_BODY,                "home"),
    "/index.html":         ("Dashboard",          HOME_BODY,                "home"),
    "/about":              ("About Us",           ABOUT_BODY,               "about"),
    "/contact":            ("Contact Desk",       CONTACT_BODY,             "contact"),
    "/services":           ("Services",           SERVICES_BODY,            "services"),
    "/reports":            ("Reports",            REPORTS_BODY,             "reports"),
    "/products/cloud":     ("Cloud Platform",     PRODUCTS_CLOUD_BODY,      ""),
    "/products/security":  ("Security Suite",     PRODUCTS_SECURITY_BODY,   ""),
    "/docs/api":           ("API Documentation",  DOCS_API_BODY,            ""),
    "/docs/api/spec":      ("API Spec",           "<div class='card'><h1>API Spec</h1></div>", ""),
    "/view/detail":        ("Detail View",        VIEW_DETAIL_BODY,         ""),
    "/services/consulting":("Consulting",         CONSULTING_BODY,          ""),
    "/services/support":   ("Support",            SUPPORT_BODY,             ""),
    "/reports/annual":     ("Annual Report",      REPORTS_ANNUAL_BODY,      ""),
    "/reports/quarterly":  ("Quarterly Report",   REPORTS_QUARTERLY_BODY,   ""),
    # CASE 16 — backslash targets (canonical forward-slash URLs; linked via backslashes)
    "/win/nested/page":              ("Backslash Hub",  WIN_NESTED_BODY,  ""),
    "/win/win-target":               ("Win Target",     WIN_TARGET_BODY,  ""),
    "/win/nested/sub/deep-target":   ("Deep Target",    DEEP_TARGET_BODY, ""),
    "/campus/About School/page":     ("About School",   CAMPUS_ABOUT_BODY, ""),
    "/campus/School HQ/Comdt.html":  ("Comdt",          COMDT_BODY,        ""),
    # CASE 17 — blob/data page (all vectors inline; no separate targets needed)
    "/media/page":                   ("Blob/Data",      MEDIA_BODY,        ""),
}

# ---------------------------------------------------------------------------
# Frames + Shadow DOM fixtures (frames/shadow audit support)
# ---------------------------------------------------------------------------
# Frames: intranet apps that live INSIDE <frameset>/<iframe> documents. Their
# srcs are link-checked AND followed into, so each frame document below is
# audited as its own page with findings attributed to its true source page.
# Served RAW (not through the chrome renderer): a <frameset> document has no
# <body>, and wrapping would mix chrome links into every frame's findings.
#   /public/frameset-app              classic <frameset> app (menu + content)
#   /public/frame-menu                broken anchor + "#" inactive + internet
#   /public/frame-content             broken PDF + display:none broken PDF +
#                                     commented-out link + nested iframe
#   /public/frame-inner               nested frame doc with its own broken link
#   /public/iframe-app                normal page whose iframe src 404s (the
#                                     panel is a real, visible hole)
# Shadow DOM: shadow-root content never appears in page.content(), so Tier-1
# extraction can only see what the page keeps in light-DOM markup — the OPEN
# root's content starts as a <template> (same truth, rendered later), while
# the visible-set probe (renderer) pierces the attached roots to decide what
# the UI actually shows under "Only on UI".
#   /public/shadow-app                open root (visible + display:none anchors)
#                                     + closed root (BY DESIGN never a finding)
#   /public/iframe-login[/panel/home] login form inside a frame — reuses the
#                                     CASE 26 authhub POST endpoint + creds
#   /public/shadow-login[/home]       login form inside an open shadow root
FRAMESET_APP_HTML = """<!DOCTYPE html>
<html>
<head><title>Frameset App</title></head>
<frameset cols="30%,70%">
  <frame src="/public/frame-menu" name="menu">
  <frame src="/public/frame-content" name="content">
</frameset>
<noframes><body>Your browser does not support frames.</body></noframes>
</html>"""

FRAME_MENU_HTML = """<!DOCTYPE html>
<html>
<head><title>Frame Menu</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px;background:#f8fafc">
  <h2 style="margin:4px 0">Menu</h2>
  <p><a href="/public/frame-content">Content panel</a></p>
  <p><a href="/public/frame-menu-broken">Quarterly filing</a></p>
  <p><a href="#">Section placeholder</a></p>
  <p><a href="https://example.com/frame-external">Corporate portal</a></p>
</body>
</html>"""

FRAME_CONTENT_HTML = """<!DOCTYPE html>
<html>
<head><title>Frame Content</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px;background:#ffffff">
  <h2 style="margin:4px 0">Payments</h2>
  <p><a href="/downloads/missing-frame.pdf">Payments register (PDF)</a></p>
  <p><a href="/static/missing-frame-hidden.pdf" style="display:none">Hidden archive (PDF)</a></p>
  <p><a href="/public/iframe-app">Reports console</a></p>
  <!-- Retired drafts section kept for reference: <a href="/public/frame-commented-broken">Old drafts list</a> -->
  <iframe src="/public/frame-inner" width="320" height="140" style="border:1px solid #cbd5e1"></iframe>
</body>
</html>"""

FRAME_INNER_HTML = """<!DOCTYPE html>
<html>
<head><title>Frame Inner</title></head>
<body style="font-family:sans-serif;margin:0;padding:10px">
  <h3 style="margin:0 0 8px">Inner document</h3>
  <p><a href="/public/frame-inner-broken">Legacy detail page</a></p>
  <p><a href="/public/about">About the company</a></p>
</body>
</html>"""

IFRAME_APP_HTML = """<!DOCTYPE html>
<html>
<head><title>Iframe App</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px">
  <h2 style="margin:4px 0">Reports console</h2>
  <iframe src="/public/iframe-src-missing" width="420" height="180"
          style="border:1px solid #cbd5e1"></iframe>
  <p><a href="/public/frame-inner">Archived inner document</a></p>
</body>
</html>"""

SHADOW_APP_HTML = """<!DOCTYPE html>
<html>
<head><title>Shadow UI</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px">
  <h2 style="margin:4px 0">Shadow widget</h2>
  <div id="host-open"></div>
  <div id="host-closed"></div>
  <p><a href="/public/frame-inner">Plain docs link</a></p>
  <template id="tpl-open">
    <a href="/public/shadow-open-broken">Live status dashboard</a>
    <a href="/public/shadow-open-hidden" style="display:none">Archived status dashboard</a>
  </template>
  <script>
  (function () {
    var tpl = document.getElementById('tpl-open');
    var host = document.getElementById('host-open');
    var open = host.attachShadow({ mode: 'open' });
    open.appendChild(tpl.content.cloneNode(true));
    // CLOSED root: browsers keep it opaque to extension code and DevTools
    // too, so this link must surface nowhere (no finding, no shot). Its URL
    // is assembled at runtime so route-string scanners stay silent.
    var closed = document.getElementById('host-closed').attachShadow({ mode: 'closed' });
    closed.innerHTML = '<a href="/pu' + 'blic/shadow-closed-broken">Closed status dashboard</a>';
  })();
  </script>
</body>
</html>"""

IFRAME_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Frame Login</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px">
  <h1 style="margin:6px 0">Panel sign-in</h1>
  <iframe src="/public/iframe-login/panel" width="440" height="330"
          style="border:1px solid #cbd5e1"></iframe>
</body>
</html>"""

IFRAME_LOGIN_PANEL_HTML = """<!DOCTYPE html>
<html>
<head><title>Panel Sign-in</title></head>
<body style="font-family:sans-serif;margin:0;padding:12px">
  <form id="panel-form">
    <label for="panel-user">Username</label>
    <input type="text" id="panel-user" name="username" autocomplete="off" required>
    <label for="panel-pass">Password</label>
    <input type="password" id="panel-pass" name="password" autocomplete="off" required>
    <button type="submit" id="panel-submit">Sign in</button>
  </form>
  <script>
  document.getElementById('panel-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    fetch(['/public', '/authhub', '/login'].join(''), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        username: document.getElementById('panel-user').value,
        password: document.getElementById('panel-pass').value
      })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d && d.ok) { top.location.href = ['/public', '/iframe-login', '/home'].join(''); }
    });
  });
  </script>
</body>
</html>"""

IFRAME_LOGIN_HOME_HTML = """<!DOCTYPE html>
<html>
<head><title>Frame Home</title></head>
<body style="font-family:sans-serif;padding:16px">
  <h1 style="margin:6px 0">Frame home — signed in</h1>
  <p>Welcome back, ahuser. The session cookie carried across frames.</p>
</body>
</html>"""

SHADOW_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Widget Sign-in</title></head>
<body style="font-family:sans-serif;margin:40px 0;padding:0 16px">
  <div id="sl-host"></div>
  <script>
  (function () {
    var host = document.getElementById('sl-host');
    var sr = host.attachShadow({ mode: 'open' });
    sr.innerHTML = '<form id="sl-form">'
      + '<label for="sl-user">Username</label>'
      + '<input type="text" id="sl-user" name="username" autocomplete="off" required>'
      + '<label for="sl-pass">Password</label>'
      + '<input type="password" id="sl-pass" name="password" autocomplete="off" required>'
      + '<button type="submit" id="sl-submit">Sign in</button>'
      + '</form>';
    var user = sr.getElementById('sl-user');
    var pass = sr.getElementById('sl-pass');
    sr.getElementById('sl-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      fetch(['/public', '/authhub', '/login'].join(''), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username: user.value, password: pass.value })
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d && d.ok) { location.href = ['/public', '/shadow-login', '/home'].join(''); }
      });
    });
  })();
  </script>
</body>
</html>"""

SHADOW_LOGIN_HOME_HTML = """<!DOCTYPE html>
<html>
<head><title>Widget Home</title></head>
<body style="font-family:sans-serif;padding:16px">
  <h1 style="margin:6px 0">Widget home — signed in</h1>
  <p>Welcome back, ahuser. The submit button inside the shadow root worked.</p>
</body>
</html>"""

# Same pages served under /public/ WITHOUT login — use for static mode scans.
# HTTP:  http://127.0.0.1:5050/public/
# HTTPS: https://127.0.0.1:5051/public/  (tests CASE 15 SSL fix)
PUBLIC_ROUTES = {
    "/public/":                    ("Dashboard",         HOME_BODY,              "home"),
    "/public/about":               ("About Us",          ABOUT_BODY,             "about"),
    "/public/contact":             ("Contact Desk",      CONTACT_BODY,           "contact"),
    "/public/services":            ("Services",          SERVICES_BODY,          "services"),
    "/public/reports":             ("Reports",           REPORTS_BODY,           "reports"),
    "/public/products/cloud":      ("Cloud Platform",    PRODUCTS_CLOUD_BODY,    ""),
    "/public/products/security":   ("Security Suite",    PRODUCTS_SECURITY_BODY, ""),
    "/public/docs/api":            ("API Documentation", DOCS_API_BODY,          ""),
    "/public/docs/api/spec":       ("API Spec",          "<div class='card'><h1>API Spec</h1></div>", ""),
    "/public/view/detail":         ("Detail View",       VIEW_DETAIL_BODY,       ""),
    "/public/services/consulting": ("Consulting",        CONSULTING_BODY,        ""),
    "/public/services/support":    ("Support",           SUPPORT_BODY,           ""),
    "/public/reports/annual":      ("Annual Report",     REPORTS_ANNUAL_BODY,    ""),
    "/public/reports/quarterly":   ("Quarterly Report",  REPORTS_QUARTERLY_BODY, ""),
    # CASE 16 mirrors — same relative backslash links resolve under /public/ too
    "/public/win/nested/page":              ("Backslash Hub",  WIN_NESTED_BODY,  ""),
    "/public/win/win-target":               ("Win Target",     WIN_TARGET_BODY,  ""),
    "/public/win/nested/sub/deep-target":   ("Deep Target",    DEEP_TARGET_BODY, ""),
    "/public/campus/About School/page":     ("About School",   CAMPUS_ABOUT_BODY, ""),
    "/public/campus/School HQ/Comdt.html":  ("Comdt",          COMDT_BODY,        ""),
    # CASE 17 mirror
    "/public/media/page":                   ("Blob/Data",      MEDIA_BODY,        ""),
    # CASE 20 resource nav page
    "/public/resource-nav":                 ("Resource Nav",   RESOURCE_NAV_BODY, ""),
    # CASE 21 namespace/glob hub (assets served from do_GET, below)
    "/public/nshub":                        ("NS Hub",         NSHUB_HTML,         ""),
    # CASE 23 rate-limit hub
    "/public/ratelimit":                    ("Rate Limit",     RATELIMIT_HTML,     ""),
}


class Handler(http.server.BaseHTTPRequestHandler):

    def _proto(self) -> str:
        return "https" if getattr(self.server, "_is_https", False) else "http"

    def _session_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE_NAME and value:
                return value
        return None

    def _is_authed(self) -> bool:
        token = self._session_token()
        if not token:
            return False
        with _SESSIONS_LOCK:
            return token in _SESSIONS

    def _send_html(self, body: bytes, status: int = 200, extra_headers: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, set_cookie: str = None):
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _send_bytes(self, data: bytes, mime: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json26(self, ok: bool, sess_cookie: str = None, clear_sess: bool = False):
        """CASE 26 JSON reply (fetch-based login/logout). Invalid credentials
        still answer 200 + ok:false so the form's tiny JS has one shape."""
        body = b'{"ok": true}' if ok else b'{"ok": false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if sess_cookie:
            self.send_header("Set-Cookie", f"{AH26_SESS_COOKIE}={sess_cookie}; Path=/")
        if clear_sess:
            self.send_header("Set-Cookie", f"{AH26_SESS_COOKIE}=; Path=/; Max-Age=0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_429(self, body: bytes, retry_after: str = None):
        self.send_response(429)
        self.send_header("Content-Type", "text/html")
        if retry_after is not None:
            self.send_header("Retry-After", retry_after)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path: str):
        safe = rel_path.lstrip("/")
        fp = (STATIC_DIR / safe).resolve()
        if not str(fp).startswith(str(STATIC_DIR.resolve())):
            return self._send_html(b"<h1>403</h1>", 403)
        if fp.is_dir():
            fp = fp / "index.html"
        if not fp.exists():
            return self._send_html(
                b"<!DOCTYPE html><html><body style='background:#0f172a;color:#ef4444;padding:40px'>"
                b"<h1>404 Not Found</h1><p>Static file not found.</p></body></html>", 404)
        mime, _ = mimetypes.guess_type(str(fp))
        self._send_bytes(fp.read_bytes(), mime or "application/octet-stream")

    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        proto = self._proto()

        # /public/* — all test cases, NO login required.
        # Use these target URLs for static mode scans:
        #   http://127.0.0.1:5050/public/   (tests CASES 1-13)
        #   https://127.0.0.1:5051/public/  (tests CASE 15 SSL fix + all others)
        # Like real servers (Apache/Nginx), /public without trailing slash
        # 301-redirects to /public/ so relative links resolve identically
        # whichever form the user enters as target.
        if path == "/public":
            return self._redirect("/public/")
        if path.startswith("/public/"):
            norm = path
            if norm in PUBLIC_ROUTES:
                title, body, tab = PUBLIC_ROUTES[norm]
                return self._send_html(render(title, body, tab, proto))
            if path == "/public/downloads/report.pdf":
                return self._send_bytes(STUB_PDF, "application/pdf")
            if path == "/public/downloads/missing.pdf":
                return self._send_html(b"<h1>404</h1>", 404)
            # CASE 16 public assets (backslash targets under /public/win/)
            if path in ("/public/win/logo.png", "/public/win/bg.png"):
                return self._send_bytes(STUB_PNG, "image/png")
            if path == "/public/win/report.pdf":
                return self._send_bytes(STUB_PDF, "application/pdf")
            if path == "/public/win/styles.css":
                return self._send_bytes(WIN_CSS_TEXT.encode("utf-8"), "text/css")
            # CASE 18 hub (static mirror, served directly like the login-gated one)
            if path == "/public/basehub":
                return self._send_html(BASEHUB_HTML.encode("utf-8"))
            # CASE 19 hub (srcset mirror)
            if path == "/public/srcsethub":
                return self._send_html(SRCSET_HUB_HTML.encode("utf-8"))
            # CASE 20 resource stubs (always 200, served at /public/assets/)
            if path == "/public/assets/test.woff2":
                return self._send_bytes(STUB_WOFF2, "font/woff2")
            if path == "/public/assets/app.js":
                return self._send_bytes(STUB_JS, "application/javascript")
            # /public/assets/missing-font.woff2 → falls through to 404 below
            # CASE 20d: API endpoint (returns JSON, not HTML)
            if path == "/api/v1/data" or path == "/api/v1/items":
                return self._send_bytes(STUB_JSON_API, "application/json")
            # CASE 21 bundle (Order-4 file-URL path)
            if path == "/public/nshub/data.js":
                return self._send_bytes(NSHUB_JS.encode("utf-8"), "application/javascript")
            # /public/nshub/real-api → falls through to 404 (honest Broken)
            # CASE 22 hub: sets its own session cookie (Order-5 jar test)
            if path == "/public/sessionhub":
                return self._send_html(
                    SESSIONHUB_HTML.encode("utf-8"),
                    extra_headers={"Set-Cookie": "sess22=live; Path=/"},
                )
            # CASE 22a: 200 with the session cookie, else 404
            if path == "/public/sessionhub/cookie-asset":
                if "sess22=live" in self.headers.get("Cookie", ""):
                    return self._send_html(b"<h1>Session asset OK</h1>")
                return self._send_html(b"<h1>404</h1><p>No session cookie.</p>", 404)
            # CASE 22b: 200 with any Referer, else 404
            if path == "/public/sessionhub/hotlink-asset":
                if self.headers.get("Referer", ""):
                    return self._send_html(b"<h1>Hotlink asset OK</h1>")
                return self._send_html(b"<h1>404</h1><p>No referer.</p>", 404)
            # CASE 22c: 404 on the first hit (expired checksum), 200 after
            if path == "/public/sessionhub/flaky":
                with _SESSIONHUB_LOCK:
                    n = _SESSIONHUB_HITS.get("flaky", 0) + 1
                    _SESSIONHUB_HITS["flaky"] = n
                if n == 1:
                    return self._send_html(b"<h1>404</h1><p>Checksum expired.</p>", 404)
                return self._send_html(b"<h1>Checksum recovered</h1>")
            # CASE 22d: permanent 404 control (stays Broken)
            if path == "/public/sessionhub/gone":
                return self._send_html(b"<h1>404</h1><p>Gone.</p>", 404)
            # CASE 23a: 429 (with Retry-After) then 429 (without) then 200
            if path == "/public/ratelimit/flaky429":
                with _RATELIMIT_LOCK:
                    n = _RATELIMIT_HITS.get("flaky429", 0) + 1
                    _RATELIMIT_HITS["flaky429"] = n
                if n == 1:
                    return self._send_429(b"<h1>429</h1><p>Slow down.</p>", retry_after="1")
                if n == 2:
                    return self._send_429(b"<h1>429</h1><p>Still limited.</p>")
                return self._send_html(b"<h1>Rate limit recovered</h1>")
            # CASE 23b: permanent 429 control (stays Broken, retried evidence)
            if path == "/public/ratelimit/always429":
                return self._send_429(b"<h1>429</h1><p>Limited.</p>", retry_after="1")
            # CASE 24: re-render simulator (fresh random nesting per load)
            if path == "/public/rerender":
                return self._send_html(render_rerender_hub())
            # CASE 25: MGS-like hub (JS session + expiring checksums)
            if path == "/public/mgshub":
                return self._send_html(_mgs25_hub_html())
            if path == "/public/mgshub/runtime":
                return self._send_html(MGS25_RUNTIME_HTML.encode("utf-8"))
            if path == "/public/mgshub/api/links":
                import json as _json
                art_cs = _mgs25_issue_cs()
                payload = _json.dumps({
                    "same": [f"/public/mgshub/runtime-article?clear=5&cs={art_cs}"],
                    "offhost": ["https://example.com/mgs-lib.js", "https://cdn.example.net/mgs.css"],
                }).encode("utf-8")
                return self._send_bytes(payload, "application/json")
            if path in ("/public/mgshub/news", "/public/mgshub/events",
                        "/public/mgshub/gone", "/public/mgshub/runtime-article"):
                qs = parse_qs((self.path.split("?", 1)[1] if "?" in self.path else ""))
                cs = (qs.get("cs") or [""])[0]
                if path == "/public/mgshub/gone":
                    return self._send_html(_mgs25_404(), 404)
                if not _mgs25_valid_session(self.headers.get("Cookie", "")):
                    return self._send_html(_mgs25_404(), 404)
                if not _mgs25_valid_cs(cs):
                    return self._send_html(_mgs25_404(), 404)
                title = path.rsplit("/", 1)[-1].upper()
                return self._send_html(
                    f"<!DOCTYPE html><html><head><title>{title} | MGS</title></head>"
                    f"<body><h1>{title} OK</h1></body></html>".encode("utf-8"))
            # CASE 26: auth hub — bounce + readonly anti-autofill + hover menu
            if path == "/public/authhub":
                if not _ah26_cookie_value(self.headers.get("Cookie", ""), AH26_KEY_COOKIE):
                    # Pre-bounce landing: its own load event fires
                    # location.replace('/public/authhub/auth-key').
                    return self._send_html(_ah26_bounce_page())
                return self._send_html(_ah26_login_page())
            if path == "/public/authhub/auth-key":
                # The post-load hop: issue the key and bounce straight back
                # to the landing, which now renders the login form.
                key = secrets.token_hex(8)
                with _AH26_LOCK:
                    _AH26_KEYS.add(key)
                return self._redirect(
                    "/public/authhub",
                    set_cookie=f"{AH26_KEY_COOKIE}={key}; Path=/",
                )
            if path == "/public/authhub/home":
                if _ah26_cookie_value(self.headers.get("Cookie", ""), AH26_SESS_COOKIE) not in _AH26_SESSIONS:
                    return self._redirect("/public/authhub")
                return self._send_html(_ah26_home_page())
            # Frames + shadow fixtures — raw serve, no chrome (see the
            # fixture block above for each page's link inventory).
            if path == "/public/frameset-app":
                return self._send_html(FRAMESET_APP_HTML.encode("utf-8"))
            if path == "/public/frame-menu":
                return self._send_html(FRAME_MENU_HTML.encode("utf-8"))
            if path == "/public/frame-content":
                return self._send_html(FRAME_CONTENT_HTML.encode("utf-8"))
            if path == "/public/frame-inner":
                return self._send_html(FRAME_INNER_HTML.encode("utf-8"))
            if path == "/public/iframe-app":
                return self._send_html(IFRAME_APP_HTML.encode("utf-8"))
            if path == "/public/shadow-app":
                return self._send_html(SHADOW_APP_HTML.encode("utf-8"))
            # Frame/shadow login fixtures — the panel posts to the same CASE
            # 26 endpoint as /public/authhub, so credentials and session
            # store are identical. /home pages gate on that session.
            if path == "/public/iframe-login":
                return self._send_html(IFRAME_LOGIN_HTML.encode("utf-8"))
            if path == "/public/iframe-login/panel":
                return self._send_html(IFRAME_LOGIN_PANEL_HTML.encode("utf-8"))
            if path == "/public/iframe-login/home":
                if _ah26_cookie_value(self.headers.get("Cookie", ""), AH26_SESS_COOKIE) not in _AH26_SESSIONS:
                    return self._redirect("/public/iframe-login")
                return self._send_html(IFRAME_LOGIN_HOME_HTML.encode("utf-8"))
            if path == "/public/shadow-login":
                return self._send_html(SHADOW_LOGIN_HTML.encode("utf-8"))
            if path == "/public/shadow-login/home":
                if _ah26_cookie_value(self.headers.get("Cookie", ""), AH26_SESS_COOKIE) not in _AH26_SESSIONS:
                    return self._redirect("/public/shadow-login")
                return self._send_html(SHADOW_LOGIN_HOME_HTML.encode("utf-8"))
            return self._send_html(
                b"<!DOCTYPE html><html><body style='background:#0f172a;color:#ef4444;"
                b"font-family:sans-serif;padding:40px'><h1>404 Not Found</h1>"
                b"<p>This public endpoint does not exist.</p></body></html>", 404)

        # /static/* — serve raw files from test_site/static/ (no login)
        if path == "/static" or path.startswith("/static/"):
            return self._serve_static(path[len("/static"):] or "/")

        # Downloads — CASE 11 & 12
        if path == "/downloads/report.pdf":
            return self._send_bytes(STUB_PDF, "application/pdf")
        if path == "/downloads/missing.pdf":
            return self._send_html(b"<h1>404</h1>", 404)

        # CASE 16 assets (backslash targets — no login needed so static scans hit them)
        if path in ("/win/logo.png", "/win/bg.png"):
            return self._send_bytes(STUB_PNG, "image/png")
        if path == "/win/report.pdf":
            return self._send_bytes(STUB_PDF, "application/pdf")
        if path == "/win/styles.css":
            return self._send_bytes(WIN_CSS_TEXT.encode("utf-8"), "text/css")

        # CASE 18 asset (base-href target — no login needed so static scans hit it)
        if path == "/baseroot/r/school/files/logo.png":
            return self._send_bytes(STUB_PNG, "image/png")
        # CASE 19 asset (srcset target — same deal)
        if path == "/baseroot/r/school/files/logo-big.png":
            return self._send_bytes(STUB_PNG, "image/png")

        # Main login-gated routes
        # Fix-3 model: / shows the public homepage before login and the
        # dashboard after login (same on http and https).
        if path in ("/", "/index.html"):
            if self._is_authed():
                title, body, tab = ROUTES[path]
                return self._send_html(render(title, body, tab, proto, authed=True))
            return self._send_html(LANDING_HTML.encode("utf-8"))

        # Public landing sub-pages (no login) — pre-login crawl surface.
        if path in PUBLIC_LANDING_ROUTES:
            return self._send_html(PUBLIC_LANDING_ROUTES[path].encode("utf-8"))

        # CASE 18 hub: /basehub/gallery is login-gated, /public/basehub is
        # served from the /public/ branch above (static mirror).
        # Same document both ways.
        if path == "/basehub/gallery":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(BASEHUB_HTML.encode("utf-8"))
        # CASE 19 hub: same split (/srcsethub/gallery gated, /public/srcsethub static).
        if path == "/srcsethub/gallery":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(SRCSET_HUB_HTML.encode("utf-8"))

        if path in ROUTES:
            if not self._is_authed():
                return self._redirect("/login")
            title, body, tab = ROUTES[path]
            return self._send_html(render(title, body, tab, proto, authed=True))

        # Logout — destroys the live server-side session (single-session
        # management). Idempotent: works with or without a valid session.
        if path == "/logout":
            token = self._session_token()
            if token:
                with _SESSIONS_LOCK:
                    _SESSIONS.discard(token)
            self.send_response(200)
            body = (b"<!DOCTYPE html><html><body style='background:#0f172a;color:#f8fafc;"
                    b"font-family:sans-serif;padding:40px'><h1>Signed out</h1>"
                    b"<p>You have been logged out. The account is free for the next sign in.</p>"
                    b"<p><a href='/login' style='color:#06b6d4'>Back to Sign In</a></p></body></html>")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", f"{SESSION_COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0")
            self.end_headers()
            self.wfile.write(body)
            return

        # Login page — hidden from already-logged-in clients (same-browser
        # tabs share the session cookie, so they land back in the app).
        if path == "/login":
            if self._is_authed():
                return self._redirect("/")
            return self._send_html(LOGIN_FORM.replace("{message}", "").encode())

        # 404 for everything else (CASE 1)
        self._send_html(
            b"<!DOCTYPE html><html><body style='background:#0f172a;color:#ef4444;"
            b"font-family:sans-serif;padding:40px'><h1>404 Not Found</h1>"
            b"<p>This endpoint does not exist.</p></body></html>", 404)

    def do_POST(self):
        # CASE 26: auth hub login (JSON fetch from the login form).
        if self.path == "/public/authhub/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            # The form posts a JSON body via fetch; accept form-encoding too.
            if "application/json" in (self.headers.get("Content-Type") or ""):
                import json as _json
                try:
                    data = _json.loads(raw) or {}
                except Exception:
                    data = {}
                fields = {str(k): ["" if v is None else str(v)] for k, v in data.items()}
            else:
                fields = parse_qs(raw)
            u = (fields.get("username") or [""])[0]
            p = (fields.get("password") or [""])[0]
            if u == AH26_USERNAME and p == AH26_PASSWORD:
                token = secrets.token_hex(16)
                with _AH26_LOCK:
                    _AH26_SESSIONS.add(token)
                # JSON responses can't redirect cross-document; the page's
                # own JS navigates to /public/authhub/home on ok:true.
                return self._json26(True, sess_cookie=token)
            return self._json26(False)
        # CASE 26: auth hub logout (JSON fetch from the hover menu button).
        if self.path == "/public/authhub/logout":
            token = _ah26_cookie_value(self.headers.get("Cookie", ""), AH26_SESS_COOKIE)
            with _AH26_LOCK:
                _AH26_SESSIONS.discard(token)
            return self._json26(True, clear_sess=True)

        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            fields = parse_qs(self.rfile.read(length).decode())
            u = (fields.get("username") or [""])[0]
            p = (fields.get("password") or [""])[0]
            c = (fields.get("captcha") or [""])[0]
            # NOTE: "remember" checkbox is intentionally ignored — its only
            # purpose is exercising the tool's fill/other replay path.
            if u == USERNAME and p == PASSWORD:
                if c != CAPTCHA_CODE:
                    msg = "<p style='color:#ef4444;text-align:center;margin-bottom:16px'>Incorrect captcha code.</p>"
                    return self._send_html(LOGIN_FORM.replace("{message}", msg).encode(), 401)
                with _SESSIONS_LOCK:
                    own_token = self._session_token()
                    if own_token and own_token in _SESSIONS:
                        action = "already"
                        token = None
                    elif _SESSIONS:
                        # Another tab/window holds the account: refuse without
                        # issuing a session. Phrasing matches the audit tool's
                        # session-conflict markers so it fails closed.
                        action = "conflict"
                        token = None
                    else:
                        action = "issue"
                        token = secrets.token_hex(16)
                        _SESSIONS.add(token)
                if action == "already":
                    # Same client, already logged in — back to the app.
                    return self._redirect("/")
                if action == "conflict":
                    msg = ("<p style='color:#ef4444;text-align:center;margin-bottom:16px'>"
                           "Your account is already logged in elsewhere — another session "
                           "is active. Log out from the previous session before signing in again.</p>")
                    return self._send_html(LOGIN_FORM.replace("{message}", msg).encode(), 200)
                return self._redirect("/", set_cookie=f"{SESSION_COOKIE_NAME}={token}; Path=/")
            msg = "<p style='color:#ef4444;text-align:center;margin-bottom:16px'>Invalid credentials.</p>"
            return self._send_html(LOGIN_FORM.replace("{message}", msg).encode(), 401)
        self._send_html(b"<h1>404</h1>", 404)

    def log_message(self, fmt, *args):
        srv = "HTTPS" if getattr(self.server, "_is_https", False) else "HTTP "
        print(f"[test_site:{srv}] {self.address_string()} - {fmt % args}")


# ---------------------------------------------------------------------------
# Generate a real self-signed cert using Python's ssl module
# ---------------------------------------------------------------------------

def _make_ssl_context() -> ssl.SSLContext | None:
    """
    Tries to create a self-signed cert context.
    Requires the 'cryptography' package OR falls back to a pre-baked
    approach using openssl CLI if available.
    If neither works, HTTPS server is skipped with a warning.
    """
    import subprocess, sys, tempfile, os

    tmp = tempfile.mkdtemp()
    cert = os.path.join(tmp, "cert.pem")
    key  = os.path.join(tmp, "key.pem")

    # Try openssl CLI (available on most Linux/macOS, Git Bash on Windows)
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "3650",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ], check=True, capture_output=True, timeout=15)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        print(f"[test_site] Self-signed cert generated via openssl CLI → {cert}")
        return ctx
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # Try Python cryptography package
    try:
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]), critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        Path(cert).write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
        Path(key).write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        print(f"[test_site] Self-signed cert generated via cryptography pkg → {cert}")
        return ctx
    except ImportError:
        pass

    print("[test_site] WARNING: openssl CLI and 'cryptography' package not found.")
    print("[test_site]          HTTPS server (port 5051) will be SKIPPED.")
    print("[test_site]          To enable it: pip install cryptography")
    return None


# ---------------------------------------------------------------------------
# Entry point — starts HTTP on 5050 and HTTPS on 5051 in parallel threads
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    # ---- HTTP server (port 5050) ----------------------------------------
    http_server = socketserver.ThreadingTCPServer(("127.0.0.1", HTTP_PORT), Handler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    print()
    print(f"🚀  HTTP  test site : http://127.0.0.1:{HTTP_PORT}/")
    print(f"🔑  Login            : username=tester  password=testpass123  captcha=X7K9 (+Remember me checkbox)")
    print(f"🚪  Logout           : http://127.0.0.1:{HTTP_PORT}/logout  (single session — frees the account)")
    print()

    # ---- HTTPS server (port 5051) — CASE 15 SSL cert -------------------
    ssl_ctx = _make_ssl_context()
    if ssl_ctx:
        https_server = socketserver.ThreadingTCPServer(("127.0.0.1", HTTPS_PORT), Handler)
        https_server._is_https = True          # flag read by Handler._proto()
        https_server.socket = ssl_ctx.wrap_socket(https_server.socket, server_side=True)
        https_thread = threading.Thread(target=https_server.serve_forever, daemon=True)
        https_thread.start()
        print(f"🔒  HTTPS test site : https://127.0.0.1:{HTTPS_PORT}/")
        print(f"    ↳ Self-signed cert — tests CASE 15 (SSL fix).")
        print(f"    ↳ Browser will warn 'Not Secure' — that is expected.")
    print()
    print("━" * 60)
    print("  CASE COVERAGE")
    print("━" * 60)
    print("  CASE  1  Broken link (404)")
    print("  CASE  2  External / internet link")
    print("  CASE  3  IP-based link")
    print("  CASE  4  Bare # anchor — inactive")
    print("  CASE  5  href='page#' — inactive but page is crawled")
    print("  CASE  6  Extension-less pages (/products/cloud, /docs/api)")
    print("  CASE  7  JS onclick navigation")
    print("  CASE  8  Inline CSS url() — working + broken")
    print("  CASE  9  Internal <style> url() — working + broken")
    print("  CASE 10  Commented links (HTML, CSS, JS)")
    print("  CASE 11  Download links — working PDF + broken PDF")
    print("  CASE 12  Image src — working PNG + broken PNG")
    print("  CASE 13  CSS dropdown nav (all links in raw HTML, CSS hidden)")
    print("  CASE 14  Login-gated site (dynamic mode + recorded login)")
    print("           Single session: 2nd login refused until /logout")
    print("  CASE 15  HTTPS self-signed cert (verify=False fix)")
    print("  CASE 16  Backslash hrefs (..\\dir\\page) — WHATWG leniency")
    print("  CASE 17  Blob URLs (excluded) + Data URLs (malformed only)")
    print("  CASE 18  <base href> re-anchoring (hub /basehub/gallery, static /public/basehub)")
    print("  CASE 19  srcset candidates (hub /srcsethub/gallery, static /public/srcsethub)")
    print("━" * 60)
    print()
    print("  CASE 16 targets: /win/nested/page, /campus/About School/page")
    print("  (public mirrors: /public/win/nested/page, /public/campus/About School/page)")
    print("  CASE 17 targets: /media/page  (public mirror: /public/media/page)")
    print("  Fix-3 model: / shows the public homepage before login (links /features,")
    print("    /pricing, /login + broken /landing-broken) and the dashboard after login.")
    print("  HTTPS mirrors (same vectors over TLS, self-signed):")
    print("    https://127.0.0.1:5051/public/media/page")
    print("    https://127.0.0.1:5051/public/win/nested/page")
    print("    https://127.0.0.1:5051/public/")
    print()
    print()
    print("Press Ctrl+C to stop.")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[test_site] Shutting down.")
        http_server.shutdown()
        if ssl_ctx:
            https_server.shutdown()