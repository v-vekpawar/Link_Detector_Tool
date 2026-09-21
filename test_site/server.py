#!/usr/bin/env python3
"""
Apex Enterprise Cloud — Demonstration Portal for Link & Navigation Audit Tool.

Stdlib-only (http.server) — no extra pip installs required.
Run:
    python test_site/server.py

Target URL for Audit Tool: http://127.0.0.1:5050/
Login Credentials: username "tester", password "testpass123"
"""

import http.server
import socketserver
from urllib.parse import parse_qs

PORT = 5050
USERNAME = "tester"
PASSWORD = "testpass123"
SESSION_COOKIE_VALUE = "authed"


def page_shell(title: str, body: str, active_tab: str = "home") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Apex Enterprise Cloud</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-dark: #0f172a;
    --card-bg: rgba(30, 41, 59, 0.7);
    --border-color: rgba(255, 255, 255, 0.1);
    --primary-indigo: #6366f1;
    --primary-purple: #8b5cf6;
    --accent-cyan: #06b6d4;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --danger-red: #ef4444;
    --warning-amber: #f59e0b;
    --success-green: #10b981;
  }}
  
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background-color: var(--bg-dark);
    background-image: 
      radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
      radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
    color: var(--text-main);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }}

  /* CSS Comment containing a commented link (Internal CSS finding demo) */
  /* Legacy Promo Link: <a href="/old-promo-banner">Deprecated Promo Page</a> */

  .navbar {{
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    padding: 16px 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
  }}
  
  .brand {{
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: 'Outfit', sans-serif;
    font-size: 1.25rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--primary-indigo), var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  
  .brand-logo {{
    width: 32px;
    height: 32px;
    background: linear-gradient(135deg, var(--primary-indigo), var(--primary-purple));
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
  }}
  
  .nav-links {{
    display: flex;
    align-items: center;
    gap: 24px;
  }}
  
  .nav-links a, .nav-links span {{
    color: var(--text-muted);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.95rem;
    transition: all 0.2s ease;
    cursor: pointer;
  }}
  
  .nav-links a:hover, .nav-links span:hover, .nav-links a.active {{
    color: var(--text-main);
  }}

  .status-pill {{
    background: rgba(16, 185, 129, 0.15);
    color: var(--success-green);
    border: 1px solid rgba(16, 185, 129, 0.3);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .status-dot {{
    width: 8px;
    height: 8px;
    background-color: var(--success-green);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--success-green);
  }}

  .container {{
    max-width: 1200px;
    margin: 40px auto;
    padding: 0 24px;
    flex: 1;
    width: 100%;
  }}

  .card {{
    background: var(--card-bg);
    backdrop-filter: blur(16px);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 24px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
  }}

  .grid-4 {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 20px;
    margin-bottom: 32px;
  }}

  .metric-card {{
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
  }}
  .metric-title {{ font-size: 0.85rem; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .metric-value {{ font-family: 'Outfit', sans-serif; font-size: 1.8rem; font-weight: 700; color: var(--text-main); }}

  .btn {{
    padding: 10px 20px;
    border-radius: 8px;
    font-weight: 600;
    border: none;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }}
  .btn:hover {{ transform: translateY(-1px); }}
  .btn-gradient {{
    background: linear-gradient(135deg, var(--primary-indigo), var(--primary-purple));
    color: white;
    box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
  }}
  
  .link-list {{ display: flex; flex-direction: column; gap: 14px; margin-top: 16px; }}
  .link-item {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 10px;
  }}
  .link-item a {{ color: var(--accent-cyan); text-decoration: none; font-weight: 500; }}
  .link-item a:hover {{ text-decoration: underline; }}
  .link-item a.text-danger {{ color: var(--danger-red); }}
  .tag {{ font-size: 0.75rem; padding: 4px 10px; border-radius: 6px; font-weight: 600; text-transform: uppercase; }}
  .tag-broken {{ background: rgba(239, 68, 68, 0.15); color: var(--danger-red); border: 1px solid rgba(239, 68, 68, 0.3); }}
  .tag-internet {{ background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.3); }}
  .tag-ip {{ background: rgba(245, 158, 11, 0.15); color: var(--warning-amber); border: 1px solid rgba(245, 158, 11, 0.3); }}
  .tag-inactive {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.3); }}

  footer {{
    text-align: center;
    padding: 24px;
    color: var(--text-muted);
    font-size: 0.85rem;
    border-top: 1px solid var(--border-color);
    margin-top: auto;
  }}
</style>
</head>
<body>

<!-- HTML Comment containing a commented link (Commented Link finding demo) -->
<!-- <a href="/v1-deprecated-portal">V1 Legacy Admin Portal (Deprecated)</a> -->

<header class="navbar">
  <div class="brand">
    <div class="brand-logo">A</div>
    <span>Apex Enterprise</span>
  </div>
  <nav class="nav-links">
    <a href="/" class="{'active' if active_tab == 'home' else ''}">Home</a>
    <a href="/about" class="{'active' if active_tab == 'about' else ''}">About</a>
    <a href="/contact" class="{'active' if active_tab == 'contact' else ''}">Contact</a>
    <span onclick="window.location.href='/services'" class="{'active' if active_tab == 'services' else ''}">Services</span>
    <a href="/reports#">Reports</a>
  </nav>
  <div class="status-pill">
    <div class="status-dot"></div>
    <span>System Operational</span>
  </div>
</header>

<main class="container">
  {body}
</main>

<footer>
  &copy; 2026 Apex Cloud Systems Inc. All rights reserved. | Security Compliance Audit Portal
</footer>

<script>
  // Real active JS navigation helper
  function go(path) {{ window.location.href = path; }}
  
  // Commented JS containing a commented link (Commented Link in JS demo)
  // TODO: <a href="/beta-v2-dashboard">Beta V2 Dashboard (Unreleased)</a>
  /* Leftover JS link: <a href="/archive-v1">Archive V1 Portal</a> */
</script>
</body>
</html>"""


LOGIN_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enterprise Single Sign-On — Apex Cloud</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@600;700&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background-color: #0f172a;
    background-image: radial-gradient(circle at 50% 30%, rgba(99, 102, 241, 0.2), transparent 70%);
    color: #f8fafc;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .login-card {
    background: rgba(30, 41, 59, 0.7);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 20px;
    padding: 40px;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  }
  .logo-header { text-align: center; margin-bottom: 32px; }
  .logo-icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    border-radius: 12px;
    display: inline-flex; align-items: center; justify-content: center;
    font-family: 'Outfit', sans-serif; font-size: 1.5rem; font-weight: 700; color: white;
    margin-bottom: 12px;
  }
  h1 { font-family: 'Outfit', sans-serif; font-size: 1.5rem; font-weight: 700; }
  p.subtitle { color: #94a3b8; font-size: 0.9rem; margin-top: 4px; }
  .field { margin-bottom: 20px; }
  label { display: block; font-size: 0.85rem; font-weight: 600; color: #cbd5e1; margin-bottom: 8px; }
  input[type="text"], input[type="password"] {
    width: 100%; padding: 12px 16px;
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 10px; color: white; font-size: 0.95rem;
    outline: none; transition: border-color 0.2s ease;
  }
  input[type="text"]:focus, input[type="password"]:focus {
    border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
  }
  button[type="submit"] {
    width: 100%; padding: 14px; margin-top: 10px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white; border: none; border-radius: 10px;
    font-size: 1rem; font-weight: 600; cursor: pointer;
    box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
    transition: transform 0.15s ease;
  }
  button[type="submit"]:hover { transform: translateY(-1px); }
  .demo-creds {
    margin-top: 24px; padding: 12px; border-radius: 8px;
    background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.2);
    font-size: 0.8rem; color: #a5b4fc; text-align: center;
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="logo-header">
    <div class="logo-icon">A</div>
    <h1>Apex Cloud Portal</h1>
    <p class="subtitle">Single Sign-On Authentication</p>
  </div>
  {message}
  <form method="POST" action="/login">
    <div class="field">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="e.g. tester" autocomplete="off" required>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="••••••••" required>
    </div>
    <button type="submit">Sign In to Dashboard</button>
  </form>
  <div class="demo-creds">
    <strong>Demo Credentials:</strong><br>Username: <code>tester</code> | Password: <code>testpass123</code>
  </div>
</div>
</body>
</html>"""

HOME_BODY = """
<div class="grid-4">
  <div class="metric-card">
    <div class="metric-title">Active Mesh Nodes</div>
    <div class="metric-value">128 / 128</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Network Latency</div>
    <div class="metric-value">4.2 ms</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Security Score</div>
    <div class="metric-value">99.8%</div>
  </div>
  <div class="metric-card">
    <div class="metric-title">Audit Engine</div>
    <div class="metric-value">Active</div>
  </div>
</div>

<!-- Active Inline CSS Demonstration -->
<div class="card" style="background: linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(139, 92, 246, 0.15)); border: 1px solid rgba(99, 102, 241, 0.3); padding: 20px; border-radius: 14px; margin-bottom: 24px;">
  <h3 style="font-size: 1.1rem; color: #a5b4fc; margin-bottom: 6px;">System Alert Notification</h3>
  <p style="color: #cbd5e1; font-size: 0.95rem;">Inline CSS styling attribute actively evaluated on this telemetry card container.</p>
</div>

<div class="card">
  <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.4rem; margin-bottom: 16px;">Target Audit Test Vectors</h2>
  <p style="color: var(--text-muted); margin-bottom: 20px;">The endpoints below exercise all target link classification categories and code findings:</p>

  <div class="link-list">
    <div class="link-item">
      <div>
        <strong style="display:block;">404 Page Outage Endpoint</strong>
        <a href="/this-page-does-not-exist" class="text-danger">/this-page-does-not-exist</a>
      </div>
      <span class="tag tag-broken">Broken Link</span>
    </div>

    <div class="link-item">
      <div>
        <strong style="display:block;">External Documentation Portal</strong>
        <a href="https://example.com/external" target="_blank">https://example.com/external</a>
      </div>
      <span class="tag tag-internet">Internet Link</span>
    </div>

    <div class="link-item">
      <div>
        <strong style="display:block;">Secondary Cluster Appliance</strong>
        <a href="http://192.0.2.55/other-app">http://192.0.2.55/other-app</a>
      </div>
      <span class="tag tag-ip">IP-Based Link</span>
    </div>

    <div class="link-item">
      <div>
        <strong style="display:block;">Quarterly Audit Report Anchor</strong>
        <a href="/reports#">/reports#</a>
      </div>
      <span class="tag tag-inactive">Inactive Link (#)</span>
    </div>
  </div>

  <div style="margin-top: 28px; display: flex; gap: 16px; align-items: center;">
    <button class="btn btn-gradient" onclick="window.location.href='/services'">
      Launch Services Portal (Inline JS Onclick)
    </button>
    <button class="btn" style="background: rgba(255,255,255,0.1); color: white;" onclick="go('/about')">
      Company Profile (Internal JS Call)
    </button>
  </div>
</div>
"""

ABOUT_BODY = """
<div class="card">
  <h1 style="font-family: 'Outfit', sans-serif; font-size: 2rem; margin-bottom: 12px;">About Apex Enterprise Cloud</h1>
  <p style="color: var(--text-muted); font-size: 1.05rem; line-height: 1.6; margin-bottom: 24px;">
    Apex Cloud Systems provides high-performance telemetry and security audit tools for mission-critical infrastructure.
  </p>

  <div style="padding: 20px; background: rgba(15, 23, 42, 0.6); border-radius: 12px; border: 1px solid var(--border-color); margin-bottom: 24px;">
    <h3 style="color: var(--accent-cyan); margin-bottom: 8px;">Multi-Hop Crawl Path Verification</h3>
    <p style="color: var(--text-muted);">
      From this page, the crawler discovers additional sub-pages: 
      <a href="/contact" style="color: var(--primary-indigo); font-weight: 600;">Proceed to Contact Desk</a>.
    </p>
  </div>
</div>
"""

CONTACT_BODY = """
<div class="card">
  <h1 style="font-family: 'Outfit', sans-serif; font-size: 2rem; margin-bottom: 12px;">Enterprise Support & Contact</h1>
  <p style="color: var(--text-muted); font-size: 1.05rem; line-height: 1.6; margin-bottom: 24px;">
    Reach out to our 24/7 Global Security Operations Center.
  </p>

  <div class="link-list">
    <div class="link-item">
      <span>Return to Operations Dashboard</span>
      <a href="/">Back to Home</a>
    </div>
  </div>
</div>
"""

SERVICES_BODY = """
<div class="card">
  <h1 style="font-family: 'Outfit', sans-serif; font-size: 2rem; margin-bottom: 12px;">Cloud Solutions & Services</h1>
  <p style="color: var(--text-muted); font-size: 1.05rem; line-height: 1.6; margin-bottom: 24px;">
    This page is accessible via the navbar's JavaScript <code>onclick</code> handler.
  </p>

  <div style="padding: 20px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px;">
    <h3 style="color: var(--success-green); margin-bottom: 8px;">JS Navigation Successfully Discovered!</h3>
    <p style="color: var(--text-main);">If you are viewing this page in a dynamic scan report, the Playwright engine successfully executed the inline JS event handler to reach this route.</p>
  </div>
</div>
"""


def render(title: str, body: str, active_tab: str = "home") -> bytes:
    return page_shell(title, body, active_tab).encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    def _is_authed(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        return f"session={SESSION_COOKIE_VALUE}" in cookie

    def _send_html(self, body: bytes, status: int = 200, set_cookie: str = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, set_cookie: str = None):
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("Dashboard", HOME_BODY, "home"))

        if self.path == "/about":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("About Us", ABOUT_BODY, "about"))

        if self.path == "/contact":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("Contact Desk", CONTACT_BODY, "contact"))

        if self.path == "/services":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("Services Showcase", SERVICES_BODY, "services"))

        if self.path == "/login":
            return self._send_html(LOGIN_FORM.replace("{message}", "").encode("utf-8"))

        # 404 handler for testing broken link category
        self._send_html(b"<!DOCTYPE html><html><body style='background:#0f172a;color:#ef4444;font-family:sans-serif;padding:40px;'><h1>404 Not Found</h1><p>The requested endpoint does not exist.</p></body></html>", status=404)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            fields = parse_qs(body)
            username = (fields.get("username") or [""])[0]
            password = (fields.get("password") or [""])[0]
            if username == USERNAME and password == PASSWORD:
                return self._redirect("/", set_cookie=f"session={SESSION_COOKIE_VALUE}; Path=/")
            msg = "<p style='color:#ef4444; margin-bottom:16px; font-size:0.9rem; text-align:center;'>Invalid credentials provided.</p>"
            return self._send_html(LOGIN_FORM.replace("{message}", msg).encode("utf-8"), status=401)
        self._send_html(b"<h1>404 Not Found</h1>", status=404)

    def log_message(self, format, *args):
        print(f"[test_site] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"🚀 Apex Enterprise Test Portal running at http://127.0.0.1:{PORT}/")
        print(f"🔑 Credentials: username={USERNAME!r} password={PASSWORD!r}")
        print(f"🎯 Target URL for audit tool: http://127.0.0.1:{PORT}/")
        httpd.serve_forever()