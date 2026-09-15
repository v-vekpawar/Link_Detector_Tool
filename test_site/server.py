#!/usr/bin/env python3
"""
Local test website for the Link & Navigation Audit Tool.

Stdlib-only (http.server) — no extra pip installs needed. Run it and point
the tool at http://127.0.0.1:5050/ as a Dynamic scan with login.

    python test_site.py

Login credentials: username "tester", password "testpass123"
(auto-fill and recorded-flow login both work against this form — it's a
plain <input type="password"> + <input type="text"> in one <form>, same
shape auto_login() looks for).

Why 127.0.0.1 and not a domain name: the tool is designed around a literal
IP as the "reference IP" (one VM = one app, per BUILD_PLAN.md) — that's
what classify_host()/extract_reference_ip() actually handle correctly.
127.0.0.1 is a literal IP, so this exercises the tool the way it's meant
to run, unlike testing against a public hostname (e.g. lumen5.com), where
every same-site link gets misclassified as "internet" since classify_host()
doesn't currently resolve/compare hostnames — see the accompanying message
for that separate issue.

What this site is built to exercise:
- Login wall (session cookie), so both auto-fill and recorded-flow login
  can be tested against it.
- A nav bar with:
    - two REAL <a href> links (About, Contact) — should be crawled.
    - one FAKE nav item with NO href at all, just onclick JS navigation
      (Services) — per README.md, this is explicitly Phase-2 scope (click-
      testing no-href JS no-ops); Phase 1 can't and shouldn't find it via
      static parsing. Confirms the crawler correctly does NOT wander into
      /services through this route (it's still reachable if you type the
      URL directly, just not discoverable by crawling).
- One of each Links-section category: broken, inactive (trailing #),
  ip_based, internet.
- One of each Source-Code-section category: inline_css, internal_css,
  inline_js, internal_js, and commented_link in all three flavors (HTML
  comment, CSS comment inside <style>, JS comment inside <script>).
- Three real pages behind the nav (Home, About, Contact) so pages_crawled
  ends up > 1, with About linking on to Contact too (not just a star
  layout from Home) as a sanity check that multi-hop crawling works.
"""

import http.server
import socketserver
from urllib.parse import parse_qs

PORT = 5050
USERNAME = "tester"
PASSWORD = "testpass123"
SESSION_COOKIE_VALUE = "authed"


def page_shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; margin: 40px; }}
  nav a, nav span {{ margin-right: 16px; cursor: pointer; }}
  /* old promo banner, dropped in the redesign: <a href="/old-promo">Old promo</a> */
  .notice {{ padding: 8px; border: 1px solid #ccc; }}
</style>
</head>
<body>
<!-- <a href="/deprecated-page">Deprecated page</a> - remove before launch -->
<nav>
  <a href="/">Home</a>
  <a href="/about">About</a>
  <a href="/contact">Contact</a>
  <span class="nav-fake" onclick="window.location.href='/services'">Services</span>
  <a href="/reports#">Reports</a>
</nav>
<h1>{title}</h1>
{body}
<script>
  // real code — nothing to flag here
  function go(path) {{ window.location.href = path; }}
  // TODO remove before launch: <a href="/old-nav-item">Old nav item</a>
  /* another leftover: <a href="/also-old">Also old</a> */
</script>
</body>
</html>"""


LOGIN_FORM = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body>
<h1>Login</h1>
{message}
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <button type="submit">Log in</button>
</form>
</body>
</html>"""

HOME_BODY = """
<div class="notice" style="color:#a3291f; font-weight:bold;">Inline-styled notice (inline CSS)</div>
<p><a href="/this-page-does-not-exist">Broken page link</a></p>
<p><a href="https://example.com/external">External site (internet link)</a></p>
<p><a href="http://192.0.2.55/other-app">Other VM on the network (ip_based link)</a></p>
<p onclick="go('/about')">Click me too (inline JS via onclick)</p>
"""

ABOUT_BODY = """
<p>About page. <a href="/contact">Continue to Contact</a> (multi-hop crawl check).</p>
"""

CONTACT_BODY = """
<p>Contact page. <a href="/">Back home</a>.</p>
"""

SERVICES_BODY = """
<p>Services page — only reachable via the nav bar's JS onclick, not a real link.
If you're seeing this in a scan report, the crawler followed a link, which it
shouldn't have been able to for this page.</p>
"""


def render(title, body):
    return page_shell(title, body).encode("utf-8")


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
            return self._send_html(render("Home", HOME_BODY))

        if self.path == "/about":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("About", ABOUT_BODY))

        if self.path == "/contact":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("Contact", CONTACT_BODY))

        if self.path == "/services":
            if not self._is_authed():
                return self._redirect("/login")
            return self._send_html(render("Services", SERVICES_BODY))

        if self.path == "/login":
            return self._send_html(LOGIN_FORM.format(message="").encode("utf-8"))

        # Anything else (including /this-page-does-not-exist) -> real 404,
        # for the "broken" link category.
        self._send_html(b"<h1>404 Not Found</h1>", status=404)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            fields = parse_qs(body)
            username = (fields.get("username") or [""])[0]
            password = (fields.get("password") or [""])[0]
            if username == USERNAME and password == PASSWORD:
                return self._redirect("/", set_cookie=f"session={SESSION_COOKIE_VALUE}; Path=/")
            msg = "<p style='color:red'>Invalid credentials.</p>"
            return self._send_html(LOGIN_FORM.format(message=msg).encode("utf-8"), status=401)
        self._send_html(b"<h1>404 Not Found</h1>", status=404)

    def log_message(self, format, *args):
        print(f"[test_site] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"Test site running at http://127.0.0.1:{PORT}/")
        print(f"Login: username={USERNAME!r} password={PASSWORD!r}")
        print("Scan target URL to use in the tool: http://127.0.0.1:5050/")
        print("Login page URL (for auto-fill mode): http://127.0.0.1:5050/login")
        httpd.serve_forever()