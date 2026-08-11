#!/usr/bin/env python3
"""Minimal Knative-servable HTTP handler: each GET request runs the
deterministic PKCS#11 workload (spike/harness.c) once against SoftHSM2 and
returns its stdout. This is the whole "application" for the scale-from-zero
matrix row -- Knative needs a container that listens on $PORT; the PKCS#11
calls happen synchronously inside the request handler so the triggering
curl doesn't return until the harness (and its full oracle call sequence)
has completed.
"""
import http.server
import os
import subprocess

PORT = int(os.environ.get("PORT", "8080"))
MODULE = "/usr/lib/softhsm/libsofthsm2.so"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        r = subprocess.run(["/usr/local/bin/harness", MODULE], capture_output=True, text=True)
        body = (r.stdout + r.stderr).encode()
        self.send_response(200 if r.returncode == 0 else 500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
