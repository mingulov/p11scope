# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Tiny loopback TLS server that requires a client certificate.

Demo ground truth for the Chromium client-auth workload: it counts TCP
accepts, completed handshakes, handshakes that presented a client
certificate, served requests, and handshake failures. A presented client
certificate on a completed TLS 1.2/1.3 handshake proves the peer signed a
CertificateVerify with the client's private key.

Usage:
  python3 clientauth-tls-server.py --client-ca client-cert.pem \\
      --generate-to DIR [--port 0] [--ready-file PATH] [--serve 1]

With --generate-to the server mints a throwaway self-signed 127.0.0.1 server
credential into DIR (openssl); otherwise --cert/--key name one. The server
prints its URL on stdout, serves until --serve requests complete, SIGTERM /
SIGINT arrives, or stdin closes, then prints one JSON counters line.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path


def mint_server_credential(workdir: Path) -> tuple[Path, Path]:
    """Mint a 2-day self-signed 127.0.0.1 server credential with openssl."""
    workdir.mkdir(parents=True, exist_ok=True)
    key = workdir / "server-key.pem"
    cert = workdir / "server-cert.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"openssl req failed: {proc.stderr.strip()}")
    return key, cert


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-ca", required=True, type=Path,
                        help="CA file the client cert must chain to")
    parser.add_argument("--cert", type=Path, help="server cert PEM")
    parser.add_argument("--key", type=Path, help="server key PEM")
    parser.add_argument("--generate-to", type=Path,
                        help="mint a server credential into DIR")
    parser.add_argument("--port", type=int, default=0, help="listen port (0=ephemeral)")
    parser.add_argument("--ready-file", type=Path,
                        help="write the server URL here once listening")
    parser.add_argument("--serve", type=int, default=0,
                        help="exit after N served requests (0=until stdin closes)")
    parser.add_argument("--handshake-timeout", type=float, default=15.0)
    args = parser.parse_args()

    if args.generate_to is not None:
        key, cert = mint_server_credential(args.generate_to)
    elif args.cert is not None and args.key is not None:
        key, cert = args.key, args.cert
    else:
        raise SystemExit("need --generate-to or both --cert and --key")

    counters = {"connections": 0, "handshakes_ok": 0, "presented": 0,
                "served": 0, "failures": 0, "errors": []}
    lock = threading.Lock()
    stop = threading.Event()

    def note(**kw):
        with lock:
            for name, delta in kw.items():
                if name == "error":
                    if len(counters["errors"]) < 3:
                        counters["errors"].append(str(delta)[:160])
                else:
                    counters[name] += delta

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    context.load_verify_locations(cafile=str(args.client_ca))
    context.verify_mode = ssl.CERT_REQUIRED

    outer = {"httpd": None}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler naming
            note(served=1)
            body = b"clientauth-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if args.serve and counters["served"] >= args.serve:
                stop.set()

        def log_message(self, *args):  # noqa: ANN001, ANN202 - stdlib override
            pass

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):  # noqa: ANN202 - stdlib override
            conn, addr = super().get_request()
            note(connections=1)
            conn.settimeout(args.handshake_timeout)
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
            except Exception as exc:  # noqa: BLE001 - every refusal is a counter
                note(failures=1, error=f"{type(exc).__name__}: {exc}")
                conn.close()
                raise ConnectionAbortedError("handshake refused") from exc
            tls_conn.settimeout(None)
            note(handshakes_ok=1)
            try:
                peer = tls_conn.getpeercert(binary_form=True)
            except Exception:  # noqa: BLE001 - counter must not raise
                peer = None
            if peer:
                note(presented=1)
            return tls_conn, addr

        def _handle_request_noblock(self):  # noqa: ANN202 - stdlib override
            try:
                super()._handle_request_noblock()
            except ConnectionAbortedError:
                pass

    try:
        httpd = Server(("127.0.0.1", args.port), Handler)
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"listen failed: {exc}") from exc
    outer["httpd"] = httpd
    url = f"https://127.0.0.1:{httpd.socket.getsockname()[1]}/"
    print(url, flush=True)
    if args.ready_file is not None:
        args.ready_file.write_text(url + "\n")
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()

    import signal

    def _stop(*_args):
        stop.set()

    signal.signal(signal.SIGTERM, _stop)

    def watch_stdin():
        try:
            sys.stdin.read()
        except Exception:  # noqa: BLE001
            pass
        stop.set()

    threading.Thread(target=watch_stdin, daemon=True).start()
    try:
        while not stop.wait(0.1):
            pass
    except KeyboardInterrupt:
        pass
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=10)
    print(json.dumps(counters), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
