# SPDX-License-Identifier: GPL-3.0-or-later
"""Local TLS/HTTP flow servers for the G33 browser cells.

The servers are the cells' independent ground truth: they record what the
browser actually did at the TLS layer (connections, presented client
certificates, requests served) so the oracle never infers PKCS#11 use from
a successful page load alone. All listeners bind 127.0.0.1 on ephemeral
ports; certificates are short-lived and confined to the cell workdir.
"""

from __future__ import annotations

import http.server
import ssl
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path


class TLSError(RuntimeError):
    """A flow server could not start."""


def make_server_credential(workdir: Path, common_name: str = "127.0.0.1") -> tuple[Path, Path]:
    """Generate a short-lived self-signed server cert (key, cert) with openssl."""
    workdir.mkdir(parents=True, exist_ok=True)
    key = workdir / "server-key.pem"
    cert = workdir / "server-cert.pem"
    proc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-days", "2", "-subj", f"/CN={common_name}",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise TLSError(f"openssl req failed: {proc.stderr.strip()}")
    return key, cert


@dataclass
class FlowServer:
    """A threaded loopback flow server recording TLS ground truth.

    ``require_client_cert`` selects a CERT_REQUIRED acceptor (the client-cert
    flow); otherwise any client may connect. ``client_ca`` is required with
    CERT_REQUIRED and names the CA file the presented client cert must chain
    to (the harness passes the self-signed client cert itself).
    ``use_tls=False`` serves plain HTTP (no cert/key needed); CERT_REQUIRED
    is meaningless there and refused.
    """

    cert: Path | None = None
    key: Path | None = None
    require_client_cert: bool = False
    client_ca: Path | None = None
    use_tls: bool = True
    connections: int = 0
    requests_served: int = 0
    client_certs_presented: int = 0
    _httpd: http.server.HTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise TLSError("server not started")
        return self._httpd.socket.getsockname()[1]

    @property
    def url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}/"

    #: Bound for one connection's TLS handshake; a stalled peer must never
    #: wedge the acceptor (a wrapped listener would block inside accept()).
    HANDSHAKE_TIMEOUT = 15.0

    def __enter__(self) -> "FlowServer":
        if self.require_client_cert and self.client_ca is None:
            raise TLSError("CERT_REQUIRED needs a client_ca file")
        if self.require_client_cert and not self.use_tls:
            raise TLSError("CERT_REQUIRED needs TLS")
        if self.use_tls and (self.cert is None or self.key is None):
            raise TLSError("TLS needs a cert and key")
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler naming
                try:
                    peer = self.connection.getpeercert(binary_form=True)
                except Exception:
                    peer = None
                server.requests_served += 1
                if peer:
                    server.client_certs_presented += 1
                body = b"g33-flow-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # noqa: ANN001, ANN202 - stdlib override
                pass

        context = None
        if self.use_tls:
            assert self.cert is not None and self.key is not None
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                context.load_cert_chain(str(self.cert), str(self.key))
                if self.require_client_cert:
                    assert self.client_ca is not None
                    context.load_verify_locations(cafile=str(self.client_ca))
                    context.verify_mode = ssl.CERT_REQUIRED
            except Exception as exc:
                raise TLSError(f"TLS setup failed: {exc}") from exc

        # Plain listener, TLS per connection: accept() itself never blocks
        # on handshake bytes, and a stalled peer fails one connection, not
        # the acceptor. Threaded so one slow flow cannot stall another.
        class AcceptingServer(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):  # noqa: ANN202 - stdlib override
                conn, client_address = super().get_request()
                server.connections += 1
                if context is None:
                    return conn, client_address
                conn.settimeout(server.HANDSHAKE_TIMEOUT)
                try:
                    tls_conn = context.wrap_socket(conn, server_side=True)
                except (OSError, ValueError):
                    conn.close()
                    raise
                tls_conn.settimeout(None)
                return tls_conn, client_address

        try:
            httpd = AcceptingServer(("127.0.0.1", 0), Handler)
        except Exception as exc:
            raise TLSError(f"listen failed: {exc}") from exc
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
