# SPDX-License-Identifier: GPL-3.0-or-later
"""Local TLS/HTTP flow servers for the G33 browser cells.

The servers are the cells' independent ground truth: they record what the
browser actually did at the TLS layer (connections, per-connection
handshake outcomes, presented client certificates, requests served) so the
oracle never infers PKCS#11 use from a successful page load alone. All
listeners bind 127.0.0.1 on ephemeral ports; certificates are short-lived
and confined to the cell workdir.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


class TLSError(RuntimeError):
    """A flow server could not start."""


#: First byte of a TLS handshake record: a ClientHello always opens one,
#: so a peeked first byte distinguishes TLS speakers from garbage.
TLS_HANDSHAKE_FIRST_BYTE = 0x16

#: Cap for one peeked ClientHello flight: a real first flight is ~0.5-2KB
#: in one record; a hello not provable within the cap fails closed as
#: incomplete.
MAX_HELLO_PEEK = 65536


def client_hello_status(buf: bytes) -> str:
    """Classify buffered handshake bytes for the ClientHello proof.

    Returns ``"complete"`` (a full ClientHello is buffered),
    ``"need_more"`` (consistent so far, more bytes needed), ``"non_tls"``
    (the first byte is not a handshake record), or ``"not_hello"`` (a
    complete first record that is not a ClientHello, or a zero-length
    record). A handshake fragmented across records is followed,
    including a 4-byte handshake header split across records (OpenSSL
    accepts it); only the first handshake message must be a ClientHello.
    """
    if not buf:
        return "need_more"
    if buf[0] != TLS_HANDSHAKE_FIRST_BYTE:
        return "non_tls"
    offset = 0
    need: int | None = None
    have = 0
    header = b""
    while True:
        if len(buf) < offset + 5:
            return "need_more"
        if buf[offset] != TLS_HANDSHAKE_FIRST_BYTE:
            return "not_hello"
        rec_len = int.from_bytes(buf[offset + 3:offset + 5], "big")
        if rec_len == 0:
            return "not_hello"
        if len(buf) < offset + 5 + rec_len:
            return "need_more"
        payload = buf[offset + 5:offset + 5 + rec_len]
        if need is None:
            header += payload
            if len(header) < 4:
                offset += 5 + rec_len
                continue
            if header[0] != 0x01:  # handshake type client_hello
                return "not_hello"
            need = int.from_bytes(header[1:4], "big")
            if need == 0:
                return "not_hello"
            have = len(header) - 4
        else:
            have += len(payload)
        offset += 5 + rec_len
        if need is not None and have >= need:
            return "complete"


def classify_handshake_error(exc: BaseException, *, cert_request_seen: bool = False) -> str:
    """Bucket a failed server-side ``wrap_socket`` into an outcome.

    Returns ``"empty_cert"`` (the client completed the handshake with an
    empty certificate: selection reached, nothing offered), ``"cert_alert"``
    (the client refused with certificate_unknown: ambiguous between a
    selection refusal and a server-cert rejection, so tolerated but never
    a witness), ``"stall"`` (a peer that sent a complete ClientHello and
    saw the server's outbound CertificateRequest never finished: stuck
    at selection), ``"abandoned"`` (the peer went away mid-handshake: EOF,
    reset, silence, or a timeout before CertificateRequest, carrying no
    selection information), or ``"failure"`` (an unrelated protocol
    failure: garbage, version/decipher errors, or any other alert). Only
    called after a complete ClientHello: peek-phase timeouts are
    abandoned, never stalls, as are post-hello timeouts without
    affirmative CertificateRequest progress on the same connection
    (for example HelloRetryRequest waiting for ClientHello2).
    """
    upper = f"{type(exc).__name__}: {exc}".upper()
    if "PEER_DID_NOT_RETURN_A_CERTIFICATE" in upper or "PEER DID NOT RETURN A CERTIFICATE" in upper:
        return "empty_cert"
    if "CERTIFICATE_UNKNOWN" in upper:
        return "cert_alert"
    if "ALERT" in upper:
        return "failure"
    if isinstance(exc, TimeoutError):
        return "stall" if cert_request_seen else "abandoned"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "abandoned"
    if "EOF" in upper:
        return "abandoned"
    return "failure"


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

    TLS ground truth per connection: ``connections`` (accepts),
    ``spoke_tls`` (peers whose first byte opened a handshake record:
    diagnostic only, never a witness), ``client_hello_complete`` (peers
    that buffered a complete ClientHello: selection could begin),
    ``cert_requests_sent`` (connections where the server's outbound
    CertificateRequest flight was observed: selection began),
    ``handshakes_ok`` (completed handshakes), ``client_certs_presented``
    (peer cert seen at handshake time, independent of requests),
    ``empty_certs`` (full handshake with an empty client certificate),
    ``selection_stalls`` (peers that saw CertificateRequest and never
    finished: stuck at selection), ``client_cert_alerts``
    (certificate_unknown refusals: tolerated, never a witness),
    ``abandoned`` (peers that went away without selection information:
    EOF, reset, silence, an incomplete ClientHello, or a timeout before
    CertificateRequest such as HelloRetryRequest waiting for
    ClientHello2), ``handshake_failures`` with the first
    ``handshake_errors`` (unrelated protocol failures).
    """

    cert: Path | None = None
    key: Path | None = None
    require_client_cert: bool = False
    client_ca: Path | None = None
    use_tls: bool = True
    connections: int = 0
    requests_served: int = 0
    client_certs_presented: int = 0
    handshakes_ok: int = 0
    spoke_tls: int = 0
    client_hello_complete: int = 0
    cert_requests_sent: int = 0
    empty_certs: int = 0
    selection_stalls: int = 0
    client_cert_alerts: int = 0
    abandoned: int = 0
    handshake_failures: int = 0
    handshake_errors: list[str] = field(default_factory=list)
    _httpd: http.server.HTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def note_handshake(self, outcome: str, detail: str) -> None:
        """Record one failed-handshake classification (see the classifier)."""
        if outcome == "empty_cert":
            self.empty_certs += 1
        elif outcome == "cert_alert":
            self.client_cert_alerts += 1
        elif outcome == "stall":
            self.selection_stalls += 1
        elif outcome == "abandoned":
            self.abandoned += 1
        else:
            self.handshake_failures += 1
            if len(self.handshake_errors) < 3:
                self.handshake_errors.append(f"{outcome}: {detail}"[:200])

    def note_handshake_ok(self, tls_conn: ssl.SSLSocket) -> None:
        """Record one completed handshake, counting a presented peer cert.

        The peer certificate is read at handshake time, independently of
        any later HTTP request: a presented cert counts even when no
        request is ever served.
        """
        self.handshakes_ok += 1
        try:
            peer = tls_conn.getpeercert(binary_form=True)
        except Exception:
            peer = None
        if peer:
            self.client_certs_presented += 1

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise TLSError("server not started")
        return self._httpd.socket.getsockname()[1]

    @property
    def url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}/"

    #: Bound for one connection's TLS handshake (peek plus wrap); a stalled
    #: peer must never wedge the acceptor (a wrapped listener would block
    #: inside accept()).
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
                # Presented certs are counted at handshake time (a served
                # request without a handshake is impossible, but a
                # handshake without a request is the PINBOUND norm).
                server.requests_served += 1
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

        # Per-connection CertificateRequest witness: TLS 1.3 can answer a
        # complete ClientHello with HelloRetryRequest and wait for
        # ClientHello2 without ever sending CertificateRequest (RFC 8446
        # Fig.2). A timeout proves selection only when this connection
        # observed an outbound CertificateRequest. The message callback
        # runs synchronously inside the wrapping thread, so thread-local
        # state ties the witness to its connection.
        tls_progress: threading.local = threading.local()

        def _note_tls_message(conn, direction, version, content_type, msg_type, data):
            try:
                if (str(direction) == "write"
                        and int(content_type) == 22
                        and int(msg_type) == 13):
                    tls_progress.cert_request_seen = True
            except Exception:
                pass

        if context is not None:
            try:
                context._msg_callback = _note_tls_message  # noqa: SLF001 - ground-truth hook
            except Exception:
                # No callback support: fail closed (timeouts never
                # become stalls without affirmative proof).
                pass

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
                # Peek before wrapping: a complete ClientHello proves the
                # peer reached the selection boundary, and peeking never
                # consumes, so the handshake below proceeds undisturbed.
                # Anything less (silence, close, reset, or an unfinished
                # first flight) carries no selection information.
                deadline = time.monotonic() + server.HANDSHAKE_TIMEOUT
                conn.settimeout(server.HANDSHAKE_TIMEOUT)
                buf = b""
                status = "need_more"
                while status == "need_more":
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    conn.settimeout(remaining)
                    try:
                        chunk = conn.recv(MAX_HELLO_PEEK, socket.MSG_PEEK)
                    except TimeoutError:
                        break
                    except OSError as exc:
                        server.note_handshake("abandoned", f"peek {type(exc).__name__}: {exc}"[:160])
                        conn.close()
                        raise
                    if not chunk:
                        server.note_handshake("abandoned", "peer closed before sending bytes")
                        conn.close()
                        raise ConnectionError("peer closed before sending TLS bytes")
                    if len(chunk) == len(buf):
                        time.sleep(0.02)  # no new bytes yet; avoid spinning
                        continue
                    buf = chunk
                    status = client_hello_status(buf)
                if status == "need_more":
                    if buf[:1] == bytes((TLS_HANDSHAKE_FIRST_BYTE,)):
                        server.spoke_tls += 1
                    server.note_handshake(
                        "abandoned",
                        f"incomplete ClientHello: {len(buf)} bytes before the deadline")
                    conn.close()
                    raise TimeoutError("TLS ClientHello never completed before the deadline")
                if status == "non_tls":
                    server.note_handshake("failure", f"non-TLS first byte {buf[0]:#04x}")
                    conn.close()
                    raise ValueError(f"peer spoke non-TLS bytes: {bytes(buf[:5])!r}")
                server.spoke_tls += 1
                if status == "not_hello":
                    server.note_handshake("failure", "TLS first record is not a ClientHello")
                    conn.close()
                    raise ValueError("peer spoke TLS but not a ClientHello first")
                server.client_hello_complete += 1
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # The hello finished exactly at the deadline: the
                    # server flight never went out, so selection never
                    # began — no witness without that proof.
                    server.note_handshake("abandoned", "deadline exhausted before the wrap")
                    conn.close()
                    raise TimeoutError("TLS handshake deadline exhausted after the ClientHello")
                conn.settimeout(remaining)
                tls_progress.cert_request_seen = False
                try:
                    tls_conn = context.wrap_socket(conn, server_side=True)
                except (OSError, ValueError) as exc:
                    # Only reached after a complete ClientHello. A timeout
                    # is a selection stall only when this connection
                    # observed its outbound CertificateRequest; without
                    # that (for example HRR waiting for ClientHello2) it
                    # is pre-selection abandonment.
                    cert_seen = bool(getattr(tls_progress, "cert_request_seen", False))
                    if cert_seen:
                        server.cert_requests_sent += 1
                    server.note_handshake(
                        classify_handshake_error(exc, cert_request_seen=cert_seen),
                        f"{type(exc).__name__}: {exc}"[:160])
                    conn.close()
                    raise
                if bool(getattr(tls_progress, "cert_request_seen", False)):
                    server.cert_requests_sent += 1
                tls_conn.settimeout(None)
                server.note_handshake_ok(tls_conn)
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
