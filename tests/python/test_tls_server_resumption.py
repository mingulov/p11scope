#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Per-handshake TLS resumption ground truth for the browser cells.

tests/fixtures/browser/tls_server.py records, for every completed
handshake, whether the peer presented a certificate and whether the
session resumed. Only full (non-resumed) presented handshakes predict
a client CertificateVerify signature, so ``full_presented`` is the
exact expected client-signature count. This suite pins the
full/resumed split of ``FlowServer.note_handshake_ok`` with fake
connections (stdlib ``ssl`` objects are hard to fake): full,
resumed, absent-cert and fail-soft (missing attribute) handshakes.

Run: python3 -I tests/python/test_tls_server_resumption.py -v
"""

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "browser"))

from tls_server import FlowServer  # noqa: E402


class ssl_SSLError(Exception):
    pass


class FakeConn:
    """A scripted stand-in for the ``ssl.SSLSocket`` surface the
    fixture reads: ``getpeercert(binary_form=True)``,
    ``session_reused`` and ``version()``."""

    def __init__(
        self,
        peer=b"cert",
        reused=False,
        version="TLSv1.3",
        peer_raises=False,
        reused_raises=False,
    ):
        self._peer = peer
        self._reused = reused
        self._version = version
        self._peer_raises = peer_raises
        self._reused_raises = reused_raises

    def getpeercert(self, binary_form=False):  # noqa: ARG002
        if self._peer_raises:
            raise ssl_SSLError("no peer cert")
        return self._peer

    @property
    def session_reused(self):
        if self._reused_raises:
            raise AttributeError("no session_reused")
        return self._reused

    def version(self):
        return self._version


class ResumptionTest(unittest.TestCase):
    def test_full_presented_handshake_counts_a_signature(self):
        server = FlowServer()
        server.note_handshake_ok(FakeConn(peer=b"cert", reused=False))
        self.assertEqual(server.handshakes_ok, 1)
        self.assertEqual(server.client_certs_presented, 1)
        self.assertEqual(server.sessions_reused, 0)
        self.assertEqual(server.full_presented, 1)
        self.assertEqual(
            server.handshake_sessions,
            [{"reused": False, "version": "TLSv1.3", "presented": True}],
        )

    def test_resumed_handshake_counts_no_signature(self):
        server = FlowServer()
        server.note_handshake_ok(FakeConn(peer=b"cert", reused=True))
        self.assertEqual(server.handshakes_ok, 1)
        self.assertEqual(server.client_certs_presented, 1)
        self.assertEqual(server.sessions_reused, 1)
        self.assertEqual(
            server.full_presented,
            0,
            "a resumed handshake presents the original cert without a "
            "CertificateVerify, so it predicts no signature",
        )
        self.assertEqual(
            server.handshake_sessions,
            [{"reused": True, "version": "TLSv1.3", "presented": True}],
        )

    def test_absent_cert_counts_neither(self):
        server = FlowServer()
        server.note_handshake_ok(FakeConn(peer=None, reused=False))
        self.assertEqual(server.handshakes_ok, 1)
        self.assertEqual(server.client_certs_presented, 0)
        self.assertEqual(server.sessions_reused, 0)
        self.assertEqual(server.full_presented, 0)
        self.assertEqual(
            server.handshake_sessions,
            [{"reused": False, "version": "TLSv1.3", "presented": False}],
        )

    def test_missing_session_reused_fails_soft_to_full(self):
        server = FlowServer()
        server.note_handshake_ok(FakeConn(peer=b"cert", reused_raises=True))
        self.assertEqual(server.handshakes_ok, 1)
        self.assertEqual(server.client_certs_presented, 1)
        self.assertEqual(server.sessions_reused, 0)
        self.assertEqual(
            server.full_presented,
            1,
            "an unreadable resumption flag counts the handshake as "
            "full, making the bind criterion harder, never easier",
        )

    def test_mixed_handshakes_split_exactly(self):
        server = FlowServer()
        server.note_handshake_ok(FakeConn(peer=b"a", reused=False))
        server.note_handshake_ok(FakeConn(peer=b"a", reused=True))
        server.note_handshake_ok(FakeConn(peer=None, reused=False))
        server.note_handshake_ok(FakeConn(peer=b"b", reused=False, version="TLSv1.2"))
        self.assertEqual(
            (
                server.handshakes_ok,
                server.client_certs_presented,
                server.sessions_reused,
                server.full_presented,
            ),
            (4, 3, 1, 2),
        )
        self.assertEqual(
            [record["reused"] for record in server.handshake_sessions],
            [False, True, False, False],
        )
        self.assertEqual(
            [record["version"] for record in server.handshake_sessions],
            ["TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.2"],
        )


if __name__ == "__main__":
    unittest.main()
