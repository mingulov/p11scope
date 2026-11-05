# SPDX-License-Identifier: GPL-3.0-or-later
"""Playwright flows for the G33 attach-drive cells.

Each factory returns a ``flow(page, context) -> dict`` callable for
``cells.attach_drive``. Flows use Playwright wait strategies (load states,
bounded timeouts), never fixed sleeps, and return JSON-able ground-truth
facts the oracle checks beside the observed profile.
"""

from __future__ import annotations

from typing import Any, Callable


def make_visit(url: str, timeout_ms: int = 30000) -> Callable[..., dict[str, Any]]:
    """Load ``url`` and report what the page showed."""

    def visit(page, context) -> dict[str, Any]:  # noqa: ANN001 - playwright types
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        body = ""
        try:
            body = page.text_content("body") or ""
        except Exception:  # noqa: BLE001 - body text is best-effort evidence
            pass
        return {
            "flow": "visit",
            "loaded_url": page.url,
            "http_status": response.status if response is not None else None,
            "body_excerpt": body[:64],
        }

    return visit


#: Navigation-error fragments proving the browser never produced a TLS
#: outcome (launch/crash/transport-setup failures, not handshake stalls).
#: Matching is a case-insensitive substring; any other navigation failure
#: is a TLS-flow outcome judged jointly with the server-side witness.
UNRELATED_CLIENT_CERT_ERRORS = (
    "executable doesn't exist",
    "has been closed",
    "target crashed",
    "browser crashed",
    "connection refused",
    "err_connection_refused",
    "err_address_unreachable",
    "err_connection_timed_out",
    "err_network_changed",
)


def classify_client_cert_error(error: str | None) -> str:
    """Classify a failed client-cert navigation: ``"tls_flow"`` or ``"unrelated"``.

    ``"unrelated"`` means the browser demonstrably never produced a TLS
    outcome (it never launched, crashed, or could not reach the loopback
    server); every other failure (TLS alerts, empty responses, navigation
    timeouts) is a TLS-flow outcome judged jointly with the server-side
    handshake witness.
    """
    if not error:
        return "unrelated"
    lowered = error.lower()
    for fragment in UNRELATED_CLIENT_CERT_ERRORS:
        if fragment in lowered:
            return "unrelated"
    return "tls_flow"


def is_navigation_timeout(error: str | None) -> bool:
    """True when ``error`` is a Playwright navigation timeout (the flow hung)."""
    if not error:
        return False
    lowered = error.lower()
    return "timeout" in lowered and "exceeded" in lowered


def make_client_cert_visit(url: str, timeout_ms: int = 20000) -> Callable[..., dict[str, Any]]:
    """Attempt a client-cert handshake; the PIN boundary usually fails it.

    Success (page served) means the browser presented a token credential
    (only possible with a login-free provider); failure with enumeration
    traffic still observed documents the interactive-PIN boundary. Either
    way the flow returns facts; it never raises for a TLS outcome.
    """

    def visit(page, context) -> dict[str, Any]:  # noqa: ANN001 - playwright types
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:  # noqa: BLE001 - TLS failure is the expected twin
            error = f"{type(exc).__name__}: {exc}".split("\n")[0][:160]
            return {
                "flow": "client_cert_visit",
                "loaded": False,
                "error": error,
                "error_kind": classify_client_cert_error(error),
            }
        return {
            "flow": "client_cert_visit",
            "loaded": True,
            "http_status": response.status if response is not None else None,
        }

    return visit
