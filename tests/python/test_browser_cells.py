# SPDX-License-Identifier: GPL-3.0-or-later
"""G33 browser application cells: real Firefox/Chromium PKCS#11 traffic.

Installed-gate suite (proposed RUN entry, self-skipping): each test drives
a fresh browser profile against a controlled SoftHSM provider and asserts
the observed attributions end to end beside independent TLS-layer ground
truth. On hosts without the gate prerequisites (P11SCOPE_BIN, passwordless
sudo, Playwright browsers, SoftHSM tooling) every test skips naming what
is missing; hosted CI therefore stays quiet and T11 runs the positives on
a qualified installed host with P11SCOPE_BROWSER_STRICT=1, which turns
prerequisite skips into failures. Single-browser hosts run their subset.

Harness: tests/fixtures/browser/ (cells, flows, oracle, servers, profiles).
"""

import functools
import json
import os
import shutil
import socket
import ssl
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "browser"))

import cells
import flows
import oracle
import softhsm
import tls_server

#: Chromium stabilizers: background fetches must not perturb the token
#: traffic shape (their timing races the observation window); the
#: calibrated shape is x5 enumeration without private-token use.
CHROMIUM_STABLE_ARGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--no-service-autorun",
)

#: Firefox equivalent: background activity stabilized out during
#: calibration so the floored shape is flow-caused (unstabilized runs see
#: ~2x the FindObjects traffic).
FIREFOX_STABLE_PREFS = {
    "app.update.disabledForTesting": True,
    "app.normandy.enabled": False,
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.enabled": False,
    "extensions.update.enabled": False,
    "network.prefetch-next": False,
}

ATTACH_DURATION = 45
RUN_DURATION = 90

#: Observation gap causes each cell kind provably tolerates (P2-3).
#: Floors are lower-bound robust (gaps can only hide calls, never invent
#: them), so floor cells additionally tolerate in-flight entries at
#: shutdown. Absence cells tolerate only discovery/window timing gaps for
#: the already-attached module: in-flight entries, detach gaps, attach
#: failures, event loss, and kernel halts would each hide exactly the
#: forbidden calls, so none is allowed.
_GAPS_ATTACHED_FLOOR = frozenset({
    "loader_discovery", "unprotected_live_windows", "in_flight_at_end",
})
_GAPS_ATTACHED_ABSENT = frozenset({
    "loader_discovery", "unprotected_live_windows",
})
#: Never-mapped cells: the structural discovery/slots/skipped shape (no
#: module, no slots, discovery subject skipped). Detach history would hide
#: behind the same cause, so the skipped records must all be structural
#: (checked separately); run-mode adds spawn-window caveats.
_GAPS_NEVER_MAPPED = frozenset({"discovery", "slots", "skipped"})
_GAPS_NEVER_MAPPED_RUN = _GAPS_NEVER_MAPPED | frozenset({
    "unprotected_live_windows", "pause_partial", "loader_discovery",
})

#: Verdict details each cell kind earned: attached cells read
#: attribution_only when observation is exact, concrete_gap behind loader
#: or window timing; never-mapped cells always carry the structural
#: discovery gap, so concrete_gap only.
_VERDICTS_ATTACHED = ("attribution_only", "concrete_gap")
_VERDICTS_NEVER_MAPPED = ("concrete_gap",)

#: Private-token operations no PINBOUND flow may ever reach: login plus
#: signing setup and signing (init and one-shot share the boundary).
_PINBOUND_ABSENT = ("C_Login", "C_SignInit", "C_Sign")


def _stall_outcomes(server) -> str:
    """One-line handshake summary for PINBOUND failure messages."""
    cert_reqs = getattr(server, "cert_requests_sent", 0)
    return (
        f"connections={server.connections} requests={server.requests_served} "
        f"certs={server.client_certs_presented} ok={server.handshakes_ok} "
        f"spoke={server.spoke_tls} hello={server.client_hello_complete} "
        f"certreq={cert_reqs} "
        f"empty={server.empty_certs} stalls={server.selection_stalls} "
        f"alerts={server.client_cert_alerts} abandoned={server.abandoned} "
        f"failures={server.handshake_failures} errors={server.handshake_errors}")


#: Installed mode: set P11SCOPE_BROWSER_STRICT=1 on a qualified installed
#: host (T11) to turn prerequisite skips into failures, requiring the
#: expected cells to execute; an empty selection fails outright. Unset
#: keeps the self-skipping hosted default.
STRICT = os.environ.get("P11SCOPE_BROWSER_STRICT") == "1"


def gate(browser):
    """Skip unless every gate prerequisite for the ``browser`` cell holds.

    In strict installed mode a missing prerequisite fails instead of
    skipping, so the expected cells must execute.
    """

    def decorator(test):
        @functools.wraps(test)
        def wrapper(self):
            try:
                cells.preflight(browser)
            except (cells.CellError, RuntimeError) as exc:
                if STRICT:
                    raise AssertionError(
                        f"strict installed mode requires this cell: {exc}") from exc
                self.skipTest(f"browser gate prerequisite missing: {exc}")
            return test(self)

        return wrapper

    return decorator


def needs_chromium(test):
    """Skip unless Playwright and its Chromium build are present (no sudo)."""

    @functools.wraps(test)
    def wrapper(self):
        try:
            import playwright  # noqa: F401
            from profiles import chromium_binary
            chromium_binary()
        except (ImportError, RuntimeError) as exc:
            if STRICT:
                raise AssertionError(
                    f"strict installed mode requires this twin: {exc}") from exc
            self.skipTest(f"chromium witness prerequisite missing: {exc}")
        return test(self)

    return wrapper


class BrowserCells(unittest.TestCase):
    maxDiff = 4096

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="g33-browser-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    def seed(self, label="G33-Browser"):
        """Fresh SoftHSM store with a client credential; returns (store, cred)."""
        store = softhsm.SoftHSMStore(self.work / "softhsm")
        cred = softhsm.generate_client_credential(self.work / "cred")
        store.seed_client_token(label, cred)
        return store, cred

    def check_report(self, result, store, floors=None, zero=False, attached=None,
                     allowed_gaps=(), allowed_verdicts=_VERDICTS_ATTACHED, absent=None,
                     s1=None):
        """Common oracle: schema, identity, counts, loss, gaps, earned verdict.

        ``attached`` pins the probe state: True (hooked the mapped module),
        False (never hooked — the module stayed unmapped), None (either).
        ``allowed_gaps`` names the observation gap causes that provably do
        not affect this cell's asserted property (per-cell table above);
        every other cause fails. ``allowed_verdicts`` pins the verdict
        details the cell earned. ``absent`` names functions that must never
        have been called (returns, open entries, and unattributed rows).
        ``s1`` opts into the v0.5.0 S1 proof over the report's S1
        sections (no Joint content, no mechanism use, no logins,
        balanced sessions): a dict with ``sessions_opened_min`` for
        cells whose floored calls need a session, or
        ``sessions_zero`` for never-mapped cells. None (the twin
        default) skips the S1 checks.
        """
        report = oracle.load_report(result.report_path)
        module_sha = oracle.sha256_of(store.lib)
        counts = oracle.module_counts(report, module_sha)
        opened = oracle.module_open_entries(report, module_sha)
        failures = []
        failures += oracle.check_no_event_loss(report)
        failures += oracle.check_capture_intact(report)
        failures += oracle.check_observation_gaps(report, allowed_gaps)
        failures += oracle.check_skipped_structural(report)
        if s1 is not None:
            failures += oracle.check_no_joint_content(report)
            failures += oracle.check_s1_mechanisms_absent(report)
            failures += oracle.check_s1_logins_absent(report)
            failures += oracle.check_s1_sessions(
                report, opened_min=s1.get("sessions_opened_min", 0),
                zero=s1.get("sessions_zero", False))
        if zero:
            failures += oracle.check_zero_counts(counts, opened)
        else:
            failures += oracle.check_min_counts(counts, floors or {})
        if attached is True:
            failures += oracle.check_attached(report)
        elif attached is False:
            hooked = report["evidence"].get("attached_probes", 0) or 0
            if hooked != 0:
                failures.append(f"attached_probes={hooked}, want 0 (module never hooked)")
        if absent:
            failures += oracle.check_absent(counts, absent, opened)
        failures += oracle.check_verdict(report, allowed_verdicts)
        if failures:
            detail = {
                "failures": failures,
                "counts": counts,
                "open_entries": opened,
                "evidence": {
                    key: report["evidence"].get(key)
                    for key in ("completeness", "verdict_detail", "event_loss",
                                "attached_probes", "active_slots", "gap_classes")
                },
                "flow": result.flow,
                "observer_stderr": result.observer_stderr_tail,
            }
            self.fail(f"{result.name} failed:\n{json.dumps(detail, indent=1)[:3000]}")
        return report

    def assert_pinbound_stall(self, label, facts, server):
        """The CERT_REQUIRED flow stalled at the PIN boundary (P2-2).

        Requires affirmative selection progress on the stalled
        connection: a complete ClientHello plus a token-selection
        witness — an empty certificate or a CertificateRequest-backed
        stall — with no successful handshake, no presented cert, no
        served request, no protocol failure, and a TLS-flow (not crashed
        or never-launched) browser outcome. A stall counts only when the
        same connection observed the server's outbound CertificateRequest
        (a complete hello alone can yield HelloRetryRequest waiting for
        ClientHello2, which is pre-selection). Client cert alerts and
        abandoned transports are tolerated but never sufficient: alerts
        are ambiguous (selection refusal vs server-cert rejection) and
        abandons carry no selection information. A navigation timeout
        alone proves nothing about selection and is never a witness.
        """
        outcomes = _stall_outcomes(server)
        self.assertGreaterEqual(server.connections, 1, f"{label}: browser never connected")
        self.assertEqual(server.requests_served, 0,
                         f"{label}: request served without a cert? [{outcomes}]")
        self.assertEqual(server.client_certs_presented, 0,
                         f"{label}: client cert presented?! [{outcomes}]")
        self.assertEqual(server.handshakes_ok, 0,
                         f"{label}: handshake succeeded?! [{outcomes}]")
        self.assertEqual(server.handshake_failures, 0,
                         f"{label}: unrelated TLS failure {server.handshake_errors} [{outcomes}]")
        self.assertGreaterEqual(
            server.client_hello_complete, 1,
            f"{label}: no complete ClientHello (selection never began) [{outcomes}]")
        if server.selection_stalls:
            self.assertGreaterEqual(
                getattr(server, "cert_requests_sent", 0), 1,
                f"{label}: stall without outbound CertificateRequest "
                f"(selection never began) [{outcomes}]")
        witness = server.empty_certs + server.selection_stalls
        self.assertGreaterEqual(
            witness, 1,
            f"{label}: no token-selection witness "
            f"(need empty-cert or CertificateRequest-backed stall) [{outcomes}]")
        self.assertNotIn("flow_error", facts,
                         f"{label}: flow setup failed: {facts.get('flow_error')}")
        self.assertFalse(facts.get("loaded", True),
                         f"{label}: client-cert flow loaded?! [{outcomes}]")
        kind = flows.classify_client_cert_error(facts.get("error"))
        self.assertNotEqual(kind, "unrelated",
                            f"{label}: browser never produced a TLS outcome: "
                            f"{facts.get('error')!r} [{outcomes}]")

    @gate("firefox")
    def test_ff_startup_observes_nss_store_traffic(self):
        """FF-STARTUP: Firefox HTTPS visit; NSS store enumeration observed."""
        store, _cred = self.seed()
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key) as flow:
            result = cells.attach_drive(
                "FF-STARTUP", "firefox", self.work / "cell", flow.url,
                flows.make_visit(flow.url), store.lib,
                register_module=store.lib, browser_env=store.env,
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=5,
                wait_for_map=(store.lib.name,),
                extra_prefs=FIREFOX_STABLE_PREFS,
                expect_attached=True)
            self.assertGreaterEqual(flow.requests_served, 1, "flow server saw no request")
        self.assertEqual(result.flow.get("profiler_exit"), 0)
        self.assertEqual(result.flow.get("http_status"), 200)
        self.assertIn("g33-flow-ok", result.flow.get("body_excerpt", ""))
        self.assertTrue(result.flow.get("profile_module_registered"),
                        "profile lost its registration?!")
        self.assertTrue(result.flow.get("target_alive"), "browser target disappeared?!")
        self.assertTrue(result.flow.get("target_identity"), "browser target PID reused?!")
        self.assertTrue(result.flow.get("mapped_at_end"), "module unmapped?!")
        self.check_report(result, store, oracle.FF_STARTUP_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_FLOOR,
                          s1={"sessions_opened_min": 1})

    @gate("chromium")
    def test_cr_plain_validates_without_private_token_use(self):
        """CR-PLAIN: Chromium validates with the provider mapped; no private use."""
        store, _cred = self.seed()
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key) as flow:
            result = cells.attach_drive(
                "CR-PLAIN", "chromium", self.work / "cell", flow.url,
                flows.make_visit(flow.url), store.lib,
                register_module=store.lib, browser_env=store.env,
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=5,
                wait_for_map=(store.lib.name,),
                extra_browser_args=CHROMIUM_STABLE_ARGS,
                expect_attached=True)
            self.assertGreaterEqual(flow.requests_served, 1, "flow server saw no request")
        self.assertEqual(result.flow.get("profiler_exit"), 0)
        self.assertEqual(result.flow.get("http_status"), 200)
        self.assertTrue(result.flow.get("nss_db_dir"), "no NSS registration witness?!")
        self.assertTrue(result.flow.get("target_alive"), "browser target disappeared?!")
        self.assertTrue(result.flow.get("target_identity"), "browser target PID reused?!")
        self.assertTrue(result.flow.get("mapped_at_end"), "module unmapped?!")
        self.check_report(result, store, oracle.CR_ENUMERATION_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_ABSENT, absent=_PINBOUND_ABSENT,
                          s1={"sessions_opened_min": 1})

    @gate("firefox")
    def test_ff_nomod_observes_nothing(self):
        """FF-NOMOD: unregistered provider; the browser maps nothing, zero rows."""
        store, _cred = self.seed()
        with tls_server.FlowServer(use_tls=False) as flow:
            result = cells.run_direct(
                "FF-NOMOD", "firefox", self.work / "cell", flow.url,
                observe_module=store.lib, register_module=None,
                browser_env=store.env, duration_seconds=RUN_DURATION)
            self.assertGreaterEqual(flow.requests_served, 1, "flow server saw no request")
        self.assertEqual(result.flow.get("observer_exit"), 0)
        self.assertGreater(result.screenshot_bytes, 0, "no screenshot bytes")
        self.check_report(result, store, zero=True, attached=False,
                          allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                          allowed_verdicts=_VERDICTS_NEVER_MAPPED,
                          s1={"sessions_zero": True})

    @gate("firefox")
    def test_ff_pinbound_never_logs_in_or_signs(self):
        """FF-PINBOUND: CERT_REQUIRED; selection races, login never happens."""
        store, cred = self.seed()
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cred.cert_pem) as flow:
            result = cells.attach_drive(
                "FF-PINBOUND", "firefox", self.work / "cell", flow.url,
                flows.make_client_cert_visit(flow.url), store.lib,
                register_module=store.lib, browser_env=store.env,
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=5,
                wait_for_map=(store.lib.name,),
                extra_prefs=FIREFOX_STABLE_PREFS,
                expect_attached=True)
            self.assert_pinbound_stall("FF-PINBOUND", result.flow, flow)
        self.assertEqual(result.flow.get("profiler_exit"), 0)
        self.assertTrue(result.flow.get("profile_module_registered"),
                        "profile lost its registration?!")
        self.assertTrue(result.flow.get("target_alive"), "browser target disappeared?!")
        self.assertTrue(result.flow.get("target_identity"), "browser target PID reused?!")
        self.assertTrue(result.flow.get("mapped_at_end"), "module unmapped?!")
        # Selection enumeration races the prompt failure (x0 or x16 across
        # runs), so no count is pinned; login and signing never happen.
        self.check_report(result, store, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_ABSENT,
                          absent=_PINBOUND_ABSENT, s1={})

    @gate("chromium")
    def test_cr_pinbound_stalls_before_login_or_signing(self):
        """CR-PINBOUND: CERT_REQUIRED; selection enumerates, login never happens."""
        store, cred = self.seed()
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cred.cert_pem) as flow:
            result = cells.attach_drive(
                "CR-PINBOUND", "chromium", self.work / "cell", flow.url,
                flows.make_client_cert_visit(flow.url), store.lib,
                register_module=store.lib, browser_env=store.env,
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=5,
                wait_for_map=(store.lib.name,),
                extra_browser_args=CHROMIUM_STABLE_ARGS,
                auto_select_cert=False,
                expect_attached=True)
            self.assert_pinbound_stall("CR-PINBOUND", result.flow, flow)
        self.assertEqual(result.flow.get("profiler_exit"), 0)
        self.assertTrue(result.flow.get("nss_db_dir"), "no NSS registration witness?!")
        self.assertTrue(result.flow.get("target_alive"), "browser target disappeared?!")
        self.assertTrue(result.flow.get("target_identity"), "browser target PID reused?!")
        self.assertTrue(result.flow.get("mapped_at_end"), "module unmapped?!")
        # Selection enumerates stably (x5 on every run) but the
        # interactive-PIN boundary holds: login and signing never happen.
        self.check_report(result, store, oracle.CR_ENUMERATION_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_ABSENT, absent=_PINBOUND_ABSENT,
                          s1={"sessions_opened_min": 1})

    # -- Unprivileged counterexample twins (P2-2/P2-3; run everywhere) --
    #
    # Each twin drives a real seam (the common oracle, a named predicate,
    # or the decorated FF-PINBOUND test with a synthetic server) with a
    # hostile input the oracle must reject. They use hand-built v3
    # documents, never the release checker's fixtures.

    @staticmethod
    def _twin_row(names, calls, sha, in_flight=0):
        """One functions[] row attached to the fake module ``sha``."""
        return {
            "names": list(names),
            "calls": calls,
            "in_flight": in_flight,
            "target": {"object": {"dev": 1, "ino": 2, "sha256": sha},
                       "file_offset": 0},
        }

    @staticmethod
    def _twin_evidence(**overrides):
        """Healthy evidence block; ``overrides`` plant the hostile input."""
        evidence = {
            "event_loss": 0,
            "attached_probes": 2,
            "verdict_detail": "attribution_only",
            "gap_classes": {
                "observation": {"status": "exact", "causes": []},
            },
            "kernel_control": {
                "capture_halted": False,
                "owner_poison": [],
                "owner_admission_failures": 0,
                "identity_unavailable": 0,
                "root_affiliation_failures": [],
            },
            "skipped": [],
            "attach_failures": [],
            "in_flight_at_end": 0,
        }
        evidence.update(overrides)
        return evidence

    def _twin_result(self, name, rows, evidence):
        """Write a twin v3 document and wrap it in a CellResult."""
        doc = {"schema": oracle.SCHEMA, "functions": rows, "evidence": evidence}
        path = self.work / f"{name}-report.json"
        path.write_text(json.dumps(doc))
        return cells.CellResult(name, path)

    @needs_chromium
    def test_chromium_uses_fresh_home_nss_db(self):
        """P2-1 twin: the launched browser's NSS DB must live in the fresh HOME."""
        from playwright.sync_api import sync_playwright
        from profiles import playwright_cache
        real_home = os.environ.get("HOME")
        real_xdg_cache = os.environ.get("XDG_CACHE_HOME")
        real_browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        pinned_cache = playwright_cache()
        caller_home = self.work / "caller-home"
        caller_home.mkdir()
        cell_work = self.work / "cell"
        try:
            os.environ["HOME"] = str(caller_home)
            # Hermetic cache environment: the browser-cache location must
            # not ride ambient variables past the HOME change. Pin the
            # pre-change cache explicitly so launch cannot fail on cache
            # resolution before NSS isolation is tested.
            os.environ.pop("XDG_CACHE_HOME", None)
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(pinned_cache)
            with sync_playwright() as pw:
                context, _match, fresh_home = cells.launch_browser_context(
                    pw, "chromium", cell_work,
                    register_module=Path("/probe-test/libsoft-test.so"))
                try:
                    used = cells.wait_for_nss_db(fresh_home, timeout_seconds=15.0)
                finally:
                    context.close()
        finally:
            if real_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = real_home
            if real_xdg_cache is None:
                os.environ.pop("XDG_CACHE_HOME", None)
            else:
                os.environ["XDG_CACHE_HOME"] = real_xdg_cache
            if real_browsers_path is None:
                os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
            else:
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = real_browsers_path
        self.assertIsNotNone(used, "no NSS database appeared under the fresh HOME")
        assert used is not None
        pkcs11 = used / "pkcs11.txt"
        self.assertTrue(pkcs11.exists(), f"our pkcs11.txt is not in the used DB dir {used}")
        self.assertIn("/probe-test/libsoft-test.so", pkcs11.read_text())
        strays = [p for p in (caller_home / ".pki", caller_home / ".local") if p.exists()]
        self.assertEqual(strays, [], f"browser NSS state leaked into caller HOME: {strays}")

    def _run_readiness_probe(self, marker_delay):
        """Run attach_drive against a scripted profiler; return (started, error).

        The fake profiler prints its readiness marker after
        ``marker_delay`` seconds; the grace period is 2s, so a long
        delay means the marker never arrives. Target liveness is valid
        synthetic liveness, so readiness is the only possible failure
        source. Returns the flow's ``started`` dict and the CellError
        raised (None when the cell ran). Uses a fake Playwright module
        and a fake profiler process: stdlib only.
        """
        import subprocess as stdlib_subprocess

        started: dict = {}

        class FakePipe:
            def __init__(self, script):
                self._script = list(script)
                self._start = time.monotonic()
                self._closed = False
                self.text = "".join(line for _, line in script)

            def readline(self):
                while self._script and not self._closed:
                    delay, line = self._script[0]
                    if time.monotonic() - self._start >= delay:
                        return self._script.pop(0)[1]
                    time.sleep(0.02)
                return ""

            def close(self):
                self._closed = True

        class FakePopen:
            def __init__(self, argv, **kwargs):
                self.argv = argv
                self._finished = False
                self.returncode = None
                self.stderr = FakePipe([
                    (0.1, "p11scope: loader readiness: 1 active hook(s)\n"),
                    (marker_delay,
                     "p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C\n"),
                ])
                self.stdout = FakePipe([])

            def poll(self):
                return 0 if self._finished else None

            def _finish(self):
                self._finished = True
                self.stderr.close()
                self.stdout.close()
                self.returncode = 0
                return 0

            def wait(self, timeout=None):
                if self._finished:
                    return 0
                raise stdlib_subprocess.TimeoutExpired(self.argv, timeout)

            def communicate(self, timeout=None):
                self._finish()
                return ("", self.stderr.text)

            def kill(self):
                self._finish()

        class FakePage:
            pass

        class FakeContext:
            def __init__(self):
                self.pages = [FakePage()]

            def new_page(self):
                page = FakePage()
                self.pages.append(page)
                return page

            def close(self):
                pass

        class FakeBrowserType:
            def launch_persistent_context(self, *args, **kwargs):
                return FakeContext()

        class FakePlaywright:
            def __init__(self):
                self.firefox = FakeBrowserType()
                self.chromium = FakeBrowserType()

        class FakePWContext:
            def __enter__(self):
                return FakePlaywright()

            def __exit__(self, *args):
                return False

        def flow(page, context):
            started["ran"] = True
            return {}

        fake_sync = SimpleNamespace(sync_playwright=lambda: FakePWContext())
        with patch.dict(sys.modules, {"playwright": SimpleNamespace(),
                                      "playwright.sync_api": fake_sync}), \
                patch("subprocess.Popen", FakePopen), \
                patch.object(cells, "main_browser_pid", return_value=os.getpid()), \
                patch.object(cells, "_target_liveness", return_value=(True, True)), \
                patch.object(cells, "p11scope_bin", return_value=Path("/fake/p11scope")):
            try:
                cells.attach_drive(
                    "TWIN-READY", "firefox", self.work / "cell", "https://127.0.0.1:1/",
                    flow, Path("definitely-not-mapped-xyz.so"),
                    duration_seconds=5, attach_grace_seconds=2)
            except cells.CellError as exc:
                return started, exc
            return started, None

    def test_navigation_waits_for_capture_readiness(self):
        """P2-4 twin: navigation must not start before capture readiness.

        The scripted profiler never prints its readiness marker inside
        the grace period; the flow must never run and the cell must fail
        with a readiness-specific error.
        """
        started, error = self._run_readiness_probe(marker_delay=30.0)
        self.assertIsNotNone(error, "cell passed without capture readiness")
        assert error is not None
        self.assertIn("never became ready", str(error),
                      f"cell failed for the wrong reason: {error}")
        self.assertFalse(started.get("ran", False),
                         "navigation started before capture readiness")

    def test_capture_readiness_marker_arrives_runs_flow(self):
        """Control: when the marker arrives promptly, navigation runs."""
        started, error = self._run_readiness_probe(marker_delay=0.1)
        self.assertIsNone(error, f"marker arrived yet the cell failed: {error}")
        self.assertTrue(started.get("ran", False),
                        "navigation never ran after capture readiness")

    def test_capture_ready_parsing(self):
        """Unit: the readiness marker parses to its attached-probe count."""
        self.assertEqual(
            cells._parse_capture_ready(
                "p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C"), 136)
        self.assertEqual(
            cells._parse_capture_ready(
                "p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C"), 0)
        self.assertIsNone(cells._parse_capture_ready(
            "p11scope: loader readiness: 1 active hook(s)"))
        self.assertIsNone(cells._parse_capture_ready("unrelated line"))

    def test_oracle_builder_healthy_accepted(self):
        """Guard: the twin builder's healthy doc passes the common oracle."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        result = self._twin_result("TWIN-HEALTHY", rows, self._twin_evidence())
        with patch.object(oracle, "sha256_of", return_value=sha):
            self.check_report(result, store, {"C_FindObjects": 1}, attached=True)

    def test_oracle_rejects_halted_capture(self):
        """P2-3 twin: a halted capture fails even when floors are met."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        evidence = self._twin_evidence(
            verdict_detail="concrete_gap",
            gap_classes={"observation": {"status": "lossy", "causes": ["kernel_control"]}},
            kernel_control={"capture_halted": True, "owner_poison": ["refund_failed"],
                            "owner_admission_failures": 0, "identity_unavailable": 0,
                            "root_affiliation_failures": []},
        )
        result = self._twin_result("TWIN-HALTED", rows, evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, {"C_FindObjects": 1}, attached=True)

    def test_oracle_rejects_inflight_absence_gap(self):
        """P2-3 twin: entered-but-unreturned C_Login/C_Sign are not absent."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_Login"], 0, sha, in_flight=1),
                self._twin_row(["C_Sign"], 0, sha, in_flight=1)]
        evidence = self._twin_evidence(
            verdict_detail="concrete_gap",
            gap_classes={"observation": {"status": "lossy", "causes": ["in_flight_at_end"]}},
            in_flight_at_end=2,
        )
        result = self._twin_result("TWIN-INFLIGHT", rows, evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, attached=True)

    def test_zero_counts_reject_inflight_entries(self):
        """P2-3 twin: returns-only zero counting must not accept open entries.

        Deliberately inconsistent document (rows show in-flight entries the
        evidence block omits): the row-level count must reject regardless.
        """
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_Login"], 0, sha, in_flight=1),
                self._twin_row(["C_Sign"], 0, sha, in_flight=1)]
        result = self._twin_result("TWIN-OPEN-ROWS", rows, self._twin_evidence())
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, zero=True, attached=True)

    def test_oracle_rejects_attach_failures(self):
        """P2-3 twin: failed attachments fail even when some probes hooked."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        evidence = self._twin_evidence(
            verdict_detail="concrete_gap",
            gap_classes={"observation": {"status": "lossy", "causes": ["attach_failures"]}},
            attach_failures=[{"slot": 7, "reason": "uprobe_link_failed"}],
        )
        result = self._twin_result("TWIN-ATTACH", rows, evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, {"C_FindObjects": 1}, attached=True)

    def test_oracle_rejects_unattributed_activity(self):
        """P2-3 twin: [unknown]-row activity fails named-absence checks."""
        counts = {"C_FindObjects": 5, "unknown": 3}
        self.assertNotEqual(oracle.check_absent(counts, ("C_Login",)), [])

    def _pinbound_rig(self, server_stats, facts):
        """Run the real FF-PINBOUND test against synthetic server/flow facts."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"), env={})
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        result = self._twin_result("FF-PINBOUND", rows, self._twin_evidence())
        doc = json.loads(result.report_path.read_text())
        doc.update({"mechanisms": [], "sessions": healthy_sessions(),
                    "logins": {}})
        result.report_path.write_text(json.dumps(doc))
        result.flow.update({
            "profiler_exit": 0, "mapped_at_end": True,
            "target_alive": True, "target_identity": True,
            "profile_module_registered": True, **facts,
        })
        server = SimpleNamespace(url="https://127.0.0.1:1/", **server_stats)
        entered = MagicMock()
        entered.__enter__.return_value = server
        case = BrowserCells("test_ff_pinbound_never_logs_in_or_signs")
        case.work = self.work
        case.seed = lambda *a: (store, SimpleNamespace(cert_pem=Path("/not-opened/client.pem")))
        with patch.object(cells, "preflight", return_value=None), \
                patch.object(cells, "attach_drive", return_value=result), \
                patch.object(tls_server, "make_server_credential",
                             return_value=(Path("/not-opened/key"), Path("/not-opened/cert"))), \
                patch.object(tls_server, "FlowServer", return_value=entered), \
                patch.object(oracle, "sha256_of", return_value=sha):
            case.test_ff_pinbound_never_logs_in_or_signs()

    @staticmethod
    def _pinbound_stats(**overrides):
        """Synthetic CERT_REQUIRED server stats; hostile (witness-free) by default.

        The hostile shape spoke TLS and vanished pre-selection with no
        recorded failure, so only the witness rule can reject it.
        """
        stats = {
            "connections": 1, "requests_served": 0, "client_certs_presented": 0,
            "handshakes_ok": 0, "spoke_tls": 1, "client_hello_complete": 0,
            "cert_requests_sent": 0, "empty_certs": 0,
            "selection_stalls": 0, "client_cert_alerts": 0, "abandoned": 1,
            "handshake_failures": 0, "handshake_errors": [],
        }
        stats.update(overrides)
        return stats

    @staticmethod
    def _pinbound_facts():
        """Synthetic failed client-cert visit (TLS failure before selection)."""
        return {"flow": "client_cert_visit", "loaded": False,
                "error": "SSLError: TLS protocol mismatch before certificate selection"}

    @staticmethod
    def _pinbound_timeout_facts():
        """Synthetic hung client-cert visit (navigation timeout, nothing selected)."""
        return {"flow": "client_cert_visit", "loaded": False,
                "error": "TimeoutError: Page.goto: Timeout 20000ms exceeded."}

    def test_pinbound_rejects_preselection_failure(self):
        """P2-2 twin: a pre-selection protocol failure must fail the cell."""
        with self.assertRaises(AssertionError):
            self._pinbound_rig(self._pinbound_stats(), self._pinbound_facts())

    def test_pinbound_rejects_partial_client_hello_stall(self):
        """P2-2 twin: a stall without a complete ClientHello must fail the cell.

        A bare TLS first byte plus a timeout is not a selection stall:
        nothing proves ClientHello completed or the CertificateRequest
        flight went out (Sol residual shape 1).
        """
        stats = self._pinbound_stats(selection_stalls=1, abandoned=0,
                                     client_hello_complete=0)
        with self.assertRaises(AssertionError):
            self._pinbound_rig(stats, self._pinbound_timeout_facts())

    def test_pinbound_rejects_abandoned_with_navigation_timeout(self):
        """P2-2 twin: abandonment plus a hung navigation must fail the cell.

        Every connection vanished pre-selection; the navigation timeout
        is context, never a selection witness (Sol residual shape 2).
        """
        with self.assertRaises(AssertionError):
            self._pinbound_rig(self._pinbound_stats(), self._pinbound_timeout_facts())

    def test_pinbound_rejects_hrr_stall_without_cert_request(self):
        """P2-2 twin: a complete hello plus timeout without CertificateRequest fails.

        A valid TLS 1.3 hello can make the server emit HelloRetryRequest
        and wait for ClientHello2 (RFC 8446 Fig.2) without ever sending
        CertificateRequest; hello=1/stalls=1 alone must not pass without
        affirmative outbound progress on the same connection.
        """
        stats = self._pinbound_stats(selection_stalls=1, abandoned=0,
                                     client_hello_complete=1, cert_requests_sent=0)
        with self.assertRaises(AssertionError):
            self._pinbound_rig(stats, self._pinbound_timeout_facts())

    def test_pinbound_rig_stall_accepted(self):
        """Guard: a hello- and CertificateRequest-backed stall still passes."""
        self._pinbound_rig(
            self._pinbound_stats(selection_stalls=1, abandoned=0,
                                 client_hello_complete=1, cert_requests_sent=1),
            self._pinbound_timeout_facts())

    def test_pinbound_rig_healthy_accepted(self):
        """Guard: the rig passes with a boundary witness (no over-reject)."""
        self._pinbound_rig(
            self._pinbound_stats(empty_certs=1, abandoned=0, client_hello_complete=1),
            self._pinbound_facts())

    def test_handshake_classifier_buckets(self):
        """Unit: every wrap failure lands in its documented outcome bucket."""
        cases = {
            "empty_cert": [
                ssl.SSLError("[SSL: PEER_DID_NOT_RETURN_A_CERTIFICATE] peer did not return a certificate"),
            ],
            "cert_alert": [
                ssl.SSLError("[SSL: SSLV3_ALERT_CERTIFICATE_UNKNOWN] ssl/tls alert certificate unknown"),
            ],
            "failure": [
                ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong version number"),
                ssl.SSLError("[SSL: TLSV1_ALERT_HANDSHAKE_FAILURE] tlsv1 alert handshake failure"),
                ValueError("peer spoke non-TLS bytes"),
            ],
            "abandoned": [
                ssl.SSLEOFError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol"),
                ConnectionResetError("peer reset"),
            ],
        }
        for want, errors in cases.items():
            for exc in errors:
                self.assertEqual(tls_server.classify_handshake_error(exc), want, repr(exc))
        # A timeout is a selection stall only with affirmative outbound
        # CertificateRequest progress on the same connection; without it
        # (for example HRR waiting for ClientHello2) it is abandonment.
        timeout = TimeoutError("The handshake operation timed out")
        self.assertEqual(
            tls_server.classify_handshake_error(timeout, cert_request_seen=True),
            "stall", repr(timeout))
        self.assertEqual(
            tls_server.classify_handshake_error(timeout, cert_request_seen=False),
            "abandoned", repr(timeout))
        self.assertEqual(
            tls_server.classify_handshake_error(timeout), "abandoned",
            "timeouts fail closed without CertificateRequest proof")

    def test_client_cert_error_kinds(self):
        """Unit: TLS-flow failures classify apart from unrelated ones."""
        tls_flow = [
            "Error: Page.goto: net::ERR_BAD_SSL_CLIENT_AUTH_CERT at https://127.0.0.1:1/",
            "Error: Page.goto: net::ERR_SOCKET_NOT_CONNECTED at https://127.0.0.1:1/",
            "Error: Page.goto: SSL_ERROR_UNKNOWN",
            "TimeoutError: Page.goto: Timeout 20000ms exceeded.",
            "SSLError: TLS protocol mismatch before certificate selection",
        ]
        for error in tls_flow:
            self.assertEqual(flows.classify_client_cert_error(error), "tls_flow", error)
        unrelated = [
            "Error: Executable doesn't exist at /none",
            "Error: Target crashed",
            "Error: Browser has been closed",
            "Error: Page.goto: net::ERR_CONNECTION_REFUSED at https://127.0.0.1:1/",
            "Error: Page.goto: net::ERR_ADDRESS_UNREACHABLE at https://127.0.0.1:1/",
            None,
            "",
        ]
        for error in unrelated:
            self.assertEqual(flows.classify_client_cert_error(error), "unrelated", repr(error))
        self.assertTrue(flows.is_navigation_timeout("TimeoutError: Page.goto: Timeout 20000ms exceeded."))
        self.assertFalse(flows.is_navigation_timeout("Error: Page.goto: SSL_ERROR_UNKNOWN"))
        self.assertFalse(flows.is_navigation_timeout(None))

    def test_flow_server_records_handshake_outcomes(self):
        """Unit: the server records outcomes independently of HTTP requests."""
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")

        key, cert = tls_server.make_server_credential(self.work / "srv")
        cred = softhsm.generate_client_credential(self.work / "cred")

        def tls_client(port, cert_pair=None):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if cert_pair is not None:
                context.load_cert_chain(str(cert_pair[0]), str(cert_pair[1]))
            raw = socket.create_connection(("127.0.0.1", port))
            return context.wrap_socket(raw, server_hostname="127.0.0.1")

        def await_outcome(flow):
            deadline = time.monotonic() + 10
            while (flow.handshakes_ok + flow.empty_certs + flow.selection_stalls
                   + flow.client_cert_alerts + flow.abandoned
                   + flow.handshake_failures == 0 and time.monotonic() < deadline):
                time.sleep(0.05)

        def read_all(peer):
            chunks = []
            while True:
                try:
                    data = peer.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)

        # CERT_REQUIRED with no client cert: selection reached, nothing offered.
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            with tls_client(flow.port) as peer:
                # The server aborts the cert-less handshake; the recorded
                # outcome below is the assert, not the client-side error.
                with self.assertRaises(Exception):
                    peer.recv(1)
            # The client's error precedes the server-side note; await it.
            await_outcome(flow)
            self.assertEqual((flow.connections, flow.spoke_tls, flow.empty_certs), (1, 1, 1))
            self.assertEqual(flow.client_hello_complete, 1)
            self.assertEqual(flow.cert_requests_sent, 1)
            self.assertEqual(flow.requests_served, 0)
            self.assertEqual(flow.client_certs_presented, 0)
            self.assertEqual(flow.handshake_failures, 0)
        # Garbage before any TLS: an unrelated protocol failure.
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            raw = socket.create_connection(("127.0.0.1", flow.port))
            raw.sendall(b"GARBAGE-NOT-TLS")
            raw.close()
            await_outcome(flow)
            self.assertEqual(flow.connections, 1)
            self.assertEqual(flow.handshake_failures, 1)
            self.assertEqual(flow.spoke_tls, 0)
            self.assertEqual(flow.client_hello_complete, 0)
            self.assertEqual(flow.cert_requests_sent, 0)
            self.assertTrue(flow.handshake_errors)
        # Connect and vanish without a byte: abandoned, never a failure.
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            socket.create_connection(("127.0.0.1", flow.port)).close()
            await_outcome(flow)
            self.assertEqual((flow.connections, flow.abandoned, flow.handshake_failures),
                             (1, 1, 0))
            self.assertEqual(flow.client_hello_complete, 0)
            self.assertEqual(flow.cert_requests_sent, 0)
        # Presented client cert: counted at handshake time, request or not.
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cred.cert_pem) as flow:
            with tls_client(flow.port, (cred.cert_pem, cred.key_pem)) as peer:
                peer.sendall(b"GET / HTTP/1.0\r\n\r\n")
                self.assertIn(b"g33-flow-ok", read_all(peer))
            self.assertEqual((flow.handshakes_ok, flow.client_certs_presented,
                              flow.requests_served), (1, 1, 1))
            self.assertEqual(flow.client_hello_complete, 1)
            self.assertEqual(flow.cert_requests_sent, 1)
        # Plain server: ordinary visit, no client cert involved.
        with tls_server.FlowServer(cert=cert, key=key) as flow:
            with tls_client(flow.port) as peer:
                peer.sendall(b"GET / HTTP/1.0\r\n\r\n")
                self.assertIn(b"g33-flow-ok", read_all(peer))
            self.assertEqual((flow.handshakes_ok, flow.client_certs_presented,
                              flow.requests_served), (1, 0, 1))
            self.assertEqual(flow.client_hello_complete, 1)
            self.assertEqual(flow.cert_requests_sent, 0)

    def test_flow_server_partial_client_hello_is_abandoned(self):
        """P2-2 twin: a partial ClientHello plus silence is abandoned, not a stall.

        Sends a TLS record header promising more bytes than arrive, then
        holds the connection open past a short handshake deadline: the
        server must not count a selection stall without a complete
        ClientHello. Stdlib sockets only.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            flow.HANDSHAKE_TIMEOUT = 2.0
            raw = socket.create_connection(("127.0.0.1", flow.port))
            try:
                raw.sendall(b"\x16\x03\x01\x00\x10" + b"\x00" * 4)
                deadline = time.monotonic() + 10
                while (flow.abandoned + flow.selection_stalls
                       + flow.handshake_failures == 0
                       and time.monotonic() < deadline):
                    time.sleep(0.05)
            finally:
                raw.close()
            self.assertEqual(flow.connections, 1)
            self.assertEqual(flow.selection_stalls, 0,
                             "partial ClientHello counted as a selection stall")
            self.assertEqual(flow.abandoned, 1)
            self.assertEqual(flow.client_hello_complete, 0)
            self.assertEqual(flow.cert_requests_sent, 0)
            self.assertEqual(flow.handshake_failures, 0)

    def test_flow_server_complete_client_hello_then_silence_stalls(self):
        """Guard: a CertificateRequest followed by silence still stalls.

        A real ClientHello goes out over a non-blocking socket whose
        handshake is never driven again; the server must see the
        finished first flight, emit CertificateRequest, and count the
        ensuing silence as a selection stall.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            flow.HANDSHAKE_TIMEOUT = 3.0
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection(("127.0.0.1", flow.port))
            raw.setblocking(False)
            peer = context.wrap_socket(raw, server_hostname="127.0.0.1",
                                       do_handshake_on_connect=False)
            try:
                with self.assertRaises((ssl.SSLWantReadError, ssl.SSLWantWriteError)):
                    peer.do_handshake()
                deadline = time.monotonic() + 10
                while (flow.selection_stalls + flow.abandoned
                       + flow.handshake_failures == 0
                       and time.monotonic() < deadline):
                    time.sleep(0.05)
            finally:
                peer.close()
            self.assertEqual((flow.connections, flow.spoke_tls,
                              flow.client_hello_complete), (1, 1, 1))
            self.assertEqual(flow.cert_requests_sent, 1)
            self.assertEqual(flow.selection_stalls, 1)
            self.assertEqual(flow.abandoned, 0)
            self.assertEqual(flow.handshake_failures, 0)

    @staticmethod
    def _client_hello_bytes(empty_key_share=False):
        """Real TLS 1.3 ClientHello bytes via MemoryBIO (no network).

        With ``empty_key_share`` the key_share extension carries an
        empty list, forcing the server to answer HelloRetryRequest and
        wait for ClientHello2 without sending CertificateRequest
        (RFC 8446 Fig.2). Otherwise the hello completes normally.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_ecdh_curve("prime256v1")
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        conn = context.wrap_bio(incoming, outgoing, server_hostname="127.0.0.1")
        try:
            conn.do_handshake()
        except ssl.SSLWantReadError:
            pass
        initial = outgoing.read()
        if not empty_key_share:
            return initial
        rec_len = int.from_bytes(initial[3:5], "big")
        hs = initial[5:5 + rec_len]
        body = hs[4:]
        pos = 34
        pos += 1 + body[pos]
        pos += 2 + int.from_bytes(body[pos:pos + 2], "big")
        pos += 1 + body[pos]
        ext_offset = pos
        ext_len = int.from_bytes(body[pos:pos + 2], "big")
        exts = body[pos + 2:pos + 2 + ext_len]
        rewritten = []
        p = 0
        while p < len(exts):
            typ = int.from_bytes(exts[p:p + 2], "big")
            n = int.from_bytes(exts[p + 2:p + 4], "big")
            data = exts[p + 4:p + 4 + n]
            if typ == 51:  # key_share: offer no shares, force HRR.
                data = b"\x00\x00"
            rewritten.append(typ.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data)
            p += 4 + n
        new_exts = b"".join(rewritten)
        new_body = body[:ext_offset] + len(new_exts).to_bytes(2, "big") + new_exts
        new_hs = b"\x01" + len(new_body).to_bytes(3, "big") + new_body
        return initial[:3] + len(new_hs).to_bytes(2, "big") + new_hs

    def test_flow_server_hrr_without_clienthello2_is_abandoned(self):
        """P2-2 twin: HRR without ClientHello2 is abandoned, not a stall.

        Sends a valid TLS 1.3 ClientHello that forces HelloRetryRequest
        (empty key_share), then holds silent without ClientHello2: the
        server emits HRR and waits, never sending CertificateRequest.
        A timeout here is pre-selection, not a selection stall.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        hello = self._client_hello_bytes(empty_key_share=True)
        self.assertEqual(tls_server.client_hello_status(hello), "complete")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            flow.HANDSHAKE_TIMEOUT = 2.0
            raw = socket.create_connection(("127.0.0.1", flow.port))
            try:
                raw.sendall(hello)
                deadline = time.monotonic() + 10
                while (flow.abandoned + flow.selection_stalls
                       + flow.handshake_failures == 0
                       and time.monotonic() < deadline):
                    time.sleep(0.05)
            finally:
                raw.close()
            self.assertEqual(flow.connections, 1)
            self.assertEqual(flow.client_hello_complete, 1)
            self.assertEqual(flow.cert_requests_sent, 0,
                             "HRR flight must not send CertificateRequest")
            self.assertEqual(flow.selection_stalls, 0,
                             "HRR wait without CertificateRequest counted as a selection stall")
            self.assertEqual(flow.abandoned, 1)
            self.assertEqual(flow.handshake_failures, 0)

    def test_flow_server_split_handshake_header_stalls(self):
        """P3 twin: a ClientHello header split across records still stalls.

        OpenSSL accepts a handshake header fragmented across TLS
        records; the server must too, then follow the normal witness
        rules (valid hello plus CertificateRequest plus silence is a
        selection stall).
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        hello = self._client_hello_bytes()
        rec_len = int.from_bytes(hello[3:5], "big")
        hs = hello[5:5 + rec_len]
        fragments = (hello[:3] + (2).to_bytes(2, "big") + hs[:2]
                     + hello[:3] + (len(hs) - 2).to_bytes(2, "big") + hs[2:])
        self.assertEqual(tls_server.client_hello_status(fragments), "complete")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            flow.HANDSHAKE_TIMEOUT = 3.0
            raw = socket.create_connection(("127.0.0.1", flow.port))
            try:
                raw.sendall(fragments)
                deadline = time.monotonic() + 10
                while (flow.selection_stalls + flow.abandoned
                       + flow.handshake_failures == 0
                       and time.monotonic() < deadline):
                    time.sleep(0.05)
            finally:
                raw.close()
            self.assertEqual((flow.connections, flow.client_hello_complete), (1, 1))
            self.assertEqual(flow.cert_requests_sent, 1)
            self.assertEqual(flow.selection_stalls, 1)
            self.assertEqual(flow.abandoned, 0)
            self.assertEqual(flow.handshake_failures, 0)

    def test_client_hello_parser_buckets(self):
        """Unit: the ClientHello proof parser buckets its inputs."""
        hello = b"\x16\x03\x01\x00\x0c" + b"\x01\x00\x00\x08" + b"\x00" * 8
        self.assertEqual(tls_server.client_hello_status(b""), "need_more")
        self.assertEqual(tls_server.client_hello_status(b"\x16\x03"), "need_more")
        self.assertEqual(tls_server.client_hello_status(b"GARBAGE"), "non_tls")
        self.assertEqual(
            tls_server.client_hello_status(b"\x16\x03\x01\x00\x10" + b"\x00" * 4),
            "need_more")
        self.assertEqual(tls_server.client_hello_status(hello), "complete")
        # Complete first record, wrong handshake type: not a hello.
        not_hello = b"\x16\x03\x03\x00\x0c" + b"\x02\x00\x00\x08" + b"\x00" * 8
        self.assertEqual(tls_server.client_hello_status(not_hello), "not_hello")
        # Zero-length record fails closed.
        self.assertEqual(
            tls_server.client_hello_status(b"\x16\x03\x01\x00\x00"), "not_hello")
        # Zero-length ClientHello body is not a hello.
        self.assertEqual(
            tls_server.client_hello_status(b"\x16\x03\x01\x00\x04" + b"\x01\x00\x00\x00"),
            "not_hello")
        # Fragmented hello across two records still proves completion.
        frag = (b"\x16\x03\x01\x00\x08" + b"\x01\x00\x00\x0a" + b"\x00" * 4
                + b"\x16\x03\x01\x00\x06" + b"\x00" * 6)
        self.assertEqual(tls_server.client_hello_status(frag), "complete")
        # Handshake header split across records still proves completion:
        # OpenSSL accepts the fragmentation, so the parser must
        # accumulate the 4-byte header instead of rejecting a short
        # first payload.
        for cut in (1, 2, 3):
            head = b"\x01\x00\x00\x08" + b"\x00" * 8
            split = (b"\x16\x03\x01" + cut.to_bytes(2, "big") + head[:cut]
                     + b"\x16\x03\x01" + (len(head) - cut).to_bytes(2, "big")
                     + head[cut:])
            self.assertEqual(
                tls_server.client_hello_status(split), "complete",
                f"header split {cut}/rest rejected")

    def _installed_copy(self):
        """Install this suite source into a scratch tests/python layout."""
        root = self.work / "strict-probe"
        target = root / "tests" / "python" / "test_browser_cells.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(Path(__file__).read_text())
        fixtures = root / "tests" / "fixtures"
        fixtures.mkdir(parents=True, exist_ok=True)
        link = fixtures / "browser"
        if not link.exists():
            link.symlink_to(Path(cells.__file__).resolve().parent)
        return target

    def test_strict_mode_rejects_empty_selection(self):
        """P3 twin: strict installed mode must fail an empty selection."""
        import subprocess as stdlib_subprocess

        target = self._installed_copy()
        base = dict(os.environ)
        base.pop("P11SCOPE_BROWSER_STRICT", None)
        strict = dict(base, P11SCOPE_BROWSER_STRICT="1")
        empty = [sys.executable, "-I", str(target), "-k", "definitely_no_such_test_zzz"]
        strict_run = stdlib_subprocess.run(
            empty, capture_output=True, text=True, check=False, env=strict, timeout=120)
        self.assertEqual(
            strict_run.returncode, 2,
            f"strict mode must fail an empty selection explicitly: {strict_run.stderr[-500:]}")
        self.assertIn("empty selection", strict_run.stderr)
        plain_run = stdlib_subprocess.run(
            empty, capture_output=True, text=True, check=False, env=base, timeout=120)
        # The self-skipping default keeps native unittest exit behavior
        # (version-defined for empty selections); it just never raises
        # the strict failure.
        self.assertNotIn("empty selection", plain_run.stderr)
        picked = stdlib_subprocess.run(
            [sys.executable, "-I", str(target), "-k", "test_capture_ready_parsing"],
            capture_output=True, text=True, check=False, env=strict, timeout=120)
        self.assertEqual(picked.returncode, 0,
                         f"strict nonempty selection must pass: {picked.stderr[-500:]}")


def require_s1(test):
    """Fail naming the missing S1 oracle (RED) once per check."""
    for name in ("check_no_joint_content", "check_s1_mechanisms_absent",
                 "check_s1_logins_absent", "check_s1_sessions"):
        if not hasattr(oracle, name):
            test.fail(f"S1 oracle not implemented: oracle.{name} missing")


def require_s1_wiring(test):
    """Fail naming the missing check_report wiring (RED)."""
    require_s1(test)
    if "s1" not in BrowserCells.check_report.__code__.co_varnames:
        test.fail("S1 oracle not implemented: check_report has no s1 wiring")


def healthy_sessions(opened=2, inherited=0, closed=1, async_opened=0,
                     peak=2):
    """Balanced S1 session accounting (balance follows the counters)."""
    total = min(opened + inherited, (1 << 64) - 1)
    return {"opened": opened, "inherited": inherited, "closed": closed,
            "async_opened": async_opened, "peak_concurrent": peak,
            "balance": total - min(closed, total)}


class BrowserS1Oracle(unittest.TestCase):
    """S1 oracle twins: unprivileged, run everywhere (no gate).

    The v0.5.0 S1 proof over the profile report's S1 sections: no
    Joint content anywhere (key-operation populations are 0.5.1), no
    mechanism use and no logins in enumeration flows, and balanced
    session accounting with a per-cell opened floor.
    """

    maxDiff = 4096

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="g33-browser-s1-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    def s1_result(self, name, rows, evidence, mechanisms, sessions, logins,
                  extra=None):
        """Write a twin v3 document with S1 sections; wrap it in a result."""
        doc = {"schema": oracle.SCHEMA, "functions": rows,
               "evidence": evidence, "mechanisms": mechanisms,
               "sessions": sessions, "logins": logins,
               "cgroups": []}
        if extra:
            doc.update(extra)
        path = self.work / f"{name}-report.json"
        path.write_text(json.dumps(doc))
        return doc, cells.CellResult(name, path)

    def healthy_rows(self, sha):
        return [BrowserCells._twin_row(["C_FindObjects"], 3, sha)]

    def test_s1_healthy_sections_accepted(self):
        require_s1_wiring(self)
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = self.healthy_rows(sha)
        doc, result = self.s1_result(
            "S1-HEALTHY", rows, BrowserCells._twin_evidence(), [],
            healthy_sessions(), {})
        self.assertEqual(oracle.check_no_joint_content(doc), [])
        self.assertEqual(oracle.check_s1_mechanisms_absent(doc), [])
        self.assertEqual(oracle.check_s1_logins_absent(doc), [])
        self.assertEqual(oracle.check_s1_sessions(doc, opened_min=1), [])
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        with patch.object(oracle, "sha256_of", return_value=sha):
            case.check_report(result, store, {"C_FindObjects": 1},
                              attached=True,
                              s1={"sessions_opened_min": 1})

    def test_s1_mechanism_use_rejected(self):
        require_s1(self)
        doc = {"mechanisms": [{"mechanism": 0x1082, "mechanism_hex": "0x1082",
                               "ops": ["sign"], "calls": 5, "errors": 0}]}
        failures = oracle.check_s1_mechanisms_absent(doc)
        self.assertNotEqual(failures, [])
        self.assertIn("0x1082", failures[0])
        self.assertNotEqual(
            oracle.check_s1_mechanisms_absent({"mechanisms": ["x"]}), [])
        self.assertNotEqual(
            oracle.check_s1_mechanisms_absent({"mechanisms": {}}), [])

    def test_s1_login_rejected(self):
        require_s1(self)
        failures = oracle.check_s1_logins_absent({"logins": {"USER": 1}})
        self.assertNotEqual(failures, [])
        self.assertIn("USER", failures[0])
        self.assertNotEqual(oracle.check_s1_logins_absent({"logins": []}), [])

    def test_s1_sessions_rejected(self):
        require_s1(self)
        with self.subTest("floor"):
            doc = {"sessions": healthy_sessions(opened=0, closed=0, peak=0)}
            self.assertNotEqual(
                oracle.check_s1_sessions(doc, opened_min=1), [])
        with self.subTest("zero"):
            doc = {"sessions": healthy_sessions()}
            self.assertNotEqual(oracle.check_s1_sessions(doc, zero=True), [])
        with self.subTest("balance"):
            sessions = healthy_sessions()
            sessions["balance"] = sessions["balance"] + 1
            self.assertNotEqual(
                oracle.check_s1_sessions({"sessions": sessions}), [])
        with self.subTest("shape"):
            sessions = healthy_sessions()
            del sessions["closed"]
            self.assertNotEqual(
                oracle.check_s1_sessions({"sessions": sessions}), [])
        with self.subTest("missing"):
            self.assertNotEqual(oracle.check_s1_sessions({}), [])
            self.assertNotEqual(
                oracle.check_s1_mechanisms_absent({}), [])
            self.assertNotEqual(oracle.check_s1_logins_absent({}), [])

    def test_s1_joint_content_rejected(self):
        require_s1(self)
        for key in ("object_observations", "key_operations",
                    "unknown_key_operations"):
            with self.subTest(key=key):
                failures = oracle.check_no_joint_content({key: []})
                self.assertNotEqual(failures, [])
                self.assertIn(key, failures[0])

    def test_s1_check_report_wiring(self):
        require_s1_wiring(self)
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = self.healthy_rows(sha)
        hostile = [{"mechanism": 0x1082, "mechanism_hex": "0x1082",
                    "ops": ["sign"], "calls": 5, "errors": 0}]
        _, result = self.s1_result(
            "S1-HOSTILE", rows, BrowserCells._twin_evidence(), hostile,
            healthy_sessions(), {})
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                case.check_report(result, store, {"C_FindObjects": 1},
                                  attached=True,
                                  s1={"sessions_opened_min": 1})
        _, clean = self.s1_result(
            "S1-UNWIRED", rows, BrowserCells._twin_evidence(), hostile,
            healthy_sessions(), {})
        with patch.object(oracle, "sha256_of", return_value=sha):
            case.check_report(clean, store, {"C_FindObjects": 1},
                              attached=True)


if __name__ == "__main__":
    # Expected-cell execution guard: in strict installed mode the suite
    # must actually run selected cells — an empty selection (a filter
    # matching nothing, a typo'd name) fails instead of succeeding
    # silently. Nonempty subsets stay legal for single-focus runs. The
    # self-skipping default keeps native unittest exit behavior.
    if STRICT:
        _program = unittest.main(verbosity=2, exit=False)
        _result = _program.result
        if _result.testsRun == 0:
            print("strict installed mode requires selected cells to execute "
                  "(empty selection)", file=sys.stderr)
            sys.exit(2)
        sys.exit(0 if _result.wasSuccessful() else 1)
    unittest.main(verbosity=2)
