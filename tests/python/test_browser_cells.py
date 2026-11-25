# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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

import ast
import functools
import inspect
import io
import json
import os
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "browser"))

import cells
import flows
import oracle
import reap_tree
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
#: Run-tree (v0.7.0): the owned browser's short-lived descendants
#: retire between admission passes, so run-mode never-mapped cells
#: honestly disclose pid_descendant_gaps. Same spawn-window caveat
#: class as the other run-mode additions: the asserted property (no
#: module ever mapped — zero rows, zero probes, structural skips)
#: is unchanged.
_GAPS_NEVER_MAPPED_RUN = _GAPS_NEVER_MAPPED | frozenset({
    "unprotected_live_windows", "pause_partial", "loader_discovery",
    "pid_descendant_gaps",
})

#: Verdict details each cell kind earned. Attached cells over a
#: standard-layout provider table read clean_proven when observation is
#: exact: the scan verifies the table without a manifest (owner ruling
#: 2026-11-11, docs/usage.md "needs no manifest"), so the SoftHSM v2.40
#: table carries semantics through the sole-complete / typed-getter-export
#: legs, semantic_unverified_slots is 0 and no gap cause remains. The pin
#: is exact on purpose: a standard-layout regression reads
#: attribution_only and any observation loss reads concrete_gap, and both
#: must fail loud. Never-mapped cells always carry the structural
#: discovery gap, so concrete_gap only. _VERDICTS_ATTACHED keeps the
#: pre-standard-layout pair for the twin builder's synthetic docs, which
#: carry verdict_detail attribution_only and no scan evidence.
_VERDICTS_ATTACHED = ("attribution_only", "concrete_gap")
_VERDICTS_ATTACHED_VERIFIED = ("clean_proven",)
_VERDICTS_NEVER_MAPPED = ("concrete_gap",)

#: Private-token operations no PINBOUND flow may ever reach: login plus
#: signing setup and signing (init and one-shot share the boundary).
_PINBOUND_ABSENT = ("C_Login", "C_SignInit", "C_Sign")

#: Run-mode attached floor cells (CR-RUN-SIGN and CR-RUN-NODELAY),
#: calibrated on sm1 (narrowed softokn scan; spawn delayed past
#: observer startup in CR-RUN-SIGN, no delay with the first-map stop
#: in CR-RUN-NODELAY): the loader/discovery window causes, the owned
#: tree's short-lived descendants retiring between admission passes
#: (``pid_descendant_gaps``), the SIGKILL-teardown link losses
#: (``task_uprobe_link_losses``: the supervisor SIGKILLs the whole
#: browser group at flow completion, so teardown links race), the
#: bounded-queue discovery drops under that churn
#: (``discovery_truncated``), the ``skipped`` cause whose records
#: the run-floor skipped qualification judges one by one, and the
#: interface-selection cause (``interface_selection``): a selection
#: pass runs before the browser maps its provider and
#: intermittently records it ``absent_uncovered`` (no truncation, no
#: unmatched tuples — the observed shape twice). Selection decides
#: which table, never whether calls count: the events lane counts
#: C_Sign independently, so the cause cannot hide a sign, and the
#: exact counts below still fail a capture that lost one. Each cause
#: can only undercount, never invent the asserted signs. Any other
#: cause fails.
_GAPS_ATTACHED_RUN = frozenset({
    "loader_discovery", "unprotected_live_windows",
    "pid_descendant_gaps", "task_uprobe_link_losses",
    "discovery_truncated", "skipped", "interface_selection",
})

#: RSA mechanism family ids (numeric, exact): the verbatim RSA_IDS table
#: from src/keymeta.rs (§4.2, the product's own family vocabulary). The
#: CR-RUN-SIGN cell seeds an RSA client credential, so the TLS sign
#: mechanism (PKCS#1 v1.5, PSS, or a hash-joined RSA id, TLS-version
#: dependent) lands in this closed set whatever the stack negotiates.
_RSA_FAMILY_IDS = frozenset({
    0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005,
    0x00000006, 0x00000007, 0x00000008, 0x00000009, 0x0000000b,
    0x0000000c, 0x0000000d, 0x0000000e, 0x00000040, 0x00000041,
    0x00000042, 0x00000043, 0x00000044, 0x00000045, 0x00000046,
    0x00000047, 0x00000060, 0x00000061, 0x00000062, 0x00000063,
    0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00001054,
    0x00004001, 0x00004002,
})

#: Digest-only mechanism id for the hostile twin: CKM_SHA256, the shape
#: a sign-missing capture shows (mechanism use without any sign family).
_SHA256_MECHANISM_ID = 0x00000250

#: Basename of the NSS softokn provider the browsers sign with. Matched
#: exactly against evidence.discovery[] paths (never a substring).
_SOFTOKN_BASENAME = "libsoftokn3.so"


def _stall_outcomes(server) -> str:
    """One-line handshake summary for PINBOUND failure messages."""
    cert_reqs = getattr(server, "cert_requests_sent", 0)
    return (
        f"connections={server.connections} requests={server.requests_served} "
        f"certs={server.client_certs_presented} ok={server.handshakes_ok} "
        f"spoke={server.spoke_tls} hello={server.client_hello_complete} "
        f"certreq={cert_reqs} "
        f"empty={server.empty_certs} stalls={server.selection_stalls} "
        f"alerts={server.client_cert_alerts} refusals={server.cert_refusals} "
        f"abandoned={server.abandoned} "
        f"failures={server.handshake_failures} errors={server.handshake_errors}")


#: Installed mode: set P11SCOPE_BROWSER_STRICT=1 on a qualified installed
#: host (T11) to turn prerequisite skips into failures, requiring the
#: expected cells to execute; an empty selection fails outright. Unset
#: keeps the self-skipping hosted default.
STRICT = os.environ.get("P11SCOPE_BROWSER_STRICT") == "1"

#: Doctor's journal-pair availability row and the one build-limit detail
#: a journal-less build reports (src/doctor.rs JOURNAL_PAIR_ROW /
#: BUILD_LIMIT_NOT_IN_BUILD): the key-operations refusal branch is only
#: valid when the binary under test reports exactly this token.
_JOURNAL_PAIR_ROW = "journal pair preflight"
_JOURNAL_NOT_IN_BUILD = "not in this build"


def observer_omits_journal():
    """Whether the binary under test omits the production journal.

    Asks the binary itself (`doctor -v` names the journal-pair
    availability): only a `not in this build` row means a
    journal-less build. Any other shape (available, unavailable for
    a host reason) means the build carries the journal. A missing
    row fails closed: an unprovable flavor never takes the refusal
    branch.
    """
    binary = cells.p11scope_bin()
    proc = subprocess.run(
        [str(binary), "doctor", "-v"],
        capture_output=True, text=True, timeout=180, check=False)
    for line in proc.stdout.splitlines():
        if line.startswith(_JOURNAL_PAIR_ROW):
            return _JOURNAL_NOT_IN_BUILD in line
    raise AssertionError(
        "doctor names no journal-pair row?! cannot prove the build flavor")


def judge_key_observations_journal_branch(observations, report, *,
                                          journal_omitted):
    """Judge a `journal_unavailable` key-operations observation.

    Returns "refusal" when the observation is the pinned
    journal-less-build refusal (status unavailable, zero rows, the
    named build cause, no lost events). Raises AssertionError when a
    journal-carrying build refused (a journal regression, which must
    fail instead of passing as a refusal) or when the refusal shape
    itself is wrong.
    """
    if not journal_omitted:
        raise AssertionError(
            "journal build refused key rows with journal_unavailable: "
            "a journal regression, not the pinned journal-less refusal")
    if observations.get("status") != "unavailable":
        raise AssertionError("journal refusal must stay unavailable")
    rows = observations.get("key_operations") or []
    if len(rows) != 0:
        raise AssertionError("journal refusal must carry zero rows")
    refusal_gaps = [
        gap.get("reason") or ""
        for gap in report.get("gaps") or []
        if isinstance(gap, dict)
        and gap.get("subject") == "key operations unavailable"
    ]
    if not any("journal-pair-unavailable-in-build" in reason
               for reason in refusal_gaps):
        raise AssertionError("journal refusal must name its build cause")
    capture = (report.get("observation") or {}).get("semantic_capture") or {}
    if capture.get("events_lost") != 0:
        raise AssertionError(
            "semantic events lost: %r" % (capture.get("events_lost"),))
    return "refusal"


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


def gate_system(browser):
    """Same prerequisites as gate(), for observer-first system cells.

    A distinct decorator name keeps the families apart: the S1 wiring
    proof counts @gate cells (profile reports, Joint-free), while
    @gate_system cells assert populated key-operation rows from an
    inventory report and are pinned by the companion oracle meta-test.
    Strict mode treats both identically (a missing prerequisite fails).
    """

    return gate(browser)


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


def aggregate_module_counts(report, module_sha):
    """Sum per-name completed calls and open entries over ``module_sha``.

    One ``(counts, opened)`` pair over the whole identity set: a
    discovery copy-up pair contributes one row per sha, so floors and
    absence legs see the summed totals, never one sha's slice. Pure
    over the parsed report (exact dicts, no thresholds), so twins pin
    the sums with exact equality.
    """
    counts: dict = {}
    opened: dict = {}
    for sha in module_sha:
        for name, calls in oracle.module_counts(report, sha).items():
            counts[name] = counts.get(name, 0) + calls
        for name, entries in oracle.module_open_entries(report, sha).items():
            opened[name] = opened.get(name, 0) + entries
    return counts, opened


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
                     s1=None, qualify_nomod_link_loss=False, module_sha=None,
                     qualify_run_floor_skipped=False, exact=None,
                     exact_opened_zero=(), no_cross_alias=()):
        """Common oracle: schema, identity, counts, loss, gaps, earned verdict.

        ``attached`` pins the probe state: True (hooked the mapped module),
        False (never hooked — the module stayed unmapped), None (either).
        ``allowed_gaps`` names the observation gap causes that provably do
        not affect this cell's asserted property (per-cell table above);
        every other cause fails. ``qualify_nomod_link_loss`` routes the
        gap check through the FF-NOMOD qualification (sole named link
        loss with zero probes and zero rows); only the FF-NOMOD cell
        sets it. ``qualify_run_floor_skipped`` routes the skipped
        check through the run-floor qualification (structural records
        plus run-tree timing: mid-flight subjects and the single
        learned-first-use record); only run-mode floor cells set it,
        never beside ``qualify_nomod_link_loss``. ``allowed_verdicts`` pins the verdict
        details the cell earned. ``absent`` names functions that must never
        have been called (returns, open entries, and unattributed rows).
        ``module_sha`` overrides the module identity: a sha string or a
        set of them (a discovery copy-up pair), resolved from the
        report's own discovery list; None (the default) hashes
        ``store.lib`` as before, and ``store`` itself may then be None.
        ``s1`` opts into the v0.5.0 S1 proof over the report's S1
        sections (no Joint content, no mechanism use, no logins,
        balanced sessions): a dict with ``sessions_opened_min`` for
        cells whose window must contain a session open, or
        ``sessions_zero`` for never-mapped cells. Attach-drive cells
        must not set ``sessions_opened_min``: the browser opens its
        sessions at startup, strictly before capture, so floored calls
        legitimately ride cached sessions. A ``sign_mechanisms`` entry
        (``{"family_ids": [...], "min_calls": n}``) selects the run-sign
        branch instead: the Joint negative and the session floor stay,
        but the enumeration absence legs give way to the attributed
        family-sign floor (mechanism use is the asserted property
        here, not a violation; an optional ``exact_calls`` pins the
        attributed family total exactly instead of flooring it).
        None (the twin default)
        skips the S1 checks. ``exact`` pins completed counts exactly
        (``{name: count}`` against independent ground truth, missing
        names read as zero) beside the floors; ``exact_opened_zero``
        names functions with no entered-but-unreturned calls at end;
        ``no_cross_alias`` lists ``(first, second)`` pairs no single
        row may claim together.
        """
        report = oracle.load_report(result.report_path)
        if module_sha is None:
            module_sha = {oracle.sha256_of(store.lib)}
        elif isinstance(module_sha, str):
            module_sha = {module_sha}
        else:
            module_sha = set(module_sha)
        counts, opened = aggregate_module_counts(report, module_sha)
        failures = []
        failures += oracle.check_function_rows_typed(report)
        failures += oracle.check_no_event_loss(report)
        failures += oracle.check_capture_intact(report)
        if qualify_nomod_link_loss:
            failures += oracle.check_observation_gaps_nomod_qualified(report, allowed_gaps)
        else:
            failures += oracle.check_observation_gaps(report, allowed_gaps)
        if qualify_nomod_link_loss and qualify_run_floor_skipped:
            failures.append(
                "conflicting skipped qualifications (test bug): "
                "nomod and run-floor are mutually exclusive")
        elif qualify_run_floor_skipped:
            failures += oracle.check_skipped_run_floor(report)
        else:
            failures += oracle.check_skipped_structural(report)
        if s1 is not None:
            failures += oracle.check_no_joint_content(report)
            sign_mechanisms = s1.get("sign_mechanisms")
            if sign_mechanisms is None:
                failures += oracle.check_s1_mechanisms_absent(report)
                failures += oracle.check_s1_logins_absent(report)
            else:
                family_ids = sign_mechanisms.get("family_ids")
                min_calls = sign_mechanisms.get("min_calls")
                exact_calls = sign_mechanisms.get("exact_calls")
                if (not isinstance(family_ids, (list, tuple, set, frozenset))
                        or not family_ids
                        or not all(type(mid) is int for mid in family_ids)
                        or type(min_calls) is not int or min_calls < 1
                        or (exact_calls is not None
                            and (type(exact_calls) is not int
                                 or exact_calls < 1))):
                    failures.append(
                        "s1 sign_mechanisms malformed: need "
                        "{family_ids: non-empty ints, min_calls: >= 1, "
                        "exact_calls: >= 1 or absent}")
                else:
                    failures += oracle.check_s1_sign_mechanisms(
                        report, module_sha, family_ids, min_calls,
                        exact_calls=exact_calls)
            failures += oracle.check_s1_sessions(
                report, opened_min=s1.get("sessions_opened_min", 0),
                zero=s1.get("sessions_zero", False))
        if zero:
            failures += oracle.check_zero_counts(counts, opened)
        else:
            failures += oracle.check_min_counts(counts, floors or {})
        if exact is not None:
            failures += oracle.check_exact_counts(counts, exact)
        if exact_opened_zero:
            failures += oracle.check_zero_open_entries(
                opened, tuple(exact_opened_zero))
        if no_cross_alias:
            failures += oracle.check_no_cross_function_alias(
                report, module_sha, tuple(no_cross_alias))
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

        Requires affirmative selection progress: a complete ClientHello
        plus a token-selection witness — an empty certificate, a
        CertificateRequest-backed stall, or a CertificateRequest-backed
        refusal (the client answering the received CertificateRequest
        with a fatal certificate_unknown alert) — with no successful
        handshake, no presented cert, no served request, no protocol
        failure, and a TLS-flow (not crashed or never-launched) browser
        outcome. A stall or refusal counts only when the same connection
        observed the server's outbound CertificateRequest (a complete
        hello alone can yield HelloRetryRequest waiting for
        ClientHello2, which is pre-selection). Bare alerts and abandoned
        transports are tolerated but never sufficient: a bare alert is
        ambiguous (selection refusal vs server-cert rejection) and an
        abandon carries no selection information. The refusal leg is
        unambiguous here: the cells run with ignored server-cert errors
        (the paired plain cell loads the same certificate with HTTP 200,
        and the no-token control yields an empty certificate instead),
        so a fatal alert after the CertificateRequest flight refuses
        selection, not the server certificate. A navigation timeout
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
        if server.cert_refusals:
            self.assertGreaterEqual(
                getattr(server, "cert_requests_sent", 0), 1,
                f"{label}: refusal without outbound CertificateRequest "
                f"(selection never began) [{outcomes}]")
        witness = (server.empty_certs + server.selection_stalls
                   + server.cert_refusals)
        self.assertGreaterEqual(
            witness, 1,
            f"{label}: no token-selection witness "
            f"(need empty-cert, CertificateRequest-backed stall, or "
            f"CertificateRequest-backed refusal) [{outcomes}]")
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
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=cells.ATTACH_GRACE_SECONDS,
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
        # No opened floor: Firefox opens its NSS token sessions at
        # startup, strictly before the profiler can attach, so the
        # window sees enumeration on cached sessions (C_OpenSession=0
        # with C_FindObjects>0) and sessions.opened is legitimately 0.
        self.check_report(result, store, oracle.FF_STARTUP_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_FLOOR,
                          allowed_verdicts=_VERDICTS_ATTACHED_VERIFIED,
                          s1={})

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
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=cells.ATTACH_GRACE_SECONDS,
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
        # No opened floor: Chromium opens its NSS token sessions at
        # startup, strictly before the profiler can attach (same
        # window argument as FF-STARTUP).
        self.check_report(result, store, oracle.CR_ENUMERATION_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_ABSENT, absent=_PINBOUND_ABSENT,
                          allowed_verdicts=_VERDICTS_ATTACHED_VERIFIED,
                          s1={})

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
                          s1={"sessions_zero": True},
                          qualify_nomod_link_loss=True)

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
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=cells.ATTACH_GRACE_SECONDS,
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
                          allowed_verdicts=_VERDICTS_ATTACHED_VERIFIED,
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
                duration_seconds=ATTACH_DURATION, attach_grace_seconds=cells.ATTACH_GRACE_SECONDS,
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
        # No opened floor (same window argument as FF-STARTUP).
        self.check_report(result, store, oracle.CR_ENUMERATION_FLOORS, attached=True,
                          allowed_gaps=_GAPS_ATTACHED_ABSENT, absent=_PINBOUND_ABSENT,
                          allowed_verdicts=_VERDICTS_ATTACHED_VERIFIED,
                          s1={})

    @gate("chromium")
    def test_cr_run_sign_observes_client_cert_signs(self):
        """CR-RUN-SIGN: run-owned Chromium client-cert signs are observed.

        ``p11scope run`` owns the browser from exec (no late discovery):
        a CERT_REQUIRED screenshot flow against the browser's own
        seeded NSS token (empty-password, so no PIN can stall it, and
        no login is required) must show completed C_SignInit/C_Sign
        calls plus an attributed RSA-family sign mechanism on the
        softokn provider the report's own discovery list resolves.
        Run reports carry no per-key rows (inventory-only); the sign
        calls plus the attributed family mechanism are the run-visible
        proof the handshake's private-key use was seen. The scan is
        narrowed to the probed system softokn (a discovery-all run
        drowns it in p11-kit slot demand on Fedora) and the spawn is
        delayed past observer startup, so the signs land in-window
        deterministically instead of racing BPF load.
        """
        softokn = cells.find_softokn()
        if softokn is None:
            if STRICT:
                raise AssertionError(
                    "strict installed mode requires this cell: "
                    "system softokn provider not found")
            self.skipTest("browser gate prerequisite missing: "
                          "system softokn provider not found")
        missing = cells.missing_nss_seed_tools()
        if missing:
            raise AssertionError(
                "installed browser cell requires NSS seed tools: "
                f"{', '.join(missing)}")
        cred = softhsm.generate_client_credential(self.work / "cred")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cred.cert_pem) as flow:
            result = cells.run_direct(
                "CR-RUN-SIGN", "chromium", self.work / "cell", flow.url,
                observe_module=softokn, register_module=None,
                browser_env=None,
                extra_browser_args=CHROMIUM_STABLE_ARGS,
                duration_seconds=RUN_DURATION,
                nss_credential=cred, auto_select_cert=True,
                # Matches the ruled BPF-load bound behind
                # cells.ATTACH_GRACE_SECONDS, kept as its own literal:
                # tightening hang detection must not tighten this
                # spawn margin.
                initial_delay_seconds=15)
            self.assertGreaterEqual(
                flow.client_certs_presented, 1,
                "client cert never presented (no TLS sign happened)")
            self.assertGreaterEqual(
                flow.handshakes_ok, 1,
                "client-cert flow never handshook (no TLS sign happened)")
        self.assertEqual(result.flow.get("observer_exit"), 0,
                         f"observer failed: {result.observer_stderr_tail}")
        self.assertTrue(result.flow.get("nss_seeded"),
                        "NSS credential was not seeded?!")
        self.assertTrue(result.flow.get("auto_select_policy"),
                        "auto-select policy was not installed?!")
        self.assertGreater(result.screenshot_bytes, 0, "no screenshot bytes")
        report = oracle.load_report(result.report_path)
        shas, failures = oracle.discovery_module_shas(
            report, _SOFTOKN_BASENAME)
        if failures:
            self.fail("CR-RUN-SIGN failed:\n"
                      f"{json.dumps({'failures': failures}, indent=1)}")
        self.assertGreater(
            len(shas), 0,
            "softokn never discovered (browser never mapped it, or "
            "discovery missed it)")
        # PARTIAL/concrete_gap is earned: the run-tree teardown and
        # the map-to-attach window are structural to run mode (see
        # _GAPS_ATTACHED_RUN); the floors, the family leg, and the TLS
        # ground truth above carry the proof, and any new gap cause
        # still fails. No sessions floor: the sign's session may
        # legitimately have opened in the tolerated pre-attach window.
        self.check_report(
            result, None, {"C_SignInit": 1, "C_Sign": 1}, attached=True,
            allowed_gaps=_GAPS_ATTACHED_RUN,
            allowed_verdicts=("concrete_gap",),
            module_sha=shas,
            qualify_run_floor_skipped=True,
            s1={"sign_mechanisms": {"family_ids": sorted(_RSA_FAMILY_IDS),
                                    "min_calls": 1}})

    @gate("chromium")
    def test_cr_run_nodelay_observes_client_cert_signs(self):
        """CR-RUN-NODELAY: run-owned Chromium signs are observed with no spawn delay.

        ``p11scope run`` owns the browser from exec, so the browser must
        never reach its provider calls before the probes attach: the
        run-tree first-map stop holds it at its first map of the
        provider until the probes attach, with no readiness margin.
        A CERT_REQUIRED screenshot flow against the browser's own
        seeded NSS token (empty-password, so no PIN can stall it, and
        no login is required) must show completed C_SignInit/C_Sign
        calls plus an attributed RSA-family sign mechanism on the
        softokn provider the report's own discovery list resolves.
        Run reports carry no per-key rows (inventory-only); the sign
        calls plus the attributed family mechanism are the run-visible
        proof the handshake's private-key use was seen. The scan is
        narrowed to the probed system softokn (a discovery-all run
        drowns it in p11-kit slot demand on Fedora) and the spawn runs
        with no delay, so a map-to-attach window fails this cell
        instead of hiding behind a margin.
        """
        softokn = cells.find_softokn()
        if softokn is None:
            if STRICT:
                raise AssertionError(
                    "strict installed mode requires this cell: "
                    "system softokn provider not found")
            self.skipTest("browser gate prerequisite missing: "
                          "system softokn provider not found")
        missing = cells.missing_nss_seed_tools()
        if missing:
            raise AssertionError(
                "installed browser cell requires NSS seed tools: "
                f"{', '.join(missing)}")
        cred = softhsm.generate_client_credential(self.work / "cred")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cred.cert_pem) as flow:
            result = cells.run_direct(
                "CR-RUN-NODELAY", "chromium", self.work / "cell", flow.url,
                observe_module=softokn, register_module=None,
                browser_env=None,
                extra_browser_args=CHROMIUM_STABLE_ARGS,
                duration_seconds=RUN_DURATION,
                nss_credential=cred, auto_select_cert=True)
            self.assertGreaterEqual(
                flow.client_certs_presented, 1,
                "client cert never presented (no TLS sign happened)")
            self.assertGreaterEqual(
                flow.handshakes_ok, 1,
                "client-cert flow never handshook (no TLS sign happened)")
            # Exactness ties to owed signs, not raw handshakes: a
            # completed handshake with an empty (or no) client
            # certificate needs no private-key use, and a resumed
            # handshake reports its cached peer cert without signing.
            # Each presented cert on a CertificateRequest connection
            # signs exactly once (CertificateVerify).
            signs = flow.signs_owed
            self.assertGreaterEqual(
                signs, 1,
                "no owed sign witnessed (no presented cert on a "
                "CertificateRequest connection)")
        self.assertEqual(result.flow.get("observer_exit"), 0,
                         f"observer failed: {result.observer_stderr_tail}")
        self.assertTrue(result.flow.get("nss_seeded"),
                        "NSS credential was not seeded?!")
        self.assertTrue(result.flow.get("auto_select_policy"),
                        "auto-select policy was not installed?!")
        self.assertGreater(result.screenshot_bytes, 0, "no screenshot bytes")
        report = oracle.load_report(result.report_path)
        shas, failures = oracle.discovery_module_shas(
            report, _SOFTOKN_BASENAME)
        if failures:
            self.fail("CR-RUN-NODELAY failed:\n"
                      f"{json.dumps({'failures': failures}, indent=1)}")
        self.assertGreater(
            len(shas), 0,
            "softokn never discovered (browser never mapped it, or "
            "discovery missed it)")
        # Anchor: every resolved sha must be the observed system
        # softokn file hashed on this host — Chromium links system
        # NSS, so a coherent substitution (another digest under a
        # same-basename path, with functions and S1 rewritten to
        # match) fails here instead of attributing to phantom rows.
        observed_sha = oracle.sha256_of(softokn)
        anchor_failures = oracle.check_discovery_shas_anchored(
            shas, {observed_sha}, observed_sha, _SOFTOKN_BASENAME)
        if anchor_failures:
            self.fail("CR-RUN-NODELAY failed:\n"
                      f"{json.dumps({'failures': anchor_failures}, indent=1)}")
        # PARTIAL/concrete_gap is earned: the run-tree teardown and
        # the map-to-attach window are structural to run mode (see
        # _GAPS_ATTACHED_RUN); the exact counts, the family leg, and
        # the TLS ground truth above carry the proof, and any new gap
        # cause still fails. No sessions floor: the sign's session may
        # legitimately have opened in the tolerated pre-attach window.
        # Exactness is per owed sign: each owes one C_SignInit +
        # one C_Sign and two attributed family mechanism uses (the
        # init and sign legs), nothing in flight at end, and the
        # pair comes from distinct rows (no single aliased row may
        # satisfy both).
        self.check_report(
            result, None, None, attached=True,
            allowed_gaps=_GAPS_ATTACHED_RUN,
            allowed_verdicts=("concrete_gap",),
            module_sha=shas,
            qualify_run_floor_skipped=True,
            exact={"C_SignInit": signs, "C_Sign": signs},
            exact_opened_zero=("C_SignInit", "C_Sign"),
            no_cross_alias=(("C_SignInit", "C_Sign"),),
            s1={"sign_mechanisms": {"family_ids": sorted(_RSA_FAMILY_IDS),
                                    "min_calls": 1,
                                    "exact_calls": 2 * signs}})

    @gate_system("firefox")

    @gate_system("firefox")
    def test_ff_first_with_background_provider_covers_browser(self):
        """FF-FIRST-BG (v0.6.0 F1): observer-first key operations beside a
        pre-existing SoftHSM caller; the late browser's key rows populate
        (the scan seal settles over the newcomer instead of seating over
        the background provider alone)."""
        missing = cells.missing_nss_seed_tools()
        if missing:
            raise AssertionError(
                "installed browser cell requires NSS seed tools: "
                f"{', '.join(missing)}")
        store, cred = self.seed()
        bg = cells.start_soft_call(store.lib, self.work / "bg", env=store.env)
        self.addCleanup(bg.stop)
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key) as plain, \
                tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                      client_ca=cred.cert_pem) as cc:
            result = cells.observe_first_system(
                "FF-FIRST-BG", "firefox", self.work / "cell",
                plain_url=plain.url, cc_url=cc.url, nss_credential=cred,
                duration_seconds=90, extra_prefs=FIREFOX_STABLE_PREFS)
            self.assertGreaterEqual(
                plain.requests_served, 1, "plain flow saw no request")
            self.assertGreaterEqual(
                cc.handshakes_ok, 1, "client-cert flow never handshook")
            self.assertGreaterEqual(
                cc.client_certs_presented, 1, "client cert never presented")
        self.assertEqual(result.flow.get("observer_exit"), 0,
                         f"observer failed: {result.observer_stderr_tail}")
        bg.stop()
        bg_calls = cells.soft_call_completed(bg.log.read_text())
        self.assertIsNotNone(
            bg_calls, "background caller left no STOP line (died mid-cell?)")
        self.assertGreaterEqual(
            bg_calls, 30,
            "background caller made too few calls to pin its precondition")
        with open(result.report_path, encoding="utf-8") as handle:
            report = json.load(handle)
        observations = report.get("object_observations") or {}
        # Broad inventory observes the run on every build: the browser's
        # softokn module and its instance must be in the report whether
        # key rows follow (journal build) or the journal refusal lands
        # (wide build). An empty capture must fail here, never pass.
        browser_modules = {
            module.get("id")
            for module in report.get("modules") or []
            if any(str(path).endswith("libsoftokn3.so")
                   for path in (module.get("paths") or []))
        }
        self.assertGreater(
            len(browser_modules), 0, "browser softokn module missing")
        # v0.8.0 inventory-rss: exited callers fold into departed_use. The
        # browser exits before the report (context closed, observer runs to
        # duration), so its callers fold; live instances hold only the
        # background softhsm caller. Live browser instances (retained) or
        # folded firefox identities (exited) prove observation; both missing
        # means an empty capture.
        browser_instances = {
            instance.get("id")
            for instance in report.get("instances") or []
            if instance.get("module") in browser_modules
        }
        modules_by_id = {
            module.get("id"): module for module in report.get("modules") or []
        }
        folded_browser_idents = []
        for mid in browser_modules:
            departed = (modules_by_id.get(mid) or {}).get("departed_use") or {}
            for ident in departed.get("identities") or []:
                exe = ((ident.get("exe") or {}).get("path") or "").lower()
                if _folded_exe_names_firefox(exe):
                    folded_browser_idents.append(ident)
        if not browser_instances:
            self.assertGreater(
                len(folded_browser_idents), 0,
                "browser softokn instance missing (neither live nor folded)")
        # The shipped build carries the production journal, so a
        # `journal_unavailable` refusal is only valid when the binary
        # under test proves it omits the journal (doctor's
        # `journal pair preflight` row reads `not in this build`); on
        # a journal-carrying build the same observation is a journal
        # regression and fails. The pinned refusal shape (status
        # unavailable, zero rows, the named build cause, no lost
        # events) is judged by the shared helper, with twins below.
        if observations.get("reason") == "journal_unavailable":
            judge_key_observations_journal_branch(
                observations, report,
                journal_omitted=observer_omits_journal())
            return
        # Name the cause on failure: every Joint birth refusal (caller,
        # reason, repeats) and the observation gaps, so a CI miss says
        # whether a birth was refused or never offered.
        birth_refusals = sorted(
            (str(gap.get("caller")), str(gap.get("reason")),
             gap.get("repeats", 1))
            for gap in report.get("gaps") or []
            if isinstance(gap, dict)
            and gap.get("subject") == "Joint birth unavailable; retained S1")
        # Ruled contract: folded browsers (exited before Joint birth,
        # or folded after sealing rows) report partial with the named
        # live_joint_feed_absent reason beside retained rows; the folded
        # reason with no rows, or beside live instances that never got a
        # live feed, still means never covered. Bootstrap means no birth
        # ever seated, so zero retained rows: a rowed bootstrap pair is
        # refused, and a rowless one still means never covered. Both
        # literals stay inline for the observer-first wiring twin below.
        rows = observations.get("key_operations") or []
        reason = observations.get("reason")
        never_covered = (
            "late browser never covered (no live per-key tracking); "
            f"birth refusals={birth_refusals}; "
            f"observation gaps={observations.get('gaps')}")
        if reason == "live_joint_feed_absent":
            self.assertEqual(
                observations.get("status"), "partial",
                "live_joint_feed_absent must commit partial")
            if _bootstrap_cover_missing(rows, browser_instances):
                self.fail(never_covered)
        elif reason == "bootstrap_unavailable":
            self.assertEqual(
                len(rows), 0,
                "bootstrap_unavailable carries no retained rows; folded "
                "rows must commit partial/live_joint_feed_absent")
            self.fail(never_covered)
        self.assertGreater(len(rows), 0, "no key-operation rows at all")
        completed_signs = sum(
            row.get("completed", 0) for row in rows
            if row.get("category") == "sign")
        self.assertGreaterEqual(
            completed_signs, 1, "no completed client-cert signs observed")
        # Live leg: rows join to live browser instances (proven above).
        # Folded leg: rows reference folded instance IDs; the background
        # slot-lister never signs, so signs outside background instances
        # prove browser coverage with a folded browser (proven above).
        browser_rows = [row for row in rows
                        if row.get("instance") in browser_instances]
        if browser_instances:
            self.assertGreater(
                len(browser_rows), 0,
                "no key-operation rows on the browser instance")
        else:
            self.assertGreater(
                len(folded_browser_idents), 0,
                "no live browser rows and no folded browser callers")
            bg_instances = {
                instance.get("id")
                for instance in report.get("instances") or []
                if instance.get("module") not in browser_modules
            }
            bg_signs = [row for row in rows
                        if row.get("category") == "sign"
                        and row.get("instance") in bg_instances]
            self.assertEqual(
                len(bg_signs), 0,
                "background caller must not sign; signs prove browser")
            folded_signs = [row for row in rows
                            if row.get("category") == "sign"
                            and _folded_sign_instance_counts(row.get("instance"),
                                                             bg_instances)]
            self.assertGreater(
                len(folded_signs), 0,
                "no sign rows outside background instances")
        capture = (report.get("observation") or {}).get("semantic_capture") or {}
        self.assertEqual(capture.get("events_lost"), 0, "semantic events lost")
        # The settle gap is diagnostic, not a failure leg: seating over an
        # unchanged set is deliberately silent, so requiring the gap would
        # couple this cell to timing instead of the fix's guarantee (the
        # browser covered). When present, it must name its wait.
        settled = [gap for gap in report.get("gaps") or []
                   if isinstance(gap, dict)
                   and gap.get("subject") == "scan seal settled"]
        for gap in settled:
            self.assertIn(
                "waited", gap.get("reason") or "",
                "the settle gap does not name its wait")

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

    def _capture_launch_env(self, browser, register_module):
        """Launch ``browser`` against a fake Playwright; return its env.

        No browser, profiler, policy install (``auto_select_cert=False``),
        or NSS seeding (``nss_credential=None``): only the profile/HOME
        setup and the ``env=`` the real browser would inherit.
        """
        captured: dict = {}

        class FakeContext:
            def close(self):
                pass

        class FakeBrowserType:
            def launch_persistent_context(self, *args, **kwargs):
                captured["env"] = dict(kwargs.get("env") or {})
                return FakeContext()

        class FakePlaywright:
            def __init__(self):
                self.firefox = FakeBrowserType()
                self.chromium = FakeBrowserType()

        context, _match, _profile = cells.launch_browser_context(
            FakePlaywright(), browser, self.work / "cell",
            register_module=register_module, auto_select_cert=False,
            nss_credential=None)
        context.close()
        return captured["env"]

    def test_run_direct_chromium_tmpdir_fits_the_singleton_socket(self):
        """Twin: a deep cell must not hand Chromium a TMPDIR whose
        SingletonSocket path overflows ``sun_path`` (FATAL, SIGABRT on
        every launch); a shallow cell and Firefox keep ``workdir/tmp``."""
        deep = self.work / ("d" * 80) / "cell"
        deep.mkdir(parents=True)
        short = cells.child_tmpdir("chromium", deep)
        try:
            self.assertNotIn(deep, short.parents)
            self.assertTrue(short.is_dir())
            self.assertEqual(short.stat().st_mode & 0o777, 0o700)
            self.assertLessEqual(
                len(os.fsencode(short)) + len(cells.CHROMIUM_SOCKET_SUFFIX),
                cells.SUN_PATH_MAX)
        finally:
            shutil.rmtree(short, ignore_errors=True)
        self.assertEqual(cells.child_tmpdir("firefox", deep), deep / "tmp")
        shallow = self.work / "c"
        shallow.mkdir()
        if len(os.fsencode(shallow / "tmp")) + len(cells.CHROMIUM_SOCKET_SUFFIX) \
                <= cells.SUN_PATH_MAX:
            self.assertEqual(cells.child_tmpdir("chromium", shallow), shallow / "tmp")

    def _capture_run_direct_argv(self, **kwargs):
        """Run ``run_direct`` against a fake observer; return its argv.

        No browser, no profiler, no sudo: only the argv the real
        observer would inherit (firefox branch, so no NSS seeding).
        The firefox path is stubbed: these twins assert argv shape,
        never the resolved binary, so they run where no browser is
        installed.
        """
        captured: dict = {}

        def fake_run(argv, **_ignored):
            captured["argv"] = list(argv)
            return SimpleNamespace(returncode=0, stderr="")

        workdir = self.work / "cell"
        with patch("subprocess.run", side_effect=fake_run), \
                patch.object(cells, "p11scope_bin",
                             return_value=Path("/bin/p11scope")), \
                patch.object(cells, "firefox_binary",
                             return_value=Path("/bin/firefox")):
            cells.run_direct("PROBE", "firefox", workdir,
                             "http://127.0.0.1:1/", **kwargs)
        return captured["argv"]

    def test_run_direct_without_module_omits_narrowing(self):
        """Twin: observe_module=None discovers everything (no --module)."""
        argv = self._capture_run_direct_argv(observe_module=None)
        self.assertNotIn("--module", argv)
        self.assertIn("run", argv)

    def test_run_direct_with_module_narrows(self):
        """Guard: a named observe_module still narrows the scan."""
        module = Path("/probe-test/libsoft-test.so")
        argv = self._capture_run_direct_argv(observe_module=module)
        self.assertIn("--module", argv)
        at = argv.index("--module")
        self.assertEqual(argv[at + 1], str(module))

    def test_run_direct_prearm_modules_pin_each_file(self):
        """Twin: every prearm entry becomes one --prearm-module."""
        mods = (Path("/probe-test/a.so"), Path("/probe-test/b.so"))
        argv = self._capture_run_direct_argv(prearm_modules=mods)
        self.assertNotIn("--module", argv)
        for mod in mods:
            self.assertIn(str(mod), argv)
        self.assertEqual(argv.count("--prearm-module"), 2)

    def test_run_direct_initial_delay_prefix(self):
        """Twin: a spawn delay prefixes the supervisor argv; zero omits it."""
        argv = self._capture_run_direct_argv(initial_delay_seconds=15)
        at = next(i for i, arg in enumerate(argv)
                  if arg.endswith("reap_tree.py"))
        self.assertEqual(argv[at + 1:at + 3], ["--initial-delay", "15"])
        self.assertIn("--flow-done", argv[at + 3:])
        argv = self._capture_run_direct_argv()
        self.assertNotIn("--initial-delay", argv)

    def test_find_softokn_prefers_ldconfig_hits(self):
        """Twin: the resolver reads ldconfig first, then candidates."""
        hit = self.work / "lib" / "libsoftokn3.so"
        hit.parent.mkdir(parents=True)
        hit.write_bytes(b"probe-softokn")
        table = (
            "libc.so.6 (libc6,x86-64) => /usr/lib/libc.so.6\n"
            "libsoftokn3.so.1 (libc6,x86-64) => /usr/lib/libsoftokn3.so.1\n"
            f"libsoftokn3.so (libc6,x86-64) => {hit}\n"
            "malformed line without arrow\n"
        )
        self.assertEqual(
            cells.find_softokn(ldconfig_text=table, candidates=[]), hit)
        # A version-suffixed soname is a different file: no match.
        self.assertIsNone(cells.find_softokn(
            ldconfig_text="libsoftokn3.so.1 (libc6,x86-64) => /usr/lib/x\n",
            candidates=[]))
        # ...even when the suffixed file exists (a substring match
        # would resolve the wrong provider here).
        suffixed = self.work / "sfx" / "libsoftokn3.so.1"
        suffixed.parent.mkdir(parents=True)
        suffixed.write_bytes(b"probe-suffixed")
        self.assertIsNone(cells.find_softokn(
            ldconfig_text=f"libsoftokn3.so.1 (libc6,x86-64) => {suffixed}\n",
            candidates=[]))
        # Order pin: with an existing hit AND an existing candidate,
        # the ldconfig hit wins (a candidates-first mutant resolves
        # the candidate here).
        cand = self.work / "ord" / "libsoftokn3.so"
        cand.parent.mkdir(parents=True)
        cand.write_bytes(b"probe-candidate")
        self.assertEqual(
            cells.find_softokn(ldconfig_text=table,
                               candidates=[str(cand)]),
            hit)

    def test_attached_run_gaps_exact(self):
        """Twin: the run-floor gap set passes calibrated causes only."""
        # Membership pin: the behavioral legs below build their passing
        # doc from the set itself, so a widening mutant (an 8th cause)
        # would stay green without this literal.
        self.assertEqual(_GAPS_ATTACHED_RUN, frozenset({
            "loader_discovery", "unprotected_live_windows",
            "pid_descendant_gaps", "task_uprobe_link_losses",
            "discovery_truncated", "skipped", "interface_selection",
        }))
        doc = {"evidence": {"gap_classes": {"observation": {
            "status": "lossy", "causes": sorted(_GAPS_ATTACHED_RUN)}}}}
        self.assertEqual(
            oracle.check_observation_gaps(doc, _GAPS_ATTACHED_RUN), [])
        doc["evidence"]["gap_classes"]["observation"]["causes"].append(
            "capture_halted")
        self.assertNotEqual(
            oracle.check_observation_gaps(doc, _GAPS_ATTACHED_RUN), [])

    def test_find_softokn_falls_back_to_candidates(self):
        """Twin: missing hits fall through to candidates, then None."""
        cand = self.work / "cand" / "libsoftokn3.so"
        cand.parent.mkdir(parents=True)
        cand.write_bytes(b"probe-softokn")
        missing = self.work / "nope" / "libsoftokn3.so"
        table = f"libsoftokn3.so (libc6,x86-64) => {missing}\n"
        self.assertEqual(
            cells.find_softokn(ldconfig_text=table,
                               candidates=[str(missing), str(cand)]),
            cand)
        self.assertIsNone(cells.find_softokn(
            ldconfig_text=table, candidates=[str(missing)]))
        self.assertIsNone(
            cells.find_softokn(ldconfig_text="", candidates=[]))

    def test_find_softokn_survives_ldconfig_failure(self):
        """Twin: an ldconfig failure/timeout falls back to candidates."""
        cand = self.work / "fb" / "libsoftokn3.so"
        cand.parent.mkdir(parents=True)
        cand.write_bytes(b"probe-softokn")
        for failure in (OSError("no ldconfig"),
                        subprocess.TimeoutExpired("ldconfig", 30)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(cells.subprocess, "run",
                                  side_effect=failure):
                    self.assertEqual(
                        cells.find_softokn(
                            ldconfig_text=None,
                            candidates=[str(cand)]),
                        cand)
        # A nonzero ldconfig exit reads as an empty table (same
        # fallback): the decoy stdout names a *different* existing
        # provider, so a mutant that trusts stdout on failure
        # resolves the decoy and this leg fails = killed (empty
        # stdout would agree with the mutant and prove nothing).
        # Two nonzero codes pin `returncode == 0`, not `!= 1`.
        decoy = self.work / "decoy" / "libsoftokn3.so"
        decoy.parent.mkdir(parents=True)
        decoy.write_bytes(b"probe-decoy")
        decoy_table = f"libsoftokn3.so (libc6,x86-64) => {decoy}\n"
        for code in (1, 2):
            with self.subTest(returncode=code):
                with patch.object(cells.subprocess, "run",
                                  return_value=SimpleNamespace(
                                      returncode=code,
                                      stdout=decoy_table)):
                    self.assertEqual(
                        cells.find_softokn(ldconfig_text=None,
                                           candidates=[str(cand)]),
                        cand)

    def test_missing_nss_seed_tools_names_absent_tools(self):
        """Twin: the NSS-seed gate names exactly the tools absent from PATH."""
        with patch.object(cells.shutil, "which",
                          return_value="/usr/bin/x"):
            self.assertEqual(cells.missing_nss_seed_tools(), [])
        with patch.object(cells.shutil, "which", return_value=None):
            self.assertEqual(cells.missing_nss_seed_tools(),
                             ["certutil", "pk12util"])

        def which(tool):
            return None if tool == "pk12util" else f"/usr/bin/{tool}"

        with patch.object(cells.shutil, "which", side_effect=which):
            self.assertEqual(cells.missing_nss_seed_tools(), ["pk12util"])

    def test_launch_without_registered_module_scrubs_store_env(self):
        """Twin: an unregistered launch must not leak SOFTHSM2_CONF.

        Chromium always maps the system-registered SoftHSM module via
        p11-kit; when the browser inherits SOFTHSM2_CONF pointing at a
        store whose token holds a client certificate, that PIN-locked
        cert joins the selection set and auto-presentation stalls
        (fedora: presented=0 with the variable exported, presented>=1
        without, identical harness). A launch with no registered
        module needs no store pointer, so both browsers must scrub it.
        """
        sentinel = str(self.work / "bg-store" / "softhsm.conf")
        with patch.dict(os.environ, {"SOFTHSM2_CONF": sentinel}):
            for browser in ("firefox", "chromium"):
                with self.subTest(browser=browser):
                    env = self._capture_launch_env(browser, None)
                    # Fixed message: never echo the captured env (values).
                    if "SOFTHSM2_CONF" in env:
                        self.fail(
                            f"{browser} inherits a store pointer with no "
                            f"module registered (client-cert selection "
                            f"poisoned)")

    def test_launch_with_registered_module_keeps_store_env(self):
        """Guard: a registered launch keeps its SOFTHSM2_CONF (no over-scrub).

        The attach-drive PKCS#11 cells register the SoftHSM module in
        the fresh profile and point the browser at its store on
        purpose; the scrub must only apply to unregistered launches.
        """
        sentinel = str(self.work / "cell-store" / "softhsm.conf")
        module = self.work / "cell-store" / "libsofthsm2.so"
        with patch.dict(os.environ, {"SOFTHSM2_CONF": sentinel}):
            for browser in ("firefox", "chromium"):
                with self.subTest(browser=browser):
                    env = self._capture_launch_env(browser, module)
                    # Fixed message: never echo the captured env (values).
                    if env.get("SOFTHSM2_CONF") != sentinel:
                        self.fail(
                            f"{browser} lost the store pointer its "
                            f"registered module needs")

    def _run_readiness_probe(self, marker_delay, grace_seconds=2):
        """Run attach_drive against a scripted profiler.

        The fake profiler prints its readiness marker after
        ``marker_delay`` seconds; the grace period is ``grace_seconds``
        (2s by default, so a long delay means the marker never
        arrives). Target liveness is valid synthetic liveness, so
        readiness is the only possible failure source. Returns the
        flow's ``started`` dict, the CellError raised (None when the
        cell ran), and the harness stderr captured during the run.
        Uses a fake Playwright module and a fake profiler process:
        stdlib only.
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
                     "p11scope: capturing: 136 probes attached; stop with Ctrl-C\n"),
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
        captured = io.StringIO()
        with redirect_stderr(captured), \
                patch.dict(sys.modules, {"playwright": SimpleNamespace(),
                                         "playwright.sync_api": fake_sync}), \
                patch("subprocess.Popen", FakePopen), \
                patch.object(cells, "main_browser_pid", return_value=os.getpid()), \
                patch.object(cells, "_target_liveness", return_value=(True, True)), \
                patch.object(cells, "p11scope_bin", return_value=Path("/fake/p11scope")):
            try:
                cells.attach_drive(
                    "TWIN-READY", "firefox", self.work / "cell", "https://127.0.0.1:1/",
                    flow, Path("definitely-not-mapped-xyz.so"),
                    duration_seconds=5, attach_grace_seconds=grace_seconds)
            except cells.CellError as exc:
                return started, exc, captured.getvalue()
            return started, None, captured.getvalue()

    def test_navigation_waits_for_capture_readiness(self):
        """P2-4 twin: navigation must not start before capture readiness.

        The scripted profiler never prints its readiness marker inside
        the grace period; the flow must never run and the cell must fail
        with a readiness-specific error.
        """
        started, error, _stderr = self._run_readiness_probe(marker_delay=30.0)
        self.assertIsNotNone(error, "cell passed without capture readiness")
        assert error is not None
        self.assertIn("never became ready", str(error),
                      f"cell failed for the wrong reason: {error}")
        self.assertFalse(started.get("ran", False),
                         "navigation started before capture readiness")

    def test_capture_readiness_marker_arrives_runs_flow(self):
        """Control: when the marker arrives promptly, navigation runs."""
        started, error, _stderr = self._run_readiness_probe(marker_delay=0.1)
        self.assertIsNone(error, f"marker arrived yet the cell failed: {error}")
        self.assertTrue(started.get("ran", False),
                        "navigation never ran after capture readiness")

    def test_slow_attach_logs_a_regression_warning(self):
        """Readiness past the original 5s bound warns but still passes.

        The strict bound is measured (15s); the original 5s stays a
        logged regression signal, not a silent pass.
        """
        started, error, stderr = self._run_readiness_probe(
            marker_delay=6.0, grace_seconds=15)
        self.assertIsNone(error, f"slow-but-bounded attach failed: {error}")
        self.assertTrue(started.get("ran", False),
                        "navigation never ran after slow readiness")
        self.assertIn("slow attach", stderr,
                      "slow attach left no regression warning")
        self.assertIn(
            f"past the {cells.SLOW_ATTACH_WARN_SECONDS:g}s regression signal",
            stderr,
            "warning does not name the original bound")

    def test_fast_attach_logs_no_regression_warning(self):
        """Control: a fast attach stays silent (no warning spam)."""
        started, error, stderr = self._run_readiness_probe(
            marker_delay=0.1, grace_seconds=15)
        self.assertIsNone(error, f"fast attach failed: {error}")
        self.assertTrue(started.get("ran", False),
                        "navigation never ran after fast readiness")
        self.assertNotIn("slow attach", stderr,
                         f"fast attach warned spuriously: {stderr!r}")

    def test_attach_grace_default_is_the_measured_bound(self):
        """The harness default is the measured 15s bound, in one place."""
        default = inspect.signature(cells.attach_drive).parameters[
            "attach_grace_seconds"].default
        self.assertEqual(default, 15)
        self.assertEqual(default, cells.ATTACH_GRACE_SECONDS)

    def test_slow_attach_threshold_preserves_the_original_bound(self):
        """The 5s regression signal survives as a named threshold."""
        self.assertEqual(cells.SLOW_ATTACH_WARN_SECONDS, 5)

    def test_strict_attach_sites_reference_the_ruled_bound(self):
        """All strict sites use cells.ATTACH_GRACE_SECONDS, never a literal."""
        violations = strict_attach_grace_literals(Path(__file__).read_text())
        self.assertEqual(violations, [])

    def test_capture_ready_parsing(self):
        """Unit: the readiness marker parses to its attached-probe count."""
        self.assertEqual(
            cells._parse_capture_ready(
                "p11scope: capturing: 136 probes attached; stop with Ctrl-C"), 136)
        self.assertEqual(
            cells._parse_capture_ready(
                "p11scope: capturing: 1 probe attached; stop with Ctrl-C"), 1)
        self.assertIsNone(cells._parse_capture_ready(
            "p11scope: capturing: waiting for a provider to load; stop with Ctrl-C"))
        self.assertIsNone(cells._parse_capture_ready(
            "p11scope: loader readiness: 1 active hook(s)"))
        self.assertIsNone(cells._parse_capture_ready("unrelated line"))

    def test_soft_call_stop_parsing(self):
        """Unit: the bg caller's STOP line parses to its completed calls."""
        self.assertEqual(
            cells.soft_call_completed(
                "READY module=m interval=1 pid=1\nCALLS n=30 last_rv=0 slots=1\n"
                "STOP n=87\n"),
            87)
        self.assertIsNone(cells.soft_call_completed(
            "READY module=m interval=1 pid=1\n"))
        self.assertIsNone(cells.soft_call_completed("INIT rv=3\n"))

    def test_observer_first_waits_for_capture_ready(self):
        """Unit: the observer-first wait returns on pass 0, fails loud."""
        err = self.work / "observer.err"
        err.write_text("p11scope: pass 0: 6 scanned (0 native, 6 scan-pinned)\n")
        running = SimpleNamespace(poll=lambda: None, returncode=None)
        cells.wait_for_observer_line(
            err, running, "p11scope: pass 0:", 5.0, "capture")
        exited = SimpleNamespace(poll=lambda: 1, returncode=1)
        with self.assertRaises(cells.CellError):
            cells.wait_for_observer_line(
                err, exited, "p11scope: pass 0:", 5.0, "capture")
        with self.assertRaises(cells.CellError):
            cells.wait_for_observer_line(
                err, running, "p11scope: never:", 0.0, "capture")

    def test_oracle_builder_healthy_accepted(self):
        """Guard: the twin builder's healthy doc passes the common oracle."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        result = self._twin_result("TWIN-HEALTHY", rows, self._twin_evidence())
        with patch.object(oracle, "sha256_of", return_value=sha):
            self.check_report(result, store, {"C_FindObjects": 1}, attached=True)

    def test_run_tree_descendant_gap_allowed_for_never_mapped_run(self):
        """Run-tree twin: a never-mapped run report whose owned browser
        retired short-lived descendants between admission passes keeps
        its zero: the honest pid_descendant_gaps cause is allowed for
        the run-mode never-mapped cells."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        evidence = self._twin_evidence(
            attached_probes=0,
            verdict_detail="concrete_gap",
            gap_classes={"observation": {
                "status": "lossy",
                "causes": ["discovery", "slots", "skipped",
                           "pid_descendant_gaps"],
            }},
        )
        result = self._twin_result("TWIN-NEVER-MAPPED-RUN", [], evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            self.check_report(result, store, zero=True, attached=False,
                              allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                              allowed_verdicts=_VERDICTS_NEVER_MAPPED)

    def _twin_nomod_result(self, name, rows, evidence):
        """A never-mapped-run twin document with the S1 sections present.

        FF-NOMOD opts into the S1 proof with ``sessions_zero``, so the
        twin carries empty mechanisms/logins and zeroed session counters
        beside the given rows and evidence.
        """
        result = self._twin_result(name, rows, evidence)
        doc = json.loads(result.report_path.read_text())
        doc["mechanisms"] = []
        doc["logins"] = {}
        doc["sessions"] = {counter: 0 for counter in oracle.SESSION_COUNTERS}
        result.report_path.write_text(json.dumps(doc))
        return result

    def _twin_nomod_observation(self, extra_causes=()):
        """The live FF-NOMOD residual shape: structural/run-mode causes.

        Mirrors the observed-profile evidence of the mid-flow link-loss
        residual (zero rows, zero probes): every cause but the named
        link loss is in _GAPS_NEVER_MAPPED_RUN; ``extra_causes`` plants
        hostile additions.
        """
        return {
            "status": "lossy",
            "causes": ["discovery", "slots", "skipped",
                       "task_uprobe_link_losses", "pause_partial",
                       "loader_discovery", "pid_descendant_gaps",
                       *extra_causes],
        }

    def test_nomod_qualified_link_loss_accepted(self):
        """FF-NOMOD twin: the sole named link loss is qualified (ruling).

        Zero rows, zero attached probes, and no other gap cause: the
        task-level exit-tracking loss on a run-tree member does not
        touch the asserted never-mapped property, so the cell passes.
        """
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        evidence = self._twin_evidence(
            attached_probes=0,
            verdict_detail="concrete_gap",
            gap_classes={"observation": self._twin_nomod_observation()},
        )
        result = self._twin_nomod_result("TWIN-NOMOD-LINK-LOSS", [], evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            self.check_report(result, store, zero=True, attached=False,
                              allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                              allowed_verdicts=_VERDICTS_NEVER_MAPPED,
                              s1={"sessions_zero": True},
                              qualify_nomod_link_loss=True)

    def test_nomod_qualified_link_loss_rejects_attached(self):
        """FF-NOMOD twin: the qualification needs zero attached probes."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        evidence = self._twin_evidence(
            attached_probes=1,
            verdict_detail="concrete_gap",
            gap_classes={"observation": self._twin_nomod_observation()},
        )
        result = self._twin_nomod_result("TWIN-NOMOD-ATTACHED", [], evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, zero=True, attached=False,
                                  allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                                  allowed_verdicts=_VERDICTS_NEVER_MAPPED,
                                  s1={"sessions_zero": True},
                                  qualify_nomod_link_loss=True)

    def test_nomod_qualified_link_loss_rejects_rows(self):
        """FF-NOMOD twin: the qualification needs zero rows.

        The planted row carries no calls, so the zero-count check would
        pass on its own: only the gate's zero-rows prong fails the cell.
        """
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 0, sha)]
        evidence = self._twin_evidence(
            attached_probes=0,
            verdict_detail="concrete_gap",
            gap_classes={"observation": self._twin_nomod_observation()},
        )
        result = self._twin_nomod_result("TWIN-NOMOD-ROWS", rows, evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, zero=True, attached=False,
                                  allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                                  allowed_verdicts=_VERDICTS_NEVER_MAPPED,
                                  s1={"sessions_zero": True},
                                  qualify_nomod_link_loss=True)

    def test_nomod_qualified_link_loss_rejects_extra_gap(self):
        """FF-NOMOD twin: the qualification needs no other gap cause."""
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        evidence = self._twin_evidence(
            attached_probes=0,
            verdict_detail="concrete_gap",
            gap_classes={"observation": self._twin_nomod_observation(
                ["in_flight_at_end"])},
        )
        result = self._twin_nomod_result("TWIN-NOMOD-EXTRA", [], evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, zero=True, attached=False,
                                  allowed_gaps=_GAPS_NEVER_MAPPED_RUN,
                                  allowed_verdicts=_VERDICTS_NEVER_MAPPED,
                                  s1={"sessions_zero": True},
                                  qualify_nomod_link_loss=True)

    def test_attached_cell_still_rejects_link_loss(self):
        """P2-3 twin: the same gap on another cell still fails closed.

        An attached floor cell never passes the FF-NOMOD qualification,
        so the named link loss fails there exactly as before.
        """
        sha = "0" * 64
        store = SimpleNamespace(lib=Path("/not-opened/provider.so"))
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        evidence = self._twin_evidence(
            verdict_detail="concrete_gap",
            gap_classes={"observation": {
                "status": "lossy",
                "causes": ["loader_discovery", "task_uprobe_link_losses"],
            }},
        )
        result = self._twin_result("TWIN-ATTACHED-LINK-LOSS", rows, evidence)
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                self.check_report(result, store, {"C_FindObjects": 1},
                                  attached=True,
                                  allowed_gaps=_GAPS_ATTACHED_FLOOR)

    def test_nomod_link_loss_gate_prongs(self):
        """Unit: each qualification prong decides on its own.

        The honest report passes the gate; flipping any one prong
        (probes, rows, an extra cause, a missing observation block)
        fails it, independent of the surrounding cell checks.
        """
        def gate_report(**overrides):
            report = {
                "functions": [],
                "evidence": {
                    "attached_probes": 0,
                    "gap_classes": {
                        "observation": {
                            "status": "lossy",
                            "causes": ["discovery", "slots", "skipped",
                                       "task_uprobe_link_losses"],
                        },
                    },
                },
            }
            report["evidence"].update(overrides.pop("evidence", {}))
            report.update(overrides)
            return report

        allowed = {"discovery", "slots", "skipped"}
        self.assertEqual(
            oracle.check_observation_gaps_nomod_qualified(
                gate_report(), allowed), [])
        hostile = {
            "attached": gate_report(evidence={"attached_probes": 1,
                "gap_classes": {"observation": {
                    "status": "lossy",
                    "causes": ["discovery", "slots", "skipped",
                               "task_uprobe_link_losses"]}}}),
            "rows": gate_report(functions=[{"names": ["C_GetInfo"]}]),
            "extra": gate_report(evidence={"attached_probes": 0,
                "gap_classes": {"observation": {
                    "status": "lossy",
                    "causes": ["discovery", "slots", "skipped",
                               "task_uprobe_link_losses",
                               "in_flight_at_end"]}}}),
            "missing": gate_report(evidence={"attached_probes": 0,
                                             "gap_classes": {}}),
        }
        for label, report in hostile.items():
            with self.subTest(label):
                self.assertNotEqual(
                    oracle.check_observation_gaps_nomod_qualified(
                        report, allowed), [])

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

    def test_multi_sha_open_entries_aggregate_for_absences(self):
        """Twin: in-flight entries sum across the pair for absence legs.

        C_Login enters-but-never-returns once on each sha of a
        copy-up pair; the absence leg must see the summed 2 and fail.
        Dropping the opened aggregation loop (``opened`` stays {})
        would pass blind.
        """
        sha = "ab" * 32
        sha2 = "cd" * 32
        rows = [self._twin_row(["C_Login"], 0, sha, in_flight=1),
                self._twin_row(["C_Login"], 0, sha2, in_flight=1)]
        result = self._twin_result("TWIN-MULTISHA-OPEN", rows,
                                   self._twin_evidence())
        with self.assertRaises(AssertionError):
            self.check_report(result, None, attached=True,
                              module_sha={sha, sha2},
                              absent=("C_Login",))

    def test_check_report_duplicate_rows_sum_within_sha(self):
        """Twin: duplicate same-sha rows sum under one floor.

        C_Sign completes once in each of two rows attached to the
        same sha (a retired-and-reattached target contributes one
        row per cell); the floor of 2 passes. An overwrite mutant
        in the per-sha counts loop leaves 1 and fails
        deterministically (row order cannot matter: 1+1 leaves 1
        either way).
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_Sign"], 1, sha),
                self._twin_row(["C_Sign"], 1, sha)]
        result = self._twin_result("TWIN-DUPROWS", rows,
                                   self._twin_evidence())
        self.check_report(result, None, {"C_Sign": 2}, attached=True,
                          module_sha={sha})

    def test_check_report_duplicate_open_entries_ordered_absence(self):
        """Twin: ordered duplicate open entries fail the absence leg.

        Two same-sha C_Login rows ordered [in_flight=1,
        in_flight=0]; the summed 1 enters the absence leg, which
        fails. An overwrite mutant in the per-sha opened loop
        leaves the trailing 0, the absence passes, and the
        assertRaises fails = killed. Row order is list order
        (deterministic), not set order.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_Login"], 0, sha, in_flight=1),
                self._twin_row(["C_Login"], 0, sha, in_flight=0)]
        result = self._twin_result("TWIN-DUPOPEN", rows,
                                   self._twin_evidence())
        with self.assertRaises(AssertionError):
            self.check_report(result, None, attached=True,
                              module_sha={sha},
                              absent=("C_Login",))

    def test_aggregate_module_counts_sums_exactly_across_pair(self):
        """Twin: cross-sha counts and opened sum exactly (== 2, == 2).

        C_Login completes once and enters-but-never-returns once on
        each sha of a copy-up pair; the helper returns exactly
        ``({"C_Login": 2}, {"C_Login": 2})``. An overwrite mutant on
        either loop leaves 1, a dropped loop leaves {} — each
        fails deterministically regardless of set order (no
        absent-leg twin can pin the opened sum: zero-vs-nonzero is
        all the absence leg distinguishes).
        """
        sha = "ab" * 32
        sha2 = "cd" * 32
        doc = {"functions": [
            self._twin_row(["C_Login"], 1, sha, in_flight=1),
            self._twin_row(["C_Login"], 1, sha2, in_flight=1)]}
        counts, opened = aggregate_module_counts(doc, {sha, sha2})
        self.assertEqual(counts, {"C_Login": 2})
        self.assertEqual(opened, {"C_Login": 2})

    def test_module_counts_sums_exactly_within_sha(self):
        """Twin: same-sha completed rows sum exactly (== 2).

        Two rows with one completed C_Sign each under one sha
        return exactly ``{"C_Sign": 2}``. Overwrite, first-wins,
        last-wins, and max mutants each leave 1 and fail; a dropped
        row leaves 1 the same way. Row order cannot matter (1+1).
        """
        sha = "ab" * 32
        doc = {"functions": [
            self._twin_row(["C_Sign"], 1, sha),
            self._twin_row(["C_Sign"], 1, sha)]}
        self.assertEqual(oracle.module_counts(doc, sha), {"C_Sign": 2})

    def test_module_open_entries_sums_exactly_within_sha(self):
        """Twin: same-sha open entries sum exactly (== 2).

        Two rows with one in-flight C_Login each under one sha
        return exactly ``{"C_Login": 2}``. The ordered-absence twin
        pins overwrite ([1, 0] leaves a trailing 0) but cannot tell
        sum from max or first-wins on that pair; this exact twin
        kills every non-summing reducer ([1, 1] leaves 1 under each).
        """
        sha = "ab" * 32
        doc = {"functions": [
            self._twin_row(["C_Login"], 0, sha, in_flight=1),
            self._twin_row(["C_Login"], 0, sha, in_flight=1)]}
        self.assertEqual(
            oracle.module_open_entries(doc, sha), {"C_Login": 2})

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
        # A healthy FF-PINBOUND report earns clean_proven (standard-layout
        # verification without a manifest); the rig simulates the live cell,
        # so its synthetic evidence carries the same verdict the cell pins.
        result = self._twin_result(
            "FF-PINBOUND", rows,
            self._twin_evidence(verdict_detail="clean_proven"))
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
            "cert_refusals": 0,
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

    def test_pinbound_refusal_after_cert_request_accepted(self):
        """Twin: a CertificateRequest-backed client refusal witnesses selection.

        Chromium answers the received CertificateRequest with a fatal
        certificate_unknown alert (fail-fast refusal) instead of
        stalling; the alert after affirmative CertificateRequest
        progress witnesses selection like the empty cert and the stall.
        Shape mirrors the live CR-PINBOUND run (3 hellos, 3
        CertificateRequests, 2 refusals, 1 abandon, hung navigation).
        """
        self._pinbound_rig(
            self._pinbound_stats(
                connections=3, client_hello_complete=3, cert_requests_sent=3,
                client_cert_alerts=2, cert_refusals=2, abandoned=1,
                selection_stalls=0, empty_certs=0),
            self._pinbound_timeout_facts())

    def test_pinbound_rejects_bare_alert_without_cert_request(self):
        """Twin: alerts without CertificateRequest progress stay insufficient.

        A client that aborts before the server's CertificateRequest
        flight went out never reached selection; bare alerts must not
        become a witness (anti-over-acceptance for the refusal leg).
        """
        stats = self._pinbound_stats(
            client_hello_complete=1, client_cert_alerts=2, cert_refusals=0,
            cert_requests_sent=0)
        with self.assertRaises(AssertionError):
            self._pinbound_rig(stats, self._pinbound_timeout_facts())

    def test_pinbound_rejects_refusal_without_cert_request(self):
        """Twin: a refusal without CertificateRequest progress must fail the cell.

        The server ties a refusal to an observed outbound
        CertificateRequest on the same connection; the assertion must
        enforce that tie fail-closed (symmetric with the stall leg),
        so a refusal without that proof never witnesses selection.
        """
        stats = self._pinbound_stats(
            client_hello_complete=1, client_cert_alerts=1, cert_refusals=1,
            cert_requests_sent=0)
        with self.assertRaises(AssertionError):
            self._pinbound_rig(stats, self._pinbound_timeout_facts())

    def test_pinbound_rig_healthy_accepted(self):
        """Guard: the rig passes with a boundary witness (no over-reject)."""
        self._pinbound_rig(
            self._pinbound_stats(empty_certs=1, abandoned=0, client_hello_complete=1),
            self._pinbound_facts())

    def _crrunsign_rig(self, rows, mechanisms, presented, handshakes,
                       extra=None):
        """Run the real CR-RUN-SIGN cell against synthetic report+server.

        Mocks the gate, the credential/server factories, and the
        browser drive (following _pinbound_rig); the cell body, its
        TLS ground-truth asserts, and its check_report composition
        run for real. Returns (drive_mock, softokn, cred) so twins
        pin the drive arguments too. ``extra`` adds top-level
        report sections (the no-sign twin needs ``logins: {}`` so
        the absence legs of a gutted cell would pass).
        """
        sha = "ab" * 32
        evidence = self._twin_evidence(
            verdict_detail="concrete_gap",
            gap_classes={"observation": {
                "status": "lossy",
                "causes": sorted(_GAPS_ATTACHED_RUN)}},
            discovery=[{"path": "/usr/lib64/libsoftokn3.so",
                        "sha256": sha, "dev": [0, 40], "ino": 11}],
            skipped=[])
        result = self._twin_result("CR-RUN-SIGN", rows, evidence)
        doc = json.loads(result.report_path.read_text())
        doc.update({"mechanisms": mechanisms,
                    "sessions": healthy_sessions()})
        if extra:
            doc.update(extra)
        result.report_path.write_text(json.dumps(doc))
        softokn = Path("/fake-nss/libsoftokn3.so")
        cred = SimpleNamespace(cert_pem=Path("/fake-nss/client.pem"))
        server = SimpleNamespace(
            url="https://127.0.0.1:1/",
            client_certs_presented=presented, handshakes_ok=handshakes)
        entered = MagicMock()
        entered.__enter__.return_value = server
        fake = cells.CellResult(
            "CR-RUN-SIGN", result.report_path, screenshot_bytes=7,
            flow={"observer_exit": 0, "nss_seeded": True,
                  "auto_select_policy": True},
            observer_stderr_tail="")
        case = BrowserCells("test_cr_run_sign_observes_client_cert_signs")
        case.work = self.work
        with patch.object(cells, "preflight", return_value=None), \
                patch.object(cells, "find_softokn",
                             return_value=softokn), \
                patch.object(cells, "missing_nss_seed_tools",
                             return_value=[]), \
                patch.object(softhsm, "generate_client_credential",
                             return_value=cred), \
                patch.object(tls_server, "make_server_credential",
                             return_value=(Path("/fake/key"),
                                           Path("/fake/cert"))), \
                patch.object(tls_server, "FlowServer",
                             return_value=entered), \
                patch.object(cells, "run_direct",
                             return_value=fake) as drive:
            case.test_cr_run_sign_observes_client_cert_signs()
        return drive, softokn, cred

    @staticmethod
    def _crrunsign_mechanism(sha, calls=1):
        """One RSA-family mechanisms[] row attributed to ``sha``."""
        return {"mechanism": 0x40, "mechanism_hex": "0x40",
                "ops": ["sign"], "calls": calls, "errors": 0,
                "by_module": [{"module": {"dev": [1, 2], "ino": 3,
                                          "sha256": sha},
                               "calls": calls, "errors": 0}]}

    def test_crrunsign_rig_healthy_sign_passes(self):
        """Twin: the real CR cell passes a healthy sign report + server.

        Both proof legs hold (completed C_SignInit/C_Sign rows plus
        an attributed RSA-family mechanism) beside TLS ground truth,
        so the cell passes; the captured drive call pins the
        targeting, timing, and policy composition (softokn module,
        15 s spawn delay, chromium policy, wired credential).
        Deleting the s1 sign branch (s1={}) fires the absence legs
        on the healthy mechanisms and fails here = killed, as does
        any dropped or retuned drive argument below.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_SignInit"], 1, sha),
                self._twin_row(["C_Sign"], 1, sha)]
        drive, softokn, cred = self._crrunsign_rig(
            rows, [self._crrunsign_mechanism(sha)], 1, 1)
        self.assertEqual(drive.call_count, 1)
        args, kwargs = drive.call_args
        self.assertEqual(args[0], "CR-RUN-SIGN")
        self.assertEqual(args[1], "chromium")
        self.assertEqual(kwargs["observe_module"], softokn)
        self.assertIsNone(kwargs["register_module"])
        self.assertIsNone(kwargs["browser_env"])
        self.assertEqual(kwargs["extra_browser_args"],
                         CHROMIUM_STABLE_ARGS)
        self.assertEqual(kwargs["duration_seconds"], RUN_DURATION)
        self.assertIs(kwargs["nss_credential"], cred)
        self.assertTrue(kwargs["auto_select_cert"])
        self.assertEqual(kwargs["initial_delay_seconds"], 15)

    def test_crrunsign_rig_no_sign_fails(self):
        """Twin: the real CR cell fails a sign-less report (both legs).

        Discovery still resolves the provider and TLS still saw a
        handshake, but no sign rows and no attributed mechanisms
        exist: the floors and the family leg fail together. A cell
        gutted of both (floors {} plus s1={}) passes this doc —
        the empty mechanisms/logins sections satisfy the absence
        legs — so the assertRaises fails = killed.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        with self.assertRaises(AssertionError):
            self._crrunsign_rig(rows, [], 1, 1, extra={"logins": {}})

    def test_crrunsign_rig_no_tls_ground_truth_fails(self):
        """Twin: the real CR cell fails without TLS ground truth.

        The report holds full sign proof, but the server saw no
        presented cert and no handshake: the ground-truth asserts
        fail first. Deleting them lets this doc pass = killed.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_SignInit"], 1, sha),
                self._twin_row(["C_Sign"], 1, sha)]
        with self.assertRaises(AssertionError):
            self._crrunsign_rig(
                rows, [self._crrunsign_mechanism(sha)], 0, 0)

    def test_crrunsign_rig_unattributed_mechanism_fails(self):
        """Twin: sign rows with an elsewhere-attributed mechanism fail.

        The family leg counts only by_module calls on the resolved
        provider shas; a mechanism attributed to another module
        fails it. Dropping the whole s1 proof (s1=None) skips that
        leg and this doc passes on floors alone = killed.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_SignInit"], 1, sha),
                self._twin_row(["C_Sign"], 1, sha)]
        with self.assertRaises(AssertionError):
            self._crrunsign_rig(
                rows, [self._crrunsign_mechanism("cd" * 32)], 1, 1)

    def test_crrunsign_rig_mechanism_without_rows_fails(self):
        """Twin: an attributed mechanism without sign rows fails the cell.

        The doc is deliberately inconsistent (mechanisms claim
        attributed signs, functions carry none) to isolate the
        floors leg: only it fails here. Deleting the floors lets
        this doc pass on the family leg alone = killed.
        """
        sha = "ab" * 32
        rows = [self._twin_row(["C_FindObjects"], 3, sha)]
        with self.assertRaises(AssertionError):
            self._crrunsign_rig(
                rows, [self._crrunsign_mechanism(sha)], 1, 1)

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

    def test_flow_server_survives_garbage_peer(self):
        """Twin: a non-TLS peer must not kill the flow server.

        The garbage connection is recorded as an unrelated protocol
        failure; the acceptor must keep serving afterwards (no dead
        serve_forever thread, no follow-up request left hanging).
        Stdlib sockets plus one real TLS client.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        thread_errors: list = []
        previous_hook = threading.excepthook
        threading.excepthook = thread_errors.append
        try:
            with tls_server.FlowServer(cert=cert, key=key) as flow:
                raw = socket.create_connection(("127.0.0.1", flow.port))
                try:
                    raw.sendall(b"GARBAGE-NOT-TLS")
                finally:
                    raw.close()
                deadline = time.monotonic() + 10
                while flow.handshake_failures == 0 and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(flow.handshake_failures, 1)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection(("127.0.0.1", flow.port))
                sock.settimeout(10)
                with context.wrap_socket(sock, server_hostname="127.0.0.1") as peer:
                    peer.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    body = b""
                    try:
                        while b"g33-flow-ok" not in body:
                            chunk = peer.recv(4096)
                            if not chunk:
                                break
                            body += chunk
                    except TimeoutError:
                        self.fail("flow server died on the garbage peer: "
                                  "follow-up request never answered")
                self.assertIn(b"g33-flow-ok", body)
                self.assertEqual(flow.requests_served, 1)
        finally:
            threading.excepthook = previous_hook
        self.assertEqual(thread_errors, [],
                         "flow server thread died on the garbage peer")

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

        A real TLS 1.3 ClientHello (built in memory) goes out over a plain
        socket that never reads or answers; the server must see the
        finished first flight, emit CertificateRequest, and count the
        ensuing silence as a selection stall.
        """
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        key, cert = tls_server.make_server_credential(self.work / "srv")
        with tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                                   client_ca=cert) as flow:
            flow.HANDSHAKE_TIMEOUT = 3.0
            # Send only the client's first flight and never read: a live
            # non-blocking handshake can finish on loopback (empty client
            # Certificate), which made this guard flaky.
            peer = socket.create_connection(("127.0.0.1", flow.port))
            try:
                peer.sendall(self._client_hello_bytes())
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


class ReapTreeDelay(unittest.TestCase):
    """Supervisor --initial-delay twins: unprivileged, run everywhere.

    The run-sign cells hold the browser spawn past observer startup so
    the flow's signs land in-window deterministically; these twins pin
    the delay, its validation, and the orphan fast-exit over the real
    supervisor subprocess.
    """

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="g33-reap-delay-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.supervisor = (ROOT / "tests" / "fixtures" / "browser"
                           / "reap_tree.py")

    def _run(self, *args, timeout=30):
        return subprocess.run(
            [sys.executable, "-I", str(self.supervisor), *args],
            capture_output=True, text=True, check=False, timeout=timeout)

    def test_initial_delay_holds_the_spawn(self):
        """Twin: the spawn waits out the delay, then runs the child."""
        start = time.monotonic()
        proc = self._run("--initial-delay", "0.6", sys.executable,
                         "-c", "pass")
        elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertGreaterEqual(elapsed, 0.6)

    def test_absent_delay_spawns_at_once(self):
        """Twin: no flag means no wait (existing behavior unchanged)."""
        start = time.monotonic()
        proc = self._run(sys.executable, "-c", "pass")
        elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertLess(elapsed, 10.0)

    def test_invalid_delay_fails_loud(self):
        """Twin: an unparseable delay fails instead of sleeping it off."""
        for value in ("nope", "-1", "nan", "inf", "301", ""):
            with self.subTest(value=value):
                proc = self._run("--initial-delay", value, sys.executable,
                                 "-c", "pass")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("usage", proc.stderr)

    def test_valueless_delay_flag_fails_usage(self):
        """Twin: a present-but-valueless --initial-delay is a usage failure.

        RED before the fix: the flag fell through and was exec'd as the
        child command (``reap_tree: the browser failed to start``).
        """
        proc = self._run("--initial-delay")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("usage", proc.stderr)

    def test_valueless_flow_done_flag_fails_usage(self):
        """Twin: a present-but-valueless --flow-done is a usage failure.

        Same class as the delay flag (present-but-valueless option
        escaping usage failure); this site predates the lane.
        """
        proc = self._run("--flow-done")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("usage", proc.stderr)

    def test_orphaned_delay_exits_promptly(self):
        """Twin: a supervisor whose parent died exits, never lingers."""
        shim = self.work / "shim.py"
        shim.write_text(
            "import subprocess, sys, time\n"
            "proc = subprocess.Popen(\n"
            "    [sys.executable, '-I', sys.argv[1], '--initial-delay',\n"
            "     '30', sys.executable, '-c', 'pass'],\n"
            "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n"
            "    start_new_session=True)\n"
            "print(proc.pid, flush=True)\n"
            # Let the supervisor reach its delay wait (reading us as
            # its parent) before we die mid-delay, the production
            # shape: an observer that outlives supervisor startup.
            "time.sleep(2.0)\n")
        proc = subprocess.run(
            [sys.executable, "-I", str(shim), str(self.supervisor)],
            capture_output=True, text=True, check=False, timeout=30)
        pid = int(proc.stdout.strip())
        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if _is_zombie(pid):
                    break
                time.sleep(0.1)
            else:
                self.fail("orphaned supervisor lingered past 10s "
                          "(parent-death watch dead?)")
        finally:
            _kill_quietly(pid)

    def test_delay_wait_rechecks_parent_after_deadline(self):
        """Twin: the parent-death watch rechecks after the deadline.

        A parent that dies during the final poll interval must still
        abort the spawn (no browser launch into an ownerless run).
        RED before the fix: the wait returned True without a final
        check.
        """
        with patch("os.getppid", return_value=os.getpid()):
            self.assertTrue(reap_tree._wait_initial_delay(0.0, os.getpid()))
        with patch("os.getppid", return_value=99999999):
            self.assertFalse(reap_tree._wait_initial_delay(0.0, os.getpid()))


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


def require_sign_wiring(test):
    """Fail naming the missing run-sign oracle (RED) once per check."""
    for name in ("check_s1_sign_mechanisms", "discovery_module_shas"):
        if not hasattr(oracle, name):
            test.fail(f"run-sign oracle not implemented: oracle.{name} missing")
    for name in ("module_sha",):
        if name not in BrowserCells.check_report.__code__.co_varnames:
            test.fail(
                "run-sign oracle not implemented: "
                f"check_report has no {name} wiring")


def live_cells_missing_s1(source):
    """Live-cell methods with no s1-proven check_report call.

    Parses ``source`` (this suite file), finds every @gate-decorated
    method of BrowserCells, and returns (found, missing): all live
    cell names, and those whose body has no check_report call
    carrying an ``s1=`` keyword. A future live cell that forgets
    ``s1=`` — or never calls check_report — lands in ``missing``.
    """
    found, missing = [], []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef) or node.name != "BrowserCells":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            gated = any(
                (isinstance(expr, ast.Call)
                 and isinstance(expr.func, ast.Name)
                 and expr.func.id == "gate")
                or (isinstance(expr, ast.Name) and expr.id == "gate")
                for expr in item.decorator_list)
            if not gated:
                continue
            found.append(item.name)
            proven = any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "check_report"
                and any(keyword.arg == "s1" for keyword in call.keywords)
                for call in ast.walk(item))
            if not proven:
                missing.append(item.name)
    return found, missing


def system_first_cells_missing_oracle(source):
    """Observer-first system cells and those lacking the rows oracle.

    Parses ``source`` (this suite file), finds every
    @gate_system-decorated method of BrowserCells, and returns
    (found, missing): all observer-first system cells, and those
    whose body has no observe_first_system drive call plus the two
    headline oracle legs (the ``bootstrap_unavailable`` reason pin
    and a ``browser_rows`` assertion). The S1 proof cannot cover
    this family: its oracle rejects Joint content, while these cells
    assert populated key-operation rows from an inventory report.
    """
    found, missing = [], []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef) or node.name != "BrowserCells":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            gated = any(
                (isinstance(expr, ast.Call)
                 and isinstance(expr.func, ast.Name)
                 and expr.func.id == "gate_system")
                or (isinstance(expr, ast.Name) and expr.id == "gate_system")
                for expr in item.decorator_list)
            if not gated:
                continue
            found.append(item.name)
            calls = [call for call in ast.walk(item)
                     if isinstance(call, ast.Call)]
            driven = any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "observe_first_system"
                for call in calls)
            constants = {const.value for const in ast.walk(item)
                         if isinstance(const, ast.Constant)}
            names = {name.id for name in ast.walk(item)
                     if isinstance(name, ast.Name)}
            if not (driven and "bootstrap_unavailable" in constants
                     and "browser_rows" in names):
                missing.append(item.name)
    return found, missing


def attach_cells_with_opened_floor(source):
    """``@gate`` attach-drive cells whose ``s1=`` may set ``sessions_opened_min``.

    Parses ``source`` (this suite file) like ``live_cells_missing_s1``.
    Attach cells must never floor in-window session opens: the browser
    opens its NSS token sessions at startup, strictly before the
    profiler can attach, so navigation traffic rides cached sessions
    and ``sessions.opened`` is legitimately zero. A non-literal ``s1=``
    (a name, a call, an unpacking, or a computed key) cannot be proven
    floor-free statically, so it counts as a violation too: the window
    rule must fail closed, never bypass silently. Returns the violating
    cell names (empty means the suite honors the window).
    """
    violations = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef) or node.name != "BrowserCells":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            gated = any(
                (isinstance(expr, ast.Call)
                 and isinstance(expr.func, ast.Name)
                 and expr.func.id == "gate")
                or (isinstance(expr, ast.Name) and expr.id == "gate")
                for expr in item.decorator_list)
            if not gated:
                continue
            calls = [call for call in ast.walk(item)
                     if isinstance(call, ast.Call)]
            attached = any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "attach_drive"
                for call in calls)
            if not attached:
                continue
            for call in calls:
                if not (isinstance(call.func, ast.Attribute)
                        and call.func.attr == "check_report"):
                    continue
                for keyword in call.keywords:
                    if keyword.arg != "s1":
                        continue
                    if not isinstance(keyword.value, ast.Dict):
                        violations.append(item.name)
                        continue
                    if any(not isinstance(key, ast.Constant)
                           for key in keyword.value.keys):
                        violations.append(item.name)
                        continue
                    keys = [key.value for key in keyword.value.keys]
                    if "sessions_opened_min" in keys:
                        violations.append(item.name)
    return violations


#: Drive entries that seed an NSS client credential before launch when
#: called with a non-None ``nss_credential`` (run_direct and
#: launch_browser_context default it to None; observe_first_system
#: requires it; attach_drive has no such parameter and never seeds).
_SEEDING_DRIVERS = ("run_direct", "observe_first_system",
                    "launch_browser_context")


def _const_truth(node):
    """Constant-test truth: True/False for a literal, else None (unknown).

    Only ``ast.Constant`` tests decide; anything dynamic (names,
    calls, ``not``-forms) is unknown and its branches stay live.
    """
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return None


def _dead_statements(item):
    """Ids of top statements in ``item`` that never execute.

    A statement is dead under a constant-false ``if``/``while``
    guard (the ``if True:`` else-branch symmetrically) or after a
    terminator (return/raise/break/continue) in the same block.
    Only tops are marked; descendants inherit through the parent
    map. Dynamic guards (``if flag:``) and ``assert`` exits stay
    live: the probe cannot decide them statically.
    """
    dead = set()

    def block(stmts):
        terminated = False
        for stmt in stmts:
            if terminated:
                dead.add(id(stmt))
            else:
                if isinstance(stmt, (ast.Return, ast.Raise,
                                     ast.Continue, ast.Break)):
                    terminated = True
                visit(stmt)

    def visit(node):
        if isinstance(node, ast.If):
            truth = _const_truth(node.test)
            if truth is False:
                for stmt in node.body:
                    dead.add(id(stmt))
            elif truth is True:
                for stmt in node.orelse:
                    dead.add(id(stmt))
            block(node.body)
            block(node.orelse)
        elif isinstance(node, ast.While):
            if _const_truth(node.test) is False:
                for stmt in node.body:
                    dead.add(id(stmt))
            block(node.body)
            block(node.orelse)
        else:
            for _name, value in ast.iter_fields(node):
                if (isinstance(value, list) and value
                        and all(isinstance(part, ast.stmt)
                                for part in value)):
                    block(value)
                elif isinstance(value, ast.stmt):
                    visit(value)

    block(item.body)
    return dead


def _positional_credential_index(driver):
    """Positional index of ``nss_credential`` for ``driver``, if any.

    Follows the real driver signature: only a positional-capable
    parameter has an index (keyword-only drivers stay None, so a
    future keyword-only ``run_direct`` disables positional
    detection structurally instead of rotting here).
    """
    func = getattr(cells, driver, None)
    if func is None:
        return None
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return None
    param = params.get("nss_credential")
    if param is None or param.kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD):
        return None
    return list(params).index("nss_credential")


def _call_seeds_nss(call):
    """True when a seeding-driver ``call`` may seed an NSS credential.

    A non-None ``nss_credential`` keyword seeds, as does a
    non-None positional in the driver's credential slot; ``*args``
    and ``**kwargs`` unpackings fail closed (their content is
    unprovable, so the call counts as seeding). ``None`` in every
    spelling means no seed runs.
    """
    func = call.func
    if not (isinstance(func, ast.Attribute)
            and func.attr in _SEEDING_DRIVERS):
        return False
    for keyword in call.keywords:
        if keyword.arg is None:
            return True
        if keyword.arg == "nss_credential" and not (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is None):
            return True
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return True
    index = _positional_credential_index(func.attr)
    if (index is not None and len(call.args) > index
            and not (isinstance(call.args[index], ast.Constant)
                      and call.args[index].value is None)):
        return True
    return False


def seeding_cells_missing_nss_gate(source):
    """NSS-seeding live cells and those lacking an effective gate.

    Parses ``source`` (this suite file), finds every
    @gate/@gate_system-decorated method of BrowserCells that drives
    a browser with a non-None ``nss_credential`` (an NSS
    client-credential seed runs before launch), and returns (found,
    missing): all seeding cells, and those with a seeding drive
    the gate does not effectively precede. Effective means a live
    ``missing_nss_seed_tools`` call whose result feeds a live
    ``if`` branch (an assigned name the test reads, or the call
    directly in the test), with the gate and the branch lexically
    before the drive: order is lexical over live statements, not a
    full CFG dominance proof. Dead code (constant-false guards,
    post-terminator lines) never counts as gating, while dead or
    unprovably-shaped seeding calls (``*args``/``**kwargs``,
    positional credentials) count as seeding: both fail closed. A
    future seeding cell that forgets the gate — erroring at the gate
    instead of erroring mid-cell from the seed step — lands in
    ``missing``.
    """
    found, missing = [], []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef) or node.name != "BrowserCells":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            gated = any(
                (isinstance(expr, ast.Call)
                 and isinstance(expr.func, ast.Name)
                 and expr.func.id in ("gate", "gate_system"))
                or (isinstance(expr, ast.Name)
                    and expr.id in ("gate", "gate_system"))
                for expr in item.decorator_list)
            if not gated:
                continue
            parents = {}
            for parent in ast.walk(item):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            dead = _dead_statements(item)

            def live(node):
                current = node
                while current is not None:
                    if id(current) in dead:
                        return False
                    current = parents.get(current)
                return True

            calls = [call for call in ast.walk(item)
                     if isinstance(call, ast.Call)]
            seeds = [call for call in calls if _call_seeds_nss(call)]
            if not seeds:
                continue
            found.append(item.name)
            gate_calls = [call for call in calls
                          if live(call)
                          and isinstance(call.func, ast.Attribute)
                          and call.func.attr == "missing_nss_seed_tools"]
            bound = set()
            for call in gate_calls:
                parent = parents.get(call)
                if isinstance(parent, ast.Assign):
                    bound.update(target.id for target in parent.targets
                                 if isinstance(target, ast.Name))
                elif (isinstance(parent, ast.AnnAssign)
                      and isinstance(parent.target, ast.Name)):
                    bound.add(parent.target.id)
            branches = [node for node in ast.walk(item)
                        if live(node) and isinstance(node, ast.If)
                        and (any(isinstance(name, ast.Name)
                                 and name.id in bound
                                 for name in ast.walk(node.test))
                             or any(node is ancestor
                                    for call in gate_calls
                                    for ancestor in _ancestors(
                                        call, parents)))]
            if any(not any(gate.lineno <= branch.lineno < seed.lineno
                           for gate in gate_calls
                           for branch in branches)
                   for seed in seeds):
                missing.append(item.name)
    return found, missing


def _ancestors(node, parents):
    """Yield ``node`` and its ancestors up to the method root."""
    current = node
    while current is not None:
        yield current
        current = parents.get(current)


def healthy_sessions(opened=2, inherited=0, closed=1, async_opened=0,
                     peak=2):
    """Balanced S1 session accounting (balance follows the counters)."""
    total = min(opened + inherited, (1 << 64) - 1)
    return {"opened": opened, "inherited": inherited, "closed": closed,
            "async_opened": async_opened, "peak_concurrent": peak,
            "balance": total - min(closed, total)}


def _bootstrap_cover_missing(rows, browser_instances):
    """True when the folded reason must fail the FF-FIRST-BG cell.

    The caller has already established the ruled
    ``live_joint_feed_absent`` reason (both no-live-feed literals stay
    inline at the call site so the observer-first wiring twin still
    sees them). Rows are tolerated only on the folded leg: live
    browser instances mean no live per-key tracking for retained
    callers, and no rows still means never covered.
    """
    return not rows or bool(browser_instances)


def _folded_exe_names_firefox(exe_path):
    """True when a departed-use exe path names a folded browser caller.

    ``exe_path`` is the already-lowered ``exe.path`` string. The
    match anchors to the binary basename: a firefox directory
    component alone must not count as a folded browser caller.
    """
    return exe_path.rsplit("/", 1)[-1].startswith("firefox")


def _folded_sign_instance_counts(instance, bg_instances):
    """True when a sign row's instance counts as folded browser evidence.

    The instance must be attributed and outside the background
    instances: an unattributed row carries no browser proof.
    """
    return instance is not None and instance not in bg_instances


class BrowserFoldedLeg(unittest.TestCase):
    """Folded-browser predicate twins: unprivileged, run everywhere.

    The FF-FIRST-BG live cell accepts folded firefox callers when no
    live browser instance survives; these twins pin the three
    folded-leg predicates over synthetic inputs so a softening of any
    of them fails here instead of silently widening the live cell.
    The full-branch rig twins below drive the real FF-FIRST-BG cell
    against synthetic reports, so the whole status/reason branch (the
    valid folded shape, the refused pairs, the guard mutant, and the
    still-eligible loss reasons) fails here instead of widening it.
    """

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="g33-folded-leg-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    @staticmethod
    def _folded_sign_rows(instances):
        """One completed sign row per ``instances`` entry."""
        return [{"category": "sign", "instance": instance, "completed": 1}
                for instance in instances]

    def _ff_first_bg_report(self, status, reason, rows, live_browser):
        """Synthetic FF-FIRST-BG inventory report over ``rows``.

        ``live_browser`` selects the live leg (a live browser instance
        owns the rows) or the folded leg (a background instance only;
        the browser survives solely as folded departed-use identities).
        """
        browser_module = {
            "id": "m0",
            "paths": ["/usr/lib64/firefox/libsoftokn3.so"],
        }
        if not live_browser:
            browser_module["departed_use"] = {
                "identities": [
                    {"exe": {"path": "/usr/lib64/firefox/firefox"}}],
            }
        doc = {
            "modules": [browser_module,
                        {"id": "m-bg",
                         "paths": ["/usr/lib64/pkcs11/libsofthsm2.so"]}],
            "instances": [{"id": "bg0", "module": "m-bg"}],
            "object_observations": {
                "status": status, "reason": reason,
                "key_operations": rows, "gaps": [],
            },
            "observation": {"semantic_capture": {"events_lost": 0}},
            "gaps": [],
        }
        if live_browser:
            doc["instances"].append({"id": "b0", "module": "m0"})
        path = self.work / "ff-first-bg-report.json"
        path.write_text(json.dumps(doc))
        return path

    def _ff_first_bg_rig(self, status, reason, rows, live_browser):
        """Run the real FF-FIRST-BG cell against a synthetic report."""
        report_path = self._ff_first_bg_report(status, reason, rows,
                                               live_browser)
        result = cells.CellResult("FF-FIRST-BG", report_path)
        result.flow["observer_exit"] = 0
        store = SimpleNamespace(lib=Path("/not-opened/libsofthsm2.so"),
                                env={})
        bg_log = self.work / "bg.log"
        bg_log.write_text("READY\nSTOP n=42\n")
        bg = SimpleNamespace(stop=lambda: None, log=bg_log)
        plain = SimpleNamespace(url="https://127.0.0.1:1/",
                                requests_served=1)
        cc = SimpleNamespace(url="https://127.0.0.1:2/",
                             handshakes_ok=1, client_certs_presented=1)
        plain_ctx = MagicMock()
        plain_ctx.__enter__.return_value = plain
        cc_ctx = MagicMock()
        cc_ctx.__enter__.return_value = cc
        case = BrowserCells(
            "test_ff_first_with_background_provider_covers_browser")
        case.work = self.work
        case.seed = lambda *a: (
            store, SimpleNamespace(cert_pem=Path("/not-opened/client.pem")))
        with patch.object(cells, "preflight", return_value=None), \
                patch.object(cells, "start_soft_call", return_value=bg), \
                patch.object(cells, "observe_first_system",
                             return_value=result), \
                patch.object(tls_server, "make_server_credential",
                             return_value=(Path("/not-opened/key"),
                                           Path("/not-opened/cert"))), \
                patch.object(tls_server, "FlowServer",
                             side_effect=[plain_ctx, cc_ctx]):
            case.test_ff_first_with_background_provider_covers_browser()

    def test_folded_branch_valid_partial_accepted(self):
        # Guard: the folded shape (partial with retained sign rows and
        # no live browser instance) passes the real cell.
        rows = self._folded_sign_rows(["i-folded-1", "i-folded-2"])
        self._ff_first_bg_rig("partial", "live_joint_feed_absent",
                              rows, False)

    def test_folded_branch_bootstrap_with_rows_refused(self):
        # Retained rows must commit partial with the folded reason: the
        # old unavailable/bootstrap pair beside proved rows is refused.
        rows = self._folded_sign_rows(["i-folded-1", "i-folded-2"])
        with self.assertRaisesRegex(AssertionError, "no retained rows"):
            self._ff_first_bg_rig("unavailable", "bootstrap_unavailable",
                                  rows, False)

    def test_folded_branch_folded_reason_requires_partial(self):
        # The folded reason beside retained rows is partial coverage,
        # never unavailable.
        rows = self._folded_sign_rows(["i-folded-1", "i-folded-2"])
        with self.assertRaisesRegex(AssertionError, "must commit partial"):
            self._ff_first_bg_rig("unavailable", "live_joint_feed_absent",
                                  rows, False)

    def test_folded_branch_live_instance_with_folded_reason_refused(self):
        # Mutant twin: live browser instances beside the folded reason
        # mean no live per-key tracking for retained callers. The rows
        # sit on the live instance, so dropping the folded reason from
        # the guard would let this pass the row gates below.
        rows = self._folded_sign_rows(["b0", "b0"])
        with self.assertRaisesRegex(AssertionError, "never covered"):
            self._ff_first_bg_rig("partial", "live_joint_feed_absent",
                                  rows, True)

    def test_folded_branch_folded_reason_without_rows_refused(self):
        # The folded reason with zero rows still means never covered.
        with self.assertRaisesRegex(AssertionError, "never covered"):
            self._ff_first_bg_rig("partial", "live_joint_feed_absent",
                                  [], False)

    def test_folded_branch_bootstrap_without_rows_refused(self):
        # Rowless bootstrap still means never covered.
        with self.assertRaisesRegex(AssertionError, "never covered"):
            self._ff_first_bg_rig("unavailable", "bootstrap_unavailable",
                                  [], False)

    def test_folded_branch_loss_reasons_stay_eligible(self):
        # Guard: specific loss/fallback reasons keep their existing
        # gates — the no-live-feed branch must not touch them.
        for status, reason in [("partial", "proof_refused_fallback"),
                               ("stale", "authority_lost")]:
            with self.subTest(reason=reason):
                rows = self._folded_sign_rows(["i-folded-1", "i-folded-2"])
                self._ff_first_bg_rig(status, reason, rows, False)

    def _journal_refusal_rig(self, **overrides):
        observations = {"status": "unavailable",
                        "reason": "journal_unavailable",
                        "key_operations": []}
        report = {
            "gaps": [{"subject": "key operations unavailable",
                      "reason": "journal-pair-unavailable-in-build"}],
            "observation": {"semantic_capture": {"events_lost": 0}},
        }
        observations.update(overrides.pop("observations", {}))
        report.update(overrides.pop("report", {}))
        assert not overrides, overrides
        return observations, report

    def test_journal_refusal_fails_on_a_journal_build(self):
        # Mutant twin: the shipped build carries the journal, so a
        # journal_unavailable refusal on it is a journal regression
        # and must fail. Dropping the flavor gate would let this
        # pass as the pinned refusal.
        observations, report = self._journal_refusal_rig()
        with self.assertRaisesRegex(AssertionError, "a journal regression"):
            judge_key_observations_journal_branch(
                observations, report, journal_omitted=False)

    def test_journal_refusal_passes_on_a_journal_less_build(self):
        # The pinned refusal stays valid where the binary proves it
        # omits the journal.
        observations, report = self._journal_refusal_rig()
        self.assertEqual(
            judge_key_observations_journal_branch(
                observations, report, journal_omitted=True),
            "refusal")

    def test_journal_refusal_with_rows_fails(self):
        # The pinned refusal carries zero rows, even journal-less.
        observations, report = self._journal_refusal_rig(
            observations={"key_operations": [{"category": "sign"}]})
        with self.assertRaisesRegex(AssertionError, "zero rows"):
            judge_key_observations_journal_branch(
                observations, report, journal_omitted=True)

    def test_journal_refusal_without_build_cause_fails(self):
        # The pinned refusal names its build cause, even journal-less.
        observations, report = self._journal_refusal_rig(
            report={"gaps": []})
        with self.assertRaisesRegex(AssertionError, "build cause"):
            judge_key_observations_journal_branch(
                observations, report, journal_omitted=True)

    def test_journal_refusal_with_lost_events_fails(self):
        # The pinned refusal loses no semantic events, even journal-less.
        observations, report = self._journal_refusal_rig(
            report={"observation": {"semantic_capture": {"events_lost": 2}}})
        with self.assertRaisesRegex(AssertionError, "semantic events lost"):
            judge_key_observations_journal_branch(
                observations, report, journal_omitted=True)

    def test_observer_omits_journal_reads_the_doctor_row(self):
        # The flavor probe parses doctor -v: only the exact
        # `not in this build` token means journal-less; a missing
        # row fails closed.
        for doctor_out, want in [
                ("journal pair preflight .... not-applicable  not in this build\n",
                 True),
                ("journal pair preflight .... ok              available\n",
                 False),
                ("journal pair preflight .... warn            unavailable: pair missing (x)\n",
                 False),
        ]:
            with self.subTest(doctor_out=doctor_out):
                with patch.object(cells, "p11scope_bin",
                                  return_value=Path("/bin/true")), patch(
                        "subprocess.run",
                        return_value=SimpleNamespace(stdout=doctor_out)):
                    self.assertIs(observer_omits_journal(), want)
        with patch.object(cells, "p11scope_bin",
                          return_value=Path("/bin/true")), patch(
                "subprocess.run",
                return_value=SimpleNamespace(stdout="Doctor: ok.\n")):
            with self.assertRaisesRegex(AssertionError, "no journal-pair row"):
                observer_omits_journal()

    def test_bootstrap_with_live_browser_instances_fails(self):
        # Folded-leg-only allowance: bootstrap with S1 rows is
        # tolerated for exited (folded) callers, but live browser
        # instances with bootstrap mean per-key tracking never
        # started for retained callers and must fail loud.
        self.assertTrue(
            _bootstrap_cover_missing([{"category": "sign"}], {"i0"}))

    def test_bootstrap_with_rows_passes_without_live_instances(self):
        # The folded leg keeps working: bootstrap with rows and no
        # live browser instance is the tolerated folded shape.
        self.assertFalse(
            _bootstrap_cover_missing([{"category": "sign"}], set()))

    def test_bootstrap_without_rows_fails(self):
        # Bootstrap with zero rows still means never covered, with or
        # without live browser instances.
        self.assertTrue(_bootstrap_cover_missing([], set()))
        self.assertTrue(_bootstrap_cover_missing([], {"i0"}))

    def test_folded_exe_matches_basename_only(self):
        # A firefox directory component must not count: only the
        # binary basename names a folded browser caller.
        self.assertFalse(_folded_exe_names_firefox(
            "/tmp/firefox-profile-helper/python"))

    def test_folded_exe_matches_firefox_binary(self):
        # Saved RED shapes keep passing: basename firefox under a
        # firefox-* directory, plus the firefox-bin variant; an empty
        # path never matches.
        self.assertTrue(_folded_exe_names_firefox(
            "/home/u/.cache/mozilla/firefox-abc123/firefox"))
        self.assertTrue(_folded_exe_names_firefox("firefox-bin"))
        self.assertFalse(_folded_exe_names_firefox(""))

    def test_folded_sign_requires_attributed_instance(self):
        # An unattributed sign row (missing instance) must not count
        # as folded browser evidence; the live leg's instance join
        # would fail it.
        self.assertFalse(_folded_sign_instance_counts(None, {"i1"}))

    def test_folded_sign_counts_non_background_instance(self):
        # Attributed signs outside background instances prove the
        # folded browser; background signs never do.
        self.assertTrue(_folded_sign_instance_counts("i0", {"i1"}))
        self.assertFalse(_folded_sign_instance_counts("i1", {"i1"}))


class BrowserS1Oracle(unittest.TestCase):
    """S1 oracle twins: unprivileged, run everywhere (no gate).

    The v0.5.0 S1 proof over the profile report's S1 sections: no
    Joint content anywhere (key-operation populations are 0.6.0), no
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

    def _sign_mechanism_entry(self, mech_id, sha, calls):
        """One mechanisms[] row with ``calls`` attributed to ``sha``."""
        return {"mechanism": mech_id, "mechanism_hex": hex(mech_id),
                "ops": ["sign"], "calls": calls, "errors": 0,
                "by_module": [{"module": {"dev": [1, 2], "ino": 3,
                                          "sha256": sha},
                               "calls": calls, "errors": 0}]}

    def test_s1_sign_mechanisms_healthy_accepted(self):
        """Twin: an RSA sign mechanism attributed to softokn passes."""
        require_sign_wiring(self)
        sha = "ab" * 32
        doc = {"mechanisms": [self._sign_mechanism_entry(0x40, sha, 3)]}
        self.assertEqual(
            oracle.check_s1_sign_mechanisms(doc, {sha}, _RSA_FAMILY_IDS, 1),
            [])
        # Two discovery shas (a copy-up pair) sum across both rows.
        sha2 = "cd" * 32
        doc = {"mechanisms": [
            self._sign_mechanism_entry(0x40, sha, 1),
            self._sign_mechanism_entry(0x43, sha2, 1)]}
        self.assertEqual(
            oracle.check_s1_sign_mechanisms(
                doc, {sha, sha2}, _RSA_FAMILY_IDS, 2),
            [])

    def test_s1_sign_mechanisms_rejected(self):
        """Twin: every non-sign shape fails the family leg (RED)."""
        require_sign_wiring(self)
        sha = "ab" * 32
        other = "cd" * 32
        cases = {
            # Attributed to another module: not our provider's signs.
            "wrong-sha": {"mechanisms": [
                self._sign_mechanism_entry(0x40, other, 3)]},
            # Digest-only: mechanism use with no sign family at all.
            "digest-only": {"mechanisms": [
                self._sign_mechanism_entry(_SHA256_MECHANISM_ID, sha, 9)]},
            # Row totals without attribution: unprovable, fail closed.
            "unattributed": {"mechanisms": [
                {"mechanism": 0x40, "calls": 3, "errors": 0,
                 "by_module": []}]},
            # Malformed entries fail closed, never pass blind.
            "malformed-entry": {"mechanisms": ["x"]},
            "malformed-shape": {"mechanisms": {}},
            "malformed-attribution": {"mechanisms": [
                {"mechanism": 0x40, "calls": 3, "errors": 0,
                 "by_module": [{"module": "x", "calls": 3,
                                "errors": 0}]}]},
            "missing-section": {},
            "empty": {"mechanisms": []},
        }
        for name, doc in cases.items():
            with self.subTest(name=name):
                failures = oracle.check_s1_sign_mechanisms(
                    doc, {sha}, _RSA_FAMILY_IDS, 1)
                self.assertNotEqual(failures, [])
        # Below the floor fails even when attributed and in-family.
        doc = {"mechanisms": [self._sign_mechanism_entry(0x40, sha, 1)]}
        self.assertNotEqual(
            oracle.check_s1_sign_mechanisms(doc, {sha}, _RSA_FAMILY_IDS, 2),
            [])

    def test_discovery_module_shas_exact(self):
        """Twin: softokn shas come from discovery[] by exact basename."""
        require_sign_wiring(self)
        sha = "ab" * 32
        report = {"evidence": {"discovery": [
            {"path": "/usr/lib64/libsoftokn3.so", "sha256": sha,
             "dev": [0, 40], "ino": 11},
            {"path": "/usr/lib64/pkcs11/libsofthsm2.so",
             "sha256": "cd" * 32, "dev": [0, 41], "ino": 12},
        ]}}
        shas, failures = oracle.discovery_module_shas(
            report, _SOFTOKN_BASENAME)
        self.assertEqual(failures, [])
        self.assertEqual(shas, {sha})
        # Near-miss basenames never match: exact equality only.
        for path in ("/usr/lib64/libsoftokn3.so.1",
                     "/usr/lib64/mylibsoftokn3.so",
                     "/usr/lib64/LIBsofTokN3.SO",
                     "/usr/lib64/libsoftokn3.so.orig"):
            with self.subTest(path=path):
                shas, failures = oracle.discovery_module_shas(
                    {"evidence": {"discovery": [
                        {"path": path, "sha256": sha}]}},
                    _SOFTOKN_BASENAME)
                self.assertEqual(failures, [])
                self.assertEqual(shas, set())
        # A matching row with no usable digest fails closed (loud, not
        # a silent empty set the cell would misread as unmapped).
        for bad in (None, "", "ab" * 31, "zz" * 32, 42):
            with self.subTest(sha=bad):
                _shas, failures = oracle.discovery_module_shas(
                    {"evidence": {"discovery": [
                        {"path": "/usr/lib64/libsoftokn3.so",
                         "sha256": bad}]}},
                    _SOFTOKN_BASENAME)
                self.assertNotEqual(failures, [])
        # A missing discovery list fails closed too.
        _shas, failures = oracle.discovery_module_shas(
            {"evidence": {}}, _SOFTOKN_BASENAME)
        self.assertNotEqual(failures, [])

    def test_s1_sign_mechanisms_check_report_wiring(self):
        """Twin: s1= with sign_mechanisms floors family signs, not absence.

        The run-sign branch keeps the Joint negative and the session
        floor but replaces the enumeration absence legs (mechanism use
        and logins are the asserted property here, not a violation).
        """
        require_sign_wiring(self)
        sha = "ab" * 32
        rows = [BrowserCells._twin_row(["C_SignInit"], 1, sha),
                BrowserCells._twin_row(["C_Sign"], 2, sha)]
        mechanisms = [self._sign_mechanism_entry(0x40, sha, 2)]
        _, result = self.s1_result(
            "S1-SIGN", rows, BrowserCells._twin_evidence(), mechanisms,
            healthy_sessions(), {})
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        s1 = {"sessions_opened_min": 1,
              "sign_mechanisms": {"family_ids": sorted(_RSA_FAMILY_IDS),
                                  "min_calls": 1}}
        case.check_report(result, None, {"C_SignInit": 1, "C_Sign": 1},
                          attached=True, module_sha={sha}, s1=s1)
        # Digest-only mechanisms fail the same wiring (RED).
        hostile = [self._sign_mechanism_entry(
            _SHA256_MECHANISM_ID, sha, 9)]
        _, bad = self.s1_result(
            "S1-SIGN-HOSTILE", rows, BrowserCells._twin_evidence(),
            hostile, healthy_sessions(), {})
        with self.assertRaises(AssertionError):
            case.check_report(bad, None, {"C_SignInit": 1, "C_Sign": 1},
                              attached=True, module_sha={sha}, s1=s1)
        # A malformed sign_mechanisms spec fails closed (a test bug must
        # never pass blind as a vacuous family leg).
        for spec in ({"family_ids": [], "min_calls": 1},
                     {"family_ids": [0x40], "min_calls": 0},
                     {"family_ids": ["0x40"], "min_calls": 1},
                     {"min_calls": 1},
                     {"family_ids": [0x40]}):
            with self.subTest(spec=spec):
                with self.assertRaises(AssertionError):
                    case.check_report(
                        result, None, {"C_SignInit": 1, "C_Sign": 1},
                        attached=True, module_sha={sha},
                        s1={"sessions_opened_min": 1,
                            "sign_mechanisms": spec})

    def test_check_report_multi_sha_floors_sum_across_pair(self):
        """Twin: check_report floors sum across a discovery copy-up pair.

        C_Sign rides both shas (1+1) under a floor of 2 while
        C_SignInit rides one sha under a floor of 1; the summed
        floors pass. An overwrite mutant (``counts[name] = calls``)
        leaves C_Sign at 1 and fails deterministically regardless of
        set order. A disjoint split (C_SignInit on one sha, C_Sign on
        the other) would NOT kill it — each name is set once, so
        overwrite equals sum — hence the shared-name summed floor.
        """
        require_sign_wiring(self)
        sha = "ab" * 32
        sha2 = "cd" * 32
        rows = [BrowserCells._twin_row(["C_SignInit"], 1, sha),
                BrowserCells._twin_row(["C_Sign"], 1, sha),
                BrowserCells._twin_row(["C_Sign"], 1, sha2)]
        mechanisms = [self._sign_mechanism_entry(0x40, sha, 1),
                      self._sign_mechanism_entry(0x43, sha2, 1)]
        _, result = self.s1_result(
            "S1-MULTISHA", rows, BrowserCells._twin_evidence(),
            mechanisms, healthy_sessions(), {})
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        s1 = {"sign_mechanisms": {"family_ids": sorted(_RSA_FAMILY_IDS),
                                  "min_calls": 2}}
        case.check_report(result, None, {"C_SignInit": 1, "C_Sign": 2},
                          attached=True, module_sha={sha, sha2}, s1=s1)

    def test_nodelay_exact_counts_reject_overcount_and_undercount(self):
        """Twin: the sign pair is exact per handshake, never a floor."""
        self.assertEqual(
            oracle.check_exact_counts(
                {"C_SignInit": 1, "C_Sign": 1},
                {"C_SignInit": 1, "C_Sign": 1}),
            [])
        for counts in ({"C_SignInit": 2, "C_Sign": 2},
                       {"C_SignInit": 1, "C_Sign": 2},
                       {"C_SignInit": 2, "C_Sign": 1},
                       {"C_SignInit": 1, "C_Sign": 0},
                       {"C_SignInit": 0, "C_Sign": 0},
                       {}):
            with self.subTest(counts=counts):
                self.assertNotEqual(
                    oracle.check_exact_counts(
                        counts, {"C_SignInit": 1, "C_Sign": 1}),
                    [])

    def test_nodelay_zero_open_entries_rejects_surplus_inflight(self):
        """Twin: no entered-but-unreturned sign may hide beside exact counts."""
        self.assertEqual(
            oracle.check_zero_open_entries(
                {"C_SignInit": 0, "C_Sign": 0},
                ("C_SignInit", "C_Sign")),
            [])
        self.assertEqual(
            oracle.check_zero_open_entries(
                {}, ("C_SignInit", "C_Sign")),
            [])
        for opened in ({"C_SignInit": 1, "C_Sign": 0},
                       {"C_SignInit": 0, "C_Sign": 1},
                       {"C_SignInit": 1, "C_Sign": 1}):
            with self.subTest(opened=opened):
                self.assertNotEqual(
                    oracle.check_zero_open_entries(
                        opened, ("C_SignInit", "C_Sign")),
                    [])

    def test_nodelay_cross_alias_rejected_distinct_rows_accepted(self):
        """Twin: one aliased row cannot prove the two sign functions."""
        sha = "ab" * 32
        report = {"functions": [
            BrowserCells._twin_row(["C_SignInit", "C_Sign"], 1, sha)]}
        self.assertNotEqual(
            oracle.check_no_cross_function_alias(
                report, {sha}, (("C_SignInit", "C_Sign"),)),
            [])
        report = {"functions": [
            BrowserCells._twin_row(["C_SignInit"], 1, sha),
            BrowserCells._twin_row(["C_Sign"], 1, sha)]}
        self.assertEqual(
            oracle.check_no_cross_function_alias(
                report, {sha}, (("C_SignInit", "C_Sign"),)),
            [])
        # An aliased row on another module is not this cell's evidence.
        report = {"functions": [
            BrowserCells._twin_row(["C_SignInit", "C_Sign"], 1, "cd" * 32)]}
        self.assertEqual(
            oracle.check_no_cross_function_alias(
                report, {sha}, (("C_SignInit", "C_Sign"),)),
            [])

    def test_function_rows_typed_rejects_bools_and_bad_shapes(self):
        """Twin: untyped counts and names fail before any floor reads them."""
        sha = "ab" * 32
        healthy = {"functions": [
            BrowserCells._twin_row(["C_Sign"], 1, sha),
            {"names": ["C_Login"], "calls": 0,
             "target": {"object": {"sha256": sha}}},
            {"target": {"object": {"sha256": "cd" * 32}}},
            {"names": [], "calls": None, "in_flight": None,
             "target": None},
        ]}
        self.assertEqual(oracle.check_function_rows_typed(healthy), [])
        self.assertEqual(oracle.check_function_rows_typed({}), [])
        self.assertEqual(
            oracle.check_function_rows_typed({"functions": []}), [])
        hostile_rows = [
            {"names": ["C_Sign"], "calls": True,
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign"], "calls": 1.5,
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign"], "calls": "1",
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign"], "calls": 1, "in_flight": True,
             "target": {"object": {"sha256": sha}}},
            {"names": "C_Sign", "calls": 1,
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign", 42], "calls": 1,
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign"], "calls": -1,
             "target": {"object": {"sha256": sha}}},
            {"names": ["C_Sign"], "calls": 1, "target": "x"},
            {"names": ["C_Sign"], "calls": 1,
             "target": {"object": "x"}},
            "not-a-row",
        ]
        for row in hostile_rows:
            with self.subTest(row=row):
                self.assertNotEqual(
                    oracle.check_function_rows_typed(
                        {"functions": [row]}),
                    [])
        self.assertNotEqual(
            oracle.check_function_rows_typed({"functions": {}}), [])

    def test_sign_mechanisms_rejects_nonsign_ops(self):
        """Twin: a contributing family entry must show signing use."""
        require_sign_wiring(self)
        sha = "ab" * 32
        entry = self._sign_mechanism_entry(0x40, sha, 3)
        self.assertEqual(
            oracle.check_s1_sign_mechanisms(
                {"mechanisms": [entry]}, {sha}, _RSA_FAMILY_IDS, 1),
            [])
        # Signing among other operations still proves a sign.
        entry["ops"] = ["encrypt", "sign"]
        self.assertEqual(
            oracle.check_s1_sign_mechanisms(
                {"mechanisms": [entry]}, {sha}, _RSA_FAMILY_IDS, 1),
            [])
        for ops in (["encrypt"], [], None, "sign", [42]):
            with self.subTest(ops=ops):
                bad = self._sign_mechanism_entry(0x40, sha, 3)
                if ops is None:
                    del bad["ops"]
                else:
                    bad["ops"] = ops
                failures = oracle.check_s1_sign_mechanisms(
                    {"mechanisms": [bad]}, {sha}, _RSA_FAMILY_IDS, 1)
                self.assertNotEqual(failures, [])
                self.assertIn("signing use", failures[0])
        # A non-contributing entry's ops stay unchecked: the floor
        # below still fails it for the missing attribution instead.
        bad = self._sign_mechanism_entry(0x40, "cd" * 32, 3)
        del bad["ops"]
        failures = oracle.check_s1_sign_mechanisms(
            {"mechanisms": [bad]}, {sha}, _RSA_FAMILY_IDS, 1)
        self.assertNotEqual(failures, [])
        self.assertIn("want >=", failures[0])

    def test_sign_mechanisms_exact_calls_rejects_duplicates(self):
        """Twin: exact family totals fail duplicate mechanism records."""
        require_sign_wiring(self)
        sha = "ab" * 32
        doc = {"mechanisms": [self._sign_mechanism_entry(0x40, sha, 2)]}
        self.assertEqual(
            oracle.check_s1_sign_mechanisms(
                doc, {sha}, _RSA_FAMILY_IDS, 1, exact_calls=2),
            [])
        for wrong in (1, 3):
            with self.subTest(exact_calls=wrong):
                failures = oracle.check_s1_sign_mechanisms(
                    doc, {sha}, _RSA_FAMILY_IDS, 1, exact_calls=wrong)
                self.assertNotEqual(failures, [])
                self.assertIn("exactly", failures[0])
        # A duplicated record (the same entry twice) reads 4, not 2.
        doubled = {"mechanisms": [self._sign_mechanism_entry(0x40, sha, 2),
                                  self._sign_mechanism_entry(0x40, sha, 2)]}
        failures = oracle.check_s1_sign_mechanisms(
            doubled, {sha}, _RSA_FAMILY_IDS, 1, exact_calls=2)
        self.assertNotEqual(failures, [])

    def test_nodelay_exact_wiring_healthy_accepted_hostile_rejected(self):
        """Twin: the exact nodelay wiring passes healthy, fails hostile."""
        require_sign_wiring(self)
        sha = "ab" * 32
        rows = [BrowserCells._twin_row(["C_SignInit"], 1, sha),
                BrowserCells._twin_row(["C_Sign"], 1, sha)]
        mechanisms = [self._sign_mechanism_entry(0x40, sha, 2)]
        _, result = self.s1_result(
            "S1-NODELAY", rows, BrowserCells._twin_evidence(),
            mechanisms, healthy_sessions(), {})
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        exact = {"C_SignInit": 1, "C_Sign": 1}
        s1 = {"sessions_opened_min": 1,
              "sign_mechanisms": {"family_ids": sorted(_RSA_FAMILY_IDS),
                                  "min_calls": 1, "exact_calls": 2}}
        case.check_report(
            result, None, None, attached=True, module_sha={sha}, s1=s1,
            exact=exact, exact_opened_zero=("C_SignInit", "C_Sign"),
            no_cross_alias=(("C_SignInit", "C_Sign"),))
        hostiles = {
            # Duplicate completed records: the floor would still pass.
            "overcount": [BrowserCells._twin_row(["C_SignInit"], 2, sha),
                          BrowserCells._twin_row(["C_Sign"], 2, sha)],
            # A boolean count is malformed, never one.
            "bool-calls": [dict(BrowserCells._twin_row(["C_SignInit"], 1, sha),
                                calls=True),
                           BrowserCells._twin_row(["C_Sign"], 1, sha)],
            # A surplus call still in flight beside exact completed.
            "in-flight": [BrowserCells._twin_row(["C_SignInit"], 1, sha, 1),
                          BrowserCells._twin_row(["C_Sign"], 1, sha)],
            # One aliased row for both functions.
            "cross-alias": [BrowserCells._twin_row(
                ["C_SignInit", "C_Sign"], 1, sha)],
            # Unresolved names hide the pair in the unknown bucket.
            "unresolved": [dict(BrowserCells._twin_row(["C_SignInit"], 1, sha),
                                names=None),
                           dict(BrowserCells._twin_row(["C_Sign"], 1, sha),
                                names=None)],
        }
        for name, hostile_rows in hostiles.items():
            with self.subTest(hostile=name):
                _, bad = self.s1_result(
                    f"S1-NODELAY-{name}", hostile_rows,
                    BrowserCells._twin_evidence(), mechanisms,
                    healthy_sessions(), {})
                with self.assertRaises(AssertionError):
                    case.check_report(
                        bad, None, None, attached=True, module_sha={sha},
                        s1=s1, exact=exact,
                        exact_opened_zero=("C_SignInit", "C_Sign"),
                        no_cross_alias=(("C_SignInit", "C_Sign"),))
        # A duplicated mechanism record reads 4 family uses, not 2.
        doubled = [self._sign_mechanism_entry(0x40, sha, 2),
                   self._sign_mechanism_entry(0x40, sha, 2)]
        _, bad = self.s1_result(
            "S1-NODELAY-MECH", rows, BrowserCells._twin_evidence(),
            doubled, healthy_sessions(), {})
        with self.assertRaises(AssertionError):
            case.check_report(
                bad, None, None, attached=True, module_sha={sha},
                s1=s1, exact=exact,
                exact_opened_zero=("C_SignInit", "C_Sign"),
                no_cross_alias=(("C_SignInit", "C_Sign"),))
        # An encrypt-only RSA row proves no sign.
        encrypt = [dict(self._sign_mechanism_entry(0x40, sha, 2),
                        ops=["encrypt"])]
        _, bad = self.s1_result(
            "S1-NODELAY-OPS", rows, BrowserCells._twin_evidence(),
            encrypt, healthy_sessions(), {})
        with self.assertRaises(AssertionError):
            case.check_report(
                bad, None, None, attached=True, module_sha={sha},
                s1=s1, exact=exact,
                exact_opened_zero=("C_SignInit", "C_Sign"),
                no_cross_alias=(("C_SignInit", "C_Sign"),))

    def test_discovery_anchor_rejects_coherent_substitution(self):
        """Twin: discovery shas must be files the cell hashed itself."""
        system = "ab" * 32
        bundled = "cd" * 32
        fake = "ef" * 32
        # Both known files discovered: healthy.
        self.assertEqual(
            oracle.check_discovery_shas_anchored(
                {system, bundled}, {system, bundled}, system,
                _SOFTOKN_BASENAME),
            [])
        # Only the observed module discovered: healthy (subset).
        self.assertEqual(
            oracle.check_discovery_shas_anchored(
                {system}, {system, bundled}, system, _SOFTOKN_BASENAME),
            [])
        # A coherent substitution (another digest, same basename,
        # functions and S1 rewritten to match) fails on the unknown sha.
        failures = oracle.check_discovery_shas_anchored(
            {fake}, {system, bundled}, system, _SOFTOKN_BASENAME)
        self.assertEqual(len(failures), 2)
        self.assertIn("never hashed", failures[0])
        # The observed module missing from discovery fails too.
        failures = oracle.check_discovery_shas_anchored(
            {bundled}, {system, bundled}, system, _SOFTOKN_BASENAME)
        self.assertEqual(len(failures), 1)
        self.assertIn("never discovered", failures[0])
        # Nothing discovered at all fails on the missing module.
        failures = oracle.check_discovery_shas_anchored(
            set(), {system, bundled}, system, _SOFTOKN_BASENAME)
        self.assertEqual(len(failures), 1)

    def test_rsa_family_mirror_matches_product_table(self):
        """Twin: the RSA mirror stays the 32-id keymeta.rs table.

        The set itself is verified against src/keymeta.rs RSA_IDS at
        commit time; this pins its size and anchor ids so an accidental
        edit fails here instead of silently widening the family leg.
        """
        self.assertEqual(len(_RSA_FAMILY_IDS), 32)
        for anchor in (0x00000001, 0x0000000e, 0x00000040, 0x00000047,
                       0x00000060, 0x00000067, 0x00001054, 0x00004002):
            self.assertIn(anchor, _RSA_FAMILY_IDS)
        self.assertNotIn(_SHA256_MECHANISM_ID, _RSA_FAMILY_IDS)

    def test_skipped_run_floor_exact(self):
        """Twin: the run-floor qualification judges records one by one."""
        healthy = {"evidence": {"skipped": [
            {"name": "discovery subject", "reason": "discovery unavailable"},
            {"name": "discovery subject",
             "reason": "process exited mid-flight"},
            {"name": "learned provider file",
             "reason": oracle.LEARNED_FIRST_USE_REASON},
        ]}}
        self.assertEqual(oracle.check_skipped_run_floor(healthy), [])
        self.assertEqual(
            oracle.check_skipped_run_floor({"evidence": {}}), [])
        # Every other learned-file reason stays refused (unbounded loss):
        # all nine non-first-use LEARNED_*_REASON literals from
        # src/render.rs, verbatim.
        refused = [
            ("learned provider file",
             "file learning reached its 32-file per-capture cap; "
             "further provider files were not learned"),
            ("learned provider file",
             "file-learning events were lost; "
             "some provider files may not have been learned"),
            ("learned provider file",
             "a learned provider's tables lost their pinned identity; "
             "its calls were not observed"),
            ("learned provider file",
             "table learning reached its 32-module per-capture cap; "
             "further provider tables were not learned"),
            ("learned provider file",
             "file learning was unavailable; short-lived first loads "
             "of new provider files were not learned"),
            ("learned provider file",
             "a provider file was replaced or deleted before staging; "
             "it was not learned"),
            ("learned provider file",
             "file learning was disabled by the operator; "
             "short-lived first loads of new provider files were not "
             "learned"),
            ("learned provider file",
             "file learning cannot see filesystems outside the "
             "observer's mount namespace; provider files opened only "
             "there were not learned"),
            ("learned provider file",
             "some filesystems were not marked for file learning, or "
             "a re-mark pass was still pending or could not start; "
             "short-lived first loads of new provider files opened "
             "only there were not learned"),
            # Retire/detach windows could hide the asserted signs.
            ("C_Sign",
             "counting probes were retired mid-capture; calls in the "
             "retire window were not observed"),
            # Near-miss records never qualify (exact pairs only).
            # (Structural reasons stay reason-only like the base check,
            # so a structural reason under any name still passes.)
            ("discovery subject", "process exited mid-flight!"),
            ("learned provider file", None),
            ("learned provider file", ""),
            (None, None),
        ]
        for name, reason in refused:
            with self.subTest(name=name, reason=reason):
                doc = {"evidence": {"skipped": [
                    {"name": name, "reason": reason}]}}
                self.assertNotEqual(
                    oracle.check_skipped_run_floor(doc), [])

    def test_skipped_run_floor_check_report_wiring(self):
        """Twin: the qualification routes through check_report, exclusively."""
        sha = "ab" * 32
        rows = [BrowserCells._twin_row(["C_Sign"], 1, sha)]
        window = [{"name": "discovery subject",
                   "reason": "process exited mid-flight"}]
        _, result = self.s1_result(
            "S1-RUNFLOOR", rows,
            BrowserCells._twin_evidence(skipped=window),
            [], healthy_sessions(), {})
        case = BrowserCells("test_oracle_builder_healthy_accepted")
        case.work = self.work
        # The base check refuses the window record...
        with patch.object(oracle, "sha256_of", return_value=sha):
            with self.assertRaises(AssertionError):
                case.check_report(result, None, {"C_Sign": 1},
                                  attached=True, module_sha={sha})
            # ...the run-floor route qualifies it...
            case.check_report(result, None, {"C_Sign": 1},
                              attached=True, module_sha={sha},
                              qualify_run_floor_skipped=True)
            # ...and the two qualifications conflict loud (test bug).
            with self.assertRaises(AssertionError):
                case.check_report(
                    result, None, {"C_Sign": 1}, attached=True,
                    module_sha={sha}, qualify_nomod_link_loss=True,
                    qualify_run_floor_skipped=True)

    def test_live_cells_all_wire_s1_proof(self):
        require_s1_wiring(self)
        found, missing = live_cells_missing_s1(
            Path(__file__).read_text())
        self.assertEqual(len(found), 7)
        self.assertEqual(missing, [])

    def test_nss_seeding_cells_call_the_seed_gate(self):
        """Twin: every NSS-seeding live cell gates the seed tools first.

        CR-RUN-SIGN, CR-RUN-NODELAY and FF-FIRST-BG seed an NSS client
        credential before launch; all must call missing_nss_seed_tools
        at the gate (error, naming the absent tools) instead of
        erroring mid-cell from the seed step. The seeding set is
        pinned exactly: a future seeder fails here until gated.
        """
        found, missing = seeding_cells_missing_nss_gate(
            Path(__file__).read_text())
        self.assertEqual(sorted(found), [
            "test_cr_run_nodelay_observes_client_cert_signs",
            "test_cr_run_sign_observes_client_cert_signs",
            "test_ff_first_with_background_provider_covers_browser",
        ])
        self.assertEqual(missing, [])

    def test_nss_seed_gate_errors_when_tools_are_missing(self):
        """Twin: a missing seed tool errors, never skips (STRICT or not).

        Ruling G: the browser gate prerequisite is an error. Every
        seeding cell's ``if missing:`` branch raises AssertionError
        naming the tools; no branch may skipTest (a skip would hide a
        broken seed setup in non-strict runs) or consult STRICT. The
        set is pinned exactly: renaming a cell or its gate call fails
        here, and reintroducing a skip fails below.
        """
        import ast as _ast
        cells = [
            "test_cr_run_nodelay_observes_client_cert_signs",
            "test_cr_run_sign_observes_client_cert_signs",
            "test_ff_first_with_background_provider_covers_browser",
        ]
        tree = _ast.parse(Path(__file__).read_text())
        seen = []
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.ClassDef) or node.name != "BrowserCells":
                continue
            for item in node.body:
                if not isinstance(item, _ast.FunctionDef) or item.name not in cells:
                    continue
                seen.append(item.name)
                branches = [n for n in _ast.walk(item)
                            if isinstance(n, _ast.If)
                            and isinstance(n.test, _ast.Name)
                            and n.test.id == "missing"]
                self.assertEqual(len(branches), 1,
                                 f"{item.name}: exactly one `if missing:` branch")
                body = branches[0].body
                raises = [n for n in _ast.walk(_ast.Module(body=body, type_ignores=[]))
                          if isinstance(n, _ast.Raise)]
                self.assertTrue(raises, f"{item.name}: the branch raises")
                skips = [n for n in _ast.walk(_ast.Module(body=body, type_ignores=[]))
                         if isinstance(n, _ast.Call)
                         and isinstance(n.func, _ast.Attribute)
                         and n.func.attr == "skipTest"]
                self.assertEqual(skips, [], f"{item.name}: the branch never skips")
                stricts = [n for n in _ast.walk(_ast.Module(body=body, type_ignores=[]))
                           if isinstance(n, _ast.Name) and n.id == "STRICT"]
                self.assertEqual(stricts, [],
                                 f"{item.name}: the branch never consults STRICT")
        self.assertEqual(sorted(seen), sorted(cells))

    def test_nss_gate_probe_flags_ungated_seeders_only(self):
        """Twin: the gate probe flags exactly the ungated seeders.

        An ungated seeder lands in missing; a gated seeder (the
        real error branch shape) and a None-credential
        drive (no seed runs) pass. Deleting either live gate block
        moves that cell into missing (see the sweep); renaming the
        probe's driver set or the gate call breaks the live-file
        twin above.
        """
        template = (
            "import unittest\n"
            "\n"
            "class BrowserCells(unittest.TestCase):\n"
            '    @gate("chromium")\n'
            "    def test_probe_ungated(self):\n"
            "        cells.run_direct(\"P\", \"chromium\", work, url,\n"
            "                         nss_credential=cred)\n"
            '    @gate("firefox")\n'
            "    def test_probe_gated(self):\n"
            "        missing = cells.missing_nss_seed_tools()\n"
            "        if missing:\n"
            "            raise AssertionError(\"NSS seed tools missing\")\n"
            "        cells.run_direct(\"P\", \"firefox\", work, url,\n"
            "                         nss_credential=cred)\n"
            '    @gate("firefox")\n'
            "    def test_probe_unseeded(self):\n"
            "        cells.run_direct(\"P\", \"firefox\", work, url,\n"
            "                         nss_credential=None)\n"
        )
        found, missing = seeding_cells_missing_nss_gate(template)
        self.assertEqual(sorted(found),
                         ["test_probe_gated", "test_probe_ungated"])
        self.assertEqual(missing, ["test_probe_ungated"])

    def test_nss_gate_probe_enforces_order_branch_and_spelling(self):
        """Twin: the gate probe pins order, branch use, and spelling.

        Each hostile shape lands in missing (or in found when it
        seeds): a gate after the drive, a gate in dead code (``if
        False:`` or past a return), a gate call whose result feeds
        no branch, a branch on the wrong name or after the drive,
        and positional/``*``/``**`` credentials an ungated cell
        could hide behind. Accepted controls (a keyword-gated
        seeder, a positional seeder with the gate first, a gate
        call directly in the ``if`` test, a None credential, a
        non-seeding driver) prove the probe is exact, not
        flag-happy: every case asserts the full (found, missing)
        pair.
        """
        gate = ("        missing = cells.missing_nss_seed_tools()\n"
                "        if missing:\n"
                "            self.skipTest(\"NSS seed tools missing\")\n")
        drive = ("        cells.run_direct(\"P\", \"chromium\", work, url,\n"
                 "                         nss_credential=cred)\n")
        positional = ("        cells.run_direct(\"P\", \"chromium\", work, url,\n"
                      "                         None, None, None, (), 120, cred)\n")
        cases = {
            # want_found, want_missing.
            "control_gated": (gate + drive, True, False),
            "control_in_test": (
                "        if cells.missing_nss_seed_tools():\n"
                "            self.skipTest(\"NSS seed tools missing\")\n"
                + drive, True, False),
            "control_gated_positional": (gate + positional, True, False),
            "control_none_credential": (
                "        cells.run_direct(\"P\", \"chromium\", work, url,\n"
                "                         None, None, None, (), 120, None)\n",
                False, False),
            "control_non_seeding_driver": (
                "        cells.attach_drive(\"P\", \"firefox\", work, url,"
                " flow, lib)\n",
                False, False),
            "late_gate": (drive + gate, True, True),
            "dead_gate_if_false": (
                "        if False:\n"
                "            missing = cells.missing_nss_seed_tools()\n"
                "        if missing:\n"
                "            self.skipTest(\"NSS seed tools missing\")\n"
                + drive, True, True),
            "dead_gate_post_return": (
                "        return\n" + gate + drive, True, True),
            "call_without_branch": (
                "        cells.missing_nss_seed_tools()\n" + drive,
                True, True),
            "branch_on_wrong_name": (
                "        missing = cells.missing_nss_seed_tools()\n"
                "        if other:\n"
                "            self.skipTest(\"NSS seed tools missing\")\n"
                + drive, True, True),
            "branch_after_drive": (
                drive
                + "        missing = cells.missing_nss_seed_tools()\n"
                "        if missing:\n"
                "            self.skipTest(\"NSS seed tools missing\")\n",
                True, True),
            "positional_credential": (positional, True, True),
            "star_args": (
                "        cells.run_direct(*args)\n", True, True),
            "kwargs_spread": (
                "        cells.run_direct(\"P\", \"chromium\", work, url,\n"
                "                         **{\"nss_credential\": cred})\n",
                True, True),
            "first_drive_ungated": (
                drive + gate + drive, True, True),
        }
        shell = ("import unittest\n"
                 "\n"
                 "class BrowserCells(unittest.TestCase):\n"
                 '    @gate("chromium")\n'
                 "    def test_m(self):\n%s")
        for name, (body, want_found, want_missing) in cases.items():
            with self.subTest(shape=name):
                found, missing = seeding_cells_missing_nss_gate(
                    shell % body)
                self.assertEqual(found, ["test_m"] if want_found else [])
                self.assertEqual(
                    missing, ["test_m"] if want_missing else [])

    def test_system_first_cells_wire_browser_rows_oracle(self):
        found, missing = system_first_cells_missing_oracle(
            Path(__file__).read_text())
        self.assertEqual(len(found), 1)
        self.assertEqual(missing, [])

    def test_attach_cells_require_no_opened_floor(self):
        """Twin: attach cells must not floor in-window session opens.

        Sessions open at browser startup, strictly before the
        attach-mode capture window exists; requiring
        ``sessions_opened_min`` there fails on correct captures.
        """
        require_s1_wiring(self)
        violations = attach_cells_with_opened_floor(
            Path(__file__).read_text())
        self.assertEqual(violations, [])

    def test_attach_cells_flag_non_literal_s1(self):
        """Twin: a non-literal s1= in an attach cell must be flagged.

        The window guard cannot prove a floor-free s1 from a name, a
        call, or an unpacking, so each must be a violation rather
        than a silent bypass.
        """
        template = (
            "import unittest\n"
            "\n"
            "class BrowserCells(unittest.TestCase):\n"
            '    @gate("firefox")\n'
            "    def test_probe_cell(self):\n"
            "        cells.attach_drive(\"PROBE\", \"firefox\", work, url, flow, lib)\n"
            "        self.check_report(result, store, s1=%s)\n"
        )
        for expr in ("FLOOR_S1", "dict()", "{**BASE}"):
            with self.subTest(s1=expr):
                self.assertEqual(
                    attach_cells_with_opened_floor(template % expr),
                    ["test_probe_cell"])
        self.assertEqual(
            attach_cells_with_opened_floor(template % "{}"), [])
        self.assertEqual(
            attach_cells_with_opened_floor(template % '{"sessions_opened_min": 1}'),
            ["test_probe_cell"])


def strict_attach_grace_literals(source):
    """Strict `attach_drive` sites that bypass the ruled bound constant.

    Parses ``source`` (this suite file), finds every
    ``attach_grace_seconds=`` keyword in ``BrowserCells`` methods, and
    returns the violating ``(method, lineno)`` sites: any site whose
    value is not the ``cells.ATTACH_GRACE_SECONDS`` attribute, except
    the readiness probe's ``grace_seconds`` passthrough. A stale
    literal (``=5`` breaks strict cells, ``=30`` silently re-widens
    the ruled bound) lands here.
    """
    violations = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef) or node.name != "BrowserCells":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            for call in ast.walk(item):
                if not isinstance(call, ast.Call):
                    continue
                for keyword in call.keywords:
                    if keyword.arg != "attach_grace_seconds":
                        continue
                    value = keyword.value
                    if isinstance(value, ast.Name) and value.id == "grace_seconds":
                        continue
                    if (isinstance(value, ast.Attribute)
                            and isinstance(value.value, ast.Name)
                            and value.value.id == "cells"
                            and value.attr == "ATTACH_GRACE_SECONDS"):
                        continue
                    violations.append((item.name, getattr(keyword, "lineno", 0)))
    return violations


def _kill_quietly(pid, sig=signal.SIGKILL):
    """Best-effort kill for twin-process cleanup (never fails the test)."""
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _reap_quietly(proc):
    """Best-effort Popen cleanup: kill, then reap (never fails the test)."""
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def _is_zombie(pid):
    """True when pid is a zombie (or already gone); False when running."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            data = handle.read()
    except OSError:
        return True
    try:
        state = data.rsplit(b")", 1)[1].split()[0]
    except (IndexError, ValueError):
        return False
    return state == b"Z"


def _wait_tree_dead(pid, timeout):
    """True once pid is gone or a zombie; False on timeout.

    The termination path is asynchronous by design (the supervisor's
    handler reaps once and exits while a killed grandchild may linger
    as a zombie until init reaps it), and a zombie still answers
    kill(pid, 0). Both gone and zombie mean the kill landed, so both
    count as dead.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        if _is_zombie(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


class FlowServerSignsOwed(unittest.TestCase):
    """TLS ground-truth twins: unprivileged, run everywhere (no gate).

    Each completed handshake that presented a non-empty peer cert on a
    connection that saw CertificateRequest owes exactly one
    private-key sign. Resumed handshakes (no request, cached cert)
    and empty certs owe none.
    """

    def _socket(self, cert):
        def getpeercert(binary_form=False):
            if isinstance(cert, Exception):
                raise cert
            return cert

        return SimpleNamespace(getpeercert=getpeercert)

    def test_full_handshake_with_cert_owes_one_sign(self):
        flow = tls_server.FlowServer()
        flow.note_handshake_ok(self._socket(b"peer-cert"), cert_request_seen=True)
        self.assertEqual(flow.handshakes_ok, 1)
        self.assertEqual(flow.client_certs_presented, 1)
        self.assertEqual(flow.signs_owed, 1)

    def test_resumed_handshake_owes_no_sign(self):
        flow = tls_server.FlowServer()
        flow.note_handshake_ok(self._socket(b"cached-cert"), cert_request_seen=True)
        flow.note_handshake_ok(self._socket(b"cached-cert"), cert_request_seen=False)
        self.assertEqual(flow.handshakes_ok, 2)
        self.assertEqual(flow.client_certs_presented, 2)
        self.assertEqual(flow.signs_owed, 1)

    def test_empty_or_missing_cert_owes_no_sign(self):
        flow = tls_server.FlowServer()
        flow.note_handshake_ok(self._socket(None), cert_request_seen=True)
        flow.note_handshake_ok(
            self._socket(OSError("no peer")), cert_request_seen=True)
        self.assertEqual(flow.handshakes_ok, 2)
        self.assertEqual(flow.client_certs_presented, 0)
        self.assertEqual(flow.signs_owed, 0)


class BrowserReapTree(unittest.TestCase):
    """Owned-child supervisor twins: unprivileged, run everywhere (no gate).

    ``run_direct`` cells execute the browser as ``p11scope run``'s owned
    child, and the run ends when that child exits. Firefox's multiprocess
    teardown trails the main process, so the bare browser child ends
    capture while descendants are still present or mid-teardown: the
    report then honestly carries RUN_TREE_SURVIVORS plus whatever
    leader-exit assessment sampled a live group
    (``task_uprobe_link_losses``), and the never-mapped oracle fails
    closed on both (the v0.7.0 browser-cells flake: FF-NOMOD failed 2 of
    16 hosted runs on ``task_uprobe_link_losses``, once with survivors).
    The supervisor (``tests/fixtures/browser/reap_tree.py``) is the owned
    child instead: a private process group plus the child-subreaper bit,
    then wait for the browser's exit, SIGKILL the stragglers, and reap to
    ECHILD before exiting with the browser's code, so capture always ends
    on a quiesced tree. The readiness signal is ECHILD (no descendants
    remain); the reap bound only fails loud on a wedged tree. These twins
    pin that contract with synthetic workloads (no browser, no root).
    """

    #: How long the synthetic stragglers would sleep unreaped; the
    #: supervisor must finish well before it (kill+reap, not waiting).
    STRAGGLER_SLEEP_SECONDS = 30
    #: How long the flow-completion child would linger past its
    #: screenshot; it exceeds the prompt bound, so a supervisor that
    #: ignores the completion trigger times out instead of passing.
    POST_SHOT_SLEEP_SECONDS = 30
    #: How long past its screenshot the flow-completion child waits
    #: before writing its lingered sentinel; the supervisor must kill
    #: the tree at completion, well before that.
    LINGERED_AFTER_SECONDS = 8
    #: Promptness bound for the supervisor (loaded-CI margin included).
    PROMPT_SECONDS = 20

    @property
    def supervisor(self):
        return str(ROOT / "tests" / "fixtures" / "browser" / "reap_tree.py")

    def setUp(self):
        if sys.platform != "linux":
            self.skipTest("the owned-child supervisor is Linux-only")
        if not Path(self.supervisor).exists():
            self.fail(f"the owned-child supervisor is missing: {self.supervisor}")

    def test_supervisor_kills_and_reaps_an_orphaned_tree(self):
        """Stragglers die by SIGKILL and are reaped; the exit code passes."""
        child = (
            "import subprocess, sys; "
            "grandchild = subprocess.Popen([sys.executable, '-c', "
            f"'import time; time.sleep({self.STRAGGLER_SLEEP_SECONDS})']); "
            "print(grandchild.pid, flush=True); "
            "sys.exit(7)"
        )
        argv = [sys.executable, self.supervisor, sys.executable, "-c", child]
        start = time.monotonic()
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        self.addCleanup(_reap_quietly, proc)
        self.addCleanup(proc.stdout.close)
        code = proc.wait(timeout=self.PROMPT_SECONDS + 5)
        elapsed = time.monotonic() - start
        self.assertEqual(code, 7,
                         "the browser's exit code is the supervisor's")
        self.assertLess(elapsed, self.PROMPT_SECONDS,
                        "kill+reap must not wait out the straggler")
        ready, _, _ = select.select([proc.stdout], [], [], self.PROMPT_SECONDS)
        self.assertTrue(ready, "the supervisor never relayed its child's output")
        grandchild = int(proc.stdout.readline().strip())
        self.addCleanup(_kill_quietly, grandchild)
        with self.assertRaises(
                ProcessLookupError,
                msg="the orphaned grandchild must be dead"):
            os.kill(grandchild, 0)

    def test_supervisor_passes_through_a_clean_exit(self):
        """Healthy twin: a clean child exit passes through with its code."""
        argv = [sys.executable, self.supervisor,
                sys.executable, "-c", "import sys; sys.exit(3)"]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 3)

    def test_supervisor_supervises_when_already_a_group_leader(self):
        """A leader (the observer's pre-exec setsid) still supervises.

        The observer's owned child already leads its session; the
        supervisor takes no session of its own (the browser founds
        one) and still kills+reaps the tree there.
        """
        setsid = shutil.which("setsid")
        if setsid is None:
            self.skipTest("setsid(1) is not installed")
        child = (
            "import subprocess, sys; "
            "grandchild = subprocess.Popen([sys.executable, '-c', "
            f"'import time; time.sleep({self.STRAGGLER_SLEEP_SECONDS})']); "
            "print(grandchild.pid, flush=True); "
            "sys.exit(7)"
        )
        argv = [setsid, sys.executable, self.supervisor,
               sys.executable, "-c", child]
        start = time.monotonic()
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        self.addCleanup(_reap_quietly, proc)
        self.addCleanup(proc.stdout.close)
        code = proc.wait(timeout=self.PROMPT_SECONDS + 5)
        elapsed = time.monotonic() - start
        self.assertEqual(code, 7,
                         "the browser's exit code is the supervisor's")
        self.assertLess(elapsed, self.PROMPT_SECONDS,
                        "kill+reap must not wait out the straggler")
        ready, _, _ = select.select([proc.stdout], [], [], self.PROMPT_SECONDS)
        self.assertTrue(ready, "the supervisor never relayed its child's output")
        grandchild = int(proc.stdout.readline().strip())
        self.addCleanup(_kill_quietly, grandchild)
        with self.assertRaises(
                ProcessLookupError,
                msg="the orphaned grandchild must be dead"):
            os.kill(grandchild, 0)

    def test_supervisor_kills_the_tree_at_flow_completion(self):
        """A complete screenshot ends the run: kill, reap, exit 0.

        The browser's remaining work after its screenshot is pure
        teardown, so the supervisor SIGKILLs the whole tree (main
        included) at the PNG trailer instead of waiting for a slow
        natural cascade it would then sample mid-teardown.
        """
        tmp = Path(tempfile.mkdtemp(prefix="g33-reap-flow-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        shot = tmp / "flow.png"
        lingered = tmp / "lingered"
        child = (
            "import subprocess, sys, time; "
            "grandchild = subprocess.Popen([sys.executable, '-c', "
            f"'import time; time.sleep({self.STRAGGLER_SLEEP_SECONDS})']); "
            "print(grandchild.pid, flush=True); "
            "time.sleep(0.5); "
            f"__import__('pathlib').Path({str(shot)!r}).write_bytes(bytes.fromhex("
            "'89504e470d0a1a0a0000000049454e44ae426082')); "
            f"time.sleep({self.LINGERED_AFTER_SECONDS}); "
            f"__import__('pathlib').Path({str(lingered)!r}).write_bytes(b'lingered'); "
            f"time.sleep({self.POST_SHOT_SLEEP_SECONDS})"
        )
        argv = [sys.executable, self.supervisor, "--flow-done", str(shot),
               sys.executable, "-c", child]
        start = time.monotonic()
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        self.addCleanup(_reap_quietly, proc)
        self.addCleanup(proc.stdout.close)
        code = proc.wait(timeout=self.PROMPT_SECONDS + 5)
        elapsed = time.monotonic() - start
        self.assertEqual(code, 0, "a completed flow exits 0")
        self.assertLess(elapsed, self.PROMPT_SECONDS,
                        "the kill lands at completion, not at child exit")
        self.assertFalse(lingered.exists(),
                         "the tree must die at completion, before it can linger")
        ready, _, _ = select.select([proc.stdout], [], [], self.PROMPT_SECONDS)
        self.assertTrue(ready, "the supervisor never relayed its child's output")
        grandchild = int(proc.stdout.readline().strip())
        self.addCleanup(_kill_quietly, grandchild)
        with self.assertRaises(
                ProcessLookupError,
                msg="the orphaned grandchild must be dead"):
            os.kill(grandchild, 0)

    def test_supervisor_forwards_termination_to_the_tree(self):
        """SIGTERM kills the whole tree; nothing leaks (the timeout path)."""
        child = (
            "import subprocess, sys, time; "
            "grandchild = subprocess.Popen([sys.executable, '-c', "
            f"'import time; time.sleep({self.STRAGGLER_SLEEP_SECONDS})']); "
            "print(grandchild.pid, flush=True); "
            f"time.sleep({self.STRAGGLER_SLEEP_SECONDS})"
        )
        argv = [sys.executable, self.supervisor, sys.executable, "-c", child]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        self.addCleanup(_reap_quietly, proc)
        self.addCleanup(proc.stdout.close)
        ready, _, _ = select.select([proc.stdout], [], [], self.PROMPT_SECONDS)
        self.assertTrue(ready, "the supervisor never started its child")
        grandchild = int(proc.stdout.readline().strip())
        self.addCleanup(_kill_quietly, grandchild)
        proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=self.PROMPT_SECONDS)
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertTrue(
            _wait_tree_dead(grandchild, timeout=10),
            "the grandchild must not outlive termination")


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
