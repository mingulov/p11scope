#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Typed verdicts for scripts/check-bpf-load-journal.sh.

The journal load gate runs one throwaway guest per kernel and judges
three inputs: the guest console log (status records the guest command
prints), the verifier-stats probe stream, and the observer's text. Each
input has one strict record grammar here, and every positive gate reads
only records that grammar accepted:

* ``guest LOG``: the guest status records (``guest-work-ready``,
  ``guest-stage=...``, ``journal-rc``, ``guest-release``). Every console
  line that starts with a status label is a candidate for that record,
  whatever follows the label; each candidate must be the exact record,
  each record appears once, in the order the guest prints them, and the
  observer's exit must equal the guest leg's exit. Prints ``ok RC
  RELEASE`` or ``infra REASON``.
* ``verdict ...``: one kernel's cell verdict. The probe stream is parsed
  by ``parse_probe_stream`` in scripts/bpf-load-report.py, the same
  parser the verifier report uses, so a load row is evidence only when
  the report would also accept it. Observer proof lines are classified
  by label: every line starting with a proof label is a candidate, each
  proof is one exact record, and a malformed or repeated candidate
  refuses with a named reason. Appends one results row; exits 0 when
  the cell qualified and 10 when it failed.
* ``budgets FILE``: validates a budgets file with the report's reader.
* ``row CELL PASS QUALIFICATION DETAIL``: prints one results row (the
  shell's infrastructure rows use the same shape).

Any other exit status is a helper failure; the shell refuses the cell.
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_REPORT_PATH = Path(__file__).resolve().with_name("bpf-load-report.py")
_SPEC = importlib.util.spec_from_file_location("bpf_load_report", _REPORT_PATH)
report = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(report)

EXIT_QUALIFIED = 0
EXIT_FAILED = 10

PAIR = ("p11_entry_journal", "p11_return_journal")
LENGTH_PAIR = ("p11_entry_journal_length", "p11_return_journal_length")
JOURNAL_ROOTS = PAIR + LENGTH_PAIR

# A decimal count as Rust and the shell print it: no sign, no leading zero.
COUNT = r"(0|[1-9][0-9]{0,19})"
# A shell exit status ($?): 0-255, no leading zero.
STATUS_RE = re.compile(r"0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5]")


# ---------------------------------------------------------------- lines

def split_lines(data):
    """LF-framed lines as bytes; a missing final newline keeps the tail."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def printable(raw):
    """The line as text when every byte is printable ASCII, else None."""
    if any(byte < 0x20 or byte > 0x7e for byte in raw):
        return None
    return raw.decode("ascii")


# ---------------------------------------------------------- guest status

# Status labels, in the order the guest prints them. A console line
# that starts with a label is a candidate for that record even when the
# delimiter or value is missing, so a truncated duplicate never vanishes.
GUEST_WORK_READY_RE = re.compile(
    r"guest-work-ready=ext4 uid-mode=0:700 TMPDIR=/var/tmp/p11scope-bpf\.[A-Za-z0-9_]{6,}")
GUEST_STAGE_RE = re.compile(
    r"guest-stage=(token-ok|token-failed|workload-ready|workload-not-ready"
    r"|observer-rc=(?P<observer>[0-9]+))")
GUEST_RC_RE = re.compile(r"journal-rc=(?P<rc>[0-9]+)")
GUEST_RELEASE_RE = re.compile(r"guest-release=(?P<release>[^=\s]+)")


def _status(text):
    return text is not None and STATUS_RE.fullmatch(text) is not None


def guest_status(data, kernel):
    """('ok', rc, release) or ('infra', reason) for one guest console log."""
    work_ready, stages, exits, releases = [], [], [], []
    for index, raw in enumerate(split_lines(data)):
        for label, bucket in ((b"guest-work-ready", work_ready),
                              (b"guest-stage", stages),
                              (b"journal-rc", exits),
                              (b"guest-release", releases)):
            if raw.startswith(label):
                bucket.append((index, printable(raw)))
                break
    # The guest leg's exit comes first: without one exact record the
    # guest command never finished.
    if len(exits) != 1 or exits[0][1] is None:
        return ("infra", "guest exit line missing, corrupt or contradictory")
    exit_match = GUEST_RC_RE.fullmatch(exits[0][1])
    if exit_match is None or not _status(exit_match["rc"]):
        return ("infra", "guest exit line missing, corrupt or contradictory")
    if (len(work_ready) != 1 or work_ready[0][1] is None
            or GUEST_WORK_READY_RE.fullmatch(work_ready[0][1]) is None):
        return ("infra", "guest work area never readied")
    if len(releases) != 1 or releases[0][1] is None:
        return ("infra", "guest release line missing, corrupt or contradictory "
                         f"(expected {kernel})")
    release_match = GUEST_RELEASE_RE.fullmatch(releases[0][1])
    if release_match is None:
        return ("infra", "guest release line missing, corrupt or contradictory "
                         f"(expected {kernel})")
    kinds = {"token": [], "workload": [], "observer": []}
    for index, text in stages:
        match = GUEST_STAGE_RE.fullmatch(text) if text is not None else None
        if match is None or (match["observer"] is not None
                             and not _status(match["observer"])):
            return ("infra", "guest stage record corrupt")
        value = match.group(1)
        kind = ("observer" if match["observer"] is not None
                else value.split("-", 1)[0])
        kinds[kind].append((index, value))
    if any(len(records) > 1 for records in kinds.values()):
        return ("infra", "guest stage records contradictory")
    token = kinds["token"][0] if kinds["token"] else None
    workload = kinds["workload"][0] if kinds["workload"] else None
    observer = kinds["observer"][0] if kinds["observer"] else None
    if token is not None and token[1] == "token-failed":
        return ("infra", "guest SoftHSM token setup failed")
    if workload is not None and workload[1] == "workload-not-ready":
        return ("infra", "guest workload never readied")
    if token is None or workload is None:
        return ("infra", "guest stages never ran")
    if observer is None:
        return ("infra", "guest observer exit record missing")
    observer_rc = observer[1].split("=", 1)[1]
    if observer_rc != exit_match["rc"]:
        return ("infra", f"guest observer exit {observer_rc} disagrees with "
                         f"guest leg exit {exit_match['rc']}")
    order = [work_ready[0][0], token[0], workload[0], observer[0],
             exits[0][0], releases[0][0]]
    if order != sorted(order):
        return ("infra", "guest status records out of order")
    return ("ok", int(exit_match["rc"]), release_match["release"])


# --------------------------------------------------------- observer text

SEAL_LABEL = "p11scope: semantic lane ready"
SEAL_FORMS = frozenset(
    "p11scope: semantic lane ready; mechanisms and API results are recorded "
    f"from now on (key operations: {state})"
    for state in ("recorded only with --key-operations", "recorded",
                  "unavailable"))
STOP_LABEL = "p11scope: semantic calls:"
STOP_RE = re.compile(
    rf"p11scope: semantic calls: collected {COUNT}, joined (?P<joined>{COUNT}), "
    rf"shed {COUNT}, lost {COUNT}, bindings (?P<bindings>{COUNT}), "
    rf"refused {COUNT}, hook misses {COUNT}, eras {COUNT}, instances {COUNT}")
DECODER_LABEL = "p11scope: joint decoder:"
DECODER_RE = re.compile(
    rf"p11scope: joint decoder: raw_malformed=(?P<total>{COUNT}|unknown) "
    r"raw_malformed_unprovable=(?P<unprovable>[01])")
KEY_SUMMARY_LABEL_RE = re.compile(r"key operations: [0-9]")
KEY_SUMMARY_RE = re.compile(
    rf"key operations: (?P<keys>{COUNT}) key(?P<ks>s?) on "
    rf"(?P<providers>{COUNT}) provider(?P<ps>s?); rev {COUNT} "
    r"(populated|partial|stale|unavailable); "
    rf"(?P<sessions>{COUNT}) session(?P<ss>s?)")
KEY_ROW_LABEL = "  key row "
KEY_CATEGORIES = (
    "rsa_1024|rsa_2048|rsa_3072|rsa_4096|rsa_other|aes_128|aes_192|aes_256|"
    "aes_other|ec_p256|ec_p384|ec_p521|x25519|x448|ed25519|ed448|hkdf_96|"
    "hkdf_128|hkdf_192|hkdf_256|hkdf_384|hkdf_other|generic_96|generic_128|"
    "generic_192|generic_256|generic_384|generic_other|ml_dsa_44|ml_dsa_65|"
    "ml_dsa_87|ml_kem_512|ml_kem_768|ml_kem_1024|slh_dsa_sha2_128s|"
    "slh_dsa_shake_128s|slh_dsa_sha2_128f|slh_dsa_shake_128f|"
    "slh_dsa_sha2_192s|slh_dsa_shake_192s|slh_dsa_sha2_192f|"
    "slh_dsa_shake_192f|slh_dsa_sha2_256s|slh_dsa_shake_256s|"
    "slh_dsa_sha2_256f|slh_dsa_shake_256f|unknown")
RSA_ROW_RE = re.compile(
    rf"  key row i{COUNT} object {COUNT} sign key \(({KEY_CATEGORIES})\): "
    r"probably RSA \(from mechanism\); RSA 2048 \(from signature length\)")
KEY_REFUSAL_LABEL = "p11scope: key operations unavailable"
OMITTED_BUILD_REASON = "journal-pair-unavailable-in-build"
OMITTED_REFUSAL = (
    "p11scope: key operations unavailable: "
    "journal-pair-unavailable-in-build: this build omits the production journal object"
    "; broad inventory continues with S1 mechanisms and API results")
CRASH_MARKERS = (b"panicked at", b"traceback", b"sigsegv", b"sigabrt")

# The finite pre-Multi live-capture refusal, one form per producer arm
# in src/attach/multi_host.rs (MultiHostRefusal's Display and
# denied_line). src/main.rs prints the error chain as `p11scope: {e:#}`
# under the run's scope context, so the gate's `inventory --system`
# command renders `p11scope: inventory --system: live capture ...`
# (observed on 6.1.188 and 5.15.221 guests). Only the producer's
# variable positions vary: the operation, the errno name and the
# missing capabilities or binary path; the cause and the retry
# instruction are fixed text. A line starting with either lead, with or
# without the context, is a candidate; only the exact framed form counts.
LIVE_REFUSAL_CONTEXT = "p11scope: inventory --system: "
LIVE_REFUSAL_LABELS = (LIVE_REFUSAL_CONTEXT + "live capture", "p11scope: live capture")
_CONTEXT = re.escape(LIVE_REFUSAL_CONTEXT)
_DOING = ("(preparing p11scope's self-probe|loading p11scope's BPF programs"
          "|attaching p11scope's probes)")
_OPERATION = ("(prepare p11scope's self-probe|load p11scope's BPF programs"
              "|attach p11scope's probes)")
# The errno name as strerror renders it: every Linux name starts with a
# capital or `.` (ELIBBAD) and may carry `:` (ETOOMANYREFS).
_ERRNO = r"( \([A-Z.][A-Za-z0-9 ,.:'/-]{0,80}\))?"
_SCAN_TAIL = re.escape(
    "; run 'p11scope doctor' for host readiness, or use 'p11scope inventory "
    "--capture scan' or 'p11scope inspect --pid N' for a scan without capture.")
_HELD_TAIL = re.escape(
    " held - a kernel lockdown, an LSM policy, or a container's seccomp "
    "profile is refusing BPF here. Run 'p11scope doctor' for host readiness, "
    "or use 'p11scope inspect --pid N' for a scan without capture.")
_USERNS_CAUSE = (
    "capture is unavailable here because BPF and uprobes need capabilities "
    "in the host user namespace (user-namespace-without-host-capabilities); "
    "run p11scope on the host or with the five-capability rootful command "
    "(see deploy/README.md)")
_NEEDS = ("(needs CAP_BPF \\(load BPF programs and attach probes\\)"
          "(; needs CAP_PERFMON \\(load BPF programs alongside CAP_BPF\\))?"
          "|needs CAP_PERFMON \\(load BPF programs alongside CAP_BPF\\))")
_SETCAP = re.escape(
    "sudo setcap 'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,"
    "cap_perfmon,cap_sys_ptrace=ep' ")
_BINARY = r"([A-Za-z0-9_@%+=:,./-]+|'([^']|'\\'')*')"
LIVE_REFUSAL_FORMS = {
    "unavailable": re.compile(
        rf"{_CONTEXT}live capture unavailable: {_DOING} is not supported on "
        rf"this host{_ERRNO}{_SCAN_TAIL}"),
    "did not start": re.compile(
        rf"{_CONTEXT}live capture did not start: {_DOING} failed{_ERRNO}"
        rf"{_SCAN_TAIL}"),
    "refused (user namespace)": re.compile(
        _CONTEXT + re.escape(
            f"live capture refused: {_USERNS_CAUSE}; or use "
            "'p11scope inspect --pid N' for a scan without capture.")),
    "refused (capabilities held)": re.compile(
        rf"{_CONTEXT}live capture refused: the kernel refused to {_OPERATION}"
        rf"{_ERRNO} with (CAP_BPF and CAP_PERFMON|CAP_SYS_ADMIN){_HELD_TAIL}"),
    "needs": re.compile(
        rf"{_CONTEXT}live capture {_NEEDS}: the kernel refused to {_OPERATION}"
        rf"{_ERRNO}\. Grant the minimal set: {_SETCAP}{_BINARY}, or use "
        r"'p11scope inspect --pid N' for a scan without capture\."),
}


class Candidates:
    """Every line starting with one proof label, as text (None when a
    byte is outside printable ASCII)."""

    def __init__(self):
        self.items = []

    def add(self, raw):
        self.items.append(printable(raw))

    def single(self):
        """The one printable candidate, or None when absent/repeated/bad."""
        if len(self.items) != 1 or self.items[0] is None:
            return None
        return self.items[0]


class ObserverText:
    """The observer's text, classified once by proof label."""

    def __init__(self, data):
        self.present = data is not None
        data = data or b""
        self.lines = split_lines(data)
        self.seal = Candidates()
        self.stop = Candidates()
        self.decoder = Candidates()
        self.key_summary = Candidates()
        self.key_refusal = Candidates()
        self.live_refusal = Candidates()
        self.key_rows = Candidates()
        lowered = data.lower()
        self.crashed = any(marker in lowered for marker in CRASH_MARKERS)
        for raw in self.lines:
            if raw.startswith(SEAL_LABEL.encode()):
                self.seal.add(raw)
            elif raw.startswith(STOP_LABEL.encode()):
                self.stop.add(raw)
            elif raw.startswith(DECODER_LABEL.encode()):
                self.decoder.add(raw)
            elif raw.startswith(KEY_REFUSAL_LABEL.encode()):
                self.key_refusal.add(raw)
            elif raw.startswith(tuple(label.encode() for label in LIVE_REFUSAL_LABELS)):
                self.live_refusal.add(raw)
            elif KEY_SUMMARY_LABEL_RE.match(raw.decode("latin-1")):
                self.key_summary.add(raw)
            elif raw.startswith(KEY_ROW_LABEL.encode()):
                self.key_rows.add(raw)

    def first_refusal(self):
        """The first key-operations refusal or omitted-build line, cut."""
        for raw in self.lines:
            if (KEY_REFUSAL_LABEL.encode() in raw
                    or OMITTED_BUILD_REASON.encode() in raw):
                return raw.decode("ascii", "replace")[:160]
        return None

    def observations(self):
        """The key-operations display state, recorded, never gated."""
        text = b"\n".join(self.lines)
        if re.search(rb"key operations: not available.*bootstrap_unavailable", text):
            return "bootstrap_unavailable"
        if b"key operations: rev " in text:
            return "populated"
        if b"not reported by this version" in text or b"journal_unavailable" in text:
            return "journal_unavailable"
        return "unknown"


def live_refusal_form(text):
    """The producer arm one refusal record matches, or None."""
    for name, form in LIVE_REFUSAL_FORMS.items():
        if form.fullmatch(text):
            return name
    return None


# ------------------------------------------------------------- the probe

class ProbeEvidence:
    """One probe file, parsed once by the report's grammar."""

    def __init__(self, path):
        self.present = path is not None and Path(path).is_file()
        if self.present:
            self.loads, self.problems = report.read_probe_file(path)
        else:
            self.loads, self.problems = [], ["probe file missing"]
        self.typed = [report.checked_load(row) for row in self.loads]

    @property
    def valid(self):
        return not self.problems

    def any_journal_loaded(self):
        """Any validated load row of a journal root that loaded.

        A refusal control's "no journal loads" claim counts every
        validated row, whatever its group or auxiliary tag: counting
        more loads can only refuse more.
        """
        return any(entry["root"] in JOURNAL_ROOTS and entry["loaded"]
                   for entry in self.typed)

    def object_roots_loaded(self, object_name):
        """Roots that loaded within the requested object's BTF groups.

        The same selection the verifier report scores, so the pair proof
        never counts a row the report assigns elsewhere.
        """
        candidates = [entry for entry in self.typed
                      if entry["auxiliary"] is None]
        selected = report.select_object_loads(candidates, object_name, [])
        return {entry["root"] for entry in selected if entry["loaded"]}


def problem_reason(problems):
    shown = "; ".join(problems[:3])
    more = f" (+{len(problems) - 3} more)" if len(problems) > 3 else ""
    return f"probe rows unreadable or corrupt ({shown}{more})"


# --------------------------------------------------------------- verdicts

def control_reasons(rc, text, probe):
    """Pre-Multi refusal control: the finite live-capture refusal."""
    reasons = []
    record = text.live_refusal.single() if text.present else None
    if record is None or live_refusal_form(record) is None:
        reasons.append("finite live-capture refusal missing")
    if rc == 1:
        pass
    elif rc == 124:
        reasons.append("observer timed out past its backstop (rc=124), not a finite refusal")
    elif 129 <= rc <= 143:
        reasons.append(f"observer signaled (rc={rc}), not a finite refusal")
    else:
        reasons.append(f"observer exited rc={rc}, want 1 (finite refusal)")
    if not probe.valid:
        reasons.append(problem_reason(probe.problems))
    if probe.any_journal_loaded():
        reasons.append("journal pair loaded on a pre-Multi kernel")
    if not text.present or text.crashed:
        reasons.append("observer crashed or left no log")
    return reasons


def omitted_reasons(rc, text, probe):
    """Omitted-build control: the exact journal-pair refusal, rc 0."""
    reasons = []
    record = text.key_refusal.single() if text.present else None
    if record != OMITTED_REFUSAL:
        reasons.append("exact journal-pair-unavailable-in-build refusal missing")
    if rc != 0:
        reasons.append(f"observer exited rc={rc}, want 0")
    if not probe.valid:
        reasons.append(problem_reason(probe.problems))
    if probe.any_journal_loaded():
        reasons.append("journal pair loaded although the build omits the object")
    if not text.present or text.crashed:
        reasons.append("observer crashed or left no log")
    return reasons


def linked_reasons(text):
    """The linked proof: sealed once, no refusal, joined calls."""
    refusal = text.first_refusal()
    if refusal is not None:
        return [f"linked lane refused: {refusal}"]
    seal = text.seal.single()
    if seal not in SEAL_FORMS:
        return ["semantic lane never sealed"]
    stop = text.stop.single()
    match = STOP_RE.fullmatch(stop) if stop is not None else None
    if match is None:
        if not text.stop.items:
            return ["linked lane idle (no joined calls)"]
        return ["linked lane idle (no single well-formed semantic calls record)"]
    if match["joined"] == "0" or match["bindings"] == "0":
        return ["linked lane idle (no joined calls)"]
    return []


def key_size_reasons(text):
    """--key-sizes: rendered key rows, a classified RSA-2048 sign row and
    one provable terminal zero decoder record."""
    reasons = []
    summary = text.key_summary.single()
    match = KEY_SUMMARY_RE.fullmatch(summary) if summary is not None else None
    plural_ok = match is not None and all(
        (match[count] == "1") == (match[suffix] == "")
        for count, suffix in (("keys", "ks"), ("providers", "ps"),
                              ("sessions", "ss")))
    if match is None or not plural_ok:
        reasons.append("key rows never rendered under --key-sizes")
    elif not any(row is not None and RSA_ROW_RE.fullmatch(row)
                 for row in text.key_rows.items):
        reasons.append("no classified RSA-2048 size under --key-sizes")
    decoder = text.decoder.single()
    decoded = DECODER_RE.fullmatch(decoder) if decoder is not None else None
    if decoded is None or decoded["unprovable"] != "0" or decoded["total"] == "unknown":
        reasons.append("raw malformed count absent or unprovable under --key-sizes")
    elif decoded["total"] != "0":
        reasons.append("malformed journal records under --key-sizes")
    return reasons


def report_summary(rows, object_name):
    """(count, max processed, its root, min headroom, first FAIL)."""
    count, best_proc, best_root, best_head, failed = 0, -1, "-", None, None
    for row in rows:
        if not row["root"].startswith(object_name + "/"):
            continue
        count += 1
        if row["processed"] is not None and row["processed"] > best_proc:
            best_proc, best_root = row["processed"], row["root"]
        headroom = report.headroom_text(row)
        if headroom != "-" and (best_head is None or float(headroom) < best_head):
            best_head = float(headroom)
        if row["status"] == "FAIL" and failed is None:
            failed = f"{row['root']}: {row['detail']}"
    return (count, best_proc, best_root,
            f"{best_head:.2f}" if best_head is not None else "-", failed)


def budgets_cover(budgets, object_name, kernel):
    return any(name.startswith(object_name + "/") and kernel in cells
               for name, cells in budgets["programs"].items())


def load_verdict(args, rc, text, probe, workload):
    """(reasons, detail, report table) for a load kernel."""
    reasons = []
    if rc == 124:
        reasons.append("observer timed out past its backstop")
    elif rc != 0:
        reasons.append(f"observer exited rc={rc}")
    if not text.present:
        reasons.append("observer left no log")
    elif text.crashed:
        reasons.append("observer crashed")
    if text.present:
        reasons.extend(linked_reasons(text))
        if args.key_sizes == "1":
            reasons.extend(key_size_reasons(text))
    if not probe.present:
        reasons.append("no probe rows (probe file missing)")
    else:
        if not probe.valid:
            reasons.append(problem_reason(probe.problems))
        pair = PAIR + (LENGTH_PAIR if args.key_sizes == "1" else ())
        loaded = probe.object_roots_loaded(args.object)
        if not all(root in loaded for root in pair):
            missing = sum(1 for root in pair if root not in loaded)
            if missing < len(pair):
                reasons.append(f"journal pair incomplete ({missing} of "
                               f"{len(pair)} roots missing)")
            else:
                reasons.append("journal pair missing from probe rows")
    budgets = None
    budgeted = "unbudgeted"
    errors = []
    if args.budgets:
        try:
            document = report.read_budgets(args.budgets)
        except report.ReportError as error:
            errors.append(str(error))
        else:
            if budgets_cover(document, args.object, args.kernel):
                budgets, budgeted = document, "budgeted"
    errors.extend(f"{args.probe}: {problem}" for problem in probe.problems)
    rows = []
    if not errors:
        try:
            rows = report.evaluate(probe.loads, args.kernel, budgets, args.object)
        except report.ReportError as error:
            errors.append(str(error))
    table = report.format_table(rows, args.kernel, args.observer_sha256, errors)
    count, best_proc, best_root, best_head, failed = report_summary(rows, args.object)
    report_failed = (bool(errors) or not rows
                     or any(row["status"] not in ("PASS", "EXPECTED") for row in rows))
    if report_failed:
        reasons.append(f"verifier report FAIL ({failed})" if failed
                       else "verifier report FAIL")
    ledgers = 0
    if workload is not None:
        ledgers = sum(1 for raw in split_lines(workload) if raw.startswith(b"LEDGER "))
    detail = (f"linked sealed live; observations={text.observations()}; "
              f"{count} journal rows; max {best_proc} {best_root}; "
              f"min headroom {best_head}%; {ledgers} workload LEDGERs; {budgeted}")
    return reasons, detail, table


def results_row(cell, passed, qualification, detail):
    return json.dumps({"cell": cell, "pass": passed,
                       "qualification": qualification, "detail": detail})


def read_optional(path):
    if path is None:
        return None
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return None


def run_verdict(args):
    rc = int(args.rc)
    text = ObserverText(read_optional(args.text))
    probe = ProbeEvidence(args.probe)
    cell = f"journal-load-{args.kernel}"
    if args.mode == "control":
        reasons = control_reasons(rc, text, probe)
        label, detail = "control", f"refused live-capture; no journal loads; rc={rc}"
        verdict_text = "PASS (refused live-capture)"
    elif args.mode == "omitted":
        reasons = omitted_reasons(rc, text, probe)
        label = "omitted"
        detail = f"refused journal-pair-unavailable-in-build; no journal loads; rc={rc}"
        verdict_text = f"PASS ({detail})"
    else:
        reasons, detail, table = load_verdict(
            args, rc, text, probe, read_optional(args.workload))
        Path(args.report_out).write_text(table, encoding="ascii")
        sys.stdout.write(table)
        label = "load"
        verdict_text = f"PASS ({detail})"
    if reasons:
        joined = "; ".join(reasons)
        print(f"# {label} {args.kernel}: FAIL ({joined})")
        row = results_row(cell, False, "failed", joined)
    else:
        print(f"# {label} {args.kernel}: {verdict_text}")
        row = results_row(cell, True, "qualified", detail)
    with open(args.results, "a", encoding="ascii") as stream:
        stream.write(row + "\n")
    return EXIT_FAILED if reasons else EXIT_QUALIFIED


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    guest = commands.add_parser("guest")
    guest.add_argument("--kernel", required=True)
    guest.add_argument("log")
    budgets = commands.add_parser("budgets")
    budgets.add_argument("file")
    row = commands.add_parser("row")
    row.add_argument("cell")
    row.add_argument("passed", choices=("0", "1"))
    row.add_argument("qualification",
                     choices=("qualified", "failed", "nonqualifying"))
    row.add_argument("detail")
    verdict = commands.add_parser("verdict")
    verdict.add_argument("--mode", required=True,
                         choices=("load", "control", "omitted"))
    verdict.add_argument("--kernel", required=True)
    verdict.add_argument("--object", required=True,
                         choices=("journal", "journal-gate1"))
    verdict.add_argument("--key-sizes", required=True, choices=("0", "1"))
    verdict.add_argument("--rc", required=True)
    verdict.add_argument("--text", required=True)
    verdict.add_argument("--probe", required=True)
    verdict.add_argument("--workload")
    verdict.add_argument("--budgets")
    verdict.add_argument("--observer-sha256", required=True)
    verdict.add_argument("--report-out", required=True)
    verdict.add_argument("--results", required=True)
    args = parser.parse_args(argv)
    if args.command == "guest":
        try:
            data = Path(args.log).read_bytes()
        except OSError:
            print("infra\tguest console log unreadable")
            return 0
        status = guest_status(data, args.kernel)
        print("\t".join(str(part) for part in status))
        return 0
    if args.command == "budgets":
        try:
            report.read_budgets(args.file)
        except report.ReportError as error:
            print(str(error))
            return 1
        return 0
    if args.command == "row":
        print(results_row(args.cell, args.passed == "1", args.qualification,
                          args.detail))
        return 0
    if not _status(args.rc):
        parser.error(f"bad --rc {args.rc!r}")
    return run_verdict(args)


if __name__ == "__main__":
    sys.exit(main())
