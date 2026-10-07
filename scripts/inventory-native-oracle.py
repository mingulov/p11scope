#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent oracle for the installed `p11scope inventory` acceptance (Task 6 C8).

Ground truth is the per-process ledger printed by
tests/fixtures/public-cli/inventory-ledger.c, never p11scope state. The oracle
reads a run directory written by scripts/qualify-inventory-native.sh:

  RUNDIR/run.json        the run manifest (MANIFEST_ID): providers, cells, observer runs
  RUNDIR/<ledger files>  workload stdout (IDENT/MAPPED/LEDGER/HELD/RETURNED/EXEC/ZOMBIE/DONE)
  RUNDIR/<run outputs>   per observer run: -o JSON, --event-log JSONL, optional PTY bytes

and checks, per observer run, that every ledgered (process image, provider) use
INSIDE THAT RUN'S CAPTURE WINDOW appears on the right caller and module with
coverage consistent with what the lane could observe, that an image idle during
the window holds no positive, that nothing is cross-attributed (also not by a
foreign process on a workload-private module), and that the JSON, the JSONL
stream and the dashboard frames agree. Every expectation and every output
string the oracle parses is a table in the TABLES block below, keyed on the
documented semantics of docs/schema/inventory-v1.md and inventory-events-v1.md
(SCHEMAS): a schema or dashboard revision (Task 7) edits tables, not logic.

Statuses: pass | fail | absent | unbound | nonqualifying | skip.
  absent         a native-only assertion found no native lane: FAIL when the run
                 expects the native lane, otherwise non-qualifying.
  unbound        a ledgered use accepted only as a module-level unbound positive
                 (plan §3.3); allowed for the roles/exec steps that table permits.
  nonqualifying  the run is incomplete by declaration (e.g. dashboard skipped).
Exit codes (EXIT): 0 qualified (no fail, no absent, no nonqualifying); 1 any
fail; 2 no fail but non-qualifying (absent or nonqualifying rows, e.g. a
`--lane scan` plumbing run); 64 usage. A run with zero passing assertions fails.

Clock assumption: ledger t0/t1 and p11scope's *_ns are both CLOCK_MONOTONIC and
are compared directly, which holds only while workload and observer share one
time namespace (host, vng guest). A container lane with its own time namespace
must translate ledger times by the namespace offset before running this oracle.

usage:
  inventory-native-oracle.py check RUNDIR        full oracle (exit codes above)
  inventory-native-oracle.py ledgers RUNDIR      ledger self-consistency only
  inventory-native-oracle.py count-kind JSONL KIND   events of KIND (EVENT_KINDS key) so far
  inventory-native-oracle.py probe-help          read `p11scope --help` on stdin, print FLAG=0|1
  inventory-native-oracle.py record-pty OUT ROWS COLS BUDGET_S STOP_AFTER_S -- ARGV...
  inventory-native-oracle.py --self-test         synthetic pass + must-fail fixtures
"""

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field

# ===========================================================================
# TABLES — every expectation and every parsed output string lives here.
# ===========================================================================

ORACLE_ID = "p11scope-c8-oracle/2"
MANIFEST_ID = "p11scope-c8-run/2"
SCHEMAS = {
    "inventory": "p11scope/inventory/v1",
    "events": "p11scope/inventory-events/v1",
}
EXIT = {"qualified": 0, "failed": 1, "nonqualifying": 2, "usage": 64}

# --- inventory-v1 snapshot ---------------------------------------------------
# Seven keys since Task 6 C3: `until_ns` is null while capture runs and, after a
# stop, the frozen end of a watched interval (`since_ns..until_ns`).
COVERAGE_KEYS = frozenset({"state", "since_ns", "until_ns", "first_ns", "lossy", "reason", "detail"})
COVERAGE_STATES = frozenset({"counted", "witnessed", "watched_no_use", "unknown"})
WATCH_STATE = "watched_no_use"
UNKNOWN_STATE = "unknown"
SCAN_ONLY_REASON = "scan_only"
OBSERVATION_OBSERVED = "observed"
OBSERVATION_LOSSY_ZERO = "unknown (usage observation lossy)"
SEMANTICS_OBSERVED = "observed"
# The documented reasons no semantic claim exists (edges[].semantics).
SEMANTICS_UNKNOWN_LABELS = frozenset({
    "unknown (semantic capture withheld)",
    "unknown (unauthoritative module)",
    "unknown (ambiguous descriptor)",
    "unknown (count-only slot)",
    "unknown (no operation evidence)",
    "unknown (same-file double-load)",
})
CALLER_LIVE_LIFECYCLE = "mapped"
MAPPING_LIVE = "mapped"
MAPPING_ENDED = "ended"
# A counted feed that lost records must say so in gaps[] (plan §3.5 note_capture_loss).
LOSS_GAP = re.compile(r"\bloss\b|\blost\b|lossy", re.I)
# O1 partial attach (fix round 1): failed endpoints make their module
# undercount (PARTIAL_ATTACH_SUBJECT in
# src/discovery/inventory_coordinator.rs) — counted uses are lower
# bounds, so COUNT-EXACT over the module is explicitly nonqualifying
# and the COUNT-WINDOW lower bound is clamped (saturation-shaped).
PARTIAL_ATTACH = re.compile(r"endpoint attach fail", re.I)
# Unbound positive (plan §3.3, "used by an unidentified caller image").
UNBOUND_GAP = re.compile(r"unidentified caller|unbound (caller|witness)", re.I)
# A gap field naming when the unbound use happened (first match wins).
UNBOUND_GAP_TIME_KEYS = ("first_ns", "t0_ns", "witness_ns")
# R-C51-2 (controller, 2026-10-03): an image whose use bound to no caller is
# covered by a pid-less unbound gap of its module plus one row of the pass
# markers' `unbound_rows` counts (the product names no pid for never-admitted
# processes), from a pass committed at or after the image's first call. A
# short-lived image's row is sighted with no live caller.
COUNTED_SHORT_LIVED_REASONS = ("no_live_caller",)
# R-C51-1: an image that used the module before its caller's admission leaves
# the pair's only row unbound (read before the admission: no_live_caller;
# after: before_admission); the product then reads its caller's edge unknown
# `use_before_admission`, never a positive or a watch.
USE_BEFORE_ADMISSION = "use_before_admission"
# DR-LIVE-LABEL-LAG: a read-but-undecided first use of a watched edge.
# Transient: the finish flush decides every row, so the final snapshot
# never carries it — only mid-run frames and edge_observed records do.
PENDING_FIRST_USE_REASON = "pending_first_use"
# C7 C4/C5: a CALLER_USE pair insert failed, so some pair has use but no
# row and absence proves nothing. The edge reads unknown/`uncounted`
# (never 0) with a zero no consumer reads as fact, and no watch starts
# again in the capture. Choice 1 (controller-accepted): the trigger is
# BPF PairInsertFailure evidence only, never the userspace pair
# precondition — so the reason requires the gap below plus evidence
# naming PairInsertFailure in its detail, while counted positives frozen
# before the evidence stand (the exact-count exception).
UNCOUNTED_REASON = "uncounted"
PAIRS_UNCOUNTED_SUBJECT = "usage coverage pair insert failure"
PAIR_INSERT_EVIDENCE = re.compile(r"PairInsertFailure")
SCAN_ONLY_REASON = "scan_only"
# The only unknown reasons a scan-lane document gives (an unadmitted module
# reads not_admitted in either lane).
SCAN_LANE_REASONS = frozenset({SCAN_ONLY_REASON, "not_admitted", None})
# Preference order (UnboundPool.claim): before_admission rows serve only
# pre-admission images.
COUNTED_PREADMISSION_REASONS = ("before_admission", "no_live_caller")
# An exec-chain image's row may stay unbound by the binder's documented exec
# rules (inventory-v1 `unbound_reasons`: Rule 4 `exec_after_admission`, and
# `exec_transition`, `exec_coverage_gap`, `cookie_mismatch` for a nonleader
# exec) - never a loss, never a pid. Exec-only reasons come first so the
# shared reasons' rows stay for short-lived and leader-exit images (L-4).
COUNTED_EXEC_REASONS = ("exec_after_admission", "exec_transition", "exec_coverage_gap", "cookie_mismatch")
COUNTED_EXEC_CHAIN_REASONS = COUNTED_EXEC_REASONS + ("before_admission", "no_live_caller")
COUNTED_EXEC_PREADMISSION_REASONS = ("before_admission",) + COUNTED_EXEC_REASONS + ("no_live_caller",)
# The --system deep-scan selection bound (inventory --max-scan-pids).
SCAN_LIMIT_GAP = re.compile(r"selected \d+ for deep scanning", re.I)
# Retirement settlement after a stop (plan C5: "retirement: unsettled";
# activation `terminal_unsettled`). Path -> {document value: verdict}.
SETTLEMENT_PATHS = [
    (("observation", "retirement"), {"unsettled": "unsettled", "settled": "settled", "complete": "settled"}),
    (("observation", "settlement"), {"unsettled": "unsettled", "settled": "settled", "complete": "settled"}),
    (("observation", "terminal_unsettled"), {True: "unsettled", False: "settled"}),
    (("retirement",), {"unsettled": "unsettled", "settled": "settled", "complete": "settled"}),
]
# An object-shaped settlement value (e.g. {"state": "unsettled", "reason": ...})
# carries its verdict under the first of these keys; any other shape is rejected.
SETTLEMENT_OBJECT_KEYS = ("state", "verdict", "status", "settlement")
SETTLEMENT_GAPS = [(re.compile(r"\bunsettled\b", re.I), "unsettled")]
# Under the current contract Inventory has no quiescence protocol: a stop with a
# call still held must read unsettled (plan §1 activation, §6).
HELD_STOP_REQUIRES = "unsettled"
STOP_OK_RC = frozenset({0})
RUN_OK_RC = frozenset({0})

# --- inventory-events-v1 stream ----------------------------------------------
EVENT_KINDS = {
    "started": "started",
    "ended": "ended",
    "gap": "gap_recorded",
    "gap_repeated": "gap_repeated",
    "pass": "pass_committed",
    "caller": "caller_event",
    "edge": "edge_observed",
    "rotated": "rotated",
    "evicted": "retention_evicted",
}
# caller_event sub-kind -> field naming the incarnation it mints.
CALLER_EVENT_MINTS = {"admitted": "caller", "exec_retired": "new", "reused": "new"}
# C7 C4/C5: a count change that is not a class change emits at most once
# per edge per 10 s (EDGE_COUNT_EMIT_INTERVAL_NS); class changes —
# including log2 bucket jumps (Choice 2, controller-accepted) — stay
# immediate, and the final sweep stays exact.
COUNT_EMIT_INTERVAL_NS = 10_000_000_000

# --- presentation: dashboard frames and edge_observed derived states ---------
ACTIVITY = {
    "recent": "recently observed",
    "inflight": "operation initialized / in flight",
    "used": "used (recency unknown)",
    "quiet": "quiet",
    "lossy": "unknown (lossy)",
    "uncovered": "not covered",
    "unknown": "unknown",
}
CAPTURE = {
    "armed": "armed", "scan_only": "scan only", "refused": "refused",
    "retired": "retired", "lost": "coverage lost", "ended": "watch ended",
}
PRESENCE = {"mapped": "mapped", "unloaded": "unloaded", "exited": "process exited", "unknown": "unknown"}
EDGE_STATES = ("presence", "capture", "activity")
# Choice 3 (ACT re-rule): the recorded activity signal is per-pass
# ("rose since previous pass"), window-free. The dashboard display
# keeps its own trailing window, but frames never reach this oracle
# with a frame time, so DASH-EDGE-LABELS admits base-or-recent there.
FRAME = {
    "repaint": b"\x1b[H",
    "alt_on": b"\x1b[?1049h",
    "alt_off": b"\x1b[?1049l",
    "coverage_marker": b"coverage:",
    "ansi": re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]"),
    "header": re.compile(r"^p11scope inventory (\S+) \| (\d+) passes \| (\d+) callers (\d+) modules (\d+) edges"),
    "coverage": re.compile(r"^coverage: (\d+) gaps"),
    "identity": re.compile(r"^(c\d+) pid (\d+) \((.*)\) -> (m\d+) \((.*)\)$"),
    "item_indent": "  ",
    "item_sep": " | ",
    "section": "---",
}
# Frame item key -> how the oracle derives the expected value.
FRAME_ITEMS = ("capture", "activity", "entries", "semantics")

# O3: at_ns stamps are u64 CLOCK_MONOTONIC nanoseconds (the JSON writer
# emits Rust u64s): exact int type within 0..u64::MAX. isinstance is
# bool-blind and unbounded, so it must never gate a clock.
U64_MAX = 2**64 - 1


def is_u64_clock(value):
    """Whether `value` is a well-formed u64 clock stamp."""
    return type(value) is int and 0 <= value <= U64_MAX


def saturation_coherent(count, saturated, cap):
    """O7 coherence arithmetic: saturated holds exactly at the cap."""
    return saturated == (count == cap)


def count_window_ok(count, saturated, lo, hi):
    """O7 window arithmetic: a saturated feed is clamped at the cap, so
    the lower bound cannot hold it; the upper bound still can."""
    return (saturated or lo <= count) and count <= hi


def is_saturated_artifact(entries):
    """Whether the edge's saturation triple earns the saturated
    exemptions: production-shaped (fixed u64::MAX cap, u64 count,
    Boolean flag) and actually saturated at the cap. Anything else —
    a forged cap, a non-u64 count, a non-Boolean flag — earns no
    exemption (COUNT-SATURATED fails it separately)."""
    cap, count, saturated = entries.get("cap"), entries.get("count"), entries.get("saturated")
    return (type(cap) is int and cap == U64_MAX
            and type(count) is int and 0 <= count <= U64_MAX
            and type(saturated) is bool
            and saturated and count == cap)

# --- CLI probe ----------------------------------------------------------------
HELP_PROBE = {"usage": "p11scope inventory", "flags": {"capture": "--capture", "manifest": "--manifest"}}

# --- workload roles -------------------------------------------------------------
@dataclass(frozen=True)
class Role:
    bind: str  # required | optional: may a used image fall back to an unbound gap?
    scan_presence: str  # required: a scan document must hold the live edge
    native_states: frozenset  # coverage allowed on the role's in-window used edges
    require_counted_when_attested: bool
    what: str
    # C7 C5: the role's used edges read counted unconditionally (the P1/P2
    # ledger cells, Counted even for unattested B), whatever attested
    # delivery says. Since v0.3.0 the native lane counts every bound row.
    require_counted: bool = False


USED = frozenset({"counted", "witnessed"})
IDLE = frozenset({WATCH_STATE, UNKNOWN_STATE})
ROLES = {
    "P1": Role("required", "required", USED, True, "attested provider A with Digest/AES-GCM/HMAC",
               require_counted=True),
    "P2": Role("required", "required", USED, False, "byte-identical copy B, distinct inode, unattested",
               require_counted=True),
    "P3": Role("required", "required", IDLE, False, "maps A and C, never calls them"),
    "P4": Role("optional", "optional", USED, False, "~100 ms CLI calling A"),
    "P5": Role("optional", "optional", USED, False, "exec chain (bind per EXEC_HOW_BIND)"),
    "P6": Role("required", "required", USED, False, "held call in the held provider, SIGINT"),
    "P7": Role("required", "required", USED, True, "late dlopen of A after capture start"),
    "LX": Role("optional", "optional", USED, False, "leader pthread_exit, worker keeps calling"),
}
# Exec chain: how an image was reached decides whether it must bind (plan §3.3:
# a leader exec is an exact exec_id transition; a non-leader exec changes the
# cookie answer and may leave the row unbound).
EXEC_HOW_BIND = {"initial": "required", "leader": "required", "thread": "optional"}
# Optional-bind cells must still bind at least one image per run.
OPTIONAL_CELL_MIN_BOUND = 1
# Counted = a counting feed. Before C7 C4 only the Detailed subset for
# operator-attested providers counted; per-pair BPF counts shipped (C1
# entry_count, C4 publish), so the native lane counts every bound row and
# attestation no longer gates the state (flipped C7 C5).
COUNTED_NEEDS_ATTESTED = False
# C7 C5 (r1 T3.5): the P1/P2 ledger cells pin counted edges with exact
# entry counts — including Counted for the unattested byte-copy B — via
# Role.require_counted above, overriding COUNTED_NEEDS_ATTESTED for those
# roles; other roles still accept the witnessed/count distinction.
# Runs the qualification needs, and the roles each must cover.
REQUIRED_RUNS = {
    "system": frozenset({"P1", "P2", "P3", "P4", "P5", "P7", "LX"}),
    "stop": frozenset({"P6"}),
    "dashboard": frozenset({"P1", "P2", "P3", "P7"}),
}
# Runs whose absence the manifest may declare (then the run is non-qualifying).
SKIPPABLE_RUNS = frozenset({"dashboard"})

# --- ledger -----------------------------------------------------------------------
# C7 C5 ledger rule (binding): ledger `calls` counts ATTACH-side calls
# only. BPF increments entry_count on entry-probe fire, so only calls
# through attached function-table endpoints count; the dlsym C_GetFunctionList
# entry — the call that receipts the table, not a call through it — is
# excluded (Use.table_calls). Error-returning calls are included: entry,
# not return, is what both the ledger and BPF count.
# O8 receipt boundary: the exclusion is acquisition-only — the
# setup-phase dlsym call, never made through an attached slot. A dlsym
# name alone does not exempt a call made after the endpoint is armed:
# through-table calls count whatever they are named. LEDGER-COUNTS pins
# exactly one setup C_GetFunctionList per provider, so the fixture
# never holds an ambiguous second setup one.
SYMBOL_ENTRY_FUNCTIONS = frozenset({"C_GetFunctionList"})
WITNESS_SLACK_NS = 20_000_000
EXEC_GAP_MIN_NS = 4 * WITNESS_SLACK_NS
OP_CATEGORY = {
    "C_DigestInit": "digest", "C_EncryptInit": "encrypt", "C_DecryptInit": "decrypt",
    "C_SignInit": "sign", "C_VerifyInit": "verify", "C_GenerateKey": "generate_key",
}
MAIN_PLAN = [("C_DigestInit", "0x250"), ("C_Digest", "0x250"), ("C_GenerateKey", "0x1080"),
             ("C_EncryptInit", "0x1087"), ("C_Encrypt", "0x1087"), ("C_GenerateKey", "0x350"),
             ("C_SignInit", "0x251"), ("C_Sign", "0x251")]
SETUP_FNS = ["C_GetFunctionList", "C_Initialize", "C_GetSlotList", "C_OpenSession", "C_Login"]
TEARDOWN_FNS = ["C_Logout", "C_CloseSession", "C_Finalize"]
LEDGER_KINDS = ("IDENT", "MAPPED", "LEDGER", "HELD", "RETURNED", "EXEC", "ZOMBIE", "DONE", "READY",
                "LEDGER_UNFLUSHED")
ZOMBIE_STATE = "Z"

# ===========================================================================
# Results
# ===========================================================================

STATUSES = ("pass", "fail", "absent", "unbound", "nonqualifying", "skip")


class Results:
    def __init__(self, expect_lane):
        self.expect_lane = expect_lane
        self.rows = []

    def add(self, run, cell, check, status, detail):
        assert status in STATUSES, status
        if status == "absent" and self.expect_lane == "native":
            status, detail = "fail", "native lane absent: " + detail
        elif status == "absent":
            detail = "native lane absent (expected lane: scan): " + detail
        self.rows.append({"run": run, "cell": cell, "check": check, "status": status, "detail": detail})

    def ok(self, run, cell, check, cond, detail_fail, detail_pass="ok"):
        self.add(run, cell, check, "pass" if cond else "fail", detail_pass if cond else detail_fail)
        return cond

    def failed(self):
        return [r for r in self.rows if r["status"] == "fail"]

    def summary(self):
        counts = {}
        for r in self.rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return counts

    def exit_code(self):
        if self.failed():
            return EXIT["failed"]
        if any(r["status"] in ("absent", "nonqualifying") for r in self.rows):
            return EXIT["nonqualifying"]
        return EXIT["qualified"]


# ===========================================================================
# Ledger
# ===========================================================================

@dataclass
class Image:
    cell: str
    pid: int
    start: int
    gen: int
    exe: str
    mapped: dict = field(default_factory=dict)
    entries: list = field(default_factory=list)
    done: str = ""
    held_t: int = None
    returned_t: int = None
    execs: list = field(default_factory=list)
    zombie: str = ""
    unflushed: bool = False


def parse_kv(line):
    parts = line.split()
    out = {}
    for token in parts[1:]:
        if "=" not in token:
            raise ValueError(f"malformed token {token!r}")
        k, v = token.split("=", 1)
        out[k] = v
    return parts[0], out


def parse_ledger(text, errors):
    images = {}
    for raw in text.splitlines():
        if not raw or raw.split(" ", 1)[0] not in LEDGER_KINDS:
            continue
        try:
            kind, kv = parse_kv(raw)
            if kind == "LEDGER_UNFLUSHED":
                errors.append(f"workload died with its ledger lock held: {raw!r}")
                continue
            key = (kv["cell"], int(kv["pid"]), int(kv["start"]), int(kv["gen"]))
        except (ValueError, KeyError) as error:
            errors.append(f"unparseable ledger line {raw!r}: {error}")
            continue
        image = images.get(key)
        if image is None:
            image = images[key] = Image(key[0], key[1], key[2], key[3], kv.get("exe", ""))
        if kind == "MAPPED":
            image.mapped[kv["module"]] = int(kv["ino"])
        elif kind == "LEDGER":
            image.entries.append({
                "module": kv["module"], "fn": kv["fn"], "mech": kv["mech"], "n": int(kv["n"]),
                "bad": int(kv["bad"]), "phase": kv["phase"], "t0": int(kv["t0"]), "t1": int(kv["t1"]),
            })
        elif kind == "HELD":
            image.held_t = int(kv["t"])
        elif kind == "RETURNED":
            image.returned_t = int(kv["t"])
        elif kind == "EXEC":
            image.execs.append((kv["how"], kv["next"]))
        elif kind == "ZOMBIE":
            image.zombie = kv["state"]
        elif kind == "DONE":
            image.done = kv["status"]
    return images


def legacy_table_call(fn, phase):
    """The phase-only classifier: every call through the function table
    except the setup-phase acquisition dlsym. The acquisition's arming
    question (below) is asked against this set — never against a set
    that already assumes the answer."""
    return fn not in SYMBOL_ENTRY_FUNCTIONS or phase != "setup"


def legacy_end_before_since(entries, since_ns):
    """The latest end stamp of a legacy attach-side line ending strictly
    before since_ns — the workload-side evidence of which line may hold
    the recording call. None when no legacy line ends before the first
    row. Only lines that made calls (n > 0, the counted population)
    qualify."""
    ends = [e["t1"] for e in entries
            if e["n"] > 0 and legacy_table_call(e["fn"], e.get("phase"))
            and type(e.get("t1")) is int and e["t1"] < since_ns]
    return max(ends) if ends else None


def is_table_call(fn, phase, entry=None, arming=None):
    """Whether the ledger line is a call through the function table (what
    BPF counts). The setup-phase acquisition dlsym is a possible
    recording call (round 2): it is excluded ONLY with evidence it
    missed — a legacy attach-side line ending at/after its own end but
    strictly before the edge's first BPF row, so that line (or a later
    one), not the acquisition, holds the recording call. `arming` is
    (since_ns, legacy_end_before): the edge's first BPF row and the
    latest legacy line end before it. Without timing context the
    legacy exclusion stands. The first-row time alone never proves
    pre-arming: an already-armed acquisition can itself create the
    first row ahead of the first ordinary table call (and then counts),
    and a predating row proves the acquisition executed after the row
    existed — through an armed endpoint (SoftHSM: export == table
    slot) — so it counts too."""
    if legacy_table_call(fn, phase):
        return True
    if entry is None or arming is None:
        return False
    since_ns, legacy_end_before = arming
    if type(since_ns) is not int:
        return False
    t1 = entry.get("t1")
    if type(t1) is not int:
        return False
    if t1 >= since_ns:
        # Overlapping or later: it may have traversed an armed endpoint
        # and counts.
        return True
    # Ended before the row: excluded only if a legacy line proves a
    # later recording call — otherwise the acquisition itself may hold
    # it and counts.
    return not (legacy_end_before is not None and legacy_end_before >= t1)


@dataclass
class Use:
    """One image's ledgered use of one provider, clipped to a capture window."""
    lines: list  # lines overlapping the window
    definite: list  # lines entirely inside the window
    t_first: int
    t_last: int
    mechs: dict

    @property
    def table_calls(self):
        return sum(e["n"] for e in self.lines if is_table_call(e["fn"], e.get("phase")))


def use_in(image, provider_path, window):
    """The image's use of the provider inside window=(start, end), or None."""
    start, end = window
    lines = [e for e in image.entries if e["module"] == provider_path and e["n"] > 0
             and e["t1"] >= start and e["t0"] <= end]
    if not lines:
        return None
    definite = [e for e in lines if e["t0"] >= start and e["t1"] <= end]
    mechs = {}
    for e in definite:
        if e["mech"] != "-" and e["fn"] in OP_CATEGORY:
            mechs.setdefault(int(e["mech"], 16), set()).add(OP_CATEGORY[e["fn"]])
    return Use(lines, definite, max(start, min(e["t0"] for e in lines)), min(end, max(e["t1"] for e in lines)),
               mechs)


def recording_before(use, since_ns):
    """The recording line (Case A) or None.

    since_ns is the first BPF row's insert stamp, taken during the
    recording call's probe: the recording call entered strictly before
    it, and every earlier call missed (no row existed yet). When no
    attach-side line straddles since_ns, the recording call is the last
    entry before it, i.e. it sits on the last attach-side line ending
    strictly before since_ns — which then contributes exactly one
    recorded call however many it ledgered. A straddling attach-side
    line (or a same-tick boundary) leaves the recording call's line
    ambiguous and there is no identified recording line."""
    arming = (since_ns, legacy_end_before_since(use.lines, since_ns))
    attach = [e for e in use.lines if is_table_call(e["fn"], e.get("phase"), e, arming)]
    if any(e["t0"] <= since_ns <= e["t1"] for e in attach):
        return None
    before = [e for e in attach if e["t1"] < since_ns]
    return max(before, key=lambda e: (e["t1"], e["t0"])) if before else None


def window_count(use, since_ns, window):
    """(lo, hi) calls a counting feed covering [max(since, start), end] must report.

    Lines completed strictly before since_ns missed (no row existed
    yet) — except the recording line itself (recording_before), whose
    recording call is always included: +1 in lo when fully inside the
    window (that call created the row, so it is counted), +n in hi.
    Lines starting strictly after since_ns are recorded (the row
    exists); same-tick boundaries are ambiguous (hi only). No entry
    timing proves the recording call contributed zero: the workload
    stamps t0/t1 before invocation, so admission or attachment may
    have landed between the stamp and the recorded entry."""
    start, end = max(since_ns, window[0]), window[1]
    lo = hi = 0
    arming = (since_ns, legacy_end_before_since(use.lines, since_ns))
    for e in use.lines:
        if e["t1"] < start or e["t0"] > end:
            continue
        hi += e["n"]
        if e["t0"] > since_ns and e["t0"] >= window[0] and e["t1"] <= end \
                and is_table_call(e["fn"], e.get("phase"), e, arming):
            lo += e["n"]
    rec = recording_before(use, since_ns)
    if rec is not None:
        hi += rec["n"]
        if rec["t0"] >= window[0] and rec["t1"] <= end:
            lo += 1
    return lo, hi


def endpoint_coverage_ok(lines, admission_endpoints):
    """O1 pigeonhole: every distinctly-called endpoint needs an admitted
    endpoint. The caller proves the count is an int first: a missing
    or malformed admission count is explicitly nonqualifying (round
    2), never silently assumed sufficient."""
    return len({e["fn"] for e in lines}) <= admission_endpoints


def has_partial_attach(view, edge):
    """Whether a partial-attach gap clouds the edge's module (O1): a
    module-scoped gap naming the edge's module, or a run-wide
    (module-less) one — either voids endpoint coverage."""
    for gap in view.doc.get("gaps", []):
        if not PARTIAL_ATTACH.search(f"{gap.get('subject', '')} {gap.get('reason', '')}"):
            continue
        if gap.get("module") is None or gap.get("module") == edge.get("module"):
            return True
    return False


def ledger_total_table_calls(image, provider_path, since_ns=None):
    """Every attach-side call the image ledgered for the provider, any time:
    the upper bound a count will never exceed (r1 T3.5 `count <= total`).
    `since_ns` arms the acquisition rule (None: the legacy exclusion)."""
    entries = [e for e in image.entries if e["module"] == provider_path]
    arming = (since_ns, legacy_end_before_since(entries, since_ns)) if since_ns is not None else None
    return sum(e["n"] for e in entries if is_table_call(e["fn"], e.get("phase"), e, arming))


def exact_window_count(use, since_ns, window, until_ns, caller_first_seen_ns,
                       mapping_first_seen_ns=None, admission_endpoints=None,
                       partial_attach=False):
    """(verdict, expected, detail): whether the ledger pins the count.

    Verdicts: "exact" (equality required over the proven covered
    workload segment), "inexact" (window bounds judge — frozen, empty,
    clipped, or unadmitted), "nonqualifying" (insufficient evidence to
    judge either way — recorded explicitly, never a pass or fail).

    The covered segment is BPF-side: lines completed strictly before
    since_ns missed (no row existed — certain zero); lines starting
    strictly after since_ns recorded (the row proves live probes). A
    line spanning since_ns splits unknowably (aggregation) — explicit
    nonqualifying. The recording line (last attach line ending before
    since_ns) is always row-possible: entry stamps precede invocation,
    so no entry timing proves it executed before attachment. It takes
    the legacy Case A (first attach line, singleton, admitted before
    it — full-sum equality, attachment-before-workload convention) or
    is insufficient evidence. Equality additionally requires endpoint
    coverage over the equated lines (every distinctly-called endpoint
    admitted — pigeonhole; no partial-attach gap clouds the module)
    and identity/mapping hold-safety (admission and mapping at or
    before the segment start, so rows bind immediately instead of
    risking hold eviction).

    since_ns is the first BPF row's insert stamp, NOT the attach time:
    entry.rs record_caller_use_with stamps recorded_at_ns = now()
    immediately before the first map insert
    (crates/ebpf-common/src/inventory_callers/entry.rs:90-91), which
    capture.rs absorb_rows copies into the witness row
    (src/attach/inventory/capture.rs:2598), which absorb_pair_counts
    keeps as PairCount.first_ns
    (src/discovery/inventory_coordinator.rs:1675,1680), which
    stage_pair_count publishes as Counted.since_ns
    (src/discovery/inventory_coordinator.rs:1727,1745). The workload
    stamps t0/t1 BEFORE the call
    (tests/fixtures/public-cli/inventory-ledger.c:229), so since_ns
    lands strictly after the recording call's entry stamp on every
    real run and since_ns <= t_first can never gate exactness."""
    arming = (since_ns, legacy_end_before_since(use.lines, since_ns))
    attach = [e for e in use.lines if is_table_call(e["fn"], e.get("phase"), e, arming)]
    # Structural, legacy-verbatim: frozen, empty, or unadmitted (a
    # malformed admission stamp is unadmitted too — the shape checks
    # fail it elsewhere; the oracle never crashes on it).
    # NOTE (round 2): no entry timing proves the recording call
    # contributed zero, so there is no pre-attachment exact arm: the
    # workload stamps t0/t1 before invocation
    # (tests/fixtures/public-cli/inventory-ledger.c:236), and
    # admission/attachment may land between the stamp and the recorded
    # entry. A row-possible recording line takes the legacy Case A
    # below or is insufficient evidence.
    if until_ns is not None:
        return "inexact", 0, ""
    if not attach:
        return "inexact", 0, ""
    if type(caller_first_seen_ns) is not int:
        return "inexact", 0, ""
    # Round 2: the coverage and hold evidence must be present and
    # well-formed before it proves anything — a missing admission
    # count or mapping first-seen is explicitly nonqualifying, never
    # silently skipped or defaulted to admission alone.
    if type(admission_endpoints) is not int:
        return "nonqualifying", 0, "admission endpoint count missing or malformed: endpoint coverage unprovable"
    if type(mapping_first_seen_ns) is not int:
        return "nonqualifying", 0, "mapping first-seen missing or malformed: mapping-hold risk unprovable"
    if any(e["t0"] <= since_ns <= e["t1"] for e in attach):
        return "nonqualifying", 0, "an attach-side line spans the first row: recorded split unknowable"
    if partial_attach:
        return "nonqualifying", 0, "a partial-attach gap clouds the module: counted uses are lower bounds"
    first_attach_t0 = min(e["t0"] for e in attach)
    whole_in_window = not any(e["t0"] < window[0] or e["t1"] > window[1] for e in use.lines)
    # Legacy predating branch (verbatim + evidenced overrides): the row
    # predates every attach-side call (the synth counting convention —
    # real rows stamp during their recording call): all recorded.
    if since_ns < first_attach_t0:
        if caller_first_seen_ns > first_attach_t0 or not whole_in_window:
            return "inexact", 0, ""
        if mapping_first_seen_ns > first_attach_t0:
            return "nonqualifying", 0, "mapping first seen after the first call: mapping-hold risk"
        if not endpoint_coverage_ok(attach, admission_endpoints):
            return "nonqualifying", 0, "more distinct endpoints called than admitted"
        return "exact", sum(e["n"] for e in attach), ""
    # Segment branch: pre-since lines are known zero (no row); post-since
    # lines recorded (the row proves live probes).
    post = [e for e in attach if e["t0"] > since_ns]
    if post:
        first_post_t0 = min(e["t0"] for e in post)
        if caller_first_seen_ns > first_post_t0:
            return "nonqualifying", 0, "admission after the covered segment: hold/eviction risk"
        if mapping_first_seen_ns > first_post_t0:
            return "nonqualifying", 0, "mapping first seen after the covered segment: mapping-hold risk"
        if not endpoint_coverage_ok(post, admission_endpoints):
            return "nonqualifying", 0, "more distinct endpoints called than admitted"
    if any(e["t0"] < window[0] or e["t1"] > window[1] for e in post):
        return "inexact", 0, ""
    rec = recording_before(use, since_ns)
    if rec is None:
        # Unreachable (a missing recording line with a non-predating row
        # means the first line spans it — caught above), kept defensive:
        # every attach line starts after the row, and the recording call
        # sits ledgered inside the first one.
        return "exact", sum(e["n"] for e in post), ""
    # Row-possible recording line: legacy Case A verbatim (first attach
    # line, singleton, admitted before it — full-sum equality) or
    # insufficient evidence (held-then-bound or an aggregation split).
    # A recording line ending before admission/mapping is NOT known
    # zero: entry stamps precede invocation, so the recording call may
    # have executed after attachment and been counted.
    first_line = min(attach, key=lambda e: (e["t0"], e["t1"]))
    if rec is not first_line or rec["n"] != 1 \
            or caller_first_seen_ns > first_attach_t0 or not whole_in_window:
        return "nonqualifying", 0, "recording line neither pre-attachment nor first-singleton"
    if mapping_first_seen_ns > first_attach_t0:
        return "nonqualifying", 0, "mapping first seen after the first call: mapping-hold risk"
    if not endpoint_coverage_ok(attach, admission_endpoints):
        return "nonqualifying", 0, "more distinct endpoints called than admitted"
    return "exact", sum(e["n"] for e in attach), ""


def reached_by(images, image):
    """How this image was reached: initial, or the predecessor's EXEC how."""
    if image.gen == 0:
        return "initial"
    prev = images.get((image.cell, image.pid, image.start, image.gen - 1))
    return prev.execs[-1][0] if prev and prev.execs else "unknown"


def check_ledgers(manifest, images_by_cell, res, run="ledger"):
    providers = manifest["providers"]
    path_role = {p["path"]: role for role, p in providers.items()}
    for cell, spec in manifest["cells"].items():
        images = sorted(images_by_cell.get(cell, {}).values(), key=lambda i: (i.pid, i.gen))
        mode = spec["mode"]
        if not res.ok(run, cell, "LEDGER-PRESENT", bool(images), "no ledger image for the cell"):
            continue
        expected_images = spec.get("instances", 1) * (len(spec.get("chain", [])) + 1)
        res.ok(run, cell, "LEDGER-IMAGES", len(images) == expected_images,
               f"{len(images)} ledger images, expected {expected_images}")
        for image in images:
            tag = f"pid={image.pid} gen={image.gen}"
            finished = image.done == "ok" or (mode == "held" and image.held_t is not None)
            res.ok(run, cell, "LEDGER-DONE", finished, f"{tag}: image did not finish (DONE={image.done or 'missing'})")
            bad = [e for e in image.entries if e["bad"]]
            res.ok(run, cell, "LEDGER-RV", not bad,
                   f"{tag}: {len(bad)} ledger lines with rv != CKR_OK: {[(e['fn'], e['bad']) for e in bad][:4]}")
            stray = [m for m in image.mapped if m not in path_role or path_role[m] not in spec["providers"]]
            res.ok(run, cell, "LEDGER-MODULES", not stray, f"{tag}: undeclared modules mapped: {stray}")
            res.ok(run, cell, "LEDGER-MAPPED",
                   all(providers[r]["path"] in image.mapped for r in spec["providers"]),
                   f"{tag}: a declared provider was never mapped ({sorted(image.mapped)})")
            timing = [e for e in image.entries if e["t0"] > e["t1"]]
            res.ok(run, cell, "LEDGER-TIME", not timing, f"{tag}: t0 > t1 on {len(timing)} lines")
            if mode == "map":
                res.ok(run, cell, "LEDGER-UNUSED", not image.entries,
                       f"{tag}: map-only image made {len(image.entries)} ledgered calls")
                continue
            if mode == "held":
                held = [e for e in image.entries if e["phase"] == "held"]
                res.ok(run, cell, "LEDGER-HELD", len(held) == 1 and held[0]["n"] == 1 and image.held_t is not None,
                       f"{tag}: expected exactly one held C_WaitForSlotEvent entry and a HELD line")
                continue
            if mode == "leader-exit":
                res.ok(run, cell, "LEDGER-LX-ZOMBIE", image.zombie == ZOMBIE_STATE,
                       f"{tag}: worker saw leader state {image.zombie or 'missing'!r}, want {ZOMBIE_STATE!r}")
            for k, role in enumerate(spec["providers"]):
                path = providers[role]["path"]
                if mode == "mech":
                    iters = spec["iters"] * (k + 1)
                elif mode == "exec-chain":
                    iters = spec["iters"] * (image.gen + 1)
                else:
                    iters = spec["iters"]
                counts, phases = {}, {}
                for e in image.entries:
                    if e["module"] != path:
                        continue
                    key = (e["phase"], e["fn"], e["mech"])
                    counts[key] = counts.get(key, 0) + e["n"]
                    lo, hi = phases.get(e["phase"], (e["t0"], e["t1"]))
                    phases[e["phase"]] = (min(lo, e["t0"]), max(hi, e["t1"]))
                want = {("main", fn, mech): iters for fn, mech in MAIN_PLAN}
                want[("main", "C_DestroyObject", "-")] = 2 * iters
                want.update({("setup", fn, "-"): 1 for fn in SETUP_FNS})
                want.update({("teardown", fn, "-"): 1 for fn in TEARDOWN_FNS})
                res.ok(run, cell, "LEDGER-COUNTS", counts == want,
                       f"{tag} {role}: counts differ from the deterministic plan: "
                       f"{sorted(set(want.items()) ^ set(counts.items()))[:6]}")
                order = [phases.get(p) for p in ("setup", "main", "teardown")]
                res.ok(run, cell, "LEDGER-PHASES",
                       None not in order and order[0][1] <= order[1][0] and order[1][1] <= order[2][0],
                       f"{tag} {role}: phases overlap or are missing: {order}")
        if mode == "exec-chain":
            ordered = sorted(images, key=lambda i: i.gen)
            gens = [i.gen for i in ordered]
            same = len({(i.pid, i.start) for i in images}) == 1
            exes = [i.exe for i in ordered]
            steps = [s.split(":", 1) for s in spec["chain"]]
            want_exes = [spec["exe"]] + [exe for _how, exe in steps]
            hows = [reached_by(images_by_cell[cell], i) for i in ordered]
            want_hows = ["initial"] + [how for how, _exe in steps]
            res.ok(run, cell, "LEDGER-CHAIN",
                   same and gens == list(range(len(want_exes))) and exes == want_exes and hows == want_hows,
                   f"chain images gens={gens} one-process={same} exes={exes} hows={hows} "
                   f"want exes={want_exes} hows={want_hows}")
            gaps = []
            for a, b in zip(ordered, ordered[1:]):
                if a.entries and b.entries:
                    gaps.append(min(e["t0"] for e in b.entries) - max(e["t1"] for e in a.entries))
            res.ok(run, cell, "LEDGER-CHAIN-GAP", bool(gaps) and min(gaps) >= EXEC_GAP_MIN_NS,
                   f"inter-image quiet gaps {gaps} ns < {EXEC_GAP_MIN_NS}: the exec cross-attribution "
                   "check cannot discriminate (raise the chain --delay-ms)")


# ===========================================================================
# Documents
# ===========================================================================

def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dig(doc, path):
    cur = doc
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def coverage(edge):
    return edge.get("entries", {}).get("coverage") or {}


def coverage_ok(edge):
    """The documented seven keys, a known state, and fields valid for the
    state (O5, grounded in inventory.rs coverage_json: until_ns only on
    a watched interval — never on counted — since_ns on counted and
    watched, first_ns on witnessed, lossy on counted; anything else is
    an invented boundary)."""
    cov = edge.get("entries", {}).get("coverage")
    if not (isinstance(cov, dict) and set(cov) == COVERAGE_KEYS and cov.get("state") in COVERAGE_STATES):
        return False
    state = cov.get("state")
    since, until = cov.get("since_ns"), cov.get("until_ns")
    first, lossy = cov.get("first_ns"), cov.get("lossy")
    reason, detail = cov.get("reason"), cov.get("detail")
    if state == "counted":
        return (isinstance(since, int) and until is None and first is None
                and isinstance(lossy, bool) and reason is None and detail is None)
    if state == "witnessed":
        return (since is None and until is None and isinstance(first, int)
                and lossy is None and reason is None and detail is None)
    if state == WATCH_STATE:
        return (isinstance(since, int) and (until is None or (isinstance(until, int) and until > since))
                and first is None and lossy is None and reason is None and detail is None)
    # unknown: only the reason/detail carry meaning; no instant applies.
    return since is None and until is None and first is None and lossy is None


def doc_lane(doc):
    """native once any native producer speaks; scan when every (well-formed)
    edge reads unknown with a scan-lane reason and nothing states a native
    lane; malformed when any coverage object breaks the schema, or a stated
    native lane has a scan_only edge (C5.1: a native run states
    `observation.lane`, and its uncovered edges read not_attached)."""
    if any(not coverage_ok(e) for e in doc.get("edges", [])):
        return "malformed"
    stated = doc.get("observation", {}).get("lane")
    reasons = {coverage(e).get("reason") for e in doc.get("edges", []) if coverage(e)["state"] == UNKNOWN_STATE}
    if stated == "native":
        return "malformed" if SCAN_ONLY_REASON in reasons else "native"
    if any(coverage(e)["state"] != UNKNOWN_STATE for e in doc.get("edges", [])):
        return "native"
    # Every edge unknown: a reason only a native producer gives (loss,
    # not_attached, use_before_admission, ...) still names the native lane.
    if reasons - SCAN_LANE_REASONS:
        return "native"
    if doc.get("observation", {}).get("usage_feed"):
        return "native"
    if any(c.get("image", {}).get("authority") == "native_exact" for c in doc.get("callers", [])):
        return "native"
    return "scan"


def positive(edge):
    cov = coverage(edge)
    if cov.get("state") == "witnessed":
        return True
    return cov.get("state") == "counted" and edge["entries"].get("count", 0) > 0


def positive_first_ns(edge):
    cov = coverage(edge)
    if cov.get("state") == "witnessed":
        return cov.get("first_ns")
    return edge["entries"].get("first_seen_ns")


def expected_capture(caller, module, edge):
    """inventory-events-v1 `capture`, re-derived from the snapshot record."""
    adm = module.get("admission", {}).get("state")
    mapping = edge.get("mapping", {}).get("state")
    cov = coverage(edge)
    if adm == "refused":
        return CAPTURE["refused"]
    if caller.get("retired") or mapping == MAPPING_ENDED:
        return CAPTURE["retired"]
    if adm == "unresolved" or mapping == "uncertain" or caller.get("lifecycle") == "unknown" \
            or module.get("lifecycle") == "unknown":
        return CAPTURE["lost"]
    if frozen_watch(edge):
        # A frozen watch: a fact about since..until only (C5.2 M-2, review fix 2).
        return CAPTURE["ended"]
    if cov.get("state") in ("counted", "witnessed", WATCH_STATE):
        return CAPTURE["armed"]
    if cov.get("reason") == SCAN_ONLY_REASON:
        return CAPTURE["scan_only"]
    return CAPTURE["lost"]


def expected_presence(caller, module, edge):
    """inventory-events-v1 `presence`, re-derived from the snapshot record
    (inventory_present.rs Presence::for_edge): an exited caller, then an
    unloaded module, then a live mapping on two live endpoints; anything
    else (exec_retired, uncertain mapping, unknown lifecycles) is unknown."""
    if caller.get("lifecycle") == "exited":
        return PRESENCE["exited"]
    if module.get("lifecycle") == "unloaded":
        return PRESENCE["unloaded"]
    if caller.get("lifecycle") == "mapped" and module.get("lifecycle") == "mapped" \
            and edge.get("mapping", {}).get("state") == MAPPING_LIVE:
        return PRESENCE["mapped"]
    return PRESENCE["unknown"]


def expected_activity_base(payload):
    """The activity base label for an edge-shaped payload (a snapshot
    edge or an edge_observed record's event): everything except the
    per-pass rise. `recent` is never the base — EDGE-ACTIVITY admits it
    only where a rise allows it."""
    entries = payload.get("entries") or {}
    cov = coverage(payload)
    if entries.get("in_flight") or (payload.get("operations") or {}).get("active"):
        return ACTIVITY["inflight"]
    if cov.get("state") == "witnessed":
        return ACTIVITY["used"]
    if payload.get("mapping", {}).get("state") != MAPPING_LIVE or frozen_watch(payload):
        return ACTIVITY["unknown"]
    if cov.get("state") == UNKNOWN_STATE and cov.get("reason") == PENDING_FIRST_USE_REASON:
        # DR-LIVE-LABEL-LAG: the edge is watched, so "not covered" would
        # lie — a read-but-undecided first use reads unknown.
        return ACTIVITY["unknown"]
    if (cov.get("state") == "counted" and not cov.get("lossy")) or cov.get("state") == WATCH_STATE:
        return ACTIVITY["quiet"]
    if cov.get("state") == "counted":
        return ACTIVITY["lossy"]
    return ACTIVITY["uncovered"]


def per_pass_recent_allowed(payload, prev_count):
    """Whether `recent` is legal on this counted record, matching
    production precedence (Activity::for_edge): a rise since the edge's
    previous record allows it (the emission may lag the rising pass),
    as does a first record (emission-cap deferral may delay it past
    the rising pass) — even over lossy coverage (a fresh rise beats
    lossy). An unchanged count forbids it — that is the Choice 3 pin —
    and so does in-flight (production reads in-flight over a rise).
    Non-counted payloads never allow it."""
    cov = coverage(payload)
    entries = payload.get("entries") or {}
    if cov.get("state") != "counted":
        return False
    if entries.get("in_flight") or (payload.get("operations") or {}).get("active"):
        return False
    count = entries.get("count")
    if prev_count is None or not isinstance(count, int) or not isinstance(prev_count, int):
        return True
    return count > prev_count


def frozen_watch(edge):
    """A watch that ended (until_ns set): a fact about since..until only."""
    cov = coverage(edge)
    return cov.get("state") == WATCH_STATE and cov.get("until_ns") is not None


def expected_entries_display(edge):
    cov = coverage(edge)
    count = edge["entries"].get("count", 0)
    if cov.get("state") == "counted" and cov.get("lossy") and count > 0:
        return f"{count}+"
    if (cov.get("state") == "counted" and not cov.get("lossy")) or \
            (cov.get("state") == WATCH_STATE and not frozen_watch(edge)):
        return str(count)
    return str(count) if count > 0 else "?"


def count_bucket(count):
    """The count's power-of-two bucket (EdgeClass): 0, 1, 2-3, 4-7, ..."""
    return 0 if count == 0 else count.bit_length()


def edge_class_key(record):
    """An edge_observed record's emit class (inventory-events-v1): the
    count bucket plus saturated/in_flight/observation, the full coverage,
    and the three derived states. Choice 2 (controller-accepted): the
    bucket stays in the class, so a bucket jump is an immediate class
    change while other count drift waits out the 10 s channel."""
    entries = record.get("entries", {})
    cov = entries.get("coverage") or {}
    return (count_bucket(entries.get("count", 0)), entries.get("saturated"), entries.get("in_flight"),
            entries.get("observation"), cov.get("state"), cov.get("since_ns"), cov.get("until_ns"),
            cov.get("first_ns"), cov.get("lossy"), cov.get("reason"), cov.get("detail"),
            record.get("presence"), record.get("capture"), record.get("activity"))


def settlement_verdict(doc):
    """(verdict, source); verdict is settled | unsettled | None, or `malformed`
    for a settlement value of an unrecognized shape (never a crash)."""
    for path, values in SETTLEMENT_PATHS:
        value = dig(doc, path)
        if value is None:
            continue
        where = ".".join(path)
        if isinstance(value, dict):
            inner = next((value[k] for k in SETTLEMENT_OBJECT_KEYS if isinstance(value.get(k), (str, bool))), None)
            if inner is None or inner not in values:
                return "malformed", f"{where} is an object without a known {SETTLEMENT_OBJECT_KEYS} value: {value!r}"
            return values[inner], f"{where}={value!r}"
        if not isinstance(value, (str, bool)):
            return "malformed", f"{where} has unsupported shape {type(value).__name__}: {value!r}"
        if value in values:
            return values[value], f"{where}={value!r}"
    text = " ".join(f"{g.get('subject', '')} {g.get('reason', '')}" for g in doc.get("gaps", []))
    for pattern, verdict in SETTLEMENT_GAPS:
        if pattern.search(text):
            return verdict, f"gap matching {pattern.pattern!r}"
    return None, "no settlement statement"


def edge_payload_problems(view, key, ev):
    """Problems ([]) when the edge_observed payload `ev` disagrees with the
    decided snapshot edge for `key`: DR-C5-EDGE replay minus the three
    derived states. Presence and capture must match the oracle's own
    derivation here; activity is per-pass and judged record-by-record
    (with its previous record) by EDGE-ACTIVITY instead."""
    edge = view.edges.get(key)
    if edge is None:
        return [(key, "not in snapshot")]
    caller, module = view.callers.get(key[0], {}), view.modules.get(key[1], {})
    problems = []
    replayed = {k: v for k, v in ev.items() if k not in EDGE_STATES}
    if replayed != edge:
        fields = sorted(k for k in set(replayed) | set(edge) if replayed.get(k) != edge.get(k))
        problems.append((key, f"fields {fields}"))
    if ev.get("presence") != expected_presence(caller, module, edge):
        problems.append((key, f"presence {ev.get('presence')!r} != {expected_presence(caller, module, edge)!r}"))
    if ev.get("capture") != expected_capture(caller, module, edge):
        problems.append((key, f"capture {ev.get('capture')!r}"))
    return problems


class RunView:
    def __init__(self, manifest, run, rundir):
        self.manifest = manifest
        self.run = run
        self.name = run["name"]
        self.doc = None
        self.events = None
        self.errors = []
        for key, loader, attr in (("json", load_json, "doc"), ("jsonl", load_jsonl, "events")):
            path = run.get(key) and os.path.join(rundir, run[key])
            if path and os.path.exists(path):
                try:
                    setattr(self, attr, loader(path))
                except (OSError, ValueError) as error:
                    self.errors.append(f"{key} unreadable: {error}")
        self.frames_path = os.path.join(rundir, run["frames"]) if run.get("frames") else None
        self.callers, self.modules, self.edges = {}, {}, {}
        if isinstance(self.doc, dict):
            self.callers = {c["id"]: c for c in self.doc.get("callers", [])}
            self.modules = {m["id"]: m for m in self.doc.get("modules", [])}
            self.edges = {(e["caller"], e["module"]): e for e in self.doc.get("edges", [])}
            obs = self.doc.get("observation", {})
            self.window = (obs.get("started_ns") or 0, obs.get("ended_ns") or 0)

    def kind(self, name):
        return [e for e in self.events or [] if e.get("kind") == EVENT_KINDS[name]]


def check_streams(view, res):
    run, doc = view.name, view.doc
    res.ok(run, "*", "DOC-SCHEMA", doc.get("schema") == SCHEMAS["inventory"],
           f"schema {doc.get('schema')!r} != {SCHEMAS['inventory']!r} (oracle tables need review)")
    malformed = [k for k, e in view.edges.items() if not coverage_ok(e)]
    res.ok(run, "*", "COVERAGE-SHAPE", not malformed,
           f"{len(malformed)} edges lack the coverage keys {sorted(COVERAGE_KEYS)}, a known state, or "
           f"until_ns > since_ns: {malformed[:4]}")
    # C7 C5 extends the C2 DR-LIVE-LABEL-LAG oracle (which judges mid-run
    # frames and records): the finish flush decides every row, so the
    # final snapshot itself never carries pending_first_use.
    pending = [k for k, e in view.edges.items() if coverage(e).get("reason") == PENDING_FIRST_USE_REASON]
    res.ok(run, "*", "PENDING-TRANSIENT", not pending,
           f"{len(pending)} snapshot edges read {PENDING_FIRST_USE_REASON}: {pending[:4]} "
           "(mid-run records and frames may; the decided snapshot never does)")
    if view.events is None:
        res.add(run, "*", "STREAM", "fail", "no --event-log JSONL to compare")
        return
    events = view.events
    res.ok(run, "*", "STREAM-SCHEMA", all(e.get("schema") == SCHEMAS["events"] for e in events),
           "a JSONL line carries a different schema id")
    rotated = view.kind("rotated") + view.kind("evicted")
    if not res.ok(run, "*", "STREAM-ROTATED", not rotated,
                  f"the stream rotated or evicted ({len(rotated)} markers): the run must pass a rotate bound "
                  "larger than the stream, or its agreement checks would read a partial stream"):
        return
    seqs = [e.get("seq") for e in events]
    res.ok(run, "*", "STREAM-SEQ", seqs == list(range(len(seqs))), f"seq not contiguous from 0: {seqs[:5]}..")
    kinds = [e.get("kind") for e in events]
    if not res.ok(run, "*", "STREAM-ENDED",
                  bool(kinds) and kinds[0] == EVENT_KINDS["started"] and kinds[-1] == EVENT_KINDS["ended"],
                  f"stream must open with started and close with ended: {kinds[:1]}..{kinds[-1:]}"):
        return
    ended = events[-1]["event"]
    res.ok(run, "*", "AGREE-BUDGETS", ended.get("budgets") == doc.get("budgets"),
           "ended.budgets differs from the snapshot budgets")
    res.ok(run, "*", "AGREE-PASSES", ended.get("passes") == doc.get("observation", {}).get("passes"),
           f"ended.passes {ended.get('passes')} != observation.passes {doc.get('observation', {}).get('passes')}")
    res.ok(run, "*", "AGREE-SUPPRESSED", ended.get("gaps_suppressed") == doc.get("gaps_suppressed"),
           "gaps_suppressed differs between stream and snapshot")
    # Retention mirrors the snapshot pass for pass: past the bound new gaps are
    # suppressed, never emitted, so the lists stay equal.
    # gap_recorded is the snapshot gap minus repeats plus its ordinal `index`;
    # repeats ride gap_repeated{index, repeats}. Mid-stream values are lower
    # bounds (power-of-two crossings); the final flush before `ended` makes
    # the LAST value per index equal the snapshot's, which is all that is
    # compared. Order, index and monotonicity are validated too.
    stream_gaps = []
    bad_gap_events = []
    for e in view.events or []:
        ev = e.get("event") if isinstance(e.get("event"), dict) else {}
        if e.get("kind") == EVENT_KINDS["gap"]:
            if type(ev.get("index")) is not int or ev["index"] != len(stream_gaps):
                bad_gap_events.append(f"gap_recorded index {ev.get('index')!r} != ordinal {len(stream_gaps)}")
            g = {k: v for k, v in ev.items() if k != "index"}
            g["repeats"] = 1
            stream_gaps.append(g)
        elif e.get("kind") == EVENT_KINDS["gap_repeated"]:
            index, repeats = ev.get("index"), ev.get("repeats")
            if type(index) is not int or not 0 <= index < len(stream_gaps):
                bad_gap_events.append(f"gap_repeated index {index!r} has no earlier gap_recorded")
            elif type(repeats) is not int or repeats < 2 or repeats < stream_gaps[index]["repeats"]:
                bad_gap_events.append(f"gap_repeated[{index}] repeats {repeats!r} not >=2 and non-decreasing")
            else:
                stream_gaps[index]["repeats"] = repeats
    passes = [e["event"] for e in view.kind("pass")]
    res.ok(run, "*", "AGREE-GAPS", stream_gaps == doc.get("gaps", []) and not bad_gap_events,
           f"stream gaps ({len(stream_gaps)}) != snapshot gaps ({len(doc.get('gaps', []))}) "
           f"or malformed gap events: {bad_gap_events[:3]}")
    new = sum(p.get("new_gaps", 0) for p in passes)
    suppressed = sum(p.get("suppressed_delta", 0) for p in passes)
    res.ok(run, "*", "AGREE-GAP-ACCOUNTING", new == len(stream_gaps) and suppressed == doc.get("gaps_suppressed"),
           f"pass accounting new_gaps={new} suppressed={suppressed} vs {len(stream_gaps)} streamed, "
           f"{doc.get('gaps_suppressed')} suppressed")
    minted = set()
    for e in view.kind("caller"):
        field_name = CALLER_EVENT_MINTS.get(e["event"].get("event"))
        if field_name:
            minted.add(e["event"].get(field_name))
    res.ok(run, "*", "AGREE-CALLERS", minted == set(view.callers),
           f"stream-minted only {sorted(minted - set(view.callers))[:5]} / snapshot-only "
           f"{sorted(set(view.callers) - minted)[:5]}")
    want = {"callers": len(view.callers), "modules": len(view.modules), "edges": len(view.edges)}
    totals = passes[-1].get("totals") if passes else None
    res.ok(run, "*", "AGREE-TOTALS", totals == want, f"last pass totals {totals} != snapshot {want}")
    # DR-C5-EDGE: production streams carry edge_observed (change-driven, capped
    # per pass, plus one exact sweep before `ended`). The LAST record per edge,
    # minus the three derived states, must equal the snapshot edge verbatim;
    # every snapshot edge needs one; the derived states must match the oracle's
    # own derivation; pass markers plus `ended` account every record.
    edge_events = view.kind("edge")
    if not edge_events and view.edges:
        res.add(run, "*", "AGREE-EDGE-EVENTS", "fail",
                f"the stream carries no edge_observed records for {len(view.edges)} snapshot edges")
        return
    last = {}
    for e in edge_events:
        ev = e.get("event") if isinstance(e.get("event"), dict) else {}
        last[(ev.get("caller"), ev.get("module"))] = ev
    bad = []
    for key, ev in last.items():
        bad.extend(edge_payload_problems(view, key, ev))
    missing = sorted(set(view.edges) - set(last))
    if missing:
        bad.append((missing[:4], f"{len(missing)} snapshot edges have no edge_observed"))
    # Accounting per commit: each pass marker's edge_events counts exactly the
    # edge_observed lines since the previous marker, ended.edge_events the
    # lines after the last one (the sweep); deferred is a count of waiting
    # edges, so a non-negative int no larger than the snapshot's edges. (A
    # deferred tail need not force a sweep record: a change that reverted
    # while it waited is already carried.)
    since, split = 0, []
    for e in events:
        if e.get("kind") == EVENT_KINDS["edge"]:
            since += 1
        elif e.get("kind") in (EVENT_KINDS["pass"], EVENT_KINDS["ended"]):
            ev = e.get("event") if isinstance(e.get("event"), dict) else {}
            stated = ev.get("edge_events")
            if type(stated) is not int or stated != since:
                split.append(f"{e.get('kind')} seq {e.get('seq')} edge_events {stated!r} != {since} lines")
            if e.get("kind") == EVENT_KINDS["pass"]:
                deferred = ev.get("edge_events_deferred")
                if type(deferred) is not int or not 0 <= deferred <= len(view.edges):
                    split.append(f"pass seq {e.get('seq')} edge_events_deferred {deferred!r} "
                                 f"not an int in 0..{len(view.edges)}")
            since = 0
    if split:
        bad.append(("*", f"edge accounting: {split[:3]}"))
    if ended.get("edges_unretained") != 0 or type(ended.get("edges_unretained")) is not int:
        bad.append(("*", f"ended.edges_unretained {ended.get('edges_unretained')!r} != 0"))
    res.ok(run, "*", "AGREE-EDGE-EVENTS", not bad, f"edge_observed disagrees with the snapshot: {bad[:4]}",
           f"{len(last)} edge_observed replays agree ({len(edge_events)} records)")
    # C7 C5 (Choice 2): a mid-run record that follows its edge's previous
    # record by less than the 10 s count channel must carry a class change
    # (bucket jumps included) — anything else is a spurious fast emit.
    # First records per edge and the exact final sweep (records after the
    # last pass marker) are exempt. Rotated streams never reach here
    # (STREAM-ROTATED returns early), so retention re-sends cannot fail it.
    sweep_seq = max([e.get("seq", -1) for e in events if e.get("kind") == EVENT_KINDS["pass"]], default=-1)
    by_edge = {}
    for e in edge_events:
        ev = e.get("event") if isinstance(e.get("event"), dict) else {}
        by_edge.setdefault((ev.get("caller"), ev.get("module")), []).append(e)
    rushed = []
    for key in sorted(by_edge, key=str):
        rows = sorted(by_edge[key], key=lambda e: e.get("seq", 0))
        for prev, cur in zip(rows, rows[1:]):
            if cur.get("seq", 0) > sweep_seq:
                continue
            prev_at, cur_at = prev.get("at_ns"), cur.get("at_ns")
            prev_ev = prev.get("event") if isinstance(prev.get("event"), dict) else None
            cur_ev = cur.get("event") if isinstance(cur.get("event"), dict) else None
            if not isinstance(prev_at, int) or not isinstance(cur_at, int) or cur_at < prev_at \
                    or prev_ev is None or cur_ev is None:
                continue
            if cur_at - prev_at < COUNT_EMIT_INTERVAL_NS and edge_class_key(prev_ev) == edge_class_key(cur_ev):
                rushed.append((key, f"seq {prev.get('seq')}->{cur.get('seq')} dt {cur_at - prev_at} ns"))
    res.ok(run, "*", "EDGE-CADENCE", not rushed,
           f"{len(rushed)} edge_observed records re-emit an unchanged class within 10 s: {rushed[:4]}")
    # O3: invalid clocks fail closed. A missing/non-integer/out-of-range
    # at_ns, or a regressing per-edge stamp, makes its pair unjudgeable
    # for cadence (which keeps skipping it above) — but the stream must
    # fail here instead of passing silently. Monotonicity judges valid
    # clocks only; anything else already failed above.
    clock_bad = []
    for key in sorted(by_edge, key=str):
        rows = sorted(by_edge[key], key=lambda e: e.get("seq", 0))
        for row in rows:
            at = row.get("at_ns")
            if not is_u64_clock(at):
                clock_bad.append((key, f"seq {row.get('seq')} at_ns {at!r} is not a u64 clock"))
        stamps = [(row.get("seq"), row.get("at_ns")) for row in rows]
        for (pseq, prev_at), (cseq, cur_at) in zip(stamps, stamps[1:]):
            if is_u64_clock(prev_at) and is_u64_clock(cur_at) and cur_at < prev_at:
                clock_bad.append((key, f"seq {pseq}->{cseq} clock regresses {prev_at}->{cur_at}"))
    res.ok(run, "*", "EDGE-CLOCK", not clock_bad,
           f"{len(clock_bad)} edge_observed records carry invalid or regressing clocks: {clock_bad[:4]}")
    # ACT (Choice 3 pin): activity is per-pass. Every record (middle,
    # last, and terminal — no sweep exemption: an unchanged terminal
    # re-emission reads quiet too) is judged against its own coverage
    # plus its edge's previous record: published counts never decrease
    # (a strict product invariant), an unchanged counted record reads
    # its base (a window echo fails), and a rise — or a first record,
    # whose emission the per-pass cap may have deferred past the rising
    # pass — admits recent-or-base. Non-counted records read base.
    # Proven comparison (fix round 1): consecutive records in ADJACENT
    # pass segments with zero deferred records on the proving markers
    # show what each pass saw — a rise across them must read recent
    # (or in-flight where recent is forbidden), never base. Non-adjacent
    # records stay lenient: the rise may predate the latest pass.
    markers = [e for e in events if e.get("kind") in (EVENT_KINDS["pass"], EVENT_KINDS["ended"])]
    markers.sort(key=lambda e: e.get("seq", 0))
    after = {}
    for cur, nxt in zip(markers, markers[1:] + [None]):
        after[cur.get("seq")] = nxt
    before = {}
    for prev, cur in zip([None] + markers, markers):
        before[cur.get("seq")] = prev

    def closing_marker(row_seq):
        for marker in markers:
            if marker.get("seq", 0) > row_seq:
                return marker
        return None

    def deferred_is_zero(marker):
        return type(marker.get("event", {}).get("edge_events_deferred")) is int \
            and marker["event"]["edge_events_deferred"] == 0

    def proven_rise(prev_row, row):
        """Whether consecutive records prove a pass-to-pass rise: they
        close in adjacent marker segments, the earlier record is fresh
        (no wait past its previous marker — or the first marker, where
        it is the edge's first record), the later one is fresh (no wait
        past the earlier segment's marker — or a sweep record, which is
        always exact-final), and the exact-int counts rise."""
        if prev_row is None:
            return False
        m1, m2 = closing_marker(prev_row.get("seq", 0)), closing_marker(row.get("seq", 0))
        if m1 is None or m2 is None or after.get(m1.get("seq")) is not m2:
            return False
        m0 = before.get(m1.get("seq"))
        if m0 is not None and not deferred_is_zero(m0):
            return False
        if m2.get("kind") != EVENT_KINDS["ended"] and not deferred_is_zero(m1):
            return False
        prev_ev = prev_row.get("event") if isinstance(prev_row.get("event"), dict) else {}
        cur_ev = row.get("event") if isinstance(row.get("event"), dict) else {}
        prev_seen = (prev_ev.get("entries") or {}).get("count")
        seen = (cur_ev.get("entries") or {}).get("count")
        return type(prev_seen) is int and type(seen) is int and seen > prev_seen

    activity_bad = []
    for key in sorted(by_edge, key=str):
        rows = sorted(by_edge[key], key=lambda e: e.get("seq", 0))
        prev_count = None
        prev_row = None
        for row in rows:
            ev = row.get("event") if isinstance(row.get("event"), dict) else None
            if ev is None or not isinstance(ev.get("entries"), dict):
                prev_count = None
                prev_row = row
                continue
            count = ev["entries"].get("count")
            base = expected_activity_base(ev)
            if isinstance(count, int) and isinstance(prev_count, int) and count < prev_count:
                activity_bad.append((key, f"seq {row.get('seq')} count decreases {prev_count}->{count}"))
            elif proven_rise(prev_row, row):
                want = ACTIVITY["recent"] if per_pass_recent_allowed(ev, prev_count) else base
                if ev.get("activity") != want:
                    activity_bad.append((key, f"seq {row.get('seq')} reads {ev.get('activity')!r}, "
                                              f"want {want!r}: consecutive passes prove "
                                              f"{prev_count}->{count}"))
            elif ev.get("activity") != base and not per_pass_recent_allowed(ev, prev_count):
                activity_bad.append((key, f"seq {row.get('seq')} reads {ev.get('activity')!r}, "
                                          f"want {base!r} (count {prev_count}->{count})"))
            elif ev.get("activity") not in {base, ACTIVITY["recent"]}:
                activity_bad.append((key, f"seq {row.get('seq')} reads {ev.get('activity')!r}, "
                                          f"want {base!r} or {ACTIVITY['recent']!r}"))
            prev_count = count if isinstance(count, int) else None
            prev_row = row
    res.ok(run, "*", "EDGE-ACTIVITY", not activity_bad,
           f"{len(activity_bad)} edge_observed records misread per-pass activity: {activity_bad[:4]}",
           f"{sum(len(v) for v in by_edge.values())} edge_observed records read per-pass activity")
    # O2: the final sweep is exact but not exempt from scrutiny. Past the
    # last pass marker every edge carries at most one terminal record —
    # production's sweep re-emits only uncarried edges (zero when the
    # pre-marker record already carries the state), so duplicates are
    # never legitimate in an unrotated stream — and every terminal
    # payload must equal the decided snapshot. First records stay
    # cadence-exempt; rotated streams never reach here (STREAM-ROTATED
    # returns early); a stream with no pass marker is already failed by
    # AGREE-TOTALS and has no sweep to judge.
    if sweep_seq >= 0:
        terminal = [e for e in edge_events if e.get("seq", 0) > sweep_seq]
        by_terminal = {}
        for e in terminal:
            ev = e.get("event") if isinstance(e.get("event"), dict) else {}
            by_terminal.setdefault((ev.get("caller"), ev.get("module")), []).append((e, ev))
        sweep_bad = []
        for key in sorted(by_terminal, key=str):
            recs = by_terminal[key]
            if len(recs) > 1:
                sweep_bad.append((key, f"{len(recs)} terminal records past pass seq {sweep_seq} "
                                      "(want at most 1)"))
            for _, ev in recs:
                sweep_bad.extend(edge_payload_problems(view, key, ev))
        res.ok(run, "*", "TERMINAL-SWEEP", not sweep_bad,
               f"{len(sweep_bad)} terminal sweep problems: {sweep_bad[:4]}",
               f"{len(terminal)} terminal records agree ({len(by_terminal)} edges)")


def resolve_providers(view, res, needed):
    """provider role -> module id, by (inode, path or sha256); never by path alone."""
    out = {}
    for role, prov in view.manifest["providers"].items():
        hits = [m["id"] for m in view.modules.values()
                if m.get("identity", {}).get("inode") == prov["ino"]
                and (prov["path"] in m.get("paths", []) or m.get("identity", {}).get("sha256") == prov.get("sha256"))]
        if len(hits) > 1:
            res.add(view.name, role, "PROV-RESOLVE", "fail", f"provider {role} matches modules {hits}")
        if hits:
            out[role] = hits[0]
        elif role in needed:
            res.add(view.name, role, "PROV-RESOLVE", "fail",
                    f"provider {role} ({prov['path']}) is mapped by a live cell but is not a module"
                    + scan_limit_note(view))
    a, b = out.get("A"), out.get("B")
    if a and b:
        res.ok(view.name, "A/B", "PROV-DISTINCT", a != b, f"byte-identical copies merged into one module {a}")
    return out


def scan_limit_note(view):
    hit = next((g for g in (view.doc or {}).get("gaps", []) if SCAN_LIMIT_GAP.search(g.get("reason", ""))), None)
    return f"; the run hit the --system deep-scan bound ({hit['reason'][:120]})" if hit else ""


def candidates(view, image):
    return [c for c in view.callers.values() if c.get("pid") == image.pid and c.get("start_time") == image.start]


def in_window(ns, use):
    return ns is not None and use.t_first <= ns <= use.t_last + WITNESS_SLACK_NS


def edge_interval(view, edge):
    """The claimed coverage interval: since_ns (not before the caller existed) up
    to the frozen until_ns and/or the edge's end, whichever comes first."""
    caller = view.callers[edge["caller"]]
    cov = coverage(edge)
    start = max(cov.get("since_ns") or 0, caller.get("first_seen_ns") or 0)
    mapping = edge.get("mapping", {})
    ends = [cov.get("until_ns"), mapping.get("last_seen_ns") if mapping.get("state") == MAPPING_ENDED else None]
    ends = [e for e in ends if e is not None]
    return start, (min(ends) if ends else None)


def unbound_gap_for(view, mid, image, use, consumed):
    for index, gap in enumerate(view.doc.get("gaps", [])):
        if index in consumed or gap.get("module") != mid:
            continue
        if not UNBOUND_GAP.search(f"{gap.get('subject', '')} {gap.get('reason', '')}"):
            continue
        when = next((gap[k] for k in UNBOUND_GAP_TIME_KEYS if isinstance(gap.get(k), int)), None)
        if gap.get("pid") == image.pid or (when is not None and in_window(when, use)):
            consumed.add(index)
            return gap
    return None


class UnboundPool:
    """The pass markers' per-pass unbound row counts (R-C51-2), consumed
    one row per covered image: the earliest pass committed at or after the
    image's first call with a row of an allowed reason left (the eligible
    passes of every image are a suffix, so earliest-fit is a maximum
    matching in any order)."""

    def __init__(self, view):
        self.rows = []  # [at_ns, module, reason, left]
        for ev in view.kind("pass"):
            for item in (ev.get("event") or {}).get("unbound_rows") or []:
                if isinstance(item, dict) and isinstance(item.get("rows"), int) and item["rows"] > 0:
                    self.rows.append([ev.get("at_ns") or 0, item.get("module"), item.get("reason"), item["rows"]])
        self.rows.sort(key=lambda row: row[0])

    def claim(self, mid, reasons, first_call_ns):
        """`reasons` in preference order: a reason only one kind of image
        may use comes first, so a shared reason's rows stay for the others
        (review L-4); earliest-fit within each reason."""
        for reason in reasons:
            for row in self.rows:
                if row[1] == mid and row[2] == reason and row[0] >= first_call_ns and row[3] > 0:
                    row[3] -= 1
                    return row
        return None


def pidless_unbound_gap(view, mid, reasons):
    """The module's pid-less unbound statement: its gap, or — when gap
    retention dropped that gap — the module's own `unbound_use` counting a
    row of one of `reasons` (never a pid either)."""
    gap = next((g for g in view.doc.get("gaps", []) if g.get("module") == mid and g.get("pid") is None
                and UNBOUND_GAP.search(f"{g.get('subject', '')} {g.get('reason', '')}")), None)
    if gap is not None:
        return gap
    # The fallback stands in for a gap only when gap retention provably
    # dropped gaps (review L-5).
    if not view.doc.get("gaps_suppressed"):
        return None
    unbound = (view.modules.get(mid) or {}).get("unbound_use") or {}
    if any((unbound.get("reasons") or {}).get(reason, 0) > 0 for reason in reasons):
        return {"subject": f"modules[{mid}].unbound_use", "pid": None}
    return None


def image_began_ns(images, image):
    """A lower bound of when `image` began: 0 for an initial image, else the
    predecessor's last ledgered instant (its exec followed it)."""
    if image.gen == 0:
        return 0
    prev = next((i for i in images.values() if i.pid == image.pid and i.gen == image.gen - 1), None)
    stamps = [e["t1"] for e in (prev.entries if prev else [])]
    return max(stamps) if stamps else 0


def first_call_ns(image, provider_path):
    calls = [e["t0"] for e in image.entries if e["module"] == provider_path and e["n"] > 0]
    return min(calls) if calls else None


def preadmission_edge(view, edges, exe_ids, first_ns):
    """R-C51-1: the image's own caller edge reads unknown use_before_admission
    and the ledger shows a call before that caller's admission."""
    for e in edges:
        cov = coverage(e)
        caller = view.callers.get(e["caller"], {})
        if (e["caller"] in exe_ids and cov.get("state") == UNKNOWN_STATE and cov.get("reason") == USE_BEFORE_ADMISSION
                and first_ns is not None and first_ns < (caller.get("first_seen_ns") or 0)):
            return e
    return None


class CellPass:
    """Per-run bookkeeping shared by the cell checks."""

    def __init__(self, view=None):
        self.pool = UnboundPool(view) if view is not None else None
        self.counted_by_cell = {}  # images covered by R-C51-1/-2 counts
        self.exec_counted = {}  # cell -> {gen}
        self.justified = set()  # positive (caller, module) edges a ledgered in-window use accounts for
        self.consumed_gaps = set()
        self.bound_by_cell = {}
        self.used_by_cell = {}
        self.exec_bound = {}  # cell -> [(gen, how, caller, first_seen)]
        self.used_modules = set()


def check_cells(view, images_by_cell, res):
    run, man = view.name, view.manifest
    lane = doc_lane(view.doc)
    expect = man["expect_lane"]
    if expect == "native":
        res.ok(run, "*", "LANE", lane == "native",
               f"native lane absent: document lane is {lane!r} (every edge unknown/scan_only, or malformed coverage)")
    else:
        res.ok(run, "*", "LANE", lane == "scan", f"expected the scan lane but the document lane is {lane!r}")
    settle = view.run.get("settle_passes")
    if settle is not None:
        res.ok(run, "*", "WINDOW-SETTLED", settle >= 2,
               f"the observer committed only {settle} passes after the last cell settled (need 2: one full "
               "pass must start after every exit/dlopen); widen DURATION")
    win = view.window
    res.ok(run, "*", "WINDOW", 0 < win[0] < win[1], f"observation window {win} is not a capture window")
    run_cells = view.run["cells"]
    needed = set()
    for cell in run_cells:
        spec = man["cells"][cell]
        for image in images_by_cell.get(cell, {}).values():
            alive = spec.get("hold", False) and image.gen == len(spec.get("chain", []))
            for prole in spec["providers"]:
                if alive or use_in(image, man["providers"][prole]["path"], win):
                    needed.add(prole)
    mod = resolve_providers(view, res, needed)
    attested_delivery = bool(man.get("attested_delivery"))
    if any(p.get("attested") for p in man["providers"].values()) and not attested_delivery:
        res.add(run, "*", "ATTESTED-DELIVERY", "absent",
                "an attested provider exists but the run could not pass its manifest "
                f"({man.get('attested_note', 'no inventory --manifest')}); attested cells are judged unattested")
    state = CellPass(view)
    for cell in run_cells:
        spec = man["cells"][cell]
        role = ROLES[spec["role"]]
        images = images_by_cell.get(cell, {})
        for image in sorted(images.values(), key=lambda i: (i.pid, i.gen)):
            check_image(view, cell, spec, role, images, image, mod, lane, attested_delivery, state, res)
        if lane == "native" and role.bind == "optional" and state.used_by_cell.get(cell):
            bound, counted = state.bound_by_cell.get(cell, 0), state.counted_by_cell.get(cell, 0)
            # A pid-naming gap excuses an instance, never a whole cell; a
            # cell whose every used image is bound or count-covered (R-C51-2)
            # is fully accounted.
            res.ok(run, cell, "BOUND-INSTANCE",
                   bound >= OPTIONAL_CELL_MIN_BOUND or (counted > 0 and bound + counted >= state.used_by_cell[cell]),
                   f"{state.used_by_cell[cell]} in-window used images, {bound} bound and {counted} count-covered: "
                   "an unbound gap may excuse an instance, never a whole cell")
        if spec["mode"] == "exec-chain" and state.used_by_cell.get(cell):
            if lane == "native":
                check_exec_split(view, cell, state.exec_bound.get(cell, []), images, man, mod, res,
                                 state.exec_counted.get(cell, set()))
            else:
                res.add(run, cell, "EXEC-SPLIT", "absent",
                        "same-binary re-exec and non-leader exec are invisible to exe-identity scan pins")
    check_positives(view, images_by_cell, mod, state, res)
    check_counted_nonzero(view, res)
    check_saturated(view, res)
    check_uncounted(view, res)


def check_image(view, cell, spec, role, images, image, mod, lane, attested_delivery, state, res):
    run, man, win = view.name, view.manifest, view.window
    tag = f"pid={image.pid} gen={image.gen}"
    cands = candidates(view, image)
    exe_ids = {c["id"] for c in cands if c.get("image", {}).get("exe", {}).get("path") == image.exe}
    alive_at_end = spec.get("hold", False) and image.gen == len(spec.get("chain", []))
    how = reached_by(images, image)
    bind = EXEC_HOW_BIND.get(how, "required") if spec["mode"] == "exec-chain" else role.bind
    for prole in spec["providers"]:
        prov = man["providers"][prole]
        mid = mod.get(prole)
        use = use_in(image, prov["path"], win)
        ctag = f"{tag} {prole}"
        edges = [view.edges[(c["id"], mid)] for c in cands if mid and (c["id"], mid) in view.edges]
        if lane != "native":
            if role.scan_presence == "required" and alive_at_end:
                res.ok(run, cell, "EDGE-PRESENT", bool(edges),
                       f"{ctag}: live mapping of {prov['path']} has no edge (callers {[c['id'] for c in cands]})"
                       + scan_limit_note(view))
            for e in edges:
                cov = coverage(e)
                res.ok(run, cell, "SCAN-ONLY",
                       cov.get("state") == UNKNOWN_STATE and e["entries"].get("observation") != OBSERVATION_OBSERVED,
                       f"{ctag}: scan-lane edge claims usage coverage {cov}")
            if use and use.definite:
                state.used_by_cell[cell] = state.used_by_cell.get(cell, 0) + 1
                res.add(run, cell, "USED-POSITIVE", "absent",
                        f"{ctag}: {use.table_calls} in-window ledgered calls; the scan lane observes no use")
                if prov.get("attested") and attested_delivery:
                    res.add(run, cell, "SEMANTICS-ATTESTED", "absent",
                            f"{ctag}: attested mechanisms {sorted(hex(m) for m in use.mechs)} need native capture")
            continue
        if mid is None:
            continue
        for e in edges:
            if use and coverage(e).get("state") == WATCH_STATE:
                s, end = edge_interval(view, e)
                overlaps = s <= use.t_last and (end is None or end >= use.t_first)
                res.ok(run, cell, "USED-NOT-WATCHED", not overlaps,
                       f"{ctag}: edge {e['caller']}->{mid} reads watched_no_use since {s} over ledgered "
                       f"in-window use {use.t_first}..{use.t_last}")
        if use is None:
            # Never called, or idle for the whole window (e.g. --hold cells of a later run).
            what = "never-called" if not any(e["module"] == prov["path"] for e in image.entries) else "idle-in-window"
            for e in edges:
                cov = coverage(e)
                res.ok(run, cell, "IDLE-NOT-POSITIVE",
                       not positive(e) and e["entries"].get("count", 0) == 0
                       and cov.get("state") in IDLE and e.get("semantics") != SEMANTICS_OBSERVED,
                       f"{ctag}: {what} edge {e['caller']}->{mid} claims use: {cov}")
            if alive_at_end and role.scan_presence == "required":
                res.ok(run, cell, "EDGE-PRESENT", bool(edges), f"{ctag}: live mapped provider has no edge"
                       + scan_limit_note(view))
            continue
        state.used_modules.add(mid)
        if not use.definite:
            res.add(run, cell, "USED-POSITIVE", "skip",
                    f"{ctag}: ledgered use straddles the window edge; a positive is allowed, not required")
            for e in edges:
                if positive(e) and in_window(positive_first_ns(e), use) and e["caller"] in exe_ids:
                    state.justified.add((e["caller"], e["module"]))
            continue
        state.used_by_cell[cell] = state.used_by_cell.get(cell, 0) + 1
        bound = [e for e in edges if positive(e) and in_window(positive_first_ns(e), use) and e["caller"] in exe_ids]
        if len(bound) > 1:
            res.add(run, cell, "NO-DOUBLE-BIND", "fail",
                    f"{ctag}: one image's use bound to {len(bound)} callers {[e['caller'] for e in bound]}")
        check = "USED-POSITIVE" if alive_at_end else "RETAINED"
        if bound:
            e = bound[0]
            state.justified.add((e["caller"], e["module"]))
            state.bound_by_cell[cell] = state.bound_by_cell.get(cell, 0) + 1
            if spec["mode"] == "exec-chain":
                state.exec_bound.setdefault(cell, []).append(
                    (image.gen, how, e["caller"], view.callers[e["caller"]].get("first_seen_ns") or 0))
            res.add(run, cell, check, "pass", f"{ctag}: bound to {e['caller']} ({coverage(e).get('state')})")
            check_bound_edge(view, cell, ctag, role, prov, e, use, image, attested_delivery, res)
            check_no_preadmission_positive(view, cell, ctag, e, res)
            if not alive_at_end:
                caller = view.callers[e["caller"]]
                res.ok(run, cell, "RETIRED-LIFECYCLE",
                       caller.get("lifecycle") != CALLER_LIVE_LIFECYCLE or caller.get("retired"),
                       f"{ctag}: exited image's caller {caller['id']} still reads mapped")
            continue
        gap = unbound_gap_for(view, mid, image, use, state.consumed_gaps) if bind == "optional" else None
        counted = None
        if gap is None and state.pool is not None:
            first_ns = first_call_ns(image, prov["path"])
            early = preadmission_edge(view, edges, exe_ids, first_ns)
            exec_chain = spec["mode"] == "exec-chain"
            short_reasons = COUNTED_EXEC_CHAIN_REASONS if exec_chain else COUNTED_SHORT_LIVED_REASONS
            early_reasons = COUNTED_EXEC_PREADMISSION_REASONS if exec_chain else COUNTED_PREADMISSION_REASONS
            pidless = pidless_unbound_gap(view, mid, short_reasons)
            # R-C51-2 covers never-admitted images only: one whose caller was
            # admitted at or before its first call must bind (review M-1).
            # The image began at its exec (after the predecessor's last
            # ledgered call): an earlier image's caller of the same binary
            # is not this image's.
            began = image_began_ns(images, image)
            admitted = first_ns is not None and any(
                (c.get("first_seen_ns") is not None and began <= c["first_seen_ns"] <= first_ns)
                for c in candidates(view, image) if c["id"] in exe_ids)
            if early is not None:
                row = state.pool.claim(mid, early_reasons, first_ns)
                if row is not None:
                    counted = (f"{ctag} (reached by {how}): used before its caller {early['caller']} was admitted; "
                               f"edge reads unknown/{USE_BEFORE_ADMISSION}, row counted {row[2]} in the pass at {row[0]}")
            elif pidless is not None and first_ns is not None and not admitted:
                row = state.pool.claim(mid, short_reasons, first_ns)
                if row is not None:
                    counted = (f"{ctag} (reached by {how}): pid-less {pidless.get('subject')!r} covered by an "
                               f"unbound_rows {row[2]} count in the pass at {row[0]}")
        if gap is not None:
            res.add(run, cell, check, "unbound",
                    f"{ctag} (reached by {how}): module-level unbound positive {gap.get('subject')!r} pid={gap.get('pid')}")
        elif counted is not None:
            state.counted_by_cell[cell] = state.counted_by_cell.get(cell, 0) + 1
            if spec["mode"] == "exec-chain":
                state.exec_counted.setdefault(cell, set()).add(image.gen)
            res.add(run, cell, check, "unbound", counted)
        else:
            res.add(run, cell, check, "fail",
                    f"{ctag} (reached by {how}, bind {bind}): {use.table_calls} in-window ledgered calls in "
                    f"{use.t_first}..{use.t_last} have no positive edge on this image's caller "
                    f"({sorted(exe_ids)}) and no unbound gap naming this pid or this window")


def check_bound_edge(view, cell, ctag, role, prov, edge, use, image, attested_delivery, res):
    run = view.name
    cov = coverage(edge)
    st = cov.get("state")
    allowed = set(role.native_states)
    attested = bool(prov.get("attested")) and attested_delivery
    if COUNTED_NEEDS_ATTESTED and not attested:
        allowed.discard("counted")
    if role.require_counted_when_attested and attested:
        allowed = {"counted"}
    if role.require_counted:
        allowed = {"counted"}
    res.ok(run, cell, "COVERAGE-ALLOWED", st in allowed,
           f"{ctag}: coverage {st} not in {sorted(allowed)} (attested={attested})")
    if st == "counted":
        until = cov.get("until_ns")
        window = (view.window[0], min(view.window[1], until)) if until is not None else view.window
        admitted = view.callers.get(edge["caller"], {}).get("first_seen_ns")
        mapping_first = edge.get("mapping", {}).get("first_seen_ns")
        lo, hi = window_count(use, cov.get("since_ns") or 0, window)
        count = edge["entries"].get("count", 0)
        total = ledger_total_table_calls(image, prov["path"], cov.get("since_ns"))
        res.ok(run, cell, "COUNT-TOTAL", count <= total,
               f"{ctag}: count {count} above the ledger total {total} attach-side calls")
        if cov.get("lossy"):
            loss_gaps = [g for g in view.doc.get("gaps", [])
                         if LOSS_GAP.search(f"{g.get('subject', '')} {g.get('reason', '')}")]
            label = edge["entries"].get("observation")
            res.ok(run, cell, "COUNT-LOSSY",
                   bool(loss_gaps) and count <= hi and (count > 0 or label == OBSERVATION_LOSSY_ZERO),
                   f"{ctag}: lossy count {count} (upper bound {hi}) needs a loss gap "
                   f"({len(loss_gaps)} found) and, at zero, observation {OBSERVATION_LOSSY_ZERO!r} (got {label!r})")
        else:
            # O7: only a production-shaped saturated triple (fixed
            # u64::MAX cap, u64 count, Boolean flag, saturated at the
            # cap) earns the clamped-bound exemption; a forged triple
            # is judged unclamped (and fails COUNT-SATURATED). O1: a
            # partial-attach gap clamps the lower bound the same way —
            # missed endpoints void it; the upper bound still holds.
            saturated = is_saturated_artifact(edge["entries"])
            partial = has_partial_attach(view, edge)
            res.ok(run, cell, "COUNT-WINDOW", count_window_ok(count, saturated or partial, lo, hi),
                   f"{ctag}: count {count} outside ledger window [{lo}, {hi}] since {cov.get('since_ns')}"
                   + (" (saturated: lower bound clamped at the cap)" if saturated else "")
                   + (" (partial attach: lower bound clamped; counted uses are lower bounds)"
                      if partial and not saturated else ""))
            doc_module = view.modules.get(edge["module"], {})
            verdict, expected, detail = exact_window_count(
                use, cov.get("since_ns") or 0, window, until, admitted,
                mapping_first, doc_module.get("admission", {}).get("endpoints"), partial)
            if verdict == "exact" and not saturated:
                # Ledger exactness = 0 error over the proven covered
                # workload segment (pre-since lines missed for certain;
                # post-since lines recorded; the recording line either
                # proven pre-attachment or the legacy first-singleton):
                # the count equals the segment sum — not a range. A
                # saturated feed stays a lower bound (COUNT-TOTAL).
                res.ok(run, cell, "COUNT-EXACT", count == expected,
                       f"{ctag}: count {count} != ledger {expected} attach-side calls "
                       f"(feed covers every in-window call since {cov.get('since_ns')})")
            elif verdict == "nonqualifying" and not saturated:
                res.add(run, cell, "COUNT-EXACT", "nonqualifying",
                        f"{ctag}: insufficient evidence for exactness: {detail}")
    if st == "witnessed":
        res.ok(run, cell, "WITNESS-COUNT", edge["entries"].get("count", 0) == 0
               and edge["entries"].get("observation") != OBSERVATION_OBSERVED,
               f"{ctag}: witnessed edge claims a count/observation {edge['entries'].get('count')}")
    if attested:
        mechs = {m.get("mechanism"): set(m.get("operations") or []) for m in edge.get("mechanisms") or []}
        missing = {hex(k): sorted(v - mechs.get(k, set())) for k, v in use.mechs.items() if not v <= mechs.get(k, set())}
        extra = sorted(hex(k) for k in mechs if k not in use.mechs)
        res.ok(run, cell, "SEMANTICS-ATTESTED",
               edge.get("semantics") == SEMANTICS_OBSERVED and not missing and not extra,
               f"{ctag}: semantics {edge.get('semantics')!r}; missing mechanism/ops {missing}; unledgered {extra}")


def check_no_preadmission_positive(view, cell, ctag, edge, res):
    """R-C51-1: a row recorded before its caller's admission never binds
    (Rule 3, native_binding.rs:777: row.recorded_at_ns < first_seen_ns),
    so the edge reads unknown/use_before_admission — never a positive.
    The judged event is the ROW (the edge's first-seen: the earliest
    insert stamp), not the ledger's first call: a table obtained before
    the observer started (the acquisition dlsym) with use recorded
    after admission and attachment binds legitimately. A counted (or
    witnessed) positive over a row recorded before admission is the
    DR-C51-PREADMIT upgrade, which v0.3.0 does not build (must-fail:
    counted-on-preadmission). This only narrows failures: a true
    pre-admission row implies a pre-admission ledger call (the entry
    precedes the insert on the same clock)."""
    row_ns = positive_first_ns(edge)
    admitted = view.callers.get(edge["caller"], {}).get("first_seen_ns")
    if row_ns is None or admitted is None:
        return
    res.ok(view.name, cell, "PREADMISSION-POSITIVE", row_ns >= admitted,
           f"{ctag}: edge {edge['caller']} reads {coverage(edge).get('state')} but its row was recorded "
           f"({row_ns}) before its caller's admission ({admitted}): a pre-admission row never binds")


def check_exec_split(view, cell, bound, images, man, mod, res, counted=frozenset()):
    """Leader-reached images bind to distinct callers minted in exec order; a
    required image whose row is count-covered (R-C51-1/-2) is accounted
    without a caller (never merged into another's)."""
    run = view.name
    required = []
    for image in sorted(images.values(), key=lambda i: i.gen):
        how = reached_by(images, image)
        used = any(use_in(image, man["providers"][p]["path"], view.window) for p in man["cells"][cell]["providers"])
        if used and EXEC_HOW_BIND.get(how, "required") == "required":
            required.append(image.gen)
    by_gen = {gen: (caller, first) for gen, _how, caller, first in bound}
    missing = [g for g in required if g not in by_gen and g not in counted]
    callers = [by_gen[g][0] for g in sorted(by_gen)]
    order = [by_gen[g][1] for g in sorted(by_gen)]
    res.ok(run, cell, "EXEC-SPLIT",
           not missing and len(set(callers)) == len(callers) and order == sorted(order),
           f"exec images must each bind to their own incarnation in order: required gens {required}, "
           f"unbound {missing}, bound (gen->caller) {dict((g, c) for g, (c, _f) in sorted(by_gen.items()))}",
           f"bound (gen->caller): {dict((g, c) for g, (c, _f) in sorted(by_gen.items()))}")


def check_counted_nonzero(view, res):
    """C7 C5: an edge reads `counted` only with a count >= 1 — a published
    0 is never a positive fact (r1 T3.5 must-fail). A counted-0 edge never
    binds, so this sweeps every edge rather than riding the bound path."""
    for key in sorted(view.edges):
        edge = view.edges[key]
        if coverage(edge).get("state") != "counted":
            continue
        count = edge["entries"].get("count", 0)
        res.ok(view.name, "*", "COUNTED-NONZERO", count >= 1,
               f"edge {key[0]}->{key[1]} reads counted with count {count}: "
               "a counted edge publishes its entry count, never 0")


def check_saturated(view, res):
    """O7: the saturation triple is production-shaped on every edge and
    coherent — production always publishes the fixed cap u64::MAX
    (MAX_EDGE_ENTRY_COUNT, src/inventory.rs edge_json), a u64 count,
    and a Boolean saturated set exactly when the count reached the cap.
    A forged cap, a non-u64 count, or a non-Boolean flag fails: the
    document can never invent its own saturation exemption."""
    for key in sorted(view.edges):
        entries = view.edges[key]["entries"]
        cap, count, saturated = entries.get("cap"), entries.get("count"), entries.get("saturated")
        wellformed = (type(cap) is int and cap == U64_MAX
                      and type(count) is int and 0 <= count <= U64_MAX
                      and type(saturated) is bool)
        ok = wellformed and saturation_coherent(count, saturated, cap)
        res.ok(view.name, "*", "COUNT-SATURATED", ok,
               f"edge {key[0]}->{key[1]} reads count {count!r} saturated {saturated!r} cap {cap!r}: "
               "production publishes cap=u64::MAX, a u64 count, and saturated exactly at the cap")


def check_uncounted(view, res):
    """C7 C5 (Choice 1): every unknown/`uncounted` edge carries BPF
    PairInsertFailure evidence — the gap plus the evidence name in its
    detail — and publishes no count as fact (zero with the unavailable
    observation). Userspace-only saturation withholds watches but never
    reads uncounted, so an uncounted edge without the BPF evidence fails.
    Counted positives are excepted (they stand beside the gap); only the
    uncounted edges themselves are judged here. O6: the registry's
    bounded output can suppress the gap (past --max-gaps) while the
    edge keeps valid uncounted coverage plus its PairInsertFailure
    detail (NotePairsUncounted demotes edges regardless) — that case
    is explicitly nonqualifying, never a pass or a fail. The detail
    itself is never suppressed, so a missing detail still fails."""
    run = view.name
    gaps = [g for g in view.doc.get("gaps", []) if g.get("subject") == PAIRS_UNCOUNTED_SUBJECT]
    suppressed = view.doc.get("gaps_suppressed") or 0
    for key in sorted(view.edges):
        edge = view.edges[key]
        cov = coverage(edge)
        if cov.get("reason") != UNCOUNTED_REASON:
            continue
        entries = edge["entries"]
        core = (cov.get("state") == UNKNOWN_STATE and entries.get("count", 0) == 0
                and entries.get("observation") == "unknown (usage observation unavailable)"
                and bool(PAIR_INSERT_EVIDENCE.search(cov.get("detail") or "")))
        if core and gaps:
            res.add(run, "*", "UNCOUNTED-EVIDENCE", "pass", "ok")
        elif core and suppressed:
            res.add(run, "*", "UNCOUNTED-EVIDENCE", "nonqualifying",
                    f"edge {key[0]}->{key[1]} reads unknown/uncounted with the BPF PairInsertFailure detail "
                    f"but the {PAIRS_UNCOUNTED_SUBJECT!r} gap is absent while gaps_suppressed={suppressed}: "
                    "bounded output may have suppressed the gap, so the evidence can neither pass nor fail")
        else:
            res.ok(run, "*", "UNCOUNTED-EVIDENCE", False,
                   f"edge {key[0]}->{key[1]} reads {cov.get('state')}/{cov.get('reason')} with count "
                   f"{entries.get('count', 0)} {entries.get('observation')!r} detail {cov.get('detail')!r} "
                   f"and {len(gaps)} {PAIRS_UNCOUNTED_SUBJECT!r} gaps: uncounted needs the BPF "
                   "PairInsertFailure evidence and publishes no count as fact")


def check_positives(view, images_by_cell, mod, state, res):
    """Every positive edge is in the window, and none is unjustified where the
    ledger is the whole truth: ledgered processes and workload-private modules."""
    run, man, win = view.name, view.manifest, view.window
    ledgered = {}
    for cell in view.run["cells"]:
        for image in images_by_cell.get(cell, {}).values():
            ledgered.setdefault((image.pid, image.start), cell)
    private = {mod[r]: r for r, p in man["providers"].items() if p.get("private") and r in mod}
    for edge in view.edges.values():
        if not positive(edge):
            continue
        first = positive_first_ns(edge)
        caller = view.callers.get(edge["caller"], {})
        res.ok(run, "*", "POSITIVE-IN-WINDOW", first is not None and win[0] <= first <= win[1],
               f"positive edge {edge['caller']}->{edge['module']} dated {first}, outside the capture window {win}")
        owner = ledgered.get((caller.get("pid"), caller.get("start_time")))
        justified = (edge["caller"], edge["module"]) in state.justified
        if owner:
            res.ok(run, owner, "NO-CROSS-ATTRIBUTION", justified,
                   f"positive edge {edge['caller']}->{edge['module']} (first {first}) on pid {caller.get('pid')} "
                   "is not justified by any in-window ledgered use of that provider by that image")
        elif edge["module"] in private:
            res.add(run, private[edge["module"]], "FOREIGN-POSITIVE", "fail",
                    f"workload-private provider {private[edge['module']]} has a positive edge from "
                    f"non-ledgered caller {edge['caller']} (pid {caller.get('pid')})")
        if edge["module"] not in state.used_modules and edge["module"] in private:
            res.add(run, private[edge["module"]], "NEVER-CALLED-POSITIVE", "fail",
                    f"provider {private[edge['module']]} has no in-window ledgered use but edge "
                    f"{edge['caller']}->{edge['module']} is positive")
    for prole, prov in man["providers"].items():
        mid = mod.get(prole)
        if mid is None or (prov.get("attested") and man.get("attested_delivery")):
            continue
        claims = [e for e in view.edges.values() if e["module"] == mid and (
            e.get("semantics") not in SEMANTICS_UNKNOWN_LABELS or e.get("mechanisms") or e.get("operations"))]
        res.ok(run, prole, "SEMANTICS-WITHHELD", not claims,
               f"unattested provider {prole}: edges outside the documented unknown labels or with claims "
               f"{[(e['caller'], e.get('semantics')) for e in claims][:4]}")


def check_stop(view, images_by_cell, res):
    stop = view.run.get("stop")
    if not stop:
        return
    run, rc = view.name, view.run.get("rc")
    held = [i for cell in view.run["cells"] for i in images_by_cell.get(cell, {}).values() if i.held_t is not None]
    sent = stop.get("sent_ns") or 0
    for image in held:
        entry = min((e["t0"] for e in image.entries if e["phase"] == "held"), default=None)
        still = entry is not None and entry <= sent and (image.returned_t is None or image.returned_t > sent)
        res.ok(run, image.cell, "STOP-HELD-AT-SIGINT", still,
               f"pid={image.pid}: held entry {entry}, returned {image.returned_t}, SIGINT at {sent}: the fixture "
               "did not hold the call across the stop", f"held from {entry} past SIGINT {sent}")
    committed = isinstance(view.doc, dict) and bool(view.events) and view.events[-1].get("kind") == EVENT_KINDS["ended"]
    latency = (stop.get("exited_ns") or 0) - sent
    if not committed and (view.doc is None or doc_lane(view.doc) != "native"):
        res.add(run, "*", "STOP-COMMIT", "absent",
                f"SIGINT stop left rc={rc}, JSON={'yes' if view.doc else 'no'}, ended={'yes' if committed else 'no'} "
                f"after {latency} ns: the classic loop's stop handling is a C5 deliverable")
        return
    res.ok(run, "*", "STOP-COMMIT", committed and rc in STOP_OK_RC,
           f"SIGINT stop: rc={rc} (want {sorted(STOP_OK_RC)}), JSON={'yes' if view.doc else 'no'}, "
           f"stream ended={'yes' if committed else 'no'}", f"committed, rc={rc}, stop latency {latency} ns")
    if doc_lane(view.doc) != "native":
        res.add(run, "*", "STOP-SETTLEMENT", "absent", "no native retirement to settle")
        return
    verdict, source = settlement_verdict(view.doc)
    if held:
        res.ok(run, "*", "STOP-SETTLEMENT", verdict == HELD_STOP_REQUIRES,
               f"a call was held across the stop, so retirement must read {HELD_STOP_REQUIRES!r}; got "
               f"{verdict!r} ({source})", f"{verdict} ({source})")
    else:
        res.ok(run, "*", "STOP-SETTLEMENT", verdict is not None, f"a native stop must state its settlement ({source})")


# ===========================================================================
# Dashboard frames
# ===========================================================================

def parse_frames(data):
    body = data.split(FRAME["alt_off"], 1)[0]
    frames = []
    for chunk in body.split(FRAME["repaint"])[1:]:
        text = FRAME["ansi"].sub(b"", chunk).replace(b"\r", b"").decode("utf-8", "replace")
        lines = text.split("\n")
        if lines and FRAME["header"].match(lines[0]):
            frames.append(lines)
    return frames


def frame_edges(lines):
    edges, current = {}, None
    indent = FRAME["item_indent"]
    for line in lines:
        m = FRAME["identity"].match(line)
        if m:
            current = (m.group(1), m.group(4))
            edges[current] = {"pid": int(m.group(2)), "items": {}}
            continue
        if current and line.startswith(indent) and not line.startswith(indent + " "):
            for item in line.strip().split(FRAME["item_sep"]):
                key, _, value = item.partition(" ")
                edges[current]["items"].setdefault(key, value)
        elif line.startswith(FRAME["section"]) or not line.strip():
            current = None
    return edges


def check_dashboard(view, images_by_cell, res):
    if not view.frames_path:
        return
    run = view.name
    try:
        with open(view.frames_path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        res.add(run, "*", "DASH-FRAME", "fail", f"pty transcript unreadable: {error}")
        return
    frames = parse_frames(data)
    if not res.ok(run, "*", "DASH-FRAME",
                  bool(frames) and FRAME["alt_on"] in data and FRAME["alt_off"] in data
                  and FRAME["coverage_marker"] in data,
                  f"{len(frames)} full frames; alternate screen entered/exited and coverage header required"):
        return
    pass_events = [e["event"] for e in view.kind("pass")]

    def records_as_of(frame_pass):
        """Each edge's last `edge_observed` record before that pass's
        (non-final) marker, or None when the stream has no such marker
        (the frame predates retention and cannot be judged)."""
        if not any(p.get("pass") == frame_pass and not p.get("final") for p in pass_events):
            return None
        as_of = {}
        for ev in view.events or []:
            if ev.get("kind") == EVENT_KINDS["pass"] and ev["event"].get("pass") == frame_pass \
                    and not ev["event"].get("final"):
                break
            if ev.get("kind") == "edge_observed":
                as_of[(ev["event"].get("caller"), ev["event"].get("module"))] = ev["event"]
        return as_of

    last = frames[-1]
    head = FRAME["header"].match(last[0])
    passes, ncallers, nmodules, nedges = (int(head.group(i)) for i in (2, 3, 4, 5))
    at = next((p for p in pass_events if p.get("pass") == passes - 1), None)
    gaps_line = next((FRAME["coverage"].match(line) for line in last if FRAME["coverage"].match(line)), None)
    if at is None:
        res.add(run, "*", "DASH-TOTALS", "fail", f"final frame claims {passes} passes; the stream has no such pass")
    else:
        cumulative = sum(p.get("new_gaps", 0) for p in pass_events if p.get("pass", 0) <= passes - 1)
        got = (ncallers, nmodules, nedges, int(gaps_line.group(1)) if gaps_line else None)
        want = (at["totals"]["callers"], at["totals"]["modules"], at["totals"]["edges"], cumulative)
        res.ok(run, "*", "DASH-TOTALS", got == want,
               f"final frame (callers, modules, edges, gaps) {got} != stream pass {passes - 1} {want}")
    mine = {}
    for cell in view.run["cells"]:
        for image in images_by_cell.get(cell, {}).values():
            mine[(image.pid, image.start)] = cell

    def want_for(caller, module, edge):
        # Frames show the dashboard display (window recency at the frame's
        # own time, which the oracle cannot see): a counted edge may
        # legally read either its base or recent on screen.
        activity = {expected_activity_base(edge)}
        cov = coverage(edge)
        if cov.get("state") == "counted" and not cov.get("lossy"):
            activity.add(ACTIVITY["recent"])
        return {"capture": {expected_capture(caller, module, edge)},
                "entries": {expected_entries_display(edge)},
                "semantics": {edge.get("semantics")},
                "activity": activity}

    # DR-ORACLE-GATE: every frame is compared with the edge state at its
    # own pass from the event stream. A frame rendered before the stop
    # that froze the watches, or while a first-use row was pending, must
    # show that pass's labels — armed/quiet/0 for a then-ongoing watch,
    # unknown/? for a then-pending edge — never the snapshot's. An edge
    # the stream had not carried yet (deferred emission) cannot be
    # judged, except on the final frame, which still falls back to the
    # snapshot.
    compared = 0
    for index, lines in enumerate(frames):
        final = index == len(frames) - 1
        frame_pass = int(FRAME["header"].match(lines[0]).group(2)) - 1
        as_of = records_as_of(frame_pass)
        for key, frame_edge in frame_edges(lines).items():
            edge = view.edges.get(key)
            if edge is None:
                res.add(run, "*", "DASH-EDGE-LABELS", "fail", f"frame edge {key} is not in the snapshot")
                continue
            caller, module = view.callers[key[0]], view.modules[key[1]]
            items = frame_edge["items"]
            record = (as_of or {}).get(key)
            if record is not None:
                want = want_for(caller, module, record)
                where = f"frame {index} (pass {frame_pass}) {key} disagrees with the stream at that pass"
            elif not final:
                continue
            else:
                want = want_for(caller, module, edge)
                where = f"frame {key} disagrees with the snapshot"
            wrong = {k: (items.get(k), sorted(v)) for k, v in want.items() if items.get(k) not in v}
            if final and (caller.get("pid"), caller.get("start_time")) in mine:
                compared += 1
            res.ok(run, "*", "DASH-EDGE-LABELS", not wrong, f"{where}: {wrong}")
    shown = frame_edges(last)
    missing = [k for k, e in view.edges.items()
               if (view.callers[k[0]].get("pid"), view.callers[k[0]].get("start_time")) in mine and k not in shown]
    res.ok(run, "*", "DASH-VISIBLE", compared > 0 and not missing,
           f"{compared} ledgered cell edges compared; not visible in the final frame: {missing[:6]} "
           "(enlarge the pty or narrow with --module)", f"{compared} ledgered cell edges compared")


# ===========================================================================
# Driver
# ===========================================================================

def load_images(manifest, rundir, res):
    images_by_cell = {}
    for cell, spec in manifest["cells"].items():
        errors = []
        try:
            with open(os.path.join(rundir, spec["ledger"]), encoding="utf-8") as handle:
                parsed = parse_ledger(handle.read(), errors)
        except OSError as error:
            errors.append(f"ledger unreadable: {error}")
            parsed = {}
        for error in errors:
            res.add("ledger", cell, "LEDGER-PARSE", "fail", error)
        images_by_cell[cell] = {k: v for k, v in parsed.items() if k[0] == cell}
    return images_by_cell


def check_completeness(manifest, res):
    roles = {spec["role"] for spec in manifest["cells"].values()}
    res.ok("manifest", "*", "ROLES-COMPLETE", roles >= set(ROLES),
           f"cells cover roles {sorted(roles)}; missing {sorted(set(ROLES) - roles)}")
    runs = {r["name"]: r for r in manifest.get("runs", [])}
    for name, need in REQUIRED_RUNS.items():
        if name not in runs:
            if name in SKIPPABLE_RUNS and name in manifest.get("skipped_runs", []):
                res.add("manifest", "*", "RUNS-COMPLETE", "nonqualifying",
                        f"run {name!r} was skipped by the operator: the qualification is incomplete")
            else:
                res.add("manifest", "*", "RUNS-COMPLETE", "fail", f"required run {name!r} is missing")
            continue
        got = {manifest["cells"][c]["role"] for c in runs[name]["cells"] if c in manifest["cells"]}
        res.ok("manifest", "*", "RUNS-COMPLETE", got >= need,
               f"run {name!r} covers roles {sorted(got)}; missing {sorted(need - got)}")


def oracle(rundir, ledgers_only=False):
    manifest = load_json(os.path.join(rundir, "run.json"))
    if manifest.get("manifest") != MANIFEST_ID:
        raise SystemExit(f"run.json manifest {manifest.get('manifest')!r} != {MANIFEST_ID!r}")
    res = Results(manifest["expect_lane"])
    for cell, spec in manifest["cells"].items():
        if spec["role"] not in ROLES:
            res.add("ledger", cell, "ROLE", "fail", f"unknown role {spec['role']!r}")
    images_by_cell = load_images(manifest, rundir, res)
    check_ledgers(manifest, images_by_cell, res)
    if ledgers_only:
        return res
    check_completeness(manifest, res)
    for run in manifest.get("runs", []):
        view = RunView(manifest, run, rundir)
        for error in view.errors:
            res.add(view.name, "*", "DOC-READ", "fail", error)
        if run.get("stop"):
            check_stop(view, images_by_cell, res)
            if not isinstance(view.doc, dict):
                continue
        elif not isinstance(view.doc, dict):
            res.add(view.name, "*", "DOC-READ", "fail", f"no -o JSON (rc={run.get('rc')})")
            continue
        else:
            res.ok(view.name, "*", "RUN-RC", run.get("rc") in RUN_OK_RC, f"observer exited rc={run.get('rc')}")
        check_streams(view, res)
        check_cells(view, images_by_cell, res)
        check_dashboard(view, images_by_cell, res)
        if not any(r["status"] == "pass" and r["run"] == view.name and r["check"] not in ("DOC-SCHEMA",)
                   for r in res.rows):
            res.add(view.name, "*", "NON-VACUOUS", "fail", "no assertion passed for this run")
    return res


def report(res, out_path=None, ledgers_only=False):
    if out_path:
        with open(out_path, "w", encoding="utf-8") as handle:
            for row in res.rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    for row in res.rows:
        if row["status"] != "pass":
            print(f"{row['status'].upper():13} {row['run']}/{row['cell']} {row['check']}: {row['detail']}")
    code = res.exit_code()
    verdict = {0: "QUALIFIED", 1: "FAILED", 2: "NON-QUALIFYING"}[code]
    if ledgers_only:
        verdict = "LEDGERS-FAILED" if code == EXIT["failed"] else "LEDGERS-CONSISTENT"
    print(f"{ORACLE_ID} expect_lane={res.expect_lane} verdict={verdict} summary={json.dumps(res.summary(), sort_keys=True)}")
    return code


def count_kind(path, kind):
    want = EVENT_KINDS[kind]
    count = 0
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    count += json.loads(line).get("kind") == want
                except ValueError:
                    pass  # a line being written right now
    except OSError:
        pass
    print(count)
    return 0


def probe_help(text):
    usage = "\n".join(line for line in text.splitlines() if HELP_PROBE["usage"] in line)
    for name, flag in HELP_PROBE["flags"].items():
        print(f"{name}={1 if flag in usage else 0}")
    return 0


def record_pty(argv):
    """record-pty OUT ROWS COLS BUDGET_S STOP_AFTER_S -- ARGV...: run ARGV on a pty sized
    ROWS x COLS, keep every byte in OUT, send `q` after STOP_AFTER_S (0 = never), kill
    at BUDGET_S. Prints `rc=<exit code>` (128+signal when killed)."""
    import fcntl
    import pty
    import select
    import struct
    import termios
    import time

    out, rows, cols, budget, stop_after = argv[0], int(argv[1]), int(argv[2]), float(argv[3]), float(argv[4])
    if argv[5] != "--":
        raise SystemExit("record-pty: expected -- before the command")
    command = argv[6:]
    child, master = pty.fork()
    if child == 0:
        os.execv(command[0], command)
        os._exit(127)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    data = bytearray()
    start = time.monotonic()
    sent_q = False
    status = None

    def drain(timeout):
        ready, _, _ = select.select([master], [], [], timeout)
        if not ready:
            return False
        try:
            chunk = os.read(master, 65536)
        except OSError:
            return False
        data.extend(chunk)
        return bool(chunk)

    while time.monotonic() - start < budget:
        done, code = os.waitpid(child, os.WNOHANG)
        if done:
            status = code
            break
        if stop_after > 0 and not sent_q and time.monotonic() - start >= stop_after:
            try:
                os.write(master, b"q")
            except OSError:
                pass
            sent_q = True
        drain(0.2)
    if status is None:
        os.kill(child, 9)
        _, status = os.waitpid(child, 0)
    while drain(0.2):
        pass
    os.close(master)
    with open(out, "wb") as handle:
        handle.write(bytes(data))
    rc = os.waitstatus_to_exitcode(status)
    print(f"rc={rc if rc >= 0 else 128 - rc}")
    return 0


# ===========================================================================
# Self-test: synthetic fixtures (no root, no p11scope, no SoftHSM2)
# ===========================================================================

T0 = 1_000_000_000_000
MS = 1_000_000


def _deep(value):
    return json.loads(json.dumps(value))


class Synth:
    """A consistent synthetic qualification: system, dashboard and stop runs.
    Cases mutate one document (or the manifest) and expect one check to fail."""

    def __init__(self, lane, expect_lane=None):
        self.lane = lane
        self.expect_lane = expect_lane or lane
        self.providers = {
            "A": {"path": "/prov/a/libsofthsm2.so", "ino": 101, "sha256": "aa" * 32, "attested": True, "private": False},
            "B": {"path": "/prov/b/libsofthsm2.so", "ino": 102, "sha256": "aa" * 32, "attested": False, "private": True},
            "C": {"path": "/prov/c/libsofthsm2.so", "ino": 103, "sha256": "aa" * 32, "attested": False, "private": True},
            "BLK": {"path": "/prov/held.so", "ino": 104, "sha256": "bb" * 32, "attested": False, "private": True},
        }
        self.cells = {
            "P1": {"role": "P1", "mode": "mech", "providers": ["A"], "iters": 3, "hold": True},
            "P2": {"role": "P2", "mode": "mech", "providers": ["B"], "iters": 2, "hold": True},
            "P3": {"role": "P3", "mode": "map", "providers": ["A", "C"], "iters": 0, "hold": True},
            "P4": {"role": "P4", "mode": "mech", "providers": ["A"], "iters": 1, "hold": False, "instances": 2},
            "P5": {"role": "P5", "mode": "exec-chain", "providers": ["A"], "iters": 1, "hold": False,
                   "exe": "/wl/ledger", "chain": ["leader:/wl/ledger", "leader:/wl/ledger2", "thread:/wl/ledger"]},
            "P6": {"role": "P6", "mode": "held", "providers": ["BLK"], "iters": 0, "hold": True},
            "P7": {"role": "P7", "mode": "mech", "providers": ["A"], "iters": 2, "hold": True},
            "LX": {"role": "LX", "mode": "leader-exit", "providers": ["A"], "iters": 2, "hold": False},
        }
        self.ledgers, self.images = {}, []
        self.clock = T0 + 1000 * MS
        pid = 5000
        for cell, spec in self.cells.items():
            text = []
            for _inst in range(spec.get("instances", 1)):
                pid += 1
                start = 777 + pid
                steps = [("initial", spec.get("exe", "/wl/ledger"))] + [tuple(s.split(":", 1)) for s in spec.get("chain", [])]
                for gen, (_how, exe) in enumerate(steps):
                    nxt = steps[gen + 1] if gen + 1 < len(steps) else None
                    text.extend(self.image_lines(cell, spec, pid, start, gen, exe, nxt))
                    self.clock += 300 * MS
            self.ledgers[cell] = "\n".join(text) + "\n"
        self.run_end = self.clock + 2000 * MS
        self.doc = self.build_doc()
        self.dash_start = self.run_end + 1000 * MS
        self.dash_doc = self.build_dash_doc()
        self.stop_sent = self.held_t + 3000 * MS

    def image_lines(self, cell, spec, pid, start, gen, exe, nxt):
        head = f"cell={cell} pid={pid} start={start} gen={gen} exe={exe}"
        lines = [f"IDENT {head}"]
        uses = {}
        for role in spec["providers"]:
            lines.append(f"MAPPED {head} module={self.providers[role]['path']} ino={self.providers[role]['ino']}")
        if spec["mode"] == "map":
            lines.append(f"DONE {head} status=ok")
        elif spec["mode"] == "held":
            path, t = self.providers["BLK"]["path"], self.clock
            lines.append(f"LEDGER {head} module={path} fn=C_GetFunctionList mech=- n=1 bad=0 phase=setup t0={t} t1={t}")
            lines.append(f"LEDGER {head} module={path} fn=C_WaitForSlotEvent mech=- n=1 bad=0 phase=held t0={t + MS} t1={t + MS}")
            lines.append(f"HELD {head} module={path} fn=C_WaitForSlotEvent t={t + 2 * MS}")
            self.held_t = t + MS
            self.held_head = head
            uses["BLK"] = (t, t + MS, 1)
            self.clock += 5 * MS
        else:
            if spec["mode"] == "leader-exit":
                lines.append(f"ZOMBIE {head} state=Z t={self.clock}")
            for k, role in enumerate(spec["providers"]):
                path = self.providers[role]["path"]
                mult = (k + 1) if spec["mode"] == "mech" else (gen + 1) if spec["mode"] == "exec-chain" else 1
                iters = spec["iters"] * mult
                plan = [("setup", fn, "-", 1) for fn in SETUP_FNS]
                plan += [("main", fn, mech, iters) for fn, mech in MAIN_PLAN]
                plan += [("main", "C_DestroyObject", "-", 2 * iters)]
                plan += [("teardown", fn, "-", 1) for fn in TEARDOWN_FNS]
                first, table = self.clock, 0
                for phase, fn, mech, n in plan:
                    t0 = self.clock
                    self.clock += 2 * MS
                    lines.append(f"LEDGER {head} module={path} fn={fn} mech={mech} n={n} bad=0 phase={phase} "
                                 f"t0={t0} t1={self.clock}")
                    self.clock += MS
                    if is_table_call(fn, phase):
                        table += n
                uses[role] = (first, self.clock, table)
            lines.append(f"DONE {head} status=ok")
            if nxt:
                lines.append(f"EXEC {head} how={nxt[0]} next={nxt[1]}")
        self.images.append((cell, pid, start, gen, exe, spec, uses))
        return lines

    def modules(self):
        mid, out = {}, []
        for i, (role, p) in enumerate(self.providers.items()):
            mid[role] = f"m{i}"
            out.append({"id": f"m{i}", "paths": [p["path"]],
                        "identity": {"device": {"major": 0, "minor": 35}, "inode": p["ino"], "sha256": p["sha256"],
                                     "build_id": None, "source": "mountinfo"},
                        "admission": {"state": "admitted", "class": "exact", "endpoints": 68, "reasons": [],
                                      "note": "", "history": []},
                        "lifecycle": "mapped", "unloaded_observed": False})
        self.mid = mid
        return out

    @staticmethod
    def edge(cid, mid, alive, first, end):
        return {"caller": cid, "module": mid,
                "mapping": {"state": "mapped" if alive else "ended", "reason": None,
                            "first_seen_ns": first, "last_seen_ns": end, "interruptions": 0},
                "entries": {"count": 0, "saturated": False, "cap": 2**64 - 1, "first_seen_ns": None,
                            "last_seen_ns": None, "in_flight": False,
                            "observation": "unknown (usage observation unavailable)",
                            "coverage": {"state": "unknown", "since_ns": None, "until_ns": None, "first_ns": None, "lossy": None,
                                         "reason": "scan_only", "detail": None}},
                "semantics": "unknown (semantic capture withheld)", "mechanisms": None, "operations": None}

    def caller(self, cid, pid, start, gen, exe, native, lifecycle, first, end, retired):
        return {"id": cid, "pid": pid, "start_time": start, "start_time_unit": "clock_ticks_since_boot",
                "incarnation": gen, "image": {"authority": "native_exact" if native else "scan_pinned",
                                              "exe": {"path": exe}, "exec_observed": True},
                "lifecycle": lifecycle, "lifecycle_reason": None, "first_seen_ns": first,
                "last_seen_ns": end, "retired": retired}

    def finish(self, callers, modules, edges, gaps, start, end, native):
        return {"schema": SCHEMAS["inventory"], "scope": "system",
                "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
                "observation": {"started_ns": start, "ended_ns": end, "passes": 9, "usage_feed": native},
                "budgets": {"callers": {"limit": 4096, "occupied": len(callers), "refused": 0}},
                "callers": callers, "modules": modules, "edges": edges,
                "gaps": [{"caller": None, "module": None, "pid": None, "subject": "exact image authority unavailable",
                          "reason": "synthetic", "budget": None, "repeats": 1}] + gaps,
                "gaps_suppressed": 0}

    def build_doc(self):
        native = self.lane == "native"
        modules = self.modules()
        callers, edges, gaps = [], [], []
        self.ids = {}
        for cell, pid, start, gen, exe, spec, uses in self.images:
            if cell == "P6":
                continue
            final = gen == len(spec.get("chain", []))
            alive = spec.get("hold") and final
            if not native and not alive:
                continue
            # The thread-reached exec image stays unbound (exercises the gap path).
            if native and spec["mode"] == "exec-chain" and gen == 3:
                gaps.append({"caller": None, "module": self.mid["A"], "pid": pid,
                             "subject": "used by an unidentified caller image", "reason": "synthetic", "budget": None, "repeats": 1})
                continue
            cid = f"c{len(callers)}"
            self.ids[(cell, pid, gen)] = cid
            first_use = min([u[0] for u in uses.values()] or [self.clock])
            lifecycle = "mapped" if alive else ("exec_retired" if not final else "exited")
            callers.append(self.caller(cid, pid, start, gen, exe, native, lifecycle, first_use - 50 * MS,
                                       self.run_end, not alive))
            for role in spec["providers"]:
                edge = self.edge(cid, self.mid[role], alive, first_use, self.run_end)
                use = uses.get(role)
                if native:
                    self.native_coverage(edge, role, use, T0)
                edges.append(edge)
        return self.finish(callers, modules, edges, gaps, T0, self.run_end, native)

    def native_coverage(self, edge, role, use, since):
        cov = edge["entries"]["coverage"]
        if use:
            # C7 C5: since v0.3.0 the native lane counts every bound row,
            # attested or not (P2's unattested B reads Counted with the
            # exact table sum). Semantic claims stay attested-only.
            # Round 2: the synth's since always predates the workload,
            # so the one setup acquisition provably executed after the
            # first row existed — through an armed endpoint — and counts
            # (LEDGER-COUNTS pins exactly one per provider).
            cov.update(state="counted", since_ns=since, lossy=False, reason=None)
            edge["entries"].update(count=use[2] + 1, first_seen_ns=use[0] + MS, last_seen_ns=use[1],
                                   observation="observed")
            if self.providers[role]["attested"]:
                edge["semantics"] = "observed"
                edge["mechanisms"] = [
                    {"mechanism": m, "mechanism_hex": hex(m), "name": None, "operations": ops, "calls": 1, "errors": 0,
                     "last_seen_ns": use[1], "evidence": {}}
                    for m, ops in [(0x250, ["digest"]), (0x251, ["sign"]), (0x350, ["generate_key"]),
                                   (0x1080, ["generate_key"]), (0x1087, ["encrypt"])]]
                edge["operations"] = {"calls": 1, "active": []}
        else:
            cov.update(state=WATCH_STATE, since_ns=since, reason=None)
            edge["entries"]["observation"] = "observed"

    def build_dash_doc(self):
        """A later --system run over the held, now idle, cells P1 P2 P3 P7."""
        native = self.lane == "native"
        modules = self.modules()
        start, end = self.dash_start, self.dash_start + 15000 * MS
        callers, edges = [], []
        self.dash_ids = {}
        for cell, pid, st, gen, exe, spec, _uses in self.images:
            if cell not in ("P1", "P2", "P3", "P7"):
                continue
            cid = f"c{len(callers)}"
            self.dash_ids[cell] = cid
            callers.append(self.caller(cid, pid, st, gen, exe, native, "mapped", start + MS, end, False))
            for role in spec["providers"]:
                edge = self.edge(cid, self.mid[role], True, start + MS, end)
                if native:
                    self.native_coverage(edge, role, None, start + 2 * MS)
                edges.append(edge)
        return self.finish(callers, modules, edges, [], start, end, native)

    def stop_doc(self, verdict="unsettled"):
        if self.lane == "scan":
            return None
        modules = self.modules()
        cell, pid, st, gen, exe, _spec, uses = next(i for i in self.images if i[0] == "P6")
        start, end = self.held_t - 1000 * MS, self.stop_sent + 200 * MS
        callers = [self.caller("c0", pid, st, gen, exe, True, "mapped", start + MS, end, False)]
        edge = self.edge("c0", self.mid["BLK"], True, start + MS, end)
        self.native_coverage(edge, "BLK", uses["BLK"], start)
        doc = self.finish(callers, modules, [edge], [], start, end, True)
        if verdict:
            doc["observation"]["retirement"] = verdict
        return doc

    def events(self, doc, edge_events=True, extra=None):
        rows = [("started", {"scope": doc["scope"]})]
        rows += [("caller_event", {"event": "admitted", "caller": c["id"]}) for c in doc["callers"]]
        rows += [("gap_recorded", dict({k: v for k, v in g.items() if k != "repeats"}, index=i))
                 for i, g in enumerate(doc["gaps"])]
        rows += [("gap_repeated", {"index": i, "repeats": g["repeats"]})
                 for i, g in enumerate(doc["gaps"]) if g.get("repeats", 1) > 1]
        edge_rows = 0
        if edge_events:
            callers = {c["id"]: c for c in doc["callers"]}
            modules = {m["id"]: m for m in doc["modules"]}
            for e in doc["edges"]:
                ev = dict(_deep(e), presence=expected_presence(callers[e["caller"]], modules[e["module"]], e),
                          capture=expected_capture(callers[e["caller"]], modules[e["module"]], e),
                          activity=expected_activity_base(e))
                rows.append(("edge_observed", ev))
                edge_rows += 1
        rows += extra or []
        rows.append(("pass_committed", {"pass": doc["observation"]["passes"] - 1, "new_gaps": len(doc["gaps"]),
                                        "suppressed_delta": doc["gaps_suppressed"],
                                        "edge_events": edge_rows, "edge_events_deferred": 0,
                                        "totals": {"callers": len(doc["callers"]), "modules": len(doc["modules"]),
                                                   "edges": len(doc["edges"])}}))
        rows.append(("ended", {"ended_ns": doc["observation"]["ended_ns"], "passes": doc["observation"]["passes"],
                               "budgets": doc["budgets"], "gaps_suppressed": doc["gaps_suppressed"],
                               "edge_events": 0, "edges_unretained": 0}))
        return [{"schema": SCHEMAS["events"], "seq": i, "at_ns": T0 + i, "kind": k, "event": e}
                for i, (k, e) in enumerate(rows)]

    def frames(self, doc, overrides=None):
        callers = {c["id"]: c for c in doc["callers"]}
        modules = {m["id"]: m for m in doc["modules"]}
        lines = [f"p11scope inventory system | {doc['observation']['passes']} passes | {len(doc['callers'])} callers "
                 f"{len(doc['modules'])} modules {len(doc['edges'])} edges",
                 f"coverage: {len(doc['gaps'])} gaps 0 refusals 0 suppressed", "budgets: ...",
                 "--- edges 1-2 of 2 [summary] ---"]
        for e in doc["edges"]:
            c, m = callers[e["caller"]], modules[e["module"]]
            activity = expected_activity_base(e)
            activity = (overrides or {}).get((e["caller"], e["module"]), activity)
            lines.append(f"{e['caller']} pid {c['pid']} ({c['image']['exe']['path']}) -> {e['module']} ({m['paths'][0]})")
            lines.append(f"  mapping {e['mapping']['state']} | presence mapped | capture {expected_capture(c, m, e)} | "
                         f"activity {activity} | entries {expected_entries_display(e)} | semantics {e['semantics']}")
        frame = "\x1b[H" + "\n".join(line + "\x1b[K" for line in lines)
        return ("\x1b[?1049h" + frame + frame + "\x1b[?25h\x1b[?1049l").encode()

    def write(self, root, doc=None, dash_doc=None, stop_doc="default", events=None, dash_events=None,
              frames=None, ledgers=None, settle=3, manifest_edit=None, edge_events=True):
        doc = self.doc if doc is None else doc
        dash_doc = self.dash_doc if dash_doc is None else dash_doc
        sdoc = self.stop_doc() if stop_doc == "default" else stop_doc
        os.makedirs(os.path.join(root, "ledgers"))
        cells = {}
        for cell, spec in self.cells.items():
            name = f"ledgers/{cell}.out"
            text = (ledgers or {}).get(cell, self.ledgers[cell])
            if cell == "P6" and "RETURNED" not in text:
                text += f"RETURNED {self.held_head} fn=C_WaitForSlotEvent t={self.stop_sent + 500 * MS} rv=0x0\n"
            with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
                handle.write(text)
            cells[cell] = dict(spec, ledger=name)

        def dump(name, value, lines=False):
            with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
                if lines:
                    handle.writelines(json.dumps(row) + "\n" for row in value)
                else:
                    json.dump(value, handle)

        dump("system.json", doc)
        dump("system.jsonl", events if events is not None else self.events(doc, edge_events), lines=True)
        dump("dashboard.json", dash_doc)
        dump("dashboard.jsonl", dash_events if dash_events is not None else self.events(dash_doc, edge_events),
             lines=True)
        with open(os.path.join(root, "dashboard.pty"), "wb") as handle:
            handle.write(frames if frames is not None else self.frames(dash_doc))
        runs = [
            {"name": "system", "cells": [c for c in self.cells if c != "P6"], "json": "system.json",
             "jsonl": "system.jsonl", "frames": None, "rc": 0, "stop": None, "settle_passes": settle},
            {"name": "dashboard", "cells": ["P1", "P2", "P3", "P7"], "json": "dashboard.json",
             "jsonl": "dashboard.jsonl", "frames": "dashboard.pty", "rc": 0, "stop": None, "settle_passes": None},
            {"name": "stop", "cells": ["P6"], "json": "stop.json" if sdoc else None,
             "jsonl": "stop.jsonl" if sdoc else None, "frames": None, "rc": 0 if sdoc else 130,
             "stop": {"signal": "INT", "sent_ns": self.stop_sent, "exited_ns": self.stop_sent + 100 * MS},
             "settle_passes": None},
        ]
        if sdoc:
            dump("stop.json", sdoc)
            dump("stop.jsonl", self.events(sdoc, edge_events), lines=True)
        manifest = {"manifest": MANIFEST_ID, "expect_lane": self.expect_lane, "attested_delivery": True,
                    "providers": self.providers, "cells": cells, "runs": runs, "skipped_runs": []}
        if manifest_edit:
            manifest_edit(manifest)
        dump("run.json", manifest)
        return root


def _edge(doc, caller, module):
    return next(e for e in doc["edges"] if e["caller"] == caller and e["module"] == module)


def self_test():
    failures = []
    with tempfile.TemporaryDirectory(prefix="c8-oracle-") as tmp:
        counter = [0]

        def run_case(name, root, want):
            res = oracle(root)
            failed = {r["check"] for r in res.failed()}
            if want is None:
                ok = not failed and res.summary().get("pass", 0) > 0
                detail = f"unexpected failures {sorted(failed)}: {[r['detail'][:160] for r in res.failed()][:3]}"
            elif isinstance(want, int):
                ok = res.exit_code() == want
                detail = f"exit {res.exit_code()} != {want}; failed={sorted(failed)}"
            else:
                ok = want in failed
                detail = f"expected {want} to fail; failed={sorted(failed)}"
            print(f"self-test {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
            if not ok:
                failures.append(name)
            return res

        def case(name, want, mutate=None, lane="native", expect=None):
            counter[0] += 1
            s = Synth(lane, expect)
            doc, dash = _deep(s.doc), _deep(s.dash_doc)
            kw = (mutate(s, doc, dash) if mutate else None) or {}
            return run_case(name, s.write(os.path.join(tmp, f"{counter[0]:02d}-{name}"), doc=doc, dash_doc=dash, **kw), want)

        def cid(s, cell, gen=0, idx=0):
            keys = sorted(k for k in s.ids if k[0] == cell and k[2] == gen)
            return s.ids[keys[idx]]

        # --- passing runs -------------------------------------------------------
        res = case("native-pass", None)
        if not any(r["status"] == "unbound" for r in res.rows):
            failures.append("native-pass-exercises-unbound")
        if not any(r["check"] == "AGREE-EDGE-EVENTS" and r["status"] == "pass" for r in res.rows):
            failures.append("native-pass-exercises-edge-events")
        if not any(r["check"] == "IDLE-NOT-POSITIVE" and r["run"] == "dashboard" for r in res.rows):
            failures.append("native-pass-exercises-idle-dashboard")
        if not any(r["check"] == "DASH-TOTALS" and r["status"] == "pass" for r in res.rows):
            failures.append("native-pass-dash-totals-not-skipped")
        res = case("scan-nonqualifying", EXIT["nonqualifying"], lane="scan")
        if res.failed() or not any(r["status"] == "absent" for r in res.rows):
            failures.append("scan-absent-rows")
        # --- capture window -----------------------------------------------------
        def dash_positive(s, d, dash):
            e = _edge(dash, s.dash_ids["P1"], s.mid["A"])
            e["entries"]["coverage"].update(state="witnessed", first_ns=s.dash_start + 5 * MS, since_ns=None)
        case("idle-cell-positive-in-later-run", "IDLE-NOT-POSITIVE", dash_positive)

        def before_start(s, d, dash):
            e = _edge(d, cid(s, "P2"), s.mid["B"])
            d["observation"]["started_ns"] = positive_first_ns(e) + MS
        case("positive-before-capture-start", "POSITIVE-IN-WINDOW", before_start)
        # --- binding --------------------------------------------------------------
        def exec_merged(s, d, dash):
            gone = {cid(s, "P5", g) for g in (1, 2)}
            d["callers"] = [c for c in d["callers"] if c["id"] not in gone]
            d["edges"] = [e for e in d["edges"] if e["caller"] not in gone]
            d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": None,
                              "subject": "used by an unidentified caller image", "reason": "x", "budget": None, "repeats": 1})
        case("exec-merged-plus-gap", "EXEC-SPLIT", exec_merged)

        def all_optional_lost(s, d, dash):
            gone = {v for k, v in s.ids.items() if k[0] in ("P4",)}
            d["callers"] = [c for c in d["callers"] if c["id"] not in gone]
            d["edges"] = [e for e in d["edges"] if e["caller"] not in gone]
            for _ in range(2):
                d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": None,
                                  "subject": "used by an unidentified caller image", "reason": "x", "budget": None, "repeats": 1})
        case("optional-cell-all-unbound", "RETAINED", all_optional_lost)

        def p4_pid_gaps(s, d, dash):
            gone = {v for k, v in s.ids.items() if k[0] == "P4"}
            pids = [k[1] for k in s.ids if k[0] == "P4"]
            d["callers"] = [c for c in d["callers"] if c["id"] not in gone]
            d["edges"] = [e for e in d["edges"] if e["caller"] not in gone]
            for pid in pids:
                d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": pid,
                                  "subject": "used by an unidentified caller image", "reason": "x", "budget": None, "repeats": 1})
        case("optional-cell-no-bound-instance", "BOUND-INSTANCE", p4_pid_gaps)

        # --- R-C51-1/-2: count-covered unbound rows (controller 2026-10-03) ---
        def counted(s, d, rows, at=None):
            """The system stream with `rows` ({module, reason, rows}) on its last
            pass marker, committed at `at` (default: the run's end)."""
            ev = s.events(d)
            for e in ev:
                if e["kind"] in ("pass_committed", "ended"):
                    e["at_ns"] = (at if at is not None else s.run_end) + e["seq"]
            next(e for e in ev if e["kind"] == "pass_committed")["event"]["unbound_rows"] = rows
            return {"events": ev}

        def drop(s, d, cell, gens=(0,)):
            gone = {v for k, v in s.ids.items() if k[0] == cell and k[2] in gens}
            d["callers"] = [c for c in d["callers"] if c["id"] not in gone]
            d["edges"] = [e for e in d["edges"] if e["caller"] not in gone]

        def pidless(s, d):
            d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": None, "repeats": 1,
                              "subject": "used by an unidentified caller image", "reason": "x", "budget": None})

        def p4_counted(n, at=None):
            def mutate(s, d, dash):
                drop(s, d, "P4")
                pidless(s, d)
                return counted(s, d, [{"module": s.mid["A"], "reason": "no_live_caller", "rows": n}], at)
            return mutate
        res = case("short-lived-count-covered", None, p4_counted(2))
        if not any(r["cell"] == "P4" and r["status"] == "unbound" for r in res.rows):
            failures.append("short-lived-count-covered-exercised")
        case("short-lived-count-short", "RETAINED", p4_counted(1))
        case("short-lived-count-before-use", "RETAINED", p4_counted(2, at=T0 + 100))

        def p4_wrong_reason(s, d, dash):
            drop(s, d, "P4")
            pidless(s, d)
            return counted(s, d, [{"module": s.mid["A"], "reason": "lifecycle_loss", "rows": 2}])
        case("short-lived-count-other-reason", "RETAINED", p4_wrong_reason)

        def p4_no_gap(s, d, dash):
            drop(s, d, "P4")
            return counted(s, d, [{"module": s.mid["A"], "reason": "no_live_caller", "rows": 2}])
        case("short-lived-count-without-pidless-gap", "RETAINED", p4_no_gap)

        def p4_module_statement(reason):
            def mutate(s, d, dash):
                drop(s, d, "P4")
                m = next(m for m in d["modules"] if m["id"] == s.mid["A"])
                m["unbound_use"] = {"first_ns": T0, "rows": 2, "reasons": {reason: 2}}
                return counted(s, d, [{"module": s.mid["A"], "reason": "no_live_caller", "rows": 2}])
            return mutate
        def p4_module_statement_retained(suppressed):
            inner = p4_module_statement("no_live_caller")

            def mutate(s, d, dash):
                d["gaps_suppressed"] = suppressed
                return inner(s, d, dash)
            return mutate
        case("short-lived-count-module-statement", None, p4_module_statement_retained(3))
        case("short-lived-count-module-statement-other-reason", "RETAINED", p4_module_statement("lifecycle_loss"))
        # Review L-5: without proven gap suppression the gap itself is required.
        case("short-lived-count-module-statement-unsuppressed", "RETAINED", p4_module_statement_retained(0))

        # Review M-1: an image whose caller was admitted and live before its
        # first call must bind; count coverage never excuses it.
        def admitted_live_counted(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"]["coverage"].update(state="unknown", first_ns=None, since_ns=None, reason="not_attached",
                                                lossy=None)
            e["entries"]["observation"] = "unknown (usage observation unavailable)"
            caller = next(c for c in d["callers"] if c["id"] == cid(s, "P1"))
            first = min(u[0] for c, _p, _s, _g, _e, _sp, uses in s.images if c == "P1" for u in uses.values())
            caller["first_seen_ns"] = first - MS
            pidless(s, d)
            return counted(s, d, [{"module": s.mid["A"], "reason": "no_live_caller", "rows": 1}])
        case("admitted-live-caller-counted", "USED-POSITIVE", admitted_live_counted)


        def p5_counted(n):
            def mutate(s, d, dash):
                drop(s, d, "P5", gens=(1, 2))
                pidless(s, d)
                return counted(s, d, [{"module": s.mid["A"], "reason": "no_live_caller", "rows": n}])
            return mutate
        case("exec-images-count-covered", None, p5_counted(2))
        case("exec-images-count-short", "EXEC-SPLIT", p5_counted(1))

        # Rule 4 (native_binding.rs): an exec-chain image's row may stay
        # unbound as exec_after_admission; the oracle counts it. Without the
        # exec-reason rule this case fails EXEC-SPLIT like count-short.
        def p5_exec_reason(s, d, dash):
            drop(s, d, "P5", gens=(1, 2))
            pidless(s, d)
            return counted(s, d, [{"module": s.mid["A"], "reason": "exec_after_admission", "rows": 2}])
        res = case("exec-chain-count-exec-reason", None, p5_exec_reason)
        if not any(r["cell"] == "P5" and r["status"] == "unbound" and "exec_after_admission" in r["detail"]
                   for r in res.rows):
            failures.append("exec-chain-count-exec-reason-exercised")

        # Exec reasons are exec-chain-only: a short-lived image cannot claim
        # them, so its no_live_caller rows are not stolen (L-4).
        def p4_exec_reason(s, d, dash):
            drop(s, d, "P4")
            pidless(s, d)
            return counted(s, d, [{"module": s.mid["A"], "reason": "exec_after_admission", "rows": 2}])
        case("short-lived-count-exec-reason-rejected", "RETAINED", p4_exec_reason)

        def p1_preadmission(n, admitted_early=False):
            def mutate(s, d, dash):
                e = _edge(d, cid(s, "P1"), s.mid["A"])
                e["entries"]["coverage"].update(state="unknown", first_ns=None, since_ns=None,
                                                reason="use_before_admission", lossy=None)
                e["entries"]["observation"] = "unknown (usage observation unavailable)"
                caller = next(c for c in d["callers"] if c["id"] == cid(s, "P1"))
                first = min(u[0] for c, _p, _s, _g, _e, _sp, uses in s.images if c == "P1" for u in uses.values())
                caller["first_seen_ns"] = first - MS if admitted_early else first + MS
                pidless(s, d)
                rows = [{"module": s.mid["A"], "reason": "before_admission", "rows": n}] if n else []
                return counted(s, d, rows)
            return mutate
        res = case("use-before-admission-counted", None, p1_preadmission(1))
        if not any(r["cell"] == "P1" and r["status"] == "unbound" for r in res.rows):
            failures.append("use-before-admission-exercised")
        case("use-before-admission-uncounted", "USED-POSITIVE", p1_preadmission(0))
        case("use-before-admission-but-admitted-first", "USED-POSITIVE", p1_preadmission(1, admitted_early=True))

        # Review L-4: a pre-admission image prefers a before_admission row,
        # so the no_live_caller rows stay for the short-lived images.
        def preadmission_and_short_lived(s, d, dash):
            drop(s, d, "P4")
            kw = p1_preadmission(1)(s, d, dash)
            ev = kw["events"]
            marker = next(e for e in ev if e["kind"] == "pass_committed")["event"]
            marker["unbound_rows"] = [{"module": s.mid["A"], "reason": "no_live_caller", "rows": 2},
                                      {"module": s.mid["A"], "reason": "before_admission", "rows": 1}]
            return kw
        case("preadmission-prefers-its-own-reason", None, preadmission_and_short_lived)

        # A native run whose every edge reads unknown (lifecycle loss, use
        # before admission) is still the native lane: it states it, and its
        # reasons are native-only.
        def all_unknown(stated, reason):
            def mutate(s, d, dash):
                for e in d["edges"]:
                    e["entries"]["coverage"].update(state="unknown", since_ns=None, until_ns=None, first_ns=None,
                                                    lossy=None, reason=reason, detail=None)
                    e["entries"].update(count=0, first_seen_ns=None, last_seen_ns=None,
                                        observation="unknown (usage observation unavailable)")
                    e.update(semantics="unknown (semantic capture withheld)", mechanisms=None, operations=None)
                d["observation"]["usage_feed"] = False
                for c in d["callers"]:
                    c["image"]["authority"] = "scan_pinned"
                if stated:
                    d["observation"]["lane"] = stated
            return mutate

        def lane_row(res):
            return next((r for r in res.rows if r["run"] == "system" and r["check"] == "LANE"), {})
        for name, stated, reason, want in (("all-unknown-stated-native", "native", "not_admitted", "pass"),
                                           ("all-unknown-loss-unstated", None, "loss", "pass"),
                                           ("all-unknown-uncounted-unstated", None, "uncounted", "pass"),
                                           ("all-unknown-scan-only-unstated", None, "scan_only", "fail"),
                                           ("stated-native-with-scan-only-edges", "native", "scan_only", "fail")):
            counter[0] += 1
            synth = Synth("native", None)
            doc, dash = _deep(synth.doc), _deep(synth.dash_doc)
            all_unknown(stated, reason)(synth, doc, dash)
            res = oracle(synth.write(os.path.join(tmp, f"{counter[0]:02d}-{name}"), doc=doc, dash_doc=dash))
            ok = lane_row(res).get("status") == want
            print(f"self-test {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": LANE {lane_row(res)}"))
            if not ok:
                failures.append(name)

        def exec_cross(s, d, dash):
            g0, g1 = _edge(d, cid(s, "P5", 0), s.mid["A"]), _edge(d, cid(s, "P5", 1), s.mid["A"])
            g1["entries"]["first_seen_ns"] = g0["entries"]["first_seen_ns"]
        case("exec-cross-attribution", "NO-CROSS-ATTRIBUTION", exec_cross)
        case("watched-on-used", "USED-NOT-WATCHED", lambda s, d, dash: _edge(d, cid(s, "P2"), s.mid["B"])["entries"]
             ["coverage"].update(state=WATCH_STATE, since_ns=T0, first_ns=None, lossy=None))

        def cross(s, d, dash):
            e = _deep(_edge(d, cid(s, "P2"), s.mid["B"]))
            e["caller"] = cid(s, "P1")
            d["edges"].append(e)
        case("cross-provider", "NO-CROSS-ATTRIBUTION", cross)
        case("p3-used", "IDLE-NOT-POSITIVE", lambda s, d, dash: _edge(d, cid(s, "P3"), s.mid["C"])["entries"]
             ["coverage"].update(state="witnessed", first_ns=T0 + 5, since_ns=None))

        def foreign(s, d, dash):
            d["callers"].append(s.caller("c999", 99999, 1, 0, "/usr/bin/x", True, "mapped", T0, s.run_end, False))
            for role in ("B", "C"):
                e = _deep(_edge(d, cid(s, "P2"), s.mid["B"]))
                e.update(caller="c999", module=s.mid[role])
                d["edges"].append(e)
            return {"events": s.events(d, True)}
        case("foreign-positive-private", "FOREIGN-POSITIVE", foreign)
        case("never-called-positive", "NEVER-CALLED-POSITIVE", foreign)
        # --- coverage / semantics -------------------------------------------------------
        def semantics_b(s, d, dash):
            e = _edge(d, cid(s, "P2"), s.mid["B"])
            e["semantics"] = "partial"
        case("unattested-semantics-label", "SEMANTICS-WITHHELD", semantics_b)
        case("count-outside-window", "COUNT-WINDOW",
             lambda s, d, dash: _edge(d, cid(s, "P1"), s.mid["A"])["entries"].update(count=10_000))

        def lossy(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"]["count"] = 1
            e["entries"]["coverage"]["lossy"] = True
        case("lossy-without-loss-gap", "COUNT-LOSSY", lossy)
        case("attested-only-witnessed", "COVERAGE-ALLOWED", lambda s, d, dash: _edge(d, cid(s, "P1"), s.mid["A"])
             ["entries"]["coverage"].update(state="witnessed", first_ns=_edge(d, cid(s, "P1"), s.mid["A"])
                                            ["entries"]["first_seen_ns"], since_ns=None, lossy=None))

        def no_cov(s, d, dash):
            for e in d["edges"]:
                del e["entries"]["coverage"]
        case("coverage-key-missing", "COVERAGE-SHAPE", no_cov)

        def six_keys(s, d, dash):
            for e in d["edges"]:
                del e["entries"]["coverage"]["until_ns"]
        case("coverage-six-keys-pre-c3", "COVERAGE-SHAPE", six_keys)

        def until_before_since(s, d, dash):
            cov = _edge(d, cid(s, "P3"), s.mid["C"])["entries"]["coverage"]
            cov["until_ns"] = cov["since_ns"]
        case("coverage-until-not-after-since", "COVERAGE-SHAPE", until_before_since)

        def watch_ending_before_use(until_offset):
            def mutate(s, d, dash):
                e = _edge(d, cid(s, "P2"), s.mid["B"])
                first = positive_first_ns(e)
                until = None if until_offset is None else first + until_offset
                e["entries"]["coverage"].update(state=WATCH_STATE, since_ns=T0, until_ns=until, first_ns=None,
                                                lossy=None)
            return mutate
        # A frozen watch that ended before the ledgered use claims nothing about it ...
        res = case("watch-until-before-use", "USED-POSITIVE", watch_ending_before_use(-50 * MS))
        if any(r["check"] == "USED-NOT-WATCHED" and r["status"] == "fail" for r in res.rows):
            failures.append("watch-until-before-use-judged-past-until")
        # ... while the same watch reaching over the use is a false "no use".
        case("watch-until-after-use", "USED-NOT-WATCHED", watch_ending_before_use(+50 * MS))

        # C5.2 M-2: a frozen watch (until_ns set: capture stop, or a custody loss
        # before it) is a fact about since..until, so it renders `watch ended`,
        # never `armed`.
        def freeze(doc, caller, module):
            cov = _edge(doc, caller, module)["entries"]["coverage"]
            cov["until_ns"] = cov["since_ns"] + 10 * MS

        def frozen_ended(s, d, dash):
            freeze(d, cid(s, "P3"), s.mid["C"])
            freeze(dash, s.dash_ids["P3"], s.mid["C"])
        res = case("frozen-watch-capture-ended", None, frozen_ended)
        if not any(r["check"] == "AGREE-EDGE-EVENTS" and r["status"] == "pass" for r in res.rows):
            failures.append("frozen-watch-edge-events-not-compared")

        def frozen_armed_event(s, d, dash):
            freeze(d, cid(s, "P3"), s.mid["C"])
            ev = s.events(d, True)
            for row in ev:
                if row["kind"] == "edge_observed" and row["event"]["entries"]["coverage"].get("until_ns"):
                    row["event"]["capture"] = CAPTURE["armed"]
            return {"events": ev}
        case("frozen-watch-event-armed", "AGREE-EDGE-EVENTS", frozen_armed_event)

        def frozen_armed_frame(s, d, dash):
            freeze(dash, s.dash_ids["P3"], s.mid["C"])
            frames = s.frames(dash)
            ended = f"capture {expected_capture({}, {}, _edge(dash, s.dash_ids['P3'], s.mid['C']))} |".encode()
            return {"frames": frames.replace(ended, f"capture {CAPTURE['armed']} |".encode())}
        case("frozen-watch-frame-armed", "DASH-EDGE-LABELS", frozen_armed_frame)

        # C5.2 review fix 2: a frozen watch is never quiet now, and its zero is
        # no current fact (`?`); the interval survives in entries.coverage.
        def frozen_frame_claims(old_item):
            def mutate(s, d, dash):
                freeze(dash, s.dash_ids["P3"], s.mid["C"])
                edge = _edge(dash, s.dash_ids["P3"], s.mid["C"])
                frames = s.frames(dash)
                item, value = old_item
                now = {"activity": expected_activity_base(edge),
                       "entries": expected_entries_display(edge)}
                items = f"capture {expected_capture({}, {}, edge)} | activity {now['activity']} | " \
                        f"entries {now['entries']} |"
                assert items.encode() in frames
                claimed = items.replace(f"{item} {now[item]} |", f"{item} {value} |")
                return {"frames": frames.replace(items.encode(), claimed.encode())}
            return mutate
        case("frozen-watch-frame-quiet", "DASH-EDGE-LABELS", frozen_frame_claims(("activity", ACTIVITY["quiet"])))
        case("frozen-watch-frame-zero", "DASH-EDGE-LABELS", frozen_frame_claims(("entries", "0")))

        # A frame rendered before the stop that froze the watches: the
        # snapshot is frozen, the frame shows the then-ongoing watches as
        # armed/quiet/0, and the stream carries the ongoing records before
        # the frame's pass marker plus the frozen sweep after it. The frame
        # is compared with the edge state at its own pass, so this passes;
        # without the as-of rule it fails DASH-EDGE-LABELS on every edge.
        def dash_frame_before_freeze(s, d, dash):
            live = _deep(dash)
            for e in dash["edges"]:
                cov = e["entries"]["coverage"]
                cov["until_ns"] = cov["since_ns"] + 10 * MS
            ev = s.events(live)
            frozen = [r for r in s.events(dash) if r["kind"] == "edge_observed"]
            at = next(i for i, r in enumerate(ev) if r["kind"] == "ended")
            out = [dict(r, seq=i) for i, r in enumerate(ev[:at] + frozen + ev[at:])]
            next(e for e in out if e["kind"] == "ended")["event"]["edge_events"] = len(frozen)
            return {"frames": s.frames(live), "dash_events": out}
        case("dashboard-frame-before-freeze", None, dash_frame_before_freeze)

        # DR-LIVE-LABEL-LAG: a frame rendered while a first-use row was
        # pending shows the then-unknown edge as `coverage lost` /
        # `unknown` / `?`, and the stream carries the pending record
        # before the frame's pass marker plus the decided sweep after it.
        # The fixed read passes; a frame that claims quiet/0 over the
        # pending row — the pre-fix product read — fails DASH-EDGE-LABELS.
        def dash_frame_pending_unknown(s, d, dash):
            live = _deep(dash)
            pending = _edge(live, s.dash_ids["P1"], s.mid["A"])
            pending["entries"]["coverage"].update(
                state=UNKNOWN_STATE, since_ns=None, reason=PENDING_FIRST_USE_REASON)
            pending["entries"]["observation"] = "unknown (usage observation unavailable)"
            ev = s.events(live)
            decided = [r for r in s.events(dash) if r["kind"] == "edge_observed"]
            at = next(i for i, r in enumerate(ev) if r["kind"] == "ended")
            out = [dict(r, seq=i) for i, r in enumerate(ev[:at] + decided + ev[at:])]
            next(e for e in out if e["kind"] == "ended")["event"]["edge_events"] = len(decided)
            return {"frames": s.frames(live), "dash_events": out}
        case("dashboard-frame-pending-unknown", None, dash_frame_pending_unknown)

        def dash_frame_quiet_over_pending(s, d, dash):
            return dict(dash_frame_pending_unknown(s, d, dash), frames=s.frames(dash))
        case("dashboard-frame-quiet-over-pending", "DASH-EDGE-LABELS", dash_frame_quiet_over_pending)

        def frozen_quiet_event(s, d, dash):
            freeze(d, cid(s, "P3"), s.mid["C"])
            ev = s.events(d, True)
            for row in ev:
                if row["kind"] == "edge_observed" and row["event"]["entries"]["coverage"].get("until_ns"):
                    row["event"]["activity"] = ACTIVITY["quiet"]
            return {"events": ev}
        case("frozen-watch-event-quiet", "EDGE-ACTIVITY", frozen_quiet_event)

        def empty(s, d, dash):
            d["callers"], d["edges"], d["modules"] = [], [], []
        case("empty-document", "PROV-RESOLVE", empty)
        case("empty-document-scan", "PROV-RESOLVE", empty, lane="scan")

        def merged_copies(s, d, dash):
            for m in d["modules"]:
                if m["id"] == s.mid["B"]:
                    m["identity"]["inode"] = s.providers["A"]["ino"]
                    m["paths"] = [s.providers["A"]["path"]]
        case("copies-merged", "PROV-RESOLVE", merged_copies)
        # --- stream agreement --------------------------------------------------------------
        def gaps(s, d, dash):
            return {"events": [e for e in s.events(d, True) if e["kind"] != "gap_recorded"]}
        case("jsonl-gap-mismatch", "AGREE-GAPS", gaps)

        def repeats_mismatch(s, d, dash):
            d["gaps"][0]["repeats"] = 3  # snapshot says 3; the stream carries no gap_repeated
            return {"events": s.events(dict(d, gaps=[dict(g, repeats=1) for g in d["gaps"]]), True)}
        case("jsonl-gap-repeats-mismatch", "AGREE-GAPS", repeats_mismatch)

        def gap_repeats_replay(s, d, dash):
            d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": None,
                              "subject": "second", "reason": "x", "budget": None, "repeats": 5})
            d["gaps"][0]["repeats"] = 3
        case("jsonl-gap-repeats-replay-positive", None, gap_repeats_replay)

        def _renumber(rows):
            return [dict(r, seq=i) for i, r in enumerate(rows)]

        def repeats_bad_index(s, d, dash):
            d["gaps"][0]["repeats"] = 3
            rows = s.events(d, True)
            for r in rows:
                if r["kind"] == "gap_repeated":
                    r["event"]["index"] = 99
            return {"events": rows}
        case("jsonl-gap-repeated-bad-index", "AGREE-GAPS", repeats_bad_index)

        def repeats_out_of_order(s, d, dash):
            d["gaps"][0]["repeats"] = 3
            rows = s.events(d, True)
            at = next(i for i, r in enumerate(rows) if r["kind"] == "gap_repeated")
            first = next(i for i, r in enumerate(rows) if r["kind"] == "gap_recorded")
            rows.insert(first, rows.pop(at))
            return {"events": _renumber(rows)}
        case("jsonl-gap-repeated-before-recorded", "AGREE-GAPS", repeats_out_of_order)

        def callers_mismatch(s, d, dash):
            return {"events": [e for e in s.events(d, True)
                               if not (e["kind"] == "caller_event" and e["event"]["caller"] == "c0")]}
        case("jsonl-callers-mismatch", "AGREE-CALLERS", callers_mismatch)

        def totals(s, d, dash):
            ev = s.events(d, True)
            next(e for e in ev if e["kind"] == "pass_committed")["event"]["totals"]["edges"] += 1
            return {"events": ev}
        case("jsonl-totals-mismatch", "AGREE-TOTALS", totals)

        def budgets(s, d, dash):
            ev = s.events(d, True)
            ev[-1]["event"]["budgets"] = {"callers": {"limit": 1}}
            return {"events": ev}
        case("jsonl-budgets-mismatch", "AGREE-BUDGETS", budgets)

        def edge_event(s, d, dash):
            ev = s.events(d, True)
            row = next(e for e in ev if e["kind"] == "edge_observed")
            row["event"]["entries"]["count"] += 5
            return {"events": ev}
        case("jsonl-edge-event-mismatch", "AGREE-EDGE-EVENTS", edge_event)

        def _edge_rows(ev):
            return [i for i, e in enumerate(ev) if e["kind"] == "edge_observed"]

        def _account(ev, extra):
            next(e for e in ev if e["kind"] == "pass_committed")["event"]["edge_events"] += extra
            return _renumber(ev)

        def edge_missing(s, d, dash):
            ev = s.events(d, True)
            ev.pop(_edge_rows(ev)[-1])
            return {"events": _account(ev, -1)}
        case("jsonl-edge-event-missing", "AGREE-EDGE-EVENTS", edge_missing)

        def edge_stale_then_exact(s, d, dash):
            ev = s.events(d, True)
            at = _edge_rows(ev)[0]
            stale = _deep(ev[at])
            stale["event"]["mapping"]["last_seen_ns"] -= 1
            stale["event"]["capture"] = CAPTURE["lost"]
            ev.insert(at, stale)
            return {"events": _account(ev, 1)}
        case("jsonl-edge-event-replay-positive", None, edge_stale_then_exact)

        def edge_stale_last(s, d, dash):
            ev = s.events(d, True)
            ev[_edge_rows(ev)[0]]["event"]["mapping"]["last_seen_ns"] -= 1
            return {"events": ev}
        case("jsonl-edge-event-stale-instant", "AGREE-EDGE-EVENTS", edge_stale_last)

        def edge_unaccounted(s, d, dash):
            ev = s.events(d, True)
            ev[-1]["event"]["edge_events"] = 1
            return {"events": ev}
        case("jsonl-edge-event-accounting", "AGREE-EDGE-EVENTS", edge_unaccounted)

        def edge_presence(s, d, dash):
            ev = s.events(d, True)
            ev[_edge_rows(ev)[0]]["event"]["presence"] = "attached"
            return {"events": ev}
        case("jsonl-edge-event-presence", "AGREE-EDGE-EVENTS", edge_presence)

        # Presence derivation, every branch and its precedence (Presence::for_edge).
        live = {"mapping": {"state": MAPPING_LIVE}}
        for caller_lc, module_lc, edge, want in (
                ("mapped", "mapped", live, "mapped"),
                ("exited", "unloaded", live, "process exited"),
                ("exec_retired", "unloaded", live, "unloaded"),
                ("mapped", "unloaded", live, "unloaded"),
                ("mapped", "mapped", {"mapping": {"state": "uncertain"}}, "unknown"),
                ("exec_retired", "mapped", live, "unknown"),
                ("mapped", "unknown", live, "unknown")):
            got = expected_presence({"lifecycle": caller_lc}, {"lifecycle": module_lc}, edge)
            if got != want:
                failures.append(f"presence-{caller_lc}-{module_lc}-{edge['mapping']['state']}")

        # Uncounted derivations (C4: they fall out of the Unknown mapping).
        def _counted(last):
            return {"mapping": {"state": MAPPING_LIVE}, "operations": None,
                    "entries": {"count": 5, "last_seen_ns": last, "in_flight": False, "observation": "observed",
                                "coverage": {"state": "counted", "since_ns": T0, "until_ns": None, "first_ns": None,
                                             "lossy": False, "reason": None, "detail": None}}}

        # (Choice 3 re-ruled: activity is per-pass; the window survives
        # only in the dashboard display, which self-test frames cover.)
        unc = _counted(None)
        unc["entries"].update(count=0, observation="unknown (usage observation unavailable)")
        unc["entries"]["coverage"].update(state=UNKNOWN_STATE, reason=UNCOUNTED_REASON,
                                          detail="CALLER_EVIDENCE[2] PairInsertFailure showed 1 failed pair insert(s)")
        endpoints = ({"retired": False, "lifecycle": "mapped"},
                     {"admission": {"state": "admitted"}, "lifecycle": "mapped"})
        if expected_capture(*endpoints, unc) != CAPTURE["lost"]:
            failures.append("uncounted-capture-derivation")
        if expected_activity_base(unc) != ACTIVITY["uncovered"]:
            failures.append("uncounted-activity-derivation")
        if expected_entries_display(unc) != "?":
            failures.append("uncounted-entries-derivation")
        # Bucket boundaries (EdgeClass): 0, 1, 2-3, 4-7, 8-15, ...
        for count, want in ((0, 0), (1, 1), (2, 2), (3, 2), (4, 3), (7, 3), (8, 4), (37, 6)):
            if count_bucket(count) != want:
                failures.append(f"bucket-{count}")

        def edge_presence_wrong_label(s, d, dash):
            ev = s.events(d, True)
            row = ev[_edge_rows(ev)[0]]["event"]
            row["presence"] = PRESENCE["unloaded"] if row["presence"] == PRESENCE["mapped"] else PRESENCE["mapped"]
            return {"events": ev}
        case("jsonl-edge-event-presence-wrong-label", "AGREE-EDGE-EVENTS", edge_presence_wrong_label)

        def split_markers(at_rows, first_count, last_count):
            """Insert an earlier pass marker after `at_rows` edge records,
            stating `first_count`; the real marker then states `last_count`."""
            def mutate(s, d, dash):
                ev = s.events(d, True)
                rows = _edge_rows(ev)
                real = next(e for e in ev if e["kind"] == "pass_committed")
                early = _deep(real)
                early["event"].update({"pass": real["event"]["pass"] - 1, "new_gaps": 0, "suppressed_delta": 0,
                                       "edge_events": first_count, "edge_events_deferred": 0})
                real["event"]["edge_events"] = last_count
                ev.insert(rows[at_rows - 1] + 1, early)
                return {"events": _renumber(ev)}
            return mutate
        n_edges = len(Synth("native", None).doc["edges"])
        case("jsonl-edge-event-split-positive", None, split_markers(2, 2, n_edges - 2))
        case("jsonl-edge-event-split-swapped", "AGREE-EDGE-EVENTS", split_markers(2, n_edges - 2, 2))

        def deferred(value):
            def mutate(s, d, dash):
                ev = s.events(d, True)
                next(e for e in ev if e["kind"] == "pass_committed")["event"]["edge_events_deferred"] = value
                return {"events": ev}
            return mutate
        case("jsonl-edge-event-deferred-too-large", "AGREE-EDGE-EVENTS", deferred(12345))
        case("jsonl-edge-event-deferred-negative", "AGREE-EDGE-EVENTS", deferred(-1))
        case("jsonl-edge-event-deferred-missing", "AGREE-EDGE-EVENTS", deferred(None))

        def unretained(s, d, dash):
            ev = s.events(d, True)
            ev[-1]["event"]["edges_unretained"] = 3
            return {"events": ev}
        case("jsonl-edge-event-unretained", "AGREE-EDGE-EVENTS", unretained)

        def rotation(s, d, dash):
            ev = s.events(d, True, extra=[("rotated", {"prior_file": "x.jsonl.1", "prior_events": 3,
                                                       "prior_bytes": 9, "rotation_seq": 1})])
            return {"events": ev}
        case("jsonl-rotated", "STREAM-ROTATED", rotation)
        # --- runs and manifest ----------------------------------------------------------------
        case("no-runs", "RUNS-COMPLETE", lambda s, d, dash: {"manifest_edit": lambda m: m.update(runs=[])})
        case("system-run-missing", "RUNS-COMPLETE", lambda s, d, dash: {
            "manifest_edit": lambda m: m.update(runs=[r for r in m["runs"] if r["name"] != "system"])})
        case("system-run-only-P1", "RUNS-COMPLETE", lambda s, d, dash: {
            "manifest_edit": lambda m: m["runs"][0].update(cells=["P1"])})

        def skip_dash(m):
            m["runs"] = [r for r in m["runs"] if r["name"] != "dashboard"]
            m["skipped_runs"] = ["dashboard"]
        case("dashboard-skipped", EXIT["nonqualifying"], lambda s, d, dash: {"manifest_edit": skip_dash})
        case("window-unsettled", "WINDOW-SETTLED", lambda s, d, dash: {"settle": 1})
        case("native-absent", "LANE", lane="scan", expect="native")
        case("scan-claims-usage", "LANE", lane="native", expect="scan")
        # --- stop / settlement ------------------------------------------------------------------
        case("held-stop-settled", "STOP-SETTLEMENT", lambda s, d, dash: {"stop_doc": s.stop_doc("settled")})
        case("held-stop-unstated", "STOP-SETTLEMENT", lambda s, d, dash: {"stop_doc": s.stop_doc(None)})

        def settlement_object(verdict):
            def mutate(s, d, dash):
                sd = s.stop_doc(None)
                sd["observation"]["retirement"] = verdict
                return {"stop_doc": sd}
            return mutate
        case("held-stop-object-unsettled", None, settlement_object({"state": "unsettled", "reason": "deadline"}))
        case("held-stop-object-settled", "STOP-SETTLEMENT", settlement_object({"state": "settled"}))
        case("held-stop-object-unknown-shape", "STOP-SETTLEMENT", settlement_object({"foo": 1}))
        case("held-stop-list-shape", "STOP-SETTLEMENT", settlement_object(["unsettled"]))
        # DR-C5-EDGE: a stream without edge_observed records now fails.
        case("stream-without-edge-events", "AGREE-EDGE-EVENTS", lambda s, d, dash: {"edge_events": False})

        def released_early(s, d, dash):
            s.stop_sent = s.held_t + 3000 * MS
            led = dict(s.ledgers)
            led["P6"] = led["P6"] + f"RETURNED {s.held_head} fn=C_WaitForSlotEvent t={s.held_t + MS} rv=0x0\n"
            return {"ledgers": led}
        case("held-call-released-before-sigint", "STOP-HELD-AT-SIGINT", released_early)
        # --- dashboard ----------------------------------------------------------------------------
        case("dashboard-p3-used", "DASH-EDGE-LABELS", lambda s, d, dash: {
            "frames": s.frames(dash, {(s.dash_ids["P3"], s.mid["C"]): ACTIVITY["used"]})})

        def dash_hidden(s, d, dash):
            shown = _deep(dash)
            shown["edges"] = [e for e in shown["edges"] if e["caller"] != s.dash_ids["P2"]]
            return {"frames": s.frames(shown).replace(
                f"{len(shown['edges'])} edges".encode(), f"{len(dash['edges'])} edges".encode())}
        case("dashboard-edge-hidden", "DASH-VISIBLE", dash_hidden)

        def dash_totals(s, d, dash):
            return {"frames": s.frames(dash).replace(b" callers ", b"0 callers ")}
        case("dashboard-totals", "DASH-TOTALS", dash_totals)
        # --- C5: ledger exactness + Choice 1-2 pins ---------------------------------------
        # r1 T3.5 must-fails: a count above the ledger, a published 0,
        # absent-as-0 (P1), counted-on-preadmission (P2).
        def above_ledger(s, d, dash):
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"] += 1
        res = case("count-above-ledger", "COUNT-EXACT", above_ledger)
        failed = {r["check"] for r in res.failed()}
        if "COUNT-TOTAL" not in failed:
            failures.append("count-above-ledger-misses-total")
        if "COUNT-WINDOW" not in failed:
            # Round 2: no dlsym slack remains — the predating
            # acquisition counts, so +1 above the ledger fails the
            # now-tight window too.
            failures.append("count-above-ledger-misses-window")

        def zero_published(s, d, dash):
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"] = 0
        case("zero-count-published", "COUNTED-NONZERO", zero_published)

        def absent_zero_p1(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"]["coverage"].update(state=WATCH_STATE, since_ns=T0, until_ns=None, first_ns=None,
                                                lossy=None)
            e["entries"].update(count=0, first_seen_ns=None, last_seen_ns=None, observation="observed")
        case("absent-as-zero-p1", "USED-NOT-WATCHED", absent_zero_p1)

        def preadmission_p2(s, d, dash):
            # The ROW predates admission (admitted after the first
            # attach-side entry, row stamped between the entry and the
            # admission): a bound positive over it is the
            # DR-C51-PREADMIT upgrade, which v0.3.0 does not build.
            first = min(u[0] for c, _p, _st, _g, _e, _sp, uses in s.images if c == "P2" for u in uses.values())
            attach_t0 = first + 3 * MS  # setup lines run 3 ms apart: dlsym, then C_Initialize
            caller = next(c for c in d["callers"] if c["id"] == cid(s, "P2"))
            caller["first_seen_ns"] = attach_t0 + MS
            edge = _edge(d, cid(s, "P2"), s.mid["B"])
            edge["entries"]["first_seen_ns"] = attach_t0 + MS // 2
            edge["entries"]["coverage"]["since_ns"] = attach_t0 + MS // 2
        case("counted-on-preadmission-p2", "PREADMISSION-POSITIVE", preadmission_p2)

        # Counted for unattested B: a witnessed P2 edge fails like P1's.
        def unattested_witnessed(s, d, dash):
            e = _edge(d, cid(s, "P2"), s.mid["B"])
            e["entries"]["coverage"].update(state="witnessed", first_ns=e["entries"]["first_seen_ns"],
                                            since_ns=None, lossy=None)
        case("unattested-witnessed", "COVERAGE-ALLOWED", unattested_witnessed)

        # Choice 1: uncounted needs the BPF PairInsertFailure evidence.
        def uncounted_edge(s, d):
            e = _edge(d, cid(s, "P3"), s.mid["C"])
            e["entries"]["coverage"].update(
                state=UNKNOWN_STATE, since_ns=None, reason=UNCOUNTED_REASON,
                detail="CALLER_EVIDENCE[2] PairInsertFailure showed 1 failed pair insert(s)")
            e["entries"]["observation"] = "unknown (usage observation unavailable)"

        def uncounted_no_gap(s, d, dash):
            uncounted_edge(s, d)
        case("uncounted-without-pair-evidence", "UNCOUNTED-EVIDENCE", uncounted_no_gap)

        def uncounted_bad_detail(s, d, dash):
            uncounted_edge(s, d)
            _edge(d, cid(s, "P3"), s.mid["C"])["entries"]["coverage"]["detail"] = \
                "userspace pair budget exhausted"
            d["gaps"].append({"caller": None, "module": s.mid["C"], "pid": None,
                              "subject": PAIRS_UNCOUNTED_SUBJECT, "reason": "synthetic", "budget": None,
                              "repeats": 1})
        case("uncounted-detail-without-bpf-name", "UNCOUNTED-EVIDENCE", uncounted_bad_detail)

        def uncounted_count(s, d, dash):
            uncounted_edge(s, d)
            _edge(d, cid(s, "P3"), s.mid["C"])["entries"].update(count=3, observation="observed")
            d["gaps"].append({"caller": None, "module": s.mid["C"], "pid": None,
                              "subject": PAIRS_UNCOUNTED_SUBJECT, "reason": "synthetic", "budget": None,
                              "repeats": 1})
        case("uncounted-with-count", "UNCOUNTED-EVIDENCE", uncounted_count)

        def uncounted_pass(s, d, dash):
            uncounted_edge(s, d)
            d["gaps"].append({"caller": None, "module": s.mid["C"], "pid": None,
                              "subject": PAIRS_UNCOUNTED_SUBJECT, "reason": "synthetic", "budget": None,
                              "repeats": 1})
        res = case("uncounted-pass-with-counted-standing", None, uncounted_pass)
        if not any(r["check"] == "UNCOUNTED-EVIDENCE" and r["status"] == "pass" for r in res.rows):
            failures.append("uncounted-pass-exercises-evidence")

        def uncounted_record(s, d):
            uncounted_edge(s, d)
            d["gaps"].append({"caller": None, "module": s.mid["C"], "pid": None,
                              "subject": PAIRS_UNCOUNTED_SUBJECT, "reason": "synthetic", "budget": None,
                              "repeats": 1})
            ev = s.events(d)
            return ev, next(e for e in ev if e["kind"] == "edge_observed"
                            and e["event"]["caller"] == cid(s, "P3") and e["event"]["module"] == s.mid["C"])

        def uncounted_activity(s, d, dash):
            ev, row = uncounted_record(s, d)
            assert row["event"]["activity"] == ACTIVITY["uncovered"], row["event"]
            row["event"]["activity"] = ACTIVITY["unknown"]
            return {"events": ev}
        case("uncounted-activity-unknown", "EDGE-ACTIVITY", uncounted_activity)

        def uncounted_capture(s, d, dash):
            ev, row = uncounted_record(s, d)
            assert row["event"]["capture"] == CAPTURE["lost"], row["event"]
            row["event"]["capture"] = CAPTURE["armed"]
            return {"events": ev}
        case("uncounted-capture-armed", "AGREE-EDGE-EVENTS", uncounted_capture)

        # Choice 2: bucket jumps are immediate class changes; other drift
        # waits out the 10 s channel.
        def drift_stages(s, d, cell, stages):
            """Replace the cell's edge records with `stages` [(count,
            at_ns)] before the pass marker; fix accounting + seq."""
            cid_, mid = cid(s, cell), s.mid["A"]
            ev = s.events(d)
            template = [e for e in ev if e["kind"] == "edge_observed"
                        and e["event"].get("caller") == cid_ and e["event"].get("module") == mid][-1]
            keep = [e for e in ev if not (e["kind"] == "edge_observed"
                                          and e["event"].get("caller") == cid_
                                          and e["event"].get("module") == mid)]
            at = next(i for i, e in enumerate(keep) if e["kind"] == "pass_committed")
            new = []
            for count, at_ns in stages:
                rec = _deep(template)
                rec["event"]["entries"]["count"] = count
                rec["at_ns"] = at_ns
                new.append(rec)
            out = keep[:at] + new + keep[at:]
            next(e for e in out if e["kind"] == "pass_committed")["event"]["edge_events"] += len(new) - 1
            return {"events": _renumber(out)}

        def fast_drift(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            assert n >= 2 and count_bucket(n - 1) == count_bucket(n), n
            return drift_stages(s, d, "P1", [(n - 1, T0 + 500), (n, T0 + 500 + 1_000_000_000)])
        case("fast-drift-same-bucket", "EDGE-CADENCE", fast_drift)

        def bucket_jump(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            prev = (1 << (count_bucket(n) - 1)) - 1
            assert count_bucket(prev) != count_bucket(n), (prev, n)
            return drift_stages(s, d, "P1", [(prev, T0 + 500), (n, T0 + 500 + 1_000_000_000)])
        case("bucket-jump-fast-pass", None, bucket_jump)

        # Choice 3 (ACT re-rule): activity is per-pass ("rose since
        # previous pass"), never a recency window. An unchanged
        # consecutive record must read quiet; a rise allows recent or
        # quiet (the emission may lag the rising pass); counts never
        # decrease.
        def activity_stages(s, d, cell, stages):
            """Like drift_stages, but each stage is (count, at_ns,
            activity): the last stage must carry the snapshot count."""
            cid_, mid = cid(s, cell), s.mid["A"]
            ev = s.events(d)
            template = [e for e in ev if e["kind"] == "edge_observed"
                        and e["event"].get("caller") == cid_ and e["event"].get("module") == mid][-1]
            keep = [e for e in ev if not (e["kind"] == "edge_observed"
                                          and e["event"].get("caller") == cid_
                                          and e["event"].get("module") == mid)]
            at = next(i for i, e in enumerate(keep) if e["kind"] == "pass_committed")
            new = []
            for count, at_ns, activity in stages:
                rec = _deep(template)
                rec["event"]["entries"]["count"] = count
                rec["event"]["activity"] = activity
                rec["at_ns"] = at_ns
                new.append(rec)
            out = keep[:at] + new + keep[at:]
            next(e for e in out if e["kind"] == "pass_committed")["event"]["edge_events"] += len(new) - 1
            return {"events": _renumber(out)}

        def rise_then_quiet(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            assert n >= 2, n
            # The rise flips quiet->recent (a class change, cadence-free);
            # the cadence re-emission 10 s later reads quiet.
            return activity_stages(s, d, "P1", [(n - 1, T0 + 500, ACTIVITY["quiet"]),
                                                (n, T0 + 600, ACTIVITY["recent"]),
                                                (n, T0 + 700 + COUNT_EMIT_INTERVAL_NS, ACTIVITY["quiet"])])
        case("per-pass-rise-then-quiet", None, rise_then_quiet)

        def fresh_last_seen(s, d):
            # In-window at the run end, so the old window rule allows
            # recent and only the per-pass pin can catch the echo.
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["last_seen_ns"] = \
                d["observation"]["ended_ns"] - 1_000

        def window_echo(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            assert n >= 2, n
            fresh_last_seen(s, d)
            return activity_stages(s, d, "P1", [(n - 1, T0 + 500, ACTIVITY["quiet"]),
                                                (n, T0 + 600, ACTIVITY["recent"]),
                                                (n, T0 + 700 + COUNT_EMIT_INTERVAL_NS, ACTIVITY["recent"])])
        case("per-pass-window-echo-fails", "EDGE-ACTIVITY", window_echo)

        def count_falls(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            assert n >= 2, n
            # A decrease mid-stream (each pair 10 s apart, cadence-free);
            # the last record still carries the snapshot count.
            fresh_last_seen(s, d)
            return activity_stages(s, d, "P1", [(n, T0 + 500, ACTIVITY["recent"]),
                                                (n - 1, T0 + 600 + COUNT_EMIT_INTERVAL_NS, ACTIVITY["quiet"]),
                                                (n, T0 + 700 + 2 * COUNT_EMIT_INTERVAL_NS, ACTIVITY["recent"])])
        case("per-pass-count-decreases-fails", "EDGE-ACTIVITY", count_falls)

        # ACT precedence (fix round 1): production reads a fresh rise as
        # recent even over lossy coverage (a rise beats lossy), while
        # in-flight beats a rise (never recent over in_flight). The
        # oracle must match both directions.
        def make_lossy_p1(s, d):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"]["coverage"]["lossy"] = True
            d["gaps"].append({"caller": None, "module": None, "pid": None,
                              "subject": "native count refresh loss",
                              "reason": "1 count-refresh read failure: scripted",
                              "budget": None, "repeats": 1})

        def lossy_rise_recent(s, d, dash):
            make_lossy_p1(s, d)
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            return activity_stages(s, d, "P1", [(n - 1, T0 + 500, ACTIVITY["lossy"]),
                                                (n, T0 + 600, ACTIVITY["recent"])])
        case("per-pass-lossy-rise-recent-pass", None, lossy_rise_recent)

        def lossy_echo(s, d, dash):
            make_lossy_p1(s, d)
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            return activity_stages(s, d, "P1", [(n, T0 + 500, ACTIVITY["lossy"]),
                                                (n, T0 + 600 + COUNT_EMIT_INTERVAL_NS, ACTIVITY["recent"])])
        case("per-pass-lossy-unchanged-recent-fails", "EDGE-ACTIVITY", lossy_echo)

        def inflight_recent(s, d, dash):
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["in_flight"] = True
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            return activity_stages(s, d, "P1", [(n - 1, T0 + 500, ACTIVITY["inflight"]),
                                                (n, T0 + 600, ACTIVITY["recent"])])
        case("per-pass-inflight-recent-fails", "EDGE-ACTIVITY", inflight_recent)

        def inflight_over_rise(s, d, dash):
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["in_flight"] = True
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            # Same bucket, same activity: the re-emission rides the 10 s
            # count channel, like production's within-bucket drift.
            return activity_stages(s, d, "P1", [(n - 1, T0 + 500, ACTIVITY["inflight"]),
                                                (n, T0 + 600 + COUNT_EMIT_INTERVAL_NS,
                                                 ACTIVITY["inflight"])])
        case("per-pass-inflight-over-rise-pass", None, inflight_over_rise)

        # ACT proven comparison (fix round 1): consecutive pass segments
        # with zero deferred records prove what each pass saw — a rise
        # across them must read recent (the reviewer's 17 -> 37
        # quiet-quiet instance). One segment per record; both markers
        # carry deferred 0.
        def two_pass_activity(s, d, cell, first, second):
            """Adjacent single-record pass segments: `first`/`second`
            are (count, at_ns, activity); the last stage must carry the
            snapshot count."""
            cid_, mid = cid(s, cell), s.mid["A"]
            ev = s.events(d)
            template = [e for e in ev if e["kind"] == "edge_observed"
                        and e["event"].get("caller") == cid_ and e["event"].get("module") == mid][-1]
            keep = [e for e in ev if not (e["kind"] == "edge_observed"
                                          and e["event"].get("caller") == cid_
                                          and e["event"].get("module") == mid)]
            at = next(i for i, e in enumerate(keep) if e["kind"] == "pass_committed")
            end = next(i for i, e in enumerate(keep) if e["kind"] == "ended")

            def rec(stage):
                count, at_ns, activity = stage
                rec = _deep(template)
                rec["event"]["entries"]["count"] = count
                rec["event"]["activity"] = activity
                rec["at_ns"] = at_ns
                return rec

            first_marker = _deep(keep[at])
            first_marker["event"]["pass"] -= 1
            second_marker = _deep(keep[at])
            second_marker["event"].update(edge_events=1, edge_events_deferred=0, new_gaps=0,
                                          suppressed_delta=0)
            out = keep[:at] + [rec(first)] + [first_marker] + [rec(second)] + [second_marker] + keep[end:]
            return {"events": _renumber(out)}

        def proven_quiet(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            prev = (1 << (count_bucket(n) - 1)) - 1
            assert count_bucket(prev) != count_bucket(n), (prev, n)
            return two_pass_activity(s, d, "P1", (prev, T0 + 500, ACTIVITY["quiet"]),
                                     (n, T0 + 600, ACTIVITY["quiet"]))
        case("per-pass-proven-rise-quiet-fails", "EDGE-ACTIVITY", proven_quiet)

        def proven_recent(s, d, dash):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            prev = (1 << (count_bucket(n) - 1)) - 1
            assert count_bucket(prev) != count_bucket(n), (prev, n)
            return two_pass_activity(s, d, "P1", (prev, T0 + 500, ACTIVITY["quiet"]),
                                     (n, T0 + 600, ACTIVITY["recent"]))
        case("per-pass-proven-rise-recent-pass", None, proven_recent)

        # C2 extension: the decided snapshot never carries pending_first_use.
        def pending_snapshot(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"]["coverage"].update(state=UNKNOWN_STATE, since_ns=None, reason=PENDING_FIRST_USE_REASON,
                                                lossy=None)
            e["entries"]["observation"] = "unknown (usage observation unavailable)"
        case("pending-in-snapshot", "PENDING-TRANSIENT", pending_snapshot)

        # --- O1: realistic since timing (sol 1, astra B1) -------------------
        # Native since_ns is the first BPF row's insert stamp, taken during
        # the recording call's probe — strictly after the workload's
        # pre-call ledger stamp — so since<=t_first never holds on real
        # runs. The recording call's realistic singleton line [t,t] lands
        # entirely before since; the old window drops it from lo AND hi
        # ([36,36] vs the correct 37) while COUNT-EXACT never engages (an
        # incorrect 36 passes everything).
        def realistic_since_ledger(s, d):
            """Collapse P1's first attach line (setup C_Initialize) to a
            realistic singleton [t,t] and stamp the first BPF record 1500
            ns (probe latency) after its entry."""
            led = dict(s.ledgers)
            pat = re.compile(r"(fn=C_Initialize mech=- n=1 bad=0 phase=setup t0=)(\d+)( t1=)\d+")
            assert len(pat.findall(led["P1"])) == 1
            match = pat.search(led["P1"])
            tick = int(match.group(2))
            led["P1"] = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(2)}",
                                led["P1"], count=1)
            since = tick + 1500
            edge = _edge(d, cid(s, "P1"), s.mid["A"])
            edge["entries"]["coverage"]["since_ns"] = since
            edge["entries"]["first_seen_ns"] = since
            # Mid-workload since: the setup acquisition missed (a legacy
            # line ends after it but before the row), so the edge drops
            # the synth's predating +1.
            edge["entries"]["count"] -= 1
            return {"ledgers": led}

        def realistic_timing(s, d, dash):
            return realistic_since_ledger(s, d)
        res = case("count-exact-realistic-timing", None, realistic_timing)
        if not any(r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"
                   and r["status"] == "pass" for r in res.rows):
            failures.append("count-exact-realistic-timing-misses-exact")

        def realistic_timing_short(s, d, dash):
            kw = realistic_since_ledger(s, d)
            _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"] -= 1
            return kw
        case("count-below-ledger-realistic-timing", "COUNT-EXACT", realistic_timing_short)

        # --- O1: covered-segment exactness (fix round 1, corrected round 2)
        # Setup-before-attachment: four setup calls precede attachment;
        # all 30 main + 3 teardown calls are captured. Admission lands
        # in the setup->main gap with the first row after it. The
        # recording call (on the last setup line) created the row, so
        # the correct count is 34 = 33 post-since calls + the recording
        # call; COUNT-EXACT is nonqualifying (entry stamps cannot prove
        # the recording call executed before attachment), and 33 or
        # fewer fails COUNT-WINDOW.
        def setup_before_attachment(s, d, count):
            login = re.search(r"fn=C_Login mech=- n=1 bad=0 phase=setup t0=\d+ t1=(\d+)",
                              s.ledgers["P1"])
            digest_init = re.search(r"fn=C_DigestInit mech=0x250 n=3 bad=0 phase=main t0=(\d+)",
                                    s.ledgers["P1"])
            setup_end, main_start = int(login.group(1)), int(digest_init.group(1))
            assert setup_end < main_start, (setup_end, main_start)
            admitted = setup_end + (main_start - setup_end) // 4
            since = setup_end + (main_start - setup_end) // 2
            caller = next(c for c in d["callers"] if c["id"] == cid(s, "P1"))
            caller["first_seen_ns"] = admitted
            edge = _edge(d, cid(s, "P1"), s.mid["A"])
            edge["entries"]["coverage"]["since_ns"] = since
            edge["entries"]["first_seen_ns"] = since
            edge["entries"]["count"] = count
            return since

        # The covered segment's correct count includes the recording
        # call (34 = 33 post-since calls + the call that created the
        # first row): the window keeps the recording-call bound, while
        # COUNT-EXACT is explicitly nonqualifying — entry stamps cannot
        # prove the recording call executed before attachment (round 2).
        def covered_segment_correct(s, d, dash):
            setup_before_attachment(s, d, 34)
        res = case("o1-covered-segment-counts-recording-call", None, covered_segment_correct)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-covered-segment-not-nonqualifying")

        # An undercount missing exactly the recording call (33) fails
        # the window's lower bound — it no longer passes as exact.
        def covered_segment_missing_recording(s, d, dash):
            setup_before_attachment(s, d, 33)
        case("o1-recording-call-missing-fails", "COUNT-WINDOW", covered_segment_missing_recording)

        def covered_segment_short(s, d, dash):
            setup_before_attachment(s, d, 32)
        case("o1-covered-segment-short-fails", "COUNT-WINDOW", covered_segment_short)

        # O1 partial attach: the module reports failed endpoints (verbatim
        # production shape — PARTIAL_ATTACH_SUBJECT in
        # src/discovery/inventory_coordinator.rs): counted uses are lower
        # bounds, so COUNT-EXACT is explicitly nonqualifying.
        def partial_attach_gap(s, d, dash):
            setup_before_attachment(s, d, 33)
            d["gaps"].append({"caller": None, "module": s.mid["A"], "pid": None,
                              "subject": "native endpoint attach failed",
                              "reason": "2 of 68 endpoints failed to attach (sticky, never retried); "
                                        "counted uses are lower bounds",
                              "budget": None, "repeats": 1})
        res = case("o1-partial-attach-nonqualifying", None, partial_attach_gap)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-partial-attach-not-nonqualifying")

        # O1 straddling first row (the reviewer's repro shape): the first
        # row lands inside an aggregated ledger line, so the recorded
        # split is unknowable — explicitly nonqualifying.
        def straddling_first_row(s, d, dash):
            login = re.search(r"fn=C_Login mech=- n=1 bad=0 phase=setup t0=\d+ t1=(\d+)",
                              s.ledgers["P1"])
            digest_init = re.search(
                r"fn=C_DigestInit mech=0x250 n=3 bad=0 phase=main t0=(\d+) t1=(\d+)", s.ledgers["P1"])
            setup_end = int(login.group(1))
            dt0, dt1 = int(digest_init.group(1)), int(digest_init.group(2))
            caller = next(c for c in d["callers"] if c["id"] == cid(s, "P1"))
            caller["first_seen_ns"] = setup_end + (dt0 - setup_end) // 2
            since = (dt0 + dt1) // 2
            edge = _edge(d, cid(s, "P1"), s.mid["A"])
            edge["entries"]["coverage"]["since_ns"] = since
            edge["entries"]["first_seen_ns"] = since
            edge["entries"]["count"] = 33
        res = case("o1-straddling-row-nonqualifying", None, straddling_first_row)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-straddling-row-not-nonqualifying")

        # O1 admission coverage: eleven distinct endpoints called in the
        # segment but only one admitted — some called endpoint missed, so
        # COUNT-EXACT is explicitly nonqualifying.
        def admitted_endpoints_short(s, d, dash):
            setup_before_attachment(s, d, 34)
            mod = next(m for m in d["modules"] if m["id"] == s.mid["A"])
            mod["admission"]["endpoints"] = 1
        res = case("o1-admission-coverage-nonqualifying", None, admitted_endpoints_short)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-admission-coverage-not-nonqualifying")

        # O1 evidence validation (round 2): a missing admission
        # endpoint count or mapping first-seen cannot prove endpoint
        # coverage or mapping hold — COUNT-EXACT is explicitly
        # nonqualifying, never exact on assumed evidence.
        def admission_endpoints_missing(s, d, dash):
            kw = realistic_since_ledger(s, d)
            mod = next(m for m in d["modules"] if m["id"] == s.mid["A"])
            mod["admission"]["endpoints"] = None
            return kw
        res = case("o1-admission-endpoints-missing-nonqualifying", None, admission_endpoints_missing)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-admission-endpoints-missing-not-nonqualifying")

        def mapping_first_seen_missing(s, d, dash):
            kw = realistic_since_ledger(s, d)
            _edge(d, cid(s, "P1"), s.mid["A"])["mapping"]["first_seen_ns"] = None
            return kw
        res = case("o1-mapping-first-seen-missing-nonqualifying", None, mapping_first_seen_missing)
        row = next((r for r in res.rows
                    if r["run"] == "system" and r["cell"] == "P1" and r["check"] == "COUNT-EXACT"), None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("o1-mapping-first-seen-missing-not-nonqualifying")

        # --- O2: terminal sweep hole (sol 2, astra B4) ----------------------
        # Every record after the last pass marker skips EDGE-CADENCE while
        # only the last record per edge must match the snapshot, so a tail
        # disagreeing with the snapshot passes everything.
        def tail_stages(s, d, cell, pre, post):
            """Replace the cell's edge records with `pre` [(count, at_ns)]
            records before the pass marker and `post` [(count, at_ns,
            mutate)] records after it (the terminal sweep); fix
            accounting + seq."""
            cid_, mid = cid(s, cell), s.mid["A"]
            ev = s.events(d)
            template = [e for e in ev if e["kind"] == "edge_observed"
                        and e["event"].get("caller") == cid_ and e["event"].get("module") == mid][-1]
            keep = [e for e in ev if not (e["kind"] == "edge_observed"
                                          and e["event"].get("caller") == cid_
                                          and e["event"].get("module") == mid)]
            at = next(i for i, e in enumerate(keep) if e["kind"] == "pass_committed")
            new_pre = []
            for count, at_ns in pre:
                rec = _deep(template)
                rec["event"]["entries"]["count"] = count
                rec["at_ns"] = at_ns
                new_pre.append(rec)
            new_post = []
            for count, at_ns, mutate in post:
                rec = _deep(template)
                rec["event"]["entries"]["count"] = count
                rec["at_ns"] = at_ns
                if mutate:
                    mutate(rec["event"])
                new_post.append(rec)
            end = next(i for i, e in enumerate(keep) if e["kind"] == "ended")
            out = keep[:at] + new_pre + keep[at:end] + new_post + keep[end:]
            next(e for e in out if e["kind"] == "pass_committed")["event"]["edge_events"] += len(new_pre) - 1
            next(e for e in out if e["kind"] == "ended")["event"]["edge_events"] = len(new_post)
            return {"events": _renumber(out)}

        def sweep_tail_disagreeing(s, d, dash):
            # sol probe: 35 before the marker, then 36->37 at the same
            # timestamp afterward; the first tail record disagrees.
            return tail_stages(s, d, "P1", [(35, T0 + 500)],
                               [(36, T0 + 600, None), (37, T0 + 600, None)])
        case("sweep-tail-disagreeing", "TERMINAL-SWEEP", sweep_tail_disagreeing)

        def sweep_tail_pending(s, d, dash):
            # astra probe: a terminal pending_first_use record followed by
            # an exact record.
            def make_pending(ev):
                ev["entries"]["coverage"].update(state=UNKNOWN_STATE, since_ns=None,
                                                reason=PENDING_FIRST_USE_REASON)
                ev["entries"]["observation"] = "unknown (usage observation unavailable)"
            return tail_stages(s, d, "P1", [(37, T0 + 500)],
                               [(37, T0 + 600, make_pending), (37, T0 + 700, None)])
        case("sweep-tail-pending-then-exact", "TERMINAL-SWEEP", sweep_tail_pending)

        def sweep_single_terminal(s, d, dash):
            # Legitimate sweep: the edge's only record is terminal and exact.
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            return tail_stages(s, d, "P1", [], [(n, T0 + 600, None)])
        res = case("sweep-single-terminal-pass", None, sweep_single_terminal)
        if not any(r["check"] == "TERMINAL-SWEEP" and r["status"] == "pass" for r in res.rows):
            failures.append("sweep-single-terminal-not-compared")

        # --- O3: invalid clocks fail open (sol 3) ---------------------------
        # Missing/non-integer/backwards timestamps skip cadence silently
        # with no other check failing. Each pair below is a bucket jump
        # (a class change), so cadence itself stays quiet and only the
        # clock verdict can fail.
        def clock_stages(s, d, first_at, second_at):
            n = _edge(d, cid(s, "P1"), s.mid["A"])["entries"]["count"]
            prev = (1 << (count_bucket(n) - 1)) - 1
            assert count_bucket(prev) != count_bucket(n), (prev, n)
            return drift_stages(s, d, "P1", [(prev, first_at), (n, second_at)])

        def clock_null(s, d, dash):
            return clock_stages(s, d, T0 + 500, None)
        case("edge-clock-null", "EDGE-CLOCK", clock_null)

        def clock_string(s, d, dash):
            return clock_stages(s, d, T0 + 500, "not-a-clock")
        case("edge-clock-string", "EDGE-CLOCK", clock_string)

        def clock_backwards(s, d, dash):
            return clock_stages(s, d, T0 + 1500, T0 + 500)
        case("edge-clock-backwards", "EDGE-CLOCK", clock_backwards)

        # O3 unsigned range (fix round 1): at_ns is a u64 CLOCK_MONOTONIC
        # stamp — exact int type (never bool) within 0..u64::MAX. Each
        # invalid stamp sits where monotonicity alone cannot catch it.
        def clock_negative(s, d, dash):
            return clock_stages(s, d, -1, T0 + 500)
        case("edge-clock-negative", "EDGE-CLOCK", clock_negative)

        def clock_bool(s, d, dash):
            return clock_stages(s, d, True, T0 + 500)
        case("edge-clock-bool", "EDGE-CLOCK", clock_bool)

        def clock_above_u64(s, d, dash):
            return clock_stages(s, d, T0 + 500, 2**64)
        case("edge-clock-above-u64", "EDGE-CLOCK", clock_above_u64)

        # --- O4: preadmission checks the wrong event (astra B2) --------------
        # The binder's Rule 3 rejects ROWS recorded before admission
        # (native_binding.rs:777: row.recorded_at_ns < first_seen_ns),
        # but the oracle compared the ledger's first call — including the
        # excluded acquisition C_GetFunctionList — against admission, so a
        # legitimate table-before-observer + use-after-admission edge
        # fails. The rejection must rest on evidence that an attached
        # entry produced a row before admission.
        def preadmission_legit_held(s, d, dash):
            sd = s.stop_doc()
            first = min(u[0] for c, _p, _st, _g, _e, _sp, uses in s.images if c == "P6"
                        for u in uses.values())
            row = first + MS
            sd["callers"][0]["first_seen_ns"] = first + MS // 2
            sd["edges"][0]["entries"]["first_seen_ns"] = row
            sd["edges"][0]["entries"]["coverage"]["since_ns"] = row
            # Mid-workload since: the setup acquisition missed, so the
            # edge drops the synth's predating +1 (round 2).
            sd["edges"][0]["entries"]["count"] = 1
            return {"stop_doc": sd}
        case("preadmission-held-table-before-observer", None, preadmission_legit_held)

        # --- O5: invented frozen-count bypass (astra B3) ---------------------
        # Native Counted has no until_ns (frozen ends belong to
        # WatchedNoUse), yet the oracle accepts a non-null counted end,
        # clips COUNT-WINDOW to it and skips COUNT-EXACT — so an early
        # until_ns with 37->1 calls passes everything.
        def counted_until_bypass(s, d, dash):
            match = re.search(r"fn=C_Initialize mech=- n=1 bad=0 phase=setup t0=\d+ t1=(\d+)",
                              s.ledgers["P2"])
            edge = _edge(d, cid(s, "P2"), s.mid["B"])
            edge["entries"]["coverage"]["until_ns"] = int(match.group(1))
            edge["entries"]["count"] = 1
        case("counted-until-frozen-bypass", "COVERAGE-SHAPE", counted_until_bypass)

        # --- O6: uncounted evidence vs gap suppression (astra A5) ------------
        # caller_registry's bounded output can suppress the pair-insert gap
        # while the edge retains valid uncounted coverage plus its
        # PairInsertFailure detail — that legitimate case fails
        # UNCOUNTED-EVIDENCE. Suppressed evidence is explicitly
        # nonqualifying (neither pass nor fail).
        def uncounted_suppressed(s, d, dash):
            uncounted_edge(s, d)
            d["gaps_suppressed"] = 1
            return {"events": s.events(d)}
        res = case("uncounted-gap-suppressed", None, uncounted_suppressed)
        row = next((r for r in res.rows if r["run"] == "system" and r["check"] == "UNCOUNTED-EVIDENCE"),
                   None)
        if row is None or row["status"] != "nonqualifying":
            failures.append("uncounted-gap-suppressed-not-nonqualifying")

        # --- O7: saturation cap bounds (astra A6) ---------------------------
        # Production's cap is fixed at u64::MAX (MAX_EDGE_ENTRY_COUNT,
        # src/inventory.rs edge_json): the document can never invent its
        # own saturation exemption. Small-cap arithmetic lives here as
        # unit checks, separate from artifact qualification (which
        # requires the fixed cap).
        arith = [
            saturation_coherent(7, True, 7),
            count_window_ok(7, True, 36, 37),
            not saturation_coherent(5, True, 7),
            not saturation_coherent(7, False, 7),
            count_window_ok(36, False, 36, 37),
            not count_window_ok(5, False, 36, 37),
        ]
        if not all(arith):
            failures.append("saturated-arithmetic-shape")

        def forged_cap_one(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(count=1, saturated=True, cap=1)
        case("saturated-forged-cap-one", "COUNT-SATURATED", forged_cap_one)

        def cap_none(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(cap=None)
        case("saturated-cap-none", "COUNT-SATURATED", cap_none)

        def saturated_off_cap(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(count=5, saturated=True)
        case("saturated-count-off-cap", "COUNT-SATURATED", saturated_off_cap)

        def unsaturated_at_cap(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(count=U64_MAX, saturated=False)
        case("unsaturated-count-at-cap", "COUNT-SATURATED", unsaturated_at_cap)

        def flag_nonbool(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(count=U64_MAX, saturated=1)
        case("saturated-flag-nonbool", "COUNT-SATURATED", flag_nonbool)

        def count_bool(s, d, dash):
            e = _edge(d, cid(s, "P1"), s.mid["A"])
            e["entries"].update(count=True)
        case("saturated-count-bool", "COUNT-SATURATED", count_bool)

        # --- O8: receipt boundary proof (astra A7, corrected round 2) ----
        # The C_GetFunctionList exclusion is acquisition-only AND
        # missed-only: the setup-phase dlsym call that receipts the
        # table counts unless a legacy attach-side line ending at/after
        # its own end but strictly before the edge's first BPF row
        # proves a later recording call. Phase, name, mechanism, and
        # the first-row time alone never exempt it — an armed
        # acquisition can itself create the first row (SoftHSM: export
        # == table slot). LEDGER-COUNTS pins exactly one setup
        # C_GetFunctionList per provider, so the fixture never holds an
        # ambiguous second one.
        def _line(fn, phase, n, t0, t1):
            return {"module": "/prov/a/libsofthsm2.so", "fn": fn, "mech": "-", "n": n, "bad": 0,
                    "phase": phase, "t0": t0, "t1": t1}
        acq = _line("C_GetFunctionList", "setup", 1, T0 + 1, T0 + 2)
        armed = _line("C_GetFunctionList", "main", 2, T0 + 3, T0 + 4)
        digest = _line("C_Digest", "main", 3, T0 + 5, T0 + 6)
        if Use([acq, armed, digest], [acq, armed, digest], T0 + 1, T0 + 6, {}).table_calls != 5:
            failures.append("o8-armed-table-call-excluded")
        if Use([acq], [acq], T0 + 1, T0 + 2, {}).table_calls != 0:
            failures.append("o8-acquisition-not-excluded")
        late = _line("C_GetFunctionList", "setup", 1, T0 + 5, T0 + 6)
        # Armed (after the first row, realistic since): counts.
        if not is_table_call("C_GetFunctionList", "setup", late, (T0 + 4, None)):
            failures.append("o8-armed-acquisition-excluded")
        # Missed: a legacy line ends after it but before the row, so
        # that line (or a later one) holds the recording call.
        if is_table_call("C_GetFunctionList", "setup", late, (T0 + 7, T0 + 6)):
            failures.append("o8-missed-acquisition-counted")
        # Predating row (synth convention: the row precedes every
        # call): the acquisition provably executed after the row
        # existed — through an armed endpoint — so it counts (round 2).
        if not is_table_call("C_GetFunctionList", "setup", late, (T0, None)):
            failures.append("o8-predating-acquisition-excluded")
        # Natural order, acquisition as the recording call (round 2):
        # no legacy line ends before the row, so it counts.
        nat_acq = _line("C_GetFunctionList", "setup", 1, T0 + 10, T0 + 10)
        if not is_table_call("C_GetFunctionList", "setup", nat_acq, (T0 + 15, None)):
            failures.append("o8-natural-acquisition-recording-excluded")
        # Natural order, acquisition missed (a legacy line ends after
        # it but before the row): excluded.
        if is_table_call("C_GetFunctionList", "setup", nat_acq, (T0 + 25, T0 + 20)):
            failures.append("o8-natural-acquisition-missed-counted")

        def armed_table_getfunctionlist(s, d, dash):
            ident = next(l for l in s.ledgers["P1"].splitlines() if l.startswith("IDENT "))
            main = re.search(r"phase=main t0=(\d+) t1=(\d+)", s.ledgers["P1"])
            led = dict(s.ledgers)
            led["P1"] += (f"LEDGER {ident.split(' ', 1)[1]} module=/prov/a/libsofthsm2.so "
                          f"fn=C_GetFunctionList mech=- n=1 bad=0 phase=main "
                          f"t0={main.group(1)} t1={main.group(2)}\n")
            return {"ledgers": led}
        case("armed-table-getfunctionlist", "LEDGER-COUNTS", armed_table_getfunctionlist)

        # O8 post-arming acquisition (fix round 1): P7 loads the
        # provider, waits, then invokes C_GetFunctionList through dlsym
        # — after the first BPF row, so the acquisition provably
        # traversed an armed endpoint (SoftHSM: export == table slot)
        # and counts. 28 (27 table + the armed acquisition) qualifies;
        # 27 (dropping it) fails.
        def armed_acquisition_ledger(s, d, count):
            led = dict(s.ledgers)
            pat_acq = re.compile(r"(fn=C_GetFunctionList mech=- n=1 bad=0 phase=setup t0=)(\d+)( t1=)(\d+)")
            pat_init = re.compile(r"(fn=C_Initialize mech=- n=1 bad=0 phase=setup t0=)(\d+)( t1=)(\d+)")
            assert len(pat_acq.findall(led["P7"])) == 1
            assert len(pat_init.findall(led["P7"])) == 1
            acq = pat_acq.search(led["P7"])
            init = pat_init.search(led["P7"])
            # Swap the two setup lines' stamps wholesale, so the phase
            # intervals (and LEDGER-COUNTS/PHASES) are unchanged but the
            # acquisition dlsym lands after C_Initialize ...
            led["P7"] = pat_acq.sub(
                lambda m: f"{m.group(1)}{init.group(2)}{m.group(3)}{init.group(4)}", led["P7"], count=1)
            led["P7"] = pat_init.sub(
                lambda m: f"{m.group(1)}{acq.group(2)}{m.group(3)}{acq.group(4)}", led["P7"], count=1)
            # ... with the first BPF row between them (mid-gap).
            since = (int(acq.group(4)) + int(init.group(2))) // 2
            edge = _edge(d, cid(s, "P7"), s.mid["A"])
            edge["entries"]["coverage"]["since_ns"] = since
            edge["entries"]["first_seen_ns"] = since
            edge["entries"]["count"] = count
            return {"ledgers": led}

        def armed_acquisition_correct(s, d, dash):
            return armed_acquisition_ledger(s, d, 28)
        case("armed-acquisition-counted-pass", None, armed_acquisition_correct)

        def armed_acquisition_short(s, d, dash):
            return armed_acquisition_ledger(s, d, 27)
        case("armed-acquisition-missing-fails", "COUNT-EXACT", armed_acquisition_short)

        # O8 acquisition as the recording call (round 2): P7's natural
        # order (acquisition dlsym before C_Initialize — the fixture's
        # own order) with the first BPF row between them. No legacy
        # line ends before the row, so the acquisition holds the
        # recording call and counts: 28 qualifies with COUNT-EXACT
        # engaged; 27 fails it.
        def natural_acquisition_ledger(s, d, count):
            led = s.ledgers["P7"]
            acq = re.search(r"fn=C_GetFunctionList mech=- n=1 bad=0 phase=setup t0=\d+ t1=(\d+)", led)
            init = re.search(r"fn=C_Initialize mech=- n=1 bad=0 phase=setup t0=(\d+)", led)
            acq_t1, init_t0 = int(acq.group(1)), int(init.group(1))
            assert acq_t1 < init_t0, (acq_t1, init_t0)
            since = (acq_t1 + init_t0) // 2
            edge = _edge(d, cid(s, "P7"), s.mid["A"])
            edge["entries"]["coverage"]["since_ns"] = since
            edge["entries"]["first_seen_ns"] = since
            edge["entries"]["count"] = count

        def natural_acquisition_correct(s, d, dash):
            natural_acquisition_ledger(s, d, 28)
        res = case("acquisition-first-record-natural-pass", None, natural_acquisition_correct)
        if not any(r["run"] == "system" and r["cell"] == "P7" and r["check"] == "COUNT-EXACT"
                   and r["status"] == "pass" for r in res.rows):
            failures.append("acquisition-first-record-natural-misses-exact")

        def natural_acquisition_short(s, d, dash):
            natural_acquisition_ledger(s, d, 27)
        case("acquisition-first-record-natural-short-fails", "COUNT-EXACT", natural_acquisition_short)
        # --- ledger ------------------------------------------------------------------------------------
        case("ledger-bad-rv", "LEDGER-RV", lambda s, d, dash: {"ledgers": {"P1": s.ledgers["P1"].replace(
            "fn=C_Sign mech=0x251 n=3 bad=0", "fn=C_Sign mech=0x251 n=3 bad=1")}})
        case("ledger-count", "LEDGER-COUNTS", lambda s, d, dash: {"ledgers": {"P2": s.ledgers["P2"].replace(
            "fn=C_Digest mech=0x250 n=2", "fn=C_Digest mech=0x250 n=1")}})
        case("ledger-leader-not-zombie", "LEDGER-LX-ZOMBIE", lambda s, d, dash: {"ledgers": {
            "LX": s.ledgers["LX"].replace("state=Z", "state=S")}})
        case("ledger-unflushed", "LEDGER-PARSE", lambda s, d, dash: {"ledgers": {
            "P1": s.ledgers["P1"] + "LEDGER_UNFLUSHED cell=P1 pid=1 reason=lock-held\n"}})
    if failures:
        print(f"{ORACLE_ID} self-test FAILED: {failures}")
        return 1
    print(f"{ORACLE_ID} self-test passed")
    return 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if len(argv) == 2 and argv[0] in ("check", "ledgers"):
        res = oracle(argv[1], ledgers_only=argv[0] == "ledgers")
        return report(res, os.path.join(argv[1], f"oracle-{argv[0]}.jsonl"), argv[0] == "ledgers")
    if len(argv) == 3 and argv[0] == "count-kind" and argv[2] in EVENT_KINDS:
        return count_kind(argv[1], argv[2])
    if argv == ["probe-help"]:
        return probe_help(sys.stdin.read())
    if argv[:1] == ["record-pty"]:
        return record_pty(argv[1:])
    print(__doc__, file=sys.stderr)
    return EXIT["usage"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
