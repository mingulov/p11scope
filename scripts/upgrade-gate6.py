#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Gate 6: saved v0.7.1 reports read by this tree's report read and diff.

Generates v0.7.1 inventory reports with the v0.7.1 binary, reads them with
this tree's `inventory cbom` (report read) and `inventory diff` (diff), and
proves the upgrade notes' three breaking items are exactly the differences.

The three breaking items (docs/releases/v0.8.0.md upgrade notes):
  B1 departed_use fold: proven-exited callers leave callers[]/edges[]/
     instances[] for per-module departed_use once rendered; new budgets
     counters account the fold. Consumers enumerating those arrays must
     also read departed_use.
  B2 live_joint_feed_absent: object-observations sections v1-v5 gained the
     live_joint_feed_absent status reason, so strict v0.7.1-era validators
     can reject new output.
  B3 observed-profile v3 new required evidence fields:
     pid_descendant_gaps_admitted, member_stop_attached,
     member_stop_unattached under the same schema id; saved v0.7.1
     profiles fail the new schema file.

Typed checks (exit 0 only if all pass):
  1. Old inventory churn report generates with the v0.7.1 binary (rc 0,
     schema p11scope/inventory/v1).
  2. New binary reads old via cbom (rc 0, CycloneDX JSON), via diff
     old-vs-old (rc 0 and typed zero changes) and old-vs-new (rc 0).
  3. B1: old has no departed_use key; new has every pinned B1 key; the
     new-vs-old key delta is exactly the B1 set plus a pinned additive set
     (all optional, all ignored by readers), with no removed keys.
  4. B2: v0.7.1 object-observations schemas v1-v5 (from tag v0.7.1) do not
     list live_joint_feed_absent in their reason enums; this tree's do;
     new cbom accepts a report carrying that reason and renders it through.
  5. B3: v0.7.1 observed-profile-v3 schema (from tag) does not require the
     three fields; this tree's does; new cbom still reads an old-shaped
     profile and renders its typed profile markers.

Usage:
  python3 -I scripts/upgrade-gate6.py \
    --old-binary /tmp/v071/p11scope \
    --new-binary target/.../p11scope \
    --workdir /tmp/gate6
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import upgrade_artifact_validation as artifact_validation

# B1: exact new-only inventory keys the current binary always emits.
# Fold budgets plus the per-module departed_use key itself (its populated
# subtree is conditional and lives in ADDITIVE_KEYS). Every B1 key must be
# present in the new report; unexpected keys fail b1_exact.
B1_KEYS = frozenset(
    [
        "budgets.callers.late_refused",
        "budgets.callers.retired",
        "budgets.callers.retired_with_calls",
        "budgets.departed_use",
        "budgets.departed_use.identities_dropped",
        "budgets.departed_use.mech_overflow",
        "budgets.edges.folded",
        "budgets.edges.folded_entries",
        "budgets.instances.folded",
        "budgets.native_departed",
        "budgets.native_departed.exec_prune_overflow",
        "budgets.native_departed.pair_dropped_base",
        "budgets.native_departed.pair_dropped_rows",
        "budgets.native_departed.pair_prune_overflow",
        "modules[0].departed_use",
    ]
)

# B1 reason vocabularies: flattened paths of count-maps keyed by reason
# labels. Leaves compare by vocabulary membership (mechanical sets from the
# producer's enums/tables), never by per-capture occurrence: a reason that
# fires on capture timing in one run is not a removal. Map nodes are exempt
# from occurrence comparison for the same reason (populated-or-not is
# timing); the strict schema, which runs first, still requires every node
# and types every map shape, so nothing structural goes unguarded.
REASON_MAP_PREFIXES = frozenset(
    [
        "modules[0].unbound_use.reasons",
        "modules[0].departed_use.entries.coverage.unknown",
        "modules[0].departed_use.entries.observation",
        "modules[0].departed_use.semantics.labels",
        "modules[0].departed_use.instances.reasons",
        "modules[0].departed_use.instances.loss_reasons",
        "observation.native_witnesses.unbound_reasons",
    ]
)
# Dynamic reason leaves carry capture values (clock ticks) and have no finite
# vocabulary; both sides' nodes and leaves under these maps are not compared.
DYNAMIC_LEAF_PREFIXES = frozenset(
    [
        "modules[0].departed_use.mapping.reasons",
    ]
)
VOCABULARIES_MANIFEST = SCRIPT_DIR / "upgrade-reason-vocabularies.json"


def load_reason_vocabularies(path=None):
    """Load committed reason-label sets; fail closed on any problem.

    Returns (vocabularies, error): vocabularies maps era -> map prefix ->
    label list when error is "". Unknown eras, missing maps, extra maps and
    non-string labels all refuse: the gate must not run B1 on a vocabulary
    it cannot account for exactly.
    """
    manifest = Path(path) if path is not None else VOCABULARIES_MANIFEST
    try:
        data = json.loads(manifest.read_text())
    except (OSError, ValueError) as exc:
        return None, f"refused: reason vocabularies unreadable: {exc}"
    if not isinstance(data, dict):
        return None, "refused: reason vocabularies root is not an object"
    expected = set(REASON_MAP_PREFIXES)
    for era in ("v071", "v072"):
        vocab = data.get(era)
        if not isinstance(vocab, dict) or set(vocab) != expected:
            return None, f"refused: reason vocabularies {era} map mismatch"
        for prefix, labels in vocab.items():
            if not isinstance(labels, list) or not all(
                isinstance(label, str) for label in labels
            ):
                return None, f"refused: reason vocabularies {era}.{prefix} not string list"
    return {"v071": data["v071"], "v072": data["v072"]}, ""


def split_reason_keys(keys):
    """Partition flattened paths into structural paths and reason leaves.

    Returns (structural, leaves) where leaves holds (map prefix, label)
    for static-map leaves. Reason-map nodes and dynamic-map subtrees are
    dropped from both sides: their occurrence is per-capture timing.
    """
    structural = set()
    leaves = []
    for path in keys:
        kind = None
        for prefix in DYNAMIC_LEAF_PREFIXES:
            if path == prefix or path.startswith(prefix + "."):
                kind = "dynamic"
                break
        if kind is None:
            for prefix in REASON_MAP_PREFIXES:
                if path == prefix:
                    kind = "node"
                    break
                if path.startswith(prefix + "."):
                    kind = ("leaf", prefix, path[len(prefix) + 1:])
                    break
        if kind is None:
            structural.add(path)
        elif kind != "node" and kind != "dynamic":
            leaves.append((kind[1], kind[2]))
    return structural, leaves


# Conditional new keys: present only when the capture populated their section.
# The populated departed_use fold subtree appears only when callers folded
# during the capture; the semantic_capture counters appear when the
# observation section carries them. Pinned: any new STRUCTURAL key outside
# B1+ADDITIVE fails the "nothing else" proof. Reason-map leaves are not
# pinned here; they compare by vocabulary membership instead.
ADDITIVE_KEYS = frozenset(
    [
        "modules[0].departed_use.callers",
        "modules[0].departed_use.edges",
        "modules[0].departed_use.entries",
        "modules[0].departed_use.entries.count",
        "modules[0].departed_use.entries.coverage",
        "modules[0].departed_use.entries.coverage.counted",
        "modules[0].departed_use.entries.coverage.first_min_ns",
        "modules[0].departed_use.entries.coverage.lossy",
        "modules[0].departed_use.entries.coverage.pid_exit",
        "modules[0].departed_use.entries.coverage.since_min_ns",
        "modules[0].departed_use.entries.coverage.until_max_ns",
        "modules[0].departed_use.entries.coverage.watched_no_use",
        "modules[0].departed_use.entries.coverage.witnessed",
        "modules[0].departed_use.entries.first_min_ns",
        "modules[0].departed_use.entries.forwarding",
        "modules[0].departed_use.entries.in_flight",
        "modules[0].departed_use.entries.last_max_ns",
        "modules[0].departed_use.entries.logical",
        "modules[0].departed_use.entries.saturated",
        "modules[0].departed_use.first_ns",
        "modules[0].departed_use.folded_instances",
        "modules[0].departed_use.folded_instances[0].caller",
        "modules[0].departed_use.folded_instances[0].id",
        "modules[0].departed_use.folded_instances_dropped",
        "modules[0].departed_use.folded_instances_saturated",
        "modules[0].departed_use.identities",
        "modules[0].departed_use.identities[0].authority",
        "modules[0].departed_use.identities[0].caller",
        "modules[0].departed_use.identities[0].exe",
        "modules[0].departed_use.identities[0].exe.dev",
        "modules[0].departed_use.identities[0].exe.ino",
        "modules[0].departed_use.identities[0].exe.mtime_nanos",
        "modules[0].departed_use.identities[0].exe.mtime_secs",
        "modules[0].departed_use.identities[0].exe.path",
        "modules[0].departed_use.identities[0].exec_observed",
        "modules[0].departed_use.identities[0].first_seen_ns",
        "modules[0].departed_use.identities[0].incarnation",
        "modules[0].departed_use.identities[0].last_seen_ns",
        "modules[0].departed_use.identities[0].lifecycle",
        "modules[0].departed_use.identities[0].lifecycle_reason",
        "modules[0].departed_use.identities[0].metadata_status",
        "modules[0].departed_use.identities[0].pid",
        "modules[0].departed_use.identities[0].start_time",
        "modules[0].departed_use.identities_dropped",
        "modules[0].departed_use.identities_saturated",
        "modules[0].departed_use.instances",
        "modules[0].departed_use.instances.api_returns",
        "modules[0].departed_use.instances.api_returns_saturated_rows",
        "modules[0].departed_use.instances.first_min_ns",
        "modules[0].departed_use.instances.folded",
        "modules[0].departed_use.instances.historical_only_returns",
        "modules[0].departed_use.instances.last_max_ns",
        "modules[0].departed_use.instances.lossy_rows",
        "modules[0].departed_use.instances.null_reasons",
        "modules[0].departed_use.instances.observed",
        "modules[0].departed_use.instances.retired",
        "modules[0].departed_use.instances.settled_live",
        "modules[0].departed_use.instances.uncertain",
        "modules[0].departed_use.mapping",
        "modules[0].departed_use.mapping.evidence",
        "modules[0].departed_use.mapping.evidence.deep_scan",
        "modules[0].departed_use.mapping.evidence.maps_match",
        "modules[0].departed_use.mapping.first_min_ns",
        "modules[0].departed_use.mapping.interruptions",
        "modules[0].departed_use.mapping.last_max_ns",
        "modules[0].departed_use.mapping.reasons_overflow",
        "modules[0].departed_use.mapping.state",
        "modules[0].departed_use.mapping.state.ended",
        "modules[0].departed_use.mapping.state.mapped",
        "modules[0].departed_use.mapping.state.uncertain",
        "modules[0].departed_use.mechanisms",
        "modules[0].departed_use.mechanisms_overflow",
        "modules[0].departed_use.mechanisms_overflow.calls",
        "modules[0].departed_use.mechanisms_overflow.errors",
        "modules[0].departed_use.mechanisms_overflow.mechs",
        "modules[0].departed_use.operations",
        "modules[0].departed_use.semantics",
        "observation.semantic_capture.length_insert_failures",
        "observation.semantic_capture.length_stash_mismatches",
        # B17 leg 2: the staged reload disclosure, present only when the
        # capture staged instance reloads (observed live on fedora-sm1).
        "instance_reload_not_excluded",
        "instance_reload_not_excluded.continued_across_global",
        "instance_reload_not_excluded.joined_across_global",
        "instance_reload_not_excluded.identities",
        "instance_reload_not_excluded.identities[0].instances",
        "instance_reload_not_excluded.identities[0].module",
    ]
)

B3_FIELDS = (
    "pid_descendant_gaps_admitted",
    "member_stop_attached",
    "member_stop_unattached",
)
BREAKING = ["departed_use", "live_joint_feed_absent", "profile_evidence_fields"]
LIVE_JOINT_REASON = "live_joint_feed_absent"
PROFILE_TEST_WINDOW = "2026-01-01T00:00:00Z..2026-01-01T00:00:01Z (capture wall clock)"
PROFILE_INPUT_NOTE = (
    "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
)
PROFILE_FIXTURE = ROOT / "tests/fixtures/upgrade/v071-observed-profile.json"


class GateFailure(Exception):
    """One typed gate check failed; the result has already been recorded."""


def initial_result() -> dict:
    return {
        "gate": 6,
        "status": "fail",
        "checks": {},
        "breaking": list(BREAKING),
        "notes": {},
        "fail_reason": "",
    }


def check(result: dict, name: str, ok: bool, detail: str = "") -> None:
    result["checks"][name] = {"pass": bool(ok), "detail": detail}
    if not ok:
        result["fail_reason"] = f"{name}: {detail}"
        raise GateFailure(result["fail_reason"])


def run(args, timeout=120, **kw):
    """Run a command, converting timeout/exec failure into a typed result."""
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, **kw
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, 124, stdout="", stderr=f"timeout after {timeout} seconds"
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args, 127, stdout="", stderr=f"exec failed: {exc}"
        )


def flatten_keys(value, path=""):
    """Yield key paths, uniting keys from every dict element of a list.

    List positions are normalized to ``[0]`` because the pinned key sets
    describe the shape of homogeneous rows, not row identities. Looking at
    every element matters: a key appearing first in modules[1] is still a
    schema-shape delta.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            here = f"{path}.{key}" if path else key
            yield here
            yield from flatten_keys(child, here)
    elif isinstance(value, list):
        for row in value:
            if not isinstance(row, dict):
                continue
            for key, child in row.items():
                here = f"{path}[0].{key}" if path else f"[0].{key}"
                yield here
                yield from flatten_keys(child, here)


def evaluate_b1_delta(old_keys, new_keys, vocabularies) -> dict:
    """Evaluate the typed B1 key delta in both directions.

    Structural paths compare by occurrence; reason leaves compare by
    vocabulary membership. An old leaf outside the v0.7.2 vocabulary is a
    removal when v0.7.1 has it, else unknown (forged input or a derivation
    gap: fails closed, never silently passes). A new leaf outside the
    v0.7.2 vocabulary is unexpected. Timing-only absence passes silently.
    """
    old_struct, old_leaves = split_reason_keys(set(old_keys))
    new_struct, new_leaves = split_reason_keys(set(new_keys))
    allowed = set(B1_KEYS) | set(ADDITIVE_KEYS)
    removed = set(old_struct - new_struct)
    removed_unknown = set()
    old_vocab = vocabularies.get("v071", {})
    new_vocab = vocabularies.get("v072", {})
    for prefix, label in old_leaves:
        if label in new_vocab.get(prefix, ()):
            continue
        path = f"{prefix}.{label}"
        if label in old_vocab.get(prefix, ()):
            removed.add(path)
        else:
            removed_unknown.add(path)
    unexpected = set((new_struct - old_struct) - allowed)
    for prefix, label in new_leaves:
        if label not in new_vocab.get(prefix, ()):
            unexpected.add(f"{prefix}.{label}")
    return {
        "removed": removed,
        "removed_unknown": removed_unknown,
        "unexpected": unexpected,
        "missing_b1": set(B1_KEYS) - set(new_keys),
    }


def admission_parity(old_count: int, new_count: int) -> tuple:
    """New build admitted at least half the old caller count.

    The churn workload is deterministic (the official v0.7.1 binary admits
    11-12 callers every round); a new side under half the old count is the
    slow-host admission shortfall (product lane v072-slow-host-admission),
    never timing noise: observed healthy ratios stay >= 1.0, the shortfall
    sits at 0.18. Returns (ok, detail).
    """
    ok = new_count * 2 >= old_count
    detail = f"old callers={old_count} new callers={new_count}"
    return ok, detail


def key_exists(value, wanted: str) -> bool:
    """True when typed JSON contains a key exactly named ``wanted``."""
    if isinstance(value, dict):
        return any(
            key == wanted or key_exists(child, wanted)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(key_exists(child, wanted) for child in value)
    return False


def schema_reason_has(schema: dict, reason: str) -> bool:
    enum = schema.get("properties", {}).get("reason", {}).get("enum", [])
    return reason in enum


def cbom_properties(document: dict) -> dict:
    """Metadata properties as one typed name -> value mapping."""
    props = {}
    for row in document.get("metadata", {}).get("properties", []):
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        value = row.get("value")
        if isinstance(name, str) and isinstance(value, str):
            props[name] = value
    return props


def diff_zero_same(document: dict) -> bool:
    """True only for a typed diff document with both change lists empty."""
    return (
        not artifact_validation.diff_errors(document)
        and document.get("application_changes") == []
        and document.get("module_path_changes") == []
    )


def cbom_live_joint_rendered(document: dict) -> bool:
    """True when cbom renders the exact injected object-observation reason."""
    return (
        cbom_properties(document).get("p11scope:object_observations")
        == f"partial ({LIVE_JOINT_REASON})"
    )


def profile_window(document: dict) -> str:
    """The typed capture window a cbom conversion must preserve."""
    capture = document.get("capture", {})
    start = capture.get("start")
    end = capture.get("end")
    if isinstance(start, str) and isinstance(end, str) and start and end:
        return f"{start}..{end} (capture wall clock)"
    return ""


def cbom_profile_markers_present(document: dict, window: str = PROFILE_TEST_WINDOW) -> bool:
    """True when the old-shaped profile's typed conversion markers flow through."""
    props = cbom_properties(document)
    return (
        props.get("p11scope:source_schema") == "p11scope/observed-profile/v3"
        and props.get("p11scope:window") == window
        and props.get("p11scope:profile_note") == PROFILE_INPUT_NOTE
    )


def profile_fixture_old_shape(document: dict) -> bool:
    """True only for a substantive v0.7.1 profile lacking the new evidence keys."""
    evidence = document.get("evidence", {})
    capture = document.get("capture", {})
    return (
        document.get("schema") == "p11scope/observed-profile/v3"
        and document.get("lane") == "profile"
        and capture.get("mode") == "profile"
        and bool(capture.get("modules"))
        and bool(document.get("functions"))
        and bool(document.get("mechanisms"))
        and evidence.get("completeness") == "COMPLETE"
        and all(key not in evidence for key in (*B3_FIELDS, "coverage_retired_slots"))
    )


def required_evidence(schema):
    req = set()
    evidence = schema.get("properties", {}).get("evidence", {})
    req.update(evidence.get("required", []))
    for clause in schema.get("allOf", []):
        # allOf entries nest required under then.properties.evidence
        # (profile lane) or properties.evidence.
        for container in (clause, clause.get("then", {})):
            props = container.get("properties", {}).get("evidence", {})
            req.update(props.get("required", []))
        for sub in clause.get("allOf", []):
            sub_props = sub.get("properties", {}).get("evidence", {})
            req.update(sub_props.get("required", []))
    return req


def then_required(schema):
    """The profile-lane then.required list (where the three live)."""
    for clause in schema.get("allOf", []):
        then = clause.get("then", {})
        props = then.get("properties", {}).get("evidence", {})
        if props.get("required"):
            return set(props["required"])
    return set()


def git_show(rev: str, path: str) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    out = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return out.stdout


def load_json_file(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


def terminate_target(target: subprocess.Popen) -> None:
    target.terminate()
    try:
        target.wait(timeout=5)
    except subprocess.TimeoutExpired:
        target.kill()
        target.wait(timeout=5)


def find_provider_module() -> str | None:
    for candidate in (
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
    ):
        if Path(candidate).exists():
            return candidate
    return None


def object_observation_schema_names() -> list[str]:
    return [
        "docs/schema/inventory-v1-object-observations.schema.json",
        *(
            f"docs/schema/inventory-v1-object-observations-{version}.schema.json"
            for version in ("v2", "v3", "v4", "v5")
        ),
    ]


def load_object_observation_schemas() -> tuple[dict, dict]:
    names = object_observation_schema_names()
    old_schemas = {
        name: json.loads(git_show("v0.7.1", name).decode()) for name in names
    }
    new_schemas = {name: json.loads((ROOT / name).read_text()) for name in names}
    return old_schemas, new_schemas


def load_profile_schemas() -> tuple[dict, dict]:
    old_prof = json.loads(
        git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json").decode()
    )
    new_prof = json.loads((ROOT / "docs/schema/observed-profile-v3.schema.json").read_text())
    return old_prof, new_prof


def generate_manifest(helper: Path, module: str, output: Path) -> str:
    """Generate the provider manifest needed for attested mechanism capture."""
    completed = run(
        [str(helper), "--module", module, "-o", str(output)],
        timeout=30,
    )
    if completed.returncode != 0 or not output.exists():
        return f"manifest generation rc={completed.returncode} stderr={completed.stderr[:300]}"
    return ""


PINS_MANIFEST = SCRIPT_DIR / "upgrade-artifact-pins.json"


def verify_artifact_pin(name: str, path: Path) -> str:
    """Check a consumed external artifact against the committed sha256 pins.

    Returns "" on match, else a typed refusal. Missing manifest entries,
    unreadable files and hash mismatches all refuse (fail closed).
    """
    try:
        manifest = json.loads(PINS_MANIFEST.read_text())
        want = manifest["artifacts"][name]["sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return f"refused: artifact pin {name!r} unavailable: {exc}"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return f"refused: artifact {name!r} unreadable: {exc}"
    if digest != want:
        return f"refused: artifact {name!r} sha256 mismatch: got {digest}, want {want}"
    return ""


def output_owner_arguments(output: Path) -> list[str]:
    """Root handover arguments when the output directory belongs to a user."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        stat = output.parent.stat()
        if stat.st_uid != 0:
            return ["--output-owner", f"{stat.st_uid}:{stat.st_gid}"]
    return []


def generate_scan_report(binary: Path, output: Path, module: str) -> str:
    """Generate one churn-workload native inventory; empty string means success."""
    workload = SCRIPT_DIR / "upgrade-softhsm-workload.py"
    child_python = output.parent / "churn-child-python"
    try:
        target = subprocess.Popen(
            [sys.executable, str(workload), "--module", module, "--child-python", str(child_python)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        return f"target exec failed for {binary}: {exc}"
    try:
        if target.stdout is None:
            return f"target stdout unavailable for {binary}"
        ready, _, _ = select.select([target.stdout], [], [], 10)
        if not ready:
            return f"target readiness timeout for {binary}"
        line = target.stdout.readline()
        if "ready" not in line:
            return f"target did not start for {binary}: {line[:200]}"
        cgroup = Path("/sys/fs/cgroup/p11scope-upgrade") / f"gate6-{os.getpid()}"
        try:
            cgroup.mkdir(parents=True, exist_ok=True)
            (cgroup / "cgroup.procs").write_text(str(target.pid))
            members = (cgroup / "cgroup.procs").read_text().split()
        except OSError as exc:
            return f"cgroup setup failed for {binary}: {exc}"
        if str(target.pid) not in members:
            return f"cgroup membership unverified for {binary} pid={target.pid}"
        completed = run(
            [
                str(binary),
                "inventory",
                "--cgroup",
                str(cgroup),
                "--capture",
                "native",
                "--duration",
                "24s",
                "--manifest",
                str(output.parent / "softhsm-manifest.json"),
                "--json",
                "-o",
                str(output),
                *output_owner_arguments(output),
            ],
            timeout=60,
        )
        if completed.returncode != 0 or not output.exists():
            return (
                f"{binary} churn inventory rc={completed.returncode} "
                f"stderr={completed.stderr[:300]}"
            )
        try:
            document = load_json_file(output)
        except ValueError as exc:
            return f"{binary} report unreadable: {exc}"
        errors = artifact_validation.inventory_errors(document)
        if errors:
            return f"{binary} invalid churn inventory report: {errors[0]}"
        return ""
    finally:
        try:
            terminate_target(target)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            for member in (cgroup / "cgroup.procs").read_text().split():
                try:
                    os.kill(int(member), signal.SIGKILL)
                except (OSError, ValueError):
                    pass
        except (OSError, NameError):
            pass
        try:
            cgroup.rmdir()
        except (OSError, NameError):
            pass


def run_gate(args, workdir: Path, result: dict) -> int:
    pin_errors = [
        verify_artifact_pin("v071-observer-binary", args.old_binary),
        verify_artifact_pin("v071-profile-fixture", PROFILE_FIXTURE),
    ]
    pin_detail = "; ".join(error for error in pin_errors if error)
    check(
        result,
        "inputs_present",
        args.old_binary.is_file()
        and os.access(args.old_binary, os.X_OK)
        and args.new_binary.is_file()
        and os.access(args.new_binary, os.X_OK)
        and not pin_detail,
        f"old={args.old_binary} new={args.new_binary}"
        + (f"; {pin_detail}" if pin_detail else ""),
    )

    # 1. Generate old + new inventory churn reports from live targets.
    module = find_provider_module()
    check(result, "reports_generated", module is not None, "no SoftHSM provider found")
    old_report = workdir / "v071-inventory.json"
    new_report = workdir / "v072-inventory.json"
    helper = getattr(args, "helper_binary", None) or args.new_binary.parent / "p11scope-discover"
    manifest = workdir / "softhsm-manifest.json"
    manifest_detail = generate_manifest(helper, module, manifest)
    if manifest_detail:
        check(result, "reports_generated", False, manifest_detail)
    for binary, output in ((args.old_binary, old_report), (args.new_binary, new_report)):
        detail = generate_scan_report(binary, output, module)
        if detail:
            check(result, "reports_generated", False, detail)
    check(
        result,
        "reports_generated",
        True,
        f"old={old_report} new={new_report}",
    )
    try:
        old = load_json_file(old_report)
        new = load_json_file(new_report)
    except ValueError as exc:
        check(result, "inventory_reports_typed", False, f"report load: {exc}")
    inventory_errors = []
    old_errors = artifact_validation.inventory_errors(old)
    new_errors = artifact_validation.inventory_errors(new)
    if old_errors:
        inventory_errors.append(f"old: {old_errors[0]}")
    if new_errors:
        inventory_errors.append(f"new: {new_errors[0]}")
    check(
        result,
        "inventory_reports_typed",
        not inventory_errors,
        "; ".join(inventory_errors)
        if inventory_errors
        else "old/new inventory reports carry typed root, observation, budget, row and gap content",
    )

    # 1b. Admission parity runs before B1: comparing key shapes across an
    # admission-divergent pair is noise; the shortfall gets one signature.
    parity_ok, parity_detail = admission_parity(len(old["callers"]), len(new["callers"]))
    check(result, "admission_parity", parity_ok, parity_detail)

    # 2. B1: departed_use delta is exactly B1+additive, nothing else, and
    # every pinned B1 key is present in the new typed report. Reason leaves
    # compare by vocabulary, never by occurrence.
    vocabularies, vocab_error = load_reason_vocabularies()
    check(
        result,
        "b1_vocabularies",
        not vocab_error,
        vocab_error
        or f"v071/v072 cover {len(REASON_MAP_PREFIXES)} reason maps",
    )
    old_keys = set(flatten_keys(old))
    new_keys = set(flatten_keys(new))
    delta = evaluate_b1_delta(old_keys, new_keys, vocabularies)
    check(
        result,
        "b1_no_removed",
        len(delta["removed"]) == 0 and len(delta["removed_unknown"]) == 0,
        f"removed={sorted(delta['removed'])} "
        f"unknown={sorted(delta['removed_unknown'])}",
    )
    check(
        result,
        "b1_all_present",
        len(delta["missing_b1"]) == 0,
        f"missing B1={sorted(delta['missing_b1'])}",
    )
    check(
        result,
        "b1_exact",
        len(delta["unexpected"]) == 0,
        f"unexpected new keys={sorted(delta['unexpected'])}",
    )
    old_has_departed = key_exists(old, "departed_use")
    check(
        result,
        "b1_old_absent",
        not old_has_departed,
        "departed_use key present in old report"
        if old_has_departed
        else "no departed_use key in old report",
    )

    # 3. B2: live_joint_feed_absent in the v1-v5 reason enums, and the new
    # reader renders it through rather than merely exiting zero.
    try:
        old_schemas, new_schemas = load_object_observation_schemas()
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        check(result, "b2_schemas", False, f"schema load: {exc}")
    old_carrying = [
        name
        for name, schema in old_schemas.items()
        if schema_reason_has(schema, LIVE_JOINT_REASON)
    ]
    check(
        result,
        "b2_old_absent",
        not old_carrying,
        f"old schemas carrying the reason={old_carrying}",
    )
    new_missing = [
        name
        for name, schema in new_schemas.items()
        if not schema_reason_has(schema, LIVE_JOINT_REASON)
    ]
    check(
        result,
        "b2_new_present",
        not new_missing,
        f"new schemas missing the reason={new_missing}",
    )

    try:
        injected = load_json_file(old_report)
        budgets = injected["object_observations"]["budgets"]
        if not isinstance(budgets, dict):
            raise TypeError("object_observations.budgets is not an object")
        injected["object_observations"] = {
            "version": 1,
            "revision": 1,
            "status": "partial",
            "reason": LIVE_JOINT_REASON,
            "budgets": budgets,
            "gaps": {"rows": [], "suppressed": 0},
            "key_operations": [],
            "objects": [],
            "sessions": [],
            "unknown_key_operations": [],
        }
    except (ValueError, KeyError, TypeError) as exc:
        check(result, "b2_reader_accepts", False, f"cannot build injection: {exc}")
    injected_path = workdir / "injected-live-joint.json"
    injected_path.write_text(json.dumps(injected))
    completed = run([str(args.new_binary), "inventory", "cbom", str(injected_path), "--json"])
    rendered = None
    cbom = {}
    cbom_errors = ["cbom command failed"]
    reader_detail = f"rc={completed.returncode}"
    if completed.returncode == 0:
        try:
            cbom = json.loads(completed.stdout)
            cbom_errors = artifact_validation.cbom_inventory_errors(cbom, injected)
            rendered = cbom_properties(cbom).get("p11scope:object_observations")
            reader_detail = (
                cbom_errors[0]
                if cbom_errors
                else f"object_observations={rendered!r}"
            )
        except json.JSONDecodeError as exc:
            cbom_errors = [f"cbom JSON parse: {exc}"]
            reader_detail = cbom_errors[0]
    expected_render = f"partial ({LIVE_JOINT_REASON})"
    rendered_ok = not cbom_errors and cbom_live_joint_rendered(cbom)
    check(
        result,
        "b2_reader_accepts",
        rendered_ok,
        f"{reader_detail}, expected {expected_render!r}",
    )

    # 4. B3: profile schema requires exactly the three new evidence fields
    # in the profile-lane then.required and exactly those plus
    # coverage_retired_slots in the full evidence-required delta.
    try:
        old_prof, new_prof = load_profile_schemas()
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        check(result, "b3_schemas", False, f"schema load: {exc}")

    old_req = required_evidence(old_prof)
    new_req = required_evidence(new_prof)
    added = new_req - old_req
    removed = old_req - new_req
    old_then = then_required(old_prof)
    new_then = then_required(new_prof)
    then_added = new_then - old_then
    then_removed = old_then - new_then
    check(
        result,
        "b3_then_exact",
        then_added == set(B3_FIELDS) and not then_removed,
        f"then_added={sorted(then_added)} then_removed={sorted(then_removed)}",
    )
    expected_added = set(B3_FIELDS) | {"coverage_retired_slots"}
    check(
        result,
        "b3_exact",
        added == expected_added and not removed,
        f"added={sorted(added)} removed={sorted(removed)}",
    )
    result["notes"]["b3_coverage"] = (
        "coverage_retired_slots is part of the exact full required delta but is "
        "not one of the three upgrade-note run-gap fields; docs lane owns that note"
    )

    # New cbom still reads a real v0.7.1-generated profile (lenient reader).
    # The fixture has non-empty capture-module, evidence, function and mechanism
    # rows; conversion must flow those rows into typed cbom properties rather
    # than merely exiting zero on a sparse synthetic object.
    try:
        profile_doc = load_json_file(PROFILE_FIXTURE)
    except ValueError as exc:
        check(result, "b3_fixture_old_shape", False, f"fixture load: {exc}")
    fixture_ok = profile_fixture_old_shape(profile_doc)
    check(
        result,
        "b3_fixture_old_shape",
        fixture_ok,
        "real v0.7.1 profile fixture with modules/evidence/functions/mechanisms "
        "and without the new required evidence keys"
        if fixture_ok
        else "fixture is not a substantive old-shaped v0.7.1 profile",
    )

    # Versioned-schema matrix: the v0.7.1 artifact is valid against the
    # schema file shipped at tag v0.7.1.  Until lane v072-compat-071 lands,
    # validating that same artifact against HEAD is a named expected failure,
    # never a compatibility pass.
    # The tag schema is read from the tree's own history and validated from
    # memory; it is never copied to a file. The logical path only anchors
    # relative $ref resolution (this schema has no external references, so a
    # future one would fail loudly instead of resolving somewhere stale).
    old_schema_path = Path("v0.7.1:docs/schema/observed-profile-v3.schema.json")
    new_schema_path = ROOT / "docs/schema/observed-profile-v3.schema.json"
    # Both profile schemas are legacy loose contracts (partial subschemas
    # plus lane-gated conditionals): strict would refuse the product's own
    # output and break if-matching, so the matrix stays non-strict. Strict
    # fail-closed applies to the current complete schemas (inventory, diff,
    # CBOM, object observations). The old fixture bytes are pinned by sha256.
    try:
        old_schema_errors = artifact_validation.json_schema.validate(
            profile_doc, old_prof, old_schema_path, strict=False
        )
        head_schema_errors = artifact_validation.json_schema.validate(
            profile_doc, new_prof, new_schema_path, strict=False
        )
    except artifact_validation.json_schema.SchemaError as exc:
        check(result, "b3_schema_matrix", False, f"schema validation error: {exc}")
    check(
        result,
        "b3_old_schema_passes",
        not old_schema_errors,
        "v0.7.1 artifact validates against tag v0.7.1 schema"
        if not old_schema_errors
        else old_schema_errors[0],
    )
    expected_names = sorted(set(B3_FIELDS) | {"coverage_retired_slots"})
    missing_names = [
        name
        for name in expected_names
        if any(f"required property '{name}' is missing" in error for error in head_schema_errors)
    ]
    expected_failure_ok = bool(head_schema_errors) and missing_names == expected_names
    detail = (
        "expected failure old-against-HEAD: missing " + ",".join(missing_names)
        if expected_failure_ok
        else f"unexpected old-against-HEAD validation outcome: {head_schema_errors[:2]!r}"
    )
    check(
        result,
        "b3_old_against_head_expected_failure",
        expected_failure_ok,
        detail,
    )
    result["notes"]["b3_schema_matrix"] = (
        "old artifact/tag-v0.7.1 schema: valid; old artifact/HEAD schema: "
        "expected failure until v072-compat-071, never counted as a pass"
    )

    completed = run(
        [str(args.new_binary), "inventory", "cbom", str(PROFILE_FIXTURE), "--json"]
    )
    cbom = {}
    profile_errors = ["cbom command failed"]
    profile_detail = f"rc={completed.returncode}"
    if completed.returncode == 0:
        try:
            cbom = json.loads(completed.stdout)
            profile_errors = artifact_validation.cbom_profile_errors(cbom, profile_doc)
            profile_detail = (
                profile_errors[0]
                if profile_errors
                else "typed profile markers and substantive rows present"
            )
        except json.JSONDecodeError as exc:
            profile_errors = [f"cbom JSON parse: {exc}"]
            profile_detail = profile_errors[0]
    profile_ok = completed.returncode == 0 and not profile_errors
    check(result, "b3_reader_accepts_old", profile_ok, profile_detail)

    # 5. New binary reads old via cbom and diff.
    completed = run([str(args.new_binary), "inventory", "cbom", str(old_report), "--json"])
    check(
        result,
        "cbom_reads_old",
        completed.returncode == 0,
        f"rc={completed.returncode}",
    )
    try:
        cbom = json.loads(completed.stdout)
        cbom_errors = artifact_validation.cbom_inventory_errors(cbom, old)
        cbom_typed_ok = not cbom_errors
        cbom_typed_detail = (
            cbom_errors[0]
            if cbom_errors
            else "typed inventory cbom flow-through matches scope/window/passes/gaps/provider/application counts"
        )
    except json.JSONDecodeError as exc:
        cbom_typed_ok = False
        cbom_typed_detail = f"cbom JSON parse: {exc}"
    check(result, "cbom_old_typed", cbom_typed_ok, cbom_typed_detail)

    completed = run(
        [
            str(args.new_binary),
            "inventory",
            "diff",
            str(old_report),
            str(old_report),
            "--json",
        ]
    )
    zero_detail = f"rc={completed.returncode}"
    zero_ok = completed.returncode == 0
    if zero_ok:
        try:
            same_diff = json.loads(completed.stdout)
            zero_errors = artifact_validation.diff_errors(same_diff, old, old)
            if same_diff.get("application_changes") != [] or same_diff.get("module_path_changes") != []:
                zero_errors.append("same-input diff has nonempty application/module-path changes")
            zero_ok = not zero_errors
            zero_detail = (
                zero_errors[0]
                if zero_errors
                else "typed ten-field diff, consistent before/after snapshots and zero changes"
            )
        except json.JSONDecodeError as exc:
            zero_ok = False
            zero_detail = f"diff JSON parse: {exc}"
    check(result, "diff_old_old_zero", zero_ok, zero_detail)

    completed = run(
        [
            str(args.new_binary),
            "inventory",
            "diff",
            str(old_report),
            str(new_report),
            "--json",
        ]
    )
    check(result, "diff_old_new", completed.returncode == 0, f"rc={completed.returncode}")
    try:
        diff_doc = json.loads(completed.stdout)
        diff_errors = artifact_validation.diff_errors(diff_doc, old, new)
        diff_ok = not diff_errors
        diff_detail = (
            diff_errors[0]
            if diff_errors
            else "typed ten-field diff with consistent before/after snapshots, comparison and summary"
        )
    except json.JSONDecodeError as exc:
        diff_doc = {}
        diff_detail = f"diff JSON parse: {exc}"
        diff_ok = False
    check(result, "diff_typed", diff_ok, diff_detail)

    # The churn workload keeps one caller alive while short-lived children
    # enter and leave over several passes.  A lifecycle claim for that group
    # is only acceptable when the reader names the pre-fold input limitation
    # (lane v072-compat-071); otherwise independent windows must not invent
    # a lifecycle transition.
    lifecycle_rows = []
    if isinstance(diff_doc, dict):
        for row in diff_doc.get("application_changes", []):
            if isinstance(row, dict) and any("lifecycle" in str(change) for change in row.get("changes", [])):
                lifecycle_rows.append(row)
    pre_fold_present = (
        isinstance(diff_doc, dict)
        and "pre_fold_input" in diff_doc.get("limitations", [])
    )
    check(
        result,
        "diff_churn_lifecycle",
        not lifecycle_rows or pre_fold_present,
        f"lifecycle_rows={len(lifecycle_rows)} pre_fold_input={pre_fold_present}",
    )

    result["status"] = "pass"
    return emit(workdir, result, 0)


def emit(workdir: Path, result: dict, code: int) -> int:
    out = workdir / "gate6-result.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", required=True, type=Path)
    parser.add_argument("--new-binary", required=True, type=Path)
    parser.add_argument("--helper-binary", type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    args = parser.parse_args()
    workdir = args.workdir
    result = initial_result()
    try:
        workdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result["checks"]["internal"] = {"pass": False, "detail": repr(exc)}
        result["fail_reason"] = f"internal: {exc!r}"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1
    try:
        return run_gate(args, workdir, result)
    except GateFailure:
        return emit(workdir, result, 1)
    except Exception as exc:  # typed failure record even for an unexpected checker bug
        result["checks"]["internal"] = {"pass": False, "detail": repr(exc)}
        result["fail_reason"] = f"internal: {exc!r}"
        return emit(workdir, result, 1)


if __name__ == "__main__":
    raise SystemExit(main())
