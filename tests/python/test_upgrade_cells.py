#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Upgrade cells: package upgrade (gate 5) and report compat (gate 6).

Gate 5 is a root-only cell (installs DEB/RPM); this suite pins its script
contract without installing: argument parsing, the non-root refusal, typed
emitter behaviour through the script's self-test mode, and the full gate
body through a typed fake package root. The live upgrade runs in the
upgrade-cells workflow and on the fedora host via scripts/upgrade-gate5.sh.

Gate 6's end-to-end leg lives in .github/workflows/upgrade-cells.yml and in
the release-candidate host runs. This suite pins its pure typed checks, its
run_gate activation wiring through typed doubles, sparse-artifact refusals,
and the exact B1/B2/B3 schema deltas from the tree alone.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
GATE5 = ROOT / "scripts/upgrade-gate5.sh"
GATE6_PATH = ROOT / "scripts/upgrade-gate6.py"


def load_gate6():
    spec = importlib.util.spec_from_file_location("upgrade_gate6_under_test", GATE6_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_vocab_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_reason_vocabularies_under_test",
        ROOT / "scripts/generate-reason-vocabularies.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_workload():
    spec = importlib.util.spec_from_file_location(
        "upgrade_softhsm_workload_under_test",
        ROOT / "scripts/upgrade-softhsm-workload.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_sweep():
    spec = importlib.util.spec_from_file_location(
        "upgrade_mutation_sweep_under_test",
        ROOT / "scripts/upgrade-mutation-sweep.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact_pin(name):
    """Read one committed sha256 pin (single source: the manifest file)."""
    manifest = json.loads((ROOT / "scripts/upgrade-artifact-pins.json").read_text())
    return manifest["artifacts"][name]["sha256"]


def load_artifact_validation():
    spec = importlib.util.spec_from_file_location(
        "upgrade_artifact_validation_under_test",
        ROOT / "scripts/upgrade_artifact_validation.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_package_release():
    spec = importlib.util.spec_from_file_location(
        "package_release_under_test", ROOT / "scripts/package-release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def parity_doc(n_callers, child_entries=0, folded_callers=0, folded_entries=0):
    """Minimal inventory-shaped doc for admission tests: caller c0 is the
    long-lived parent (span 100, 500 edge entries); c1.. are short-lived
    children (span 10), the first carrying child_entries; one module whose
    departed_use holds folded_callers/folded_entries when nonzero."""
    callers = [{"id": "c0", "first_seen_ns": 0, "last_seen_ns": 100}]
    edges = [{"caller": "c0", "entries": {"count": 500}}]
    for index in range(1, n_callers):
        callers.append({"id": f"c{index}", "first_seen_ns": 0,
                        "last_seen_ns": 10})
        edges.append({"caller": f"c{index}", "entries": {
            "count": child_entries if index == 1 else 0}})
    departed = ({"callers": folded_callers,
                 "entries": {"count": folded_entries}}
                if folded_callers else None)
    return {"callers": callers, "edges": edges,
            "modules": [{"departed_use": departed}]}


def substantive_inventory(schema="p11scope/inventory/v1"):
    """One small but fully typed inventory document used by typed doubles.

    The body lives in tests/fixtures/upgrade/valid-inventory.json so the
    gate5 simulation mock (a separate script) consumes the identical bytes.
    """
    document = json.loads(
        (ROOT / "tests/fixtures/upgrade/valid-inventory.json").read_text()
    )
    document["schema"] = schema
    return document


def inventory_cbom_properties(document):
    """The inventory flow-through properties a non-vacuous cbom must carry."""
    observation = document["observation"]
    object_observations = document.get("object_observations")
    if object_observations is None:
        object_render = "absent"
    elif object_observations.get("status") == "populated":
        object_render = "populated"
    else:
        object_render = f"{object_observations.get('status')} ({object_observations.get('reason')})"
    properties = {
        "p11scope:source_schema": "p11scope/inventory/v1",
        "p11scope:scope": document["scope"],
        "p11scope:window": (
            f"{observation['started_ns']}..{observation['ended_ns']} (CLOCK_MONOTONIC ns)"
        ),
        "p11scope:passes": str(observation["passes"]),
        "p11scope:source_gaps": str(len(document["gaps"])),
        "p11scope:established_source_query": "0",
        "p11scope:established_source_creation_success": "0",
        "p11scope:established_source_unrecorded": "0",
        "p11scope:object_observations": object_render,
        "p11scope:applications": "1",
        "p11scope:providers": str(len(document["modules"])),
        "p11scope:algorithms": "1",
        "p11scope:keys": "0",
        "p11scope:callers_unknown_exe": "0",
        "p11scope:mechanisms_unnamed": "0",
        "p11scope:mechanisms_unknown_primitive": "0",
        "p11scope:keys_unknown_size": "0",
        "p11scope:keys_unknown_type": "0",
    }
    subjects = sorted({row["subject"] for row in document["gaps"]})
    if subjects:
        properties["p11scope:gap_subjects"] = ",".join(subjects)
    return properties


def diff_snapshot(source):
    """One substantive typed diff snapshot projection for harness documents.

    Snapshots and evidence pools are projections, not copies: label
    references become pool indices, coverage moves out of entries, and
    report-only rows (ids, incarnations, launched_by, initialize,
    mechanisms/operations details) are dropped, mirroring the producer.
    """
    caller_index = {row["id"]: pos for pos, row in enumerate(source["callers"])}
    module_index = {row["id"]: pos for pos, row in enumerate(source["modules"])}
    callers = []
    for row in source["callers"]:
        callers.append({
            "pid": row["pid"],
            "start_time": row["start_time"],
            "start_time_unit": row["start_time_unit"],
            "image": {
                "authority": row["image"]["authority"],
                "exe": copy.deepcopy(row["image"]["exe"]),
                "exec_observed": row["image"]["exec_observed"],
            },
            "lifecycle": row["lifecycle"],
            "lifecycle_reason": row.get("lifecycle_reason"),
            "first_seen_ns": row["first_seen_ns"],
            "last_seen_ns": row["last_seen_ns"],
            "retired": row["retired"],
        })
    modules = []
    for row in source["modules"]:
        # Pool departed rows are flattened aggregates, not copies: counts and
        # reason maps only. The gate never relates pool aggregates back to
        # the report fold, so the double carries minimal valid content.
        departed = row.get("departed_use")
        pool_departed = None
        if departed is not None:
            pool_departed = {
                "callers": 1,
                "edges": 1,
                "entries": {
                    "count": 0, "counted": 0, "forwarding": 0, "in_flight": 0,
                    "logical": 0, "lossy": 0, "observation": {},
                    "pid_exit": 0, "saturated": 0, "unknown": {},
                    "watched_no_use": 0, "witnessed": 0,
                },
                "identities": [],
                "identities_dropped": 0,
                "identities_saturated": False,
                "instances": {
                    "api_returns": 0, "api_returns_saturated_rows": 0,
                    "folded": 0, "historical_only_returns": 0,
                    "loss_reasons": {}, "lossy_rows": 0, "null_reasons": 0,
                    "observed": 0, "reasons": {}, "retired": 0,
                    "settled_live": 0, "uncertain": 0,
                },
                "mapping": {
                    "deep_scan": 0, "ended": 0, "interruptions": 0,
                    "mapped": 0, "maps_match": 0, "reasons": {},
                    "reasons_overflow": 0, "uncertain": 0,
                },
                "mechanisms": [],
                "mechs_overflow": 0,
                "mechs_overflow_calls": 0,
                "mechs_overflow_errors": 0,
                "operations": None,
                "semantic_labels": {},
            }
        modules.append({
            "paths": list(row["paths"]),
            "identity": copy.deepcopy(row["identity"]),
            "admission": copy.deepcopy(row["admission"]),
            "lifecycle": row["lifecycle"],
            "unloaded_observed": row["unloaded_observed"],
            "unbound_use": copy.deepcopy(row["unbound_use"]),
            "departed_use": pool_departed,
        })
    edges = []
    for row in source["edges"]:
        entries = copy.deepcopy(row["entries"])
        coverage = entries.pop("coverage")
        edges.append({
            "caller": caller_index[row["caller"]],
            "module": module_index[row["module"]],
            "mapping": copy.deepcopy(row["mapping"]),
            "entries": entries,
            "coverage": coverage,
            "semantics": row["semantics"],
        })
    gaps = []
    for row in source["gaps"]:
        gaps.append({
            "caller": None if row["caller"] is None else caller_index[row["caller"]],
            "module": None if row["module"] is None else module_index[row["module"]],
            "pid": row["pid"],
            "subject": row["subject"],
            "reason": row["reason"],
            "budget": copy.deepcopy(row["budget"]),
            "repeats": row["repeats"],
        })
    budgets = {
        key: {
            subkey: source["budgets"][key][subkey]
            for subkey in ("limit", "occupied", "refused")
        }
        for key in (
            "callers", "modules", "edges", "endpoints", "inventory_endpoints",
            "inventory_attach_modules",
        )
    }
    budgets.update({
        key: copy.deepcopy(source["budgets"][key])
        for key in ("counters", "semantic_state", "retained_history", "native_preadmission")
    })
    return {
        "scope": source["scope"],
        "clock": dict(source["clock"]),
        "observation": {
            "started_ns": source["observation"]["started_ns"],
            "ended_ns": source["observation"]["ended_ns"],
            "passes": source["observation"]["passes"],
            "usage_feed": source["observation"]["usage_feed"],
            "lane": "native",
            "settlement": "unsettled",
            "retirement": "closed",
            "attach": {
                "selection": "auto",
                "mechanism": "uprobe-multi",
                "fallback": None,
                "scope_filter": "bpf-cgroup",
            },
            "lifecycle": {
                "records": 0,
                "ring_loss": 0,
                "malformed": 0,
                "failed_quanta": 0,
                "recovery_rescans": 0,
            },
            "native_witnesses": dict(source["observation"]["native_witnesses"]),
        },
        "pid_namespace": dict(source["pid_namespace"]),
        "scope_completeness": "unknown",
        "reported_gaps": len(source["gaps"]),
        "suppressed_gaps": source["gaps_suppressed"],
        "refusals": {
            "reported_budget_gaps": 0,
            "budget_counters": {
                "callers": 0,
                "edges": 0,
                "endpoints": 0,
                "inventory_attach_modules": 0,
                "inventory_endpoints": 0,
                "modules": 0,
                "native_preadmission": 0,
                "semantic_state": 0,
            },
        },
        "budgets": budgets,
        "loss_evidence": {
            "lifecycle": {
                "records": 0,
                "ring_loss": 0,
                "malformed": 0,
                "failed_quanta": 0,
                "recovery_rescans": 0,
            },
            "native_witnesses": dict(source["observation"]["native_witnesses"]),
        },
        "gaps": gaps,
        "evidence": {
            "callers": callers,
            "modules": modules,
            "edges": edges,
            "caller_occurrences": list(range(len(source["callers"]))),
            "module_occurrences": list(range(len(source["modules"]))),
            "edge_occurrences": list(range(len(source["edges"]))),
        },
    }


def valid_diff_document(before_source, after_source):
    """One typed nonzero-projection diff consistent with the two inputs."""
    same = before_source == after_source
    application_path = before_source["callers"][0]["image"]["exe"]["path"]
    digest = before_source["modules"][0]["identity"]["sha256"]
    changes = [] if same else ["caller_population"]
    application_changes = [] if same else [
        {
            "key": {"exe_path_ref": 0, "sha256": digest},
            "presence": "both",
            "changes": changes,
            "before": [0],
            "after": [0],
            "before_population": {"callers": [0], "modules": [0]},
            "after_population": {"callers": [0], "modules": [0]},
        }
    ]
    return {
        "schema": "p11scope/inventory-diff/v1",
        "before": diff_snapshot(before_source),
        "after": diff_snapshot(after_source),
        "comparison": {
            "host_relation": "unknown",
            "boot_relation": "unknown",
            "process_continuity": "unknown",
            "physical_continuity": "unknown",
            "counter_relation": "independent_windows",
            "scope_relation": (
                "same_recorded_label"
                if before_source["scope"] == after_source["scope"]
                else "different_recorded_labels"
            ),
            "application_paths": [application_path],
        },
        "summary": {
            "application_groups_compared": 1,
            "application_groups_changed": 0 if same else 1,
            "content_both": 1,
            "content_before_only": 0,
            "content_after_only": 0,
            "module_paths_changed": 0,
            "unresolved_observations": 0,
        },
        "module_contents": [
            {"key": {"sha256": digest}, "presence": "both", "changes": [], "before": [0], "after": [0]}
        ],
        "application_changes": application_changes,
        "module_path_changes": [],
        "unresolved": [],
        "limitations": [
            "absence_is_not_removal",
            "application_groups_use_recorded_paths",
            "counts_are_independent_windows",
            "host_boot_continuity_unknown",
            "physical_continuity_unknown",
            "process_continuity_unknown",
            "scope_completeness_unknown",
            "semantic_details_not_compared",
        ],
    }


MOCK_PACKAGE_TOOL = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


def package_version(path):
    version = ""
    for line in Path(path).read_text().splitlines():
        if line.startswith("version="):
            version = line.split("=", 1)[1]
            break
    side = "old" if version == "0.7.1" else "new"
    if control(f"metadata-{side}-empty"):
        return ""
    return version


def state_dir():
    return Path(os.environ["SIM_STATE_DIR"])


def control(name):
    path = state_dir() / name
    return path if path.exists() else None


def control_text(name):
    path = control(name)
    return path.read_text().strip() if path else None


def install_package(package):
    state = state_dir()
    version = package_version(package)
    side = "old" if version == "0.7.1" else "new"
    if control(f"fail-{side}-install"):
        return 1
    (state / "installed-version").write_text(version)
    binary = Path(os.environ["SIM_P11SCOPE_BIN"])
    if control(f"skip-binary-{side}"):
        binary.unlink(missing_ok=True)
    else:
        binary.parent.mkdir(parents=True, exist_ok=True)
        fixture = Path(os.environ["SIM_FIXTURE_DIR"]) / "valid-inventory.json"
        inventory = json.loads(fixture.read_text())
        correct_inventory = json.dumps(inventory, separators=(",", ":"))
        wrong_inventory = json.dumps({**inventory, "schema": "wrong/schema"}, separators=(",", ":"))
        script = """#!/bin/sh
state=${SIM_STATE_DIR:?}
version="$(cat "$state/installed-version" 2>/dev/null || printf unknown)"
case "$version" in
  0.7.1) side=old ;;
  *) side=new ;;
esac
if [ -f "$state/binary-$side-version" ]; then
  version="$(cat "$state/binary-$side-version")"
fi
if [ "${1:-}" = "--version" ]; then
  printf 'p11scope %s\n' "$version"
  exit 0
fi
if [ "${1:-}" = "doctor" ]; then
  rc=0
  [ -f "$state/doctor-$side-rc" ] && rc="$(cat "$state/doctor-$side-rc")"
  if [ ! -f "$state/doctor-$side-no-line" ]; then
    printf 'Doctor: fake\n'
  fi
  exit "$rc"
fi
if [ "${1:-}" = "inventory" ]; then
  out=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -o) out="$2"; shift 2 ;;
      --output-owner) shift 2 ;;
      *) shift ;;
    esac
  done
  [ -n "$out" ] || exit 2
  if [ -f "$state/capture-$side-sparse" ]; then
    printf '{"schema":"p11scope/inventory/v1"}\n' >"$out"
  elif [ -f "$state/capture-$side-wrong-schema" ]; then
    printf '%s\n' '__WRONG_INVENTORY__' >"$out"
  else
    printf '%s\n' '__CORRECT_INVENTORY__' >"$out"
  fi
  rc=0
  [ -f "$state/capture-$side-rc" ] && rc="$(cat "$state/capture-$side-rc")"
  exit "$rc"
fi
exit 2
""".replace("__CORRECT_INVENTORY__", correct_inventory).replace("__WRONG_INVENTORY__", wrong_inventory)
        binary.write_text(script)
        binary.chmod(0o755)
    if version != "0.7.1":
        fmt = os.environ["SIM_FORMAT"]
        if control("corrupt-recovery-on-new"):
            recovery = Path(os.environ["SIM_RECOVERY_DIR"]) / f"gate5-canary-{fmt}"
            with recovery.open("a") as handle:
                handle.write("corrupted\n")
        if control("corrupt-report-on-new"):
            report = Path(os.environ["SIM_WORKDIR"]) / f"operator-report-{fmt}.json"
            with report.open("a") as handle:
                handle.write("corrupted\n")
    return 0


WART_11_RPM = [
    "/usr/share/doc/p11scope",
    "/usr/share/doc/p11scope/LICENSES",
    "/usr/share/doc/p11scope/notices",
    "/usr/share/doc/p11scope/notices/licenses",
    "/usr/share/doc/p11scope/notices/licenses/cargo",
    "/usr/share/doc/p11scope/notices/licenses/package-files",
    "/usr/share/doc/p11scope/notices/licenses/rust-1.99.1",
    "/usr/share/doc/p11scope/notices/licenses/rust-1.99.1/licenses",
    "/usr/share/doc/p11scope/notices/licenses/rust-nightly-2026-05-20",
    "/usr/share/doc/p11scope/notices/licenses/rust-nightly-2026-05-20/licenses",
    "/usr/share/doc/p11scope/notices/licenses/upstream",
]
SHARED_PREFIXES = ["/", "/usr", "/usr/bin", "/usr/share", "/usr/share/doc"]
# dpkg -L spells the filesystem root "/." (rpm lists payload entries only).
DEB_OWNED_ROOT = "/."
OWNED_FILES = [
    "/usr/bin/p11scope",
    "/usr/bin/p11scope-discover",
    "/usr/share/doc/p11scope/COPYRIGHT",
]


def owned_paths():
    fmt = os.environ["SIM_FORMAT"]
    if fmt == "deb":
        paths = [DEB_OWNED_ROOT] + SHARED_PREFIXES[1:] + OWNED_FILES + WART_11_RPM
    else:
        paths = ["/usr/share/doc/p11scope"] + OWNED_FILES
    sys.stdout.write("\n".join(paths) + "\n")
    return 0


def uninstall_package():
    state = state_dir()
    try:
        installed = (state / "installed-version").read_text().strip()
    except OSError:
        return 1
    side = "old" if installed == "0.7.1" else "new"
    if control(f"fail-uninstall-{side}"):
        return 1
    fake = Path(os.environ["SIM_FAKE_ROOT"])
    fmt = os.environ["SIM_FORMAT"]
    if fmt == "rpm":
        for entry in WART_11_RPM:
            if control(f"drop-wart-{side}") and entry.endswith("/upstream"):
                continue
            (fake / entry.lstrip("/")).mkdir(parents=True, exist_ok=True)
        if control(f"leftover-extra-{side}"):
            (fake / "usr/share/doc/p11scope/EXTRA").mkdir(parents=True, exist_ok=True)
    if control(f"leftover-file-{side}"):
        target = fake / "usr/share/doc/p11scope/STRAY"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("stray")
    if not control(f"keep-binary-{side}"):
        Path(os.environ["SIM_P11SCOPE_BIN"]).unlink(missing_ok=True)
    (state / "installed-version").write_text("")
    return 0


def query_version():
    try:
        version = (state_dir() / "installed-version").read_text().strip()
    except OSError:
        return 1
    side = "old" if version == "0.7.1" else "new"
    if control(f"query-{side}-missing"):
        return 1
    version = control_text(f"query-{side}-version") or version
    sys.stdout.write(version)
    return 0


def main():
    name = Path(sys.argv[0]).name
    args = sys.argv[1:]
    if name == "dpkg-deb":
        print(package_version(args[1]))
        return 0
    if name == "dpkg-query":
        if "-L" in args:
            return owned_paths()
        return query_version()
    if name == "dpkg":
        if args and args[0] == "-r":
            return uninstall_package()
        return install_package(args[-1])
    if name == "rpm":
        if "-qp" in args:
            print(package_version(args[-1]))
            return 0
        if "-ql" in args:
            return owned_paths()
        if "-q" in args:
            return query_version()
        if "-e" in args:
            return uninstall_package()
        return install_package(args[-1])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
'''

MOCK_SHA256SUM = r'''#!/usr/bin/env python3
import hashlib
import os
import sys
from pathlib import Path

path = sys.argv[1]
old_pkg = os.environ.get("SIM_OLD_PKG", "")
if old_pkg and path == old_pkg:
    tampered = (Path(os.environ["SIM_STATE_DIR"]) / "tamper-old-package").exists()
    digest = "0" * 64 if tampered else os.environ["SIM_OLD_PIN"]
    print(digest + "  " + path)
    raise SystemExit(0)
state = Path(os.environ["SIM_STATE_DIR"])
try:
    installed = (state / "installed-version").read_text().strip()
except OSError:
    installed = ""
side = "old" if installed == "0.7.1" else "new"
name = Path(path).name
if name.startswith("gate5-canary-"):
    kind = "recovery"
elif name.startswith("operator-report-"):
    kind = "report"
else:
    kind = ""
empty = bool(kind) and (
    (state / f"sha-empty-{kind}-{side}").exists()
    or (state / f"sha-empty-{kind}-both").exists()
)
if empty:
    print("  " + path)
else:
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    print(f"{digest}  {path}")
'''


def write_gate5_mockbin(mockbin: Path) -> None:
    mockbin.mkdir()
    write_executable(mockbin / "id", "#!/bin/sh\nprintf '0\\n'\n")
    for name in ("dpkg-deb", "dpkg", "dpkg-query", "rpm"):
        write_executable(mockbin / name, MOCK_PACKAGE_TOOL)
    write_executable(mockbin / "sha256sum", MOCK_SHA256SUM)


def run_gate5_simulation(format_name="deb", old_version="0.7.1", new_version="0.7.2", controls=None):
    """Run gate5's production main flow against a typed fake package root.

    The seam is shell-internal sourcing, not a production environment override:
    the script still defaults to /usr/bin/p11scope whenever executed normally.
    The fake package manager installs a fake binary into the test-only path
    assigned after sourcing, so every sequencing and comparison statement in
    the gate body executes behaviorally without touching the host.
    """
    controls = controls or {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        mockbin = base / "mockbin"
        state = base / "state"
        workdir = base / "work"
        recovery = base / "recovery"
        fakeroot = base / "fakeroot"
        binary = base / "root" / "p11scope"
        state.mkdir()
        fakeroot.mkdir()
        write_gate5_mockbin(mockbin)
        suffix = "deb" if format_name == "deb" else "rpm"
        old = base / f"old.{suffix}"
        new = base / f"new.{suffix}"
        old.write_text(f"version={old_version}\n")
        new.write_text(f"version={new_version}\n")
        for name, content in controls.items():
            (state / name).write_text(content)
        runner = base / "run-simulated-gate.sh"
        runner.write_text(
            "#!/bin/bash\n"
            "set -eu\n"
            f"export PATH={shlex.quote(str(mockbin))}:\"$PATH\"\n"
            f"export SIM_STATE_DIR={shlex.quote(str(state))}\n"
            f"export SIM_WORKDIR={shlex.quote(str(workdir))}\n"
            f"export SIM_RECOVERY_DIR={shlex.quote(str(recovery))}\n"
            f"export SIM_P11SCOPE_BIN={shlex.quote(str(binary))}\n"
            f"export SIM_FAKE_ROOT={shlex.quote(str(fakeroot))}\n"
            f"export SIM_FIXTURE_DIR={shlex.quote(str(ROOT / 'tests/fixtures/upgrade'))}\n"
            f"export SIM_OLD_PKG={shlex.quote(str(old))}\n"
            f"export SIM_OLD_PIN={shlex.quote(artifact_pin(f'v071-{format_name}'))}\n"
            f"export SIM_FORMAT={shlex.quote(format_name)}\n"
            "P11SCOPE_GATE5_SOURCE_ONLY=1\n"
            f". {shlex.quote(str(GATE5))}\n"
            'P11SCOPE_BIN="$SIM_P11SCOPE_BIN"\n'
            'recovery_dir() { printf \'%s\' "$SIM_RECOVERY_DIR"; }\n'
            'package_fs_root() { printf \'%s\' "$SIM_FAKE_ROOT"; }\n'
            f"main --format {shlex.quote(format_name)}"
            f" --old {shlex.quote(str(old))}"
            f" --new {shlex.quote(str(new))}"
            f" --workdir {shlex.quote(str(workdir))}\n"
        )
        completed = subprocess.run(
            ["bash", str(runner)], capture_output=True, text=True, timeout=20
        )
        result_path = workdir / "gate5-result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else None
        return completed.returncode, completed.stderr, result


def q5(value=""):
    return types.SimpleNamespace(returncode=0, stdout=value, stderr="")


class UpgradeGate6Harness:
    """Synthetic typed-input harness for gate6 run_gate wiring."""

    def __init__(self, gate6):
        self.gate6 = gate6

    @staticmethod
    def base_inventory():
        return substantive_inventory()

    @classmethod
    def good_old_doc(cls):
        return cls.base_inventory()

    @classmethod
    def good_new_doc(cls):
        doc = cls.base_inventory()
        budgets = doc["budgets"]
        budgets["callers"].update(
            {"late_refused": 0, "retired": 0, "retired_with_calls": 0}
        )
        budgets["departed_use"] = {"identities_dropped": 0, "mech_overflow": 0}
        budgets["edges"].update({"folded": 0, "folded_entries": 0})
        budgets["instances"].update({"folded": 0})
        budgets["native_departed"] = {
            "exec_prune_overflow": 0,
            "pair_dropped_base": 0,
            "pair_dropped_rows": 0,
            "pair_prune_overflow": 0,
        }
        doc["modules"][0]["departed_use"] = {
            "callers": 1,
            "edges": 1,
            "entries": {
                "count": 0,
                "coverage": {
                    # Coherent measured fold: the one folded edge was
                    # counted (observed with zero entries), so the
                    # positive flow exercises the measured path.
                    "counted": 1,
                    "first_min_ns": None,
                    "lossy": 0,
                    "pid_exit": 0,
                    "since_min_ns": None,
                    "unknown": {},
                    "until_max_ns": None,
                    "watched_no_use": 0,
                    "witnessed": 0,
                },
                "first_min_ns": None,
                "forwarding": 0,
                "in_flight": 0,
                "last_max_ns": None,
                "logical": 0,
                "observation": {},
                "saturated": 0,
            },
            "first_ns": 100,
            "folded_instances": [],
            "folded_instances_dropped": 0,
            "folded_instances_saturated": False,
            "identities": [
                {
                    "authority": "scan_pinned",
                    "caller": "c99",
                    "exe": {
                        "dev": 8,
                        "ino": 999,
                        "mtime_secs": 1700000000,
                        "mtime_nanos": 0,
                        "path": "/driver",
                    },
                    "exec_observed": True,
                    "first_seen_ns": 110,
                    "incarnation": 0,
                    "last_seen_ns": 190,
                    "lifecycle": "exited",
                    "lifecycle_reason": "process exited (pid names no live process)",
                    "metadata_status": None,
                    "pid": 4243,
                    "start_time": 987700,
                }
            ],
            "identities_dropped": 0,
            "identities_saturated": False,
            "instances": {
                "api_returns": 0,
                "api_returns_saturated_rows": 0,
                "first_min_ns": None,
                "folded": 0,
                "historical_only_returns": 0,
                "last_max_ns": None,
                "loss_reasons": {},
                "lossy_rows": 0,
                "null_reasons": 0,
                "observed": 0,
                "reasons": {},
                "retired": 0,
                "settled_live": 0,
                "uncertain": 0,
            },
            "mapping": {
                "evidence": {"deep_scan": 0, "maps_match": 0},
                "first_min_ns": 0,
                "interruptions": 0,
                "last_max_ns": 0,
                "reasons": {},
                "reasons_overflow": 0,
                "state": {"ended": 0, "mapped": 0, "uncertain": 0},
            },
            "mechanisms": None,
            "mechanisms_overflow": {"calls": 0, "errors": 0, "mechs": 0},
            "operations": None,
            "semantics": {"labels": {}},
        }
        doc["observation"]["semantic_capture"].update(
            {"length_insert_failures": 0, "length_stash_mismatches": 0}
        )
        return doc

    @staticmethod
    def object_schema(live):
        # Wiring double only (explicitly open): strict shape is proven by
        # validator-level tests and the live gate on real schemas.
        reasons = ["none"] + ([LIVE_TEST_REASON] if live else [])
        return {"properties": {"reason": {"enum": reasons}}, "additionalProperties": True}

    @classmethod
    def object_schema_sets(cls, old_live=False, new_live=True):
        names = [f"schema-{version}" for version in ("v1", "v2", "v3", "v4", "v5")]
        return (
            {name: cls.object_schema(old_live) for name in names},
            {name: cls.object_schema(new_live) for name in names},
        )

    @staticmethod
    def profile_schemas():
        # Wiring doubles only (explicitly open): strict shape is proven by
        # validator-level tests and the live gate on real schemas.
        old = {"properties": {"evidence": {"required": ["completeness"]}}, "allOf": [],
               "additionalProperties": True}
        new = {
            "properties": {
                "evidence": {
                    "required": [
                        "completeness",
                        "coverage_retired_slots",
                        "pid_descendant_gaps_admitted",
                        "member_stop_attached",
                        "member_stop_unattached",
                    ]
                }
            },
            "allOf": [
                {
                    "then": {
                        "properties": {
                            "evidence": {
                                "required": [
                                    "pid_descendant_gaps_admitted",
                                    "member_stop_attached",
                                    "member_stop_unattached",
                                ]
                            }
                        }
                    }
                }
            ],
            "additionalProperties": True,
        }
        return old, new

    @staticmethod
    def cbom(properties, bom_format="CycloneDX"):
        def count(name):
            try:
                return int(properties.get(name, "0"))
            except ValueError:
                return 0

        components = []
        for index in range(count("p11scope:applications")):
            components.append(
                {
                    "type": "application",
                    "bom-ref": f"p11scope:caller:{index}",
                    "name": f"application-{index}",
                }
            )
        for index in range(count("p11scope:providers")):
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"p11scope:module:{index}",
                    "name": f"provider-{index}.so",
                }
            )
        for index in range(count("p11scope:algorithms")):
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"p11scope:mechanism:{index}",
                    "name": f"mechanism-{index}",
                }
            )
        for index in range(count("p11scope:keys")):
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"p11scope:key:{index}",
                    "name": f"key-{index}",
                }
            )
        dependencies = [
            {"ref": component["bom-ref"], "dependsOn": []}
            for component in components
        ]
        return {
            "bomFormat": bom_format,
            "specVersion": "1.6",
            "metadata": {
                "properties": [
                    {"name": name, "value": value} for name, value in properties.items()
                ]
            },
            "components": components,
            "dependencies": dependencies,
        }

    def fake_completed(self, command, rc=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(command, rc, stdout=stdout, stderr=stderr)

    def default_run(self, command, timeout=120, **kwargs):
        del timeout, kwargs
        text_command = [str(part) for part in command]
        if "cbom" in text_command:
            source = Path(text_command[text_command.index("cbom") + 1])
            properties = {}
            if source.name == "injected-live-joint.json":
                injected = json.loads(source.read_text())
                properties = inventory_cbom_properties(injected)
                reason = injected["object_observations"]["reason"]
                properties["p11scope:object_observations"] = f"partial ({reason})"
            elif source.name == "v071-inventory.json":
                source_document = json.loads(source.read_text())
                if "observation" in source_document:
                    properties = inventory_cbom_properties(source_document)
            elif source.name == "v071-observed-profile.json":
                profile = json.loads(source.read_text())
                window = self.gate6.profile_window(profile)
                properties.update(
                    {
                        "p11scope:source_schema": "p11scope/observed-profile/v3",
                        "p11scope:window": window,
                        "p11scope:profile_note": (
                            "profile input: mechanisms are capture-global, without "
                            "caller, usage-edge or key linkage"
                        ),
                        "p11scope:completeness": "COMPLETE",
                        "p11scope:providers": "1",
                        "p11scope:algorithms": "1",
                        "p11scope:applications": "0",
                        "p11scope:keys": "0",
                        "p11scope:object_observations": "absent",
                        "p11scope:established_source_query": "0",
                        "p11scope:established_source_creation_success": "0",
                        "p11scope:established_source_unrecorded": "0",
                        "p11scope:callers_unknown_exe": "0",
                        "p11scope:mechanisms_unnamed": "0",
                        "p11scope:mechanisms_unknown_primitive": "0",
                        "p11scope:keys_unknown_size": "0",
                        "p11scope:keys_unknown_type": "0",
                    }
                )
            return self.fake_completed(
                command, stdout=json.dumps(self.cbom(properties))
            )
        if "diff" in text_command:
            index = text_command.index("diff")
            before = json.loads(Path(text_command[index + 1]).read_text())
            after = json.loads(Path(text_command[index + 2]).read_text())
            if "scope" in before and "scope" in after:
                document = valid_diff_document(before, after)
            else:
                document = {
                    "schema": "p11scope/inventory-diff/v1",
                    "application_changes": [],
                    "module_path_changes": [],
                }
            return self.fake_completed(command, stdout=json.dumps(document))
        return self.fake_completed(command, rc=2, stderr="unexpected command")

    def run_faulted(self, fault, command, timeout=120, **kwargs):
        text_command = [str(part) for part in command]
        cbom_source = ""
        if "cbom" in text_command:
            cbom_source = Path(text_command[text_command.index("cbom") + 1]).name
        if fault == "cbom-old-rc" and cbom_source == "v071-inventory.json":
            return self.fake_completed(command, rc=1, stderr="injected cbom failure")
        if fault == "diff-old-new-rc" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] != text_command[index + 2]:
                return self.fake_completed(command, rc=1, stderr="injected diff failure")
        completed = self.default_run(command, timeout=timeout, **kwargs)
        document = None
        if completed.stdout:
            try:
                document = json.loads(completed.stdout)
            except json.JSONDecodeError:
                document = None
        if document is None:
            return completed
        if fault == "cbom-old-sparse" and cbom_source == "v071-inventory.json":
            document = {"bomFormat": "CycloneDX", "metadata": {"properties": []}}
        elif fault == "diff-zero-sparse" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] == text_command[index + 2]:
                document = {
                    "schema": "p11scope/inventory-diff/v1",
                    "application_changes": [],
                    "module_path_changes": [],
                }
        elif fault == "diff-new-sparse" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] != text_command[index + 2]:
                document = {
                    "schema": "p11scope/inventory-diff/v1",
                    "application_changes": [{"change": "expected"}],
                    "module_path_changes": [],
                }
        elif fault == "b2-sparse-cbom" and cbom_source == "injected-live-joint.json":
            document = {
                "bomFormat": "CycloneDX",
                "metadata": {
                    "properties": [
                        {
                            "name": "p11scope:object_observations",
                            "value": "partial (live_joint_feed_absent)",
                        }
                    ]
                },
            }
        elif fault == "b3-sparse-cbom" and cbom_source == "v071-observed-profile.json":
            properties = document["metadata"]["properties"]
            document = {"bomFormat": "CycloneDX", "metadata": {"properties": properties}}
        elif fault == "cbom-old-bad-format" and cbom_source == "v071-inventory.json":
            document["bomFormat"] = "wrong"
        elif fault == "diff-zero-wrong-schema" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] == text_command[index + 2]:
                document["schema"] = "other"
        elif fault == "diff-new-wrong-schema" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] != text_command[index + 2]:
                document["schema"] = "other"
        elif fault == "diff-new-lifecycle" and "diff" in text_command:
            index = text_command.index("diff")
            if text_command[index + 1] != text_command[index + 2]:
                document["application_changes"][0]["changes"].append("lifecycle")
        elif fault == "b2-wrong-render" and cbom_source == "injected-live-joint.json":
            for prop in document["metadata"]["properties"]:
                if prop["name"] == "p11scope:object_observations":
                    prop["value"] = "partial (bogus_reason)"
        elif fault == "b3-wrong-render" and cbom_source == "v071-observed-profile.json":
            for prop in document["metadata"]["properties"]:
                if prop["name"] == "p11scope:window":
                    prop["value"] = "wrong-window"
        return self.fake_completed(command, stdout=json.dumps(document))

    def execute(
        self,
        *,
        fault=None,
        old_doc=None,
        new_doc=None,
        missing_old_binary=False,
        generate_error="",
        module_present=True,
        object_old_live=False,
        object_new_live=True,
        profile_schema_mutator=None,
        profile_fixture_shape_valid=True,
        verify_pins=False,
        tamper_fixture=False,
    ):
        gate6 = self.gate6
        old_doc = copy.deepcopy(old_doc) if old_doc is not None else self.good_old_doc()
        new_doc = copy.deepcopy(new_doc) if new_doc is not None else self.good_new_doc()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workdir = base / "work"
            workdir.mkdir()
            old_binary = base / "old-p11scope"
            new_binary = base / "new-p11scope"
            if not missing_old_binary:
                write_executable(old_binary, "#!/bin/sh\nexit 2\n")
            write_executable(new_binary, "#!/bin/sh\nexit 2\n")
            args = types.SimpleNamespace(old_binary=old_binary, new_binary=new_binary)
            result = gate6.initial_result()
            old_schemas, new_schemas = self.object_schema_sets(
                old_live=object_old_live, new_live=object_new_live
            )
            old_profile, new_profile = self.profile_schemas()
            if profile_schema_mutator:
                old_profile, new_profile = profile_schema_mutator(old_profile, new_profile)

            def fake_generate(binary, output, module):
                del module
                if generate_error:
                    return generate_error
                document = old_doc if binary == old_binary else new_doc
                output.write_text(json.dumps(document))
                return ""

            fixture_path = gate6.PROFILE_FIXTURE
            if not profile_fixture_shape_valid:
                fixture_doc = json.loads(gate6.PROFILE_FIXTURE.read_text())
                fixture_doc["capture"]["modules"] = []
                fixture_path = base / "v071-observed-profile.json"
                fixture_path.write_text(json.dumps(fixture_doc))
            if tamper_fixture:
                fixture_path = base / "v071-observed-profile.json"
                fixture_path.write_text(
                    gate6.PROFILE_FIXTURE.read_text() + " "
                )

            def fake_run(command, timeout=120, **kwargs):
                if fault:
                    return self.run_faulted(fault, command, timeout=timeout, **kwargs)
                return self.default_run(command, timeout=timeout, **kwargs)

            patches = [
                mock.patch.object(
                    gate6,
                    "find_provider_module",
                    return_value="/fake/libsofthsm2.so" if module_present else None,
                ),
                mock.patch.object(gate6, "generate_scan_report", side_effect=fake_generate),
                mock.patch.object(gate6, "generate_manifest", return_value=""),
                mock.patch.object(gate6, "run", side_effect=fake_run),
                mock.patch.object(
                    gate6,
                    "load_object_observation_schemas",
                    return_value=(old_schemas, new_schemas),
                ),
                mock.patch.object(
                    gate6,
                    "load_profile_schemas",
                    return_value=(old_profile, new_profile),
                ),
                mock.patch.object(gate6, "PROFILE_FIXTURE", fixture_path),
            ]
            if not verify_pins:
                patches.append(
                    mock.patch.object(gate6, "verify_artifact_pin", return_value="")
                )
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                with contextlib.redirect_stdout(io.StringIO()):
                    try:
                        code = gate6.run_gate(args, workdir, result)
                    except gate6.GateFailure:
                        code = 1
            return code, result


LIVE_TEST_REASON = "live_joint_feed_absent"


class UpgradeGate5ContractTests(unittest.TestCase):
    def run_gate5(self, *args, env=None):
        return subprocess.run(
            ["bash", str(GATE5), *args],
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
        )

    def test_gate5_rejects_bad_format(self):
        r = self.run_gate5("--format", "bogus")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--format", r.stderr)

    def test_gate5_missing_option_values_are_usage_errors(self):
        for option in ("--format", "--old", "--new", "--workdir", "--self-test"):
            with self.subTest(option=option):
                r = self.run_gate5(option)
                self.assertEqual(r.returncode, 2)
                self.assertIn(f"{option} requires a value", r.stderr)

    def test_gate5_self_test_cannot_combine_with_gate_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_gate5("--self-test", tmp, "--format", "deb")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--self-test cannot be combined with gate arguments", r.stderr)

    def test_gate5_requires_gate_arguments(self):
        r = self.run_gate5("--format", "deb")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--old/--new/--workdir required", r.stderr)

    def test_gate5_source_only_environment_cannot_bypass_normal_execution(self):
        env = dict(os.environ, P11SCOPE_GATE5_SOURCE_ONLY="1")
        r = self.run_gate5("--format", "bogus", env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--format", r.stderr)

    def test_gate5_refuses_valid_args_without_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            old = base / "old.pkg"
            new = base / "new.pkg"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            workdir = base / "work"
            mockbin = base / "mockbin"
            mockbin.mkdir()
            write_executable(mockbin / "id", "#!/bin/sh\nprintf '1000\n'\n")
            env = dict(os.environ, PATH=f"{mockbin}:{os.environ['PATH']}")
            r = self.run_gate5(
                "--format", "deb",
                "--old", str(old),
                "--new", str(new),
                "--workdir", str(workdir),
                env=env,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn("must run as root", r.stderr)
            self.assertFalse(workdir.exists(), "refusal must happen before any install state")

    def test_gate5_self_test_emits_exact_typed_results(self):
        expected_keys = {
            "gate",
            "format",
            "status",
            "old_package",
            "new_package",
            "binary",
            "old_version",
            "new_version",
            "old_package_version",
            "new_package_version",
            "old_installed_package_version",
            "new_installed_package_version",
            "doctor_old_rc",
            "doctor_new_rc",
            "doctor_rcs_equal",
            "capture_old_rc",
            "capture_new_rc",
            "canary_recovery_sha_before",
            "canary_recovery_sha_after",
            "canary_report_sha_before",
            "canary_report_sha_after",
            "canary_survived",
            "old_leftover_dirs",
            "new_leftover_dirs",
            "fail_reason",
            "synthetic",
        }
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_gate5("--self-test", tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            passed = json.loads((Path(tmp) / "gate5-result.json").read_text())
            mismatch = json.loads((Path(tmp) / "gate5-result-mismatch.json").read_text())
            doctor_mismatch = json.loads(
                (Path(tmp) / "gate5-result-doctor-mismatch.json").read_text()
            )
            empty_hash = json.loads((Path(tmp) / "gate5-result-empty-hash.json").read_text())
        self.assertEqual(set(passed), expected_keys)
        self.assertEqual(set(mismatch), expected_keys)
        self.assertEqual(set(doctor_mismatch), expected_keys)
        self.assertEqual(set(empty_hash), expected_keys)
        self.assertEqual(passed["gate"], 5)
        self.assertEqual(passed["binary"], "/usr/bin/p11scope")
        self.assertEqual(passed["status"], "pass")
        self.assertEqual(passed["old_installed_package_version"], "0.7.1")
        self.assertEqual(passed["new_installed_package_version"], "0.7.2")
        self.assertIs(passed["doctor_rcs_equal"], True)
        self.assertIs(passed["canary_survived"], True)
        self.assertIs(passed["synthetic"], True)
        self.assertEqual(len(passed["canary_recovery_sha_before"]), 64)
        self.assertEqual(passed["old_leftover_dirs"], ["/w/old-a", "/w/old-b"])
        self.assertEqual(passed["new_leftover_dirs"], [])
        self.assertIs(mismatch["canary_survived"], False)
        self.assertNotEqual(
            mismatch["canary_report_sha_before"], mismatch["canary_report_sha_after"]
        )
        self.assertIs(doctor_mismatch["doctor_rcs_equal"], False)
        self.assertNotEqual(doctor_mismatch["doctor_old_rc"], doctor_mismatch["doctor_new_rc"])
        self.assertEqual(empty_hash["canary_recovery_sha_before"], "")
        self.assertEqual(empty_hash["canary_recovery_sha_after"], "")
        self.assertIs(empty_hash["canary_survived"], False)


WART_11_RPM = [
    "/usr/share/doc/p11scope",
    "/usr/share/doc/p11scope/LICENSES",
    "/usr/share/doc/p11scope/notices",
    "/usr/share/doc/p11scope/notices/licenses",
    "/usr/share/doc/p11scope/notices/licenses/cargo",
    "/usr/share/doc/p11scope/notices/licenses/package-files",
    "/usr/share/doc/p11scope/notices/licenses/rust-1.99.1",
    "/usr/share/doc/p11scope/notices/licenses/rust-1.99.1/licenses",
    "/usr/share/doc/p11scope/notices/licenses/rust-nightly-2026-05-20",
    "/usr/share/doc/p11scope/notices/licenses/rust-nightly-2026-05-20/licenses",
    "/usr/share/doc/p11scope/notices/licenses/upstream",
]


class UpgradeGate5SimulationTests(unittest.TestCase):
    def test_simulated_upgrade_passes_for_both_package_formats(self):
        for format_name in ("deb", "rpm"):
            with self.subTest(format=format_name):
                controls = {}
                if format_name == "rpm":
                    controls = {"doctor-old-rc": "1", "doctor-new-rc": "1"}
                rc, stderr, result = run_gate5_simulation(format_name, controls=controls)
                self.assertEqual(rc, 0, stderr)
                self.assertIsNotNone(result)
                self.assertEqual(result["status"], "pass")
                self.assertIs(result["synthetic"], False)
                self.assertEqual(result["format"], format_name)
                self.assertEqual(result["old_version"], "0.7.1")
                self.assertEqual(result["new_version"], "0.7.2")
                self.assertEqual(result["old_package_version"], "0.7.1")
                self.assertEqual(result["new_package_version"], "0.7.2")
                self.assertEqual(result["old_installed_package_version"], "0.7.1")
                self.assertEqual(result["new_installed_package_version"], "0.7.2")
                self.assertIs(result["doctor_rcs_equal"], True)
                self.assertEqual(result["capture_old_rc"], 0)
                self.assertEqual(result["capture_new_rc"], 0)
                self.assertIs(result["canary_survived"], True)
                self.assertEqual(len(result["canary_recovery_sha_before"]), 64)
                self.assertEqual(
                    result["canary_recovery_sha_before"],
                    result["canary_recovery_sha_after"],
                )
                self.assertEqual(
                    result["canary_report_sha_before"],
                    result["canary_report_sha_after"],
                )
                if format_name == "rpm":
                    self.assertEqual(result["old_leftover_dirs"], WART_11_RPM)
                    self.assertEqual(result["new_leftover_dirs"], WART_11_RPM)
                else:
                    self.assertEqual(result["old_leftover_dirs"], [])
                    self.assertEqual(result["new_leftover_dirs"], [])

    def test_simulated_wrong_package_negative_is_exact_for_both_formats(self):
        for format_name in ("deb", "rpm"):
            with self.subTest(format=format_name):
                rc, stderr, result = run_gate5_simulation(format_name, new_version="0.7.1")
                self.assertEqual(rc, 1, stderr)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(
                    result["fail_reason"],
                    "new package is version '0.7.1', expected '0.7.2'",
                )

    def test_simulated_negative_controls_fail_with_exact_typed_reasons(self):
        scenarios = [
            (
                "old metadata empty",
                {},
                {"metadata-old-empty": ""},
                "old package metadata version empty",
            ),
            (
                "new metadata empty",
                {},
                {"metadata-new-empty": ""},
                "new package metadata version empty",
            ),
            (
                "missing old installed binary",
                {},
                {"skip-binary-old": ""},
                "installed old binary missing at {binary}",
            ),
            (
                "missing new installed binary",
                {},
                {"skip-binary-new": ""},
                "installed new binary missing at {binary}",
            ),
            (
                "old package manager missing",
                {},
                {"query-old-missing": ""},
                "package manager does not list old p11scope",
            ),
            (
                "new package manager missing",
                {},
                {"query-new-missing": ""},
                "package manager does not list new p11scope",
            ),
            (
                "wrong_old_metadata",
                {"old_version": "0.7.2"},
                {},
                "old package is version '0.7.2', expected 0.7.1",
            ),
            (
                "fail_old_install",
                {},
                {"fail-old-install": ""},
                "old install failed (see install-old.log)",
            ),
            (
                "wrong_old_binary_version",
                {},
                {"binary-old-version": "0.7.2"},
                "old version is '0.7.2', expected 0.7.1",
            ),
            (
                "old_package_manager_mismatch",
                {},
                {"query-old-version": "0.7.0"},
                "old package manager version is '0.7.0', expected '0.7.1'",
            ),
            (
                "old doctor invalid",
                {},
                {"doctor-old-rc": "2"},
                "old doctor rc=2",
            ),
            (
                "old doctor missing line",
                {},
                {"doctor-old-no-line": ""},
                "old doctor output has no Doctor line",
            ),
            (
                "old capture rc",
                {},
                {"capture-old-rc": "1"},
                "old capture rc=1",
            ),
            (
                "old capture schema",
                {},
                {"capture-old-wrong-schema": ""},
                "old capture report failed typed validation: inventory schema: $.schema: value 'wrong/schema' is not const 'p11scope/inventory/v1'",
            ),
            (
                "old capture sparse",
                {},
                {"capture-old-sparse": ""},
                "old capture report failed typed validation: inventory schema: $: required property 'budgets' is missing",
            ),
            (
                "empty recovery hash before",
                {},
                {"sha-empty-recovery-old": ""},
                "recovery canary hash empty before upgrade",
            ),
            (
                "empty report hash before",
                {},
                {"sha-empty-report-old": ""},
                "saved-report canary hash empty before upgrade",
            ),
            (
                "fail_new_install",
                {},
                {"fail-new-install": ""},
                "upgrade to new failed (see install-new.log)",
            ),
            (
                "wrong_new_binary_version",
                {},
                {"binary-new-version": "0.7.1"},
                "new version is '0.7.1', expected '0.7.2'",
            ),
            (
                "new doctor invalid",
                {},
                {"doctor-new-rc": "2"},
                "new doctor rc=2",
            ),
            (
                "new doctor missing line",
                {},
                {"doctor-new-no-line": ""},
                "new doctor output has no Doctor line",
            ),
            (
                "doctor flip",
                {},
                {"doctor-new-rc": "1"},
                "doctor rc flipped 0->1",
            ),
            (
                "new capture rc",
                {},
                {"capture-new-rc": "1"},
                "new capture rc=1",
            ),
            (
                "new capture schema",
                {},
                {"capture-new-wrong-schema": ""},
                "new capture report failed typed validation: inventory schema: $.schema: value 'wrong/schema' is not const 'p11scope/inventory/v1'",
            ),
            (
                "new capture sparse",
                {},
                {"capture-new-sparse": ""},
                "new capture report failed typed validation: inventory schema: $: required property 'budgets' is missing",
            ),
            (
                "empty recovery hash after",
                {},
                {"sha-empty-recovery-new": ""},
                "recovery canary hash empty after upgrade",
            ),
            (
                "empty report hash after",
                {},
                {"sha-empty-report-new": ""},
                "saved-report canary hash empty after upgrade",
            ),
            (
                "corrupt recovery canary",
                {},
                {"corrupt-recovery-on-new": ""},
                "recovery canary changed across upgrade",
            ),
            (
                "corrupt report canary",
                {},
                {"corrupt-report-on-new": ""},
                "saved-report canary changed across upgrade",
            ),
            (
                "new package manager mismatch",
                {},
                {"query-new-version": "0.7.1"},
                "package manager version is '0.7.1', expected '0.7.2'",
            ),
            (
                "old uninstall rc",
                {},
                {"fail-uninstall-old": ""},
                "old uninstall failed (see uninstall-old.log)",
            ),
            (
                "old binary survives uninstall",
                {},
                {"keep-binary-old": ""},
                "installed binary survived old uninstall",
            ),
            (
                "old leftover file",
                {},
                {"leftover-file-old": ""},
                "old uninstall left unexpected content: /usr/share/doc/p11scope/STRAY",
            ),
            (
                "new leftover file",
                {},
                {"leftover-file-new": ""},
                "new uninstall left unexpected content: /usr/share/doc/p11scope/STRAY",
            ),
            (
                "old package tampered",
                {},
                {"tamper-old-package": ""},
                f"refused: old deb package sha256 mismatch: got {'0' * 64}, "
                f"want {artifact_pin('v071-deb')}",
            ),
        ]
        for name, kwargs, controls, expected_reason in scenarios:
            with self.subTest(name=name):
                rc, stderr, result = run_gate5_simulation(
                    "deb", controls=controls, **kwargs
                )
                self.assertEqual(rc, 1, stderr)
                self.assertIsNotNone(result, stderr)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(
                    result["fail_reason"],
                    expected_reason.format(binary=result["binary"]),
                )

    def test_simulated_rpm_uninstall_negatives_fail_with_exact_typed_reasons(self):
        want = " ".join(WART_11_RPM)
        extra = " ".join([WART_11_RPM[0], "/usr/share/doc/p11scope/EXTRA"] + WART_11_RPM[1:])
        missing = " ".join(w for w in WART_11_RPM if not w.endswith("/upstream"))
        scenarios = [
            (
                "old uninstall rc",
                {"fail-uninstall-old": ""},
                "old uninstall failed (see uninstall-old.log)",
            ),
            (
                "old leftover file",
                {"leftover-file-old": ""},
                "old uninstall left unexpected content: /usr/share/doc/p11scope/STRAY",
            ),
            (
                "old leftover extra dir",
                {"leftover-extra-old": ""},
                f"old uninstall leftovers differ: got [{extra}] want [{want}]",
            ),
            (
                "old missing wart dir",
                {"drop-wart-old": ""},
                f"old uninstall leftovers differ: got [{missing}] want [{want}]",
            ),
            (
                "new leftover file",
                {"leftover-file-new": ""},
                "new uninstall left unexpected content: /usr/share/doc/p11scope/STRAY",
            ),
            (
                "old package tampered",
                {"tamper-old-package": ""},
                f"refused: old rpm package sha256 mismatch: got {'0' * 64}, "
                f"want {artifact_pin('v071-rpm')}",
            ),
        ]
        for name, controls, expected_reason in scenarios:
            with self.subTest(name=name):
                rc, stderr, result = run_gate5_simulation("rpm", controls=controls)
                self.assertEqual(rc, 1, stderr)
                self.assertIsNotNone(result, stderr)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["fail_reason"], expected_reason)


class UpgradeArtifactValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validation = load_artifact_validation()

    def test_inventory_validator_accepts_substantive_typed_document(self):
        self.assertEqual(self.validation.inventory_errors(substantive_inventory()), [])

    def test_inventory_validator_rejects_schema_only_document_typed_exactly(self):
        errors = self.validation.inventory_errors({"schema": "p11scope/inventory/v1"})
        self.assertEqual(errors[0], "inventory schema: $: required property 'budgets' is missing")
        self.assertIn("inventory schema: $: required property 'gaps_suppressed' is missing", errors)

    def test_inventory_positive_payload_rejects_hollow_typed_rows(self):
        document = substantive_inventory()
        document["callers"] = []
        errors = self.validation.inventory_errors(document)
        self.assertIn("inventory positive payload: fewer than one typed caller row", errors)
        document = substantive_inventory()
        document["modules"] = []
        errors = self.validation.inventory_errors(document)
        self.assertIn("inventory positive payload: fewer than one typed provider row", errors)
        document = substantive_inventory()
        document["edges"] = []
        errors = self.validation.inventory_errors(document)
        self.assertIn("inventory positive payload: fewer than one typed caller-provider edge", errors)

    def test_artifact_pins_manifest_matches_recorded_hashes(self):
        manifest = json.loads(
            (ROOT / "scripts/upgrade-artifact-pins.json").read_text()
        )
        self.assertEqual(
            set(manifest["artifacts"]),
            {"v071-deb", "v071-rpm", "v071-observer-binary", "v071-profile-fixture"},
        )
        self.assertEqual(
            manifest["artifacts"]["v071-deb"]["sha256"],
            "f7bf841286c7308fe9b998f04a5158ea2b95c2a5912171d51487208fc5ce74a6",
        )
        self.assertEqual(
            manifest["artifacts"]["v071-rpm"]["sha256"],
            "fac6918c0bb01100d295e71a8cac0c65a6d28b12a1d8041bf8b25b7636ef8fd3",
        )
        self.assertEqual(
            manifest["artifacts"]["v071-observer-binary"]["sha256"],
            "36a0f57e4ad4d425bdf5cfb4ef5277937beeda3f5f87bf180545d5e7068fa17e",
        )
        self.assertEqual(
            manifest["artifacts"]["v071-profile-fixture"]["sha256"],
            "50d3c8276231131cffb339508007d943663e112d48c48e974b0944adc0db6766",
        )

    def test_cbom_exact_format_and_version_refusals(self):
        source = substantive_inventory()
        document = UpgradeGate6Harness.cbom(inventory_cbom_properties(source))
        bad_format = copy.deepcopy(document)
        bad_format["bomFormat"] = "SPDX"
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_format, source),
            ["refused: cbom bomFormat 'SPDX' is not 'CycloneDX'"],
        )
        bad_version = copy.deepcopy(document)
        bad_version["specVersion"] = "1.5"
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_version, source),
            ["refused: cbom specVersion '1.5' is not '1.6'"],
        )

    def test_diff_positive_payload_rejects_hollow_caller_projections(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        for side in ("before", "after"):
            hollow = copy.deepcopy(document)
            hollow[side]["evidence"]["caller_occurrences"] = []
            errors = self.validation.diff_errors(hollow, before, after)
            self.assertIn(f"diff positive payload: fewer than one caller occurrence on {side}", errors)

    def test_inventory_validator_rejects_each_required_root_field(self):
        schema = json.loads((ROOT / "docs/schema/inventory-v1.schema.json").read_text())
        required = schema["required"]
        self.assertEqual(len(required), 17)
        for key in required:
            with self.subTest(key=key):
                document = substantive_inventory()
                del document[key]
                self.assertIn(
                    f"inventory schema: $: required property '{key}' is missing",
                    self.validation.inventory_errors(document),
                )

    def test_cbom_inventory_validator_requires_source_flow_through(self):
        source = substantive_inventory()
        cbom = UpgradeGate6Harness.cbom(inventory_cbom_properties(source))
        self.assertEqual(self.validation.cbom_inventory_errors(cbom, source), [])
        hollow = copy.deepcopy(cbom)
        hollow["components"] = []
        hollow["dependencies"] = []
        hollow_errors = self.validation.cbom_inventory_errors(hollow, source)
        self.assertIn("cbom positive payload: fewer than one typed applications component", hollow_errors)
        self.assertIn("cbom positive payload: fewer than one typed providers component", hollow_errors)
        self.assertIn("cbom positive payload: fewer than one typed algorithms component", hollow_errors)
        present = {"applications": 1, "providers": 1, "algorithms": 1, "keys": 0}
        for name, count in present.items():
            with self.subTest(name=name):
                mismatched = copy.deepcopy(cbom)
                for prop in mismatched["metadata"]["properties"]:
                    if prop["name"] == f"p11scope:{name}":
                        prop["value"] = "2"
                mismatch_errors = self.validation.cbom_inventory_errors(mismatched, source)
                self.assertIn(
                    f"cbom positive payload: 'p11scope:{name}' is 2, "
                    f"but {count} typed component(s) are present",
                    mismatch_errors,
                )
        non_decimal = copy.deepcopy(cbom)
        for prop in non_decimal["metadata"]["properties"]:
            if prop["name"] == "p11scope:established_source_query":
                prop["value"] = "x"
        self.assertIn(
            "cbom property 'p11scope:established_source_query' is 'x', expected a decimal count",
            self.validation.cbom_inventory_errors(non_decimal, source),
        )
        sparse = {"bomFormat": "CycloneDX", "metadata": {"properties": []}}
        self.assertEqual(
            self.validation.cbom_inventory_errors(sparse, source)[0],
            "refused: cbom specVersion None is not '1.6'",
        )

    def test_cbom_inventory_validator_rejects_schema_violations(self):
        source = substantive_inventory()
        cbom = UpgradeGate6Harness.cbom(inventory_cbom_properties(source))
        bad_name = copy.deepcopy(cbom)
        bad_name["components"][0]["name"] = 123
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_name, source),
            ["cbom schema: $.components[0].name: is integer, expected string"],
        )
        bad_dependency = copy.deepcopy(cbom)
        bad_dependency["dependencies"][0] = {"ref": 123}
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_dependency, source),
            ["cbom schema: $.dependencies[0].ref: is integer, expected string"],
        )

    def test_diff_validator_requires_ten_field_typed_document_and_consistency(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        self.assertEqual(self.validation.diff_errors(document, before, after), [])
        schema = json.loads((ROOT / "docs/schema/inventory-diff-v1.schema.json").read_text())
        required = schema["required"]
        self.assertEqual(len(required), 10)
        for key in required:
            with self.subTest(key=key):
                sparse = copy.deepcopy(document)
                del sparse[key]
                self.assertIn(
                    f"diff schema: $: required property '{key}' is missing",
                    self.validation.diff_errors(sparse, before, after),
                )
        mistyped = copy.deepcopy(document)
        mistyped["summary"]["module_paths_changed"] = "1"
        self.assertEqual(
            self.validation.diff_errors(mistyped, before, after),
            ["diff schema: $.summary.module_paths_changed: is string, expected integer"],
        )
        inconsistent = copy.deepcopy(document)
        inconsistent["before"]["scope"] = "other"
        self.assertIn(
            "diff before.scope is 'other', expected 'system'",
            self.validation.diff_errors(inconsistent, before, after),
        )

    def test_inventory_validator_rejects_wrong_nested_types(self):
        document = substantive_inventory()
        document["observation"]["passes"] = "2"
        self.assertIn(
            "inventory schema: $.observation.passes: is string, expected integer",
            self.validation.inventory_errors(document),
        )

        document = substantive_inventory()
        document["modules"][0]["paths"] = None
        self.assertIn(
            "inventory schema: $.modules[0].paths: is null, expected array",
            self.validation.inventory_errors(document),
        )

        document = substantive_inventory()
        document["gaps_suppressed"] = True
        self.assertIn(
            "inventory schema: $.gaps_suppressed: is boolean, expected integer",
            self.validation.inventory_errors(document),
        )

    def test_diff_validator_rejects_snapshot_inconsistent_with_source(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        document["before"]["observation"]["started_ns"] += 1
        self.assertIn(
            "diff before.observation.started_ns is 101, expected 100",
            self.validation.diff_errors(document, before, after),
        )

    def test_inventory_strict_mode_refuses_extra_wrongid_missing(self):
        document = substantive_inventory()
        extra = copy.deepcopy(document)
        extra["zzz_extra"] = 1
        self.assertIn(
            "inventory schema: $: additional property 'zzz_extra' is not allowed",
            self.validation.inventory_errors(extra),
        )
        nested = copy.deepcopy(document)
        nested["callers"][0]["zzz_extra"] = 1
        self.assertIn(
            "inventory schema: $.callers[0]: additional property 'zzz_extra' is not allowed",
            self.validation.inventory_errors(nested),
        )
        wrong_id = copy.deepcopy(document)
        wrong_id["schema"] = "wrong/schema"
        self.assertIn(
            "inventory schema: $.schema: value 'wrong/schema' is not const 'p11scope/inventory/v1'",
            self.validation.inventory_errors(wrong_id),
        )
        missing = copy.deepcopy(document)
        del missing["callers"][0]["pid"]
        self.assertIn(
            "inventory schema: $.callers[0]: required property 'pid' is missing",
            self.validation.inventory_errors(missing),
        )

    def test_object_observations_dispatch_refuses_unknown_version(self):
        self.assertIn(
            "refused: inventory object_observations version 99 has no shipped product schema",
            self.validation.object_observations_schema_errors({"version": 99}),
        )
        self.assertIn(
            "refused: inventory object_observations version 'x' has no shipped product schema",
            self.validation.object_observations_schema_errors({"version": "x"}),
        )

    def test_inventory_accepts_producer_grounded_nulls_and_conditionals(self):
        document = substantive_inventory()
        caller = document["callers"][0]
        caller["launched_by_gap"] = None
        caller["launched_by_unit"] = "user@1000.service"
        caller["launched_by"][0]["exe_gap"] = "exe unreadable"
        caller["launched_by"][0]["folded"] = 2
        caller["metadata"] = {
            "status": "pending", "reason": None, "revision": "0",
            "sample_started_ns": None, "sample_ended_ns": None, "validity": None,
            "cgroup": {"status": "unknown", "source": None, "directory_inode": None,
                       "mount_context": None, "reason": None},
            "container": {"status": "unknown", "source": None, "runtime": None,
                          "id": None, "reason": None},
            "pod": {"status": "unknown", "source": None, "uid": None, "reason": None},
        }
        module = document["modules"][0]
        module["provider_info"] = {
            "cryptoki_major": 2, "cryptoki_minor": 40,
            "manufacturer": "SoftHSM", "description": None,
            "flags": 0, "library_major": 2, "library_minor": 6,
        }
        module["initialize"]["last_error_rv"] = {"rv": 7, "rv_hex": "0x7", "name": None}
        document["edges"][0]["mechanisms"] = [{
            "mechanism": 1, "mechanism_hex": "0x1", "name": None,
            "operations": ["sign"], "calls": 2, "errors": 0, "last_seen_ns": 9,
            "evidence": {"functions": ["C_Sign"],
                         "returns": [{"rv": 0, "rv_hex": "0x0", "name": None}],
                         "truncated": False},
        }]
        document["edges"][0]["operations"] = {
            "calls": 2, "started": 2, "completed": 2, "cancelled": 0,
            "failed": 0, "unknown": 0, "orphans": 0, "dropped": 0,
            "last_seen_ns": 9, "active": [],
            "evidence": {"state_reconciliations": 0, "session_cancel_ambiguities": 0,
                         "session_cancel_unknown_flags": 0, "operation_state_imports": 0,
                         "auth_state_ambiguities": 0, "semantic_capture_failures": 0,
                         "async_duplicates": 0, "async_evictions": 0,
                         "unmatched_closes": 0},
        }
        document["provider_observations"] = {"version": 8, "tokens": [],
                                             "mechanisms": [], "gaps": []}
        document["excluded_modules"] = []
        document["unmatched_modules"] = []
        document["prearm"] = [{
            "path": "/x.so",
            "identity": {"device": {"major": 0, "minor": 0}, "inode": 1, "sha256": None},
            "mapped": False, "attached_at_ns": None,
            "watch": {"since_ns": None, "state": "armed"},
            "unobserved_windows": [{"start_ns": 0, "end_ns": 1, "reason": "late_discovery"}],
        }]
        self.assertEqual(self.validation.inventory_errors(document), [])

    def test_inventory_strict_mode_rejects_mistyped_nested_contract_fields(self):
        document = substantive_inventory()
        document["callers"][0]["image"]["exe"]["path"] = 42
        self.assertTrue(self.validation.inventory_errors(document))
        document = substantive_inventory()
        document["edges"][0]["entries"]["coverage"] = "x"
        self.assertTrue(self.validation.inventory_errors(document))
        document = substantive_inventory()
        document["object_observations"]["objects"] = ["x"]
        errors = self.validation.inventory_errors(document)
        self.assertTrue(errors)
        self.assertTrue(
            any("object_observations" in error for error in errors), errors
        )

    def test_diff_strict_mode_refuses_extra_wrongid_missing(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        extra = copy.deepcopy(document)
        extra["zzz_extra"] = 1
        self.assertIn(
            "diff schema: $: additional property 'zzz_extra' is not allowed",
            self.validation.diff_errors(extra, before, after),
        )
        nested = copy.deepcopy(document)
        nested["before"]["scope_completeness"] = "zzz"
        self.assertTrue(self.validation.diff_errors(nested, before, after))
        wrong_id = copy.deepcopy(document)
        wrong_id["schema"] = "wrong/schema"
        self.assertIn(
            "diff schema: $.schema: value 'wrong/schema' is not const 'p11scope/inventory-diff/v1'",
            self.validation.diff_errors(wrong_id, before, after),
        )
        missing = copy.deepcopy(document)
        del missing["comparison"]
        self.assertIn(
            "diff schema: $: required property 'comparison' is missing",
            self.validation.diff_errors(missing, before, after),
        )

    def test_diff_references_must_resolve_inside_pools(self):
        before = substantive_inventory()
        after = substantive_inventory()
        after["scope"] = "cgroup:/other"
        oob_app = copy.deepcopy(valid_diff_document(before, after))
        oob_app["application_changes"][0]["before"] = [99]
        self.assertIn(
            "diff application_changes[0].before reference 99 does not resolve within the before edges pool",
            self.validation.diff_errors(oob_app, before, after),
        )
        oob_module = copy.deepcopy(valid_diff_document(before, after))
        oob_module["module_contents"][0]["after"] = [7]
        self.assertIn(
            "diff module_contents[0].after reference 7 does not resolve within the after modules pool",
            self.validation.diff_errors(oob_module, before, after),
        )
        oob_pop = copy.deepcopy(valid_diff_document(before, after))
        oob_pop["application_changes"][0]["before_population"]["callers"] = [5]
        self.assertIn(
            "diff application_changes[0].before_population.callers reference 5 "
            "does not resolve within the before callers pool",
            self.validation.diff_errors(oob_pop, before, after),
        )
        oob_path = copy.deepcopy(valid_diff_document(before, after))
        oob_path["application_changes"][0]["key"]["exe_path_ref"] = 3
        self.assertIn(
            "diff application_changes[0].key.exe_path_ref 3 "
            "does not resolve to a compared application path",
            self.validation.diff_errors(oob_path, before, after),
        )

    def test_diff_ordering_must_hold(self):
        before = substantive_inventory()
        second = copy.deepcopy(before["callers"][0])
        second["id"] = "c1"
        second["pid"] = 4243
        before["callers"].append(second)
        after = substantive_inventory()
        unsorted_occ = copy.deepcopy(valid_diff_document(before, after))
        unsorted_occ["before"]["evidence"]["caller_occurrences"] = [1, 0]
        self.assertIn(
            "diff before.evidence.caller_occurrences is not sorted",
            self.validation.diff_errors(unsorted_occ, before, after),
        )
        unsorted_refs = copy.deepcopy(valid_diff_document(before, after))
        unsorted_refs["module_contents"][0]["after"] = [1, 0]
        self.assertIn(
            "diff module_contents[0].after references are not sorted",
            self.validation.diff_errors(unsorted_refs, before, after),
        )
        unsorted_paths = copy.deepcopy(valid_diff_document(before, after))
        unsorted_paths["comparison"]["application_paths"] = ["/b", "/a"]
        self.assertIn(
            "diff comparison.application_paths is not sorted",
            self.validation.diff_errors(unsorted_paths, before, after),
        )
        dup_paths = copy.deepcopy(valid_diff_document(before, after))
        dup_paths["comparison"]["application_paths"] = ["/a", "/a"]
        self.assertIn(
            "diff schema: $.comparison.application_paths: item 1 duplicates an earlier item",
            self.validation.diff_errors(dup_paths, before, after),
        )
        unsorted_changes = copy.deepcopy(valid_diff_document(before, after))
        unsorted_changes["application_changes"][0]["changes"] = ["entries", "caller_population"]
        self.assertIn(
            "diff application_changes[0].changes are not sorted",
            self.validation.diff_errors(unsorted_changes, before, after),
        )
        dup_changes = copy.deepcopy(valid_diff_document(before, after))
        dup_changes["application_changes"][0]["changes"] = ["entries", "entries"]
        self.assertIn(
            "diff schema: $.application_changes[0].changes: item 1 duplicates an earlier item",
            self.validation.diff_errors(dup_changes, before, after),
        )

    def test_diff_occurrence_cardinality_matches_sources(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        document["before"]["evidence"]["caller_occurrences"] = [0, 0]
        self.assertIn(
            "diff before.evidence.caller_occurrences has 2 references for 1 source callers",
            self.validation.diff_errors(document, before, after),
        )

    def test_diff_compared_group_positive_rule(self):
        before = substantive_inventory()
        after = substantive_inventory()
        unresolved_only = copy.deepcopy(valid_diff_document(before, after))
        unresolved_only["summary"]["application_groups_compared"] = 0
        unresolved_only["application_changes"] = []
        unresolved_only["module_contents"] = []
        unresolved_only["unresolved"] = [
            {"side": "before", "kind": "caller", "reasons": ["comparison skipped"]}
        ]
        self.assertIn(
            "diff positive payload: fewer than one compared application group",
            self.validation.diff_errors(unresolved_only, before, after),
        )
        lying = copy.deepcopy(valid_diff_document(before, after))
        lying["application_changes"] = []
        lying["module_contents"] = []
        self.assertIn(
            "diff positive payload: no compared group backed by rows on both sides",
            self.validation.diff_errors(lying, before, after),
        )

    def test_cbom_exact_format_and_version(self):
        source = substantive_inventory()
        cbom = UpgradeGate6Harness.cbom(inventory_cbom_properties(source))
        bad_format = copy.deepcopy(cbom)
        bad_format["bomFormat"] = "SPDX"
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_format, source),
            ["refused: cbom bomFormat 'SPDX' is not 'CycloneDX'"],
        )
        bad_version = copy.deepcopy(cbom)
        bad_version["specVersion"] = "1.5"
        self.assertEqual(
            self.validation.cbom_inventory_errors(bad_version, source),
            ["refused: cbom specVersion '1.5' is not '1.6'"],
        )
        nested_extra = copy.deepcopy(cbom)
        nested_extra["components"][0]["zzz_extra"] = 1
        self.assertIn(
            "cbom schema: $.components[0]: additional property 'zzz_extra' is not allowed",
            self.validation.cbom_inventory_errors(nested_extra, source),
        )
        missing_ref = copy.deepcopy(cbom)
        missing_ref["dependencies"] = [{"dependsOn": []}]
        self.assertTrue(self.validation.cbom_inventory_errors(missing_ref, source))


class UpgradeJsonSchemaConformanceTests(unittest.TestCase):
    """Compact conformance matrix for the stdlib schema evaluator.

    Covers every keyword the shipped schemas use (plus strict mode and the
    draft-07 $ref-sibling rule). Each row is (name, schema, instance,
    strict, expect_pass).
    """

    CASES = [
        ("type-string-pass", {"type": "string"}, "x", False, True),
        ("type-string-fail", {"type": "string"}, 1, False, False),
        ("type-integer-pass", {"type": "integer"}, 3, False, True),
        ("type-integer-bool-fail", {"type": "integer"}, True, False, False),
        ("type-boolean-bool-pass", {"type": "boolean"}, False, False, True),
        ("type-boolean-int-fail", {"type": "boolean"}, 1, False, False),
        ("type-null-pass", {"type": "null"}, None, False, True),
        ("type-null-fail", {"type": "null"}, 0, False, False),
        ("type-object-pass", {"type": "object"}, {"a": 1}, False, True),
        ("type-array-pass", {"type": "array"}, [1], False, True),
        ("required-pass", {"required": ["a"]}, {"a": 1, "b": 2}, False, True),
        ("required-fail", {"required": ["a"]}, {"b": 2}, False, False),
        ("properties-pass", {"properties": {"a": {"type": "integer"}}}, {"a": 1}, False, True),
        ("properties-fail", {"properties": {"a": {"type": "integer"}}}, {"a": "x"}, False, False),
        ("pattern-pass", {"patternProperties": {"^x-": {"type": "integer"}}}, {"x-a": 1}, False, True),
        ("pattern-fail", {"patternProperties": {"^x-": {"type": "integer"}}}, {"x-a": "s"}, False, False),
        ("pattern-nomatch", {"patternProperties": {"^x-": {"type": "integer"}}}, {"y": "s"}, False, True),
        ("additional-true", {"properties": {"a": {}}, "additionalProperties": True}, {"a": 1, "b": 2}, False, True),
        ("additional-false", {"properties": {"a": {}}, "additionalProperties": False}, {"a": 1, "b": 2}, False, False),
        ("additional-dict", {"properties": {"a": {}}, "additionalProperties": {"type": "integer"}}, {"a": 1, "b": "x"}, False, False),
        ("pattern-str-pass", {"pattern": "^[a-f0-9]+$"}, "ab12", False, True),
        ("pattern-str-fail", {"pattern": "^[a-f0-9]+$"}, "zz", False, False),
        ("pattern-null-pass", {"type": ["null", "string"], "pattern": "^a+$"}, None, False, True),
        ("minimum-null-pass", {"type": ["integer", "null"], "minimum": 0}, None, False, True),
        ("const-pass", {"const": "v1"}, "v1", False, True),
        ("const-fail", {"const": "v1"}, "v2", False, False),
        ("const-type-strict", {"const": 1}, True, False, False),
        ("enum-pass", {"enum": ["a", "b"]}, "b", False, True),
        ("enum-fail", {"enum": ["a", "b"]}, "c", False, False),
        ("minimum-pass", {"minimum": 2}, 2, False, True),
        ("minimum-fail", {"minimum": 2}, 1, False, False),
        ("maximum-fail", {"maximum": 2}, 3, False, False),
        ("minLength-fail", {"minLength": 2}, "x", False, False),
        ("maxLength-fail", {"maxLength": 2}, "xyz", False, False),
        ("items-pass", {"items": {"type": "integer"}}, [1, 2], False, True),
        ("items-fail", {"items": {"type": "integer"}}, [1, "x"], False, False),
        ("prefixItems-pass", {"prefixItems": [{"type": "integer"}]}, [1, "x"], False, True),
        ("prefixItems-fail", {"prefixItems": [{"type": "integer"}]}, ["x"], False, False),
        ("additionalItems-fail", {"prefixItems": [{"type": "integer"}], "additionalItems": {"type": "integer"}}, [1, "x"], False, False),
        ("dependentRequired-pass", {"dependentRequired": {"a": ["b"]}}, {"a": 1, "b": 2}, False, True),
        ("dependentRequired-fail", {"dependentRequired": {"a": ["b"]}}, {"a": 1}, False, False),
        ("contains-pass", {"contains": {"type": "integer"}}, ["x", 1], False, True),
        ("contains-fail", {"contains": {"type": "integer"}}, ["x"], False, False),
        ("exclusiveMinimum-fail", {"exclusiveMinimum": 2}, 2, False, False),
        ("multipleOf-fail", {"multipleOf": 2}, 3, False, False),
        ("uniqueItems-pass", {"uniqueItems": True}, [1, 2], False, True),
        ("uniqueItems-fail", {"uniqueItems": True}, [1, 1], False, False),
        ("allOf-pass", {"allOf": [{"type": "integer"}, {"minimum": 2}]}, 3, False, True),
        ("allOf-fail", {"allOf": [{"type": "integer"}, {"minimum": 2}]}, 1, False, False),
        ("anyOf-pass", {"anyOf": [{"type": "integer"}, {"type": "string"}]}, "x", False, True),
        ("anyOf-fail", {"anyOf": [{"type": "integer"}, {"type": "string"}]}, None, False, False),
        ("oneOf-pass", {"oneOf": [{"type": "integer"}, {"minimum": 5}]}, 3, False, True),
        ("oneOf-fail", {"oneOf": [{"type": "integer"}, {"minimum": 5}]}, 7, False, False),
        ("not-pass", {"not": {"type": "string"}}, 1, False, True),
        ("not-fail", {"not": {"type": "string"}}, "x", False, False),
        ("if-then-pass", {"if": {"properties": {"k": {"const": 1}}}, "then": {"required": ["v"]}}, {"k": 1, "v": 2}, False, True),
        ("if-then-fail", {"if": {"properties": {"k": {"const": 1}}}, "then": {"required": ["v"]}}, {"k": 1}, False, False),
        ("if-nomatch-skip", {"if": {"properties": {"k": {"const": 1}}}, "then": {"required": ["v"]}}, {"k": 2}, False, True),
        ("if-else-fail", {"if": {"properties": {"k": {"const": 1}}}, "else": {"required": ["v"]}}, {"k": 2}, False, False),
        ("ref-local", {"$defs": {"x": {"type": "integer"}}, "$ref": "#/$defs/x"}, 4, False, True),
        ("ref-local-fail", {"$defs": {"x": {"type": "integer"}}, "$ref": "#/$defs/x"}, "x", False, False),
        ("propertyNames-pass", {"propertyNames": {"enum": ["a"]}}, {"a": 1}, False, True),
        ("propertyNames-fail", {"propertyNames": {"enum": ["a"]}}, {"b": 1}, False, False),
        ("format-datetime-pass", {"format": "date-time"}, "2026-01-01T00:00:00Z", False, True),
        ("format-datetime-fail", {"format": "date-time"}, "not-a-date", False, False),
        ("format-unknown-ignored", {"format": "idn-email"}, "anything", False, True),
        ("strict-extra-fail", {"properties": {"a": {}}}, {"a": 1, "b": 2}, True, False),
        ("strict-extra-pass-nonstrict", {"properties": {"a": {}}}, {"a": 1, "b": 2}, False, True),
        ("strict-respects-explicit", {"properties": {"a": {}}, "additionalProperties": True}, {"a": 1, "b": 2}, True, True),
        ("strict-combinator-open", {"anyOf": [{"type": "object"}]}, {"a": 1}, True, True),
        ("ref-sibling-ignored", {"$ref": "#/$defs/x", "type": "string", "$defs": {"x": {"type": "integer"}}}, 5, False, True),
    ]

    def test_conformance_matrix(self):
        validation = load_artifact_validation()
        validate = validation.json_schema.validate
        for name, schema, instance, strict, expect_pass in self.CASES:
            with self.subTest(name=name):
                errors = validate(instance, schema, Path("conformance.json"), strict=strict)
                self.assertEqual(errors == [], expect_pass, errors[:1])

    def test_rejects_unsupported_keywords(self):
        validation = load_artifact_validation()
        validate = validation.json_schema.validate
        with self.assertRaises(validation.json_schema.SchemaError):
            validate({}, {"$dynamicRef": "#x"}, Path("conformance.json"))


class UpgradeTagSchemaMatrixTests(unittest.TestCase):
    """Real tag-vs-HEAD profile matrix (suite-only: needs the git history).

    Deliberately excluded from the mutation-sweep control set, which runs
    from a plain file copy without .git. The sweep's schema mutants are
    killed by the validator-level tests above instead.
    """

    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()
        cls.validation = load_artifact_validation()

    def test_fixture_passes_tag_schema(self):
        old_prof, _ = self.gate6.load_profile_schemas()
        document = json.loads(self.gate6.PROFILE_FIXTURE.read_text())
        errors = self.validation.json_schema.validate(
            document, old_prof,
            Path("v0.7.1:docs/schema/observed-profile-v3.schema.json"),
            strict=False,
        )
        self.assertEqual(errors, [])

    def test_tag_schema_refuses_wrongid_missing(self):
        old_prof, _ = self.gate6.load_profile_schemas()
        validate = self.validation.json_schema.validate
        tag_path = Path("v0.7.1:docs/schema/observed-profile-v3.schema.json")
        document = json.loads(self.gate6.PROFILE_FIXTURE.read_text())
        wrong_id = copy.deepcopy(document)
        wrong_id["schema"] = "wrong/schema"
        self.assertTrue(validate(wrong_id, old_prof, tag_path, strict=False))
        missing = copy.deepcopy(document)
        del missing["evidence"]
        self.assertTrue(validate(missing, old_prof, tag_path, strict=False))

    def test_head_schema_expected_failure_shape(self):
        _, new_prof = self.gate6.load_profile_schemas()
        document = json.loads(self.gate6.PROFILE_FIXTURE.read_text())
        errors = self.validation.json_schema.validate(
            document, new_prof,
            Path("docs/schema/observed-profile-v3.schema.json"),
            strict=False,
        )
        self.assertEqual(
            sorted(errors),
            sorted(
                f"$.evidence: required property '{name}' is missing"
                for name in (
                    "coverage_retired_slots",
                    "pid_descendant_gaps_admitted",
                    "member_stop_attached",
                    "member_stop_unattached",
                )
            ),
        )

    def test_head_schema_refuses_wrongid_missing(self):
        _, new_prof = self.gate6.load_profile_schemas()
        validate = self.validation.json_schema.validate
        head_path = Path("docs/schema/observed-profile-v3.schema.json")
        document = json.loads(self.gate6.PROFILE_FIXTURE.read_text())
        wrong_id = copy.deepcopy(document)
        wrong_id["schema"] = "wrong/schema"
        self.assertTrue(validate(wrong_id, new_prof, head_path, strict=False))
        missing = copy.deepcopy(document)
        del missing["evidence"]
        self.assertTrue(validate(missing, new_prof, head_path, strict=False))


class UpgradeGate6PureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()

    def test_initial_result_has_exact_breaking_list_and_shape(self):
        result = self.gate6.initial_result()
        self.assertEqual(set(result), {"gate", "status", "checks", "breaking", "notes", "fail_reason"})
        self.assertEqual(result["gate"], 6)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["checks"], {})
        self.assertEqual(result["fail_reason"], "")
        self.assertEqual(
            result["breaking"],
            ["departed_use", "live_joint_feed_absent", "profile_evidence_fields"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.gate6.emit(Path(tmp), result, 0)
            self.assertEqual(code, 0)
            emitted = json.loads((Path(tmp) / "gate6-result.json").read_text())
        self.assertEqual(emitted, result)

    def test_b1_and_additive_pins_are_exact(self):
        self.assertEqual(
            set(self.gate6.B1_KEYS),
            {
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
            },
        )
        self.assertEqual(
            set(self.gate6.ADDITIVE_KEYS),
            {
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
                "instance_reload_not_excluded",
                "instance_reload_not_excluded.continued_across_global",
                "instance_reload_not_excluded.joined_across_global",
                "instance_reload_not_excluded.identities",
                "instance_reload_not_excluded.identities[0].instances",
                "instance_reload_not_excluded.identities[0].module",
            },
        )

    def test_flatten_keys_unions_every_list_element(self):
        value = {
            "modules": [
                {"path": "one", "departed_use": None},
                {"path": "two", "extra": {"nested": 1}},
            ]
        }
        self.assertEqual(
            set(self.gate6.flatten_keys(value)),
            {
                "modules",
                "modules[0].path",
                "modules[0].departed_use",
                "modules[0].extra",
                "modules[0].extra.nested",
            },
        )

    def test_b1_delta_is_exact_in_both_directions(self):
        old_keys = {"schema", "modules[0].path"}
        good_new = old_keys | set(self.gate6.B1_KEYS) | set(self.gate6.ADDITIVE_KEYS)
        empty = {"v071": {}, "v072": {}}
        delta = self.gate6.evaluate_b1_delta(old_keys, good_new, empty)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["unexpected"], set())
        self.assertEqual(delta["missing_b1"], set())

        missing = self.gate6.evaluate_b1_delta(old_keys, good_new - {"budgets.edges.folded"}, empty)
        self.assertEqual(missing["missing_b1"], {"budgets.edges.folded"})
        unexpected = self.gate6.evaluate_b1_delta(old_keys, good_new | {"modules[0].surprise"}, empty)
        self.assertEqual(unexpected["unexpected"], {"modules[0].surprise"})
        removed = self.gate6.evaluate_b1_delta(old_keys, good_new - {"modules[0].path"}, empty)
        self.assertEqual(removed["removed"], {"modules[0].path"})

    def test_b1_timing_only_reason_absence_is_not_a_removal(self):
        prefix = "modules[0].unbound_use.reasons"
        vocabs = {"v071": {prefix: ["no_mapping_edge"]},
                  "v072": {prefix: ["no_mapping_edge"]}}
        delta = self.gate6.evaluate_b1_delta(
            {prefix, f"{prefix}.no_mapping_edge"}, {prefix}, vocabs)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["removed_unknown"], set())

    def test_b1_reason_node_absence_passes(self):
        prefix = "modules[0].unbound_use.reasons"
        vocabs = {"v071": {prefix: ["no_mapping_edge"]},
                  "v072": {prefix: ["no_mapping_edge"]}}
        delta = self.gate6.evaluate_b1_delta(
            {prefix, f"{prefix}.no_mapping_edge"}, set(), vocabs)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["removed_unknown"], set())

    def test_b1_dynamic_mapping_leaves_are_not_compared(self):
        old_keys = {"modules[0].departed_use.mapping.reasons",
                    "modules[0].departed_use.mapping.reasons.pid reused: x"}
        new_keys = set()
        delta = self.gate6.evaluate_b1_delta(
            old_keys, new_keys, {"v071": {}, "v072": {}})
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["removed_unknown"], set())

    def test_b1_unexpected_reason_fails(self):
        prefix = "modules[0].unbound_use.reasons"
        vocabs = {"v071": {prefix: []}, "v072": {prefix: []}}
        delta = self.gate6.evaluate_b1_delta(
            {prefix}, {prefix, f"{prefix}.zzz_new"}, vocabs)
        self.assertEqual(delta["unexpected"], {f"{prefix}.zzz_new"})

    def test_measured_child_entries_unknown_refuses(self):
        doc = parity_doc(n_callers=3, child_entries=0)
        for edge in doc["edges"]:
            if edge["caller"] != "c0":
                edge["entries"]["observation"] = "unknown (usage observation unavailable)"
        total, measured = self.gate6.measured_child_entries(doc)
        self.assertEqual(total, 0)
        self.assertFalse(measured)

    def test_measured_child_entries_observed_zero_passes(self):
        doc = parity_doc(n_callers=3, child_entries=0)
        for edge in doc["edges"]:
            if edge["caller"] != "c0":
                edge["entries"]["observation"] = "observed"
        total, measured = self.gate6.measured_child_entries(doc)
        self.assertEqual(total, 0)
        self.assertTrue(measured)

    def test_measured_child_entries_excludes_unknown(self):
        doc = parity_doc(n_callers=3, child_entries=0)
        edges = [e for e in doc["edges"] if e["caller"] != "c0"]
        edges[0]["entries"].update({"observation": "observed", "count": 10})
        edges[1]["entries"].update(
            {"observation": "unknown (usage observation lossy)", "count": 99})
        total, measured = self.gate6.measured_child_entries(doc)
        self.assertEqual(total, 10)
        self.assertTrue(measured)

    def test_measured_child_entries_vacuous_without_children(self):
        total, measured = self.gate6.measured_child_entries(
            parity_doc(n_callers=1))
        self.assertEqual((total, measured), (0, True))

    def test_measured_child_entries_departed_measured(self):
        doc = parity_doc(n_callers=1, folded_callers=2)
        doc["modules"][0]["departed_use"]["entries"]["coverage"] = {
            "counted": 2, "witnessed": 0, "watched_no_use": 0}
        doc["modules"][0]["departed_use"]["entries"]["count"] = 7
        total, measured = self.gate6.measured_child_entries(doc)
        self.assertEqual((total, measured), (7, True))

    def test_measured_child_entries_departed_unmeasured(self):
        doc = parity_doc(n_callers=1, folded_callers=2)
        doc["modules"][0]["departed_use"]["entries"]["coverage"] = {
            "counted": 0, "witnessed": 0, "watched_no_use": 0}
        doc["modules"][0]["departed_use"]["entries"]["count"] = 0
        total, measured = self.gate6.measured_child_entries(doc)
        self.assertEqual((total, measured), (0, False))

    def test_b1_vocabularies_match_across_eras(self):
        committed = json.loads(self.gate6.VOCABULARIES_MANIFEST.read_text())
        for prefix, labels in committed["v072"].items():
            self.assertEqual(sorted(labels), sorted(committed["v071"][prefix]))

    def test_admission_parity_folded_counts_close(self):
        old = parity_doc(n_callers=11, child_entries=0)
        new = parity_doc(n_callers=2, child_entries=0, folded_callers=9)
        for doc in (old, new):
            for edge in doc["edges"]:
                edge["entries"]["observation"] = "observed"
        ok, detail = self.gate6.admission_parity(old, new)
        self.assertTrue(ok, detail)

    def test_admission_parity_shortfall_names_missing(self):
        old = parity_doc(n_callers=11, child_entries=0)
        new = parity_doc(n_callers=2, child_entries=0, folded_callers=8)
        ok, detail = self.gate6.admission_parity(old, new)
        self.assertFalse(ok)
        self.assertIn("missing=1", detail)

    def test_admission_parity_entries_shortfall_fails(self):
        old = parity_doc(n_callers=11, child_entries=10)
        new = parity_doc(n_callers=2, child_entries=0, folded_callers=9,
                         folded_entries=5)
        for doc in (old, new):
            for edge in doc["edges"]:
                edge["entries"]["observation"] = "observed"
        ok, detail = self.gate6.admission_parity(old, new)
        self.assertFalse(ok)
        self.assertIn("entry shortfall", detail)

    def test_admission_parity_entries_up_passes(self):
        old = parity_doc(n_callers=11, child_entries=0)
        new = parity_doc(n_callers=2, child_entries=0, folded_callers=9,
                         folded_entries=64)
        for doc in (old, new):
            for edge in doc["edges"]:
                edge["entries"]["observation"] = "observed"
        ok, detail = self.gate6.admission_parity(old, new)
        self.assertTrue(ok, detail)

    def test_admission_parity_unmeasured_oracle_refuses(self):
        old = parity_doc(n_callers=11, child_entries=0)
        new = parity_doc(n_callers=2, child_entries=0, folded_callers=9)
        ok, detail = self.gate6.admission_parity(old, new)
        self.assertFalse(ok)
        self.assertIn("entry oracle not measured", detail)

    def test_b1_vocab_removed_unexercised_fails(self):
        prefix = "modules[0].unbound_use.reasons"
        removed = self.gate6.vocab_removed_labels(
            {prefix: ["gone"]}, {prefix: []})
        self.assertEqual(removed, {f"{prefix}.gone"})

    def test_b1_vocab_removed_equal_passes(self):
        prefix = "modules[0].unbound_use.reasons"
        labels = ["a", "b"]
        removed = self.gate6.vocab_removed_labels(
            {prefix: labels}, {prefix: list(labels)})
        self.assertEqual(removed, set())

    def test_b1_vocabularies_loader_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.json"
            vocabs, error = self.gate6.load_reason_vocabularies(missing)
            self.assertIsNone(vocabs)
            self.assertTrue(error)
            garbage = Path(tmp) / "garbage.json"
            garbage.write_text("{nope")
            vocabs, error = self.gate6.load_reason_vocabularies(garbage)
            self.assertIsNone(vocabs)
            self.assertTrue(error)
            nonobject = Path(tmp) / "nonobject.json"
            nonobject.write_text("[1, 2]")
            vocabs, error = self.gate6.load_reason_vocabularies(nonobject)
            self.assertIsNone(vocabs)
            self.assertTrue(error)
            mismatch = Path(tmp) / "mismatch.json"
            mismatch.write_text(json.dumps({"v071": {}, "v072": {}}))
            vocabs, error = self.gate6.load_reason_vocabularies(mismatch)
            self.assertIsNone(vocabs)
            self.assertTrue(error)
            nonstrings = Path(tmp) / "nonstrings.json"
            bad = {era: {prefix: [1] for prefix in self.gate6.REASON_MAP_PREFIXES}
                   for era in ("v071", "v072")}
            nonstrings.write_text(json.dumps(bad))
            vocabs, error = self.gate6.load_reason_vocabularies(nonstrings)
            self.assertIsNone(vocabs)
            self.assertTrue(error)
            vocabs, error = self.gate6.load_reason_vocabularies()
            self.assertEqual(error, "")
            self.assertEqual(set(vocabs), {"v071", "v072"})

    def test_b1_removed_reason_fails(self):
        vocabs = {"v071": {"modules[0].unbound_use.reasons": ["gone"]},
                  "v072": {"modules[0].unbound_use.reasons": []}}
        delta = self.gate6.evaluate_b1_delta(
            {"modules[0].unbound_use.reasons",
             "modules[0].unbound_use.reasons.gone"},
            {"modules[0].unbound_use.reasons"}, vocabs)
        self.assertEqual(delta["removed"],
                         {"modules[0].unbound_use.reasons.gone"})

    def test_b1_renamed_reason_fails(self):
        vocabs = {"v071": {"modules[0].unbound_use.reasons": ["old_name"]},
                  "v072": {"modules[0].unbound_use.reasons": ["new_name"]}}
        delta = self.gate6.evaluate_b1_delta(
            {"modules[0].unbound_use.reasons",
             "modules[0].unbound_use.reasons.old_name"},
            {"modules[0].unbound_use.reasons"}, vocabs)
        self.assertEqual(delta["removed"],
                         {"modules[0].unbound_use.reasons.old_name"})

    def test_b1_unknown_reason_fails_closed(self):
        vocabs = {"v071": {"modules[0].unbound_use.reasons": []},
                  "v072": {"modules[0].unbound_use.reasons": []}}
        delta = self.gate6.evaluate_b1_delta(
            {"modules[0].unbound_use.reasons",
             "modules[0].unbound_use.reasons.zzz_forged"},
            {"modules[0].unbound_use.reasons"}, vocabs)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["removed_unknown"],
                         {"modules[0].unbound_use.reasons.zzz_forged"})

    def test_b1_admission_emptiness_detected(self):
        old_keys = {"modules[0].path", "instances[0].caller",
                    "semantic_edges[0].caller"}
        new_keys = {"modules[0].path"}
        vocabs = {"v071": {}, "v072": {}}
        delta = self.gate6.evaluate_b1_delta(old_keys, new_keys, vocabs)
        self.assertEqual(delta["removed"],
                         {"instances[0].caller", "semantic_edges[0].caller"})

    def test_b1_vocabularies_are_fresh(self):
        committed = json.loads(self.gate6.VOCABULARIES_MANIFEST.read_text())
        fresh = load_vocab_generator().derive_reason_vocabularies()
        self.assertEqual(fresh, committed)

    def test_reason_membership_uses_enum_not_description(self):
        schema = {
            "properties": {
                "reason": {
                    "enum": ["none"],
                    "description": "mentions live_joint_feed_absent only in prose",
                }
            }
        }
        self.assertFalse(self.gate6.schema_reason_has(schema, "live_joint_feed_absent"))
        schema["properties"]["reason"]["enum"].append("live_joint_feed_absent")
        self.assertTrue(self.gate6.schema_reason_has(schema, "live_joint_feed_absent"))

    def test_cbom_properties_are_typed_exactly(self):
        doc = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:object_observations", "value": "partial (live_joint_feed_absent)"},
                    {"name": "unrelated", "value": "x"},
                ]
            }
        }
        props = self.gate6.cbom_properties(doc)
        self.assertEqual(
            props["p11scope:object_observations"], "partial (live_joint_feed_absent)"
        )
        self.assertEqual(props["unrelated"], "x")

    def test_run_timeout_is_a_typed_failure_result(self):
        completed = self.gate6.run(
            [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.2
        )
        self.assertEqual(completed.returncode, 124)
        self.assertIn("timeout", completed.stderr)

    def test_key_exists_recurses_typed_json(self):
        self.assertTrue(self.gate6.key_exists({"a": [{"departed_use": None}]}, "departed_use"))
        self.assertFalse(self.gate6.key_exists({"a": [{"other": "departed_use"}]}, "departed_use"))

    def test_diff_zero_requires_typed_empty_changes(self):
        source = substantive_inventory()
        good = valid_diff_document(source, source)
        self.assertTrue(self.gate6.diff_zero_same(good))
        changed = copy.deepcopy(good)
        changed["application_changes"] = [{"x": 1}]
        self.assertFalse(self.gate6.diff_zero_same(changed))
        changed = copy.deepcopy(good)
        changed["module_path_changes"] = [{"x": 1}]
        self.assertFalse(self.gate6.diff_zero_same(changed))
        changed = copy.deepcopy(good)
        changed["schema"] = "other"
        self.assertFalse(self.gate6.diff_zero_same(changed))
        self.assertFalse(self.gate6.diff_zero_same({"schema": "p11scope/inventory-diff/v1"}))

    def test_live_joint_render_requires_exact_reason(self):
        doc = {
            "metadata": {
                "properties": [
                    {
                        "name": "p11scope:object_observations",
                        "value": "partial (live_joint_feed_absent)",
                    }
                ]
            }
        }
        self.assertTrue(self.gate6.cbom_live_joint_rendered(doc))
        bogus = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:object_observations", "value": "partial (bogus_reason)"}
                ]
            }
        }
        self.assertFalse(self.gate6.cbom_live_joint_rendered(bogus))

    def test_profile_markers_require_exact_window_and_note(self):
        note = (
            "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
        )
        doc = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:source_schema", "value": "p11scope/observed-profile/v3"},
                    {
                        "name": "p11scope:window",
                        "value": "2026-01-01T00:00:00Z..2026-01-01T00:00:01Z (capture wall clock)",
                    },
                    {"name": "p11scope:profile_note", "value": note},
                ]
            }
        }
        self.assertTrue(self.gate6.cbom_profile_markers_present(doc))
        changed = json.loads(json.dumps(doc))
        changed["metadata"]["properties"][1]["value"] = "other"
        self.assertFalse(self.gate6.cbom_profile_markers_present(changed))


class UpgradeGate6ActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()
        cls.harness = UpgradeGate6Harness(cls.gate6)

    def assert_gate_failure(self, check_name, **kwargs):
        code, result = self.harness.execute(**kwargs)
        self.assertEqual(code, 1)
        self.assertIn(check_name, result["checks"])
        self.assertIs(result["checks"][check_name]["pass"], False)
        self.assertEqual(result["fail_reason"].split(":", 1)[0], check_name)
        return result

    def test_run_gate_positive_synthetic_typed_flow_is_exact(self):
        code, result = self.harness.execute()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["fail_reason"], "")
        self.assertEqual(
            set(result["checks"]),
            {
                "inputs_present",
                "reports_generated",
                "inventory_reports_typed",
                "admission_parity",
                "cbom_reads_old",
                "cbom_old_typed",
                "diff_old_old_zero",
                "diff_old_new",
                "diff_typed",
                "diff_churn_lifecycle",
                "b1_vocabularies",
                "b1_vocab_removed",
                "b1_no_removed",
                "b1_all_present",
                "b1_exact",
                "b1_old_absent",
                "b2_old_absent",
                "b2_new_present",
                "b2_reader_accepts",
                "b3_then_exact",
                "b3_exact",
                "b3_fixture_old_shape",
                "b3_old_schema_passes",
                "b3_old_against_head_expected_failure",
                "b3_reader_accepts_old",
            },
        )
        self.assertTrue(all(row["pass"] for row in result["checks"].values()))

    def test_run_gate_activation_negative_controls(self):
        missing_b1 = self.harness.good_new_doc()
        del missing_b1["budgets"]["edges"]["folded"]
        unexpected = self.harness.good_new_doc()
        unexpected["excluded_modules"] = [
            {"path": "/x.so", "dev": 1, "ino": 2, "processes": 3}
        ]
        removed = self.harness.good_new_doc()
        del removed["callers"][0]["app_hint"]
        old_departed = self.harness.good_old_doc()
        old_departed["modules"][0]["departed_use"] = None
        thin_admission_old = self.harness.good_old_doc()
        template_caller = copy.deepcopy(thin_admission_old["callers"][0])
        template_edge = copy.deepcopy(thin_admission_old["edges"][0])
        for index in (1, 2):
            caller = copy.deepcopy(template_caller)
            caller["id"] = f"c{index}"
            caller["pid"] = template_caller["pid"] + index
            thin_admission_old["callers"].append(caller)
            edge = copy.deepcopy(template_edge)
            edge["caller"] = f"c{index}"
            thin_admission_old["edges"].append(edge)
        for edge in thin_admission_old["edges"]:
            edge["entries"]["observation"] = "observed"
            edge["entries"]["count"] = 0
        thin_admission_new = self.harness.good_new_doc()
        thin_admission_new["edges"][0]["entries"]["observation"] = "observed"
        thin_admission_new["edges"][0]["entries"]["count"] = 0

        def then_missing(old, new):
            required = new["allOf"][0]["then"]["properties"]["evidence"]["required"]
            required.remove("member_stop_attached")
            return old, new

        def full_missing(old, new):
            required = new["properties"]["evidence"]["required"]
            required.remove("coverage_retired_slots")
            return old, new

        scenarios = [
            ("admission_parity", {"old_doc": thin_admission_old,
                                  "new_doc": thin_admission_new}),
            ("inputs_present", {"missing_old_binary": True}),
            ("reports_generated", {"generate_error": "injected generation failure"}),
            ("reports_generated", {"module_present": False}),
            ("inventory_reports_typed", {"old_doc": {"schema": "p11scope/inventory/v1"}}),
            ("inventory_reports_typed", {"new_doc": {"schema": "p11scope/inventory/v1"}}),
            ("cbom_reads_old", {"fault": "cbom-old-rc"}),
            ("cbom_old_typed", {"fault": "cbom-old-bad-format"}),
            ("cbom_old_typed", {"fault": "cbom-old-sparse"}),
            ("diff_old_old_zero", {"fault": "diff-zero-wrong-schema"}),
            ("diff_old_old_zero", {"fault": "diff-zero-sparse"}),
            ("diff_old_new", {"fault": "diff-old-new-rc"}),
            ("diff_typed", {"fault": "diff-new-wrong-schema"}),
            ("diff_typed", {"fault": "diff-new-sparse"}),
            ("diff_churn_lifecycle", {"fault": "diff-new-lifecycle"}),
            ("b1_no_removed", {"new_doc": removed}),
            ("b1_all_present", {"new_doc": missing_b1}),
            ("b1_exact", {"new_doc": unexpected}),
            ("b1_old_absent", {"old_doc": old_departed}),
            ("b2_old_absent", {"object_old_live": True}),
            ("b2_new_present", {"object_new_live": False}),
            ("b2_reader_accepts", {"fault": "b2-wrong-render"}),
            ("b2_reader_accepts", {"fault": "b2-sparse-cbom"}),
            ("b3_then_exact", {"profile_schema_mutator": then_missing}),
            ("b3_exact", {"profile_schema_mutator": full_missing}),
            ("b3_fixture_old_shape", {"profile_fixture_shape_valid": False}),
            ("b3_reader_accepts_old", {"fault": "b3-wrong-render"}),
            ("b3_reader_accepts_old", {"fault": "b3-sparse-cbom"}),
        ]
        for check_name, kwargs in scenarios:
            with self.subTest(check=check_name):
                self.assert_gate_failure(check_name, **kwargs)

    def test_run_gate_b1_vocab_removed_fires(self):
        prefix = "modules[0].unbound_use.reasons"
        vocabs = ({"v071": {prefix: ["gone"]}, "v072": {prefix: []}}, "")
        with mock.patch.object(self.gate6, "load_reason_vocabularies",
                               return_value=vocabs):
            code, result = self.harness.execute()
        self.assertEqual(code, 1)
        self.assertIn("b1_vocab_removed", result["checks"])
        self.assertIs(result["checks"]["b1_vocab_removed"]["pass"], False)
        self.assertEqual(result["fail_reason"].split(":", 1)[0], "b1_vocab_removed")
        self.assertIn("gone", result["fail_reason"])

    def test_diff_zero_failure_detail_uses_actual_schema(self):
        result = self.assert_gate_failure(
            "diff_old_old_zero", fault="diff-zero-wrong-schema"
        )
        self.assertIn(
            "diff schema: $.schema: value 'other' is not const 'p11scope/inventory-diff/v1'",
            result["checks"]["diff_old_old_zero"]["detail"],
        )

    def test_verify_artifact_pin_match_mismatch_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.bin"
            path.write_bytes(b"bytes")
            self.assertEqual(
                self.gate6.verify_artifact_pin("v071-profile-fixture", path),
                "refused: artifact 'v071-profile-fixture' sha256 mismatch: got "
                "277089d91c0bdf4f2e6862ba7e4a07605119431f5d13f726dd352b06f1b206a9, "
                "want 50d3c8276231131cffb339508007d943663e112d48c48e974b0944adc0db6766",
            )
            self.assertEqual(
                self.gate6.verify_artifact_pin(
                    "v071-profile-fixture", self.gate6.PROFILE_FIXTURE
                ),
                "",
            )
            self.assertIn(
                "refused: artifact pin 'no-such-entry' unavailable",
                self.gate6.verify_artifact_pin("no-such-entry", path),
            )
            self.assertIn(
                "refused: artifact 'v071-profile-fixture' unreadable",
                self.gate6.verify_artifact_pin(
                    "v071-profile-fixture", Path(tmp) / "absent.bin"
                ),
            )

    def test_inputs_present_refuses_tampered_fixture(self):
        result = self.assert_gate_failure(
            "inputs_present", verify_pins=True, tamper_fixture=True
        )
        detail = result["checks"]["inputs_present"]["detail"]
        self.assertIn("refused: artifact 'v071-profile-fixture' sha256 mismatch", detail)
        self.assertIn("refused: artifact 'v071-observer-binary' sha256 mismatch", detail)

    def test_inputs_present_refuses_unpinned_binary(self):
        result = self.assert_gate_failure("inputs_present", verify_pins=True)
        detail = result["checks"]["inputs_present"]["detail"]
        self.assertIn("refused: artifact 'v071-observer-binary' sha256 mismatch", detail)
        self.assertNotIn("v071-profile-fixture", detail)

    def test_v071_profile_fixture_is_real_old_shaped_and_substantive(self):
        path = ROOT / "tests/fixtures/upgrade/v071-observed-profile.json"
        document = json.loads(path.read_text())
        self.assertEqual(document["schema"], "p11scope/observed-profile/v3")
        self.assertEqual(document["lane"], "profile")
        for key in ("mode", "privacy_mode", "scope", "ring_bytes", "drain_interval_ms", "modules"):
            self.assertIn(key, document["capture"])
        self.assertEqual(document["capture"]["mode"], "profile")
        self.assertGreater(len(document["capture"]["modules"]), 0)
        self.assertGreater(len(document["functions"]), 0)
        self.assertGreater(len(document["mechanisms"]), 0)
        self.assertEqual(document["mechanisms"][0]["name"], "CKM_SHA256")
        self.assertEqual(document["evidence"]["completeness"], "COMPLETE")
        for key in (
            "pid_descendant_gaps_admitted",
            "member_stop_attached",
            "member_stop_unattached",
            "coverage_retired_slots",
        ):
            self.assertNotIn(key, document["evidence"])
        self.assertEqual(
            self.gate6.profile_window(document),
            "2026-11-26T10:46:44Z..2026-11-26T10:46:54Z (capture wall clock)",
        )

    def test_profile_fixture_flow_requires_substantive_typed_conversion(self):
        validation = self.gate6.artifact_validation
        profile = {
            "schema": "p11scope/observed-profile/v3",
            "capture": {
                "start": "2026-11-25T11:14:57Z",
                "end": "2026-11-25T11:15:00Z",
                "modules": [{"path": "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"}],
            },
            "evidence": {"completeness": "COMPLETE"},
            "mechanisms": [{"mechanism": 592, "name": "CKM_SHA256"}],
        }
        properties = {
            "p11scope:source_schema": "p11scope/observed-profile/v3",
            "p11scope:window": "2026-11-25T11:14:57Z..2026-11-25T11:15:00Z (capture wall clock)",
            "p11scope:profile_note": (
                "profile input: mechanisms are capture-global, without caller, "
                "usage-edge or key linkage"
            ),
            "p11scope:completeness": "COMPLETE",
            "p11scope:providers": "1",
            "p11scope:algorithms": "1",
            "p11scope:applications": "0",
            "p11scope:keys": "0",
            "p11scope:object_observations": "absent",
            "p11scope:established_source_query": "0",
            "p11scope:established_source_creation_success": "0",
            "p11scope:established_source_unrecorded": "0",
            "p11scope:callers_unknown_exe": "0",
            "p11scope:mechanisms_unnamed": "1",
            "p11scope:mechanisms_unknown_primitive": "1",
            "p11scope:keys_unknown_size": "0",
            "p11scope:keys_unknown_type": "0",
        }
        document = UpgradeGate6Harness.cbom(properties)
        self.assertEqual(validation.cbom_profile_errors(document, profile), [])
        for name in (
            "p11scope:providers",
            "p11scope:algorithms",
            "p11scope:completeness",
            "p11scope:window",
            "p11scope:profile_note",
        ):
            with self.subTest(name=name):
                changed = copy.deepcopy(document)
                for prop in changed["metadata"]["properties"]:
                    if prop["name"] == name:
                        prop["value"] = "wrong"
                self.assertTrue(validation.cbom_profile_errors(changed, profile))
        hollow = copy.deepcopy(document)
        hollow["components"] = []
        hollow["dependencies"] = []
        hollow_errors = validation.cbom_profile_errors(hollow, profile)
        self.assertIn(
            "cbom positive payload: fewer than one typed providers component", hollow_errors
        )
        self.assertIn(
            "cbom positive payload: fewer than one typed algorithms component", hollow_errors
        )
        bad_name = copy.deepcopy(document)
        bad_name["components"][0]["name"] = 123
        self.assertEqual(
            validation.cbom_profile_errors(bad_name, profile),
            ["cbom schema: $.components[0].name: is integer, expected string"],
        )
        bad_format = copy.deepcopy(document)
        bad_format["bomFormat"] = "SPDX"
        self.assertEqual(
            validation.cbom_profile_errors(bad_format, profile),
            ["refused: cbom bomFormat 'SPDX' is not 'CycloneDX'"],
        )
        bad_version = copy.deepcopy(document)
        bad_version["specVersion"] = "1.5"
        self.assertEqual(
            validation.cbom_profile_errors(bad_version, profile),
            ["refused: cbom specVersion '1.5' is not '1.6'"],
        )


class UpgradeTestPackageTests(unittest.TestCase):
    def test_test_build_variant_never_claims_official(self):
        package = load_package_release()
        variant = package.system_package_variant("full", test_build=True)
        self.assertIn("TEST build", variant)
        self.assertIn("not an official release", variant)
        self.assertNotIn("FULL official build", variant)
        description = package.system_package_description("full", "0.7.2", test_build=True)
        self.assertIn(variant, description)


class UpgradeSchemaDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate6 = load_gate6()

    def git_show(self, rev, path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        out = subprocess.run(
            ["git", "show", f"{rev}:{path}"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            check=True,
        )
        return out.stdout

    def test_b2_live_joint_only_in_new_reason_enums(self):
        names = [
            "docs/schema/inventory-v1-object-observations.schema.json",
            *(f"docs/schema/inventory-v1-object-observations-{ver}.schema.json" for ver in ("v2", "v3", "v4", "v5")),
        ]
        self.assertEqual(len(names), 5)
        for name in names:
            with self.subTest(name=name):
                old = json.loads(self.git_show("v0.7.1", name))
                new = json.loads((ROOT / name).read_text())
                old_enum = old["properties"]["reason"]["enum"]
                new_enum = new["properties"]["reason"]["enum"]
                self.assertNotIn("live_joint_feed_absent", old_enum)
                self.assertIn("live_joint_feed_absent", new_enum)

    def test_b3_then_required_adds_exactly_three(self):
        old = json.loads(
            self.git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json")
        )
        new = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )
        added = self.gate6.then_required(new) - self.gate6.then_required(old)
        self.assertEqual(
            added,
            {
                "pid_descendant_gaps_admitted",
                "member_stop_attached",
                "member_stop_unattached",
            },
        )

    def test_b3_full_required_adds_exactly_four(self):
        old = json.loads(
            self.git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json")
        )
        new = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )
        added = self.gate6.required_evidence(new) - self.gate6.required_evidence(old)
        removed = self.gate6.required_evidence(old) - self.gate6.required_evidence(new)
        self.assertEqual(
            added,
            {
                "pid_descendant_gaps_admitted",
                "member_stop_attached",
                "member_stop_unattached",
                "coverage_retired_slots",
            },
        )
        self.assertEqual(removed, set())


class UpgradeWorkloadLoopTests(unittest.TestCase):
    def test_child_repeats_digest_during_lifetime(self):
        workload = load_workload()
        inits = []

        class FakeLib:
            def C_GetSlotList(self, _present, slots, count):
                import ctypes

                if slots is None:
                    ctypes.cast(count, ctypes.POINTER(ctypes.c_ulong)).contents.value = 1
                else:
                    slots[0] = 7
                    ctypes.cast(count, ctypes.POINTER(ctypes.c_ulong)).contents.value = 1
                return 0

            def C_OpenSession(self, *args):
                del args
                return 0

            def C_DigestInit(self, *args):
                del args
                inits.append(1)
                return 0

            def C_Digest(self, *args):
                del args
                return 0

            def C_CloseSession(self, *args):
                del args
                return 0

            def C_Finalize(self, *args):
                del args
                return 0

        with (
            mock.patch.object(workload, "prepare_token"),
            mock.patch.object(workload, "open_provider", return_value=FakeLib()),
            mock.patch("time.sleep"),
        ):
            self.assertEqual(workload.child("fake.so"), 0)
        self.assertEqual(len(inits), workload.CHILD_DIGESTS)
        self.assertGreaterEqual(workload.CHILD_DIGESTS, 2)


class UpgradeSweepControlTests(unittest.TestCase):
    def test_control_covers_pure_killers(self):
        sweep = load_sweep()
        self.assertIn("UpgradeGate6PureTests", sweep.CONTROL_TESTS)

    def test_control_test_count_parses(self):
        sweep = load_sweep()
        self.assertEqual(sweep.control_tests_ran("Ran 36 tests in 1s\nOK\n"), 36)
        self.assertEqual(sweep.control_tests_ran("nope"), 0)


if __name__ == "__main__":
    unittest.main()
