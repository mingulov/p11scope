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


def substantive_inventory(schema="p11scope/inventory/v1"):
    """One small but fully typed inventory document used by typed doubles."""
    return {
        "schema": schema,
        "scope": "system",
        "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
        "observation": {
            "started_ns": 100,
            "ended_ns": 200,
            "passes": 1,
            "usage_feed": False,
            "semantic_capture": {},
            "native_witnesses": {
                "rows": 0,
                "bound": 0,
                "unbound": 0,
                "pending": 0,
                "integrity": 0,
                "unbound_reasons": {},
                "placement": {"edge": 0, "module": 0, "ambiguous": 0, "unresolved": 0},
            },
        },
        "pid_namespace": {"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
        "budgets": {
            "callers": {"limit": 4096, "occupied": 1, "refused": 0},
            "modules": {"limit": 4096, "occupied": 1, "refused": 0},
            "edges": {"limit": 32768, "occupied": 1, "refused": 0},
            "instances": {"limit": 4096, "occupied": 0, "refused": 0},
            "endpoints": {"limit": 1048576, "occupied": 1, "refused": 0},
            "inventory_endpoints": {"limit": 32768, "occupied": 1, "refused": 0},
            "inventory_attach_modules": {"limit": 32768, "occupied": 1, "refused": 0},
            "counters": {
                "cap": 18446744073709551615,
                "observed_edges": 1,
                "saturated_edges": 0,
            },
            "semantic_state": {
                "limit": 32768,
                "occupied": 0,
                "status": "withheld",
                "unknown_edges": 1,
                "refused": 0,
            },
            "retained_history": {"limit": 8192, "retained": 1, "suppressed": 0},
            "native_preadmission": None,
        },
        "callers": [
            {
                "id": "c0",
                "pid": 4242,
                "start_time": 987654,
                "start_time_unit": "clock_ticks_since_boot",
                "incarnation": 0,
                "image": {
                    "authority": "scan_pinned",
                    "task_cookie": None,
                    "exec_id": None,
                    "exe": {
                        "dev": 8,
                        "ino": 12345,
                        "mtime_secs": 1700000000,
                        "mtime_nanos": 0,
                        "path": "/driver",
                    },
                    "exec_observed": True,
                },
                "lifecycle": "mapped",
                "lifecycle_reason": None,
                "first_seen_ns": 110,
                "last_seen_ns": 190,
                "retired": False,
            }
        ],
        "modules": [
            {
                "id": "m0",
                "paths": ["/provider.so"],
                "identity": {
                    "device": {"major": 8, "minor": 1},
                    "inode": 23456,
                    "sha256": "a" * 64,
                    "build_id": None,
                    "source": "mountinfo",
                },
                "admission": {
                    "state": "admitted",
                    "class": "exact",
                    "endpoints": 1,
                    "reasons": [],
                    "note": "scan-only admission: manifest corroboration was not consulted",
                    "history": [],
                },
                "lifecycle": "mapped",
                "unloaded_observed": False,
                "unbound_use": None,
            }
        ],
        "edges": [
            {
                "caller": "c0",
                "module": "m0",
                "mapping": {
                    "state": "mapped",
                    "evidence": "deep_scan",
                    "reason": None,
                    "first_seen_ns": 110,
                    "last_seen_ns": 190,
                    "interruptions": 0,
                },
                "entries": {
                    "count": 0,
                    "saturated": False,
                    "cap": 18446744073709551615,
                    "first_seen_ns": None,
                    "last_seen_ns": None,
                    "in_flight": False,
                    "observation": "unknown (usage observation unavailable)",
                    "coverage": {
                        "state": "unknown",
                        "since_ns": None,
                        "until_ns": None,
                        "first_ns": None,
                        "lossy": None,
                        "reason": "scan_only",
                        "detail": None,
                    },
                },
                "semantics": "unknown (semantic capture withheld)",
                "mechanisms": None,
                "operations": None,
            }
        ],
        "object_observations": {
            "version": 1,
            "revision": 1,
            "status": "unavailable",
            "reason": "journal_unavailable",
            "budgets": {},
            "gaps": {"rows": [], "suppressed": 0},
            "key_operations": [],
            "objects": [],
            "sessions": [],
            "unknown_key_operations": [],
        },
        "gaps": [
            {
                "caller": None,
                "module": None,
                "pid": None,
                "subject": "exact image authority unavailable",
                "reason": "no BPF image identity; scan-lane incarnation pinning",
                "budget": None,
                "repeats": 1,
            }
        ],
        "gaps_suppressed": 0,
    }


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
    """One substantive typed diff snapshot projection for harness documents."""
    return {
        "scope": source["scope"],
        "clock": dict(source["clock"]),
        "observation": {
            "started_ns": source["observation"]["started_ns"],
            "ended_ns": source["observation"]["ended_ns"],
            "passes": source["observation"]["passes"],
            "usage_feed": source["observation"]["usage_feed"],
            "lane": None,
            "settlement": None,
            "retirement": None,
            "attach": None,
            "lifecycle": None,
            "native_witnesses": dict(source["observation"]["native_witnesses"]),
        },
        "pid_namespace": dict(source["pid_namespace"]),
        "scope_completeness": "unknown",
        "reported_gaps": len(source["gaps"]),
        "suppressed_gaps": source["gaps_suppressed"],
        "refusals": {"reported_budget_gaps": 0, "budget_counters": {}},
        "budgets": dict(source["budgets"]),
        "loss_evidence": {"lifecycle": None, "native_witnesses": dict(source["observation"]["native_witnesses"])},
        "gaps": copy.deepcopy(source["gaps"]),
        "evidence": {
            "callers": copy.deepcopy(source["callers"]),
            "modules": copy.deepcopy(source["modules"]),
            "edges": copy.deepcopy(source["edges"]),
            "caller_occurrences": [0],
            "module_occurrences": [0],
            "edge_occurrences": [0],
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
        inventory = {
            "schema": "p11scope/inventory/v1",
            "scope": "system",
            "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
            "observation": {
                "started_ns": 100,
                "ended_ns": 200,
                "passes": 1,
                "usage_feed": False,
                "semantic_capture": {},
                "native_witnesses": {
                    "rows": 0,
                    "bound": 0,
                    "unbound": 0,
                    "pending": 0,
                    "integrity": 0,
                    "unbound_reasons": {},
                    "placement": {"edge": 0, "module": 0, "ambiguous": 0, "unresolved": 0},
                },
            },
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
            "budgets": {
                "callers": {"limit": 4096, "occupied": 1, "refused": 0},
                "modules": {"limit": 4096, "occupied": 1, "refused": 0},
                "edges": {"limit": 32768, "occupied": 1, "refused": 0},
                "instances": {"limit": 4096, "occupied": 0, "refused": 0},
                "endpoints": {"limit": 1048576, "occupied": 1, "refused": 0},
                "inventory_endpoints": {"limit": 32768, "occupied": 1, "refused": 0},
                "inventory_attach_modules": {"limit": 32768, "occupied": 1, "refused": 0},
                "counters": {"cap": 18446744073709551615, "observed_edges": 1, "saturated_edges": 0},
                "semantic_state": {"limit": 32768, "occupied": 0, "status": "withheld", "unknown_edges": 1, "refused": 0},
                "retained_history": {"limit": 8192, "retained": 1, "suppressed": 0},
                "native_preadmission": None,
            },
            "callers": [{
                "id": "c0",
                "pid": 4242,
                "start_time": 987654,
                "start_time_unit": "clock_ticks_since_boot",
                "incarnation": 0,
                "image": {
                    "authority": "scan_pinned",
                    "task_cookie": None,
                    "exec_id": None,
                    "exe": {"dev": 8, "ino": 12345, "mtime_secs": 1700000000, "mtime_nanos": 0, "path": "/driver"},
                    "exec_observed": True,
                },
                "lifecycle": "mapped",
                "lifecycle_reason": None,
                "first_seen_ns": 110,
                "last_seen_ns": 190,
                "retired": False,
            }],
            "modules": [{
                "id": "m0",
                "paths": ["/provider.so"],
                "identity": {
                    "device": {"major": 8, "minor": 1},
                    "inode": 23456,
                    "sha256": "a" * 64,
                    "build_id": None,
                    "source": "mountinfo",
                },
                "admission": {
                    "state": "admitted",
                    "class": "exact",
                    "endpoints": 1,
                    "reasons": [],
                    "note": "scan-only admission: manifest corroboration was not consulted",
                    "history": [],
                },
                "lifecycle": "mapped",
                "unloaded_observed": False,
                "unbound_use": None,
            }],
            "edges": [{
                "caller": "c0",
                "module": "m0",
                "mapping": {"state": "mapped", "evidence": "deep_scan", "reason": None, "first_seen_ns": 110, "last_seen_ns": 190, "interruptions": 0},
                "entries": {
                    "count": 0,
                    "saturated": False,
                    "cap": 18446744073709551615,
                    "first_seen_ns": None,
                    "last_seen_ns": None,
                    "in_flight": False,
                    "observation": "unknown (usage observation unavailable)",
                    "coverage": {"state": "unknown", "since_ns": None, "until_ns": None, "first_ns": None, "lossy": None, "reason": "scan_only", "detail": None},
                },
                "semantics": "unknown (semantic capture withheld)",
                "mechanisms": None,
                "operations": None,
            }],
            "object_observations": {
                "version": 1,
                "revision": 1,
                "status": "unavailable",
                "reason": "journal_unavailable",
                "budgets": {},
                "gaps": {"rows": [], "suppressed": 0},
                "key_operations": [],
                "objects": [],
                "sessions": [],
                "unknown_key_operations": [],
            },
            "gaps": [{
                "caller": None,
                "module": None,
                "pid": None,
                "subject": "exact image authority unavailable",
                "reason": "no BPF image identity; scan-lane incarnation pinning",
                "budget": None,
                "repeats": 1,
            }],
            "gaps_suppressed": 0,
        }
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
        return query_version()
    if name == "dpkg":
        return install_package(args[-1])
    if name == "rpm":
        if "-qp" in args:
            print(package_version(args[-1]))
            return 0
        if "-q" in args:
            return query_version()
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
        binary = base / "root" / "p11scope"
        state.mkdir()
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
            f"export SIM_FORMAT={shlex.quote(format_name)}\n"
            "P11SCOPE_GATE5_SOURCE_ONLY=1\n"
            f". {shlex.quote(str(GATE5))}\n"
            'P11SCOPE_BIN="$SIM_P11SCOPE_BIN"\n'
            'recovery_dir() { printf \'%s\' "$SIM_RECOVERY_DIR"; }\n'
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
        doc["modules"][0]["departed_use"] = {}
        doc["observation"]["semantic_capture"].update(
            {"length_insert_failures": 0, "length_stash_mismatches": 0}
        )
        return doc

    @staticmethod
    def object_schema(live):
        reasons = ["none"] + ([LIVE_TEST_REASON] if live else [])
        return {"properties": {"reason": {"enum": reasons}}}

    @classmethod
    def object_schema_sets(cls, old_live=False, new_live=True):
        names = [f"schema-{version}" for version in ("v1", "v2", "v3", "v4", "v5")]
        return (
            {name: cls.object_schema(old_live) for name in names},
            {name: cls.object_schema(new_live) for name in names},
        )

    @staticmethod
    def profile_schemas():
        old = {"properties": {"evidence": {"required": ["completeness"]}}, "allOf": []}
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
        self.assertIs(mismatch["canary_survived"], False)
        self.assertNotEqual(
            mismatch["canary_report_sha_before"], mismatch["canary_report_sha_after"]
        )
        self.assertIs(doctor_mismatch["doctor_rcs_equal"], False)
        self.assertNotEqual(doctor_mismatch["doctor_old_rc"], doctor_mismatch["doctor_new_rc"])
        self.assertEqual(empty_hash["canary_recovery_sha_before"], "")
        self.assertEqual(empty_hash["canary_recovery_sha_after"], "")
        self.assertIs(empty_hash["canary_survived"], False)


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
                "old capture report failed typed validation: schema is 'wrong/schema', expected 'p11scope/inventory/v1'",
            ),
            (
                "old capture sparse",
                {},
                {"capture-old-sparse": ""},
                "old capture report failed typed validation: missing inventory root field 'scope'",
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
                "new capture report failed typed validation: schema is 'wrong/schema', expected 'p11scope/inventory/v1'",
            ),
            (
                "new capture sparse",
                {},
                {"capture-new-sparse": ""},
                "new capture report failed typed validation: missing inventory root field 'scope'",
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


class UpgradeArtifactValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validation = load_artifact_validation()

    def test_inventory_validator_accepts_substantive_typed_document(self):
        self.assertEqual(self.validation.inventory_errors(substantive_inventory()), [])

    def test_inventory_validator_rejects_schema_only_document_typed_exactly(self):
        errors = self.validation.inventory_errors({"schema": "p11scope/inventory/v1"})
        self.assertEqual(errors[0], "missing inventory root field 'scope'")
        self.assertIn("missing inventory root field 'gaps_suppressed'", errors)

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

    def test_diff_positive_payload_rejects_hollow_caller_projections(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        for side in ("before", "after"):
            hollow = copy.deepcopy(document)
            hollow[side]["evidence"]["caller_occurrences"] = []
            errors = self.validation.diff_errors(hollow, before, after)
            self.assertIn(f"diff positive payload: fewer than one compared caller row on {side}", errors)

    def test_inventory_validator_rejects_each_required_root_field(self):
        for key in (
            "scope",
            "clock",
            "observation",
            "budgets",
            "callers",
            "modules",
            "edges",
            "gaps",
            "gaps_suppressed",
        ):
            with self.subTest(key=key):
                document = substantive_inventory()
                del document[key]
                self.assertEqual(
                    self.validation.inventory_errors(document)[0],
                    f"missing inventory root field '{key}'",
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
        sparse = {"bomFormat": "CycloneDX", "metadata": {"properties": []}}
        self.assertEqual(
            self.validation.cbom_inventory_errors(sparse, source)[0],
            "missing cbom root field 'specVersion'",
        )

    def test_diff_validator_requires_ten_field_typed_document_and_consistency(self):
        before = substantive_inventory()
        after = substantive_inventory()
        document = valid_diff_document(before, after)
        self.assertEqual(self.validation.diff_errors(document, before, after), [])
        sparse = {
            "schema": "p11scope/inventory-diff/v1",
            "application_changes": [],
            "module_path_changes": [],
        }
        self.assertEqual(
            self.validation.diff_errors(sparse, before, after)[0],
            "missing diff root field 'before'",
        )
        inconsistent = copy.deepcopy(document)
        inconsistent["summary"]["module_paths_changed"] = 1
        self.assertIn(
            "diff summary module_paths_changed is 1, expected 0",
            self.validation.diff_errors(inconsistent, before, after),
        )

    def test_inventory_validator_rejects_wrong_nested_types(self):
        document = substantive_inventory()
        document["observation"]["passes"] = "2"
        self.assertIn(
            "inventory observation.passes is string, expected a positive integer",
            self.validation.inventory_errors(document),
        )

        document = substantive_inventory()
        document["modules"][0]["paths"] = None
        self.assertIn(
            "inventory modules[0].paths is null, expected an array of nonempty strings",
            self.validation.inventory_errors(document),
        )

        document = substantive_inventory()
        document["gaps_suppressed"] = True
        self.assertIn(
            "inventory field 'gaps_suppressed' is bool, expected a nonnegative integer",
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
                "observation.semantic_capture.length_insert_failures",
                "observation.semantic_capture.length_stash_mismatches",
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
        delta = self.gate6.evaluate_b1_delta(old_keys, good_new)
        self.assertEqual(delta["removed"], set())
        self.assertEqual(delta["unexpected"], set())
        self.assertEqual(delta["missing_b1"], set())

        missing = self.gate6.evaluate_b1_delta(old_keys, good_new - {"budgets.edges.folded"})
        self.assertEqual(missing["missing_b1"], {"budgets.edges.folded"})
        unexpected = self.gate6.evaluate_b1_delta(old_keys, good_new | {"modules[0].surprise"})
        self.assertEqual(unexpected["unexpected"], {"modules[0].surprise"})
        removed = self.gate6.evaluate_b1_delta(old_keys, good_new - {"modules[0].path"})
        self.assertEqual(removed["removed"], {"modules[0].path"})

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
                "cbom_reads_old",
                "cbom_old_typed",
                "diff_old_old_zero",
                "diff_old_new",
                "diff_typed",
                "diff_churn_lifecycle",
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
        unexpected["modules"][0]["surprise"] = 1
        removed = self.harness.good_new_doc()
        del removed["callers"][0]["incarnation"]
        old_departed = self.harness.good_old_doc()
        new_departed = self.harness.good_new_doc()
        old_departed["departed_use"] = {}
        new_departed["departed_use"] = {}

        def then_missing(old, new):
            required = new["allOf"][0]["then"]["properties"]["evidence"]["required"]
            required.remove("member_stop_attached")
            return old, new

        def full_missing(old, new):
            required = new["properties"]["evidence"]["required"]
            required.remove("coverage_retired_slots")
            return old, new

        scenarios = [
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
            ("b1_no_removed", {"new_doc": removed}),
            ("b1_all_present", {"new_doc": missing_b1}),
            ("b1_exact", {"new_doc": unexpected}),
            ("b1_old_absent", {"old_doc": old_departed, "new_doc": new_departed}),
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

    def test_diff_zero_failure_detail_uses_actual_schema(self):
        result = self.assert_gate_failure(
            "diff_old_old_zero", fault="diff-zero-wrong-schema"
        )
        self.assertIn("diff schema is 'other'", result["checks"]["diff_old_old_zero"]["detail"])

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
            "2026-11-25T11:14:57Z..2026-11-25T11:15:00Z (capture wall clock)",
        )

    def test_profile_fixture_flow_requires_substantive_typed_conversion(self):
        window = "2026-11-25T11:14:57Z..2026-11-25T11:15:00Z (capture wall clock)"
        note = (
            "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
        )
        document = {
            "metadata": {
                "properties": [
                    {"name": "p11scope:source_schema", "value": "p11scope/observed-profile/v3"},
                    {"name": "p11scope:window", "value": window},
                    {"name": "p11scope:profile_note", "value": note},
                    {"name": "p11scope:completeness", "value": "COMPLETE"},
                    {"name": "p11scope:providers", "value": "1"},
                    {"name": "p11scope:algorithms", "value": "1"},
                ]
            }
        }
        self.assertTrue(self.gate6.cbom_profile_fixture_flow(document, window))
        changed = copy.deepcopy(document)
        changed["metadata"]["properties"][4]["value"] = "0"
        self.assertFalse(self.gate6.cbom_profile_fixture_flow(changed, window))
        changed = copy.deepcopy(document)
        changed["metadata"]["properties"][5]["value"] = "0"
        self.assertFalse(self.gate6.cbom_profile_fixture_flow(changed, window))


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


if __name__ == "__main__":
    unittest.main()
