#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Upgrade cells: package upgrade (gate 5) and report compat (gate 6).

Gate 5 is a root-only cell (installs DEB/RPM); this suite pins its script
contract without installing: argument parsing, the non-root refusal, typed
emitter behaviour through the script's self-test mode, and the schema/key
pins gate 6 consumes. The live upgrade runs in the upgrade-cells workflow
and on the fedora host via scripts/upgrade-gate5.sh.

Gate 6's end-to-end leg lives in .github/workflows/upgrade-cells.yml and in
the release-candidate host runs. This suite pins its pure typed checks and
the exact B1/B2/B3 schema deltas from the tree alone.
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


MOCK_PACKAGE_TOOL = r'''#!/usr/bin/env python3
import os
import sys
from pathlib import Path


def package_version(path):
    for line in Path(path).read_text().splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1]
    return ""


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
    if not control(f"skip-binary-{side}"):
        binary = Path(os.environ["SIM_P11SCOPE_BIN"])
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("""#!/bin/sh
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
  schema='p11scope/inventory/v1'
  [ -f "$state/capture-$side-wrong-schema" ] && schema='wrong/schema'
  printf '{"schema":"%s"}\n' "$schema" >"$out"
  rc=0
  [ -f "$state/capture-$side-rc" ] && rc="$(cat "$state/capture-$side-rc")"
  exit "$rc"
fi
exit 2
""")
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
        return {
            "schema": "p11scope/inventory/v1",
            "budgets": {"callers": {}, "edges": {}, "instances": {}},
            "modules": [{"path": "/provider.so"}],
            "object_observations": {"budgets": {}},
            "observation": {"semantic_capture": {}},
        }

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
        return {
            "bomFormat": bom_format,
            "metadata": {
                "properties": [
                    {"name": name, "value": value} for name, value in properties.items()
                ]
            },
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
                reason = injected["object_observations"]["reason"]
                properties["p11scope:object_observations"] = f"partial ({reason})"
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
                    }
                )
            return self.fake_completed(
                command, stdout=json.dumps(self.cbom(properties))
            )
        if "diff" in text_command:
            index = text_command.index("diff")
            same = text_command[index + 1] == text_command[index + 2]
            document = {
                "schema": "p11scope/inventory-diff/v1",
                "application_changes": [] if same else [{"change": "expected"}],
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
        if fault == "cbom-old-bad-format" and cbom_source == "v071-inventory.json":
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
                "old capture report has wrong schema",
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
                "new capture report has wrong schema",
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
                self.assertEqual(result["fail_reason"], expected_reason)


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
        good = {
            "schema": "p11scope/inventory-diff/v1",
            "application_changes": [],
            "module_path_changes": [],
        }
        self.assertTrue(self.gate6.diff_zero_same(good))
        self.assertFalse(self.gate6.diff_zero_same({**good, "application_changes": [{"x": 1}]}))
        self.assertFalse(self.gate6.diff_zero_same({**good, "module_path_changes": [{"x": 1}]}))
        self.assertFalse(self.gate6.diff_zero_same({**good, "schema": "other"}))

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
                "cbom_reads_old",
                "cbom_old_typed",
                "diff_old_old_zero",
                "diff_old_new",
                "diff_typed",
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
        del removed["modules"][0]["path"]
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
            ("cbom_reads_old", {"fault": "cbom-old-rc"}),
            ("cbom_old_typed", {"fault": "cbom-old-bad-format"}),
            ("diff_old_old_zero", {"fault": "diff-zero-wrong-schema"}),
            ("diff_old_new", {"fault": "diff-old-new-rc"}),
            ("diff_typed", {"fault": "diff-new-wrong-schema"}),
            ("b1_no_removed", {"new_doc": removed}),
            ("b1_all_present", {"new_doc": missing_b1}),
            ("b1_exact", {"new_doc": unexpected}),
            ("b1_old_absent", {"old_doc": old_departed, "new_doc": new_departed}),
            ("b2_old_absent", {"object_old_live": True}),
            ("b2_new_present", {"object_new_live": False}),
            ("b2_reader_accepts", {"fault": "b2-wrong-render"}),
            ("b3_then_exact", {"profile_schema_mutator": then_missing}),
            ("b3_exact", {"profile_schema_mutator": full_missing}),
            ("b3_reader_accepts_old", {"fault": "b3-wrong-render"}),
        ]
        for check_name, kwargs in scenarios:
            with self.subTest(check=check_name):
                self.assert_gate_failure(check_name, **kwargs)

    def test_diff_zero_failure_detail_uses_actual_schema(self):
        result = self.assert_gate_failure(
            "diff_old_old_zero", fault="diff-zero-wrong-schema"
        )
        self.assertIn("schema=other", result["checks"]["diff_old_old_zero"]["detail"])

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
