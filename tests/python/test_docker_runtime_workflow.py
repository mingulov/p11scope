#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real Docker workflow shell with transport/host stubs only."""

import json
import fcntl
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/docker-runtime.yml"


class WorkflowTests(unittest.TestCase):
    def workflow(self):
        self.assertTrue(WORKFLOW.is_file(), "independent Docker workflow missing")
        return yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)

    def test_manual_host_job_has_read_only_permissions_and_bounded_outer_deadline(self):
        workflow = self.workflow()
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch", "workflow_call"})
        supplied = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(supplied), {"preview_run_id"})
        self.assertEqual(supplied["preview_run_id"]["required"], "true")
        self.assertEqual(workflow["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(set(workflow["jobs"]), {"docker-runtime"})
        job = workflow["jobs"]["docker-runtime"]
        self.assertEqual(job["runs-on"], "ubuntu-26.04")
        self.assertEqual(job["timeout-minutes"], "25")
        self.assertNotIn("container", job)
        self.assertNotIn("services", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("strategy", job)
        stages = {step.get("id"): step for step in job["steps"] if step.get("id")}
        self.assertEqual(stages["observer"]["env"]["PREVIEW_RUN_ID"], "${{ inputs.preview_run_id }}")
        self.assertEqual(stages["observer"]["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertNotIn("continue-on-error", stages["runtime"])

    def body(self, step):
        return next(item["run"] for item in self.workflow()["jobs"]["docker-runtime"]["steps"]
                    if item.get("id") == step)

    def test_storage_rejects_external_repository_event_and_self_hosted_routing(self):
        for overrides in ({}, {"GITHUB_REPOSITORY": "elsewhere/p11scope"},
                          {"GITHUB_EVENT_NAME": "pull_request"},
                          {"RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                base = root / "owned-base"
                program = self.body("storage").replace("/var/tmp/p11scope-ws-tmp", str(base))
                env = os.environ | {"GITHUB_EVENT_NAME": "workflow_dispatch",
                                    "GITHUB_REPOSITORY": "mingulov/p11scope",
                                    "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                                    "RUNNER_ARCH": "X64", "GITHUB_ENV": str(root / "env")} | overrides
                result = subprocess.run(["bash", "-c", program], env=env,
                                        text=True, capture_output=True, timeout=10)
                if overrides:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(base.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(base.stat().st_mode & 0o777, 0o700)
                    self.assertIn("P11SCOPE_PRIVILEGED_LOCK=", (root / "env").read_text())

    def exercise(self, scenario="ok", **environment):
        with tempfile.TemporaryDirectory(prefix="docker-workflow-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            tools, scripts, work = root / "tools", root / "scripts", root / "work"
            tools.mkdir()
            scripts.mkdir()
            (scripts / "matrix").mkdir()
            work.mkdir(mode=0o700)
            (work / "logs").mkdir()
            (work / "tmp").mkdir(mode=0o700)
            (root / "spike").mkdir()
            shutil.copy(ROOT / "spike/expected.txt", root / "spike/expected.txt")
            for script in ("check-capture-evidence.py", "qualify-return-probe-admission.py"):
                shutil.copy(ROOT / "scripts" / script, scripts / script)
            shutil.copy(ROOT / "scripts/matrix/check-count-multiset.py", scripts / "matrix")
            fixture = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
            evidence = fixture["evidence_fixture"](fixture["LEGACY_SURFACES"])
            evidence.update(table_entries=68, slots=68, active_slots=68, attached_probes=136)
            profile = fixture["document_fixture"](evidence, schema=fixture["METRICS_SCHEMA"],
                                                   mode="metrics", privacy="aggregate-only")
            profile["functions"] = fixture["function_items"]([
                (["C_CloseSession"], 10), (["C_Digest"], 50), (["C_DigestInit"], 50),
                (["C_Finalize"], 1), (["C_GenerateRandom"], 100), (["C_GetInfo"], 3),
                (["C_GetSlotList"], 1), (["C_Initialize"], 1), (["C_OpenSession"], 10),
                (["C_GetFunctionList"], 1)])
            if scenario == "missing-count":
                profile["functions"][0]["calls"] = 0
            if scenario == "loss":
                profile["evidence"]["event_loss"] = 1
            (root / "profile.json").write_text(json.dumps(profile))
            observer = work / "p11scope"
            observer.write_text("#!" + sys.executable + "\n" + '''
import os, sys
assert sys.argv[1:] == ["doctor"]
scenario = os.environ["SCENARIO"]
rows = [
    "uprobe-multi attach (own libc) ... ok scratch program loaded; self-link attached and detached (delivery unmeasured)",
    "uretprobe vs seccomp ... ok the trampoline's syscall is exempt from seccomp; confined targets are safe",
    "object-attribute capture ... ok enabled (read only; key operations are reported from 0.6.0)"]
if scenario == "multi": rows[0] = rows[0].replace("ok scratch", "WARN scratch")
if scenario == "unsafe": rows[1] = rows[1].replace("ok the", "WARN the")
if scenario == "p0": rows[2] = "object-attribute capture ... WARN not enabled in this P0 build"
print("\\n".join(rows))
sys.exit(2 if scenario == "doctor-error" else 0)
''')
            observer.chmod(0o755)
            transport = "#!" + sys.executable + "\n" + '''
import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
scenario = os.environ["SCENARIO"]
with open(os.environ["COMMANDS"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "sudo":
    assert args[0] == "-n"
    if args[1:] == ["true"]: sys.exit(1 if scenario == "sudo" else 0)
    os.execvp(args[1], args[1:])
if name == "pgrep":
    sys.exit(0 if scenario == "compiler" and "cargo" in " ".join(args) else 1)
if name == "docker":
    if args[:2] == ["context", "inspect"]:
        print("ssh://external" if scenario == "remote-context" else "unix:///var/run/docker.sock")
    elif args[:1] == ["info"]:
        print(json.dumps({"Driver": "overlay2", "CgroupVersion": "1" if scenario == "cgroup-v1" else "2",
                          "DockerRootDir": os.environ["STUB_ROOT"], "OSType": "linux", "Architecture": "x86_64"}))
    elif args[:2] in (["ps", "-a"], ["image", "ls"]):
        if scenario == "cleanup" and (Path(os.environ["STUB_ROOT"]) / "harness-ran").exists(): print("owned-leftover")
    else: sys.exit(91)
    sys.exit(0)
if name == "bpftool":
    assert args[0] == "-j" and args[1] in ("link", "prog", "map") and args[2] == "show"
    leak = {"bpf-leak": "link", "bpf-prog-leak": "prog", "bpf-map-leak": "map"}.get(scenario)
    print('[{"id": 2}]' if leak == args[1] and (Path(os.environ["STUB_ROOT"]) / "harness-ran").exists() else '[]')
    sys.exit(0)
if name == "python3":
    if args == ["-I", "-", os.environ["DOCKER_RUNTIME_WORK"]]:
        # Host facts are the external boundary: capture assertions and all
        # other embedded Python bodies still run unchanged.
        from unittest.mock import patch
        program = sys.stdin.read()
        sys.argv = ["-", *args[2:]]
        # Low free pages can coexist with ample reclaimable/available RAM.
        pages = 0
        available_blocks = 0 if scenario == "low-disk" else 1048576
        facts = {"SC_AVPHYS_PAGES": pages, "SC_PAGE_SIZE": 4096}
        filesystem = os.statvfs_result((4096, 4096, 1048576, available_blocks,
                                       available_blocks, 100, 100, 100, 0, 255))
        with patch("os.sysconf", side_effect=lambda key: facts[key]), patch("os.statvfs", return_value=filesystem):
            exec(compile(program, "<workflow-host-preflight>", "exec"))
        sys.exit(0)
    os.execv(sys.executable, [sys.executable, *args])
if name == "cargo": sys.exit(99)
sys.exit(92)
'''
            for name in ("sudo", "pgrep", "docker", "bpftool", "cargo", "python3"):
                (tools / name).write_text(transport)
                (tools / name).chmod(0o755)
            harness = scripts / "matrix/verify-docker.sh"
            harness.write_text('''#!/bin/sh
set -eu
test -n "$P11SCOPE_BIN"
test -x "$P11SCOPE_BIN"
case "$P11SCOPE_BIN" in /*) ;; *) exit 94 ;; esac
touch "$STUB_ROOT/harness-ran"
capture=$(mktemp -d "$P11SCOPE_MATRIX_TMPDIR/p11scope-docker-XXXXXX")
cp "$STUB_ROOT/profile.json" "$capture/observed.json"
echo "work root: $capture"
case $SCENARIO in unrun) exit 2 ;; nonzero) exit 7 ;; no-record) rm "$capture/observed.json" ;; esac
if [ "$SCENARIO" != no-summary ]; then echo '=== docker: ALL OK ==='; fi
''')
            harness.chmod(0o755)
            for path in ("sys/kernel/btf", "sys/fs/cgroup"):
                (root / path).mkdir(parents=True)
            (root / "sys/kernel/btf/vmlinux").write_text("BTF fixture")
            (root / "sys/fs/cgroup/cgroup.controllers").write_text("pids memory cpu")
            if scenario == "missing-btf":
                (root / "sys/kernel/btf/vmlinux").unlink()
            (root / "proc").mkdir()
            available = "1" if scenario == "low-memory" else "4194304"
            memory = f"MemFree: 8 kB\nMemAvailable: {available} kB\n"
            if scenario == "malformed-memory":
                memory = "MemFree: 8 kB\nMemAvailable: NaN kB\n"
            elif scenario == "missing-memory":
                memory = "MemFree: 8 kB\n"
            elif scenario == "oversized-memory":
                memory += " " * 65536
            (root / "proc/meminfo").write_text(memory)
            env = os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"],
                                "P11SCOPE_BIN": str(observer), "DOCKER_RUNTIME_WORK": str(work),
                                "TMPDIR": str(work / "tmp"), "P11SCOPE_MATRIX_TMPDIR": str(work / "tmp"),
                                "P11SCOPE_PRIVILEGED_LOCK": str(work / "privileged.lock"),
                                "COMMANDS": str(root / "commands"), "STUB_ROOT": str(root),
                                "SCENARIO": scenario} | environment
            if scenario == "missing-observer":
                env.pop("P11SCOPE_BIN")
            program = self.body("runtime").replace("/sys/", str(root / "sys") + "/")
            program = program.replace("/proc/meminfo", str(root / "proc/meminfo"))
            with (work / "privileged.lock").open("w") as held:
                if scenario == "busy-lane":
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(["bash", "--noprofile", "--norc", "-c", program],
                                        cwd=root, env=env, text=True, capture_output=True, timeout=20)
            ran = (root / "harness-ran").exists()
            calls = [json.loads(line) for line in (root / "commands").read_text().splitlines()] \
                if (root / "commands").exists() else []
            self.assertFalse(any(call[0] == "cargo" for call in calls), "hidden Rust build executed")
            return result, ran, calls

    def test_real_shell_passes_with_local_full_observer_and_exact_counts(self):
        result, ran, _ = self.exercise()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(ran)

    def test_preflight_refusals_never_start_harness_or_cargo(self):
        for scenario in ("busy-lane", "missing-observer", "missing-btf", "sudo", "multi", "unsafe", "p0",
                         "doctor-error", "remote-context", "cgroup-v1", "compiler", "low-memory", "low-disk",
                         "malformed-memory", "missing-memory", "oversized-memory"):
            with self.subTest(scenario=scenario):
                result, ran, _ = self.exercise(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(ran)
        result, ran, _ = self.exercise(DOCKER_HOST="tcp://external:2375")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(ran)

    def test_required_cell_unrun_nonzero_missing_counts_loss_and_cleanup_fail(self):
        for scenario in ("unrun", "nonzero", "no-summary", "no-record", "missing-count", "loss",
                         "cleanup", "bpf-leak", "bpf-prog-leak", "bpf-map-leak"):
            with self.subTest(scenario=scenario):
                result, ran, _ = self.exercise(scenario)
                self.assertTrue(ran, result.stdout + result.stderr)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
