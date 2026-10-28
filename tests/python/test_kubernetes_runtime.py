#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real hosted Kubernetes coordinator, with only daemon/capture boundaries stubbed."""

import copy
import importlib.util
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/kubernetes-runtime.py"
NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
IMAGE_ID = "sha256:" + "a" * 64


def k1_rows():
    rows = [{"check": check, "ok": True} for check in
            ("posture", "doctor", "isolation", "negative", "inventory", "pid-refusal")]
    rows.extend({"check": "profile-exact", "ok": True, "calls": calls,
                 "pid_namespace_causes": ["pid_namespace"]} for calls in (2400, 1500, 1800))
    rows.append({"check": "trace-exact", "ok": True, "calls": 1200,
                 "pid_namespace_causes": ["pid_namespace"]})
    rows.extend({"check": check, "record_only": True} for check in
                ("trace-pid-namespace", "observer-memory"))
    return rows


def k2_rows():
    return [{"check": "profile-exact", "ok": True, "calls": 2400,
             "pid_namespace_causes": ["pid_namespace"]},
            {"check": "negative", "ok": True},
            {"check": "scan-limit", "ok": True, "leg": "counted-exact",
             "causes": ["pid_namespace"], "disclosure": []}]


def load_helper():
    if not HELPER.is_file():
        raise AssertionError("Kubernetes setup/cleanup coordinator is missing")
    spec = importlib.util.spec_from_file_location("kubernetes_runtime", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SummaryTests(unittest.TestCase):
    def check(self, cell, rows, log=None):
        helper = load_helper()
        with tempfile.TemporaryDirectory(prefix="p11-k8s-summary-", dir="/var/tmp") as raw:
            work = Path(raw)
            (work / "cell").mkdir()
            (work / "cell/summary.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            (work / "runtime.log").write_text(log or (
                "=== kind e2e: ALL OK (10 gated checks passed; 2 record-only lines; summary /owned/summary.jsonl) ===\n"
                if cell == "K1" else "SUMMARY cell=K2 verdict=PASS reason=\"exact and negative and scan\"\n"))
            helper.validate_results(cell, work)

    def test_original_complete_k1_k2_outputs_pass(self):
        self.check("K1", k1_rows())
        self.check("K2", k2_rows())

    def test_missing_duplicate_false_and_ready_only_outputs_fail(self):
        for cell, healthy in (("K1", k1_rows()), ("K2", k2_rows())):
            for rows in (healthy[1:], healthy + [healthy[0]],
                         [{**healthy[0], "ok": False}, *healthy[1:]]):
                with self.subTest(cell=cell, rows=rows), self.assertRaises(ValueError):
                    self.check(cell, rows)
            with self.assertRaises(ValueError):
                self.check(cell, healthy, "container Ready\n")

    def test_wrong_counts_missing_namespace_and_silent_late_zero_fail(self):
        for cell, healthy in (("K1", k1_rows()), ("K2", k2_rows())):
            for key, value in (("calls", 0), ("pid_namespace_causes", [])):
                rows = copy.deepcopy(healthy)
                next(row for row in rows if row["check"] == "profile-exact")[key] = value
                with self.assertRaises(ValueError):
                    self.check(cell, rows)
        for leg, disclosure in (("attached-zero", []), ("absent", []), ("unknown", ["loader_discovery"])):
            rows = k2_rows()
            rows[-1].update(leg=leg, disclosure=disclosure)
            with self.assertRaises(ValueError):
                self.check("K2", rows)

    def test_disclosed_late_provider_boundary_remains_accepted(self):
        rows = k2_rows()
        rows[-1].update(leg="attached-zero", disclosure=["loader_discovery"])
        self.check("K2", rows)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "Kubernetes setup/cleanup coordinator is missing")
        self.temp = tempfile.TemporaryDirectory(prefix="p11-k8s-coordinator-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(HELPER, self.root / "scripts/kubernetes-runtime.py")
        for name in ("qualify-return-probe-admission.py", "check-capture-evidence.py"):
            shutil.copy2(ROOT / "scripts" / name, self.root / "scripts" / name)
        (self.root / "mise.toml").write_text('[tools]\nkind = "0.33.0"\n')
        self.binary = self.root / "p11scope"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.fake = self.root / "bin"
        self.fake.mkdir()
        self.work = self.root / "run"
        self.env = os.environ.copy()
        self.env.update({"STUB_STATE": str(self.root / "state.json"),
                         "STUB_CALLS": str(self.root / "calls.jsonl"),
                         "STUB_ROOT": str(self.root), "PATH": f"{self.fake}:{os.environ['PATH']}"})
        self.state = {"clusters": [], "images": {}, "containers": [], "loaded_id": IMAGE_ID,
                      "kind": "v0.33.0", "kubectl": "v1.37.0", "bpf_leak": False,
                      "node_ref": NODE, "node_id": IMAGE_ID, "doctor": "FULL"}
        self.write_state()
        stub = self.fake / "external.py"
        stub.write_text(f"#!{sys.executable}\n" + '''\
import json, os, sys
from pathlib import Path
tool, args = Path(sys.argv[0]).name, sys.argv[1:]
state_path = Path(os.environ["STUB_STATE"])
state = json.loads(state_path.read_text())
with open(os.environ["STUB_CALLS"], "a") as out:
    out.write(json.dumps([tool, *args]) + "\\n")
joined = " ".join(args)
if os.environ.get("STUB_FAIL") and os.environ["STUB_FAIL"] in tool + " " + joined:
    raise SystemExit(8)
if tool == "kind":
    if args == ["version"]:
        print("kind " + state["kind"] + " go1.26 linux/amd64")
    elif args == ["get", "clusters"]:
        print("\\n".join(state["clusters"]))
    elif args[:2] == ["create", "cluster"]:
        state["clusters"].append(args[args.index("--name") + 1])
        state["containers"] = ["owned-node"]
    elif args[:2] == ["get", "nodes"]:
        print(args[args.index("--name") + 1] + "-control-plane")
    elif args[:2] == ["delete", "cluster"]:
        state["clusters"].remove(args[args.index("--name") + 1])
        state["containers"] = []
elif tool == "kubectl":
    print(json.dumps({"clientVersion": {"gitVersion": state["kubectl"]}}))
elif tool == "docker":
    if args[:3] == ["image", "ls", "--quiet"]:
        print(state["images"].get(args[-1], ""))
    elif args[:2] == ["image", "inspect"]:
        print(state["images"].get(args[-1], state["node_id"]))
    elif args[:1] == ["inspect"]:
        print(state["node_ref"] if "Config.Image" in joined else state["node_id"])
    elif args[:1] == ["build"]:
        state["images"][args[args.index("-t") + 1]] = state["node_id"]
    elif args[:2] == ["image", "rm"]:
        for image in args[2:]:
            if image != "-f":
                state["images"].pop(image, None)
    elif args[:1] == ["exec"] and "inspecti" in args:
        print(json.dumps({"status": {"id": state["loaded_id"]}}))
    elif args[:1] == ["ps"]:
        print("\\n".join(state["containers"]))
elif tool == "sudo":
    if "bpftool" in args:
        print(json.dumps([{"id": 42}] if state.get("ran") and state["bpf_leak"] else []))
    elif "doctor" in args:
        print("uprobe-multi attach (own libc) ... ok scratch program loaded; self-link attached and detached (delivery unmeasured)")
        print("uretprobe vs seccomp ... " + ("FAIL" if state["doctor"] == "unsafe" else "ok the trampoline's syscall is exempt from seccomp; confined targets are safe"))
        print("object-attribute capture ... " + ("WARN not enabled in this P0 build" if state["doctor"] == "P0" else "ok enabled"))
state_path.write_text(json.dumps(state))
if tool == "sudo" and "doctor" in args and state["doctor"] == "warn":
    raise SystemExit(1)
''')
        stub.chmod(0o755)
        for tool in ("kind", "docker", "kubectl", "sudo"):
            (self.fake / tool).symlink_to(stub)
        harness = self.root / "scripts/stub-harness.py"
        harness.write_text('''\
import json, os, pathlib, subprocess, sys
root = pathlib.Path(os.environ["STUB_ROOT"])
state_path = pathlib.Path(os.environ["STUB_STATE"])
args = sys.argv[1:]
if os.environ.get("P11SCOPE_K8S_OBSERVER_BIN"):
    cell, token = "K1", os.environ["P11SCOPE_K8S_TOKEN"]
    work = pathlib.Path(os.environ["P11SCOPE_K8S_WORK"])
    cluster, node = os.environ["P11SCOPE_K8S_CLUSTER"], os.environ["P11SCOPE_K8S_NODE_IMAGE"]
    images = ["p11scope-observer:e2e-" + token, "p11scope-holder:e2e-" + token]
else:
    cell, token = "K2", args[args.index("--token") + 1]
    work = pathlib.Path(args[args.index("--work") + 1])
    cluster, node = "p11scope-k2-" + token, args[args.index("--node-image") + 1]
    images = ["p11scope-k2-holder:" + token]
work.mkdir(mode=0o700)
for image in images:
    subprocess.run(["docker", "build", "-t", image, "context"], check=True)
subprocess.run(["kind", "create", "cluster", "--name", cluster, "--kubeconfig", str(work / "kubeconfig"), "--image", node], check=True)
subprocess.run([sys.executable, "-I", str(root / "scripts/kubernetes-runtime.py"), "load-images", "--cluster", cluster, *images], check=True)
state = json.loads(state_path.read_text())
state["ran"] = True
state_path.write_text(json.dumps(state))
if os.environ.get("STUB_LEAK_CLIENT"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    (root / "client.pid").write_text(str(child.pid))
if os.environ.get("STUB_HARNESS_FAIL"):
    raise SystemExit(3)
rows = json.loads((root / (cell + ".json")).read_text())
(work / "summary.jsonl").write_text("".join(json.dumps(row) + "\\n" for row in rows))
print("=== kind e2e: ALL OK (10 gated checks passed; 2 record-only lines; summary x) ===" if cell == "K1" else "SUMMARY cell=K2 verdict=PASS reason=exact-and-twins")
''')
        for name in ("kind-e2e.sh", "kind-attach-pod-e2e.sh"):
            (self.root / "scripts" / name).write_text(f'#!/bin/sh\nexec {sys.executable} -I "{harness}" "$@"\n')
        (self.root / "K1.json").write_text(json.dumps(k1_rows()))
        (self.root / "K2.json").write_text(json.dumps(k2_rows()))

    def write_state(self):
        Path(self.env["STUB_STATE"]).write_text(json.dumps(self.state))

    def read_state(self):
        return json.loads(Path(self.env["STUB_STATE"]).read_text())

    def calls(self):
        path = Path(self.env["STUB_CALLS"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run_cell(self, cell="K1", observer=None, node=NODE):
        return subprocess.run([sys.executable, "-I", str(self.root / "scripts/kubernetes-runtime.py"),
                               "run", "--cell", cell, "--observer", str(observer or self.binary),
                               "--node-image", node, "--work", str(self.work), "--token", "123-1"],
                              env=self.env, text=True, capture_output=True, timeout=20)

    def test_complete_k1_k2_run_cleanup_and_preserve_foreign_resources(self):
        for cell in ("K1", "K2"):
            self.work = self.root / cell
            self.state["clusters"] = ["caller-cluster"]
            self.state["images"] = {"caller:important": IMAGE_ID}
            self.write_state()
            result = self.run_cell(cell)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(self.read_state()["clusters"], ["caller-cluster"])
            self.assertEqual(self.read_state()["images"], {"caller:important": IMAGE_ID})
            self.assertTrue(json.loads((self.work / "result.json").read_text())["ok"])
        loads = [call for call in self.calls() if call[:3] == ["kind", "load", "docker-image"]]
        self.assertEqual(len(loads), 2)

    def test_missing_binary_and_unpinned_node_refuse_before_resources(self):
        for kwargs in ({"observer": self.root / "missing"}, {"node": "kindest/node:latest"}):
            self.assertNotEqual(self.run_cell(**kwargs).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_foreign_kubeconfig_refuses_before_resources(self):
        self.env["KUBECONFIG"] = "/home/caller/.kube/config"
        self.assertNotEqual(self.run_cell().returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_existing_cluster_or_image_are_never_owned_or_removed(self):
        for cell, cluster in (("K1", "p11scope-e2e-123-1"), ("K2", "p11scope-k2-123-1")):
            self.work = self.root / cell
            self.state["clusters"] = [cluster]
            self.write_state()
            self.assertNotEqual(self.run_cell(cell).returncode, 0)
            self.assertEqual(self.read_state()["clusters"], [cluster])
        self.assertFalse(any(call[1:3] == ["delete", "cluster"] for call in self.calls()))
        self.work = self.root / "existing-image"
        self.state["clusters"] = []
        self.state["images"] = {"p11scope-holder:e2e-123-1": IMAGE_ID}
        self.write_state()
        self.assertNotEqual(self.run_cell().returncode, 0)
        self.assertEqual(self.read_state()["images"], self.state["images"])
        self.assertFalse(any(call[1:3] == ["image", "rm"] for call in self.calls()))

    def test_tool_pin_drift_refuses_before_capture(self):
        for tool, bad in (("kind", "v0.32.0"), ("kubectl", "v1.34.0")):
            self.work = self.root / tool
            self.state[tool] = bad
            self.write_state()
            self.assertNotEqual(self.run_cell().returncode, 0)
            self.state[tool] = "v0.33.0" if tool == "kind" else "v1.37.0"
        self.assertFalse(self.read_state().get("ran", False))

    def test_p0_or_unsafe_doctor_never_starts_a_harness(self):
        for verdict in ("P0", "unsafe"):
            self.work = self.root / verdict
            self.state["doctor"] = verdict
            self.write_state()
            self.assertNotEqual(self.run_cell().returncode, 0)
        self.assertFalse(self.read_state().get("ran", False))

    def test_doctor_warning_exit_with_all_required_functional_rows_can_run(self):
        self.state["doctor"] = "warn"
        self.write_state()
        result = self.run_cell()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_wrong_loaded_image_fails_and_is_cleaned(self):
        self.state["loaded_id"] = "sha256:" + "b" * 64
        self.write_state()
        result = self.run_cell()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loaded image identity", result.stdout + result.stderr)
        self.assertEqual(self.read_state()["clusters"], [])
        self.assertEqual(self.read_state()["images"], {})

    def test_owned_local_client_is_stopped_after_the_harness_exits(self):
        self.env["STUB_LEAK_CLIENT"] = "1"
        result = self.run_cell()
        pid = int((self.root / "client.pid").read_text())
        def stop_leaked_fixture():
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.addCleanup(stop_leaked_fixture)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            self.assertEqual(stat.read_text().rsplit(") ", 1)[1].split()[0], "Z",
                             "an owned local capture client is still running")

    def test_runtime_unrun_cleanup_failure_and_bpf_leak_remain_failures(self):
        self.env["STUB_HARNESS_FAIL"] = "1"
        result = self.run_cell()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read_state()["clusters"], [])
        self.env.pop("STUB_HARNESS_FAIL")
        self.work = self.root / "delete-failure"
        self.env["STUB_FAIL"] = "kind delete cluster"
        self.assertNotEqual(self.run_cell().returncode, 0)
        self.env.pop("STUB_FAIL")
        self.state["bpf_leak"] = True
        self.write_state()
        self.work = self.root / "leak"
        self.assertNotEqual(self.run_cell().returncode, 0)

    def test_tampered_cleanup_state_never_deletes_foreign_resources(self):
        self.assertEqual(self.run_cell().returncode, 0)
        state_path = self.work / "owned.json"
        owned = json.loads(state_path.read_text())
        owned["cluster"] = "caller-cluster"
        state_path.write_text(json.dumps(owned))
        calls_before = len(self.calls())
        result = subprocess.run([sys.executable, "-I", str(self.root / "scripts/kubernetes-runtime.py"),
                                 "cleanup", "--work", str(self.work)], env=self.env,
                                text=True, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), calls_before)


if __name__ == "__main__":
    unittest.main()
