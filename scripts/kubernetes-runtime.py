#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run existing K1/K2 oracles with a prebuilt observer and owned resources.

The artifact consumer validates the package before invoking this coordinator.
This file never builds Rust, downloads an observer or changes a Docker daemon.
`load-images` is the existing harnesses' narrow setup seam: load once, then
compare each node's CRI config ID with the exact local Docker image ID.
"""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "p11scope/hosted-kubernetes-owned/v1"


def command(args, seconds=30, allowed_statuses=(0,)):
    result = subprocess.run(["timeout", "--signal=TERM", "--kill-after=10s", f"{seconds}s", *args],
                            text=True, capture_output=True, check=False)
    if result.returncode not in allowed_statuses:
        raise ValueError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def names(cell, token):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,25}[a-z0-9])?", token):
        raise ValueError("token must be a short lowercase DNS label (at most 27 characters)")
    if cell == "K1":
        return f"p11scope-e2e-{token}", [f"p11scope-observer:e2e-{token}", f"p11scope-holder:e2e-{token}"]
    if cell == "K2":
        return f"p11scope-k2-{token}", [f"p11scope-k2-holder:{token}"]
    raise ValueError("cell must be K1 or K2")


def validate_node(node):
    match = re.fullmatch(r"kindest/node:(v1\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}", node)
    if not match:
        raise ValueError("a versioned kindest/node image pinned by SHA-256 is required")
    return match.group(1)


def image_present(image):
    return bool(command(["docker", "image", "ls", "--quiet", "--no-trunc", image]))


def load_images(cluster, images, node_image=None):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", cluster) or not images:
        raise ValueError("a named cluster and explicit local images are required")
    nodes = command(["kind", "get", "nodes", "--name", cluster]).splitlines()
    if nodes != [f"{cluster}-control-plane"]:
        raise ValueError("expected this run's single named kind node")
    if node_image:
        validate_node(node_image)
        actual = command(["docker", "inspect", "--format", "{{.Config.Image}}", nodes[0]])
        if actual != node_image:
            raise ValueError("kind node image does not match the pinned reference")
        node_id = command(["docker", "inspect", "--format", "{{.Image}}", nodes[0]])
        local_id = command(["docker", "image", "inspect", "--format", "{{.Id}}", node_image])
        if node_id != local_id:
            raise ValueError("kind node image ID differs from the pinned local image")
    expected = {}
    for image in images:
        identity = command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
            raise ValueError(f"local image ID is unavailable: {image}")
        expected[image] = identity
    command(["kind", "load", "docker-image", "--name", cluster, *images], 1200)
    for node in nodes:
        for image, identity in expected.items():
            loaded = json.loads(command(["docker", "exec", node, "crictl", "inspecti", "-o", "json", image]))
            if loaded.get("status", {}).get("id") != identity:
                raise ValueError(f"loaded image identity differs from the local image: {image}")
            print(f"loaded-image node={node} image={image} id={identity}", flush=True)


def validate_results(cell, work):
    rows = [json.loads(line) for line in (work / "cell/summary.jsonl").read_text().splitlines()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("oracle summaries must be JSON objects")
    gated = [row for row in rows if row.get("ok") is True and "record_only" not in row]
    recorded = [row for row in rows if row.get("record_only") is True and "ok" not in row]
    expected = Counter({"profile-exact": 3, "posture": 1, "doctor": 1, "isolation": 1,
                        "trace-exact": 1, "negative": 1, "inventory": 1, "pid-refusal": 1}) if cell == "K1" \
        else Counter({"profile-exact": 1, "negative": 1, "scan-limit": 1})
    records = Counter({"trace-pid-namespace": 1, "observer-memory": 1}) if cell == "K1" else Counter()
    if (len(gated) + len(recorded) != len(rows)
            or Counter(row.get("check") for row in gated) != expected
            or Counter(row.get("check") for row in recorded) != records):
        raise ValueError("required oracle checks missing, duplicated or not successful")
    profiles = [row for row in gated if row["check"] == "profile-exact"]
    if sorted(row.get("calls", -1) for row in profiles) != ([1500, 1800, 2400] if cell == "K1" else [2400]):
        raise ValueError("original exact profile counts are missing")
    for row in gated:
        if row["check"] in {"profile-exact", "trace-exact"}:
            if row.get("pid_namespace_causes") != ["pid_namespace"]:
                raise ValueError("nested PID namespace disclosure is missing")
        if row["check"] == "trace-exact" and row.get("calls") != 1200:
            raise ValueError("original exact trace count is missing")
        if row["check"] == "scan-limit":
            if "pid_namespace" not in row.get("causes", []):
                raise ValueError("scan-limit nested PID namespace disclosure is missing")
            if row.get("leg") not in {"counted-exact", "absent", "attached-zero"}:
                raise ValueError("scan-limit classification is missing")
            if row["leg"] != "counted-exact" and not row.get("disclosure"):
                raise ValueError("late provider zero has no disclosure")
    log = (work / "runtime.log").read_text()
    marker = r"^=== kind e2e: ALL OK \(10 gated checks passed; 2 record-only lines; summary .+\) ===$" \
        if cell == "K1" else r"^SUMMARY cell=K2 verdict=PASS reason=.+$"
    if len(re.findall(marker, log, re.M)) != 1:
        raise ValueError("original harness completion summary is missing or duplicated")


def bpf_ids():
    return {kind: [row["id"] for row in json.loads(command(["sudo", "-n", "bpftool", "-j", kind, "show"]))]
            for kind in ("prog", "map", "link")}


def read_owned(work):
    path = work / "owned.json"
    if work.is_symlink() or path.is_symlink() or work.stat().st_uid != os.getuid() \
            or work.stat().st_mode & 0o077 or not path.is_file():
        raise ValueError("cleanup requires this caller's private owned work directory")
    state = json.loads(path.read_text())
    cluster, images = names(state["cell"], state["token"])
    if (state.get("schema") != SCHEMA or state.get("cluster") != cluster or state.get("images") != images
            or not isinstance(state.get("started"), bool)
            or (state.get("session") is not None and (type(state["session"]) is not int or state["session"] <= 0))):
        raise ValueError("cleanup ownership state does not match this run's exact resources")
    return state


def stop_session(session, leader_start):
    """Drain only live local clients in the harness's dedicated Linux session."""
    if session is None:
        return []
    leader = Path(f"/proc/{session}/stat")
    try:
        if leader.read_text().rsplit(") ", 1)[1].split()[19] != leader_start:
            return ["harness session leader birth changed; refusing to signal"]
    except FileNotFoundError:
        pass  # A live member retains its departed leader's session ID.
    def members():
        found = {}
        for path in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = path.read_text().rsplit(") ", 1)[1].split()
                if int(fields[3]) == session and fields[0] != "Z":
                    found[int(path.parent.name)] = fields[19]
            except (OSError, ValueError, IndexError):
                continue
        return found
    for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 2)):
        for pid, start in members().items():
            # Recheck birth before signalling a PID that may have exited.
            if members().get(pid) == start:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + seconds
        while members() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not members():
            return []
    return ["owned local capture clients remain after drain"]


def cleanup(work):
    if not work.exists() or not (work / "owned.json").exists():
        return []
    state = read_owned(work)
    errors = stop_session(state.get("session"), state.get("session_start"))
    if state["started"]:
        try:
            clusters = command(["kind", "get", "clusters"]).splitlines()
            if state["cluster"] in clusters:
                command(["kind", "delete", "cluster", "--name", state["cluster"],
                         "--kubeconfig", str(work / "cell/kubeconfig")], 300)
        except (ValueError, OSError) as error:
            errors.append(str(error))
        for image in state["images"]:
            try:
                if image_present(image):
                    command(["docker", "image", "rm", "-f", image], 60)
                if image_present(image):
                    errors.append(f"owned image remains: {image}")
            except (ValueError, OSError) as error:
                errors.append(str(error))
        try:
            if state["cluster"] in command(["kind", "get", "clusters"]).splitlines():
                errors.append("owned cluster remains")
            if command(["docker", "ps", "-aq", "--filter", f"label=io.x-k8s.kind.cluster={state['cluster']}"]):
                errors.append("owned kind containers remain")
        except (ValueError, OSError) as error:
            errors.append(str(error))
    if (work / "bpf-before.json").is_file():
        try:
            before = json.loads((work / "bpf-before.json").read_text())
            after = bpf_ids()
            for kind, ids in after.items():
                if set(ids) - set(before[kind]):
                    errors.append(f"new BPF {kind} resources remain after cleanup")
        except (ValueError, OSError) as error:
            errors.append(str(error))
    return errors


def run(args):
    cluster, images = names(args.cell, args.token)
    version = validate_node(args.node_image)
    observer = Path(args.observer)
    if not observer.is_absolute() or observer.is_symlink() or not observer.is_file() or not os.access(observer, os.X_OK):
        raise ValueError("an absolute executable prebuilt observer is required")
    if os.environ.get("KUBECONFIG"):
        raise ValueError("foreign kubeconfig refused; the harness creates its own private kubeconfig")
    work = Path(args.work)
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ValueError("work must be an absolute new private directory")
    work.mkdir(mode=0o700)
    state = {"schema": SCHEMA, "cell": args.cell, "token": args.token,
             "cluster": cluster, "images": images, "started": False}
    (work / "owned.json").write_text(json.dumps(state))
    errors = []
    child = None
    status = None
    try:
        with (ROOT / "mise.toml").open("rb") as handle:
            kind_version = tomllib.load(handle)["tools"]["kind"]
        if command(["kind", "version"]).split()[1:2] != [f"v{kind_version}"]:
            raise ValueError("kind does not match the repository pin")
        kubectl = json.loads(command(["kubectl", "version", "--client", "-o", "json"]))
        if kubectl.get("clientVersion", {}).get("gitVersion") != version:
            raise ValueError("kubectl must match the pinned node release")
        if cluster in command(["kind", "get", "clusters"]).splitlines():
            raise ValueError("existing cluster refused; it will not be reused or deleted")
        if any(image_present(image) for image in images):
            raise ValueError("existing image tag refused; it will not be reused or deleted")
        (work / "bpf-before.json").write_text(json.dumps(bpf_ids()))
        # A warning-only doctor can return 1 (for example, no selected target).
        # Admit only the same functional safety rows as the hosted capture lane.
        doctor = command(["sudo", "-n", "env", f"TMPDIR={os.environ.get('TMPDIR', work)}", str(observer), "doctor"],
                         120, allowed_statuses=(0, 1))
        (work / "doctor.txt").write_text(doctor + "\n")
        admission = runpy.run_path(str(ROOT / "scripts/qualify-return-probe-admission.py"))
        try:
            admission["require_clean_doctor"](doctor)
        except admission["Refused"] as error:
            raise ValueError(str(error)) from error
        if len(re.findall(r"^object-attribute capture \.+ ok +enabled(?:[ (].*)?$", doctor, re.M)) != 1:
            raise ValueError("functional FULL object-capture doctor row missing or unsafe")
        env = os.environ.copy()
        env.pop("P11SCOPE_K8S_LOCK", None)  # the workflow owns the ancestor lane
        if args.cell == "K1":
            env.update(P11SCOPE_K8S_TOKEN=args.token, P11SCOPE_K8S_CLUSTER=cluster,
                       P11SCOPE_K8S_OBSERVER_BIN=str(observer), P11SCOPE_K8S_WORK=str(work / "cell"),
                       P11SCOPE_K8S_NODE_IMAGE=args.node_image)
            invocation = ["sh", "scripts/kind-e2e.sh"]
        else:
            invocation = ["sh", "scripts/kind-attach-pod-e2e.sh", "--observer", str(observer),
                          "--token", args.token, "--node-image", args.node_image, "--work", str(work / "cell")]
        state["started"] = True  # reserve only the unused names proven above
        (work / "owned.json").write_text(json.dumps(state))
        with (work / "runtime.log").open("w") as log:
            child = subprocess.Popen(invocation, cwd=ROOT, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            state["session"] = child.pid
            state["session_start"] = Path(f"/proc/{child.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
            (work / "owned.json").write_text(json.dumps(state))
            status = child.wait()
        if status:
            raise ValueError(f"{args.cell} harness exited {status}; UNRUN is not PASS")
        validate_results(args.cell, work)
    except (ValueError, OSError, KeyboardInterrupt) as error:
        errors.append(str(error) or "runtime interrupted")
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        errors.extend(cleanup(work))
    result = {"cell": args.cell, "ok": not errors, "harness_status": status, "errors": errors}
    (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if (work / "runtime.log").exists():
        print((work / "runtime.log").read_text()[-32768:])
    print(json.dumps(result), flush=True)
    return 0 if result["ok"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    capture = commands.add_parser("run")
    capture.add_argument("--cell", choices=("K1", "K2"), required=True)
    capture.add_argument("--observer", required=True)
    capture.add_argument("--node-image", required=True)
    capture.add_argument("--work", required=True)
    capture.add_argument("--token", required=True)
    clear = commands.add_parser("cleanup")
    clear.add_argument("--work", required=True)
    load = commands.add_parser("load-images")
    load.add_argument("--cluster", required=True)
    load.add_argument("--node-image")
    load.add_argument("images", nargs="+")
    args = parser.parse_args()
    try:
        if args.action == "run":
            # GitHub cancellation must unwind the harness's own cleanup traps.
            def interrupted(_signal, _frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, interrupted)
            return run(args)
        if args.action == "load-images":
            load_images(args.cluster, args.images, args.node_image)
            return 0
        errors = cleanup(Path(args.work))
        if errors:
            raise ValueError("; ".join(errors))
        return 0
    except (ValueError, OSError, KeyError) as error:
        print(f"kubernetes-runtime: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
