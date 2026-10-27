#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One combined stock pre-Multi refusal guest, not an old positive/load lane.

The caller reserves the guest lane. Image checksums belong to the workflow;
this driver verifies the transferred observer/script and actual kernel.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile

TOKEN = "uprobe-multi-required"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_commands(observer, work):
    """Exercise actual command/sink/workload boundaries; callable unprivileged."""
    rows = []
    sentinel = work / "workload-ran"
    commands = [("doctor", ["doctor"])]
    for backend in ("auto", "multi", "singles"):
        commands.append(("profile-" + backend,
                         ["profile", "--system", "--attach-backend", backend, "--duration", "1s"]))
        for capture in ("auto", "native"):
            commands.append(("inventory-" + capture + "-" + backend,
                             ["inventory", "--system", "--capture", capture,
                              "--attach-backend", backend, "--duration", "1s"]))
        commands.append(("run-" + backend,
                         ["run", "--attach-backend", backend, "--duration", "1s"]))
    for mode in ("counts", "timestamps", "latency"):
        commands.append(("counter-" + mode,
                         ["profile", "--system", "--mode", "metrics",
                          "--counter-mode", mode, "--duration", "1s"]))
    for case, argv in commands:
        sink = work / (case + ".json")
        before = b"owned-preexisting-sink\n"
        if case != "doctor":
            sink.write_bytes(before)
            identity = sink.stat().st_ino
            argv += ["-o", str(sink)]
        if argv[0] == "run":
            argv += ["--", "/bin/sh", "-c", 'printf unexpected > "$1"',
                     "multi-refusal", str(sentinel)]
        result = subprocess.run([str(observer), *argv], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=60 if case == "doctor" else 20)
        if result.returncode == 0 or result.returncode < 0:
            raise RuntimeError(case + ": expected nonzero setup refusal")
        if TOKEN not in result.stdout + result.stderr:
            raise RuntimeError(case + ": missing " + TOKEN + ": " + result.stderr[-1000:])
        if case != "doctor" and (sink.read_bytes() != before or sink.stat().st_ino != identity):
            raise RuntimeError(case + ": pre-existing sink changed")
        if sentinel.exists():
            raise RuntimeError(case + ": user workload executed before refusal")
        rows.append({"case": case, "outcome": "refused", "rc": result.returncode,
                     "reason": TOKEN})
    for case, argv in (("help", ["--help"]), ("version", ["--version"])):
        result = subprocess.run([str(observer), *argv], capture_output=True, text=True, timeout=20)
        if result.returncode != 0 or TOKEN in result.stdout + result.stderr:
            raise RuntimeError(case + ": offline command blocked")
        rows.append({"case": case, "outcome": "offline-ok", "rc": 0})
    report = work / "scan.json"
    result = subprocess.run([str(observer), "inventory", "--pid", str(os.getpid()),
                             "--capture", "scan", "--json", "-o", str(report)],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or not report.is_file() or TOKEN in result.stdout + result.stderr:
        raise RuntimeError("inventory-scan: offline command blocked")
    if json.loads(report.read_text()).get("schema") != "p11scope/inventory/v1":
        raise RuntimeError("inventory-scan: invalid offline report")
    rows.append({"case": "inventory-scan", "outcome": "offline-ok", "rc": 0})
    result = subprocess.run([str(observer), "inventory", "diff", str(report), str(report)],
                            capture_output=True, text=True, timeout=20)
    if result.returncode != 0 or TOKEN in result.stdout + result.stderr:
        raise RuntimeError("inventory-diff: offline command blocked")
    rows.append({"case": "inventory-diff", "outcome": "offline-ok", "rc": 0})
    return rows


def trust_stage_owner(stage, runner_uid):
    # Root's output trust policy also checks the runner-owned shared ancestors.
    if type(runner_uid) is not int or not 0 <= runner_uid < 2**32 - 1 or stage.stat().st_uid != runner_uid:
        raise RuntimeError("invalid stage owner UID")
    try:
        account = pwd.getpwuid(runner_uid)
    except KeyError as error:
        raise RuntimeError("stage owner UID has no account") from error
    if account.pw_uid != runner_uid:
        raise RuntimeError("stage owner account UID mismatch")
    if runner_uid:
        os.environ["SUDO_UID"] = str(runner_uid)
    else:
        os.environ.pop("SUDO_UID", None)


def guest(stage):
    if os.geteuid() != 0:
        raise RuntimeError("guest root required")
    metadata = json.loads((stage / "inputs.json").read_text())
    for name, expected in metadata["sha256"].items():
        if digest(stage / name) != expected:
            raise RuntimeError("transferred input mismatch: " + name)
    kernel = os.uname().release
    expected = metadata["kernel"].removeprefix("v")
    if kernel != expected and not kernel.startswith(expected + "-"):
        raise RuntimeError("wrong guest kernel: " + kernel)
    trust_stage_owner(stage, metadata.get("runner_uid"))
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="multi-refusal-", dir=stage) as temp:
        work = Path(temp)
        os.environ["TMPDIR"] = str(work)
        rows = check_commands(stage / "p11scope", work)
    result = {"kernel": kernel, "observer_sha256": metadata["sha256"]["p11scope"],
              "qualification": "unsupported-host-refusal", "capture_positive": False,
              "cases": rows}
    (stage / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("MULTI_HOST_REFUSAL PASS cases=" + str(len(rows)) + " capture_positive=false")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.guest:
        if len(args.paths) != 1:
            parser.error("guest requires STAGE")
        guest(Path(args.paths[0]))
        return 0
    if len(args.paths) != 3:
        parser.error("requires OBSERVER FRESH_STAGE KERNEL")
    observer = Path(args.paths[0]).resolve(strict=True)
    stage = Path(args.paths[1]).absolute()
    kernel = args.paths[2]
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", kernel) is None:
        parser.error("use an explicit stock kernel release")
    # Refuse reuse; the source tree and every other task remain untouched.
    stage.mkdir(mode=0o700)
    shutil.copy2(observer, stage / "p11scope")
    shutil.copy2(Path(__file__).resolve(), stage / "guest.py")
    metadata = {"kernel": kernel, "runner_uid": stage.stat().st_uid,
                "sha256": {name: digest(stage / name) for name in ("p11scope", "guest.py")}}
    (stage / "inputs.json").write_text(json.dumps(metadata) + "\n")
    command = shlex.join(["python3", str(stage / "guest.py"), "--guest", str(stage)])
    with (stage / "guest.log").open("w") as log:
        result = subprocess.run(["timeout", "-k", "20", "300", "vng", "--run", kernel,
                                 "--user", "root", "--cpus", "2", "--memory", "2G",
                                 "--rwdir", str(stage), "--exec", command],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode != 0 or not (stage / "result.json").is_file():
        raise RuntimeError("refusal guest failed; inspect " + str(stage / "guest.log"))
    print((stage / "result.json").read_text())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("multi-host refusal control: " + str(error), file=sys.stderr)
        raise SystemExit(1)
