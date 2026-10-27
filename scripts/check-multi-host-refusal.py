#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One combined stock pre-Multi refusal guest, not an old positive/load lane.

The caller reserves the guest lane. Image checksums belong to the workflow;
this driver verifies the transferred observer/script and actual kernel.
"""
import argparse
from contextlib import contextmanager
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
OUTPUT_LIMIT = 4096
WORK_IMAGE_BYTES = 128 * 1024 * 1024
GUEST_WORK_MOUNT = Path("/var/tmp")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_commands(observer, work, progress=None):
    """Exercise actual command/sink/workload boundaries; callable unprivileged."""
    rows = []

    def complete(case, result, outcome, checks, reason=None):
        failed = [(name, message) for name, passed, message in checks if not passed]
        row = {"case": case, "outcome": "failed" if failed else outcome,
               "rc": result.returncode, "command": result.args,
               "failed_predicates": [name for name, _ in failed]}
        for stream in ("stdout", "stderr"):
            output = getattr(result, stream) or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            row[stream] = output[-OUTPUT_LIMIT:]
            row[stream + "_truncated"] = len(output) > OUTPUT_LIMIT
        if reason is not None and not failed:
            row["reason"] = reason
        rows.append(row)
        # This path is outside the disposable work directory. Preserve every
        # completed case and the failing result before raising or cleanup.
        if progress is not None:
            progress.write_text(json.dumps({"cases": rows}, indent=2) + "\n")
        if failed:
            raise RuntimeError(case + ": " + "; ".join(message for _, message in failed))

    def run(case, argv, timeout):
        args = [str(observer), *argv]
        try:
            return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            complete(case, subprocess.CompletedProcess(args, None, error.stdout, error.stderr),
                     "failed", [("command_timeout", False, "command timed out")])
        except OSError as error:
            complete(case, subprocess.CompletedProcess(args, None, "", str(error)),
                     "failed", [("command_spawn", False, "command could not start")])

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
        result = run(case, argv, 60 if case == "doctor" else 20)
        try:
            sink_unchanged = case == "doctor" or (sink.read_bytes() == before and sink.stat().st_ino == identity)
        except OSError:
            sink_unchanged = False
        complete(case, result, "refused", [
            ("refusal_exit", result.returncode > 0, "expected nonzero setup refusal"),
            ("named_refusal", TOKEN in result.stdout + result.stderr, "missing " + TOKEN),
            ("sink_unchanged", sink_unchanged, "pre-existing sink changed"),
            ("workload_not_run", not sentinel.exists(), "user workload executed before refusal"),
        ], TOKEN)
    for case, argv in (("help", ["--help"]), ("version", ["--version"])):
        result = run(case, argv, 20)
        complete(case, result, "offline-ok", [
            ("offline_exit", result.returncode == 0, "offline command blocked: nonzero exit"),
            ("live_gate_absent", TOKEN not in result.stdout + result.stderr, "offline command blocked: live gate"),
        ])
    report = work / "scan.json"
    result = run("inventory-scan", ["inventory", "--pid", str(os.getpid()),
                                   "--capture", "scan", "--json", "-o", str(report)], 30)
    checks = [
        ("offline_exit", result.returncode == 0, "offline command blocked: nonzero exit"),
        ("report_exists", report.is_file(), "offline command blocked: missing report"),
        ("live_gate_absent", TOKEN not in result.stdout + result.stderr, "offline command blocked: live gate"),
    ]
    if all(passed for _, passed, _ in checks):
        try:
            valid_schema = json.loads(report.read_text()).get("schema") == "p11scope/inventory/v1"
        except (OSError, ValueError, AttributeError):
            valid_schema = False
        checks.append(("report_schema", valid_schema, "invalid offline report"))
    complete("inventory-scan", result, "offline-ok", checks)
    result = run("inventory-diff", ["inventory", "diff", str(report), str(report)], 20)
    complete("inventory-diff", result, "offline-ok", [
        ("offline_exit", result.returncode == 0, "offline command blocked: nonzero exit"),
        ("live_gate_absent", TOKEN not in result.stdout + result.stderr, "offline command blocked: live gate"),
    ])
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


def prepare_guest_disk(stage):
    image = stage / "work.img"
    fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.truncate(WORK_IMAGE_BYTES)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(image)], check=True)


@contextmanager
def guest_disk_work(stage):
    # A non-root runner's 9p stage can map guest-root creations to its UID.
    # Atomic output correctly requires a private file owned by guest root.
    # Keep shared-stage diagnostics, but run real sink checks on a fresh disk.
    # Mount over the existing guest directory before creating private work;
    # this needs no writable root/9p ancestor and never removes that directory.
    mount = str(GUEST_WORK_MOUNT)
    loop = None
    mounted = False
    try:
        candidate = subprocess.run(["losetup", "-f", "--show", str(stage / "work.img")],
                                   capture_output=True, text=True, check=True).stdout.strip()
        if re.fullmatch(r"/dev/loop[0-9]+", candidate) is None:
            raise RuntimeError("unexpected owned guest loop device")
        loop = candidate
        subprocess.run(["mount", "-t", "ext4", "-o", "nodev,nosuid", loop, mount], check=True)
        mounted = True
        with tempfile.TemporaryDirectory(prefix="work-", dir=mount) as temp:
            work = Path(temp)
            metadata = work.stat()
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o777 != 0o700:
                raise RuntimeError("guest work must be private and owned by the effective UID")
            yield work
    finally:
        try:
            if mounted:
                subprocess.run(["umount", mount], check=True)
        finally:
            if loop is not None:
                subprocess.run(["losetup", "-d", loop], check=True)


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
    context = {"kernel": kernel, "observer_sha256": metadata["sha256"]["p11scope"],
               "runner_uid": metadata["runner_uid"], "euid": os.geteuid(),
               "sudo_uid": os.environ.get("SUDO_UID")}
    with guest_disk_work(stage) as work:
        os.environ["TMPDIR"] = str(work)
        context.update({"work": str(work), "work_uid": work.stat().st_uid,
                        "work_mode": oct(work.stat().st_mode & 0o777),
                        "work_filesystem": "ext4"})
        (stage / "guest-context.json").write_text(json.dumps(context, indent=2) + "\n")
        rows = check_commands(stage / "p11scope", work, progress=stage / "case-results.json")
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
    prepare_guest_disk(stage)
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
