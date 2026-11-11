#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""One combined stock pre-Multi refusal guest, not an old positive/load lane.

The caller reserves the guest lane. Image checksums belong to the workflow;
this driver verifies the transferred observer/script and actual kernel.

With --libtest/--denial the guest also runs the dual-outcome identity
cell for one named branch (denied on 5.15, eligible elsewhere) and fails
on any other marker.

`inventory --capture auto` rows expect the scan fallback (exit 0 with a
valid inventory/v1 document that names the unavailable counts); every
other live row (doctor, profile, counter, run, `inventory --capture
native`) still refuses before any capture side effect.

With --expect-counter-objects 0 the counter rows expect the exact
counter-mode omission refusal of a build without counter objects (a
SMALL build) instead of the live-capture refusal; every other row is
unchanged. The build gate fires before any kernel probe, so on a
pre-Multi host the omission refusal wins over the live-capture one.
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

REFUSAL_LEADS = (
    "live capture needs CAP_",
    "live capture refused: ",
    "live capture unavailable: ",
    "live capture did not start: ",
)


def refused(output):
    """Whether the observer refused with its finite live-capture refusal."""
    return any(lead in output for lead in REFUSAL_LEADS)


COUNTER_OMISSION_REFUSAL = "counter-mode-unavailable-in-build: this build omits counter objects"


FALLBACK_GAP_SUBJECT = "native usage feed unavailable"
FALLBACK_REASON_FRAGMENT = "call counts unavailable on this host"


def fallback_document(sink):
    """The scan-fallback inventory document, or None when absent/invalid.

    A pre-Multi `inventory --capture auto` run exits 0 with modules and
    callers but no counts: the schema must be inventory/v1, the
    observation must not claim a usage feed, must keep at least one
    pass, and one gap must name the unavailable counts. No
    refusal-lead check applies here: the stderr fallback notice embeds
    the host summary, which carries a lead.
    """
    try:
        document = json.loads(sink.read_bytes())
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("schema") != "p11scope/inventory/v1":
        return None
    observation = document.get("observation")
    if not isinstance(observation, dict) or observation.get("usage_feed") is not False:
        return None
    if type(observation.get("passes")) is not int or observation["passes"] < 1:
        return None
    gaps = document.get("gaps")
    if not isinstance(gaps, list):
        return None
    for gap in gaps:
        if (isinstance(gap, dict) and gap.get("subject") == FALLBACK_GAP_SUBJECT
                and FALLBACK_REASON_FRAGMENT in str(gap.get("reason", ""))):
            return document
    return None
DENIAL_CELL = "inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed"
DENIAL_MARKER = "IDENTITY_515_DENIAL outcome="
OUTPUT_LIMIT = 4096
WORK_IMAGE_BYTES = 128 * 1024 * 1024
GUEST_WORK_MOUNT = Path("/var/tmp")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_commands(observer, work, progress=None, doctor_timeout=60,
                   expect_counter_objects=1):
    """Exercise actual command/sink/workload boundaries; callable unprivileged.

    doctor_timeout is a liveness bound only (the refusal oracle is
    unchanged): the old verifiers grind ~65 s through doctor's preflight
    loads (measured 65 s on 5.15, 64 s on 6.1), so refusal guests pass
    300 there. expect_counter_objects selects the counter-row oracle:
    1 demands the live-capture refusal (a build with counter objects),
    0 demands the exact counter-mode omission refusal (a build without
    them); every other row is unchanged either way.
    """
    if expect_counter_objects not in (0, 1):
        raise ValueError("expect_counter_objects must be 0 or 1")
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
        result = run(case, argv, doctor_timeout if case == "doctor" else 20)
        try:
            sink_unchanged = case == "doctor" or (sink.read_bytes() == before and sink.stat().st_ino == identity)
        except OSError:
            sink_unchanged = False
        output = result.stdout + result.stderr
        if case.startswith("inventory-auto-"):
            complete(case, result, "fallback", [
                ("fallback_exit", result.returncode == 0,
                 "expected scan fallback: nonzero exit"),
                ("fallback_document", fallback_document(sink) is not None,
                 "expected scan-fallback inventory document with the named counts gap"),
                ("workload_not_run", not sentinel.exists(),
                 "user workload executed before fallback"),
            ], "scan fallback")
            continue
        if case.startswith("counter-") and not expect_counter_objects:
            complete(case, result, "refused", [
                ("refusal_exit", result.returncode > 0,
                 "expected nonzero setup refusal"),
                ("omission_refusal", COUNTER_OMISSION_REFUSAL in output,
                 "missing counter-mode omission refusal"),
                ("sink_unchanged", sink_unchanged, "pre-existing sink changed"),
                ("workload_not_run", not sentinel.exists(),
                 "user workload executed before refusal"),
            ], "counter-mode omission refusal")
            continue
        complete(case, result, "refused", [
            ("refusal_exit", result.returncode > 0, "expected nonzero setup refusal"),
            ("named_refusal", refused(output), "missing live-capture refusal"),
            ("sink_unchanged", sink_unchanged, "pre-existing sink changed"),
            ("workload_not_run", not sentinel.exists(), "user workload executed before refusal"),
        ], "live-capture refusal")
    for case, argv in (("help", ["--help"]), ("version", ["--version"])):
        result = run(case, argv, 20)
        complete(case, result, "offline-ok", [
            ("offline_exit", result.returncode == 0, "offline command blocked: nonzero exit"),
            ("live_gate_absent", not refused(result.stdout + result.stderr), "offline command blocked: live gate"),
        ])
    report = work / "scan.json"
    result = run("inventory-scan", ["inventory", "--pid", str(os.getpid()),
                                   "--capture", "scan", "--json", "-o", str(report)], 30)
    checks = [
        ("offline_exit", result.returncode == 0, "offline command blocked: nonzero exit"),
        ("report_exists", report.is_file(), "offline command blocked: missing report"),
        ("live_gate_absent", not refused(result.stdout + result.stderr), "offline command blocked: live gate"),
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
        ("live_gate_absent", not refused(result.stdout + result.stderr), "offline command blocked: live gate"),
    ])
    return rows


def check_denial_cell(libtest, work, expect, progress=None):
    """Run the 5.15 identity cell for one named branch; callable unprivileged."""
    if expect not in ("denied", "eligible"):
        raise RuntimeError("denial branch must be denied or eligible")
    args = [str(libtest), "--exact", DENIAL_CELL, "--ignored",
            "--test-threads=1", "--nocapture"]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=120,
                                cwd=str(work))
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(args, None, error.stdout,
                                             error.stderr)
    except OSError as error:
        result = subprocess.CompletedProcess(args, None, "", str(error))
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    stderr = result.stderr if isinstance(result.stderr, str) else ""
    combined = stdout + stderr
    other = "eligible" if expect == "denied" else "denied"
    checks = [
        ("cell_exit", result.returncode == 0, "identity cell exited nonzero"),
        ("cell_single_pass",
         "test result: ok. 1 passed" in combined,
         "identity cell did not report exactly one pass"),
        ("denial_branch", DENIAL_MARKER + expect in combined,
         "missing " + DENIAL_MARKER + expect),
        ("denial_single_branch", DENIAL_MARKER + other not in combined,
         "unexpected " + DENIAL_MARKER + other),
    ]
    failed = [(name, message) for name, passed, message in checks if not passed]
    row = {"case": "identity-515-denial",
           "outcome": "failed" if failed else "disclosed",
           "rc": result.returncode, "command": result.args,
           "failed_predicates": [name for name, _ in failed]}
    for stream, output in (("stdout", stdout), ("stderr", stderr)):
        row[stream] = output[-OUTPUT_LIMIT:]
        row[stream + "_truncated"] = len(output) > OUTPUT_LIMIT
    if not failed:
        row["reason"] = DENIAL_MARKER + expect
    if progress is not None:
        try:
            cases = json.loads(progress.read_text()).get("cases", [])
        except (OSError, ValueError, AttributeError):
            cases = []
        cases.append(row)
        progress.write_text(json.dumps({"cases": cases}, indent=2) + "\n")
    if failed:
        raise RuntimeError("identity-515-denial: "
                           + "; ".join(message for _, message in failed))
    return row


def stage_guest_binaries(stage, parent, metadata):
    """Copy the transferred binaries to guest-local disk, verified.

    The 9p share demand-pages a 391 MB observer in 65 s on 5.15 (FS-Cache
    per-page pathology); a sequential copy takes 10 s and every later
    case runs from fast local disk. The copies are re-verified against
    the transferred digests before anything executes them.
    """
    destdir = Path(tempfile.mkdtemp(prefix="refusal-bin-", dir=str(parent)))
    os.chmod(destdir, 0o700)
    names = ["p11scope"] + (["lib-tests"] if metadata.get("denial") is not None else [])
    staged = {}
    for name in names:
        target = destdir / name
        shutil.copyfile(stage / name, target)
        os.chmod(target, 0o700)
        if digest(target) != metadata["sha256"][name]:
            raise RuntimeError("staged binary mismatch: " + name)
        staged[name] = target
    return destdir, staged


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
    counter_objects = metadata.get("counter_objects", 1)
    if counter_objects not in (0, 1):
        raise RuntimeError("corrupt counter-object expectation")
    os.umask(0o022)
    context = {"kernel": kernel, "observer_sha256": metadata["sha256"]["p11scope"],
               "runner_uid": metadata["runner_uid"], "euid": os.geteuid(),
               "sudo_uid": os.environ.get("SUDO_UID")}
    with guest_disk_work(stage) as work:
        os.environ["TMPDIR"] = str(work)
        bindir, staged = stage_guest_binaries(stage, Path("/tmp"), metadata)
        # Every refusal guest is pre-Multi with an old slow verifier
        # (measured: 65 s on 5.15, 64 s on 6.1; OD32/CP-5 accept old
        # kernels slow but correct). Liveness bound only; the refusal
        # oracle is unchanged.
        doctor_timeout = 300
        context.update({"work": str(work), "work_uid": work.stat().st_uid,
                        "work_mode": oct(work.stat().st_mode & 0o777),
                        "work_filesystem": "ext4", "bindir": str(bindir),
                        "doctor_timeout": doctor_timeout})
        (stage / "guest-context.json").write_text(json.dumps(context, indent=2) + "\n")
        rows = check_commands(staged["p11scope"], work, progress=stage / "case-results.json",
                              doctor_timeout=doctor_timeout,
                              expect_counter_objects=counter_objects)
        if metadata.get("denial") is not None:
            rows.append(check_denial_cell(staged["lib-tests"], work,
                                          metadata["denial"],
                                          progress=stage / "case-results.json"))
    result = {"kernel": kernel, "observer_sha256": metadata["sha256"]["p11scope"],
              "qualification": "unsupported-host-refusal", "capture_positive": False,
              "cases": rows}
    (stage / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("MULTI_HOST_REFUSAL PASS cases=" + str(len(rows)) + " capture_positive=false")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--libtest", default=None,
                        help="lib-test binary for the identity denial cell")
    parser.add_argument("--denial", default=None,
                        choices=("denied", "eligible"),
                        help="expected identity-cell branch (needs --libtest)")
    parser.add_argument("--expect-counter-objects", default=1, type=int,
                        choices=(0, 1),
                        help="counter rows expect the counter objects (1) "
                             "or the exact omission refusal of a build "
                             "without them (0, a SMALL build)")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.guest:
        if len(args.paths) != 1:
            parser.error("guest requires STAGE")
        guest(Path(args.paths[0]))
        return 0
    if len(args.paths) != 3:
        parser.error("requires OBSERVER FRESH_STAGE KERNEL")
    if (args.libtest is None) != (args.denial is None):
        parser.error("--libtest and --denial are required together")
    observer = Path(args.paths[0]).resolve(strict=True)
    libtest = Path(args.libtest).resolve(strict=True) if args.libtest else None
    stage = Path(args.paths[1]).absolute()
    kernel = args.paths[2]
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", kernel) is None:
        parser.error("use an explicit stock kernel release")
    # Refuse reuse; the source tree and every other task remain untouched.
    stage.mkdir(mode=0o700)
    shutil.copy2(observer, stage / "p11scope")
    shutil.copy2(Path(__file__).resolve(), stage / "guest.py")
    names = ["p11scope", "guest.py"]
    if libtest is not None:
        shutil.copy2(libtest, stage / "lib-tests")
        names.append("lib-tests")
    prepare_guest_disk(stage)
    metadata = {"kernel": kernel, "runner_uid": stage.stat().st_uid,
                "sha256": {name: digest(stage / name) for name in names}}
    if args.denial is not None:
        metadata["denial"] = args.denial
    metadata["counter_objects"] = args.expect_counter_objects
    (stage / "inputs.json").write_text(json.dumps(metadata) + "\n")
    command = shlex.join(["python3", str(stage / "guest.py"), "--guest", str(stage)])
    # Liveness bound only: a healthy 5.15 run needs boot (~111 s) plus
    # staged binaries plus ~65 s of doctor verifier grind plus 20 more
    # cases, which a loaded host cannot fit in 300 s. The refusal oracle
    # is unchanged; a hung guest still fails loudly here.
    with (stage / "guest.log").open("w") as log:
        result = subprocess.run(["timeout", "-k", "20", "600", "vng", "--run", kernel,
                                 "--user", "root", "--cpus", "2", "--memory", "4G",
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
