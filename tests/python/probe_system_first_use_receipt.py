#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit privileged receipt prerequisite, never an ordinary-suite skip.

The outer owner must already hold the shared live leases and supervisor
custody, and pin this script, its helpers, fixture binaries and inputs.
This probe does not attach BPF or qualify observer first-use capture.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

m = load_path(ROOT / "scripts/system_first_use_receipt.py", "first_use_receipt")
c = load_path(ROOT / "scripts/canary_process_custody.py", "first_use_custody")


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run_case(args, name):
    directory = args.out / name
    directory.mkdir(mode=0o700)
    receipt_dir = directory / "raw"
    receipt_dir.mkdir(mode=0o700)
    source = args.heap if name == "heap" else args.provider
    provider = directory / "provider.so"
    shutil.copyfile(source, provider)
    expected = m.mapping.file_identity(provider)
    nonce = secrets.token_hex(32)
    ledger = directory / "ledger.jsonl"
    receive, send = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    result = {"case": name, "status": "INVALID", "expected": expected,
              "driver_sha256": hashlib.sha256(args.driver.read_bytes()).hexdigest(),
              "provider_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    parent_namespace = m.mapping.read_mount_namespace("/proc", os.getpid())
    with receive, send:
        receive.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        command = [str(args.driver), str(provider), str(ledger), "-", "-",
                   str(send.fileno()), nonce, str(receipt_dir)]
        if name == "mount-namespace":
            command = ["unshare", "--mount", "--propagation", "private", "--", *command]
        if name == "permission-refusal":
            command = ["setpriv", "--bounding-set=-checkpoint_restore,-sys_admin", "--", *command]
        result["command"] = command
        write(directory / "invocation.json", result)
        with (directory / "stdout").open("xb") as out, (directory / "stderr").open("xb") as err:
            try:
                with c.Custody() as owner:
                    deadline = time.monotonic() + 5
                    child = owner.launch(command, role="workload", stdout=out, stderr=err,
                                         pass_fds=(send.fileno(),), deadline=deadline)
                    send.close()
                    result.update(pid=child.popen.pid, birth=child.group.generation)
                    # Preserve the ordinary wait owner and pin, but deliberately
                    # receive only after the child is terminal. No observer gate.
                    while not select.select([child.group.fd], [], [], min(m.remaining(deadline), .05))[0]:
                        owner.check_cancelled()
                    result["terminal_before_receive"] = True
                    if name == "permission-refusal":
                        status = child.wait(deadline)
                        result["fixture_exit"] = status
                        phases = [json.loads(line)["phase"] for line in ledger.read_text().splitlines()]
                        m.require(status != 0 and "entry_executed" in phases
                                  and "entry_returned" in phases and "receipt_started" in phases
                                  and "receipt_sent" not in phases, "permission control did not reach acquisition")
                        m.require("Operation not permitted" in (directory / "stderr").read_text(),
                                  "permission control did not prove map_files EPERM")
                        m.require((receipt_dir / "maps-before").is_file()
                                  and not (receipt_dir / "mountinfo").exists(),
                                  "permission failure was not at map_files acquisition")
                        m.terminal_eof(receive)
                        result["status"] = "EXPECTED_REFUSAL"
                    else:
                        receipt = m.collect(receive, child, nonce, receipt_dir, expected, ledger, deadline)
                        if name == "mount-namespace":
                            m.require(receipt["mount_namespace_identity_before"] != parent_namespace,
                                      "mount namespace was not changed")
                        write(directory / "receipt.json", receipt)
                        result["status"] = "RECEIPT_VERIFIED"
                    result["child_settled"] = child.settled
                result["pidfd_closed"] = child.group.closed
            except Exception as error:
                result.update(status="INVALID", error=f"{type(error).__name__}: {error}")
            finally:
                write(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("driver", "provider", "heap", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    m.require(os.geteuid() == 0, "explicit privileged receipt prerequisite requires root")
    for name in ("driver", "provider", "heap"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.out.mkdir(mode=0o700)
    rows = []
    for name in ("file", "heap", "mount-namespace", "permission-refusal"):
        rows.append(run_case(args, name))
        if rows[-1]["status"] == "INVALID":
            break
    write(args.out / "results.json", {"receipt_prerequisite_only": True, "cases": rows})
    return 0 if len(rows) == 4 and all(r["status"] != "INVALID" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
