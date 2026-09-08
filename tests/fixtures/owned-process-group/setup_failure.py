"""Inject only OS capability acquisition failures; real child/exec/settlement."""

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
from unittest import mock


path = Path(__file__).resolve().parents[2] / "support/owned_process_group.py"
spec = importlib.util.spec_from_file_location("owned_group_failure_subject", path)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
mode = sys.argv.pop(1)
control = Path(os.environ.get("OWNED_GROUP_CONTROL", "/nonexistent-owned-group-control"))
if mode == "contained_diagnostic":
    # The external unittest parent created this wholly owned session. Neither
    # sibling leaves it. A broken child kill(0) can reach only this container.
    signal.alarm(8)
    assert os.getpid() == os.getpgrp() == os.getsid(0), "requires a fresh owned session"
    (control / "container-owner").write_text(str(os.getpid()))
    children = []
    try:
        for argv in ([sys.executable, "-I", str(Path(__file__).with_name("workload.py")),
                      "survivor", str(control / "decoy-ready")],
                     [sys.executable, "-I", __file__, "child_diagnostic", *sys.argv[1:]]):
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                fd = os.pidfd_open(proc.pid)
            except BaseException:
                proc.kill()
                proc.wait(timeout=2)
                raise
            children.append((proc, fd))
            if len(children) == 1:
                deadline = time.monotonic() + 2
                while not (control / "decoy-ready").exists() and time.monotonic() < deadline:
                    if select.select([fd], [], [], 0.01)[0]:
                        break
                if not (control / "decoy-ready").exists():
                    raise RuntimeError("contained decoy never became ready")
        supervisor, supervisor_fd = children[1]
        if not select.select([supervisor_fd], [], [], 4)[0]:
            raise RuntimeError("contained supervisor did not finish")
        supervisor.wait(timeout=1)
        decoy_survived = not select.select([children[0][1]], [], [], 0)[0]
        (control / "container-result.json").write_text(json.dumps(
            dict(supervisor_exit=supervisor.returncode, decoy_survived=decoy_survived,
                 decoy_identity=json.loads((control / "decoy-ready").read_text()))))
    finally:
        statuses = []
        for proc, fd in children:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            statuses.append(dict(pid=proc.pid, returncode=proc.returncode))
            os.close(fd)
        (control / "container-waits.json").write_text(json.dumps(statuses))
    sys.exit(0)
elif mode == "child_diagnostic":
    owner = int((control / "container-owner").read_text())
    assert os.getpgrp() == os.getsid(0) == owner != os.getpid(), "requires containing-session custody"
    original_pid = os.getpid()
    original_write = os.write

    def fail_setsid():
        signal.alarm(8)
        (control / "child-before-setsid.json").write_text(json.dumps(
            dict(pid=os.getpid(), pgid=os.getpgrp(), sid=os.getsid(0))))
        raise OSError(1, "injected child setsid refusal")

    def fail_diagnostic(fd, value):
        if os.getpid() != original_pid and fd == 2:
            raise OSError(9, "injected child diagnostic refusal")
        return original_write(fd, value)

    with mock.patch.object(subject.os, "setsid", fail_setsid), mock.patch.object(subject.os, "write", fail_diagnostic):
        sys.exit(subject.main())
elif mode == "delayed_ready":
    original_select = subject.select.select

    def stop_after_ready(*args):
        result = original_select(*args)
        if result[0] and not (control / "ready-observed").exists():
            (control / "ready-observed").write_text("real select returned readiness\n")
            signal.raise_signal(signal.SIGSTOP)
        return result

    with mock.patch.object(subject.select, "select", stop_after_ready):
        sys.exit(subject.main())
if mode == "pidfd":
    with mock.patch.object(subject.os, "pidfd_open", side_effect=OSError(38, "injected pidfd refusal")):
        sys.exit(subject.main())
elif mode == "prctl":
    with mock.patch.object(subject.ctypes, "CDLL", side_effect=OSError(1, "injected prctl refusal")):
        sys.exit(subject.main())
raise ValueError(mode)
