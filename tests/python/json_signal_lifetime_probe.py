#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Small entry module for the JSON signal-lifetime probe.

`test_canary_evidence.py` used to run this probe via `runpy` on the whole
~3000-line test module, so the probe child paid the full import cost inside
the parent's sub-second PID-publication wait. Importing this module instead
keeps the probe's startup cost to one small file plus the dumper script.
The probe body is unchanged; it is also re-exported to the test module so
existing `runpy`-based call sites keep working.
"""

import ctypes
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
DUMPER = ROOT / "scripts" / "dump-owned-bpf-maps.py"

sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


def load_dumper():
    return load_path(DUMPER, "owned_bpf_maps")


def json_signal_lifetime_probe(case, interposer=None):
    """Run a signal-boundary probe under the test parent's independent timeout."""
    dumper = load_dumper()
    real_popen, real_open = subprocess.Popen, os.pidfd_open
    real_mask = signal.pthread_sigmask
    real_selector = dumper.selectors.DefaultSelector
    before = real_mask(signal.SIG_BLOCK, [])
    spawned, handles, selectors = [], [], []
    # Must outlive the parent's 5 s PID-publication wait (watchdog-stall):
    # an early exit would make the parent's exit-readiness poll non-empty
    # before the watchdog fires. Torn down by the probe for cases that
    # complete, by the external watchdog for watchdog-stall.
    unrelated = real_popen([sys.executable, "-c", "import time; time.sleep(60)"])
    injected = False
    errors = []

    def capture_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        if case == "watchdog-stall":
            pending = Path(interposer).with_suffix(".tmp")
            pending.write_text(json.dumps([os.getpid(), process.pid, unrelated.pid]))
            pending.replace(interposer)
        return process

    def capture_open(pid, flags=0):
        fd = real_open(pid, flags)
        handles.append(fd)
        return fd

    def capture_selector():
        selector = real_selector()
        selectors.append(selector)
        return selector

    def interposed_mask(how, signals):
        nonlocal injected
        if how == signal.SIG_BLOCK and signal.SIGINT in signals and not injected:
            injected = True
            # The real native call raises SIGINT before changing the kernel
            # mask. Python delivers KeyboardInterrupt only after it returns.
            native.interrupt_then_block()
        return real_mask(how, signals)

    lifetime = getattr(dumper, "_run_bounded_bytes", dumper.run_json)
    source, first_line = inspect.getsourcelines(lifetime)
    boundary = ("        cleanup_error = None\n" if case.startswith("entry") else
                "        if streams is not None:\n")
    boundary_line = first_line + source.index(boundary)

    def trace(frame, event, _arg):
        nonlocal injected
        if (event == "line" and frame.f_code is lifetime.__code__
                and frame.f_lineno == boundary_line and not injected):
            injected = True
            # A real signal at a control-flow boundary, outside cleanup(action).
            os.kill(os.getpid(), signal.SIGINT)
        return trace

    def closed_fd(fd):
        try:
            os.fstat(fd)
        except OSError:
            return True
        return False

    try:
        if case == "mask-mutation":
            native = ctypes.PyDLL(interposer)
            native.interrupt_then_block.argtypes = []
            native.interrupt_then_block.restype = ctypes.c_int
            mask_patch = mock.patch.object(dumper.signal, "pthread_sigmask",
                                           side_effect=interposed_mask)
        else:
            mask_patch = mock.patch.object(dumper.signal, "pthread_sigmask", wraps=real_mask)
            sys.settrace(trace)
        try:
            with mock.patch.object(dumper.subprocess, "Popen", side_effect=capture_popen), \
                    mock.patch.object(dumper.os, "pidfd_open", side_effect=capture_open), \
                    mock.patch.object(dumper.selectors, "DefaultSelector", side_effect=capture_selector), \
                    mask_patch:
                # The watchdog-stall probe must still be lingering when the
                # parent's external `timeout` guard fires (6 s): its child
                # sleeps far beyond that guard, and its own acquisition
                # deadline is run_json's 8 s maximum, which the guard beats
                # with margin. The expiry under test is the external
                # watchdog's, not this one.
                dumper.run_json([sys.executable, "-c", (
                    "import time; time.sleep(60)" if case == "watchdog-stall"
                    else "import time; time.sleep(5)" if case == "entry-live"
                    else "print('[]')")],
                    timeout_seconds=8 if case == "watchdog-stall" else 0.2, max_bytes=1024)
        except BaseException as error:
            while error is not None:
                errors.append({"type": type(error).__name__, "message": str(error)})
                error = error.__cause__
        finally:
            sys.settrace(None)

        reaped = []
        for process in spawned:
            try:
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                reaped.append(False)
            except ChildProcessError:
                reaped.append(True)
        selector_closed = []
        for selector in selectors:
            try:
                selector.select(0)
                selector_closed.append(False)
            except ValueError:
                selector_closed.append(True)
        report = {
            "injected": injected, "errors": errors,
            "mask_before": sorted(before),
            "mask_after": sorted(real_mask(signal.SIG_BLOCK, [])),
            "spawn_count": len(spawned), "reaped": reaped,
            "pipes_closed": [p.stdout.closed and p.stderr.closed for p in spawned],
            "pidfds_closed": [closed_fd(fd) for fd in handles],
            "selectors_closed": selector_closed,
            "unrelated_alive": unrelated.poll() is None,
        }
    finally:
        sys.settrace(None)
        # Safe RED teardown: restore the caller mask and close/terminate/reap
        # only the actual children and resources captured by this probe.
        real_mask(signal.SIG_SETMASK, before)
        for process in spawned:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)
            process.stdout.close()
            process.stderr.close()
        for selector in selectors:
            selector.close()
        for fd in handles:
            if not closed_fd(fd):
                os.close(fd)
        unrelated.kill()
        unrelated.wait(timeout=1)
    print(json.dumps(report))


def main(argv):
    if len(argv) < 2 or len(argv) > 3:
        raise SystemExit(f"usage: {Path(argv[0]).name} <case> [interposer]")
    case = argv[1]
    interposer = argv[2] if len(argv) > 2 else None
    json_signal_lifetime_probe(case, interposer)


if __name__ == "__main__":
    main(sys.argv)
