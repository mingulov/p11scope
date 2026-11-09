# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned-child supervisor for run-mode browser cells.

``p11scope run`` ends capture when its owned child exits and honestly
reports process-tree members still present then (RUN_TREE_SURVIVORS)
plus any leader-exit assessment that sampled a live group
(``task_uprobe_link_losses``). Firefox's multiprocess teardown trails
the main process's exit, so the bare browser child ends capture while
descendants are still present or mid-teardown, and the never-mapped
oracle fails closed on both (the v0.7.0 browser-cells flake).

This supervisor is the owned child instead of the browser directly. It
marks itself a child subreaper (orphans reparent here, never to init),
spawns the browser in its own session (the command argv, stdio and env
inherited), and waits for the flow: with --flow-done, a complete
screenshot (the PNG trailer) ends the run even while the browser is
still alive; otherwise the browser's exit does. It then SIGKILLs the
whole browser group (stragglers, or main included at flow completion)
and reaps to ECHILD before exiting with the browser's code, or 0 for a
completed flow. The flow's artifacts are done by then, so the killed
processes' remaining work is teardown by definition; SIGKILL (never a
grace wait) collapses every in-flight teardown atomically instead of
leaving slow exits for the sampler to catch mid-teardown. The strike
itself goes through a pre-forked helper (~1ms group killpg, no scan),
so it beats even a fast shutdown wave; a post-spawn scan proves the
fresh group has no recycled-pgid stale members first, else
descent-checked scan-kill covers the run. Capture therefore always
ends on a quiesced tree. The browser's argv is passed through opaquely
and never inspected; only the supervisor's own --flow-done path is read.

The readiness signal is ECHILD (no descendants remain), not a timeout:
REAP_BUDGET_SECONDS only fails loud on a wedged tree, where the
observer's honest gap then judges the run. Termination (the observer's
--kill-on-timeout, Ctrl-C) SIGKILLs the tree at once and exits
128+signum, so nothing outlives the run. A browser that died by a
signal is propagated as the same signal death. Every internal failure
exits nonzero with a fixed stderr line (never argv/env values), so the
observer's nonzero exit fails the cell loud.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import signal
import subprocess
import sys
import time

#: Failsafe bound for tree reaping; the mechanism is ECHILD.
REAP_BUDGET_SECONDS = 30.0
_REAP_POLL_SECONDS = 0.05
_FLOW_POLL_SECONDS = 0.05

#: A screenshot is complete exactly when its PNG trailer landed.
_PNG_IEND_TRAILER = bytes.fromhex("0000000049454e44ae426082")

_PR_SET_CHILD_SUBREAPER = 36


def _fail(message):
    """Fixed-string stderr diagnostic; the exit code fails the cell loud."""
    print(f"reap_tree: {message}", file=sys.stderr)
    return 1


def _stat_ppid_pgrp(pid):
    """The (ppid, pgrp) of a live process; None when unreadable."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    try:
        fields = data.rsplit(b")", 1)[1].split()
        return int(fields[1]), int(fields[2])
    except (IndexError, ValueError):
        return None


def _descends_from(pid, ancestor):
    """True when pid's ppid chain reaches ancestor.

    A recycled pgid can still hold another session's orphaned members,
    which a bare group scan would mistake for ours; only a process that
    descends from us (or reparented to us as subreaper) is our tree.
    """
    seen = set()
    current = pid
    while current not in (0, 1) and current not in seen:
        if current == ancestor:
            return True
        seen.add(current)
        sample = _stat_ppid_pgrp(current)
        if sample is None:
            return False
        current = sample[0]
    return False


def _group_members(pgid):
    """Live PIDs in our process group besides ourselves (a /proc scan)."""
    me = os.getpid()
    members = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return members
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        sample = _stat_ppid_pgrp(pid)
        if sample is not None and sample[1] == pgid:
            members.append(pid)
    return members


def _tree_members(pgid):
    """Our tree's live PIDs besides ourselves (group scan, descent-checked)."""
    me = os.getpid()
    return [pid for pid in _group_members(pgid) if _descends_from(pid, me)]


def _killer_main(pipe_r, pgid):
    """Forked helper: every requested byte SIGKILLs the group at once.

    One killpg lands in ~1ms with no scan; the browser's own session
    keeps our group out of it. EOF (or a read error) exits.
    """
    try:
        devnull = os.open(os.devnull, os.O_RDWR)
        for stdio in (0, 1, 2):
            try:
                os.dup2(devnull, stdio)
            except OSError:
                pass
    except OSError:
        pass
    while True:
        try:
            chunk = os.read(pipe_r, 1)
        except OSError:
            break
        if not chunk:
            break
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    os._exit(0)


def _spawn_killer(pgid):
    """Fork the outside-group killpg helper; None when unavailable."""
    try:
        pipe_r, pipe_w = os.pipe()
        killer = os.fork()
    except OSError:
        return None
    if killer == 0:
        try:
            os.close(pipe_w)
        except OSError:
            pass
        _killer_main(pipe_r, pgid)
        os._exit(1)  # Unreachable; _killer_main always exits.
    try:
        os.close(pipe_r)
    except OSError:
        pass
    return (killer, pipe_w)


def _poke_killer(killer):
    """One group SIGKILL via the helper; False when it is gone."""
    if killer is None:
        return False
    try:
        os.write(killer[1], b"K")
        return True
    except OSError:
        return False


def _close_killer(killer):
    """Stop the helper and reap exactly it (never the tree)."""
    if killer is None:
        return
    pid, pipe_w = killer
    try:
        os.close(pipe_w)
    except OSError:
        pass
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            done, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if done != 0:
            return
        time.sleep(0.01)


def _kill_tree(pgid):
    """SIGKILL every tree member besides ourselves (shutdown is over)."""
    for pid in _tree_members(pgid):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            continue


def _reap_children():
    """Reap every exited child; True when none remain (ECHILD)."""
    try:
        while True:
            pid, _status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                return False
    except ChildProcessError:
        return True


def _reap_tree(pgid, killer=None, budget=REAP_BUDGET_SECONDS):
    """SIGKILL stragglers until ECHILD; False when the bound expires.

    The first strike goes through the killpg helper (~1ms, no scan),
    which then exits and is reaped with the tree; scan-kill follows up
    anything the strike missed while the loop verifies quiescence
    (ECHILD plus no tree members).
    """
    _poke_killer(killer)
    _close_killer(killer)
    deadline = time.monotonic() + budget
    while True:
        _kill_tree(pgid)
        if _reap_children() and not _tree_members(pgid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_REAP_POLL_SECONDS)


def _install_termination_handler(state):
    """Termination kills the tree at once and exits 128+signum.

    ``state`` carries the browser group and helper once spawned; before
    that there is no tree to kill.
    """

    def terminate(signum, _frame):
        _poke_killer(state["killer"])
        if state["pgid"] is not None:
            _kill_tree(state["pgid"])
        _reap_children()
        os._exit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, terminate)


def _flow_complete(shot):
    """True when the screenshot file carries a complete PNG trailer.

    Only the last eight bytes are ever read; a missing, short, or
    unreadable file is simply incomplete.
    """
    if shot is None:
        return False
    try:
        with open(shot, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() < len(_PNG_IEND_TRAILER):
                return False
            handle.seek(-len(_PNG_IEND_TRAILER), os.SEEK_END)
            return handle.read(len(_PNG_IEND_TRAILER)) == _PNG_IEND_TRAILER
    except OSError:
        return False


def _claim_subreaper():
    """Mark ourselves a child subreaper; False when refused."""
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        libc.prctl.argtypes = [ctypes.c_ulong] * 5
        return libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except OSError:
        return False


def main(argv):
    rest = argv[1:]
    shot = None
    if len(rest) >= 2 and rest[0] == "--flow-done":
        shot = rest[1]
        rest = rest[2:]
    if not rest:
        return _fail("usage: reap_tree.py [--flow-done shot.png] <command> [args ...]")
    if sys.platform != "linux":
        return _fail("the owned-child supervisor is Linux-only")
    if not _claim_subreaper():
        return _fail("the child-subreaper bit is unavailable")
    state = {"pgid": None, "killer": None}
    _install_termination_handler(state)
    try:
        # The browser founds its own session: the killpg helper and the
        # reaper act on exactly that group, never ours.
        child = subprocess.Popen(rest, start_new_session=True)
    except OSError:
        return _fail("the browser failed to start")
    group = child.pid
    # The killpg helper is safe only behind a clean group: a recycled
    # pgid's stale members (another session's orphans) would catch the
    # unfiltered SIGKILL too. Nobody can join the browser's fresh
    # session group except our own descendants, so one scan now proves
    # the helper safe for the whole run; otherwise scan-kill.
    me = os.getpid()
    stale = [pid for pid in _group_members(group) if not _descends_from(pid, me)]
    state["killer"] = None if stale else _spawn_killer(group)
    state["pgid"] = group
    while True:
        if _flow_complete(shot):
            break
        if child.poll() is not None:
            break
        time.sleep(_FLOW_POLL_SECONDS)
    code = child.returncode
    quiesced = _reap_tree(group, state["killer"])
    if not quiesced:
        print("reap_tree: the process tree would not quiesce", file=sys.stderr)
    if code is None:
        # The flow completed while the browser was still running: the
        # tree (main included) was SIGKILLed above, and its remaining
        # work was pure teardown, so the completed flow exits 0.
        return 0
    if code < 0:
        # The browser died by a signal: die by it too, so the observer
        # sees a spontaneous signal death rather than our exit code.
        signum = -code
        try:
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        except (OSError, ValueError, RuntimeError):
            pass
        return 128 + signum
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
