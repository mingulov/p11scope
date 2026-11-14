#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Pinned-rate PKCS#11 churn driver for the v0.8.0 memory soaks (A0/A1).

Drives a probed SoftHSM2 module at a fixed iteration rate with a fixed
share of deliberately failing calls, so the observer's memory counters
(R1-R12) and the trace R11 roll-up all move under a reproducible load.
Single-threaded; an optional fork share adds short-lived processes for
the R12 live/dead split.

Reads no credentials: it uses a private SOFTHSM2_CONF under a mkdtemp
dir, initializes one throwaway token there, and the only "PIN" in play
is a wrong PIN sent to provoke CKR failures (never a real secret; the
observer captures call metadata only, never PINs).
"""
import argparse
import ctypes
import os
import shutil
import signal
import subprocess
import tempfile
import time

CKR_OK = 0
CKF_SERIAL_SESSION = 0x4
CKF_RW_SESSION = 0x2
CKU_USER = 1

# cryptoki.h order: C_Initialize is index 0 after the version word.
I_INIT = 0
I_FINALIZE = 1
I_GET_SLOT_LIST = 4
I_OPEN_SESSION = 12
I_CLOSE_SESSION = 13
I_LOGIN = 18

CANDIDATE_LIBS = [
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Debian/Ubuntu
    "/usr/lib64/pkcs11/libsofthsm2.so",  # Fedora
    "/usr/lib/softhsm/libsofthsm2.so",
]


class CK_VERSION(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [("version", CK_VERSION), ("funcs", ctypes.c_void_p * 68)]


STOP = False


def _stop(signum, frame):
    global STOP
    STOP = True


def probe_lib(explicit):
    """Return the SoftHSM path: explicit override, else first readable candidate."""
    if explicit:
        if os.access(explicit, os.R_OK):
            return explicit
        raise SystemExit(f"mem-churn: --lib {explicit} is not readable")
    for path in CANDIDATE_LIBS:
        if os.access(path, os.R_OK):
            return path
    raise SystemExit(
        "mem-churn: no SoftHSM2 module found (tried "
        + ", ".join(CANDIDATE_LIBS)
        + "); pass --lib"
    )


def private_conf(workdir):
    tokendir = os.path.join(workdir, "tokens")
    os.makedirs(tokendir, exist_ok=True)
    conf = os.path.join(workdir, "softhsm2.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write(
            "directories.tokendir = %s\n"
            "objectstore.backend = file\n"
            "slots.removable = false\n" % tokendir
        )
    return conf


class Driver:
    def __init__(self, libpath):
        self.lib = ctypes.CDLL(libpath)
        get_list = ctypes.CFUNCTYPE(
            ctypes.c_ulong, ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))
        )(("C_GetFunctionList", self.lib))
        flist = ctypes.POINTER(CK_FUNCTION_LIST)()
        rv = get_list(ctypes.byref(flist))
        if rv != CKR_OK:
            raise SystemExit(f"mem-churn: C_GetFunctionList rv={rv:#x}")
        self.flist = flist.contents
        if self.flist.version.major not in (2, 3):
            raise SystemExit(
                f"mem-churn: unexpected function-list version "
                f"{self.flist.version.major}.{self.flist.version.minor}"
            )
        funcs = self.flist.funcs
        self.init = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(
            funcs[I_INIT]
        )
        self.finalize = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(
            funcs[I_FINALIZE]
        )
        self.get_slot_list = ctypes.CFUNCTYPE(
            ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_void_p, ctypes.c_void_p
        )(funcs[I_GET_SLOT_LIST])
        self.open_session = ctypes.CFUNCTYPE(
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )(funcs[I_OPEN_SESSION])
        self.close_session = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong)(
            funcs[I_CLOSE_SESSION]
        )
        self.login = ctypes.CFUNCTYPE(
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
        )(funcs[I_LOGIN])

    def slots(self):
        count = ctypes.c_ulong(0)
        rv = self.get_slot_list(0, None, ctypes.byref(count))
        if rv != CKR_OK or count.value == 0:
            return []
        buf = (ctypes.c_ulong * count.value)()
        rv = self.get_slot_list(0, buf, ctypes.byref(count))
        if rv != CKR_OK:
            return []
        return [buf[i] for i in range(count.value)]


def init_token(conf):
    """Initialize slot 0 in the private conf so sessions open.

    Test PINs only, local to this throwaway token; the failing-login
    shape below deliberately uses a wrong PIN. The observer never
    captures PINs (call metadata only). Fatal on failure (Important 2):
    a missing tool or a failed init would otherwise degrade silently to
    an all-failure workload that the bench/soaks accept.
    """
    tool = shutil.which("softhsm2-util")
    if tool is None:
        raise SystemExit("mem-churn: softhsm2-util missing (token init required)")
    env = dict(os.environ, SOFTHSM2_CONF=conf)
    proc = subprocess.run(
        [tool, "--init-token", "--slot", "0", "--label", "mem-churn",
         "--so-pin", "1234", "--pin", "1234"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"mem-churn: token init failed ({proc.stderr.strip()})"
        )


def reap():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def run(args):
    libpath = probe_lib(args.lib)
    workdir = tempfile.mkdtemp(prefix="mem-churn-")
    try:
        conf = private_conf(workdir)
        os.environ["SOFTHSM2_CONF"] = conf
        init_token(conf)
        drv = Driver(libpath)
        rv = drv.init(None)
        if rv != CKR_OK:
            raise SystemExit(f"mem-churn: C_Initialize rv={rv:#x}")
        slots = drv.slots()
        if not slots:
            raise SystemExit("mem-churn: module reports no slots")
        slot = slots[0]
        # First success-shape open (Important 2): fail fast on a wrong
        # slot order or an unusable token, instead of running a full
        # all-failure soak that the bench would accept.
        probe_handle = ctypes.c_ulong(0)
        if (
            drv.open_session(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(probe_handle),
            )
            != CKR_OK
        ):
            raise SystemExit(
                f"mem-churn: first success-shape open failed (slot={slot})"
            )
        drv.close_session(probe_handle.value)
        print(
            f"mem-churn: lib={libpath} slots={len(slots)} rate={args.rate}/s "
            f"fail_share={args.fail_share} fork_every={args.fork_every} "
            f"duration={args.duration}s",
            flush=True,
        )

        period = 1.0 / args.rate
        fail_every = (
            int(round(1.0 / args.fail_share)) if args.fail_share > 0 else 0
        )
        start = time.monotonic()
        deadline = start + args.duration
        ok = fail = forked = 0
        ok_attempts = 0
        iteration = 0
        last_report = start
        try:
            while not STOP and time.monotonic() < deadline:
                tick = time.monotonic()
                do_fail = fail_every and (iteration % fail_every) == (fail_every - 1)
                do_fork = args.fork_every and (iteration % args.fork_every) == 0
                if do_fork and not do_fail:
                    pid = os.fork()
                    # Child: one open+close, then exit, WITHOUT a fresh
                    # C_Initialize (it inherits the parent's initialized
                    # state across fork). SoftHSM tolerates this; other
                    # providers may not (Minor 8: forked children are a
                    # SoftHSM-only shape).
                    if pid == 0:
                        try:
                            handle = ctypes.c_ulong(0)
                            if (
                                drv.open_session(
                                    slot,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    None,
                                    None,
                                    ctypes.byref(handle),
                                )
                                == CKR_OK
                            ):
                                drv.close_session(handle.value)
                        finally:
                            os._exit(0)
                    # Forked attempts count only in `forked`: the child's
                    # open/close result is invisible to the parent, so the
                    # done line partitions (ok + fail + forked == iterations).
                    forked += 1
                    reap()
                elif do_fail:
                    shape = (iteration // max(fail_every, 1)) % 3
                    if shape == 0:
                        handle = ctypes.c_ulong(0)
                        drv.open_session(
                            0xFFFFFFFF, CKF_SERIAL_SESSION, None, None,
                            ctypes.byref(handle),
                        )
                    elif shape == 1:
                        drv.close_session(0xFFFFFFFE)
                    else:
                        drv.login(0xFFFFFFFD, CKU_USER, b"wrong-pin", 9)
                    fail += 1
                else:
                    ok_attempts += 1
                    handle = ctypes.c_ulong(0)
                    if (
                        drv.open_session(
                            slot,
                            CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            None,
                            None,
                            ctypes.byref(handle),
                        )
                        == CKR_OK
                    ):
                        drv.close_session(handle.value)
                        ok += 1
                    else:
                        fail += 1
                iteration += 1
                now = time.monotonic()
                if now - last_report >= 60:
                    wall = now - start
                    print(
                        f"mem-churn: t={wall:.0f}s iterations={iteration} "
                        f"ok={ok} fail={fail} forked={forked} "
                        f"rate={iteration / wall:.1f}/s",
                        flush=True,
                    )
                    last_report = now
                delay = period - (time.monotonic() - tick)
                if delay > 0:
                    time.sleep(delay)
        finally:
            reap()
            # Reap stragglers briefly, then finalize.
            for _ in range(50):
                try:
                    if os.waitpid(-1, os.WNOHANG)[0] == 0:
                        break
                except ChildProcessError:
                    break
                time.sleep(0.02)
            drv.finalize(None)
        wall = time.monotonic() - start
        print(
            f"mem-churn: done t={wall:.0f}s iterations={iteration} ok={ok} "
            f"fail={fail} forked={forked} rate={iteration / max(wall, 1e-9):.1f}/s",
            flush=True,
        )
        # No silent all-failure workload (Important 2): when any
        # non-forked success was attempted but none succeeded, the run
        # is a misconfiguration (wrong slot, dead token), not a soak.
        # All-forked runs (fork_every=1) rely on the first-open probe
        # above, since forked results are invisible to the parent.
        if ok_attempts > 0 and ok == 0:
            raise SystemExit(
                f"mem-churn: no success in {ok_attempts} ok-attempts "
                f"({fail} fail, {forked} forked)"
            )
    finally:
        # The private token dir leaves with the run (a forked child exits
        # via os._exit, so this runs in the parent only). --keep-workdir
        # preserves it for debugging token setup.
        if args.keep_workdir:
            print(f"mem-churn: keeping workdir {workdir}", flush=True)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="pinned-rate PKCS#11 churn")
    parser.add_argument("--lib", default=os.environ.get("SOFTHSM_LIB"),
                        help="SoftHSM module path (default: probe)")
    parser.add_argument("--rate", type=float, default=20,
                        help="iterations/s (default 20)")
    parser.add_argument("--fail-share", type=float, default=0.2,
                        help="share of failing iterations (default 0.2)")
    parser.add_argument("--fork-every", type=int, default=0,
                        help="run every Nth ok-iteration in a forked child, "
                             "counted in forked rather than ok "
                             "(0=off; proof uses 20)")
    parser.add_argument("--duration", type=float, default=660,
                        help="run seconds (default 660)")
    parser.add_argument("--keep-workdir", action="store_true",
                        help="keep the private token dir after the run "
                             "(default: remove it)")
    args = parser.parse_args(argv)
    if args.rate <= 0 or args.duration <= 0:
        raise SystemExit("mem-churn: --rate and --duration must be positive")
    if not 0 <= args.fail_share < 1:
        raise SystemExit("mem-churn: --fail-share must be in [0, 1)")
    if args.fork_every < 0:
        raise SystemExit("mem-churn: --fork-every must be >= 0")
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    run(args)


if __name__ == "__main__":
    main()
