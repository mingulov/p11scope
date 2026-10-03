#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive `p11scope inventory --dashboard` under a pty and verify it.

Waits for a dashboard frame, scrolls once with `j` (asserting the
footer scroll marker advances — the stdin→key→scroll→render path),
sends `q`, then asserts: exit 0 well before `--duration` (the key
quit the run), alternate-screen enter and exit sequences bracket
the frames (terminal restored), and the stderr frame accounting
landed. Any timeout kills the child and fails loudly (never a hung
suite).
"""

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time


def main() -> int:
    binary, pid, duration, budget = (
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
        float(sys.argv[4]),
    )
    duration_secs = float(duration)
    argv = [binary, "inventory", "--pid", pid, "--dashboard", "--duration", duration]
    child, master = pty.fork()
    if child == 0:
        os.execv(binary, argv)
        os._exit(127)  # unreachable; pacifies linters
    # A real 80x24 window (openpty defaults to 0x0, which the dashboard
    # would only fall back from — here the queried size is asserted).
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    output = bytearray()
    start = time.monotonic()

    def read_until(needle: bytes) -> bool:
        while time.monotonic() - start < budget:
            ready, _, _ = select.select([master], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return False  # EIO: the slave side closed.
            if not chunk:
                return False
            output.extend(chunk)
            if needle in output:
                return True
        return False

    try:
        if not read_until(b"p11scope inventory"):
            return fail("timed out waiting for the first dashboard frame", output, child)
        # The two-provider fixture yields 2 edges (footer "scroll 0/1"):
        # one `j` must advance the marker to "scroll 1/1", proving the
        # live stdin→poll_key→scroll→render path end to end.
        # A frame can arrive in several reads under load: wait for the
        # footer rather than testing the read that held the header.
        if not read_until(b"scroll 0/1"):
            return fail("fixture is not a 2-edge scrollable view", output, child)
        try:
            os.write(master, b"j")
        except OSError:
            return fail("pty write of scroll key failed", output, child)
        if not read_until(b"scroll 1/1"):
            return fail("scroll marker never advanced after `j`", output, child)
        os.write(master, b"q")
        # Drain to EOF (the child exits on `q`, or on --duration).
        # EIO/EOF means the slave closed — usually the exit itself —
        # so it must NOT end the wait: a freshly dead child still
        # needs its reap, which can lag the pty teardown by a tick.
        status = None
        eof = False
        while time.monotonic() - start < budget:
            done, code = os.waitpid(child, os.WNOHANG)
            if done != 0:
                status = code
                break
            if eof:
                time.sleep(0.05)
                continue
            ready, _, _ = select.select([master], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                eof = True
                continue
            if not chunk:
                eof = True
                continue
            output.extend(chunk)
        if status is None:
            return fail("timed out waiting for dashboard exit", output, child)
        # The reap can beat the last stderr bytes out of the pty, so
        # drain whatever remains before the marker checks below.
        while True:
            ready, _, _ = select.select([master], [], [], 0.2)
            if not ready:
                break
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
    finally:
        try:
            os.kill(child, 9)
        except OSError:
            pass
        try:
            os.waitpid(child, 0)
        except OSError:
            pass
        os.close(master)

    elapsed = time.monotonic() - start
    exit_code = os.waitstatus_to_exitcode(status)
    checks = [
        ("exit 0", exit_code == 0, f"exit={exit_code}"),
        # The `q` keystroke quit the run: it ended well before the
        # --duration deadline (a broken key path would run the clock out).
        ("quit before duration", elapsed < duration_secs - 15, f"elapsed={elapsed:.1f}s"),
        ("alternate screen entered", b"\x1b[?1049h" in output, ""),
        ("alternate screen exited", b"\x1b[?1049l" in output, ""),
        ("cursor restored", b"\x1b[?25h" in output, ""),
        ("coverage header shown", b"coverage:" in output, ""),
        ("frame accounting on stderr", b"dashboard frames:" in output, ""),
    ]
    failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
    print(f"pty-dashboard: {len(output)} bytes in {elapsed:.1f}s, exit={exit_code}")
    if failed:
        print(f"pty-dashboard FAILED: {'; '.join(failed)}")
        print(output[-2000:].decode("utf-8", "replace"))
        return 1
    print("pty-dashboard: PASS (frame, scroll-key, q-quit, restoration, accounting)")
    return 0


def fail(message: str, output: bytearray, child: int) -> int:
    print(f"pty-dashboard FAILED: {message}")
    print(output[-2000:].decode("utf-8", "replace"))
    try:
        os.kill(child, 9)
    except OSError:
        pass
    try:
        os.waitpid(child, 0)
    except OSError:
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
