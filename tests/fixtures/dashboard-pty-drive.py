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

Mode `stall` (C5.3): `BINARY PID DURATION BUDGET stall STALL_SECS REPORT`.
Waits for the first frame on a 200x60 window, then never reads the pty
for STALL_SECS (its buffer fills within seconds), sends SIGINT and only
then reads again. Asserts: exit 0 within 5 s of the SIGINT, the screen
restored after the stall (alternate screen left, cursor shown), the
stderr terminal account shows shed frames (the stall bit), a longest
service gap under 100 ms (the stall never delayed a tick) and passes on
their cadence (under 1 s across a pass), and the `-o` report was written.

Mode `stderr` (C5.3 review M1): `BINARY - DURATION BUDGET stderr ROUTE [FILE]`.
Starts a `sleep 3` of its own (reaped as it exits) and runs the dashboard on
its pid until DURATION, so passes fail and the caller exits mid-run. ROUTE
`file` sends the dashboard's stderr to FILE (`2>file`): the pass-failure
warning and the caller-exit line must reach it. ROUTE `tty` leaves stderr on
the pty: both lines must be replayed after the screen is restored.

Mode `xoff` (C5.3 review L1): `BINARY PID DURATION BUDGET xoff`. After the
first frame sends Ctrl-S (raw mode keeps IXON: the terminal stops taking
output), then `q`; the restore is shed. Ctrl-Q comes 4 s later, once the
report is written: the restore retried after the report must then reach
the terminal (alternate screen left, cursor shown) and say so.
"""

import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def main() -> int:
    if len(sys.argv) > 5 and sys.argv[5] == "stall":
        return stall_mode()
    if len(sys.argv) > 5 and sys.argv[5] == "stderr":
        return stderr_mode()
    if len(sys.argv) > 5 and sys.argv[5] == "xoff":
        return xoff_mode()
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


def read_some(master: int, output: bytearray, wait: float) -> bool:
    """One read within `wait`; False once the slave side closed."""
    ready, _, _ = select.select([master], [], [], wait)
    if not ready:
        return True
    try:
        chunk = os.read(master, 65536)
    except OSError:
        return False
    if not chunk:
        return False
    output.extend(chunk)
    return True


def stall_mode() -> int:
    binary, pid, duration, budget = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
    stall_secs, report = float(sys.argv[6]), sys.argv[7]
    argv = [
        binary, "inventory", "--pid", pid, "--dashboard", "--duration", duration, "-o", report,
    ]
    child, master = pty.fork()
    if child == 0:
        os.execv(binary, argv)
        os._exit(127)
    # A large window: big frames fill the pty buffer within seconds.
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 200, 0, 0))
    output = bytearray()
    start = time.monotonic()
    status = None
    try:
        while b"p11scope inventory" not in output:
            if time.monotonic() - start > budget or not read_some(master, output, 0.5):
                return fail("timed out waiting for the first dashboard frame", output, child)
        # Never read for the stall: the child must keep running (its
        # ticks are the point) and must not exit on its own.
        stall_mark = len(output)
        stall_began = time.monotonic()
        while time.monotonic() - stall_began < stall_secs:
            done, _ = os.waitpid(child, os.WNOHANG)
            if done != 0:
                return fail("the dashboard exited during the stall", output, child)
            time.sleep(0.5)
        os.kill(child, signal.SIGINT)
        interrupted = time.monotonic()
        eof = False
        while time.monotonic() - interrupted < budget:
            done, code = os.waitpid(child, os.WNOHANG)
            if done != 0:
                status = code
                break
            if eof:
                time.sleep(0.02)
                continue
            eof = not read_some(master, output, 0.05)
        exit_secs = time.monotonic() - interrupted
        if status is None:
            return fail("timed out waiting for the exit after SIGINT", output, child)
        while read_some(master, output, 0.2) and select.select([master], [], [], 0)[0]:
            pass
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

    exit_code = os.waitstatus_to_exitcode(status)
    after = bytes(output[stall_mark:])
    account = re.search(
        rb"dashboard terminal: (\d+) frames written, (\d+) shed .*?longest gap (\d+) ms "
        rb"\((\d+) ms across a pass\)",
        output,
    )
    written, shed, gap, pass_gap = (
        (int(group) for group in account.groups()) if account else (0, 0, -1, -1)
    )
    try:
        with open(report, encoding="utf-8") as handle:
            schema = json.load(handle).get("schema")
    except (OSError, ValueError) as error:
        schema = f"unreadable: {error}"
    checks = [
        ("exit 0", exit_code == 0, f"exit={exit_code}"),
        ("exit within 5 s of SIGINT", exit_secs < 5.0, f"{exit_secs:.2f}s"),
        ("alternate screen exited after the stall", b"\x1b[?1049l" in after, ""),
        ("cursor restored after the stall", b"\x1b[?25h" in after, ""),
        ("terminal account on stderr", account is not None, ""),
        ("the stall shed frames", shed > 0, f"written={written} shed={shed}"),
        ("longest service gap under 100 ms", 0 <= gap < 100, f"gap={gap}ms"),
        # A pass between two ticks carries its own scan (milliseconds for
        # one pid); a pass held by a blocked write would show here.
        ("passes keep their cadence", 0 <= pass_gap < 1000, f"pass gap={pass_gap}ms"),
        ("report written", schema == "p11scope/inventory/v1", f"schema={schema}"),
    ]
    failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
    print(
        f"pty-dashboard-stall: {len(output)} bytes, stall {stall_secs:.0f}s, "
        f"exit={exit_code} in {exit_secs:.2f}s after SIGINT, frames written={written} "
        f"shed={shed}, longest service gap {gap} ms ({pass_gap} ms across a pass)"
    )
    if failed:
        print(f"pty-dashboard-stall FAILED: {'; '.join(failed)}")
        print(output[-2000:].decode("utf-8", "replace"))
        return 1
    print("pty-dashboard-stall: PASS (ticks kept, frames shed, SIGINT exit, restored, report)")
    return 0


def stderr_mode() -> int:
    binary, duration, budget = sys.argv[1], sys.argv[3], float(sys.argv[4])
    route = sys.argv[6]
    path = sys.argv[7] if route == "file" else None
    sleeper = subprocess.Popen(["sleep", "3"])
    argv = [
        binary, "inventory", "--pid", str(sleeper.pid), "--dashboard", "--duration", duration,
    ]
    child, master = pty.fork()
    if child == 0:
        if path is not None:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(fd, 2)
        os.execv(binary, argv)
        os._exit(127)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    output = bytearray()
    start = time.monotonic()
    status = None
    try:
        eof = False
        while time.monotonic() - start < budget:
            sleeper.poll()
            done, code = os.waitpid(child, os.WNOHANG)
            if done != 0:
                status = code
                break
            if eof:
                time.sleep(0.05)
                continue
            eof = not read_some(master, output, 0.1)
        if status is None:
            return fail("timed out waiting for the dashboard to end", output, child)
        while read_some(master, output, 0.2) and select.select([master], [], [], 0)[0]:
            pass
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
        sleeper.kill()
        sleeper.wait()

    exit_code = os.waitstatus_to_exitcode(status)
    if path is not None:
        with open(path, "rb") as handle:
            stderr = handle.read()
        where = "the stderr file"
    else:
        restored = output.rfind(b"\x1b[?1049l")
        stderr = bytes(output[restored:]) if restored >= 0 else b""
        where = "the terminal after the restore"
    checks = [
        ("dashboard ran", b"\x1b[?1049h" in output, ""),
        ("pass-failure warning", b"pass failed, continuing without its scan" in stderr, where),
        ("caller-exit line", re.search(rb"caller c\d+ exited", stderr) is not None, where),
        ("stderr account", b"dashboard stderr: " in stderr, where),
    ]
    if path is None:
        checks.append(("replay header", b"stderr while the dashboard ran" in stderr, where))
    else:
        # A file is never captured: it keeps its lines as they come.
        checks.append(("file left alone", b"dashboard stderr: left alone" in stderr, where))
    failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
    print(f"pty-dashboard-stderr ({route}): exit={exit_code}, {len(stderr)} stderr bytes")
    if failed:
        print(f"pty-dashboard-stderr FAILED: {'; '.join(failed)}")
        print(stderr[-3000:].decode("utf-8", "replace"))
        return 1
    print(f"pty-dashboard-stderr: PASS ({route}: warnings and caller events kept)")
    return 0


def xoff_mode() -> int:
    binary, pid, duration, budget = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
    argv = [binary, "inventory", "--pid", pid, "--dashboard", "--duration", duration]
    child, master = pty.fork()
    if child == 0:
        os.execv(binary, argv)
        os._exit(127)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    output = bytearray()
    start = time.monotonic()
    status = None
    try:
        while b"p11scope inventory" not in output:
            if time.monotonic() - start > budget or not read_some(master, output, 0.5):
                return fail("timed out waiting for the first dashboard frame", output, child)
        os.write(master, b"\x13")  # Ctrl-S: the terminal stops taking output.
        stopped = time.monotonic()
        while time.monotonic() - stopped < 1.0:
            read_some(master, output, 0.1)
        os.write(master, b"q")
        quit_at = time.monotonic()
        while time.monotonic() - quit_at < 4.0:
            done, code = os.waitpid(child, os.WNOHANG)
            if done != 0:
                return fail("exited before the terminal read again", output, child)
            read_some(master, output, 0.1)
        mark = len(output)
        os.write(master, b"\x11")  # Ctrl-Q: the terminal reads again.
        eof = False
        while time.monotonic() - quit_at < budget:
            done, code = os.waitpid(child, os.WNOHANG)
            if done != 0:
                status = code
                break
            if eof:
                time.sleep(0.02)
                continue
            eof = not read_some(master, output, 0.05)
        exit_secs = time.monotonic() - quit_at
        if status is None:
            return fail("timed out waiting for the exit after q", output, child)
        while read_some(master, output, 0.2) and select.select([master], [], [], 0)[0]:
            pass
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

    exit_code = os.waitstatus_to_exitcode(status)
    after = bytes(output[mark:])
    checks = [
        ("exit 0", exit_code == 0, f"exit={exit_code}"),
        ("alternate screen left after Ctrl-Q", b"\x1b[?1049l" in after, ""),
        ("cursor shown after Ctrl-Q", b"\x1b[?25h" in after, ""),
        ("retry said so", b"screen restored after the report" in after, ""),
    ]
    failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
    print(f"pty-dashboard-xoff: exit={exit_code} {exit_secs:.2f}s after q")
    if failed:
        print(f"pty-dashboard-xoff FAILED: {'; '.join(failed)}")
        print(after[-2000:].decode("utf-8", "replace"))
        return 1
    print("pty-dashboard-xoff: PASS (shed restore retried after the report)")
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
