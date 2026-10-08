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

Mode `app-first`: `BINARY PID DURATION BUDGET app-first`. The owned
app-first-driver maps app-p1.so and app-p2.so. Verify both named associations
at 80x24, resize to 40x10, scroll to the later module, enlarge, then quit and
verify terminal restoration. This mode always uses the unprivileged scan lane.
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


class PtyChild:
    """Keep a forked child's PID owned until its one reap, then retire it."""

    def __init__(self, pid: int):
        self.pid = pid
        self.reaped = False

    def wait(self, options: int) -> tuple[int, int]:
        try:
            done, status = os.waitpid(self.pid, options)
        except ChildProcessError:
            self.reaped = True
            raise
        if done != 0:
            self.reaped = True
        return done, status

    def cleanup(self) -> None:
        if self.reaped:
            return
        # Reap an exited child without signaling it; ECHILD also retires
        # custody if another wait has already consumed this child's exit.
        try:
            done, _ = self.wait(os.WNOHANG)
        except OSError:
            return
        if done != 0:
            return
        # This single-threaded driver has no competing reaper. Until the
        # wait below, even an intervening exit keeps this PID reserved.
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.wait(0)
        except OSError:
            pass


def main() -> int:
    if len(sys.argv) > 5 and sys.argv[5] == "stall":
        return stall_mode()
    if len(sys.argv) > 5 and sys.argv[5] == "stderr":
        return stderr_mode()
    if len(sys.argv) > 5 and sys.argv[5] == "xoff":
        return xoff_mode()
    if len(sys.argv) > 5 and sys.argv[5] == "app-first":
        return app_first_mode()
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
    child = PtyChild(child)
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
            done, code = child.wait(os.WNOHANG)
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
        child.cleanup()
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


def app_first_mode() -> int:
    binary, pid, duration, budget = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
    argv = [
        binary, "inventory", "--pid", pid, "--capture", "scan", "--dashboard",
        "--duration", duration,
    ]
    launch_read, launch_write = os.pipe()
    child, master = pty.fork()
    if child == 0:
        os.close(launch_write)
        os.read(launch_read, 1)
        os.close(launch_read)
        os.execv(binary, argv)
        os._exit(127)
    child = PtyChild(child)
    os.close(launch_read)
    output = bytearray()
    start = time.monotonic()
    status = None
    excerpts = []

    def resize(width: int, height: int) -> None:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

    def complete_frame(mark: int, height: int, predicate) -> str:
        """Require every row, including the footer, from a fresh full repaint."""
        cursor = mark
        while time.monotonic() - start < budget:
            raw = bytes(output)
            frame_start = raw.find(b"\x1b[H", cursor)
            while frame_start >= 0:
                next_start = raw.find(b"\x1b[H", frame_start + 3)
                frame_end = next_start if next_start >= 0 else len(raw)
                frame = raw[frame_start:frame_end]
                # Each row ends with erase-to-end-of-line. The last row is
                # the footer; a partial PTY read is never a complete frame.
                if frame.count(b"\x1b[K") >= height:
                    text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", frame).decode("utf-8")
                    lines = text.replace("\r", "").split("\n")
                    text = "\n".join(lines[:height])
                    if predicate(text):
                        return text
                    cursor = frame_end
                elif next_start >= 0:
                    cursor = next_start
                else:
                    break
                frame_start = raw.find(b"\x1b[H", cursor)
            if not read_some(master, output, 0.1):
                break
        raise AssertionError("timed out waiting for a complete matching dashboard frame")

    try:
        # Record terminal settings before the observer can enter raw mode.
        initial_termios = termios.tcgetattr(master)
        resize(80, 24)
        os.write(launch_write, b"1")
        first = complete_frame(0, 24, lambda text: "scroll 0/1" in text
                               and "app-p1.so" in text and "app-p2.so" in text)
        associations = re.findall(r"app-first-driver \[(c\d+)\] -> (app-p[12]\.so) \[(m\d+)\]", first)
        assert len(associations) == 2, f"two named initial associations: {first}"
        caller_ids = {caller for caller, _, _ in associations}
        assert len(caller_ids) == 1, f"one owned caller: {associations}"
        caller_id = associations[0][0]
        modules = {name: module for _, name, module in associations}
        assert len(set(modules.values())) == 2, f"physical modules remain separate: {modules}"
        # Navigation follows the rendered edge order, rather than assuming
        # module IDs were assigned in the fixture's argument order.
        first_name, first_id = associations[0][1:]
        later_name, later_id = associations[1][1:]
        assert f"pid {pid} incarnation 0" in first, first
        excerpts.append(("80x24 initial", first))

        mark = len(output)
        resize(40, 10)
        compact = complete_frame(mark, 10, lambda text: "(minimal)" in text
                                 and "summary 1-1/2" in text and "tab q quit" in text)
        assert f"application app-first-driver [{caller_id}]" in compact, compact
        assert f"module {first_name} [{first_id}]" in compact, compact
        assert "Module mapped; activity not captured" in compact, compact
        assert "totals: 1 callers 2 modules 2 edges" in compact, compact
        assert all(len(line) <= 40 for line in compact.splitlines()), compact
        excerpts.append(("40x10 first association", compact))

        mark = len(output)
        os.write(master, b"j")
        later = complete_frame(mark, 10, lambda text: "summary 2-2/2" in text and "tab q quit" in text)
        assert f"application app-first-driver [{caller_id}]" in later, later
        assert f"module {later_name} [{later_id}]" in later, later
        assert f"module {first_name} [{first_id}]" not in later, later
        assert "Module mapped; activity not captured" in later, later
        assert "totals: 1 callers 2 modules 2 edges" in later, later
        assert all(len(line) <= 40 for line in later.splitlines()), later
        excerpts.append(("40x10 after j", later))

        mark = len(output)
        resize(80, 24)
        enlarged = complete_frame(mark, 24, lambda text: "scroll 1/1" in text and "q quit" in text)
        assert f"app-first-driver [{caller_id}] -> {later_name} [{later_id}]" in enlarged, enlarged
        assert f"pid {pid} incarnation 0" in enlarged, enlarged
        assert "presence mapped | capture scan only | activity not covered" in enlarged, enlarged
        assert "entries ?" in enlarged, enlarged
        excerpts.append(("80x24 enlarged after j", enlarged))
        os.write(master, b"q")
        eof = False
        while time.monotonic() - start < budget:
            done, code = child.wait(os.WNOHANG)
            if done != 0:
                status = code
                break
            if eof:
                time.sleep(0.05)
            else:
                eof = not read_some(master, output, 0.1)
        assert status is not None, "timed out waiting for q exit"
        while read_some(master, output, 0.2) and select.select([master], [], [], 0)[0]:
            pass
        elapsed = time.monotonic() - start
        assert os.waitstatus_to_exitcode(status) == 0, f"exit status {status}"
        assert elapsed < float(duration) - 15, f"q did not quit early: {elapsed:.1f}s"
        entered = output.find(b"\x1b[?1049h")
        restored = output.rfind(b"\x1b[?1049l")
        assert 0 <= entered < restored, "alternate-screen enter/exit did not bracket frames"
        assert b"\x18\x1b[?25h\x1b[?1049l" in output[entered:], "cursor and screen restore sequence missing"
        assert termios.tcgetattr(master) == initial_termios, "terminal settings not restored"
        assert b"dashboard frames:" in output, "frame accounting missing"
    except (AssertionError, OSError) as error:
        return fail(str(error), output, child)
    finally:
        child.cleanup()
        os.close(master)
        os.close(launch_write)

    for label, text in excerpts:
        print(f"pty-dashboard-app-first frame ({label}):\n{text}")
    print(f"pty-dashboard-app-first: {len(output)} bytes in {elapsed:.1f}s, exit=0")
    print("pty-dashboard-app-first: PASS (names, IDs, compact resize, later module, enlargement, q, restoration)")
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
    child = PtyChild(child)
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
            done, _ = child.wait(os.WNOHANG)
            if done != 0:
                return fail("the dashboard exited during the stall", output, child)
            time.sleep(0.5)
        os.kill(child.pid, signal.SIGINT)
        interrupted = time.monotonic()
        eof = False
        while time.monotonic() - interrupted < budget:
            done, code = child.wait(os.WNOHANG)
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
        child.cleanup()
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
    child = PtyChild(child)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    output = bytearray()
    start = time.monotonic()
    status = None
    try:
        eof = False
        while time.monotonic() - start < budget:
            sleeper.poll()
            done, code = child.wait(os.WNOHANG)
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
        child.cleanup()
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
    child = PtyChild(child)
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
            done, code = child.wait(os.WNOHANG)
            if done != 0:
                return fail("exited before the terminal read again", output, child)
            read_some(master, output, 0.1)
        mark = len(output)
        os.write(master, b"\x11")  # Ctrl-Q: the terminal reads again.
        eof = False
        while time.monotonic() - quit_at < budget:
            done, code = child.wait(os.WNOHANG)
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
        child.cleanup()
        os.close(master)

    exit_code = os.waitstatus_to_exitcode(status)
    after = bytes(output[mark:])
    checks = [
        ("exit 0", exit_code == 0, f"exit={exit_code}"),
        ("alternate screen left after Ctrl-Q", b"\x1b[?1049l" in after, ""),
        ("cursor shown after Ctrl-Q", b"\x1b[?25h" in after, ""),
        ("retry said so", b"p11scope: dashboard screen restored (the terminal read again)" in after, ""),
    ]
    failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
    print(f"pty-dashboard-xoff: exit={exit_code} {exit_secs:.2f}s after q")
    if failed:
        print(f"pty-dashboard-xoff FAILED: {'; '.join(failed)}")
        print(after[-2000:].decode("utf-8", "replace"))
        return 1
    print("pty-dashboard-xoff: PASS (shed restore retried after the report)")
    return 0


def fail(message: str, output: bytearray, child: PtyChild) -> int:
    print(f"pty-dashboard FAILED: {message}")
    print(output[-2000:].decode("utf-8", "replace"))
    child.cleanup()
    return 1


if __name__ == "__main__":
    sys.exit(main())
