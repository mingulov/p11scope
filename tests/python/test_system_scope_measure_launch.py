# SPDX-License-Identifier: GPL-3.0-or-later
"""Observer launch construction and custody checks for system-scope-measure.sh."""

import importlib.util
import json
import os
from contextlib import contextmanager
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
MEASURE = ROOT / "scripts" / "system-scope-measure.sh"
LANE_A = ROOT / "scripts" / "task-1.6-lane-a.py"
TEST_TMP = Path("/var/tmp/p11scope-ws-tmp")


def ensure_test_tmp(path=TEST_TMP):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if not path.is_dir():
        raise RuntimeError(f"test temp root is not a directory: {path}")


def run_condition_source(source=None):
    if source is None:
        source = MEASURE.read_text(encoding="utf-8")
    start = source.index("run_condition() {")
    end = source.index('\ncase "$SCOPE" in', start)
    return source[start:end]


def wait_attach_source():
    source = MEASURE.read_text(encoding="utf-8")
    start = source.index("owned_require_live() {")
    end = source.index("\n# fd_plateau_state", start)
    return source[start:end]


def process_starttime(pid):
    fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
    return int(fields[19])


def require_root_observer_launch(privilege):
    if privilege != "root":
        raise AssertionError(
            f"observer must use owned_launch root, got {privilege!r}")


def load_lane_a():
    spec = importlib.util.spec_from_file_location("task_1_6_lane_a", LANE_A)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeObserverProc:
    """Minimal stand-in for the Popen object wait_attach polls."""

    def __init__(self, returncode=None):
        self._returncode = returncode

    def poll(self):
        return self._returncode

    @property
    def returncode(self):
        return self._returncode


@contextmanager
def live_sleep():
    proc = subprocess.Popen(["sleep", "30"])
    try:
        yield proc, process_starttime(proc.pid)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)


class SystemScopeMeasureLaunchTests(unittest.TestCase):
    maxDiff = None

    def test_temp_root_is_created_private_without_changing_existing_mode(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            missing = Path(raw) / "missing"
            ensure_test_tmp(missing)
            self.assertEqual(stat.S_IMODE(missing.stat().st_mode), 0o700)
            missing.chmod(0o750)
            ensure_test_tmp(missing)
            self.assertEqual(stat.S_IMODE(missing.stat().st_mode), 0o750)

    def test_readiness_uses_birth_identity_and_never_signal_permission(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            base = Path(raw)
            condition = base / "condition"
            condition.mkdir()
            (condition / "stderr.txt").write_text(
                "p11scope: discovery:\n"
                "p11scope: attached 136 probes\n", encoding="utf-8")
            (condition / "observer.stdout").write_text(
                "probes attached\n", encoding="utf-8")
            live = subprocess.Popen(["sleep", "30"])
            terminal = subprocess.Popen(["true"])
            live_birth = process_starttime(live.pid)
            terminal_birth = process_starttime(terminal.pid)
            terminal.wait(timeout=2)
            fake_helper = base / "unknown-helper"
            helper_log = base / "unknown-helper.invocation"
            fake_helper.write_text(
                "import json, pathlib, sys\n"
                f"log = pathlib.Path({str(helper_log)!r})\n"
                "log.write_text('\\n'.join(sys.argv[1:]) + '\\n', "
                "encoding='utf-8')\n"
                "if sys.argv[1:2] != ['inspect-process']:\n"
                "    raise SystemExit(2)\n"
                "arguments = sys.argv[2:]\n"
                "def value(flag):\n"
                "    return int(arguments[arguments.index(flag) + 1])\n"
                "print(json.dumps({\n"
                "    'pid': value('--pid'),\n"
                "    'starttime': value('--starttime'),\n"
                "    'state': 'unknown',\n"
                "    'reason': 'injected permission denial',\n"
                "}, sort_keys=True))\n",
                encoding="utf-8",
            )
            kill_log = base / "kill-called"
            shell = textwrap.dedent(
                f"""
                set -u
                P11SCOPE_RECEIPT_HELPER={shlex.quote(str(ROOT / 'scripts/system-scope-receipt.py'))}
                export P11SCOPE_RECEIPT_HELPER
                . scripts/system-scope-owned.sh
                {wait_attach_source()}
                date() {{ printf '100\\n'; }}
                kill() {{
                    if [ "${{DENY_KILL:-0}}" -eq 1 ]; then
                        printf 'called\\n' >> {shlex.quote(str(kill_log))}
                        return 1
                    fi
                    command kill "$@"
                }}
                DENY_KILL=1
                wait_attach {shlex.quote(str(condition))} {live.pid} {live_birth} 1
                live_rc=$?
                DENY_KILL=0
                wait_attach {shlex.quote(str(condition))} {live.pid} {live_birth + 1} 1
                replacement_rc=$?
                wait_attach {shlex.quote(str(condition))} {terminal.pid} {terminal_birth} 1
                terminal_rc=$?
                P11SCOPE_RECEIPT_HELPER={shlex.quote(str(fake_helper))}
                wait_attach {shlex.quote(str(condition))} {live.pid} {live_birth} 1
                unknown_rc=$?
                printf '%s %s %s %s\\n' "$live_rc" "$replacement_rc" \
                    "$terminal_rc" "$unknown_rc"
                """
            )
            try:
                result = subprocess.run(
                    ["sh", "-c", shell], cwd=ROOT, text=True,
                    capture_output=True, timeout=5,
                )
            finally:
                if live.poll() is None:
                    live.terminate()
                    live.wait(timeout=2)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "0 2 2 3")
            self.assertFalse(kill_log.exists(), "readiness called kill -0")
            self.assertEqual(
                helper_log.read_text(encoding="utf-8").splitlines(),
                [
                    "inspect-process",
                    "--pid", str(live.pid),
                    "--starttime", str(live_birth),
                ],
            )

    def test_every_readiness_call_forwards_pid_and_birth(self):
        source = MEASURE.read_text(encoding="utf-8")
        normalized = " ".join(source.replace("\\\n", " ").split())
        self.assertNotIn("kill -0", source)
        for call in (
            'wait_attach "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600',
            'wait_marker "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600',
            'wait_fd_plateau "$dir" "$STARGET_PID" "$STARGET_STARTTIME" 600',
            'wait_file_alive "$dir/mapped" "$STARGET_PID" '
            '"$STARGET_STARTTIME" "$WTARGET_PID" "$WTARGET_STARTTIME" 60',
            'WTARGET_STARTTIME=$OWNED_COMMAND_STARTTIME',
            'STARGET_STARTTIME=$OWNED_COMMAND_STARTTIME',
        ):
            self.assertIn(call, normalized)
        self.assertEqual(
            source.count(
                'owned_require_live "$STARGET_PID" "$STARGET_STARTTIME"'),
            2,
        )

    def test_sampler_receives_exact_observer_identity(self):
        source = MEASURE.read_text(encoding="utf-8")
        normalized = " ".join(source.replace("\\\n", " ").split())
        self.assertIn(
            'system-scope-sample.py" --pid "$STARGET_PID" '
            '--starttime "$STARGET_STARTTIME"',
            normalized,
        )
        self.assertNotIn('system-scope-sample.py" --ppid', normalized)
        self.assertNotIn(
            'sudo -n python3 -I "$PWD/scripts/system-scope-sample.py"',
            normalized,
        )
        self.assertIn('owned_command_outcome "$SMPID_RECEIPT"', source)

    def capture_observer_launch(self, base, scope, mode, binary, source=None):
        capture = base / "constructed-argv"
        harness = textwrap.dedent(
            f"""
            set -eu
            {run_condition_source(source)}
            WORK={shlex.quote(str(base / 'work'))}
            mkdir -p "$WORK"
            BINARY={shlex.quote(str(binary))}
            MODULE=/fixture/provider.so
            N_CALLS=3
            PACE_US=0
            SEED=7
            DURATION=8
            RING_BYTES=
            DRAIN_MS=
            SINK=file
            SINK_RATE_KBPS=4
            CFIFO=
            SFIFO=
            P11SCOPE_RECEIPT_HELPER={shlex.quote(str(ROOT / 'scripts/system-scope-receipt.py'))}
            launch_count=0
            wait_file() {{ return 0; }}
            collect_receipt() {{ return 0; }}
            mono_ns() {{ echo 1; }}
            owned_verify_launch() {{ return 0; }}
            owned_launch() {{
                owned_privilege=$1
                shift 4
                [ "$1" = -- ]
                shift
                found=false
                for argument do
                    [ "$argument" != "$BINARY" ] || found=true
                done
                if [ "$found" = true ]; then
                    {{
                        printf '%s\\n' "$owned_privilege"
                        printf '%s\\n' "$@"
                    }} > {shlex.quote(str(capture))}
                    exit 73
                fi
                launch_count=$((launch_count + 1))
                OWNED_PID=$((1000 + launch_count))
                OWNED_STARTTIME=$((2000 + launch_count))
                OWNED_RECEIPT={shlex.quote(str(base / 'stub-receipt'))}.$launch_count
                OWNED_COMMAND_PID=4242
                OWNED_COMMAND_STARTTIME=4343
            }}
            run_condition {shlex.quote(scope)} {shlex.quote(mode)}
            exit 99
            """
        )
        result = subprocess.run(
            ["sh", "-c", harness], cwd=ROOT, text=True,
            capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        recorded = capture.read_text(encoding="utf-8").splitlines()
        return recorded[0], recorded[1:]

    def run_owned_command(self, base, privilege, command):
        sudo_log = base / "sudo.log"
        observer_capture = base / "observer.json"
        observer_release = base / "observer.release"
        fake_sudo = base / "sudo"
        fake_sudo.write_text(
            "#!/bin/sh\n"
            ": \"${SUDO_LOG:?}\"\n"
            "printf 'call\\n' >> \"$SUDO_LOG\"\n"
            "if [ \"${SUDO_UID+x}\" = x ]; then\n"
            "  export SUDO_UID=0 SUDO_GID=0\n"
            "else\n"
            "  export SUDO_UID=\"$(id -u)\" SUDO_GID=\"$(id -g)\"\n"
            "fi\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in -n|--preserve-env=*) shift;; *) break;; esac\n"
            "done\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        fake_sudo.chmod(0o755)
        shell = textwrap.dedent(
            f"""
            set -eu
            cd {shlex.quote(str(ROOT))}
            PATH={shlex.quote(str(base))}:$PATH
            export PATH
            TMPDIR={shlex.quote(str(base))}
            SOFTHSM2_CONF={shlex.quote(str(base / 'softhsm2.conf'))}
            SUDO_LOG={shlex.quote(str(sudo_log))}
            OBSERVER_CAPTURE={shlex.quote(str(observer_capture))}
            OBSERVER_RELEASE={shlex.quote(str(observer_release))}
            export TMPDIR SOFTHSM2_CONF SUDO_LOG OBSERVER_CAPTURE OBSERVER_RELEASE
            unset SUDO_UID SUDO_GID || true
            . scripts/system-scope-owned.sh
            owned_privilege=$1
            shift
            owned_launch "$owned_privilege" - /dev/null {shlex.quote(str(base / 'stderr'))} -- "$@"
            wrapper=$OWNED_PID
            birth=$OWNED_STARTTIME
            receipt=$OWNED_RECEIPT
            owned_verify_launch "$wrapper" "$birth" "$receipt"
            : > "$OBSERVER_RELEASE"
            owned_wait_supervisor_terminal "$receipt" 5
            owned_finish "$wrapper" "$birth" "$receipt" 0
            owned_command_outcome "$receipt"
            [ "$OWNED_COMMAND_EXIT" -eq 0 ]
            [ "$OWNED_COMMAND_SIGNAL" = null ]
            python3 -I - "$receipt" <<'PY'
            import json, os, sys
            record = json.load(open(sys.argv[1], encoding="utf-8"))
            assert record["root_group"] is True
            assert record["cleanup_ok"] is True
            assert os.stat(sys.argv[1]).st_uid == os.getuid()
            PY
            """
        )
        result = subprocess.run(
            ["sh", "-c", shell, "owned-launch", privilege, *command], cwd=ROOT,
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return (
            sudo_log.read_text(encoding="utf-8").splitlines(),
            json.loads(observer_capture.read_text(encoding="utf-8")),
        )

    def test_user_call_site_mutation_is_rejected(self):
        source = MEASURE.read_text(encoding="utf-8")
        original = 'owned_launch root - "$dir/observer.stdout" "$CFIFO" -- "$@"'
        mutated = 'owned_launch user - "$dir/observer.stdout" "$CFIFO" -- "$@"'
        self.assertEqual(source.count(original), 1)
        source = source.replace(original, mutated, 1)
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            base = Path(raw)
            privilege, command = self.capture_observer_launch(
                base, "pid", "metrics", base / "observer", source)
        self.assertEqual(privilege, "user", command)
        with self.assertRaisesRegex(AssertionError, "owned_launch root"):
            require_root_observer_launch(privilege)

    def test_each_observer_shape_has_one_root_boundary_and_keeps_invoker(self):
        self.assertNotEqual(os.getuid(), 0, "this contract requires a nonroot test owner")
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            root = Path(raw)
            binary = root / "observer"
            binary.write_text(
                "#!/usr/bin/python3\n"
                "import json, os, pathlib, sys, time\n"
                "json.dump({'argv': sys.argv[1:], 'sudo_uid': os.environ.get('SUDO_UID'), "
                "'sudo_gid': os.environ.get('SUDO_GID'), "
                "'softhsm2_conf': os.environ.get('SOFTHSM2_CONF')}, "
                "open(os.environ['OBSERVER_CAPTURE'], 'w', encoding='utf-8'))\n"
                "release = pathlib.Path(os.environ['OBSERVER_RELEASE'])\n"
                "deadline = time.monotonic() + 5\n"
                "while not release.exists() and time.monotonic() < deadline: time.sleep(0.01)\n"
                "if not release.exists(): raise SystemExit('release gate timed out')\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            for scope in ("pid", "system"):
                for mode in ("metrics", "profile", "trace"):
                    with self.subTest(scope=scope, mode=mode):
                        case = root / f"{scope}-{mode}"
                        case.mkdir()
                        privilege, command = self.capture_observer_launch(
                            case, scope, mode, binary)
                        require_root_observer_launch(privilege)
                        calls, observed = self.run_owned_command(
                            case, privilege, command)
                        self.assertEqual(calls, ["call"], command)
                        self.assertEqual(observed["sudo_uid"], str(os.getuid()))
                        self.assertEqual(observed["sudo_gid"], str(os.getgid()))
                        self.assertEqual(
                            observed["softhsm2_conf"], str(case / "softhsm2.conf"))
                        self.assertEqual(command[0], str(binary), command)
                        if mode == "trace":
                            self.assertEqual(command[1], "trace")
                            self.assertNotIn("--mode", command)
                        else:
                            self.assertEqual(command[1], "profile")
                            self.assertEqual(
                                command[command.index("--mode") + 1], mode)
                        self.assertIn(
                            "--pid" if scope == "pid" else "--system", command)


class PrivilegedAttachGateTests(unittest.TestCase):
    """Both wait_attach copies gate on the stderr attach-complete line.

    Since M-10 (7eb86f0d) live frames render only on a terminal while the
    harness captures observer stdout to a file, the old stdout "probes
    attached" frame signal can never fire. The gate is the discovery
    marker AND the product's stderr attach-complete line (0801e79c).
    """

    maxDiff = None

    # Exact spellings pinned by the product test
    # attach_complete_line_names_the_probe_count (src/run.rs).
    ATTACH_SPELLINGS = (
        "p11scope: attached 0 probes",
        "p11scope: attached 1 probe",
        "p11scope: attached 136 probes",
    )
    DISCOVERY = ("p11scope: discovery: 1 module(s), 68 attach slot(s), "
                 "scan 8ms, conflicts 0, uncorroborated 0")
    OBSOLETE_FRAME = "68/136 probes attached"

    @classmethod
    def setUpClass(cls):
        cls.lane_a = load_lane_a()

    def write_condition(self, base, stderr_text, stdout_text):
        condition = base / "condition"
        condition.mkdir(parents=True)
        (condition / "stderr.txt").write_text(
            stderr_text, encoding="utf-8")
        (condition / "observer.stdout").write_text(
            stdout_text, encoding="utf-8")
        return condition

    def run_shell_gate(self, condition, pid, birth, timeout):
        shell = textwrap.dedent(
            f"""
            set -u
            P11SCOPE_RECEIPT_HELPER={shlex.quote(str(ROOT / 'scripts/system-scope-receipt.py'))}
            export P11SCOPE_RECEIPT_HELPER
            . scripts/system-scope-owned.sh
            {wait_attach_source()}
            wait_attach {shlex.quote(str(condition))} {pid} {birth} {timeout}
            printf 'rc=%s\\n' "$?"
            """
        )
        result = subprocess.run(
            ["sh", "-c", shell], cwd=ROOT, text=True,
            capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        [line] = [entry for entry in result.stdout.splitlines()
                  if entry.startswith("rc=")]
        return int(line.removeprefix("rc="))

    def test_shell_gate_fires_on_stderr_signals_with_empty_stdout(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw),
                f"{self.DISCOVERY}\n{self.ATTACH_SPELLINGS[2]}\n", "")
            with live_sleep() as (proc, birth):
                self.assertEqual(
                    self.run_shell_gate(condition, proc.pid, birth, 5), 0)

    def test_shell_gate_ignores_the_obsolete_stdout_frame(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw), f"{self.DISCOVERY}\n",
                f"{self.OBSOLETE_FRAME}\n")
            with live_sleep() as (proc, birth):
                self.assertEqual(
                    self.run_shell_gate(condition, proc.pid, birth, 1), 1)

    def test_shell_gate_still_requires_discovery(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw), f"{self.ATTACH_SPELLINGS[2]}\n", "")
            with live_sleep() as (proc, birth):
                self.assertEqual(
                    self.run_shell_gate(condition, proc.pid, birth, 1), 1)

    def test_shell_gate_accepts_all_product_attach_spellings(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            base = Path(raw)
            with live_sleep() as (proc, birth):
                for spelling in self.ATTACH_SPELLINGS:
                    with self.subTest(spelling=spelling):
                        condition = self.write_condition(
                            base / spelling.replace(" ", "_").replace(
                                "/", "_"),
                            f"{self.DISCOVERY}\n{spelling}\n", "")
                        self.assertEqual(
                            self.run_shell_gate(
                                condition, proc.pid, birth, 5), 0)

    def test_python_gate_fires_on_stderr_signals_with_empty_stdout(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw),
                f"{self.DISCOVERY}\n{self.ATTACH_SPELLINGS[2]}\n", "")
            fired = self.lane_a.wait_attach(
                condition, FakeObserverProc(), timeout_s=5)
            self.assertIsInstance(fired, int)

    def test_python_gate_times_out_without_the_attach_complete_line(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw), f"{self.DISCOVERY}\n",
                f"{self.OBSOLETE_FRAME}\n")
            with self.assertRaisesRegex(
                    SystemExit, "attach never settled"):
                self.lane_a.wait_attach(
                    condition, FakeObserverProc(), timeout_s=0.2)

    def test_python_gate_still_requires_discovery(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw), f"{self.ATTACH_SPELLINGS[2]}\n", "")
            with self.assertRaisesRegex(
                    SystemExit, "attach never settled"):
                self.lane_a.wait_attach(
                    condition, FakeObserverProc(), timeout_s=0.2)

    def test_python_gate_accepts_all_product_attach_spellings(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            base = Path(raw)
            for spelling in self.ATTACH_SPELLINGS:
                with self.subTest(spelling=spelling):
                    self.assertTrue(
                        self.lane_a.has_attach_complete_line(spelling))
                    condition = self.write_condition(
                        base / spelling.replace(" ", "_").replace("/", "_"),
                        f"{self.DISCOVERY}\n{spelling}\n", "")
                    fired = self.lane_a.wait_attach(
                        condition, FakeObserverProc(), timeout_s=5)
                    self.assertIsInstance(fired, int)

    def test_python_gate_reports_observer_death(self):
        ensure_test_tmp()
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as raw:
            condition = self.write_condition(
                Path(raw),
                f"{self.DISCOVERY}\n{self.ATTACH_SPELLINGS[2]}\n", "")
            with self.assertRaisesRegex(
                    SystemExit,
                    r"observer died during attach \(rc=3\)"):
                self.lane_a.wait_attach(
                    condition, FakeObserverProc(returncode=3),
                    timeout_s=5)


if __name__ == "__main__":
    unittest.main()
