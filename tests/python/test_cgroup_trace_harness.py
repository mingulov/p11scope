# SPDX-License-Identifier: GPL-3.0-or-later
"""Ownership checks must fail before any signal or cgroup mutation."""

from collections import Counter
import os
import json
import io
from pathlib import Path
import runpy
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HARNESS = runpy.run_path(str(ROOT / 'scripts/qualify-cgroup-trace.py'))


class CellTimingTests(unittest.TestCase):
    def test_long_sparse_waits_cover_the_real_span_and_final_drain(self):
        for name, span in (('sparse1', 4), ('sparse10', 30), ('sparse59', 118), ('sparse61', 122)):
            with self.subTest(cell=name):
                budget = HARNESS['cell_timing'](name)
                self.assertGreaterEqual(budget['acknowledgement_seconds'], span + 10)
                self.assertGreaterEqual(budget['duration_seconds'], span + 30)

    def test_existing_cells_keep_their_bounded_duration_and_wait(self):
        for name in HARNESS['INITIAL_CELLS']:
            self.assertEqual(HARNESS['cell_timing'](name),
                             dict(duration_seconds=20, acknowledgement_seconds=10))


class CleanupTests(unittest.TestCase):
    def test_process_cleanup_attempts_every_owner_and_retains_every_error(self):
        owners = [mock.Mock(), mock.Mock()]
        failures = [ValueError('wrong birth'), OSError('pidfd refused')]
        namespace = HARNESS['cleanup_processes'].__globals__
        with mock.patch.dict(namespace, terminate=mock.Mock(side_effect=failures)):
            with self.assertRaises(RuntimeError) as raised:
                HARNESS['cleanup_processes'](owners)
            self.assertEqual(raised.exception.errors, tuple(failures))
            self.assertEqual(namespace['terminate'].call_count, 2)
        for owner in owners:
            owner.close.assert_called_once_with()

    def test_cgroup_cleanup_attempts_every_group_and_retains_every_error(self):
        groups = [mock.Mock(), mock.Mock()]
        failures = [OSError('parent replaced'), ValueError('still populated')]
        groups[1].remove.side_effect = failures[0]
        groups[0].remove.side_effect = failures[1]
        with self.assertRaises(RuntimeError) as raised:
            HARNESS['cleanup_cgroups'](groups)
        self.assertEqual(raised.exception.errors, tuple(failures))
        for group in groups:
            group.remove.assert_called_once_with()


class ReadinessTests(unittest.TestCase):
    # Replay the installed run's actual startup shape: initial zero provider
    # probes, complete native setup, and dynamically captured setup completion.
    # Image/provider inputs stand for the separately verified held-FD receipts;
    # these stream controls never use a candidate name as expected identity.
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.readers = []
        self.image = dict(image=0, pid=2399485)
        self.provider = dict(dev=[0, 35], ino=356176)
        self.target = dict(kind='target', image=0, fn='C_OpenSession',
                           dev=[0, 35], ino=356176, file_offset=163168)
        self.call = dict(kind='call', image=0, pid=2399485, tid=2399485,
                         fn='C_OpenSession', rv=0, phase='setup', scope='selected',
                         t0=80770110210158, t1=80770110220397)
        self.ready = dict(kind='ready', image=0, t=80770110222431)

    def reader(self, lines):
        reader = HARNESS['Reader'](io.StringIO(''.join(lines)),
                                   Path(self.scratch.name) / str(len(self.readers)))
        self.readers.append(reader)
        self.addCleanup(reader.finish)
        return reader

    def capture(self, event=None, target=None, call=None):
        records = [self.target if target is None else target,
                   self.call if call is None else call, self.ready]
        lines = ['N3LEDGER ' + json.dumps(row) + '\n' for row in records]
        if event is not None:
            lines.append(event)
        return self.reader(lines)

    def event(self, pid=2399485, tid=2399485, rv='CKR_OK'):
        return (f'11:53:22.120433 Unknown executable (PID {pid}, TID {tid}) '
                f'C_OpenSession [semantics unverified] → {rv} 6.3µs\n')

    def test_observed_zero_start_then_authentic_dynamic_setup_is_ready(self):
        errors = self.reader([
            'p11scope: discovery: 0 module(s), 0 attach slot(s), scan 1ms, conflicts 0, uncorroborated 0\n',
            'p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C\n'])
        self.assertTrue(HARNESS['wait_capture_started'](errors, allow_empty=True, seconds=0.2))
        capture = self.capture(self.event())
        self.assertEqual(HARNESS['wait_run_provider_ready'](
            capture, self.image, self.provider, seconds=0.2), self.call)

    def test_zero_capture_banner_is_still_refused_for_cgroup(self):
        errors = self.reader(['p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C\n'])
        with self.assertRaises(TimeoutError):
            HARNESS['wait_capture_started'](errors, seconds=0.2)

    def test_positive_cgroup_start_still_passes(self):
        errors = self.reader(['p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C\n'])
        self.assertTrue(HARNESS['wait_capture_started'](errors, seconds=0.2))

    def test_native_ready_without_dynamic_completion_cannot_release_gate(self):
        with self.assertRaises(TimeoutError):
            HARNESS['wait_run_provider_ready'](self.capture(), self.image,
                                                self.provider, seconds=0.2)

    def test_completion_for_another_pid_cannot_release_gate(self):
        with self.assertRaises(TimeoutError):
            HARNESS['wait_run_provider_ready'](self.capture(self.event(pid=2399486)),
                                                self.image, self.provider, seconds=0.2)

    def test_unsuccessful_completion_cannot_release_gate(self):
        with self.assertRaises(TimeoutError):
            HARNESS['wait_run_provider_ready'](self.capture(self.event(rv='CKR_GENERAL_ERROR')),
                                                self.image, self.provider, seconds=0.2)

    def test_setup_target_must_match_the_independent_provider(self):
        with self.assertRaises(ValueError):
            HARNESS['wait_run_provider_ready'](self.capture(self.event(),
                target=dict(self.target, ino=356177)), self.image, self.provider, seconds=0.2)

    def test_setup_call_must_match_the_owned_caller_tuple(self):
        with self.assertRaises(ValueError):
            HARNESS['wait_run_provider_ready'](self.capture(self.event(),
                call=dict(self.call, tid=2399486)), self.image, self.provider, seconds=0.2)


class OwnershipTests(unittest.TestCase):
    def process(self):
        return dict(pid=123, ppid=77, start_time=99, uid=1000,
                    pid_namespace=5, time_namespace=6)

    def test_unchanged_owned_process_passes(self):
        expected = self.process()
        self.assertTrue(HARNESS['assert_process_identity'](expected, dict(expected)))

    def test_wrong_parent_is_refused(self):
        expected = self.process()
        actual = dict(expected, ppid=76)
        with self.assertRaises(ValueError):
            HARNESS['assert_process_identity'](expected, actual)

    def test_reused_pid_birth_is_refused(self):
        expected = self.process()
        with self.assertRaises(ValueError):
            HARNESS['assert_process_identity'](expected, dict(expected, start_time=100))

    def test_namespace_change_is_refused(self):
        expected = self.process()
        with self.assertRaises(ValueError):
            HARNESS['assert_process_identity'](expected, dict(expected, pid_namespace=7))

    def test_zero_birth_is_refused_even_if_both_claim_it(self):
        expected = dict(self.process(), start_time=0)
        with self.assertRaises(ValueError):
            HARNESS['assert_process_identity'](expected, expected)

    def test_replaced_directory_is_refused(self):
        with self.assertRaises(ValueError):
            HARNESS['assert_directory_identity']((5, 6), (5, 7), 0x63677270)

    def test_non_cgroup_filesystem_is_refused(self):
        with self.assertRaises(ValueError):
            HARNESS['assert_directory_identity']((5, 6), (5, 6), 0x9123683E)

    def test_unchanged_cgroup_directory_passes(self):
        self.assertTrue(HARNESS['assert_directory_identity']((5, 6), (5, 6), 0x63677270))

    def test_real_child_wrong_parent_refuses_signal_and_leaves_it_alive(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])
        owner = HARNESS['OwnedProcess'](child.pid, os.getpid(), os.getuid(), child)
        try:
            original = owner.identity['ppid']
            owner.identity['ppid'] += 1
            with self.assertRaises(ValueError):
                owner.send(signal.SIGTERM)
            self.assertIsNone(child.poll())
            owner.identity['ppid'] = original
        finally:
            HARNESS['terminate'](owner)
            owner.close()

    def test_non_cgroup_directory_control_performs_no_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'sentinel').write_text('unchanged')
            with self.assertRaises(ValueError):
                HARNESS['Cgroup'](path)
            self.assertEqual((path / 'sentinel').read_text(), 'unchanged')
            self.assertEqual(list(path.iterdir()), [path / 'sentinel'])

    def test_owned_child_without_popen_confirms_exit_and_escalates(self):
        child = subprocess.Popen([sys.executable, '-c',
            'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
            'print("ready", flush=True); time.sleep(10)'], stdout=subprocess.PIPE, text=True)
        self.assertEqual(child.stdout.readline().strip(), 'ready')
        owner = HARNESS['OwnedProcess'](child.pid, os.getpid(), os.getuid())
        try:
            HARNESS['terminate'](owner)
            self.assertEqual(child.wait(timeout=0.3), -signal.SIGKILL)
        finally:
            if child.poll() is None:
                owner.send(signal.SIGKILL)
                child.wait(timeout=3)
            owner.close()
            child.stdout.close()


class AcquisitionTests(unittest.TestCase):
    def test_failed_cgroup_open_removes_the_actual_created_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path, groups = Path(directory) / 'new', []
            namespace = HARNESS['create_cgroup'].__globals__
            with mock.patch.dict(namespace, fs_magic=lambda _: 0x63677270,
                                 Cgroup=mock.Mock(side_effect=OSError('open refused'))):
                with self.assertRaises(OSError):
                    HARNESS['create_cgroup'](path, groups)
                HARNESS['cleanup_cgroups'](groups)
            self.assertFalse(path.exists(), 'created directory was never enrolled')

    def test_failed_acquisition_never_removes_a_replacement_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path, groups = Path(directory) / 'new', []
            original = Path(directory) / 'original'
            namespace = HARNESS['create_cgroup'].__globals__
            with mock.patch.dict(namespace, fs_magic=lambda _: 0x63677270,
                                 Cgroup=mock.Mock(side_effect=OSError('open refused'))):
                with self.assertRaises(OSError):
                    HARNESS['create_cgroup'](path, groups)
                path.rename(original)
                path.mkdir()
                with self.assertRaises(HARNESS['CleanupError']):
                    HARNESS['cleanup_cgroups'](groups)
                self.assertTrue(path.is_dir())
                self.assertTrue(original.is_dir())

    def test_wrong_filesystem_refuses_creation_before_mkdir(self):
        with tempfile.TemporaryDirectory() as directory:
            path, groups = Path(directory) / 'new', []
            with self.assertRaises(ValueError):
                HARNESS['create_cgroup'](path, groups)
            self.assertFalse(path.exists())
            HARNESS['cleanup_cgroups'](groups)

    def test_failed_process_ownership_still_reaps_the_actual_popen_child(self):
        owners, children = [], []
        original_popen = subprocess.Popen
        def capture(*args, **options):
            child = original_popen(*args, **options)
            children.append(child)
            return child
        namespace = HARNESS['spawn_owned'].__globals__
        try:
            with mock.patch.object(subprocess, 'Popen', capture), mock.patch.dict(namespace,
                    OwnedProcess=mock.Mock(side_effect=ValueError('identity refused'))):
                with self.assertRaises(ValueError):
                    HARNESS['spawn_owned'](owners, [sys.executable, '-c', 'import time; time.sleep(10)'],
                                          os.getuid(), start_new_session=True)
            HARNESS['cleanup_processes'](owners)
            self.assertIsNotNone(children[0].poll(), 'actual Popen child was never enrolled')
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)

    def test_late_ownership_refusal_closes_pidfd_and_reaps_the_direct_child(self):
        owners, children, pidfds = [], [], []
        original_popen, original_pidfd = subprocess.Popen, os.pidfd_open
        def capture(*args, **options):
            child = original_popen(*args, **options)
            children.append(child)
            return child
        def open_pidfd(*args):
            fd = original_pidfd(*args)
            pidfds.append(fd)
            return fd
        try:
            with mock.patch.object(subprocess, 'Popen', capture), mock.patch.object(os, 'pidfd_open', open_pidfd), \
                    mock.patch.object(HARNESS['OwnedProcess'], 'verify', side_effect=ValueError('late refusal')):
                with self.assertRaises(ValueError):
                    HARNESS['spawn_owned'](owners, [sys.executable, '-c', 'import time; time.sleep(10)'], os.getuid())
            with self.assertRaises(OSError):
                os.fstat(pidfds[0])
            HARNESS['cleanup_processes'](owners)
            self.assertIsNotNone(children[0].poll())
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)

    def test_sigterm_during_acquisition_is_delivered_after_directory_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            path, groups = Path(directory) / 'new', []
            namespace = HARNESS['create_cgroup'].__globals__
            def interrupted_open(_path):
                os.kill(os.getpid(), signal.SIGTERM)
                raise OSError('open refused after TERM')
            with HARNESS['signal_cleanup']():
                try:
                    with mock.patch.dict(namespace, fs_magic=lambda _: 0x63677270, Cgroup=interrupted_open):
                        with self.assertRaises(HARNESS['TerminationRequested']):
                            HARNESS['create_cgroup'](path, groups)
                        HARNESS['cleanup_cgroups'](groups)
                finally:
                    self.assertFalse(path.exists())


class TerminationTests(unittest.TestCase):
    def test_short_child_stays_enrolled_when_term_interrupts_after_acquisition(self):
        # Interrupt the former remove/insert gap, or the first post-acquisition
        # read once enrollment is continuous. Deliver a real SIGTERM through
        # the installed guard and clean only actual direct Popen children.
        class Owners(list):
            def remove(owners, child):
                super().remove(child)
                os.kill(os.getpid(), signal.SIGTERM)
        owners, acquired = Owners(), []
        original_spawn = HARNESS['spawn_owned']
        def spawn(owners, _argv, **options):
            for option in ('user', 'group', 'extra_groups'):
                options.pop(option, None)
            child = original_spawn(owners,
                [sys.executable, '-c', 'import time; time.sleep(10)'], **options)
            acquired.append(child)
            return child
        def interrupted_read(*_args):
            os.kill(os.getpid(), signal.SIGTERM)
            self.fail('installed termination guard did not unwind')
        namespace = HARNESS['short_workload'].__globals__
        selected = mock.Mock()
        try:
            with tempfile.TemporaryDirectory() as directory, HARNESS['signal_cleanup']():
                try:
                    with mock.patch.dict(namespace, spawn_owned=spawn, Reader=interrupted_read):
                        with self.assertRaises(HARNESS['TerminationRequested']):
                            HARNESS['short_workload'](mock.Mock(uid=os.getuid(), gid=os.getgid()),
                                Path(directory), os.environ, mock.Mock(), mock.Mock(),
                                selected, owners, [], [])
                    self.assertEqual(owners, acquired, 'TERM lost the acquired child from cleanup')
                    selected.move.assert_not_called()
                finally:
                    HARNESS['cleanup_processes'](owners)
            self.assertIsNotNone(acquired[0].popen.poll())
            self.assertIsNone(acquired[0].pidfd)
        finally:
            # Also bound the deliberately broken RED path without signaling
            # arbitrary PIDs or leaving its acquired pidfd/streams open.
            HARNESS['cleanup_processes'](acquired)
            for child in acquired:
                for stream in (child.popen.stdout, child.popen.stderr):
                    stream.close()

    def test_actual_sigterm_unwinds_and_second_term_cannot_abort_cleanup(self):
        # Children retire themselves if the deliberately broken RED controller
        # dies; the test never abandons descendants or guesses replacement PIDs.
        child_program = ('import os,signal,time; p=os.getppid(); '
                         'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                         'print("ready",flush=True); '
                         'exec("while os.getppid()==p: time.sleep(0.01)")')
        program = """
import json,os,runpy,signal,sys,time
h=runpy.run_path(sys.argv[1]); owners=[]
try:
    with h['signal_cleanup']():
        try:
            for _ in range(2):
                owner=h['spawn_owned'](owners,[sys.executable,'-c',sys.argv[2]],os.getuid(),
                    stdout=-1,text=True,start_new_session=True)
                assert owner.popen.stdout.readline().strip()=='ready'
            print('READY '+json.dumps([owner.pid for owner in owners]),flush=True)
            while True: time.sleep(0.1)
        finally:
            print('CLEANING',flush=True)
            h['cleanup_processes'](owners)
            print('CLEANED',flush=True)
except h['TerminationRequested'] as error:
    sys.exit(128+error.signum)
"""
        controller = subprocess.Popen([sys.executable, '-I', '-c', program,
            str(ROOT / 'scripts/qualify-cgroup-trace.py'), child_program],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        pidfds = []
        try:
            ready = controller.stdout.readline()
            self.assertTrue(ready.startswith('READY '), ready)
            for pid in json.loads(ready[6:]):
                identity = HARNESS['process_identity'](pid)
                self.assertEqual(identity['ppid'], controller.pid)
                self.assertEqual(identity['uid'], os.getuid())
                pidfds.append(os.pidfd_open(pid))
            controller.send_signal(signal.SIGTERM)
            cleaning = controller.stdout.readline()
            if cleaning.strip() == 'CLEANING':
                controller.send_signal(signal.SIGTERM)
            output, errors = controller.communicate(timeout=8)
            self.assertEqual(controller.returncode, 128 + signal.SIGTERM, errors)
            self.assertEqual(cleaning.strip(), 'CLEANING')
            self.assertIn('CLEANED', output)
        finally:
            if controller.poll() is None:
                controller.kill()
                controller.wait(timeout=3)
            for fd in pidfds:
                poll = select.poll()
                poll.register(fd, select.POLLIN)
                self.assertTrue(poll.poll(1000), 'owned fixture descendant failed to retire')
                os.close(fd)
            controller.stdout.close()
            controller.stderr.close()


class NativeMatrixFixtureTests(unittest.TestCase):
    def setUp(self):
        self.provider = Path('/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
        if not self.provider.is_file() or not shutil.which('softhsm2-util') or not shutil.which('gcc'):
            self.skipTest('requires existing SoftHSM/gcc; installs nothing')
        self.scratch = tempfile.TemporaryDirectory(prefix='n3-matrix-native-')
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.executable = self.directory / 'trace-a'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-o', str(self.executable), str(ROOT / 'tests/fixtures/cgroup-trace/caller.c'),
                        '-ldl'], check=True, capture_output=True, timeout=20)
        self.successor = self.directory / 'trace-b'
        shutil.copyfile(self.executable, self.successor)
        self.successor.chmod(0o700)
        tokens = self.directory / 'tokens'
        tokens.mkdir()
        config = self.directory / 'softhsm2.conf'
        config.write_text(f'directories.tokendir = {tokens}\nlog.level = ERROR\n')
        self.env = dict(os.environ, SOFTHSM2_CONF=str(config))
        subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', 'n3-matrix-host',
                        '--so-pin', '5678', '--pin', '1234'], env=self.env, check=True,
                       capture_output=True, timeout=10)
        self.owners, self.readers, self.pins = [], [], []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        try:
            HARNESS['cleanup_processes'](self.owners)
        finally:
            for reader in self.readers:
                reader.finish()
            for pin in self.pins:
                pin.close()
            for owner in self.owners:
                if owner.popen:
                    for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                        if stream:
                            stream.close()

    def start(self, extra=()):
        self.spawn_started = time.monotonic_ns()
        owner = HARNESS['spawn_owned'](self.owners,
            [str(self.executable), str(self.provider), '0', 'selected', *extra], os.getuid(),
            env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        stdout = HARNESS['Reader'](owner.popen.stdout, self.directory / 'ledger')
        stderr = HARNESS['Reader'](owner.popen.stderr, self.directory / 'stderr')
        self.readers.extend((stdout, stderr))
        return owner, stdout

    def image(self, reader, owner, path, number):
        pin = HARNESS['FilePin'](path)
        self.pins.append(pin)
        return pin.image_receipt(reader.record('image', number), owner)

    def stop(self, owner, reader, number):
        owner.popen.stdin.write('stop\n')
        owner.popen.stdin.flush()
        reader.record('ack', number, 'done')
        self.assertEqual(owner.popen.wait(timeout=3), 0)
        pin = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['pin'](self.provider)
        targets = {(x['image'], x['fn']): x for x in reader.records if x['kind'] == 'target'}
        for call in (x for x in reader.records if x['kind'] == 'call'):
            target = targets[call['image'], call['fn']]
            self.assertEqual((target['dev'], target['ino']), (pin['dev'], pin['ino']))
            self.assertEqual(call['rv'], 0)

    def test_real_spaced_calls_complete_and_record_actual_gaps(self):
        owner, reader = self.start()
        reader.record('ready')
        self.image(reader, owner, self.executable, 0)
        phases = []
        HARNESS['command'](owner, reader, 'C_GetSessionInfo', 3, 20, 'sparse', 'selected',
                           phases=phases, spaced=True, acknowledgement_seconds=1)
        calls = [x for x in reader.records if x['kind'] == 'call' and x['phase'] == 'sparse']
        self.assertEqual(len(calls), 3)
        for earlier, later in zip(calls, calls[1:]):
            self.assertGreaterEqual(later['t0'] - earlier['t1'], 20_000_000)
        self.assertEqual(phases[0]['gap_ms'], 20)
        self.stop(owner, reader, 0)

    def test_spaced_request_outside_the_bounded_schedule_performs_no_work(self):
        owner, reader = self.start()
        reader.record('ready')
        owner.popen.stdin.write('spaced C_GetSessionInfo 4 61000 refused selected\n')
        owner.popen.stdin.flush()
        self.assertEqual(owner.popen.wait(timeout=1), 2)
        reader.finish()
        self.assertFalse(any(x['kind'] == 'call' and x['phase'] == 'refused' for x in reader.records))

    def exec_control(self, command, path, mode):
        owner, reader = self.start()
        reader.record('ready')
        before = self.image(reader, owner, self.executable, 0)
        HARNESS['command'](owner, reader, 'C_GetInfo', 1, 0, 'outside', 'outside')
        owner.popen.stdin.write(f'{command} {path}\n')
        owner.popen.stdin.flush()
        reader.record('ready', 1)
        after = self.image(reader, owner, path, 1)
        request = reader.wait(lambda r: next((x for x in r.records
            if x['kind'] == 'exec' and x['image'] == 0), None), seconds=0.2)
        self.assertEqual((before['pid'], before['start_time']), (after['pid'], after['start_time']))
        self.assertEqual(request['mode'], mode)
        self.assertEqual(request['path'], str(path))
        self.assertEqual(request['scope'], 'outside')
        self.assertLess(request['t'], reader.record('image', 1)['t'])
        if mode == 'nonleader':
            self.assertNotEqual(request['tid'], request['pid'])
        else:
            self.assertEqual(request['tid'], request['pid'])
        HARNESS['command'](owner, reader, 'C_GetSessionInfo', 2, 0, 'after', 'selected', 1)
        self.stop(owner, reader, 1)
        return before, after

    def test_real_same_path_exec_keeps_file_and_birth_but_reports_generation(self):
        before, after = self.exec_control('exec', self.executable, 'leader')
        self.assertEqual((before['path'], before['ino']), (after['path'], after['ino']))

    def test_real_nonleader_exec_has_a_distinct_executing_tid(self):
        before, after = self.exec_control('thread-exec', self.successor, 'nonleader')
        self.assertNotEqual((before['path'], before['ino']), (after['path'], after['ino']))

    def test_short_native_start_gate_precedes_provider_calls_and_actual_exit(self):
        gate = self.directory / 'start-gate'
        owner, reader = self.start(('--start-gate', str(gate), '--auto-gate', str(gate),
                                    '--auto-count', '1', '--auto-delay-ms', '0'))
        self.image(reader, owner, self.executable, 0)
        self.assertFalse(any(x['kind'] == 'call' for x in reader.records))
        gate.touch()
        reader.record('ack', 0, 'done')
        self.assertTrue(owner.wait_exit(1))
        self.assertLessEqual((time.monotonic_ns() - self.spawn_started) / 1e9, 1)
        self.assertEqual(owner.popen.wait(timeout=1), 0)
        calls = [x for x in reader.records if x['kind'] == 'call']
        self.assertEqual(Counter(x['phase'] for x in calls), Counter(setup=4, main=1, teardown=2))

    def short_adapter(self, refuse_move=False):
        # Exercise the actual producer adapter with owned ordinary-user native
        # processes. The cgroup write is the only mocked privileged seam.
        class Group:
            path = Path('/sys/fs/cgroup/owned-host-control')
            def move(group, owner):
                owner.verify()
                if refuse_move:
                    raise ValueError('owned membership barrier refused')
                group.moved_ns = time.monotonic_ns()
        selected = Group()
        caller = HARNESS['FilePin'](self.executable)
        provider = HARNESS['FilePin'](self.provider)
        self.pins.extend((caller, provider))
        original_spawn = HARNESS['spawn_owned']
        def ordinary_spawn(owners, argv, **options):
            for option in ('user', 'group', 'extra_groups'):
                options.pop(option, None)
            return original_spawn(owners, argv, **options)
        args = mock.Mock(uid=os.getuid(), gid=os.getgid())
        images = []
        with mock.patch.dict(HARNESS['short_workload'].__globals__, spawn_owned=ordinary_spawn):
            result = HARNESS['short_workload'](args, self.directory, self.env, provider, caller,
                                              selected, self.owners, self.readers, images)
        return result, selected, images

    def test_short_real_adapter_validates_image_and_observes_pidfd_exit(self):
        result, selected, images = self.short_adapter()
        self.assertEqual(result['caller_rc'], 0)
        self.assertEqual(images[0]['image'], 1)
        self.assertGreaterEqual(result['phase']['t0'], selected.moved_ns)
        lifetime = result['lifetime']
        self.assertLessEqual((lifetime['exit_observed_ns'] - lifetime['spawn_started_ns']) / 1e9, 1)
        calls = [x for x in result['reader'].records if x['kind'] == 'call']
        self.assertEqual(Counter(x['phase'] for x in calls), Counter(setup=4, main=1, teardown=2))

    def test_short_real_adapter_refuses_before_gate_on_membership_failure(self):
        with self.assertRaises(ValueError):
            self.short_adapter(refuse_move=True)
        self.assertFalse((self.directory / 'short-start-gate').exists())
        self.assertFalse(any(x['kind'] == 'call' for reader in self.readers for x in reader.records))


class NativeFixtureTests(unittest.TestCase):
    def test_real_provider_setup_calls_exec_and_teardown_are_all_ledgered(self):
        provider = Path('/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
        if not provider.is_file() or not shutil.which('softhsm2-util') or not shutil.which('gcc'):
            self.skipTest('requires the existing SoftHSM fixture and gcc; installs nothing')
        with tempfile.TemporaryDirectory(prefix='n3-native-') as scratch:
            directory = Path(scratch)
            executable = directory / 'trace-a'
            subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                            '-o', str(executable), str(ROOT / 'tests/fixtures/cgroup-trace/caller.c'),
                            '-ldl'], check=True, capture_output=True, timeout=20)
            successor = directory / 'trace-b'
            shutil.copyfile(executable, successor)
            successor.chmod(0o700)
            tokens = directory / 'tokens'
            tokens.mkdir()
            config = directory / 'softhsm2.conf'
            config.write_text(f'directories.tokendir = {tokens}\nlog.level = ERROR\n')
            env = dict(os.environ, SOFTHSM2_CONF=str(config), N3_PRIVATE_ENV='N3_PRIVATE_ENV_a279d2')
            subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', 'n3-host-test',
                            '--so-pin', '5678', '--pin', '1234'], env=env, check=True,
                           capture_output=True, timeout=10)
            child = subprocess.Popen([str(executable), str(provider), '0', 'selected',
                                      '--canary', 'N3_PRIVATE_ARG_248abc'], env=env, text=True,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            owner = HARNESS['OwnedProcess'](child.pid, os.getpid(), os.getuid(), child)
            stdout = HARNESS['Reader'](child.stdout, directory / 'ledger')
            stderr = HARNESS['Reader'](child.stderr, directory / 'errors')
            pins = [HARNESS['FilePin'](executable), HARNESS['FilePin'](successor)]
            try:
                stdout.record('ready')
                before = pins[0].image_receipt(stdout.record('image'), owner)
                HARNESS['command'](owner, stdout, 'C_GenerateRandom', 2, 0, 'a', 'selected')
                child.stdin.write(f'exec {successor}\n')
                child.stdin.flush()
                stdout.record('ready', 1)
                after = pins[1].image_receipt(stdout.record('image', 1), owner)
                self.assertEqual((before['pid'], before['start_time']), (after['pid'], after['start_time']))
                self.assertNotEqual((before['path'], before['ino']), (after['path'], after['ino']))
                HARNESS['command'](owner, stdout, 'C_GetSessionInfo', 3, 0, 'b', 'outside', 1)
                HARNESS['command'](owner, stdout, 'C_GetInfo', 1, 0, 'outside', 'outside', 1)
                child.stdin.write('stop\n')
                child.stdin.flush()
                stdout.record('ack', 1, 'done')
                self.assertEqual(child.wait(timeout=3), 0)
                text = stdout.finish()
                self.assertEqual(stderr.finish(), '')
                calls = [row for row in stdout.records if row['kind'] == 'call']
                self.assertEqual(Counter(row['fn'] for row in calls),
                    Counter(C_GetFunctionList=2, C_Initialize=2, C_GetSlotList=2,
                            C_OpenSession=2, C_GenerateRandom=2, C_GetSessionInfo=3,
                            C_GetInfo=1, C_CloseSession=1, C_Finalize=1))
                pin = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['pin'](provider)
                targets = {(row['image'], row['fn']): row for row in stdout.records if row['kind'] == 'target'}
                for call in calls:
                    self.assertEqual(call['rv'], 0)
                    self.assertGreaterEqual(call['t1'], call['t0'])
                    target = targets[call['image'], call['fn']]
                    self.assertEqual((target['dev'], target['ino']), (pin['dev'], pin['ino']))
                self.assertNotIn('N3_PRIVATE_ENV_a279d2', text)
                self.assertNotIn('N3_PRIVATE_ARG_248abc', text)
                self.assertNotIn('N3_PRIVATE_BUFFER_91b947', text)
            finally:
                HARNESS['terminate'](owner)
                owner.close()
                child.stdin.close()
                child.stdout.close()
                child.stderr.close()
                for pin in pins:
                    pin.close()


if __name__ == '__main__':
    unittest.main()
