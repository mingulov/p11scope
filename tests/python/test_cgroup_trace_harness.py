# SPDX-License-Identifier: GPL-3.0-or-later
"""Ownership checks must fail before any signal or cgroup mutation."""

from collections import Counter
import os
import json
from pathlib import Path
import runpy
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HARNESS = runpy.run_path(str(ROOT / 'scripts/qualify-cgroup-trace.py'))


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
                with self.assertRaises(ExceptionGroup):
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


class NativeFixtureTests(unittest.TestCase):
    def test_real_provider_setup_calls_exec_and_teardown_are_all_ledgered(self):
        provider = Path('/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
        if not provider.is_file() or not shutil.which('softhsm2-util') or not shutil.which('gcc'):
            self.skipTest('requires the existing SoftHSM fixture and gcc; installs nothing')
        with tempfile.TemporaryDirectory(prefix='n3-native-') as scratch:
            directory = Path(scratch)
            executable = directory / 'trace-a'
            subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
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
