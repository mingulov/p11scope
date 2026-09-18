#!/usr/bin/env python3
"""Unprivileged seed-qualifier probes with injected BPF acquisition boundaries.

Every genuinely privileged step - real task-storage map creation, seeding,
iteration and kernel-side cleanup - is UNRUN here and is never simulated into a
pass. Branches whose acquisition boundary or fixture is a stand-in carry
`injected` in their name or docstring. The fixture is x86-64 only, so this file
takes no target-width argument.
"""
import errno
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


def load(name, relative):
    return load_path(ROOT / relative, name)


qualifier = load('qualifier', 'scripts/qualify-task-storage-canary.py')
coordinator = qualifier.coordinator
custody = qualifier.custody
dumper = qualifier.dumper
evidence = qualifier.evidence
evidence.initialize(qualifier.TARGET_BITS)
LEGACY = evidence.SENTINELS['LEGACY_NAME']
IDS = (4001, 4002, 4003)

# An x86-64 ELF wrapper so the qualifier's real native-ABI check applies, which
# then execs the injected stand-in behaviour below. It creates no BPF map.
STANDIN_C = r'''
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char *interpreter = getenv("P11SCOPE_STANDIN_PYTHON");
    char *script = getenv("P11SCOPE_STANDIN_SCRIPT");
    char *arguments[16];
    int index;
    if (!interpreter || !script || argc < 1 || argc > 12)
        return 2;
    arguments[0] = interpreter;
    arguments[1] = (char *)"-I";
    arguments[2] = script;
    for (index = 1; index < argc; index++)
        arguments[2 + index] = argv[index];
    arguments[2 + argc] = NULL;
    execv(interpreter, arguments);
    return 3;
}
'''

STANDIN_PY = r'''"""Injected stand-in for the frozen native fixture: it creates no BPF map."""
import json
import os
from pathlib import Path
import sys
import time

obj, seed, ready, release, timeout_ms = sys.argv[1:6]
plan = json.loads(Path(os.environ['P11SCOPE_STANDIN_PLAN']).read_bytes())
if plan.get('child'):
    if os.fork() == 0:
        time.sleep(plan['child'])
        os._exit(0)
if plan.get('exit_before_ready'):
    sys.exit(plan.get('status', 1))
generation = int(Path('/proc/self/stat').read_text().rsplit(') ', 1)[1].split()[19])
body = plan['ready'].replace('@PID@', str(os.getpid())).replace('@GEN@', str(generation))
handle = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(handle, body.encode())
os.close(handle)
deadline = time.monotonic() + float(timeout_ms) / 1000
while not os.path.lexists(release):
    if time.monotonic() > deadline:
        sys.exit(9)
    time.sleep(.005)
sys.exit(plan.get('status', 0))
'''


def ready_maps(ids=IDS):
    return [{'name': name, 'id': map_id, 'type': 'task_storage', 'bytes_key': 4,
             'bytes_value': size, 'max_entries': 0, 'map_flags': 1}
            for map_id, (name, _, size) in zip(ids, qualifier.MAP_LAYOUT)]


def ready_document(pid='@PID@', generation='@GEN@', ids=IDS):
    return {'schema': qualifier.SCHEMA, 'abi': qualifier.ABI, 'pid': pid, 'tid': pid,
            'generation': generation,
            'tasks': [{'pid': pid, 'tid': pid, 'generation': generation}],
            'maps': ready_maps(ids)}


def ready_template(**changes):
    document = ready_document(**changes)
    raw = json.dumps(document)
    return raw.replace('"@PID@"', '@PID@').replace('"@GEN@"', '@GEN@')


def frame(kind, map_id, pid, tid, value=b''):
    return dumper.TASK_STORAGE_HEADER.pack(dumper.TASK_STORAGE_MAGIC, kind, map_id, pid, tid,
                                           len(value)) + value


def stream(rows, *, terminal=True):
    raw = b''.join(frame(dumper.TASK_STORAGE_RECORD, *row) for row in rows)
    return raw + (frame(dumper.TASK_STORAGE_EOF, 0, 0, 0) if terminal else b'')


def seeded_rows(case, pid, ids=IDS):
    values = qualifier.control_values(case)
    return [(map_id, pid, pid, values[name])
            for map_id, (name, _, _) in zip(ids, qualifier.MAP_LAYOUT)]


def config_for(directory, **changes):
    directory = Path(directory)
    out_dir = directory / 'seed'
    config = SimpleNamespace(
        fixture=directory / 'fixture', reader=directory / 'reader',
        obj=directory / 'object.bpf.o', out_dir=out_dir,
        receipt=out_dir / 'qualification.json', cases=qualifier.CASES,
        lane='task-storage-seed', target_bits=qualifier.TARGET_BITS)
    for name, value in changes.items():
        setattr(config, name, value)
    return config


class InjectedSeedMaps:
    """Injected acquisition boundary: no BPF map is created, pinned or read."""
    def __init__(self, case, plan):
        self.case, self.plan = case, plan
        self.ids = list(plan.get('ids', IDS))
        self.pinned, self.closed, self.probed = [], 0, []

    def inventory(self, group, deadline):
        coordinator.remaining(deadline)
        group.snapshot(deadline)
        return sorted(self.ids)

    def pin(self, maps, deadline):
        coordinator.remaining(deadline)
        self.pinned = [item['id'] for item in maps]

    def info(self, map_id):
        index = self.ids.index(map_id)
        name, _, size = qualifier.MAP_LAYOUT[index]
        return {'type': qualifier.BPF_MAP_TYPE_TASK_STORAGE, 'id': map_id, 'bytes_key': 4,
                'bytes_value': size, 'max_entries': 0, 'map_flags': 1,
                'name': name[:qualifier.KERNEL_NAME_LIMIT]}

    def frames(self, owner, config, pid, maps, deadline):
        with owner.helper_wait():
            coordinator.remaining(deadline)
            return stream(seeded_rows(self.case, pid, self.ids))

    def absent(self, map_id):
        # Record how many closes preceded each probe. A retained descriptor
        # keeps its map id resolvable on a live kernel, so an id probed before
        # the explicit `source.close()` must never read as cleanup here either.
        self.probed.append((map_id, self.closed))
        if not self.closed:
            return 'resolvable'
        return self.plan.get('absence', 'absent')

    def close(self):
        self.closed += 1


def injected_factory(plan, created=None):
    def factory(case):
        source = InjectedSeedMaps(case, plan)
        if created is not None:
            created.append(source)
        return source
    return factory


def assert_close_precedes_absence(sources, cases):
    """Every absence probe ran after the explicit close, and only after it."""
    assert len(sources) == cases, (len(sources), cases)
    for source in sources:
        assert [map_id for map_id, _ in source.probed] == list(IDS), source.probed
        assert [closes for _, closes in source.probed] == [1, 1, 1], source.probed
        # The explicit cleanup close, then the ledger close in the finally.
        assert source.closed == 2, source.closed


def probe_case(directory, name):
    """Real custody in a childless process with an injected acquisition."""
    directory = Path(directory)
    plan = json.loads((directory / 'plan.json').read_bytes())
    config = config_for(directory, fixture=directory / 'standin-fixture',
                        reader=directory / 'standin-fixture',
                        obj=directory / 'plan.json')
    if plan.get('cases'):
        config.cases = tuple(plan['cases'])
    if name.startswith('generation_change'):
        original, calls = qualifier.read_generation, []
        # 1 bumps only the post-stop recheck; 0 bumps the pre-READY read as well,
        # so a single-case probe reaches exactly one generation comparison.
        bump_after = plan.get('bump_after', 1)

        def bumped(pid, deadline):
            calls.append(pid)
            value = original(pid, deadline)
            return value + 1 if len(calls) > bump_after else value
        qualifier.read_generation = bumped
    failure, sources = None, []
    try:
        receipt = qualifier.qualify(config, injected_factory(plan, sources))
    except coordinator.CaptureError as error:
        failure, receipt = error, None
    surfaces = sorted(path.name for path in config.out_dir.glob('*.bin'))
    seeds = sorted(path.name for path in config.out_dir.glob('*.seed'))
    if name == 'complete':
        assert failure is None, str(failure)
        assert receipt == config.receipt and receipt.is_file(), 'receipt was not published'
        document = json.loads(receipt.read_bytes())
        assert document['contract'] == qualifier.CONTRACT, document['contract']
        assert document['terminal_pass'] is True
        assert document['fixture']['abi']['machine'] == 'x86-64'
        assert document['fixture']['abi']['distinct_from_paired_ia32_workload'] is True
        assert document['kernel_release'] == os.uname().release
        assert sorted(document['cases']) == sorted(qualifier.CASES)
        assert document['scanner']['baseline'] == 'accepted'
        assert document['scanner']['early'] == 'refused'
        assert document['scanner']['late'] == 'refused'
        for case, summary in document['cases'].items():
            assert summary['terminal_eof']['records'] == 3, summary
            assert [row['id'] for row in summary['maps']] == list(IDS), summary
            assert [row['value_bytes'] for row in summary['maps']] == [8, 544, 8], summary
            assert summary['cleanup'] == 'map ids absent with ENOENT', summary
        assert len(surfaces) == 9 and len(seeds) == 3, (surfaces, seeds)
        assert receipt.stat().st_mode & 0o777 == 0o600
        assert_close_precedes_absence(sources, len(qualifier.CASES))
    elif name == 'close_ordering':
        # The cleanup close must precede the absence probe: the injected
        # boundary reports a still-retained id as resolvable, so a probe that
        # ran before `source.close()` cannot reach a cleanup pass.
        assert failure is None, str(failure)
        assert receipt is None, 'a single-case run published a receipt'
        assert_close_precedes_absence(sources, 1)
    elif name == 'subset':
        assert failure is None, str(failure)
        assert receipt is None, 'a subset run published a receipt'
        assert not config.receipt.exists(), 'a subset run published a receipt file'
    else:
        assert failure is not None, f'{name} was accepted'
        assert not config.receipt.exists(), f'{name} published a receipt'
        assert not surfaces and not seeds, (name, surfaces, seeds)
        # Rollback covers every path this run created except the per-case
        # fixture log, which is the only trace a refused live run leaves: the
        # READY/RELEASE handshake, the seed and every surface must be gone.
        left = sorted(entry.name for entry in config.out_dir.iterdir())
        assert set(left) <= {f'{case}.fixture.log' for case in qualifier.CASES}, (name, left)
        issue = plan.get('issue')
        # Pin the named invariant: another check refusing first is not a pass.
        assert issue is None or issue in str(failure), (name, issue, str(failure))
    if name == 'extra_child':
        assert 'unexpected' in str(failure) or 'CustodyError' in str(failure), str(failure)
    assert not custody._children(os.getpid(), custody._tasks(os.getpid(), time.monotonic() + 1),
                                 time.monotonic() + 1), 'probe leaked a child'


class TaskStorageCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        root = Path(cls.build.name)
        cls.output = root / 'build'
        cls.build_result = subprocess.run(
            [str(ROOT / 'scripts/build-task-storage-canary.sh'), str(cls.output)],
            capture_output=True, text=True, timeout=120)
        cls.fixture = cls.output / 'task-storage-canary'
        cls.standin = root / 'standin-fixture'
        cls.standin_script = root / 'standin_fixture.py'
        cls.standin_script.write_text(STANDIN_PY)
        source = root / 'standin.c'
        source.write_text(STANDIN_C)
        subprocess.run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', str(source),
                        '-o', str(cls.standin)], check=True, capture_output=True, timeout=120)
        cls.absent_object = root / 'absent' / 'dump-task-storage.bpf.o'

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def fixture_run(self, arguments, directory):
        return subprocess.run([str(self.fixture), *arguments], capture_output=True, text=True,
                              timeout=30, cwd=directory)

    def assert_refused(self, result, directory, *, quiet=True):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertFalse((Path(directory) / 'ready.json').exists())
        self.assertFalse((Path(directory) / 'release').exists())
        if quiet:
            self.assertNotIn('libbpf', result.stderr)

    def seed_directory(self, stack, *, case='baseline'):
        directory = Path(stack.name)
        (directory / 'seed').write_bytes(qualifier.seed_bytes(case))
        return directory

    def probe(self, name, plan):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan.json').write_text(json.dumps(plan))
            shutil.copy2(self.standin, root / 'standin-fixture')
            environment = dict(os.environ, P11SCOPE_STANDIN_PYTHON=sys.executable,
                               P11SCOPE_STANDIN_SCRIPT=str(self.standin_script),
                               P11SCOPE_STANDIN_PLAN=str(root / 'plan.json'))
            result = subprocess.run(
                ['timeout', '--kill-after=2s', '60s', sys.executable, '-I', __file__,
                 '--probe', name, str(root)],
                capture_output=True, text=True, timeout=90, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # ---- the frozen fixture, built and exercised without BPF privilege -----

    def test_builder_compiles_the_fixture_and_its_unprivileged_checks_pass(self):
        self.assertEqual(self.build_result.returncode, 0,
                         self.build_result.stdout + self.build_result.stderr)
        self.assertEqual(self.build_result.stderr, '', 'the fixture did not compile cleanly')
        self.assertTrue(self.fixture.is_file() and os.access(self.fixture, os.X_OK))
        self.assertEqual(self.fixture.stat().st_mode & 0o077, 0)
        self.assertEqual(qualifier.elf_identity(self.fixture),
                         (qualifier.ELF_CLASS64, qualifier.ELF_LITTLE_ENDIAN,
                          qualifier.ELF_MACHINE_X86_64))
        result = subprocess.run([str(self.fixture), '--self-test'], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len([line for line in result.stdout.splitlines()
                              if line.endswith(': OK')]), 5, result.stdout)
        # The identity/release case owns the one expected stderr diagnostic.
        self.assertEqual([line for line in result.stderr.splitlines()
                          if 'timed out waiting for RELEASE' in line],
                         ['task-storage-canary: timed out waiting for RELEASE'],
                         result.stderr)

    def test_fixture_refuses_wrong_argument_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / 'seed'
            seed.write_bytes(qualifier.seed_bytes('baseline'))
            complete = [str(self.absent_object), str(seed), f'{directory}/ready.json',
                        f'{directory}/release', '1000']
            for count in (0, 1, 2, 3, 4, 6, 7):
                with self.subTest(arguments=count):
                    arguments = (complete + ['extra', 'more'])[:count]
                    if count == 2:
                        arguments = [str(self.absent_object), '--self-tests']
                    result = self.fixture_run(arguments, directory)
                    self.assert_refused(result, directory)
                    self.assertIn('usage: task-storage-canary', result.stderr)

    def test_fixture_refuses_relative_paths_and_out_of_range_timeouts(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / 'seed'
            seed.write_bytes(qualifier.seed_bytes('baseline'))
            complete = [str(self.absent_object), str(seed), f'{directory}/ready.json',
                        f'{directory}/release', '1000']
            for index, label in enumerate(('OBJECT', 'SEED', 'READY', 'RELEASE')):
                with self.subTest(relative=label):
                    arguments = list(complete)
                    arguments[index] = 'relative/path'
                    result = self.fixture_run(arguments, directory)
                    self.assert_refused(result, directory)
                    self.assertIn(f'{label} path must be absolute', result.stderr)
            for timeout in ('0', '60001', 'abc', '', '1000x', '-1', '+1', '000060001'):
                with self.subTest(timeout=timeout):
                    result = self.fixture_run(complete[:4] + [timeout], directory)
                    self.assert_refused(result, directory)
                    self.assertIn('TIMEOUT_MS must be a decimal in (0, 60000]', result.stderr)

    def test_fixture_refuses_malformed_seeds_and_existing_ready_or_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = root / 'seed'
            good.write_bytes(qualifier.seed_bytes('baseline'))
            (root / 'short').write_bytes(qualifier.seed_bytes('baseline')[:559])
            (root / 'long').write_bytes(qualifier.seed_bytes('baseline') + b'\x00')
            (root / 'directory').mkdir()
            os.mkfifo(root / 'fifo')
            (root / 'link').symlink_to(good)
            unreadable = root / 'unreadable'
            unreadable.write_bytes(qualifier.seed_bytes('baseline'))
            os.chmod(unreadable, 0)
            cases = (('missing', root / 'absent-seed', 'cannot open SEED'),
                     ('short', root / 'short', 'shorter than the fixed 560-byte layout'),
                     ('long', root / 'long', 'longer than the fixed 560-byte layout'),
                     ('directory', root / 'directory', 'SEED is not a regular file'),
                     ('fifo', root / 'fifo', 'SEED is not a regular file'),
                     ('symlink', root / 'link', 'cannot open SEED'))
            for label, path, message in cases:
                with self.subTest(seed=label):
                    result = self.fixture_run(
                        [str(self.absent_object), str(path), f'{directory}/ready.json',
                         f'{directory}/release', '1000'], directory)
                    self.assert_refused(result, directory)
                    self.assertIn(message, result.stderr)
            with self.subTest(seed='unreadable'):
                result = self.fixture_run(
                    [str(self.absent_object), str(unreadable), f'{directory}/ready.json',
                     f'{directory}/release', '1000'], directory)
                # A privileged caller can still read mode 0 ; the refusal itself is
                # unconditional because the object path never exists.
                self.assert_refused(result, directory,
                                    quiet=not os.access(unreadable, os.R_OK))
                if not os.access(unreadable, os.R_OK):
                    self.assertIn('cannot open SEED', result.stderr)
            for label in ('ready.json', 'release'):
                with self.subTest(existing=label):
                    (root / label).write_text('')
                    result = self.fixture_run(
                        [str(self.absent_object), str(good), f'{directory}/ready.json',
                         f'{directory}/release', '1000'], directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('already exists', result.stderr)
                    self.assertNotIn('libbpf', result.stderr)
                    (root / label).unlink()

    # ---- the frozen seed layout and the three controls ---------------------

    def test_seed_is_exactly_560_bytes_in_the_frozen_split(self):
        for case in qualifier.CASES:
            with self.subTest(case=case):
                raw = qualifier.seed_bytes(case)
                self.assertEqual(len(raw), 560)
                values = qualifier.control_values(case)
                self.assertEqual([len(values[name]) for name, _, _ in qualifier.MAP_LAYOUT],
                                 [8, 544, 8])
                for name, offset, size in qualifier.MAP_LAYOUT:
                    self.assertEqual(raw[offset:offset + size], values[name])
                self.assertNotEqual(values['TASK_COOKIE'], values['ROOT_AFFILIATION'])
                self.assertTrue(any(values['TASK_COOKIE']) and any(values['ROOT_AFFILIATION']))
        self.assertEqual([offset for _, offset, _ in qualifier.MAP_LAYOUT], [0, 8, 552])

    def test_early_and_late_controls_sit_at_the_frozen_owner_offsets(self):
        self.assertEqual(len(LEGACY), 9)
        baseline = qualifier.control_values('baseline')['THREAD_OWNER']
        early = qualifier.control_values('early')['THREAD_OWNER']
        late = qualifier.control_values('late')['THREAD_OWNER']
        self.assertNotIn(LEGACY, baseline)
        self.assertEqual(early[0:9], LEGACY)
        self.assertEqual(early.count(LEGACY), 1)
        self.assertEqual(late[535:544], LEGACY)
        self.assertEqual(late.count(LEGACY), 1)
        self.assertEqual(535 + len(LEGACY), 544)
        self.assertNotEqual(late[0:9], LEGACY)
        self.assertNotIn(LEGACY, late[:535])

    def test_controls_differ_from_the_baseline_only_where_specified(self):
        baseline = qualifier.control_values('baseline')
        for case, span in (('early', range(0, 9)), ('late', range(535, 544))):
            with self.subTest(case=case):
                values = qualifier.control_values(case)
                self.assertEqual(values['TASK_COOKIE'], baseline['TASK_COOKIE'])
                self.assertEqual(values['ROOT_AFFILIATION'], baseline['ROOT_AFFILIATION'])
                differing = [index for index in range(544)
                             if values['THREAD_OWNER'][index] != baseline['THREAD_OWNER'][index]]
                self.assertTrue(set(differing).issubset(set(span)), differing)
                self.assertEqual(len(values['THREAD_OWNER']), 544)

    # ---- the real shared scanner as the only control oracle ----------------

    def scan_paths(self, directory, case, values):
        paths = []
        for name, _, _ in qualifier.MAP_LAYOUT:
            path = Path(directory) / f'{case}-{name}.bin'
            path.write_bytes(values[name])
            paths.append(path)
        return paths

    def test_baseline_surfaces_pass_the_real_shared_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.scan_paths(directory, 'baseline', qualifier.control_values('baseline'))
            evidence.assert_final_artifact_privacy(paths)
            run = qualifier.Qualifier(config_for(directory))
            self.assertEqual(run.scan('baseline', paths), 'accepted')

    def test_baseline_branch_refuses_a_leaking_surface_with_sanitised_text(self):
        """The baseline branch calls the real scanner, so a leak raises there too."""
        with tempfile.TemporaryDirectory() as directory:
            leaking = qualifier.control_values('late')
            paths = self.scan_paths(directory, 'baseline', leaking)
            run = qualifier.Qualifier(config_for(directory))
            with self.assertRaises(AssertionError) as raised:
                run.scan('baseline', paths)
            # The raw assertion does carry context, which is exactly why the
            # coordinator never renders it.
            self.assertIn('LEGACY_NAME', str(raised.exception))
            issues = coordinator.sanitized('baseline-surfaces', raised.exception)
            self.assertEqual(issues, ['baseline-surfaces: AssertionError'])
            rendered = '; '.join(issues)
            self.assertNotIn('LEGACY_NAME', rendered)
            self.assertNotIn(LEGACY.decode(), rendered)
            for name, _, _ in qualifier.MAP_LAYOUT:
                self.assertNotIn(leaking[name][:8].decode('ascii', 'replace'), rendered)

    def test_early_and_late_surfaces_are_refused_by_the_real_shared_scanner(self):
        for case in ('early', 'late'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                paths = self.scan_paths(directory, case, qualifier.control_values(case))
                with self.assertRaises(AssertionError) as raised:
                    evidence.assert_final_artifact_privacy(paths)
                self.assertIn('ordinary pointer canaries leaked', str(raised.exception))
                self.assertIn('LEGACY_NAME', str(raised.exception))
                run = qualifier.Qualifier(config_for(directory))
                self.assertEqual(run.scan(case, paths), 'refused')
                # A control the scanner accepts is not a control at all.
                clean = self.scan_paths(directory, 'clean',
                                        qualifier.control_values('baseline'))
                with self.assertRaises(coordinator.CaptureError) as refusal:
                    run.scan(case, clean)
                self.assertIn('was not refused', str(refusal.exception))

    def test_full_byte_comparison_precedes_any_expected_refusal(self):
        """Injected acquisition: a differently leaking value may not pose as a control."""
        maps = ready_maps()
        values = qualifier.control_values('early')
        substitute = dict(values)
        owner = bytearray(qualifier.control_values('baseline')['THREAD_OWNER'])
        owner[100:100 + len(evidence.SENTINELS['PIN'])] = evidence.SENTINELS['PIN']
        substitute['THREAD_OWNER'] = bytes(owner)
        rows = [(map_id, 77, 77, substitute[name])
                for map_id, (name, _, _) in zip(IDS, qualifier.MAP_LAYOUT)]
        with self.assertRaises(coordinator.CaptureError) as raised:
            qualifier.read_records(stream(rows), maps, 77, values)
        self.assertIn('differs from the expected control bytes', str(raised.exception))
        with tempfile.TemporaryDirectory() as directory:
            paths = self.scan_paths(directory, 'substitute', substitute)
            with self.assertRaises(AssertionError):
                evidence.assert_final_artifact_privacy(paths)

    def test_absent_probe_treats_only_enoent_as_a_cleanup_pass(self):
        """The real errno mapping of LiveSeedMaps.absent, driven through `_bpf`.

        No BPF map is created: only the class's own syscall seam is injected, so
        this states nothing about a live kernel.
        """
        source = qualifier.LiveSeedMaps()
        read_fd, write_fd = os.pipe()
        seen, dups = [], []

        def resolving(command, attr):
            seen.append((command, bytes(attr.raw)))
            dups.append(os.dup(read_fd))
            return dups[-1], 0

        def refusing(code):
            def call(command, attr):
                seen.append((command, bytes(attr.raw)))
                return -1, code
            return call
        try:
            source._bpf = resolving
            self.assertEqual(source.absent(4001), 'resolvable')
            # A resolvable probe must not leak the descriptor it opened.
            with self.assertRaises(OSError) as leaked:
                os.fstat(dups[0])
            self.assertEqual(leaked.exception.errno, errno.EBADF)
            source._bpf = refusing(errno.ENOENT)
            self.assertEqual(source.absent(4002), 'absent')
            for code in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EBADF,
                         errno.ENOMEM):
                with self.subTest(code=errno.errorcode[code]):
                    source._bpf = refusing(code)
                    state = source.absent(4003)
                    self.assertEqual(state, 'unresolved')
                    # EPERM is the reason this rule exists: it is never cleanup.
                    self.assertNotEqual(state, 'absent')
            self.assertEqual([command for command, _ in seen],
                             [qualifier.BPF_MAP_GET_FD_BY_ID] * 7)
            self.assertEqual([struct.unpack_from('=III', raw) for _, raw in seen],
                             [(4001, 0, 0), (4002, 0, 0)] + [(4003, 0, 0)] * 5)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    # ---- qualifier input validation ---------------------------------------

    def prepared(self, directory):
        root = Path(directory)
        shutil.copy2(self.standin, root / 'fixture')
        shutil.copy2(self.standin, root / 'reader')
        (root / 'object.bpf.o').write_bytes(b'\x7fELF fake object')
        return config_for(root)

    def test_config_refuses_relative_missing_and_non_regular_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / 'fifo')
            (root / 'plain').write_text('not executable')
            os.chmod(root / 'plain', 0o600)
            problems = {
                'relative-fixture': {'fixture': Path('fixture')},
                'relative-reader': {'reader': Path('reader')},
                'relative-object': {'obj': Path('object.bpf.o')},
                'missing-fixture': {'fixture': root / 'absent'},
                'missing-reader': {'reader': root / 'absent'},
                'missing-object': {'obj': root / 'absent'},
                'fifo-object': {'obj': root / 'fifo'},
                'directory-fixture': {'fixture': root},
                'nonexecutable-reader': {'reader': root / 'plain'},
                'relative-out-dir': {'out_dir': Path('seed')},
                'relative-receipt': {'receipt': Path('qualification.json')},
                'ia32-fixture': {'fixture': root / 'plain'},
            }
            for label, change in problems.items():
                with self.subTest(problem=label):
                    config = self.prepared(root)
                    for name, value in change.items():
                        setattr(config, name, value)
                    if label == 'ia32-fixture':
                        os.chmod(root / 'plain', 0o700)
                    with self.assertRaises(coordinator.CaptureError):
                        qualifier.validate_config(config)
                    os.chmod(root / 'plain', 0o600)

    def test_config_refuses_a_lane_work_root_out_dir_and_a_pre_existing_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.prepared(root)
            qualifier.validate_config(config)
            for name in ('default-safe-profile.output', 'mapdump_TASK_COOKIE_x.bin',
                         'aggregate-only-metrics.observer.log'):
                with self.subTest(lane_artifact=name):
                    marker = config.out_dir / name
                    marker.write_text('')
                    with self.assertRaises(coordinator.CaptureError) as raised:
                        qualifier.validate_config(self.prepared(root))
                    self.assertIn('lane', str(raised.exception))
                    marker.unlink()
            with self.subTest(problem='existing-receipt'):
                config.receipt.write_text('')
                with self.assertRaises(coordinator.CaptureError) as raised:
                    qualifier.validate_config(config)
                self.assertIn('receipt already exists', str(raised.exception))
                config.receipt.unlink()
            with self.subTest(problem='world-readable-out-dir'):
                os.chmod(config.out_dir, 0o755)
                with self.assertRaises(coordinator.CaptureError) as raised:
                    qualifier.validate_config(config)
                self.assertIn('private', str(raised.exception))
                os.chmod(config.out_dir, 0o700)
            with self.subTest(problem='missing-receipt-directory'):
                config.receipt = root / 'absent' / 'qualification.json'
                with self.assertRaises(coordinator.CaptureError):
                    qualifier.validate_config(config)

    def test_config_refuses_unknown_or_repeated_case_names(self):
        with tempfile.TemporaryDirectory() as directory:
            for cases in (('baseline', 'unknown'), (), ('baseline', 'baseline'),
                          ('early', 'Late'), ('all',)):
                with self.subTest(cases=cases):
                    config = self.prepared(Path(directory))
                    config.cases = cases
                    with self.assertRaises(coordinator.CaptureError):
                        qualifier.validate_config(config)
            config = self.prepared(Path(directory))
            config.cases = ('baseline', 'early', 'late')
            qualifier.validate_config(config)

    # ---- the public custody seam for proc generations ---------------------

    def test_generation_reads_use_the_public_custody_seam(self):
        """Same decoder, same refusals, no reach into the custody privates."""
        pid, deadline = os.getpid(), time.monotonic() + 5
        expected = custody._stat(pid, deadline)[0]
        self.assertGreater(expected, 0)
        self.assertEqual(custody.read_generation(pid, deadline), expected)
        self.assertEqual(qualifier.read_generation(pid, deadline), expected)
        tid = custody._tasks(pid, deadline)[0]
        self.assertEqual(custody.read_generation(pid, deadline, tid), expected)
        source = (ROOT / 'scripts/qualify-task-storage-canary.py').read_text()
        self.assertNotIn('custody._', source, 'the qualifier reaches into custody privates')
        for label, deadline_value in (('expired', time.monotonic() - 1),
                                      ('nonfinite', float('inf'))):
            with self.subTest(deadline=label):
                with self.assertRaises(custody.CustodyError):
                    custody.read_generation(pid, deadline_value)
        with self.subTest(problem='unreadable-proc-path'):
            with self.assertRaises(OSError):
                custody.read_generation(1 << 30, time.monotonic() + 5)

    # ---- the rollback ledger over adopted handshake files -----------------

    def test_adopted_handshake_paths_roll_back_and_keep_their_ownership_check(self):
        """Adoption is the seam that puts fixture-created paths in the ledger."""
        with tempfile.TemporaryDirectory() as directory:
            config = config_for(Path(directory))
            config.out_dir.mkdir(mode=0o700)
            files = coordinator.AcquisitionFiles(config)
            seed = config.out_dir / 'baseline.seed'
            files.write(seed, qualifier.seed_bytes('baseline'))
            release = config.out_dir / 'baseline.release'
            coordinator.create_control(release, lambda: files.adopt(release))
            ready = config.out_dir / 'baseline.ready.json'
            ready.write_bytes(b'{}')
            files.adopt(ready)
            self.assertEqual(files.remove(), [])
            self.assertEqual(sorted(entry.name for entry in config.out_dir.iterdir()), [])
            with self.subTest(problem='non-regular'):
                (config.out_dir / 'handshake-directory').mkdir()
                (config.out_dir / 'handshake-link').symlink_to(release)
                for name in ('handshake-directory', 'handshake-link', 'absent'):
                    with self.assertRaises((coordinator.CaptureError, OSError)):
                        files.adopt(config.out_dir / name)
            with self.subTest(problem='replaced-after-adoption'):
                replaced = config.out_dir / 'replaced.ready.json'
                replaced.write_bytes(b'{}')
                files.adopt(replaced)
                replaced.unlink()
                replaced.write_bytes(b'{}')
                issues = files.remove()
                self.assertTrue(issues, 'a substituted adopted path was unlinked anyway')
                self.assertTrue(replaced.is_file(), 'rollback unlinked a foreign file')
            with self.subTest(problem='raising-ledger-hook'):
                # The hook runs between the exclusive create and the close, so a
                # raising hook must not leak the descriptor it was handed.
                hooked = config.out_dir / 'hooked.release'
                descriptors = len(os.listdir('/proc/self/fd'))
                with self.assertRaises(RuntimeError):
                    coordinator.create_control(hooked, lambda: (_ for _ in ()).throw(
                        RuntimeError('ledger hook')))
                self.assertTrue(hooked.is_file())
                self.assertEqual(len(os.listdir('/proc/self/fd')), descriptors)

    # ---- injected READY refusals ------------------------------------------

    def test_ready_document_refusals_injected(self):
        pid, generation = 5150, 987654321
        good = ready_document(pid, generation)
        self.assertEqual([item['id'] for item in qualifier.validate_ready(good, pid, generation)],
                         list(IDS))
        problems = {}
        problems['schema'] = {**good, 'schema': 'p11scope/task-storage-canary/v2'}
        problems['abi'] = {**good, 'abi': 'i386'}
        problems['pid'] = {**good, 'pid': pid + 1}
        problems['tid'] = {**good, 'tid': pid + 1}
        problems['generation'] = {**good, 'generation': generation + 1}
        problems['roster-generation'] = {
            **good, 'tasks': [{'pid': pid, 'tid': pid, 'generation': generation + 1}]}
        problems['extra-task'] = {
            **good, 'tasks': good['tasks'] + [{'pid': pid, 'tid': pid + 1,
                                               'generation': generation}]}
        problems['empty-roster'] = {**good, 'tasks': []}
        problems['extra-roster-field'] = {
            **good, 'tasks': [{**good['tasks'][0], 'role': 'leader'}]}
        problems['extra-map'] = {**good, 'maps': good['maps'] + [dict(good['maps'][0])]}
        problems['missing-map'] = {**good, 'maps': good['maps'][:2]}
        duplicate = [dict(item) for item in good['maps']]
        duplicate[2]['id'] = duplicate[0]['id']
        problems['duplicate-map-id'] = {**good, 'maps': duplicate}
        shape = [dict(item) for item in good['maps']]
        shape[1]['bytes_value'] = 8
        problems['map-metadata'] = {**good, 'maps': shape}
        flags = [dict(item) for item in good['maps']]
        flags[0]['map_flags'] = 0
        problems['map-flags'] = {**good, 'maps': flags}
        boolean = [dict(item) for item in good['maps']]
        boolean[0]['max_entries'] = False
        problems['boolean-metadata'] = {**good, 'maps': boolean}
        order = {**good, 'maps': [good['maps'][1], good['maps'][0], good['maps'][2]]}
        problems['map-order'] = order
        problems['extra-field'] = {**good, 'origin': 'canary'}
        problems['missing-field'] = {key: value for key, value in good.items() if key != 'abi'}
        problems['zero-map-id'] = {
            **good, 'maps': [{**good['maps'][0], 'id': 0}, good['maps'][1], good['maps'][2]]}
        problems['not-an-object'] = [good]
        for label, document in problems.items():
            with self.subTest(problem=label):
                with self.assertRaises((coordinator.CaptureError, RuntimeError)):
                    qualifier.validate_ready(document, pid, generation)

    def test_ready_acquisition_refusals_injected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deadline = time.monotonic() + 5
            duplicate = root / 'duplicate.json'
            duplicate.write_text('{"schema":"a","schema":"b"}')
            oversized = root / 'oversized.json'
            oversized.write_bytes(b'{"pad":"' + b'A' * qualifier.READY_BOUND + b'"}')
            fifo = root / 'fifo.json'
            os.mkfifo(fifo)
            link = root / 'link.json'
            link.symlink_to(duplicate)
            for label, path, message in (('duplicate-keys', duplicate, 'duplicate JSON field'),
                                         ('oversized', oversized, 'byte bound exceeded'),
                                         ('non-regular', fifo, 'not a regular file')):
                with self.subTest(problem=label):
                    with self.assertRaises(coordinator.CaptureError) as raised:
                        coordinator.read_json(path, qualifier.READY_BOUND,
                                              deadline=time.monotonic() + 5)
                    self.assertIn(message, str(raised.exception))
            with self.subTest(problem='symlink'):
                with self.assertRaises(OSError) as failure:
                    coordinator.read_json(link, qualifier.READY_BOUND,
                                          deadline=time.monotonic() + 5)
                self.assertEqual(failure.exception.errno, errno.ELOOP)
                self.assertEqual(coordinator.sanitized('ready', failure.exception),
                                 ['ready: OSError'])
            good = root / 'ready.json'
            good.write_text(json.dumps(ready_document(11, 22)))
            self.assertEqual(
                coordinator.read_json(good, qualifier.READY_BOUND, deadline=deadline)['pid'], 11)

    # ---- injected frame refusals ------------------------------------------

    def test_frame_refusals_injected(self):
        pid, maps = 4242, ready_maps()
        values = qualifier.control_values('baseline')
        rows = seeded_rows('baseline', pid)
        surfaces, proof = qualifier.read_records(stream(rows), maps, pid, values)
        self.assertEqual([len(surfaces[name]) for name, _, _ in qualifier.MAP_LAYOUT],
                         [8, 544, 8])
        self.assertEqual(proof['records'], 3)
        problems = {
            'two-records': stream(rows[:2]),
            'four-records': stream(rows + [(IDS[0], pid, pid, values['TASK_COOKIE'])]),
            'foreign-pid': stream([(IDS[0], pid + 1, pid, values['TASK_COOKIE'])] + rows[1:]),
            'foreign-tid': stream(rows[:2] + [(IDS[2], pid, pid + 1,
                                               values['ROOT_AFFILIATION'])]),
            'unknown-map-id': stream([(9999, pid, pid, values['TASK_COOKIE'])] + rows[1:]),
            'short-value': stream(rows[:1] + [(IDS[1], pid, pid, values['THREAD_OWNER'][:-1])]
                                  + rows[2:]),
            'long-value': stream(rows[:1] + [(IDS[1], pid, pid,
                                              values['THREAD_OWNER'] + b'\x00')] + rows[2:]),
            'missing-terminal-eof': stream(rows, terminal=False),
            'bytes-after-eof': stream(rows) + frame(dumper.TASK_STORAGE_EOF, 0, 0, 0),
            'wrong-owner-bytes': stream(
                rows[:1] + [(IDS[1], pid, pid, qualifier.control_values('early')['THREAD_OWNER'])]
                + rows[2:]),
            'late-region-owner-bytes': stream(
                rows[:1] + [(IDS[1], pid, pid, qualifier.control_values('late')['THREAD_OWNER'])]
                + rows[2:]),
        }
        for label, data in problems.items():
            with self.subTest(problem=label):
                with self.assertRaises((coordinator.CaptureError, RuntimeError)):
                    qualifier.read_records(data, maps, pid, values)

    def test_owner_mismatch_only_past_offset_535_is_refused_injected(self):
        """No truncated-prefix compare: a late-region-only difference must refuse."""
        pid, maps = 606, ready_maps()
        expected = qualifier.control_values('baseline')
        substitute = qualifier.control_values('late')['THREAD_OWNER']
        differing = [index for index in range(qualifier.OWNER_SIZE)
                     if substitute[index] != expected['THREAD_OWNER'][index]]
        # Every differing byte is at or past the late offset, so a comparison
        # truncated to [0, 535) could not tell these two values apart.
        self.assertEqual(differing, list(range(qualifier.LATE_OFFSET, qualifier.OWNER_SIZE)))
        self.assertEqual(substitute[:qualifier.LATE_OFFSET],
                         expected['THREAD_OWNER'][:qualifier.LATE_OFFSET])
        self.assertEqual(len(substitute), len(expected['THREAD_OWNER']))
        rows = seeded_rows('baseline', pid)
        rows[1] = (IDS[1], pid, pid, substitute)
        with self.assertRaises(coordinator.CaptureError) as raised:
            qualifier.read_records(stream(rows), maps, pid, expected)
        self.assertIn('differs from the expected control bytes', str(raised.exception))

    def test_terminal_eof_proof_records_the_exact_stream_shape(self):
        pid, maps = 909, ready_maps()
        values = qualifier.control_values('late')
        data = stream(seeded_rows('late', pid))
        _, proof = qualifier.read_records(data, maps, pid, values)
        header = dumper.TASK_STORAGE_HEADER.size
        self.assertEqual(proof['stream_bytes'], len(data))
        self.assertEqual(proof['terminal_frame_offset'], len(data) - header)
        self.assertEqual(proof['records'], 3)
        self.assertEqual(proof['proved_by'], 'dump-owned-bpf-maps.parse_task_storage_frames')
        self.assertEqual(len(data), 560 + 4 * header)
        records = dumper.parse_task_storage_frames(data, maps, max_records=3, max_bytes=560)
        for label, mutated in (
                ('trailing-byte', data + b'\x00'),
                ('leading-frame', frame(dumper.TASK_STORAGE_EOF, 0, 0, 0) + data),
                ('short-stream', data[header:]),
                ('no-terminal-frame', data[:-header] + frame(dumper.TASK_STORAGE_RECORD, IDS[0],
                                                             pid, pid))):
            with self.subTest(problem=label):
                with self.assertRaises(coordinator.CaptureError):
                    qualifier.terminal_eof_proof(mutated, records)

    def test_retained_map_metadata_refusals_injected(self):
        maps = ready_maps()
        source = InjectedSeedMaps('baseline', {})
        good = {item['id']: source.info(item['id']) for item in maps}
        qualifier.validate_infos(good, maps)
        for label, change in (('id', {'id': 9999}), ('type', {'type': 1}),
                              ('key', {'bytes_key': 8}), ('value', {'bytes_value': 16}),
                              ('max-entries', {'max_entries': 1}), ('flags', {'map_flags': 0}),
                              ('name', {'name': 'TASK_COOKIEX'})):
            with self.subTest(problem=label):
                mutated = {key: dict(value) for key, value in good.items()}
                mutated[IDS[0]].update(change)
                with self.assertRaises(coordinator.CaptureError):
                    qualifier.validate_infos(mutated, maps)
        truncated = {key: dict(value) for key, value in good.items()}
        truncated[IDS[2]]['name'] = 'ROOT_AFFILIATION'
        with self.assertRaises(coordinator.CaptureError):
            qualifier.validate_infos(truncated, maps)

    # ---- real custody with an injected acquisition (childless probes) ------

    def test_complete_run_publishes_one_receipt_injected(self):
        self.probe('complete', {'ready': ready_template(), 'ids': list(IDS)})

    def test_absence_probe_runs_only_after_the_explicit_close_injected(self):
        self.probe('close_ordering', {'ready': ready_template(), 'ids': list(IDS),
                                      'cases': ['baseline']})

    def test_case_subset_publishes_no_receipt_injected(self):
        self.probe('subset', {'ready': ready_template(), 'ids': list(IDS),
                              'cases': ['baseline']})

    def test_fixture_exit_before_ready_fails_injected(self):
        self.probe('exit_before_ready', {'ready': ready_template(), 'ids': list(IDS),
                                         'exit_before_ready': True, 'status': 1})

    def test_generation_change_across_the_stopped_interval_fails_injected(self):
        # One case, and the first proc read left alone, so the post-stop recheck
        # is the only generation comparison the bump can reach.
        self.probe('generation_change',
                   {'ready': ready_template(), 'ids': list(IDS), 'cases': ['baseline'],
                    'bump_after': 1,
                    'issue': 'fixture generation changed across the stopped interval'})

    def test_generation_change_before_ready_fails_injected(self):
        # The first proc read is already bumped, so the pre-READY comparison
        # against custody's own recorded generation is the invariant under test.
        self.probe('generation_change_before_ready',
                   {'ready': ready_template(), 'ids': list(IDS), 'cases': ['baseline'],
                    'bump_after': 0,
                    'issue': 'fixture generation changed before READY'})

    def test_extra_live_map_id_beyond_the_three_ready_maps_fails_injected(self):
        # The injected inventory reports a fourth id the READY document does not
        # name, so the inventory equality - not a later check - must refuse.
        self.probe('extra_map_id',
                   {'ready': ready_template(), 'ids': list(IDS) + [IDS[-1] + 1],
                    'cases': ['baseline'],
                    'issue': 'fixture map inventory is not exactly the three READY maps'})

    def test_adopted_extra_child_is_nonpassing_injected(self):
        self.probe('extra_child', {'ready': ready_template(), 'ids': list(IDS), 'child': 8})

    def test_nonzero_fixture_exit_after_release_fails_injected(self):
        self.probe('bad_exit', {'ready': ready_template(), 'ids': list(IDS), 'status': 3})

    def test_resolvable_map_id_after_close_fails_cleanup_injected(self):
        self.probe('map_resolvable', {'ready': ready_template(), 'ids': list(IDS),
                                      'absence': 'resolvable'})

    def test_unresolved_absence_probe_is_not_a_cleanup_pass_injected(self):
        self.probe('absence_unresolved', {'ready': ready_template(), 'ids': list(IDS),
                                          'absence': 'unresolved'})


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--probe':
        probe_case(sys.argv[3], sys.argv[2])
    else:
        unittest.main()
