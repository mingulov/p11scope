# SPDX-License-Identifier: GPL-3.0-or-later
"""E16 qualification runner: reducers, lifecycle and the eight H1 regressions.

Run as a script, never through pytest collection:

    python3 -I tests/python/test_e16_oracle.py -v

Everything here is unprivileged. Lifecycle tests run the real E16 fixture
drivers (gcc and readelf required) under a fake observer script; mapping
receipts go through the shared receipt helper against a mirrored /proc
subset, because opening /proc/<pid>/map_files needs privilege. These tests
prove the runner's decisions, never a live BPF result.
"""

import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import _loader  # noqa: E402

E16 = _loader.load_path(ROOT / "scripts" / "qualify-e16-surfaces.py", "qualify_e16_surfaces")
HELPER = E16.helpers()
Unknown = E16.Unknown
OWNED = {"dev": [0, 35], "ino": 4242, "sha256": "a" * 64}
FOREIGN = {"dev": [0, 35], "ino": 4243, "sha256": "a" * 64}
OFFSET = 0x1130
KERNEL_CONTROL = {"capture_halted": False, "owner_poison": [], "owner_admission_failures": 0,
                  "identity_unavailable": 0, "identity_budget_exhausted": False,
                  "root_affiliation_failures": []}
FAKE_RUSTC = b"rustc version 1.98.1 (0123456789 2026-09-01)"
FAKE_BPF = b"\x7fELF-fake-bpf-object-" + bytes(range(256)) * 4


def capture(rows, *, completeness="PARTIAL", skipped=(), modules=None):
    if modules is None:
        modules = []
        for row in rows:
            if row["module"] is not None and row["module"] not in modules:
                modules.append(row["module"])
    return {"schema": E16.PROFILE_SCHEMA, "functions": rows,
            "capture": {"modules": [dict(module, path="/x", build_id=None) for module in modules]},
            "evidence": {"completeness": completeness, "skipped": list(skipped),
                         "kernel_control": dict(KERNEL_CONTROL)}}


def row(identity, offset, calls, *, in_flight=0, ordinal=0, module="same", names=("unknown",)):
    owner = identity if module == "same" else module if isinstance(module, dict) else None
    ambiguous = module == "ambiguous"
    return {"names": list(names), "aliased": len(names) > 1, "calls": calls,
            "in_flight": in_flight, "target": {"object": identity, "file_offset": offset},
            "ordinals": [] if ordinal is None else [{"table_file_offset": 0, "ordinal": ordinal}],
            "module": owner, "module_ambiguous": ambiguous,
            "module_unresolved": owner is None and not ambiguous}


def judge(document, *, expect="supported", name="control", refusal=None, calls=4,
          mode="pid-hinted", owned=OWNED, offset=OFFSET):
    observation = E16.observe(document, owned, offset)
    return E16.judge_cell(name, expect, mode, ledger={"entered": calls, "returned": calls},
                          observation=observation, document=document, refusal=refusal,
                          calls=calls)


def proc_stat(pid, starttime):
    return f"{pid} (owned worker) S " + " ".join(["0"] * 18 + [str(starttime)]) + "\n"


def fd_mount_id(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
            if line.startswith("mnt_id:\t"):
                return int(line.removeprefix("mnt_id:\t"))
    finally:
        os.close(fd)
    raise AssertionError("no fd mount identity")


def synthetic_proc(root, mapped, *, label, pid=4321, starttime=777, mapping_dev=None):
    """One process whose single r-xp mapping is ``mapped``, rendered as ``label``."""
    process = root / str(pid)
    (process / "map_files").mkdir(parents=True)
    (process / "ns").mkdir()
    (process / "ns" / "mnt").write_text("synthetic\n")
    (process / "stat").write_text(proc_stat(pid, starttime))
    info = mapped.stat()
    dev = mapping_dev or f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}"
    (process / "maps").write_text(f"7f000000-7f001000 r-xp 00000000 {dev} {info.st_ino} {label}\n")
    (process / "map_files" / "7f000000-7f001000").symlink_to(mapped)
    major, minor = (int(part, 16) for part in dev.split(":"))
    (process / "mountinfo").write_text(
        f"{fd_mount_id(mapped)} 1 {major}:{minor} / /synthetic rw - synthetic synthetic rw\n")
    return {"pid": pid, "starttime": starttime, "endpoint": 0x7F000123, "image": 0x7F000200,
            "calls": 1}


def receipt_for(base, mapped, expected, *, label=None, mapping_dev=None):
    proc = base / "proc"
    ready = synthetic_proc(proc, mapped, label=label or str(expected), mapping_dev=mapping_dev)
    handshake = base / "handshake"
    handshake.write_text(E16.handshake_text(ready, ready["endpoint"]))
    return E16.file_mapping_receipt(HELPER.receipt, proc, ready, ready["endpoint"], expected,
                                    handshake)


class H1PhysicalEndpointSelection(unittest.TestCase):
    """H1: count the exact executed object/offset/ordinal; never require names."""

    def test_unknown_named_physical_endpoint_with_exact_calls_passes(self):
        self.assertEqual(judge(capture([row(OWNED, OFFSET, 4)])), [])

    def test_names_are_recorded_never_required(self):
        observation = E16.observe(capture([row(OWNED, OFFSET, 4)]), OWNED, OFFSET)
        self.assertEqual(observation["endpoint_names"], ["unknown"])

    def test_foreign_byte_identical_object_never_satisfies_the_cell(self):
        reasons = judge(capture([row(FOREIGN, OFFSET, 4)]))
        self.assertTrue(any("0 report rows" in reason for reason in reasons), reasons)

    def test_ambiguous_or_unresolved_owner_does_not_satisfy_the_cell(self):
        for module in ("ambiguous", None):
            with self.subTest(module=module):
                reasons = judge(capture([row(OWNED, OFFSET, 4, module=module)], modules=[OWNED]))
                self.assertTrue(any("solely owned" in reason for reason in reasons), reasons)

    def test_other_offset_or_ordinal_is_not_the_executed_endpoint(self):
        self.assertTrue(judge(capture([row(OWNED, OFFSET + 16, 4)])))
        reasons = judge(capture([row(OWNED, OFFSET, 4, ordinal=3)]))
        self.assertTrue(any("ordinal" in reason for reason in reasons), reasons)

    def test_entered_and_returned_must_both_match_the_ledger(self):
        for calls, in_flight in ((3, 0), (5, 0), (3, 1), (4, 1)):
            with self.subTest(calls=calls, in_flight=in_flight):
                reasons = judge(capture([row(OWNED, OFFSET, calls, in_flight=in_flight)]))
                self.assertTrue(any("owned count mismatch" in reason for reason in reasons))


class H2ReceiptBeforeGo(unittest.TestCase):
    """H2: identity comes from the live pin before GO, never a later pathname."""

    def test_same_path_equal_byte_replacement_inode_is_refused_at_pin(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            mapped = base / "mapped.so"
            mapped.write_bytes(b"provider-bytes")
            replacement = base / "provider.so"
            replacement.write_bytes(b"provider-bytes")
            with self.assertRaisesRegex(Unknown, "expected copy identity"):
                receipt_for(base, mapped, replacement)

    def test_path_replaced_after_the_pin_no_longer_names_the_mapped_object(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            provider = base / "provider.so"
            provider.write_bytes(b"provider-bytes")
            receipt = receipt_for(base, provider, provider)
            E16.path_still_names_pin(HELPER.receipt, provider, receipt)
            staged = base / "staged.so"
            staged.write_bytes(b"provider-bytes")
            os.replace(staged, provider)
            with self.assertRaisesRegex(Unknown, "no longer names the mapped object"):
                E16.path_still_names_pin(HELPER.receipt, provider, receipt)

    def test_report_identity_is_the_mapping_domain_joined_by_the_bridge(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            provider = base / "provider.so"
            provider.write_bytes(b"provider-bytes")
            # btrfs-style: maps renders a device that fstat does not report.
            receipt = receipt_for(base, provider, provider, mapping_dev="0:7ff")
            owned = E16.owned_identity(HELPER, receipt)
            info = provider.stat()
            self.assertEqual(owned["dev"], [0, 0x7FF])
            self.assertEqual(owned["ino"], info.st_ino)
            stat_domain = dict(owned, dev=[os.major(info.st_dev), os.minor(info.st_dev)])
            reasons = judge(capture([row(stat_domain, 0x123, 4)]), owned=owned, offset=0x123)
            self.assertTrue(any("0 report rows" in reason for reason in reasons), reasons)
            self.assertEqual(judge(capture([row(owned, 0x123, 4)]), owned=owned, offset=0x123),
                             [])

    def test_forged_bridge_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            provider = base / "provider.so"
            provider.write_bytes(b"provider-bytes")
            receipt = receipt_for(base, provider, provider)
            receipt["mapping_bridge"]["range"] = "0-1"
            with self.assertRaisesRegex(Unknown, "bridge"):
                E16.owned_identity(HELPER, receipt)


def fake_observer_binary(base, *, bpf=FAKE_BPF, rustc=FAKE_RUSTC):
    binary = base / "observer"
    binary.write_bytes(b"\x7fELF" + b"\0" * 64 + rustc + b"\0" + bpf + b"\0" * 64)
    objects = base / "objects"
    objects.mkdir(exist_ok=True)
    obj = objects / "p11scope-ebpf"
    obj.write_bytes(FAKE_BPF)
    return binary, obj


def clean_git(arguments, root):
    return "0123456789abcdef0123456789abcdef01234567\n" if arguments[0] == "rev-parse" else ""


class H3ObserverProvenance(unittest.TestCase):
    """H3: freeze and bind the observer, its BPF objects and its source first."""

    def manifest(self, base, **kwargs):
        binary, obj = fake_observer_binary(base, **kwargs)
        return binary, E16.make_provenance(binary, [obj], git=clean_git)

    def test_bound_observer_validates(self):
        with tempfile.TemporaryDirectory() as raw:
            binary, manifest = self.manifest(Path(raw))
            result = E16.validate_provenance(manifest, binary.read_bytes(), check_sources=False)
            self.assertEqual(result["revision"], "0123456789abcdef0123456789abcdef01234567")

    def test_unrelated_or_changed_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            binary, manifest = self.manifest(Path(raw))
            changed = bytearray(binary.read_bytes())
            changed[2] ^= 1
            for data in (b"unrelated", bytes(changed)):
                with self.subTest(size=len(data)), self.assertRaisesRegex(Unknown, "observer bytes"):
                    E16.validate_provenance(manifest, data, check_sources=False)

    def test_dirty_or_unbound_source_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            binary, obj = fake_observer_binary(base)

            def dirty(arguments, root):
                return " M src/run.rs\n" if arguments[0] == "status" else clean_git(arguments, root)

            with self.assertRaisesRegex(Unknown, "dirty"):
                E16.make_provenance(binary, [obj], git=dirty)
            _, manifest = self.manifest(base)
            for mutate, message in (
                (lambda m: m["source"].update(tree_clean=False), "dirty"),
                (lambda m: m["source"].pop("revision"), "source revision"),
                (lambda m: m["source"]["files"].popitem(), "every runner"),
            ):
                broken = copy.deepcopy(manifest)
                mutate(broken)
                with self.subTest(message=message), self.assertRaisesRegex(Unknown, message):
                    E16.validate_provenance(broken, binary.read_bytes(), check_sources=False)

    def test_changed_runner_or_fixture_source_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            binary, manifest = self.manifest(base)
            tree = base / "tree"
            for rel in E16.BOUND_SOURCES:
                (tree / rel).parent.mkdir(parents=True, exist_ok=True)
                (tree / rel).write_bytes((ROOT / rel).read_bytes())
            E16.validate_provenance(manifest, binary.read_bytes(), root=tree)
            with (tree / "tests/fixtures/e16/e16_driver.c").open("a") as stream:
                stream.write("/* edited */\n")
            with self.assertRaisesRegex(Unknown, "changed since the provenance"):
                E16.validate_provenance(manifest, binary.read_bytes(), root=tree)

    def test_mismatched_or_missing_bpf_artifact_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            binary, manifest = self.manifest(base)
            other = base / "p11scope-ebpf"
            other.write_bytes(b"not-the-embedded-object")
            with self.assertRaisesRegex(Unknown, "not embedded"):
                E16.make_provenance(binary, [other], git=clean_git)
            for mutate, message in (
                (lambda m: m["bpf_objects"][0].update(sha256="b" * 64), "not embedded"),
                (lambda m: m["bpf_objects"][0].update(observer_offset=1), "not embedded"),
                (lambda m: m["bpf_objects"][0].update(name="other"), "p11scope-ebpf"),
                (lambda m: m.update(bpf_objects=[]), "no BPF object"),
                (lambda m: m.update(release_rust_version="1.99.0"), "release compiler"),
            ):
                broken = copy.deepcopy(manifest)
                mutate(broken)
                with self.subTest(message=message), self.assertRaisesRegex(Unknown, message):
                    E16.validate_provenance(broken, binary.read_bytes(), check_sources=False)


class H4BoundedReads(unittest.TestCase):
    """H4: silence, partial lines, EOF and oversize end as UNKNOWN on time."""

    def reader(self, **bounds):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        return E16.FramedReader(read_fd, **bounds), write_fd

    def test_silent_held_pipe_times_out_within_the_deadline(self):
        reader, write_fd = self.reader()
        self.addCleanup(os.close, write_fd)
        started = time.monotonic()
        with self.assertRaisesRegex(Unknown, "deadline"):
            reader.read_line(time.monotonic() + 0.2)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_partial_line_then_eof_is_unknown_and_retained(self):
        reader, write_fd = self.reader()
        os.write(write_fd, b"P11SCOPE_E16 ready pid=1")
        os.close(write_fd)
        with self.assertRaisesRegex(Unknown, "partial line"):
            reader.read_line(time.monotonic() + 5)
        self.assertEqual(bytes(reader.transcript), b"P11SCOPE_E16 ready pid=1")

    def test_early_eof_is_unknown(self):
        reader, write_fd = self.reader()
        os.write(write_fd, b"one\n")
        os.close(write_fd)
        self.assertEqual(reader.read_line(time.monotonic() + 5), "one")
        with self.assertRaisesRegex(Unknown, "EOF before"):
            reader.read_line(time.monotonic() + 5)

    def test_oversize_line_and_transcript_are_unknown(self):
        reader, write_fd = self.reader(max_line=64)
        self.addCleanup(os.close, write_fd)
        os.write(write_fd, b"x" * 100)
        with self.assertRaisesRegex(Unknown, "line exceeds"):
            reader.read_line(time.monotonic() + 5)
        reader, write_fd = self.reader(max_bytes=32)
        self.addCleanup(os.close, write_fd)
        os.write(write_fd, b"y\n" * 40)
        with self.assertRaisesRegex(Unknown, "transcript exceeds"):
            for _ in range(41):
                reader.read_line(time.monotonic() + 5)

    def test_ledger_rejects_partial_reordered_failed_and_short_transcripts(self):
        ready = b"P11SCOPE_E16 ready pid=7 starttime=9 endpoint=0x10 image=0x20 calls=2\n"
        good = (ready + b"P11SCOPE_E16 provider static E16_C_Initialize\n"
                b"P11SCOPE_E16 call table[0] 0 rv=0\nP11SCOPE_E16 call table[0] 1 rv=0\n"
                b"P11SCOPE_E16 done calls=2\n")
        self.assertEqual(E16.parse_ledger(good, label="table[0]", calls=2)["returned"], 2)
        for transcript in (good[:-1], good.replace(b"] 1 rv", b"] 0 rv"),
                           good.replace(b"1 rv=0", b"1 rv=5"), good.replace(b"calls=2\n", b"calls=1\n", 1),
                           ready + b"P11SCOPE_E16 done calls=2\n", b""):
            with self.subTest(transcript=transcript), self.assertRaises(Unknown):
                E16.parse_ledger(transcript, label="table[0]", calls=2)


class H6ReduceRawEvidence(unittest.TestCase):
    """H6: counts and refusals come from attributable rows, else UNKNOWN."""

    REFUSAL = [{"name": "discovery subject", "reason": E16.TABLE_UNAVAILABLE}]

    def diagnostics(self, *subjects, aggregated=False):
        count = " ×2" if aggregated else ""
        return "\n".join(
            f"p11scope: discovery: other{count}: discovery skipped {subject} — matched a "
            f"--module hint; {E16.NO_TABLE_DIAGNOSTIC}; a table built at run time" for subject in subjects)

    def test_owned_no_table_refusal_binds_only_its_own_label(self):
        owned = E16.no_table_diagnostic_subjects(self.diagnostics("/e16/build/direct.so"))
        self.assertEqual(owned, [{"subject": "/e16/build/direct.so", "aggregated": False}])
        foreign = E16.no_table_diagnostic_subjects(self.diagnostics("/elsewhere/FOREIGN.so"))
        self.assertNotEqual(foreign[0]["subject"], "/e16/build/direct.so")
        self.assertTrue(E16.no_table_diagnostic_subjects(
            self.diagnostics("/e16/build/direct.so", aggregated=True))[0]["aggregated"])

    def test_foreign_only_skip_or_missing_public_record_is_unknown(self):
        document = capture([], skipped=self.REFUSAL)
        self.assertEqual(judge(document, expect="explicit-unsupported",
                               refusal={"public": True, "bound": True}), [])
        for refusal in ({"public": True, "bound": False}, {"public": False, "bound": True}, None):
            with self.subTest(refusal=refusal):
                self.assertTrue(judge(document, expect="explicit-unsupported", refusal=refusal))

    def test_foreign_positive_counts_never_fill_a_missing_owned_endpoint(self):
        reasons = judge(capture([row(FOREIGN, OFFSET, 4)]))
        self.assertTrue(reasons)
        observation = E16.observe(capture([row(FOREIGN, OFFSET, 4)]), OWNED, OFFSET)
        self.assertEqual(observation["foreign"]["returned"], 4)
        self.assertEqual(observation["endpoint"]["returned"], 0)

    def test_missing_owned_output_is_unknown_not_zero(self):
        reasons = E16.judge_cell("control", "supported", "pid-hinted",
                                 ledger={"entered": 4, "returned": 4}, observation=None,
                                 document=None, refusal=None, calls=4)
        self.assertIn("no attributable capture outcome", reasons)
        with self.assertRaisesRegex(Unknown, "no capture"):
            E16.load_capture(HELPER, b"")

    def test_unexpected_owned_rows_are_unknown(self):
        reasons = judge(capture([row(OWNED, OFFSET, 4), row(OWNED, OFFSET + 8, 1, ordinal=1)]))
        self.assertTrue(any("unexpected owned rows" in reason for reason in reasons), reasons)
        reasons = judge(capture([row(OWNED, OFFSET, 0)], skipped=self.REFUSAL),
                        expect="explicit-unsupported", refusal={"public": True, "bound": True})
        self.assertTrue(any("owned report rows" in reason for reason in reasons), reasons)

    def test_wrong_device_domain_or_colliding_bytes_is_unknown(self):
        other_domain = dict(OWNED, dev=[8, 3])
        self.assertTrue(judge(capture([row(other_domain, OFFSET, 4)])))
        colliding = dict(OWNED, sha256="c" * 64)
        reasons = judge(capture([row(colliding, OFFSET, 4)]))
        self.assertTrue(any("collides" in reason for reason in reasons), reasons)

    def test_unsupported_surface_must_not_be_called_complete(self):
        document = capture([], completeness="COMPLETE", skipped=self.REFUSAL)
        reasons = judge(document, expect="explicit-unsupported",
                        refusal={"public": True, "bound": True})
        self.assertTrue(any("COMPLETE" in reason for reason in reasons), reasons)

    def test_jit_cell_refuses_any_counted_row_in_its_process(self):
        reasons = judge(capture([row(FOREIGN, OFFSET, 2)]), expect="bounded-unsupported",
                        name="anonymous-jit", refusal={"boundary": E16.JIT_BOUNDARY})
        self.assertTrue(any("anonymous code" in reason for reason in reasons), reasons)
        self.assertEqual(judge(capture([]), expect="bounded-unsupported", name="anonymous-jit",
                               refusal={"boundary": E16.JIT_BOUNDARY}), [])

    def test_malformed_capture_rows_fail_the_release_oracle_contract(self):
        document = capture([row(OWNED, OFFSET, 4)])
        document["functions"][0]["module_unresolved"] = True
        with self.assertRaisesRegex(Unknown, "row contract"):
            E16.load_capture(HELPER, json.dumps(document).encode())


class H7SeparateOutcomes(unittest.TestCase):
    """H7: each exit, signal, timeout and cleanup keeps its own verdict."""

    def outcome(self, returncode, **extra):
        return {"launched": True, **E16.outcome_of(returncode), "timed_out": False,
                "cleanup": {"attempted": False, "error": None}, **extra}

    def test_signal_beside_a_clean_exit_is_not_collapsed(self):
        outcomes = [self.outcome(0), self.outcome(-15)]
        failures = [failure for index, outcome in enumerate(outcomes)
                    for failure in E16.process_failures(f"observer {index}", outcome)]
        self.assertEqual(failures, ["observer 1 ended by signal 15"])

    def test_nonzero_timeout_and_cleanup_failures_each_fail(self):
        for outcome, fragment in (
            (self.outcome(6), "exit code 6"),
            (self.outcome(0, timed_out=True), "timed out"),
            (self.outcome(0, cleanup={"attempted": False, "error": "EPERM"}), "cleanup failed"),
            (self.outcome(0, cleanup={"attempted": True, "error": None}), "forced cleanup"),
            (self.outcome(None, launched=False), "never launched"),
        ):
            with self.subTest(fragment=fragment):
                self.assertTrue(any(fragment in failure
                                    for failure in E16.process_failures("driver", outcome)))
        self.assertEqual(E16.process_failures("driver", self.outcome(0)), [])


class H8PrivateEvidenceRoot(unittest.TestCase):
    """H8: validate every ancestor before the one exclusive mkdir."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(self._cleanup)
        try:
            probe = E16.create_private_root(str(self.base / "probe"))
            probe.close()
        except Unknown as error:
            self.skipTest(f"the temporary directory's own ancestry is untrusted here: {error}")

    def _cleanup(self):
        for path in sorted(self.base.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                path.chmod(0o700)
                path.rmdir()
        self.base.rmdir()

    def test_new_directory_is_created_owner_only(self):
        private = E16.create_private_root(str(self.base / "evidence"))
        private.close()
        info = (self.base / "evidence").stat()
        self.assertEqual(info.st_mode & 0o7777, 0o700)
        self.assertEqual(info.st_uid, os.geteuid())

    def test_existing_directory_is_refused_without_permission_change(self):
        existing = self.base / "existing"
        existing.mkdir(mode=0o755)
        (existing / "keep").write_text("content")
        with self.assertRaisesRegex(Unknown, "already exists"):
            E16.create_private_root(str(existing))
        self.assertEqual(existing.stat().st_mode & 0o7777, 0o755)
        self.assertEqual((existing / "keep").read_text(), "content")

    def test_symlink_ancestor_is_refused_before_any_creation(self):
        real = self.base / "real"
        real.mkdir(mode=0o700)
        (self.base / "link").symlink_to(real)
        with self.assertRaisesRegex(Unknown, "not a plain directory"):
            E16.create_private_root(str(self.base / "link" / "evidence"))
        self.assertEqual(list(real.iterdir()), [])

    def test_group_or_world_writable_ancestor_is_refused(self):
        for mode in (0o777, 0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                shared = self.base / f"shared-{mode:o}"
                shared.mkdir()
                shared.chmod(mode)
                with self.assertRaisesRegex(Unknown, "writable by group or others"):
                    E16.create_private_root(str(shared / "evidence"))
                self.assertEqual(list(shared.iterdir()), [])
                self.assertEqual(shared.stat().st_mode & 0o7777, mode)

    def test_sticky_world_writable_ancestor_is_trusted(self):
        sticky = self.base / "sticky"
        sticky.mkdir()
        sticky.chmod(0o1777)
        E16.create_private_root(str(sticky / "evidence")).close()

    def test_foreign_owned_ancestor_is_refused(self):
        foreign_euid = os.geteuid() + 1 if os.geteuid() else 65534
        target = self.base / "evidence"
        with self.assertRaisesRegex(Unknown, "untrusted uid"):
            E16.create_private_root(str(target), euid=foreign_euid, environ={})
        self.assertFalse(target.exists())

    def test_relative_or_dotted_paths_are_refused(self):
        for path in ("relative/evidence", str(self.base) + "/../evidence", str(self.base) + "/./e"):
            with self.subTest(path=path), self.assertRaises(Unknown):
                E16.create_private_root(path)

    def test_sudo_uid_is_trusted_only_for_root_and_real_accounts(self):
        uid = os.getuid()
        self.assertEqual(E16.sudo_uid({"SUDO_UID": str(uid)}, 0), uid if uid else None)
        self.assertIsNone(E16.sudo_uid({"SUDO_UID": str(uid)}, 1000))
        for value in ("", "0", "abc", "-1", str(2**32 - 1), "٣"):
            with self.subTest(value=value):
                self.assertIsNone(E16.sudo_uid({"SUDO_UID": value}, 0))


FAKE_OBSERVER = r'''
import hashlib, json, os, signal, sys, time
mode, capture, spec_path, duration = sys.argv[1:5]
spec = json.load(open(spec_path))
err = sys.stderr
err.write("p11scope: discovery: 1 module(s), 2 attach slot(s), scan 1ms, conflicts 0, uncorroborated 0\n")
if mode == "silent":
    err.flush(); time.sleep(600); sys.exit(0)
for member in spec:
    if member["expect"] == "explicit-unsupported" and member["hinted"]:
        subject = member["hint"] + (".FOREIGN.so" if mode == "foreign-diagnostic" else "")
        err.write("p11scope: discovery: other: discovery skipped " + subject + " — matched a "
                  "--module hint; no function table was found in its file-backed data; a table "
                  "built at run time is outside the memory scan's reach\n")
err.write("p11scope: capturing: 2 probe(s) attached; stop with Ctrl-C\n")
err.flush()
if mode == "exit-after-ready":
    sys.exit(0)
if mode == "hang":
    time.sleep(600)
time.sleep(float(duration))
rows, modules, skipped = [], [], []
for member in spec:
    if member["expect"] in ("supported", "foreign"):
        endpoint = member["endpoint"]
        for line in open(f"/proc/{member['pid']}/maps"):
            fields = line.split(None, 5)
            start, end = (int(part, 16) for part in fields[0].split("-"))
            if start <= endpoint < end and "x" in fields[1]:
                major, minor = (int(part, 16) for part in fields[3].split(":"))
                identity = {"dev": [major, minor], "ino": int(fields[4]),
                            "sha256": hashlib.sha256(open(member["hint"], "rb").read()).hexdigest()}
                offset = endpoint - start + int(fields[2], 16)
        calls = member["calls"]
        if mode == "swap-foreign" and member["name"] == "control":
            calls += spec[-1]["calls"]
        rows.append({"names": ["unknown"], "aliased": False, "calls": calls, "in_flight": 0,
                     "target": {"object": identity, "file_offset": offset},
                     "ordinals": [{"table_file_offset": 0, "ordinal": 0}], "module": identity,
                     "module_ambiguous": False, "module_unresolved": False})
        modules.append(dict(identity, path=member["hint"], build_id=None))
    elif member["expect"] == "explicit-unsupported" and member["hinted"]:
        skipped.append({"name": "discovery subject",
                        "reason": "function table unavailable in file-backed data"})
document = {"schema": "p11scope/observed-profile/v3", "functions": rows,
            "capture": {"modules": modules},
            "evidence": {"completeness": "PARTIAL", "skipped": skipped,
                         "kernel_control": {"capture_halted": False, "owner_poison": [],
                                            "owner_admission_failures": 0,
                                            "identity_unavailable": 0,
                                            "identity_budget_exhausted": False,
                                            "root_affiliation_failures": []}}}
with open(capture + ".tmp", "w") as stream:
    json.dump(document, stream)
os.rename(capture + ".tmp", capture)
if mode == "sigterm":
    os.kill(os.getpid(), signal.SIGTERM)
'''


class LifecycleBase(unittest.TestCase):
    """Real fixture drivers and the real orchestration, with a fake observer."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix="e16-oracle-"))
        cls.build = cls.base / "build"
        cls.build.mkdir()
        cls.fixtures = E16.build_fixtures(cls.build)
        cls.fake = cls.base / "fake_observer.py"
        cls.fake.write_text(FAKE_OBSERVER)
        binary, obj = fake_observer_binary(cls.base)
        cls.observer_bytes = binary.read_bytes()
        cls.manifest = E16.make_provenance(binary, [obj], git=clean_git)
        cls.counter = 0
        cls.original_receipt = E16.file_mapping_receipt

        def mirrored_receipt(receipt_mod, proc_root, ready, address, expected_file, handshake):
            cls.counter += 1
            mirror = cls.base / f"proc-{cls.counter}"
            E16.mirror_proc(ready["pid"], mirror)
            return cls.original_receipt(receipt_mod, mirror, ready, address, expected_file,
                                        handshake)

        E16.file_mapping_receipt = mirrored_receipt
        # Class cleanups run even when a subclass's setUpClass fails, so the
        # patch can never leak into the receipt tests of another class.
        cls.addClassCleanup(setattr, E16, "file_mapping_receipt", cls.original_receipt)
        cls.addClassCleanup(subprocess.run, ["rm", "-rf", "--", str(cls.base)], check=False)

    def argv_for(self, mode, duration):
        def build(campaign, participants, capture):
            hinted = not E16.CAMPAIGNS[campaign]["foreign"]
            spec = [{"name": p.name, "expect": p.spec["expect"], "pid": p.process.pid,
                     "endpoint": p.ready["endpoint"], "calls": p.ready["calls"],
                     "hint": str(self.build / p.spec["hint"]), "hinted": hinted}
                    for p in participants]
            spec_path = capture.with_name("fake-spec.json")
            spec_path.write_text(json.dumps(spec))
            return [sys.executable, "-I", str(self.fake), mode, str(capture), str(spec_path),
                    str(duration)]
        return build

    def campaign(self, campaign="hinted", mode="exact", *, duration=0.3, grace=20.0,
                 ready_timeout=20.0):
        root = Path(tempfile.mkdtemp(dir=self.base)) / "evidence"
        private = E16.create_private_root(str(root))
        try:
            frozen = E16.freeze_observer(private, self.observer_bytes)
            record, files = E16.execute_campaign(
                HELPER, private, campaign, build=self.build, fixture_records=self.fixtures,
                observer_argv_for=self.argv_for(mode, duration), calls=3, foreign_calls=5,
                duration=duration, ready_timeout=ready_timeout, observer_grace=grace,
                manifest=self.manifest, frozen=frozen)
        finally:
            private.close()
        return root, record, files

    def verify(self, record, files):
        return E16.verify_record(HELPER, record, files, frozen_observer_bytes=self.observer_bytes,
                                 manifest=self.manifest)


class H5LifecycleOrder(LifecycleBase):
    """H5: GO only to a live observer; release only after it finished."""

    def test_ready_marker_from_an_exited_observer_withholds_go(self):
        process = subprocess.Popen([sys.executable, "-c", "pass"])
        pidfd = os.pidfd_open(process.pid)
        self.addCleanup(os.close, pidfd)
        process.wait()
        marker = "p11scope: capturing: 2 probe(s) attached; stop with Ctrl-C\n"
        with self.assertRaisesRegex(Unknown, "already exited; GO withheld"):
            E16.ready_and_live(lambda: marker, pidfd)

    def test_exact_campaign_orders_completion_before_release(self):
        _, record, files = self.campaign()
        self.assertEqual(self.verify(record, files)["status"], "PASS")
        for run in record["runs"]:
            stamps = run["timeline"]
            self.assertLess(stamps["go_sent"], stamps["ledgers_closed"])
            self.assertLess(stamps["observer_exited"], stamps["release_sent"])
            self.assertLess(stamps["release_sent"], stamps["drivers_exited"])
        cells = {cell["name"]: cell for cell in record["cells"]}
        self.assertEqual(cells["control"]["observation"]["endpoint"]["returned"], 3)
        self.assertEqual(cells["direct-no-table"]["refusal"]["bound"], True)
        self.assertEqual(cells["anonymous-jit"]["refusal"]["boundary"], E16.JIT_BOUNDARY)

    def test_observer_exit_after_ready_is_unknown_and_cleaned_up(self):
        _, record, files = self.campaign(mode="exit-after-ready")
        with self.assertRaises(Unknown):
            self.verify(record, files)
        # Whether GO raced the exit or not, the run never verifies, every
        # owned process is reaped with its own outcome and evidence is kept.
        for run in record["runs"]:
            for participant in run["participants"]:
                self.assertTrue(participant["exit_code"] is not None
                                or participant["signal"] is not None, participant)
            self.assertIn(f"{run['id']}/{run['participants'][0]['name']}/driver.stderr", files)

    def test_hung_observer_times_out_with_bounded_cleanup_and_kept_evidence(self):
        _, record, files = self.campaign(mode="hang", grace=0.5)
        with self.assertRaisesRegex(Unknown, "timed out"):
            self.verify(record, files)
        run = record["runs"][0]
        self.assertTrue(run["observer"]["timed_out"])
        self.assertTrue(run["observer"]["cleanup"]["attempted"])
        self.assertIsNotNone(run["observer"]["signal"])
        self.assertTrue(files[f"{run['id']}/{run['participants'][0]['name']}/driver.stderr"])

    def test_silent_observer_never_gets_go(self):
        _, record, files = self.campaign(mode="silent", ready_timeout=1.0)
        with self.assertRaises(Unknown):
            self.verify(record, files)
        self.assertTrue(all("go_sent" not in run["timeline"] for run in record["runs"]))


class H7EndToEnd(LifecycleBase):
    def test_observer_killed_by_signal_after_a_valid_capture_is_not_verified(self):
        _, record, files = self.campaign(mode="sigterm")
        self.assertTrue(all(cell["verdict"] == "PASS" for cell in record["cells"]))
        with self.assertRaisesRegex(Unknown, "ended by signal 15"):
            self.verify(record, files)


class CampaignManifest(LifecycleBase):
    """The record is judged against the fixed campaign, not its own claims."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        runner = cls("test_exact_record_verifies_and_reverifies_from_disk")
        cls.root, cls.record, cls.files = runner.campaign("hinted")

    def assert_refused(self, record=None, files=None, fragment=""):
        with self.assertRaisesRegex(Unknown, fragment):
            self.verify(record or self.record, files or self.files)

    def test_exact_record_verifies_and_reverifies_from_disk(self):
        self.assertEqual(self.verify(self.record, self.files)["status"], "PASS")
        on_disk = json.loads((self.root / "e16-record.json").read_text())
        files = E16.collect_files(self.root, on_disk["runs"])
        self.assertEqual(self.verify(on_disk, files)["status"], "PASS")

    def test_omitted_duplicate_or_relabeled_cells_are_refused(self):
        mutations = (
            lambda r: r["cells"].pop(),
            lambda r: r["cells"].append(copy.deepcopy(r["cells"][0])),
            lambda r: r["cells"][4].update(expect="supported"),
            lambda r: r["cells"][0].update(name="vendor"),
            lambda r: r["runs"].pop(),
            lambda r: r.update(campaign="system-mixed"),
        )
        for index, mutate in enumerate(mutations):
            record = copy.deepcopy(self.record)
            mutate(record)
            with self.subTest(index=index):
                self.assert_refused(record, fragment="campaign manifest|E16|cells|runs")

    def test_recorded_results_must_match_artifacts(self):
        record = copy.deepcopy(self.record)
        record["cells"][4]["verdict"] = "PASS"
        record["cells"][4]["reasons"] = []
        record["cells"][0]["observation"]["endpoint"]["returned"] = 99
        self.assert_refused(record, fragment="re-derived")
        files = dict(self.files)
        name = next(rel for rel in files if rel.endswith("capture.json"))
        files[name] = files[name].replace(b'"calls": 3', b'"calls": 4')
        self.assert_refused(files=files, fragment="missing or changed")

    def test_lifecycle_order_and_process_outcomes_are_checked(self):
        record = copy.deepcopy(self.record)
        timeline = record["runs"][0]["timeline"]
        timeline["release_sent"], timeline["observer_exited"] = (timeline["observer_exited"],
                                                                 timeline["release_sent"])
        self.assert_refused(record, fragment="lifecycle order")
        record = copy.deepcopy(self.record)
        record["runs"][2]["participants"][0].update(exit_code=None, signal=15)
        self.assert_refused(record, fragment="signal 15")

    def test_provenance_is_rechecked_against_the_frozen_observer(self):
        with self.assertRaisesRegex(Unknown, "observer bytes"):
            E16.verify_record(HELPER, self.record, self.files,
                              frozen_observer_bytes=self.observer_bytes + b"x",
                              manifest=self.manifest)
        record = copy.deepcopy(self.record)
        record["provenance"]["source"]["revision"] = "f" * 40
        self.assert_refused(record, fragment="frozen manifest")


class SystemMixedCampaign(LifecycleBase):
    """Unhinted mixed run: foreign byte-identical traffic is never owned."""

    def test_exact_mixed_campaign_passes_and_foreign_traffic_stays_foreign(self):
        _, record, files = self.campaign("system-mixed")
        self.assertEqual(self.verify(record, files)["status"], "PASS")
        cells = {cell["name"]: cell for cell in record["cells"]}
        self.assertEqual(cells["foreign-traffic"]["observation"]["endpoint"]["returned"], 5)
        self.assertEqual(cells["control"]["observation"]["endpoint"]["returned"], 3)
        self.assertEqual(cells["control"]["owned_identity"]["sha256"],
                         cells["foreign-traffic"]["owned_identity"]["sha256"])
        self.assertNotEqual(cells["control"]["owned_identity"]["ino"],
                            cells["foreign-traffic"]["owned_identity"]["ino"])

    def test_foreign_calls_credited_to_the_owned_row_are_refused(self):
        _, record, files = self.campaign("system-mixed", mode="swap-foreign")
        cells = {cell["name"]: cell for cell in record["cells"]}
        self.assertTrue(any("owned count mismatch" in reason
                            for reason in cells["control"]["reasons"]))
        with self.assertRaises(Unknown):
            self.verify(record, files)


class HintedRefusalBinding(LifecycleBase):
    def test_a_foreign_objects_no_table_diagnostic_never_satisfies_direct(self):
        _, record, files = self.campaign(mode="foreign-diagnostic")
        cells = {cell["name"]: cell for cell in record["cells"]}
        self.assertEqual(cells["direct-no-table"]["verdict"], "UNKNOWN")
        self.assertIn("no no-table diagnostic bound to the owned object",
                      cells["direct-no-table"]["reasons"])


class RunnerSurface(unittest.TestCase):
    def test_run_refuses_without_root_and_names_the_operator_command(self):
        if os.geteuid() == 0:
            self.skipTest("refusal is for unprivileged callers")
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "qualify-e16-surfaces.py"), "run",
             "--campaign", "hinted", "--observer", "/nonexistent", "--provenance", "/nonexistent",
             "--artifacts", "/nonexistent/e16"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("run needs root", result.stderr)
        self.assertFalse(Path("/nonexistent/e16").exists())

    def test_campaign_tables_are_exact(self):
        self.assertEqual([name for name, _, _ in E16.required_cells("hinted")],
                         list(E16.CELL_ORDER))
        self.assertEqual(sorted(E16.SURFACES), sorted(E16.CELL_ORDER))
        self.assertEqual(E16.required_runs("system-mixed"),
                         [["system", list(E16.CELL_ORDER) + ["foreign-traffic"]]])

    def test_bound_sources_cover_every_e16_fixture(self):
        fixtures = sorted(f"tests/fixtures/e16/{path.name}"
                          for path in (ROOT / "tests/fixtures/e16").iterdir())
        self.assertEqual(sorted(rel for rel in E16.BOUND_SOURCES if "/e16/" in rel), fixtures)
        for rel in E16.BOUND_SOURCES:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_fixture_hashes_are_recorded(self):
        with tempfile.TemporaryDirectory() as raw:
            records = E16.build_fixtures(Path(raw))
            outputs = {record["output"]: record for record in records}
            self.assertEqual(outputs["foreign.so"]["sha256"], outputs["control.so"]["sha256"])
            self.assertEqual(hashlib.sha256((Path(raw) / "driver").read_bytes()).hexdigest(),
                             outputs["driver"]["sha256"])


def _signal_sanity():
    """A harness that ignores SIGTERM cannot judge signal outcomes (nohup trap)."""
    result = subprocess.run(["sh", "-c", "kill -TERM $$"], check=False)
    if result.returncode != -signal.SIGTERM and result.returncode != 128 + signal.SIGTERM:
        raise SystemExit("SIGTERM is not deliverable in this harness; refusing to run")


if __name__ == "__main__":
    _signal_sanity()
    unittest.main()
