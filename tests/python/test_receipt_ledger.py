# SPDX-License-Identifier: GPL-3.0-or-later
"""Task-4 input-v1 ledger contract tests."""

import hashlib
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
GOLDEN_PATH = REPO / "tests/fixtures/receipt/input-ledger-golden.tsv"
SCRIPT_PATH = REPO / "scripts/receipt-build-subject.py"
MODULE_NAME = "receipt_build_subject_ledger_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

LARGE_SIZE = (
    b"input-v1\t0\ttool\tread\tpresent\t0644\t2159017984\t"
    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
    b"external:/opt/rust/bin/rustc\n"
)
MAX_SIZE = (
    b"input-v1\t0\ttool\tread\tpresent\t0644\t4294967296\t"
    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
    b"external:/opt/rust/bin/rustc-max\n"
)
OVERSIZE = (
    b"input-v1\t0\ttool\tread\tpresent\t0644\t4294967297\t"
    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
    b"external:/opt/rust/bin/rustc-oversize\n"
)
SPECIAL_CLASSES = (
    b"input-v1\t0\thost-config\tread\tpresent\t0644\t17\t"
    b"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\t"
    b"external:/config\n"
    b"input-v1\t1\tlane09-base\tread\tpresent\t0644\t23\t"
    b"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\t"
    b"external:/lane09-base\n"
    b"input-v1\t2\tlane09-package\tread\tpresent\t0644\t29\t"
    b"3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7\t"
    b"external:/lane09-package\n"
)
INVALID_VECTORS = (
    (
        "eight-fields",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\trepo:/Cargo.lock\n",
    ),
    (
        "missing-final-lf",
        b"input-v1\t0\ttool\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"external:/opt/tool",
    ),
    (
        "duplicate-locator",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/a\n"
        b"input-v1\t1\trepo\tread\tpresent\t0644\t1\t"
        b"2222222222222222222222222222222222222222222222222222222222222222\t"
        b"repo:/a\n",
    ),
    (
        "unsorted-locator",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/z\n"
        b"input-v1\t1\trepo\tread\tpresent\t0644\t1\t"
        b"2222222222222222222222222222222222222222222222222222222222222222\t"
        b"repo:/a\n",
    ),
    (
        "leading-zero-seq",
        b"input-v1\t00\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/a\n",
    ),
    (
        "noncontiguous-seq",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/a\n"
        b"input-v1\t2\trepo\tread\tpresent\t0644\t1\t"
        b"2222222222222222222222222222222222222222222222222222222222222222\t"
        b"repo:/b\n",
    ),
    (
        "illegal-matrix-pair",
        b"input-v1\t0\tdynamic\tprobe\tENOENT\t-\t-\t-\texternal:/x\n",
    ),
    (
        "absent-with-values",
        b"input-v1\t0\tabsent\tprobe\tENOENT\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/x\n",
    ),
    (
        "namespace-class-mismatch",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"external:/x\n",
    ),
    (
        "dotdot-component",
        b"input-v1\t0\trepo\tread\tpresent\t0644\t1\t"
        b"1111111111111111111111111111111111111111111111111111111111111111\t"
        b"repo:/src/../Cargo.toml\n",
    ),
)


class InputLedgerTests(unittest.TestCase):
    def setUp(self):
        self._previous_module = sys.modules.get(MODULE_NAME, MISSING)
        self._previous_dont_write_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        self.addCleanup(self._restore_import_state)

        try:
            self.module = load_path(SCRIPT_PATH, MODULE_NAME)
        except FileNotFoundError:
            self.fail("could not import receipt build-subject script")
        sys.modules[MODULE_NAME] = self.module
        self.golden = GOLDEN_PATH.read_bytes()
        self.digest = hashlib.sha256(b"abc").hexdigest()

    def _restore_import_state(self):
        sys.dont_write_bytecode = self._previous_dont_write_bytecode
        if self._previous_module is MISSING:
            sys.modules.pop(MODULE_NAME, None)
        else:
            sys.modules[MODULE_NAME] = self._previous_module

    def assertRejectedByParser(self, raw, name):
        with self.subTest(vector=name):
            with self.assertRaises(self.module.FormatError):
                self.module.parse_ledger(raw)

    def assertRejectedByEncoder(self, records, name):
        with self.subTest(vector=name):
            with self.assertRaises(self.module.FormatError):
                self.module.encode_ledger(records)

    def test_round_trip_fixed_vectors_and_boundary_locator(self):
        for name, raw in (
            ("golden", self.golden),
            ("large-size", LARGE_SIZE),
            ("maximum-size", MAX_SIZE),
            ("special-classes", SPECIAL_CLASSES),
        ):
            with self.subTest(vector=name):
                records = self.module.parse_ledger(raw)
                self.assertEqual(self.module.encode_ledger(records), raw)
                self.assertTrue(all(type(record) is self.module.InputRecord for record in records))

        boundary_locator = "external:/" + "/".join(["a" * 255] * 15 + ["b" * 246])
        self.assertEqual(len(boundary_locator.encode("ascii")), 4096)
        boundary_record = self.module.InputRecord(
            0, "tool", "read", "present", 0o644, 0, self.digest, boundary_locator
        )
        boundary_bytes = self.module.encode_ledger([boundary_record])
        parsed = self.module.parse_ledger(boundary_bytes)
        self.assertEqual(parsed, [boundary_record])
        self.assertIs(type(parsed[0]), self.module.InputRecord)

    def test_parser_rejects_invalid_vectors(self):
        self.assertRejectedByParser(OVERSIZE, "size 4294967297")
        locator_4097 = "external:/" + "/".join(["a" * 255] * 15 + ["b" * 247])
        self.assertEqual(len(locator_4097.encode("ascii")), 4097)
        locator_256 = "external:/" + "c" * 256
        self.assertRejectedByParser(
            f"input-v1\t0\ttool\tread\tpresent\t0644\t0\t{self.digest}\t{locator_4097}\n".encode("ascii"),
            "4097-byte locator",
        )
        self.assertRejectedByParser(
            f"input-v1\t0\ttool\tread\tpresent\t0644\t0\t{self.digest}\t{locator_256}\n".encode("ascii"),
            "256-byte component",
        )
        for name, raw in INVALID_VECTORS:
            self.assertRejectedByParser(raw, name)

        generated_invalid = {
            "4097-rows": b"".join(
                (
                    f"input-v1\t{index}\ttool\tread\tpresent\t0644\t0\t"
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
                    f"external:/tool/{index:04d}\n"
                ).encode("ascii")
                for index in range(4097)
            ),
            "bom": b"\xef\xbb\xbf" + self.golden,
            "cr": self.golden.replace(b"\n", b"\r\n", 1),
            "locator-unicode-cf": self.golden.replace(
                b"repo:/Cargo.toml", b"repo:/Cargo.\xe2\x80\x8btoml", 1
            ),
        }
        component = "a" * 250
        oversized = b"".join(
            (
                f"input-v1\t{index}\ttool\tread\tpresent\t0644\t0\t"
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\t"
                f"external:/oversized/{index:04d}/{component}/{component}/{component}/{component}\n"
            ).encode("ascii")
            for index in range(4096)
        )
        self.assertGreater(len(oversized), 4 * 1024 * 1024)
        generated_invalid["oversized"] = oversized
        for name, raw in generated_invalid.items():
            self.assertRejectedByParser(raw, name)

    def test_encoder_rejects_invalid_records(self):
        locator_4097 = "external:/" + "/".join(["a" * 255] * 15 + ["b" * 247])
        locator_256 = "external:/" + "c" * 256
        for name, size, locator in (
            ("size 4294967297", 4294967297, "external:/oversize"),
            ("4097-byte locator", 0, locator_4097),
            ("256-byte component", 0, locator_256),
        ):
            self.assertRejectedByEncoder(
                [self.module.InputRecord(0, "tool", "read", "present", 0o644, size, self.digest, locator)],
                name,
            )

        empty_digest = hashlib.sha256(b"").hexdigest()
        invalid_records = {
            "boolean-sequence": [
                self.module.InputRecord(False, "repo", "read", "present", 0o644, 3, self.digest, "repo:/bool-seq")
            ],
            "boolean-size": [
                self.module.InputRecord(0, "repo", "read", "present", 0o644, True, self.digest, "repo:/bool-size")
            ],
            "invalid-directory-mode": [
                self.module.InputRecord(0, "directory", "probe", "present", 0o10000, 0, empty_digest, "repo:/dir")
            ],
            "invalid-symlink-mode": [
                self.module.InputRecord(
                    0,
                    "symlink",
                    "probe",
                    "present",
                    0o10000,
                    1,
                    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                    "repo:/link",
                )
            ],
        }
        for name, records in invalid_records.items():
            self.assertRejectedByEncoder(records, name)

        long_component = "x" * 255
        oversized_records = [
            self.module.InputRecord(
                index,
                "tool",
                "read",
                "present",
                0o644,
                0,
                empty_digest,
                f"external:/{index:04d}/" + "/".join([long_component] * 15),
            )
            for index in range(4096)
        ]
        self.assertRejectedByEncoder(oversized_records, "oversized-programmatic-ledger")


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
