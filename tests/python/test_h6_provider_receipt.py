#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Held provider receipts must not remap a watched file during observation."""

import copy
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
RECEIPT = H6["provider_receipt"]


class HeldProviderReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="h6-provider-receipt-")
        self.addCleanup(temporary.cleanup)
        self.provider = Path(temporary.name) / "test-owned-provider"
        self.provider.write_bytes(b"test-owned provider bytes\n" * 256)

    def counted_mapping(self):
        calls = []
        actual = RECEIPT.__globals__["PIN_FD"]

        def counted(fd):
            calls.append(fd)
            return actual(fd)

        return calls, mock.patch.dict(RECEIPT.__globals__, {"PIN_FD": counted})

    def test_repeated_receipts_keep_original_mapping_and_copy_nested_fields(self):
        pin = H6["FilePin"](self.provider)
        try:
            calls, counting = self.counted_mapping()
            with counting:
                first = RECEIPT(pin)
                expected = copy.deepcopy(first)
                first["dev"][0] = -1
                first["mapping"]["dev"][0] = -1
                first["file_identity"]["dev"][0] = -1
                second = RECEIPT(pin)
                self.assertEqual(second, expected)
                self.assertEqual(calls, [pin.fd],
                                 "a repeated receipt must not map the watched provider again")
        finally:
            pin.close()

    def test_each_original_filepin_calibrates_its_own_mapping(self):
        first = H6["FilePin"](self.provider)
        second = H6["FilePin"](self.provider)
        try:
            calls, counting = self.counted_mapping()
            with counting:
                self.assertEqual(RECEIPT(first), RECEIPT(first))
                self.assertEqual(RECEIPT(first), RECEIPT(second))
                self.assertEqual(calls, [first.fd, second.fd])
        finally:
            first.close()
            second.close()

    def test_cached_mapping_still_refuses_changed_held_file(self):
        pin = H6["FilePin"](self.provider)
        try:
            calls, counting = self.counted_mapping()
            with counting:
                RECEIPT(pin)
                self.provider.write_bytes(b"changed provider bytes\n" * 256)
                with self.assertRaisesRegex(ValueError, "held file changed"):
                    RECEIPT(pin)
                self.assertEqual(calls, [pin.fd])
        finally:
            pin.close()

    def test_cached_mapping_refuses_closed_or_reused_descriptor(self):
        pin = H6["FilePin"](self.provider)
        RECEIPT(pin)
        pin.close()
        with self.assertRaises(OSError):
            RECEIPT(pin)

        original = H6["FilePin"](self.provider)
        replacement_path = self.provider.with_name("different-provider")
        replacement_path.write_bytes(b"different provider bytes\n" * 256)
        replacement = H6["FilePin"](replacement_path)
        try:
            RECEIPT(original)
            original_fd = original.fd
            os.close(original_fd)
            os.dup2(replacement.fd, original_fd)
            with self.assertRaisesRegex(ValueError, "held file changed"):
                RECEIPT(original)
        finally:
            original.close()
            replacement.close()

    def test_cached_mapping_refuses_a_different_descriptor_on_same_owner(self):
        pin = H6["FilePin"](self.provider)
        try:
            RECEIPT(pin)
            original_fd = pin.fd
            alias = os.dup(original_fd)
            try:
                pin.fd = alias
                with self.assertRaisesRegex(ValueError, "descriptor changed"):
                    RECEIPT(pin)
            finally:
                pin.fd = original_fd
                os.close(alias)
        finally:
            pin.close()


if __name__ == "__main__":
    unittest.main()
