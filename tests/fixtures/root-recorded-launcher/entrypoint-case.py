"""Exercise the real direct entrypoint with a mandatory skip or empty loader."""

import runpy
import sys
import unittest
from unittest import mock


mode, path = sys.argv[1:]


class MandatoryCase(unittest.TestCase):
    @unittest.skip("injected mandatory case skip")
    def test_required(self):
        pass


def selected(*args, **kwargs):
    return unittest.TestSuite([MandatoryCase("test_required")] if mode == "skip" else [])


sys.argv = [path, "mandatory-case"]
with mock.patch.object(unittest.TestLoader, "loadTestsFromNames", selected):
    runpy.run_path(path, run_name="__main__")
