#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Single importlib driver for file-path helper modules.

Every checker, lane oracle and python test that used to repeat the
``spec_from_file_location`` + ``module_from_spec`` + ``exec_module`` driver
loads through :func:`load_sibling` (a file in this directory) or
:func:`load_path` (an explicit path). Each call returns a fresh module
object; nothing is registered in ``sys.modules``. Importing this module
disables bytecode writes process-wide: consumers execute from
integrity-checked trees (fixture repositories must stay git-clean),
so loads must never create ``__pycache__`` entries.
Callers ``sys.path.insert`` this directory first so the import also
resolves when the caller itself was loaded via importlib.
"""
import importlib.util
import sys
from pathlib import Path

# Re-asserted here, but every importer must set this BEFORE importing:
# bytecode is cached before the module body runs, so this line alone
# cannot suppress this module's own .pyc.
sys.dont_write_bytecode = True


def load_path(path, name=None):
    """Load the python file at *path* under *name* (default: stem)."""
    resolved = Path(path)
    if not resolved.is_file():
        raise FileNotFoundError(f"helper script not found: {resolved}")
    spec = importlib.util.spec_from_file_location(name or resolved.stem, resolved)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load helper script: {resolved}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def load_sibling(name):
    """Load the file *name* from this directory (``scripts/``)."""
    return load_path(Path(__file__).with_name(name), Path(name).stem)
