#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Long-lived child used to exercise the Popen-return signal boundary."""

from pathlib import Path
import os
import time


Path(os.environ["P11SCOPE_BOUNDARY_PID"]).write_text(str(os.getpid()), encoding="ascii")
time.sleep(5)
