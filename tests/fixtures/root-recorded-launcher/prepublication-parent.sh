#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
if [ "$1" = chain ]; then
    "$REAL_PYTHON" -I "$FIXTURE_DIR/owned-exec.py" middle sh "$0" single &
else
    "$REAL_PYTHON" -I "$FIXTURE_DIR/prepublication-case.py" "$FIXTURE_DIR/owned-exec.py" &
fi
wait "$!"
