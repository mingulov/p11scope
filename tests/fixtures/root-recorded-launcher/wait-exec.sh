#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
printf '%s\n' "$$" > "$CASE_DIR/waiting.pid"
while [ ! -e "$CASE_DIR/go" ]; do sleep 0.01; done
exec sh "$FIXTURE_DIR/target.sh" "$@"
