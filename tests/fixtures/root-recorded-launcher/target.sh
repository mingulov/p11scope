#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
set -eu
printf '%s\n' "$$" > "$CASE_DIR/target.entered"
printf '%s\0' "$@" > "$CASE_DIR/argv"
cat > "$CASE_DIR/stdin"
exit 23
