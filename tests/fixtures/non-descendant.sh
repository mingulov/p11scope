#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
set -eu

start=$(cut -d ' ' -f 22 "/proc/$$/stat")
printf '%s %s\n' "$$" "$start"
IFS= read -r token
[ "$token" = go ]
exec sleep "$1"
