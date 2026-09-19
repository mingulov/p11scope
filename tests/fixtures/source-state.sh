#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

[ "$#" -eq 3 ] || exit 64
before="$(pwd)|$(umask)|$-|$(export -p)"
trap > "$3/before.traps"
. "$1"
after="$(pwd)|$(umask)|$-|$(export -p)"
trap > "$3/after.traps"
[ "$before" = "$after" ] || exit 1
cmp -s "$3/before.traps" "$3/after.traps" || exit 1
command -v "$2" >/dev/null
