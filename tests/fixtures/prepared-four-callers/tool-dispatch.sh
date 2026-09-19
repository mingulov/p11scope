#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
name=${0##*/}
if [ "${P11SCOPE_FAIL_TOOL-}" = "$name" ]; then
    echo "$name fixture refusal" >&2
    exit 29
fi
exec "/usr/bin/$name" "$@"
