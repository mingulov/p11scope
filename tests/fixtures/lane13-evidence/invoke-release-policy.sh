#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 6 ] || { echo "usage: invoke-release-policy.sh FUNCTION WORK FACTS CALLS URL NAME" >&2; exit 64; }
function_file=$1
WORK=$2
FACTS=$3
CALLS=$4
lane13_url=$5
lane13_name=$6
KNATIVE_VERSION=knative-v1.23.0

case $function_file:$WORK:$FACTS:$CALLS in
    /*:/*:/*:/*) ;;
    *) echo "release-policy fixture paths must be absolute" >&2; exit 64 ;;
esac
[ -f "$function_file" ] && [ ! -L "$function_file" ] || exit 64
[ -f "$FACTS" ] && [ ! -L "$FACTS" ] || exit 64

lane13_fact() {
    printf '%s\n' "$1" >> "$FACTS"
}
curl() {
    printf '%s\n' curl >> "$CALLS"
    return 91
}
kubectl() {
    printf '%s\n' kubectl >> "$CALLS"
    return 92
}
timeout() {
    printf '%s\n' timeout >> "$CALLS"
    return 93
}
lane13_sha256() {
    return 94
}

. "$function_file"
lane13_fetch_release "$lane13_url" "$lane13_name"
