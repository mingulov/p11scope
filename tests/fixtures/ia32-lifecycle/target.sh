#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
record=$1
mode=$2
status=$3
shift 3
starttime=$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }' "/proc/$$/stat")
printf '%s %s\n' "$$" "$starttime" >"$record.identity"
printf '%s\0' "$@" >"$record.argv"
cat >"$record.stdin"
printf 'READY\n' >"$record.ready"
case $mode in
    delayed-stop) sleep 0.1; kill -STOP "$$" ;;
    stopped) kill -STOP "$$" ;;
    ignore) trap '' HUP INT TERM; exec sleep "${IA32_TEST_HOLD_SECONDS:-12}" ;;
    hold) exec sleep "${IA32_TEST_HOLD_SECONDS:-12}" ;;
    exit) ;;
    *) exit 96 ;;
esac
exit "$status"
