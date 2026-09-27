#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
if [ "$1" = doctor ]; then
    pid=; previous=
    for argument do [ "$previous" = --pid ] && pid=$argument; previous=$argument; done
    echo "/proc/$pid/maps ...................... FAIL EACCES — module discovery unavailable for this target"
    echo "/proc/$pid/mem ....................... FAIL EACCES — memory scan unavailable for this target"
    exit 1
fi
if [ "$1" = profile ]; then
    case " $* " in *" --duration 1 "*) echo 'cannot inspect the file locator now (Permission denied)' >&2; exit 1 ;; esac
    output=; previous=
    for argument do [ "$previous" = -o ] && output=$argument; previous=$argument; done
    [ -z "$output" ] || /usr/bin/python3 "$D2_FIXTURES/write-observed.py" "$output"
    echo 'capture — privacy=aggregate-only'
fi
exit 0
