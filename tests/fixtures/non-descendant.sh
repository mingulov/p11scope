#!/bin/sh
set -eu

start=$(cut -d ' ' -f 22 "/proc/$$/stat")
printf '%s %s\n' "$$" "$start"
IFS= read -r token
[ "$token" = go ]
exec sleep "$1"
