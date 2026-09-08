#!/bin/sh
set -eu
printf '%s\n' "$$" > "$CASE_DIR/target.entered"
printf '%s\0' "$@" > "$CASE_DIR/argv"
cat > "$CASE_DIR/stdin"
printf 'stdout from target\n'
printf 'stderr from target\n' >&2
exit 37
