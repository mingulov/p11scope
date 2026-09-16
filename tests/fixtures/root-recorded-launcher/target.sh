#!/bin/sh
set -eu
printf '%s\n' "$$" > "$CASE_DIR/target.entered"
printf '%s\0' "$@" > "$CASE_DIR/argv"
cat > "$CASE_DIR/stdin"
exit 23
