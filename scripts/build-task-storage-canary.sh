#!/bin/sh
set -eu

# Builds the unprivileged x86-64 task-storage seed fixture only. There is no new
# BPF object: the fixture loads the reader's dump-task-storage.bpf.o with every
# program's autoload disabled. Never run this builder with elevated privilege.
[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; }
case $1 in
    /*) output=$1 ;;
    *) echo "output directory must be absolute" >&2; exit 2 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
umask 077
mkdir -p "$output"

cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$script_dir/native/task-storage-canary.c" \
    -o "$output/task-storage-canary" -ldl
