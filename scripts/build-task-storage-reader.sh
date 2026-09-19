#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; }
case $1 in
    /*) output=$1 ;;
    *) echo "output directory must be absolute" >&2; exit 2 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
umask 077
mkdir -p "$output"

clang-18 -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wextra -Werror \
    -c "$script_dir/native/dump-task-storage.bpf.c" \
    -o "$output/dump-task-storage.bpf.o"
cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$script_dir/native/dump-task-storage.c" \
    -o "$output/dump-task-storage" -ldl
