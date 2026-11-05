#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Scope-matrix process tree: a root with a descendant plus an outside
# sibling, then a leave/re-enter cycle once the GO file appears.
#
# usage: tree.sh WORKDIR GO_FILE
#
# WORKDIR holds tree.jsonl (one JSON object per line: spawn/leave rows with
# role, pid and ppid read back from /proc) and the cycle rendezvous files.
# The script prints READY pid=<controller> root=<pid> descendant=<pid>
# sibling=<pid>, waits for GO_FILE, drives the descendant leave plus a
# re-enter under the same root, prints the cycle rows, then holds the tree
# until SIGTERM/SIGINT and exits 0. Every wait is bounded; usage and setup
# errors exit 2, a failed tree exits 1.
set -eu

usage() {
    echo "usage: $0 WORKDIR GO_FILE" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
workdir=$1
go=$2
[ -n "$workdir" ] && [ -n "$go" ] || usage
[ -d "$workdir" ] || { echo "tree.sh: workdir is not a directory" >&2; exit 2; }
ledger=$workdir/tree.jsonl
desc_file=$workdir/descendant.pid
cycle=$workdir/cycle
if [ -e "$ledger" ]; then echo "tree.sh: ledger already exists" >&2; exit 2; fi
if [ -e "$go" ]; then echo "tree.sh: go file already exists" >&2; exit 2; fi

stop=0
root=0
sibling=0
on_signal() {
    stop=1
}
trap on_signal TERM INT

ppid_of() {
    stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    rest=${stat##*)}
    # shellcheck disable=SC2086
    set -- $rest
    printf '%s\n' "$2"
}

emit() {
    printf '%s\n' "$1" >>"$ledger"
}

# Root: spawns generation-1 descendant, waits for the cycle file, retires
# generation 1 (leave) and spawns generation 2 (re-enter), then waits.
sh -c '
    desc_file=$1/descendant.pid
    cycle=$1/cycle
    sleep 600 & echo "1:$!" >"$desc_file"
    steps=0
    while [ ! -e "$cycle" ]; do
        steps=$((steps + 1))
        if [ "$steps" -gt 2400 ]; then exit 1; fi
        sleep 0.05
    done
    old=$(cut -d: -f2 "$desc_file")
    kill "$old" 2>/dev/null || true
    wait "$old" 2>/dev/null || true
    sleep 600 & echo "2:$!" >"$desc_file"
    wait
' sh "$workdir" &
root=$!

descendant_wait() {
    steps=0
    while [ ! -f "$desc_file" ]; do
        steps=$((steps + 1))
        if [ "$steps" -gt 600 ] || [ "$stop" -eq 1 ]; then return 1; fi
        sleep 0.05
    done
    return 0
}

cleanup() {
    trap '' TERM INT
    for target in "$root" "$sibling"; do
        if [ "$target" -ne 0 ]; then
            kill "$target" 2>/dev/null || true
        fi
    done
    if [ -f "$desc_file" ]; then
        dead=$(cut -d: -f2 "$desc_file" 2>/dev/null) || dead=""
        if [ -n "$dead" ]; then kill "$dead" 2>/dev/null || true; fi
    fi
    wait 2>/dev/null || true
}

if ! descendant_wait; then
    echo "tree.sh: root did not spawn its descendant" >&2
    cleanup
    exit 1
fi
descendant=$(cut -d: -f2 "$desc_file")
sleep 600 &
sibling=$!
root_ppid=$(ppid_of "$root") || { echo "tree.sh: root vanished" >&2; cleanup; exit 1; }
desc_ppid=$(ppid_of "$descendant") || { echo "tree.sh: descendant vanished" >&2; cleanup; exit 1; }
sib_ppid=$(ppid_of "$sibling") || { echo "tree.sh: sibling vanished" >&2; cleanup; exit 1; }
emit "{\"event\":\"spawn\",\"role\":\"root\",\"pid\":$root,\"ppid\":$root_ppid}"
emit "{\"event\":\"spawn\",\"role\":\"descendant\",\"generation\":1,\"pid\":$descendant,\"ppid\":$desc_ppid}"
emit "{\"event\":\"spawn\",\"role\":\"sibling\",\"pid\":$sibling,\"ppid\":$sib_ppid}"
echo "READY pid=$$ root=$root descendant=$descendant sibling=$sibling"

steps=0
while [ ! -e "$go" ] && [ "$stop" -eq 0 ]; do
    steps=$((steps + 1))
    if [ "$steps" -gt 2400 ]; then
        echo "tree.sh: go file timed out" >&2
        cleanup
        exit 1
    fi
    sleep 0.05
done
if [ "$stop" -eq 1 ]; then
    cleanup
    exit 0
fi

: >"$cycle"
steps=0
generation=""
while [ "$stop" -eq 0 ]; do
    if [ -f "$desc_file" ]; then
        generation=$(cut -d: -f1 "$desc_file" 2>/dev/null) || generation=""
        if [ "$generation" = "2" ]; then break; fi
    fi
    steps=$((steps + 1))
    if [ "$steps" -gt 600 ]; then
        echo "tree.sh: re-enter timed out" >&2
        cleanup
        exit 1
    fi
    sleep 0.05
done
if [ "$stop" -eq 1 ]; then
    cleanup
    exit 0
fi
replacement=$(cut -d: -f2 "$desc_file")
replacement_ppid=$(ppid_of "$replacement") || { echo "tree.sh: re-entered descendant vanished" >&2; cleanup; exit 1; }
emit "{\"event\":\"leave\",\"role\":\"descendant\",\"generation\":1,\"pid\":$descendant}"
emit "{\"event\":\"spawn\",\"role\":\"descendant\",\"generation\":2,\"pid\":$replacement,\"ppid\":$replacement_ppid}"
echo "CYCLE leave=$descendant reenter=$replacement root=$root"

while [ "$stop" -eq 0 ]; do
    sleep 0.1
done
cleanup
exit 0
