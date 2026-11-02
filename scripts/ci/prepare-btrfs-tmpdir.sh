#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Loop-mounted btrfs TMPDIR for the privileged runner's btrfs group.
#
# Usage: scripts/ci/prepare-btrfs-tmpdir.sh IMG MNT
#        scripts/ci/prepare-btrfs-tmpdir.sh --teardown IMG MNT
#
# Prepare makes a 256M btrfs image at IMG, loop-mounts it at MNT, verifies
# the mount really is btrfs, and prints MNT (and only MNT) to stdout.
# Teardown unmounts MNT (lazily on a busy first attempt) and removes both
# paths; it is idempotent. Needs root, mkfs.btrfs (apt: btrfs-progs),
# loop devices and btrfs support in the running kernel.
#
# Exit codes: 0 done; 77 a prerequisite is missing or the mount cannot be
# provided (stderr is one reason line); 2 bad usage.
set -uo pipefail

PROG=${0##*/}

teardown() {
    local img=$1 mnt=$2
    if [ -z "$img" ] || [ -z "$mnt" ] || [ "$mnt" = "/" ]; then
        echo "$PROG: refusing teardown with an empty or root path" >&2
        exit 2
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mnt" 2>/dev/null; then
        if ! umount "$mnt" 2>/dev/null; then
            umount -l "$mnt" 2>/dev/null || true
        fi
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mnt" 2>/dev/null; then
        echo "$PROG: $mnt is still mounted; leaving $img for a human" >&2
        exit 1
    fi
    rm -rf "$mnt" "$img"
}

if [ "${1:-}" = "--teardown" ]; then
    [ $# -eq 3 ] || { echo "usage: $PROG --teardown IMG MNT" >&2; exit 2; }
    teardown "$2" "$3"
    exit 0
fi

if [ $# -ne 2 ]; then
    echo "usage: $PROG IMG MNT" >&2
    exit 2
fi
img=$1
mnt=$2

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (loop-mounts a btrfs image)" >&2
    exit 77
fi
if ! command -v mkfs.btrfs >/dev/null 2>&1; then
    echo "mkfs.btrfs not found (install btrfs-progs)" >&2
    exit 77
fi
if [ -e "$img" ] && [ ! -f "$img" ]; then
    echo "image path exists and is not a file: $img" >&2
    exit 77
fi
rm -f "$img"
if ! truncate -s 256M "$img" 2>/dev/null; then
    echo "cannot create a 256M image at $img" >&2
    exit 77
fi
if ! mkfs.btrfs -q -f "$img" >/dev/null 2>&1; then
    rm -f "$img"
    echo "mkfs.btrfs could not format $img" >&2
    exit 77
fi
mkdir -p "$mnt" || { rm -f "$img"; echo "cannot create $mnt" >&2; exit 77; }
if ! mount -o loop "$img" "$mnt" 2>/dev/null; then
    rm -f "$img"
    rmdir "$mnt" 2>/dev/null || true
    echo "cannot loop-mount btrfs (no loop device or no btrfs in this kernel)" >&2
    exit 77
fi
fstype=$(stat -f -c %T "$mnt" 2>/dev/null || true)
if [ "$fstype" != "btrfs" ]; then
    umount "$mnt" 2>/dev/null || umount -l "$mnt" 2>/dev/null || true
    rm -f "$img"
    rmdir "$mnt" 2>/dev/null || true
    echo "mounted $mnt but it is $fstype, not btrfs" >&2
    exit 77
fi
echo "$mnt"
