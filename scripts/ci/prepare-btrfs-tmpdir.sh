#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Loop-mounted btrfs TMPDIR for the privileged runner's btrfs group.
#
# Usage: scripts/ci/prepare-btrfs-tmpdir.sh IMG MNT
#        scripts/ci/prepare-btrfs-tmpdir.sh --teardown IMG MNT
#
# Prepare makes a 256M btrfs image at IMG, loop-mounts it at MNT, verifies
# the mount really is btrfs, writes an ownership marker on the mount and
# prints MNT (and only MNT) to stdout. It refuses when MNT is already a
# mountpoint or a non-empty directory. Teardown unmounts MNT (lazily on
# a busy first attempt) and removes both paths; it is idempotent.
# Teardown only removes mounts and directories this tool created and
# recorded: a mounted MNT comes down only with a matching marker, an
# unmounted MNT is removed only when empty (rmdir, never rm -rf), and
# IMG is removed only when a plain file. Needs root, mkfs.btrfs (apt:
# btrfs-progs), loop devices and btrfs support in the running kernel.
#
# Exit codes: 0 done; 77 a prerequisite is missing or the mount cannot be
# provided (stderr is one reason line); 1 teardown refused (not this
# tool's mount or data); 2 bad usage.
set -uo pipefail

PROG=${0##*/}
MARKER=.p11-btrfs-tmpdir
MARKER_MAGIC="p11scope-btrfs-tmpdir v1"

teardown() {
    local img=$1 mnt=$2 marker_line1 marker_line2
    if [ -z "$img" ] || [ -z "$mnt" ] || [ "$mnt" = "/" ]; then
        echo "$PROG: refusing teardown with an empty or root path" >&2
        exit 2
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mnt" 2>/dev/null; then
        # Mounted: only this tool's own mount comes down. The marker,
        # written by setup after verifying btrfs, proves ownership and
        # records the image the mount was made from.
        marker_line1=$(sed -n '1p' "$mnt/$MARKER" 2>/dev/null || true)
        marker_line2=$(sed -n '2p' "$mnt/$MARKER" 2>/dev/null || true)
        if [ "$marker_line1" != "$MARKER_MAGIC" ] || [ "$marker_line2" != "img=$img" ]; then
            echo "$PROG: refusing teardown: $mnt is mounted but not this tool's btrfs mount" >&2
            exit 1
        fi
        if ! umount "$mnt" 2>/dev/null; then
            umount -l "$mnt" 2>/dev/null || true
        fi
        if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mnt" 2>/dev/null; then
            echo "$PROG: $mnt is still mounted; leaving $img for a human" >&2
            exit 1
        fi
    fi
    # Unmounted: only an empty directory and a plain image file go
    # away. Anything else (someone's data, a non-file image) is
    # refused loudly, never removed.
    if [ -e "$img" ] && [ ! -f "$img" ]; then
        echo "$PROG: refusing teardown: $img is not a plain file" >&2
        exit 1
    fi
    if [ -e "$mnt" ] && ! rmdir "$mnt" 2>/dev/null; then
        echo "$PROG: refusing teardown: $mnt is not an empty directory" >&2
        exit 1
    fi
    rm -f "$img"
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

# State conflicts are checked before privilege: mounting over an
# occupied or dirty directory would shadow someone's data (or stack a
# mount), and teardown only takes down mounts this tool recorded.
if [ -e "$mnt" ] && [ -n "$(ls -A "$mnt" 2>/dev/null)" ]; then
    echo "$mnt exists and is not empty; teardown only removes what this tool created" >&2
    exit 77
fi
if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mnt" 2>/dev/null; then
    echo "$mnt is already a mountpoint" >&2
    exit 77
fi
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
# Ownership record for teardown: the magic proves this tool made the
# mount, the image line binds this mount to its image file.
if ! {
    echo "$MARKER_MAGIC"
    echo "img=$img"
} >"$mnt/$MARKER" 2>/dev/null; then
    umount "$mnt" 2>/dev/null || umount -l "$mnt" 2>/dev/null || true
    rm -f "$img"
    rmdir "$mnt" 2>/dev/null || true
    echo "cannot write the ownership marker on $mnt" >&2
    exit 77
fi
echo "$mnt"
