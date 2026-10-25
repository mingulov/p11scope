#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the late-b cell inputs: two distinct-file SoftHSM providers plus one
# token store holding the P11SCOPE-A and P11SCOPE-B tokens.
#
#   mk-providers.sh DEST
#
# Layout: DEST/provider-a.so and DEST/provider-b.so are copies (never links)
# of the system SoftHSM module, so they are distinct files with distinct
# inodes; DEST/softhsm2.conf points at DEST/tokens. Run late-b beside this
# file with SOFTHSM2_CONF=DEST/softhsm2.conf. Prints the provider paths
# with their (device, inode) identity plus the conf path on stdout.
# Test-only PINs (1234); nothing here is captured or secret.
set -eu

DEST=${1:?usage: mk-providers.sh DEST}
mkdir -p "$DEST"
DEST=$(cd "$DEST" && pwd)

LIB=${SOFTHSM_LIB:-}
if [ -z "$LIB" ]; then
    for candidate in \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so; do
        if [ -f "$candidate" ]; then
            LIB=$candidate
            break
        fi
    done
fi
if [ -z "$LIB" ] || [ ! -f "$LIB" ]; then
    echo "mk-providers: libsofthsm2.so not found in the known system paths" >&2
    exit 2
fi
if ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "mk-providers: softhsm2-util not found" >&2
    exit 2
fi

mkdir -p "$DEST/tokens"
cp "$LIB" "$DEST/provider-a.so"
cp "$LIB" "$DEST/provider-b.so"
INO_A=$(stat -c %i "$DEST/provider-a.so")
INO_B=$(stat -c %i "$DEST/provider-b.so")
if [ "$INO_A" = "$INO_B" ]; then
    echo "mk-providers: copies share an inode" >&2
    exit 2
fi
DEV_A=$(stat -c %d "$DEST/provider-a.so")
DEV_B=$(stat -c %d "$DEST/provider-b.so")

printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
    "$DEST" >"$DEST/softhsm2.conf"
export SOFTHSM2_CONF="$DEST/softhsm2.conf"
softhsm2-util --init-token --free --label "P11SCOPE-A" \
    --pin 1234 --so-pin 1234 >/dev/null
softhsm2-util --init-token --free --label "P11SCOPE-B" \
    --pin 1234 --so-pin 1234 >/dev/null

echo "PROVIDER_A path=$DEST/provider-a.so dev=$DEV_A ino=$INO_A"
echo "PROVIDER_B path=$DEST/provider-b.so dev=$DEV_B ino=$INO_B"
echo "CONF path=$DEST/softhsm2.conf"
