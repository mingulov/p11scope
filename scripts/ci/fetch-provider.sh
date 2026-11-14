#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# fetch-provider.sh NAME DESTDIR: download one pinned provider artifact
# (scripts/provider-matrix/pins.sh), verify its sha256, and unpack it into
# DESTDIR (the cell's TASK_DIR). Idempotent: a matching .fetch-NAME.ok
# marker skips the download. Exit 0 on success, 1 on download/unpack
# failure, 2 on usage errors or sha256 mismatch.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
if [ $# -ne 2 ]; then echo "usage: fetch-provider.sh NAME DESTDIR (NAME: haskoki, kryoptic, softhsm26)" >&2; exit 2; fi
NAME=$1; DEST=$2
# shellcheck disable=SC1091
. "$REPO/scripts/provider-matrix/pins.sh"
case $NAME in
  haskoki) URL=$HASKOKI_URL; SHA=$HASKOKI_SHA256; FILE=haskoki-$HASKOKI_VERSION-linux-x86_64.tar.gz; KIND=tarball ;;
  kryoptic) URL=$KRYOPTIC_URL; SHA=$KRYOPTIC_SHA256; FILE=kryoptic-$KRYOPTIC_VERSION.rpm; KIND=rpm; SUBDIR=kryoptic-rpm ;;
  softhsm26) URL=$SOFTHSM26_URL; SHA=$SOFTHSM26_SHA256; FILE=softhsm-$SOFTHSM26_VERSION.rpm; KIND=rpm; SUBDIR=softhsm-2.6.1/root ;;
  *) echo "fetch-provider: unknown provider: $NAME" >&2; exit 2 ;;
esac
mkdir -p "$DEST/downloads" || exit 1
if [ -f "$DEST/.fetch-$NAME.ok" ] && [ "$(cat "$DEST/.fetch-$NAME.ok")" = "$SHA" ]; then
  echo "fetch-provider: $NAME already fetched ($SHA)"
  exit 0
fi
echo "fetch-provider: downloading $URL"
curl -fSL --retry 3 --max-time 600 -o "$DEST/downloads/$FILE" "$URL" || { echo "fetch-provider: download failed: $URL" >&2; exit 1; }
echo "$SHA  $DEST/downloads/$FILE" | sha256sum --check --status - || { echo "fetch-provider: sha256 mismatch for $FILE" >&2; exit 2; }
case $KIND in
  tarball)
    tar xzf "$DEST/downloads/$FILE" -C "$DEST" || { echo "fetch-provider: unpack failed" >&2; exit 1; }
    ;;
  rpm)
    mkdir -p "$DEST/$SUBDIR" || exit 1
    if command -v rpm2cpio >/dev/null 2>&1; then
      (cd "$DEST/$SUBDIR" && rpm2cpio "$DEST/downloads/$FILE" | cpio -idm) || { echo "fetch-provider: rpm unpack failed" >&2; exit 1; }
    elif command -v bsdtar >/dev/null 2>&1; then
      bsdtar -xf "$DEST/downloads/$FILE" -C "$DEST/$SUBDIR" || { echo "fetch-provider: rpm unpack failed" >&2; exit 1; }
    else
      echo "fetch-provider: need rpm2cpio or bsdtar to unpack rpms" >&2
      exit 1
    fi
    ;;
esac
echo "$SHA" >"$DEST/.fetch-$NAME.ok"
echo "fetch-provider: $NAME ready ($SHA)"
