#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -u
. "$1"
dependency_digest controlled "$2" >"$3"
