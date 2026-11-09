#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
set -eu
. scripts/prepared-dependency-snapshot.sh
p11scope_prepared_snapshot "$@"
