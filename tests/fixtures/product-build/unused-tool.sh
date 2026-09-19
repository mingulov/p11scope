#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
: > "${P11SCOPE_PRODUCT_BUILD_RECORD%/*}/unused-tool-invoked"
echo "unexpected product-build tool invoked: ${0##*/}" >&2
exit 97
