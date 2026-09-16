#!/bin/sh
set -eu
: > "${P11SCOPE_PRODUCT_BUILD_RECORD%/*}/unused-tool-invoked"
echo "unexpected product-build tool invoked: ${0##*/}" >&2
exit 97
