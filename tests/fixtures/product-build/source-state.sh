#!/bin/sh

before="$(pwd)|$(umask)|$-|$(trap)|$(export -p)"
. "$1"
after="$(pwd)|$(umask)|$-|$(trap)|$(export -p)"
[ "$before" = "$after" ] || exit 1
command -v p11scope_product_build >/dev/null
