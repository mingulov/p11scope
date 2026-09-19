#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
case ${1-} in ignore) trap '' TERM ;; stopped) kill -STOP "$$" ;; esac
exec sleep 300
