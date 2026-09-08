#!/bin/sh
set -eu
case ${1-} in ignore) trap '' TERM ;; stopped) kill -STOP "$$" ;; esac
exec sleep 300
