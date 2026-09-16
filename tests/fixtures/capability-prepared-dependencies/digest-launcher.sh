#!/bin/sh
set -u
. "$1"
dependency_digest controlled "$2" >"$3"
