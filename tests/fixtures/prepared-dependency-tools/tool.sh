#!/bin/sh

# The tool pinning layer identifies its executables by behaviour (it runs
# `python --version` and requires a `Python ` banner), so a stub standing in
# for python must answer as python. This file is copied under many tool names,
# but only the python stand-in is ever probed; the selected cargo/rustc tools
# are canonicalized, not identified.
if [ "$1" = "--version" ]; then
    printf 'Python 3.14.0 (p11scope test fixture)\n'
    exit 0
fi

exit 0
