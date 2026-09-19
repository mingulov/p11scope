#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Callers define cleanup() before sourcing this file.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
