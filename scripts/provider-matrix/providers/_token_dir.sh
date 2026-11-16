# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# shellcheck shell=bash disable=SC2034  # sourced interface: env setups call the function
# Shared task-scoped token-directory reset for the provider matrix.
# SoftHSM 2.7 stores each token as a directory, so the old
# `rm -f "$dir"/tokens/*` left them behind and the next cell in the same
# task dir failed with "Is a directory". Remove the task's own tokens
# directory itself (recursively, never an arbitrary caller path) and
# recreate it so repeat cells start clean.
reset_task_token_dir() {
  case ${1:-} in
    */tokens) ;;
    *) echo "reset_task_token_dir: refusing non-token path '${1:-}'" >&2; return 2 ;;
  esac
  rm -rf -- "$1" && mkdir -p -- "$1"
}
