# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# shellcheck shell=bash disable=SC2034  # sourced interface: env setups call the function
# Shared task-scoped token-directory reset for the provider matrix.
# SoftHSM 2.7 stores each token as a directory, so the old
# `rm -f "$dir"/tokens/*` left them behind and the next cell in the same
# task dir failed with "Is a directory". Remove the task's own tokens
# directory itself (recursively) and recreate it so repeat cells start
# clean. The guard requires an absolute path at least two levels deep
# ending in /tokens and rejects any .. component; every call site
# passes a fixed task path, never an arbitrary caller path.
reset_task_token_dir() {
  case ${1:-} in
    /*/*/tokens)
      case $1 in
        *..*) echo "reset_task_token_dir: refusing .. in token path '$1'" >&2; return 2 ;;
      esac
      ;;
    *) echo "reset_task_token_dir: refusing non-token path '${1:-}'" >&2; return 2 ;;
  esac
  rm -rf -- "$1" && mkdir -p -- "$1"
}
