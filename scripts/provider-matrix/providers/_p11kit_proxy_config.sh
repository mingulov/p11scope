# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# shellcheck shell=bash disable=SC2034  # sourced interface: p11kit-managed.env and p11kit-unmanaged.env
# Shared setup for the p11-kit aggregating-proxy rows: serve one task-dir
# SoftHSM token to the real p11-kit-proxy through a private user config
# (XDG_CONFIG_HOME with user-config:only), with the module `managed`
# flag yes or no. The suite then runs against the proxy exactly like any
# other provider; setup refuses unless the proxy serves precisely the
# one expected token, which also proves the resolved module is the
# aggregator rather than the forwarding client.
#
# Sourced by the env files, never executed directly. Inputs from the
# cell: $PKCS11_MODULE (the proxy), $PKCS11_TOOL, $P11TEST_PIN and
# $P11TEST_SO_PIN (throwaway token PINs, never echoed).

# shellcheck disable=SC1090,SC1091  # shipped sibling, delivered with the env files
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_token_dir.sh"

# p11kit_proxy_check_token_list LISTING WANT-LABEL: true iff the
# pkcs11-tool -L listing names exactly one token and it is WANT-LABEL.
p11kit_proxy_check_token_list() {
  [ $# -eq 2 ] || return 2
  [ -f "$1" ] || return 2
  labels=$(grep "token label" "$1" | sed 's/^.*token label[^:]*: *//') || return 1
  [ "$(printf '%s\n' "$labels" | grep -c .)" = 1 ] || return 1
  [ "$labels" = "$2" ] || return 1
  return 0
}

# p11kit_proxy_config_setup TASKDIR MANAGED CELLNAME: init a SoftHSM
# token, write the private proxy config with the managed flag, and prove
# the proxy serves exactly the p11matrix token through it.
p11kit_proxy_config_setup() {
  case $2 in yes|no) ;; *) echo "managed flag must be yes or no, got '$2'" >&2; return 2 ;; esac
  dir=$1/$3
  mkdir -p "$dir/xdg/pkcs11/modules"
  command -v p11-kit >/dev/null 2>&1 || { echo "p11-kit binary missing" >&2; return 1; }
  softhsm=
  for cand in /usr/lib64/pkcs11/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
    if [ -f "$cand" ]; then softhsm=$cand; break; fi
  done
  [ -n "$softhsm" ] || { echo "no SoftHSM library to serve" >&2; return 1; }
  printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$dir/tokens" >"$dir/softhsm2.conf"
  reset_task_token_dir "$dir/tokens" || return 1
  SOFTHSM2_CONF=$dir/softhsm2.conf softhsm2-util --init-token --slot 0 \
    --label "p11matrix" --pin "$P11TEST_PIN" --so-pin "$P11TEST_SO_PIN" || return 1
  printf 'user-config: only\n' >"$dir/xdg/pkcs11/pkcs11.conf"
  printf 'module: %s\nmanaged: %s\n' "$softhsm" "$2" >"$dir/xdg/pkcs11/modules/zz-matrix.module"
  SOFTHSM2_CONF=$dir/softhsm2.conf XDG_CONFIG_HOME=$dir/xdg \
    "${PKCS11_TOOL:-pkcs11-tool}" --module "$PKCS11_MODULE" -L >"$dir/probe.log" 2>&1 || {
    echo "proxy probe failed; see $dir/probe.log" >&2
    return 1
  }
  p11kit_proxy_check_token_list "$dir/probe.log" "p11matrix" || {
    echo "proxy serves != 1 p11matrix token; see $dir/probe.log" >&2
    return 1
  }
  echo "proxy serves one p11matrix token (managed: $2):"
  cat "$dir/xdg/pkcs11/modules/zz-matrix.module"
}
