#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
#
# README -- Chromium client-certificate demo workload that actually signs
# ----------------------------------------------------------------------
# Headless Chrome for Testing never presents a client certificate from a
# stock SoftHSM token: the `--auto-select-certificate-for-urls` switch is
# gone in v156 (selection needs the managed AutoSelectCertificateForUrls
# policy), and the token key needs a PIN no headless browser can enter.
# This setup makes one headless page load perform a real TLS client-auth
# handshake, hence a real C_Sign, through an external PKCS#11 module:
#
#  1. Managed policy: AutoSelectCertificateForUrls for the demo server URL,
#     installed in /etc/opt/chrome_for_testing/policies/managed/ -- the
#     directory the Chrome-for-Testing build actually reads (verified in
#     the binary's strings and with --enable-logging: config_dir_policy_
#     loader logs "Found mandatory policy file" headless). No headed
#     Xvfb run is needed; headless honors the policy.
#  2. Login without a prompt: tests/browser/autologin-shim.c, a tiny
#     forwarding PKCS#11 module over SoftHSM that performs a real C_Login
#     with the test PIN on every C_OpenSession (and before C_SignInit).
#     A SoftHSM key with CKA_PRIVATE=false was tried first: it signs
#     without login at the raw PKCS#11 level, but NSS still demands slot
#     login (CKF_LOGIN_REQUIRED) before client auth, so Chromium refuses.
#     The auto-login shim is the realistic option; the token itself stays
#     a standard private-key token seeded with stock pkcs11-tool.
#
# Recipe (demo runbook):
#   tests/browser/chromium-clientauth-setup.sh setup /tmp/clientauth
#   set -a; source /tmp/clientauth/env.sh; set +a
#   python3 tests/browser/clientauth-tls-server.py \
#       --client-ca /tmp/clientauth/cred/client-cert.pem \
#       --generate-to /tmp/clientauth/srv --serve 1 --ready-file /tmp/clientauth/url
#   # in another shell, while the server runs:
#   python3 tests/browser/chromium-clientauth-demo.py \
#       --workdir /tmp/clientauth --url "$(cat /tmp/clientauth/url)"
#   # observe the sign, e.g.:
#   sudo p11scope profile --pid <chromium-main-pid> \
#       --module /tmp/clientauth/autologin-shim.so --duration 45
#   tests/browser/chromium-clientauth-setup.sh teardown /tmp/clientauth
#
# The server prints its URL, then one JSON counters line; presented>=1
# proves the peer signed CertificateVerify with the token key. p11scope
# counts the literal C_Sign/C_SignInit calls on the browser PID.
#
# Requirements: cc, openssl, softhsm2-util, pkcs11-tool, python3 with
# playwright + `playwright install chromium`, passwordless `sudo -n` (only
# for the managed-policy file). teardown removes only the policy file this
# setup installed; it never touches other files in the policy directory.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM_SRC="$SELF_DIR/autologin-shim.c"
POLICY_DIR="/etc/opt/chrome_for_testing/policies/managed"
POLICY_NAME_DEFAULT="chromium-clientauth.json"
PIN_DEFAULT="1234"
LABEL_DEFAULT="clientauth"
PATTERN_DEFAULT="https://127.0.0.1:*/*"

die() { echo "chromium-clientauth-setup: $*" >&2; exit 1; }

need_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required host tool missing: $1"
}

find_softhsm_lib() {
    for candidate in \
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" \
        "/usr/lib/softhsm/libsofthsm2.so" \
        "/usr/lib64/pkcs11/libsofthsm2.so" \
        "/usr/lib64/softhsm/libsofthsm.so"; do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    die "libsofthsm2.so not found in the known system paths"
}

chromium_present() {
    python3 -c "from playwright.sync_api import sync_playwright; print('pw-ok')" 2>/dev/null | grep -q pw-ok \
        || die "python playwright is not installed"
    local cache="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
    ls -d "$cache"/chromium-*/chrome-linux*/chrome >/dev/null 2>&1 \
        || die "no playwright chromium in $cache (run: playwright install chromium)"
}

cmd_setup() {
    local workdir="${1:-}"; [[ -n "$workdir" ]] || die "usage: $0 setup <workdir>"
    local pin="${PIN:-$PIN_DEFAULT}" label="${LABEL:-$LABEL_DEFAULT}"
    local pattern="${PATTERN:-$PATTERN_DEFAULT}"
    local policy_name="${POLICY_NAME:-$POLICY_NAME_DEFAULT}"
    need_tool cc; need_tool openssl; need_tool softhsm2-util; need_tool pkcs11-tool
    need_tool python3
    chromium_present
    sudo -n true 2>/dev/null || die "passwordless 'sudo -n' is required (managed-policy file)"
    [[ -f "$SHIM_SRC" ]] || die "shim source missing: $SHIM_SRC"

    mkdir -p "$workdir"
    workdir="$(cd "$workdir" && pwd)"
    local store="$workdir/softhsm" cred="$workdir/cred" home="$workdir/chrome-home"
    mkdir -p "$store/tokens" "$cred" "$home/.pki/nssdb"

    echo "-- building the auto-login shim"
    cc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
        -o "$workdir/autologin-shim.so" "$SHIM_SRC" -ldl

    local softlib
    softlib="$(find_softhsm_lib)"
    export SOFTHSM2_CONF="$store/softhsm.conf"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
        "$store/tokens" >"$SOFTHSM2_CONF"

    echo "-- seeding token '$label' on $softlib"
    softhsm2-util --init-token --slot 0 --label "$label" \
        --pin "$pin" --so-pin "$pin" >/dev/null
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$cred/client-key.pem" -out "$cred/client-cert.pem" \
        -days 2 -subj "/CN=clientauth-client" >/dev/null 2>&1
    openssl x509 -in "$cred/client-cert.pem" -outform DER \
        -out "$cred/client-cert.der" >/dev/null 2>&1
    pkcs11-tool --module "$softlib" --token-label "$label" \
        --login --pin "$pin" --write-object "$cred/client-key.pem" \
        --type privkey --label "clientauth-key" --id 0101 >/dev/null
    pkcs11-tool --module "$softlib" --token-label "$label" \
        --login --pin "$pin" --write-object "$cred/client-cert.der" \
        --type cert --label "clientauth-cert" --id 0101 >/dev/null

    echo "-- registering the shim in a fresh Chromium HOME"
    cat >"$home/.pki/nssdb/pkcs11.txt" <<EOF
library=$workdir/autologin-shim.so
name=ClientAuthShim
parameters=
NSS=trustOrder=75 cipherOrder=100 slotParams={0x1=[slotFlags=RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,PBE,ASKPW,EMPTY]}
EOF

    echo "-- installing the managed auto-select policy"
    if [[ ! -d "$POLICY_DIR" ]]; then
        die "policy dir missing: $POLICY_DIR (is Chrome for Testing installed?)"
    fi
    local clash
    clash="$(grep -l AutoSelectCertificateForUrls "$POLICY_DIR"/*.json 2>/dev/null || true)"
    if [[ -n "$clash" ]]; then
        echo "WARNING: $clash already sets AutoSelectCertificateForUrls;" \
            "Chrome merges managed files and one value wins -- verify the demo" >&2
    fi
    local policy_json
    policy_json="$(python3 -c 'import json,sys; print(json.dumps(
        {"AutoSelectCertificateForUrls": [json.dumps(
            {"pattern": sys.argv[1], "filter": {}})]}))' "$pattern")"
    echo "$policy_json" | sudo -n tee "$POLICY_DIR/$policy_name" >/dev/null
    echo "$POLICY_DIR/$policy_name" >"$workdir/policy-path"

    cat >"$workdir/env.sh" <<EOF
SOFTHSM2_CONF='$SOFTHSM2_CONF'
P11SCOPE_CLIENTAUTH_UPSTREAM='$softlib'
P11SCOPE_CLIENTAUTH_PIN='$pin'
CHROMIUM_CLIENTAUTH_HOME='$home'
CLIENTAUTH_PATTERN='$pattern'
EOF
    echo "-- ready: set -a; source $workdir/env.sh; set +a"
    echo "   token:  $label (PIN $pin) via $workdir/autologin-shim.so"
    echo "   policy: $POLICY_DIR/$policy_name for $pattern"
}

cmd_teardown() {
    local workdir="${1:-}"; [[ -n "$workdir" ]] || die "usage: $0 teardown <workdir>"
    local record="$workdir/policy-path"
    [[ -f "$record" ]] || die "no policy record in $workdir (already torn down?)"
    local policy_path
    policy_path="$(cat "$record")"
    case "$policy_path" in
        "$POLICY_DIR"/*.json) ;;
        *) die "refusing to remove non-policy path: $policy_path" ;;
    esac
    sudo -n rm -f "$policy_path" || die "sudo -n rm failed for $policy_path"
    rm -f "$record"
    echo "-- removed $policy_path"
}

cmd_check() {
    local workdir="${1:-}"; [[ -n "$workdir" ]] || die "usage: $0 check <workdir>"
    set -a
    # shellcheck disable=SC1091
    source "$workdir/env.sh"
    set +a
    [[ -f "$workdir/autologin-shim.so" ]] || die "shim missing (run setup?)"
    need_tool pkcs11-tool
    echo "-- objects visible WITHOUT login through the shim (expect cert + private key)"
    P11SCOPE_CLIENTAUTH_UPSTREAM="$P11SCOPE_CLIENTAUTH_UPSTREAM" \
        pkcs11-tool --module "$workdir/autologin-shim.so" \
        --token-label "${LABEL:-$LABEL_DEFAULT}" -O
}

cmd="${1:-}"; shift || true
case "$cmd" in
    setup) cmd_setup "$@" ;;
    teardown) cmd_teardown "$@" ;;
    check) cmd_check "$@" ;;
    *) die "usage: $0 {setup|teardown|check} <workdir>" ;;
esac
