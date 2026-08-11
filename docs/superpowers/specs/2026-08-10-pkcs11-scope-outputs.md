# pkcs11-scope — What you will see

**Date:** 2026-08-10 · **Status:** Draft, companion to the
[design spec](2026-08-10-pkcs11-scope-design.md). Examples are illustrative
mock-ups of v1 output; exact formatting will evolve, the *content* is the
commitment.

## CLI surface (v1)

```bash
# 1. One-time discovery: where are the provider's real functions?
p11scope discover --module /opt/vendor/lib/libpkcs11.so -o manifest.json
p11scope discover --module /usr/lib/softhsm/libsofthsm2.so --pid 12345 -o manifest.json
#   (--pid: resolve & run inside that process's mount view, e.g. a container)

# 2. Long-running aggregate observation (default mode: profile)
p11scope profile --manifest manifest.json --pid 12345 -o observed-profile.json
p11scope profile --manifest manifest.json --cmd 'myapp --sign-daemon' --duration 1h
p11scope profile --manifest manifest.json --cgroup /sys/fs/cgroup/kubepods.slice/... --mode metrics

# 3. Short detailed investigation (time-bounded, per-event)
p11scope trace --manifest manifest.json --pid 12345 --duration 30s
```

Targeting is explicit in v1: a module path plus `--pid`, `--cmd` (launch and
observe), or `--cgroup`. No magical system-wide discovery.

## Live summary (profile mode)

Refreshing terminal view while the capture runs:

```text
p11scope 0.1 — libsofthsm2.so (2.40) — pid 12345 — up 00:12:31 — mode profile
FUNCTION            CALLS     ERR    p50      p95      p99    IN-FLIGHT
C_Sign             12,840       7   2.1ms    4.8ms   11.2ms       3
C_SignInit         12,847       0    11µs     19µs     40µs       0
C_GetAttributeValue 3,301       3    711µs   1.4ms    2.9ms       0
C_OpenSession         119       0    88µs    140µs    210µs       0
C_WaitForSlotEvent      1       0      —        —        —        1  (since start)

Mechanisms: CKM_RSA_PKCS_PSS(SHA256/MGF1-SHA256/salt=32) ×12,833 · CKM_AES_KEY_GEN ×210
Errors:     CKR_DEVICE_ERROR ×7 (last 00:11:58) · CKR_SESSION_HANDLE_INVALID ×2
Sessions:   14 open (peak 22) · login USER ×3 · open/close balance +14
Evidence:   68/68 attached · 0 aliased · 0 non-file-backed · event loss 0
```

Answers at a glance: what is the app calling, how often, how slow, what fails,
what never returns (in-flight column — a hung `C_Sign` shows up here), and how
trustworthy the capture is (evidence line, always present).

## Trace mode (short investigations)

One line per completed call, in order, with safe metadata only:

```text
12:00:01.123456 pid 12345 tid 12401 sess#7 C_SignInit CKM_RSA_PKCS_PSS(hash=SHA256 mgf=MGF1_SHA256 salt=32) key=K3 → CKR_OK 18µs
12:00:01.123601 pid 12345 tid 12401 sess#7 C_Sign in_len=51 → CKR_OK 2.13ms
12:00:01.201115 pid 12345 tid 12402 sess#9 C_GetAttributeValue [CKA_VALUE] → CKR_ATTRIBUTE_SENSITIVE 92µs
12:00:01.288812 pid 12345 tid 12401 sess#7 C_CloseSession → CKR_OK 7µs
```

`sess#7` and `key=K3` are pseudonyms scoped to the capture — never raw handle
values. Buffer lengths appear only where safe-listed; buffer *contents* never
do, in any mode. If the ring buffer drops events, the trace ends with an
explicit `LOST n events` line — a trace never silently pretends completeness.

## observed-profile.json (the machine-readable deliverable)

Abbreviated but structurally faithful example:

```json
{
  "schema": "pkcs11-scope/observed-profile/v1",
  "capture": {
    "start": "2026-08-10T12:00:00Z", "end": "2026-08-10T13:00:00Z",
    "mode": "profile", "kernel": "6.8.0-45-generic",
    "module": { "path": "/usr/lib/softhsm/libsofthsm2.so",
                "build_id": "9f7c81…", "interface": "PKCS 11", "version": "2.40" }
  },
  "evidence": {
    "table_entries": 68, "attached": 68, "aliased": [], "non_file_backed": [],
    "event_loss": 0, "completeness": "COMPLETE",
    "caveats": ["capture window did not include key-rotation or DR procedures"]
  },
  "functions": {
    "C_Sign":  { "calls": 12840, "errors": { "CKR_DEVICE_ERROR": 7 },
                 "latency_us": { "p50": 2100, "p95": 4800, "p99": 11200 } },
    "C_Login": { "calls": 3, "user_type": "CKU_USER", "errors": {} }
  },
  "mechanisms": [
    { "mechanism": "CKM_RSA_PKCS_PSS", "ops": ["sign"], "calls": 12833,
      "params": { "hash": "SHA256", "mgf": "MGF1_SHA256", "salt_len": 32 } },
    { "mechanism": "0x80001042", "ops": ["encrypt"], "calls": 4,
      "params": null, "note": "vendor-defined; params not decoded (not in registry)" }
  ],
  "attributes": {
    "requested_types": ["CKA_KEY_TYPE", "CKA_MODULUS_BITS"],
    "sensitive_denied": [ { "type": "CKA_VALUE", "rv": "CKR_ATTRIBUTE_SENSITIVE", "count": 3 } ]
  },
  "templates": [
    { "op": "C_GenerateKey", "mechanism": "CKM_AES_KEY_GEN", "calls": 210,
      "requested": { "CKA_TOKEN": true, "CKA_EXTRACTABLE": false } }
  ],
  "concurrency": { "sessions_peak": 22, "sign_ops_peak": 8 }
}
```

This is the integration boundary: `pkcs11-lab` joins it with `pkcs11-check`
results to produce the migration assessment categories from the original
analysis (OBSERVED AND VALIDATED / OBSERVED BUT CANDIDATE DIFFERED / OBSERVED
BUT NOT COVERED / TESTED BUT NOT OBSERVED / UNKNOWN). Everything those
categories need is present: exact mechanisms + parameters, attribute usage,
template policy requests, error distributions, and the evidence section that
keeps "UNKNOWN" honest.

## Questions it answers (worked examples)

- *"This app intermittently fails against our HSM — what is it doing?"* →
  trace mode: the failing call, its CK_RV, what preceded it, per-thread
  ordering, latency of each step.
- *"What must a replacement provider support before we migrate?"* → profile
  mode over a representative window → the mechanisms/params/attributes lists
  above, fed to pkcs11-check/pkcs11-lab.
- *"Is the app leaking sessions / hammering login?"* → session open/close
  balance, login frequency, concurrency peaks.
- *"Is the provider or the app slow?"* → per-function, per-mechanism latency
  percentiles; a `C_Sign` p99 of 11ms against a network HSM is a very
  different conversation than 40µs against SoftHSM.
- *"Did the app ask for extractable keys?"* → template section — reported as
  *requested* attributes, deliberately not as effective key policy (the
  provider may override; verifying effective policy is pkcs11-check's job).

## What you will NOT see (by design, in every mode)

PINs, key material, `CKA_VALUE` contents, plaintext, ciphertext, signatures,
wrapped blobs, random output, operation-state blobs, raw mechanism byte
arrays, raw handle values. **Update, post-implementation (v0.1.0):** this
draft originally sketched Labels/`CKA_ID` as available "behind an explicit
opt-in flag" — the shipped tool is stricter than that sketch: it refuses
both outright, with no flag of any kind that reveals them (see
[`docs/privacy/allowlist-v1.md`](../../privacy/allowlist-v1.md)). There is
no flag combination that dumps buffers. A profile describes the observed
window only — it is evidence of what the app *did*, never proof of what it
*cannot do*.
