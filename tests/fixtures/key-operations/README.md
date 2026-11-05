<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# RSA application fixture and ledger

`rsa-ledger.c` prepares the application side of the future key-operation
qualification. It executes real RSA with a PKCS#11 provider and emits a
bounded JSONL ledger. It does not start an observer or establish object
bootstrap, journal authority or capture qualification.

The current cell is Linux x86-64 LP64 with one disposable initialized SoftHSM
token. Compilation needs `gcc` and an actual `pkcs11.h`; a system header or
the cached `cryptoki-sys` vendor header works. Named `CK_FUNCTION_LIST` members
come from that header; no function-table ordinals are recreated. The Python
test discovers these headers locally and reports a skip if a prerequisite is
absent. It downloads nothing and runs no Rust build.

The driver loads the module, publishes `header` and `ready`, then waits for
one `G` byte on stdin before its first PKCS#11 call. After all calls and
cleanup it publishes `done` and waits for `F`, retaining the same process and
provider mapping. These are application control barriers. They are not H8
birth witnesses. The absolute deadline is 30 seconds across both barriers
and all work; `P11SCOPE_KEY_FIXTURE_TIMEOUT_MS` may select 1-90,000 ms. It
never extends a deadline while waiting. The controller must also own/reap
the child and require its successful exit.

The fixed workload generates an RSA-2048 **session** key pair, queries class,
key type, token and modulus-bit attributes before use, then performs:

- Seven successful one-shot signs and three successful multipart signs.
- A null-output size query, `CKR_BUFFER_TOO_SMALL` and successful retry within
  the first sign operation, with one Init and one completion.
- Three Updates for each multipart sign, followed by one SignFinal.
- Ten valid verifies, covering every returned signature, plus two verifies
  of deliberately corrupted signatures. Each verify has a new Init.
- Explicit destruction of both session objects, logout, close and finalize.

The positive denominator is ten completed sign operations, ten completed
verify operations and two failed verify operations. There are 68 application
API calls including setup, metadata and cleanup; `C_Sign` occurs nine times,
`C_SignUpdate` nine times and `C_Verify` twelve times. Query/retry calls do not
add operations. These counts exclude the separate token-initialization
utility; a future observer controller must define its own window and preserve
that distinction.

All JSONL rows have a contiguous `seq` and finite `kind`. Marker, metadata,
operation and summary rows have `time_ns`; call rows carry independent
monotonic `start_ns`/`end_ns`, exact function name, CK_RV, phase and local
operation number (zero for setup/metadata/cleanup). No PID or handle is an
operation identifier. The kinds are:

| Kind | Application fact |
| --- | --- |
| `header` | Version 1, LP64, SHA256-RSA mechanism and exact safe creation requests |
| `ready` / `go` | Application control progression |
| `call` | One returned provider invocation, with its result and phase |
| `metadata` | Separately queried finite provider attributes for public/private member |
| `operation` | Begin/end of one local sign/verify; verify names its local sign origin |
| `done` | Convenience counters, independently checked against the preceding calls |

Creation requests and established provider observations stay separate. A
private-key modulus-bit query may be unsupported even when the public member
reports 2048. That private field remains explicitly unknown; the oracle never
copies the request or public member into it. Public class/type/token/2048-bit
metadata and private class/type/token metadata are required for this cell.
Provider queries may return the permitted partial-attribute errors while
preserving usable neighbors.

No PIN, raw handle, key material, message, signature, pointer, arbitrary
attribute bytes or label appears in the ledger or driver diagnostics. The
generated keys are nonpersistent and private material is never exported.
Failure cleanup calls are logged, and a failed call stream has no `done`.
The oracle validates the application's self-reports; it cannot independently
prove the behavior of a dishonest provider or an edited ledger.

Run the focused controls from the repository root:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/python -p test_key_operation_ledger.py
```

For a manual disposable SoftHSM run, set `PKCS11_HEADER_DIR` to the directory
containing the actual header, then:

```sh
set -eu
export TMPDIR=/var/tmp/p11scope-ws-tmp
key_work=$(mktemp -d "$TMPDIR/p11scope-key-ledger.XXXXXX")
trap 'rm -rf "$key_work"' EXIT
mkdir -m 700 "$key_work/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
  "$key_work/tokens" > "$key_work/softhsm2.conf"
chmod 600 "$key_work/softhsm2.conf"
export SOFTHSM2_CONF="$key_work/softhsm2.conf"
softhsm2-util --init-token --free --label key-ledger --so-pin 5678 --pin 1234
gcc -std=c11 -O2 -Wall -Wextra -Werror -I "$PKCS11_HEADER_DIR" \
  tests/fixtures/key-operations/rsa-ledger.c -ldl -o "$key_work/rsa-ledger"
printf GF | P11SCOPE_KEY_FIXTURE_PIN=1234 "$key_work/rsa-ledger" \
  /usr/lib/softhsm/libsofthsm2.so > "$key_work/application.jsonl"
python3 scripts/key-operation-ledger.py "$key_work/application.jsonl"
```

The example credentials are for this temporary token. Generated binaries,
token files and ledgers are disposable. Do not run this workload concurrently
with a SYSTEM-scoped observer qualification using the same physical provider;
its application calls would contaminate that population.
