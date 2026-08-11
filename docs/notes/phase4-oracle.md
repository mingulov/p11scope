# Phase 4 Task 7 — `pkcs11-check` oracle diff

Every other verification script in this repo checks p11scope's capture
against a workload **we** wrote (`spike/harness.c` + `spike/expected.txt`).
`scripts/matrix/verify-oracle.sh` is the first check against an
**independent** implementation's own record of what it did:
[`pkcs11-check`](/home/user/src/m/pkcs11-check-ws/pkcs11-check), a
separate, vendor-neutral PKCS#11 test client with its own pure-ctypes
binding and its own per-call `CK_RV` trace feature
(`docs/rv-trace-design.md` in that repo, `--rv-trace`).

## How it was driven

- Target: SoftHSM2, a private/disposable token
  (`target/matrix-oracle/softhsm2.conf`, `--label oracle`).
- Selection: `--marker smoke` (the fast slice; ~27 real tests, most of the
  remaining 257 files in the full 284-file collection deselect
  everything for this marker and just pay subprocess start-up cost).
- Isolation: `--isolation file` — one subprocess per test **file**
  (`core/file_runner.py`), which is exactly the shape Task 7's brief
  calls out: many `C_Initialize`/`C_Finalize` cycles, many PIDs, most of
  which do not exist yet when the observer attaches.
- Trace: `--rv-trace`, `--output json --output-file .../results.json`
  (`report.jsonl` lands next to `results.json`).
- Invocation: the venv's own installed console script
  (`$PKCS11_CHECK_DIR/.venv/bin/pkcs11-check`), **not** `uv run` — see
  "A third thing found: `uv` is a snap" below.
- Scope: a `systemd-run --scope --unit=p11scope-oracle-$$` cgroup, created
  (and therefore attachable) **before** pkcs11-check is even exec'd — the
  same attach-before-run + go-file gating pattern every other script in
  this repo uses, just with `--cgroup` in place of `--pid`.
- Measured run: 284 files, ~90-100s real wall time, 17 tests carried a
  non-empty `CK_RV` trace, 40 real calls logged across 10 distinct
  `(function, CK_RV)` pairs (after excluding the one known
  misattribution — see below). `evidence.completeness == COMPLETE`,
  `attached_probes == 136` (68 slots × entry+return).

## The two documented caveats (handled explicitly, per the brief)

Both are stated as comments directly in `scripts/matrix/verify-oracle.sh`,
not silently filtered out of the numbers:

1. **rv-trace resets per test after bootstrap + `C_Login`.** Every test's
   bootstrap-phase calls land in the capture (p11scope sees literally
   everything) but never in the oracle. Because the assertion direction
   is **oracle ⊆ capture**, this is tolerable *by construction*:
   bootstrap calls can only ever add entries on the capture side, which
   can never make an oracle-side key come up missing. They show up as
   informational capture-only surplus (58 function names with
   oracle-logged-count 0 on this run — `C_CloseSession: 17`,
   `C_Finalize: 4`, and 56 more with `calls=0`), never as a failure.
2. **`--isolation file` spawns many subprocesses.** `--pid` would only
   ever see the first one. `--cgroup`, with Task 1's descendant matching,
   sees all of them regardless of when they were forked relative to
   attach.

## Two things found while building this that weren't in the brief

### A real infra gotcha: `uv` is a snap package

The first real run captured **zero** calls of any kind (`0/136` probes
firing on real activity, `attached_probes: 136` but every function count
`0`), despite `evidence.completeness: COMPLETE`. Root-caused by checking
`systemctl status`/`journalctl` on the scope unit mid-run: `uv run
pkcs11-check test ...` under the `systemd-run --scope` cgroup shows the
unit as **`Deactivated successfully` within the same second it starts**,
even though the real workload (verified via the growing log file) keeps
running correctly for the full ~90s. `uv` on this host is a **snap
package** (`/snap/bin/uv`); snap's confinement machinery (`snap-confine`)
moves the process into its own systemd-managed cgroup independent of
whatever cgroup it was launched under, orphaning our target scope with
zero member processes (systemd garbage-collects an empty transient scope
immediately). Reproduced in isolation: `uv run python3 -c "import time;
time.sleep(15)"` under the exact same wrapper shows the identical
`Deactivated successfully` timing, while `sleep 30` (a plain, non-snap
binary) and the venv's own `.venv/bin/python3` (no snap involved) both
stay in the target cgroup for the full duration — confirmed directly by
reading `cgroup.procs` mid-run.

**Fix:** invoke the venv's own installed console script directly
(`$PKCS11_CHECK_DIR/.venv/bin/pkcs11-check`), never `uv run`. `uv sync`
must already have been run in that directory (it has been); the script
only ever reads the resulting `.venv`.

### A second real gotcha: stale isolation-resume state

An earlier attempt (before the `uv`/snap fix was even isolated) showed a
suspicious **exact 2×** overcount for six functions
(`C_GenerateKey`/`C_EncryptInit`/`C_Encrypt`/`C_DecryptInit`/`C_Decrypt`/
`C_DestroyObject`), which raised (and, once the state file was cleared and
the mismatch persisted identically, ruled out) `file_runner.py`'s
resume/checkpoint file
(`.pkcs11-check-isolation-state.json`/`-policy.json`, left over from
earlier manual runs in the same directory during development of this
script) as the cause. The script now clears both files before every run
regardless, since a stale one *could* fold old, out-of-window results into
a new run's `report.jsonl` — a real risk even though it wasn't the
explanation this time. Comment + `rm -f` are in the script.

## The one real discrepancy found, investigated, and why it's excluded

With both fixes above in place, the mechanical `oracle ⊆ capture` diff
still reported six `(function, CK_RV)` mismatches, all at exactly the
capture-is-half-of-oracle ratio, all belonging to the same 8-call
sequence (`C_GenerateKey → C_EncryptInit → C_Encrypt ×2 → C_DecryptInit →
C_Decrypt ×2 → C_DestroyObject`):

```
FAIL oracle-only: C_Decrypt 0x00000000: oracle logged 4, capture has 2
FAIL oracle-only: C_DecryptInit 0x00000000: oracle logged 2, capture has 1
FAIL oracle-only: C_DestroyObject 0x00000000: oracle logged 2, capture has 1
FAIL oracle-only: C_Encrypt 0x00000000: oracle logged 4, capture has 2
FAIL oracle-only: C_EncryptInit 0x00000000: oracle logged 2, capture has 1
FAIL oracle-only: C_GenerateKey 0x00000000: oracle logged 2, capture has 1
```

**Root cause, verified directly (not guessed):** `report.jsonl` carried
this exact trace on **two** adjacent teardown records —
`TestInterfaceV30::test_v30_encrypt_decrypt_aes` and
`TestInterfaceV32::test_v32_interface_negotiated` — in
`src/pkcs11_check/testcases/test_interface.py`. Reading
`test_v32_interface_negotiated`'s own source:

```python
def test_v32_interface_negotiated(self, p11_interface_version: str) -> None:
    """Module has negotiated v3.2 interface."""
    if p11_interface_version != "3.2":
        pytest.skip("module did not negotiate v3.2")
    assert p11_interface_version == "3.2", f"Expected v3.2 but got v{p11_interface_version}"
```

`p11_interface_version` (`fixtures.py:138-141`) is a session-scoped
fixture that returns an already-cached plain `str` — no PKCS#11 module
handle is ever in scope in this test's body. **It is physically incapable
of making a `C_*` call.** Its recorded trace is pkcs11-check's own
rv-trace attributing one physical call sequence (test_v30's) to two
adjacent node IDs — an oracle-side bookkeeping artifact, not a p11scope
capture gap.

Independent confirmation that the capture is the correct side: `functions`
counts are sourced from the aggregate BPF maps, documented as the count
authority and "never subject to ring-buffer loss"
(`docs/schema/observed-profile-v1.md`), and every *other*
`(function, CK_RV)` pair in this run — `C_CloseSession`, `C_OpenSession`,
`C_Login`, `C_Logout`, `C_GenerateRandom`, `C_GetMechanismInfo`,
`C_GetMechanismList`, `C_GetTokenInfo`, and this same 8-call sequence's
single real execution — matched or exceeded the oracle exactly. If
p11scope were dropping calls under load, it would not drop *exactly* one
full occurrence of a specific 8-call group while getting every other call
across a 90-second, 284-file run exactly right.

**Handling:** `scripts/matrix/verify-oracle.sh` excludes this exact
node ID by name (not by pattern — see the comment at the exclusion site),
still counts and prints it, and states the full chain of evidence inline.
This is the same "explicit, not silently dropped" treatment the two
documented caveats get, extended to a third, previously-undocumented
artifact this run discovered on its own. If pkcs11-check fixes the
misattribution upstream, the exclusion becomes inert (there will be
nothing at that node ID to exclude).

## Result

```
oracle: 17 tests carried a CK_RV trace, 10 distinct (function, CK_RV) pairs, 40 total calls logged
oracle: excluded 1 teardown record(s) matching a known oracle-side misattribution nodeid
oracle subset-of capture: every (function, CK_RV) pair pkcs11-check logged is present in the capture at least as many times
evidence: 136 probes, COMPLETE
=== oracle: ALL OK ===
```

`scripts/matrix/verify-oracle.sh` exits 0. Re-run twice for reproducibility
(both runs above are from independent, fresh invocations) with identical
results.
