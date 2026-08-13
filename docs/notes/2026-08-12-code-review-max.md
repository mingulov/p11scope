# Full-repo code review (`/code-review max`) — 2026-08-12

**Scope:** everything in the repo at `349cb39` (v0.1.0, 87 commits, 109 tests).
**Result:** 15 confirmed findings reported, plus 12 more cut only by the
report's 15-finding cap. **v0.1.0 is not clean.**

This closes the *first* of Gate G5's two human-triggered items. The whole-tool
`/security-review` remains OUTSTANDING.

## Status of verification

The reviewer confirmed several findings by building fixtures and running the
shipped binaries — those are marked **fixture-verified** below. After the
report landed I independently re-read the source for eight findings (4, 5, 6,
7, 8, 9, 14, 15); all eight hold exactly as described. Nothing in this report
is un-reproduced speculation, but the findings I have *not* personally
re-derived are marked as such.

## What this review does NOT invalidate

- `verify-attach-e2e.sh`'s 9/9 exact match checks **function** call counts,
  not mechanism counts. That result stands.
- `verify-oracle.sh`'s oracle ⊆ capture with 0 missed logged calls stands.
- The measured overhead and measured privilege numbers stand.

What is wrong is the *mechanism attribution* layered on top of the function
counts, the container-scope story, the discovery helper's identity handling,
and the strength of two gates.

---

## A. Wrong numbers, reported as correct

### A1. Stale mechanism binding inflates every mechanism's call count
`src/semantics.rs:340` — **re-verified**

Every non-close `SESSION_ARG0` call is billed to the session's active
mechanism, and one-shot terminators never clear that binding because
`is_final` (`semantics.rs:209`) only matches names ending in `"Final"` —
which `C_Sign`, `C_Verify`, `C_Encrypt`, `C_Decrypt` and `C_Digest` do not.

On **this project's own oracle workload** (`spike/harness.c:65-74`: 50×
`C_DigestInit`+`C_Digest`, then 100× `C_GenerateRandom` on the same session)
`mechanisms[0x250].calls` reports **200 instead of 100** — a 2× inflation —
with 100 RNG durations folded into the SHA-256 latency histogram, `total_ns`
and `max_ns`, and the same doubling mirrored in `cgroups[].mechanisms[]`.

`kinds.rs:22-32` puts `C_GenerateRandom`, `C_GetSessionInfo`, `C_FindObjects`,
`C_GetAttributeValue`, `C_DestroyObject` and `C_CopyObject` into that kind, so
any session that ever ran an `*Init` mis-attributes every later session call
for the rest of the capture.

### A2. `C_FindObjectsFinal` clears the cryptographic binding
`src/semantics.rs:209` — **re-verified**

Same bare `ends_with("Final")` suffix test. `C_SignInit(sess)` binds
`CKM_SHA256_RSA_PKCS`; the app runs an interleaved object search (legal in
PKCS#11); `C_FindObjectsFinal` is counted as a call *of the signing mechanism*
with the search's latency, **and** removes the binding. The following
`C_SignFinal` then hits the `None` arm and is counted in
`evidence.orphan_ops` — documented as evidence the capture started
mid-operation. The signing mechanism loses its terminating call and gains an
unrelated one.

### A3. `C_CloseAllSessions` is classified by the wrong argument
`src/kinds.rs:22` — **re-verified**

Classified `fnkind::SESSION_ARG0` ("session is arg0"), but its arg0 is a
`CK_SLOT_ID`. The BPF probe records a slot id as `Event.session`.

`is_close_session` matches only the literal `"C_CloseSession"`
(`semantics.rs:208`), so this teardown call takes the *operational* path keyed
by `(pid, slotID)`: with a slot id that collides with a live handle it is
charged to that session's active mechanism and `trace` prints a bogus
`sess#N`; otherwise it inflates `orphan_ops`. Either way `semantics.rs:329-335`
is the only site that removes from `open`, so an app cleaning up via
`C_CloseAllSessions` leaves `sessions.closed` at 0 and `balance`
(`render.rs:582`) reports **every session as leaked** — the exact diagnostic
the schema sells at `observed-profile-v1.md:286`.

### A4. Sessions are never retired; state grows without bound
`src/semantics.rs:263` — **re-verified**

Session state is reclaimed only by an explicit successful `C_CloseSession`.
`C_Finalize` classifies as `fnkind::OTHER` and is dropped; process exit is
never observed.

A service that forks a short-lived worker per request (`C_OpenSession` →
`C_SignInit`/`C_Sign` → `C_Finalize` → exit): after 10,000 requests
`open.len()` is 10,000, so `sessions.peak_concurrent` claims 10,000 concurrent
sessions and `balance` reports 10,000 leaked, when at most one was ever open.
`open`/`pseudonym_of`/`active_op`/`next_pseudonym` also retain one entry per
`(pid, handle)` for the whole capture — unbounded growth on any long-running
node-wide attach, with no eviction anywhere and `State` built once per capture
(`main.rs:251`, `main.rs:385`).

### A5. Failed logins are counted as successful
`src/semantics.rs:364` — **re-verified**

`observe_login` counts every observed `C_Login` regardless of `ev.rv`, while
`docs/schema/observed-profile-v1.md:296` defines `logins` as "the number of
**successful** `C_Login` calls seen with that user type."

A client retrying a wrong PIN 500 times (every call `CKR_PIN_INCORRECT`)
renders as `"logins": {"1": 500}`. Every sibling handler *does* gate on `rv`
(`semantics.rs:268`, `:318`, `:325-327`), and the only test hardcodes
`rv: 0` (`semantics.rs:533`), so the failing case is uncovered.

---

## B. Wrong scope, wrong address

### B1. `cgroup_level` is lexical; the kernel helper wants an absolute level
`src/scope.rs:32` — **re-verified**

`cgroup_level` counts path components under a hardcoded `/sys/fs/cgroup`, but
`bpf_get_current_ancestor_cgroup_id()` wants the cgroup's level in the
kernel's initial unified hierarchy.

Observer running inside a container with its own cgroup namespace — the design
spec's documented "privileged pod" placement — computes level 0 from
`--cgroup /sys/fs/cgroup` while the task's real `cgrp->level` is e.g. 2. The
helper returns the true root's id, `CGROUP_FILTER.get()` never hits,
`in_scope()` is false before any counter is touched, and the run renders an
empty table with **`completeness: COMPLETE`**.

Same silent zero for hybrid layouts (`/sys/fs/cgroup/unified/...`, off by one,
measured), for any path containing `..` (measured: `/sys/fs/cgroup/a/../a` → 3
vs true 1 — Rust's `Path::components()` normalizes `.` but not `..`), and for
cgroup v1 paths (a v1 inode is not a v2 cgroup id).

The doc comment at `scope.rs:21-26` asserts the opposite: "this cannot
disagree with what the BPF side computes." Every matrix test ran the observer
on the host in the initial namespace — the one configuration where the lexical
count is accidentally right.

### B2. Discovery resolves through the whole `DT_NEEDED` scope
`crates/discover/src/discover.rs:65` — **fixture-verified**

`module_anchor` resolves the module's own mapping via `dlsym` on the library
handle, which searches the whole dependency scope, so a thin wrapper provider
gets its dependency's function offsets recorded under the *wrapper's* path and
build-id.

Verified with a built fixture: `wrapper.so` (15,288 bytes, defines no
`C_GetFunctionList`, linked against `libsofthsm2.so`).
`p11scope-discover --module wrapper.so` emits a manifest with exactly one
object — wrapper.so, wrapper.so's build-id — while every `file_offset`
(`C_Initialize` = `0x265E0` = 157152) belongs to `libsofthsm2.so`, which
appears nowhere. `verify::check_reuse` passes (wrapper.so still hashes to
itself), and `attach.rs:110` then places uprobes at offset `0x265E0` of a 15 KB
file: past EOF here, or silently on unrelated instructions of a larger wrapper.
**Nothing compares the resolved mapping against the `--module` file.**

### B3. Manifest identity comes from the argv string, not the resolved mapping
`crates/discover/src/discover.rs:92` — **fixture-verified**

`ObjectTable::id` substitutes the verbatim `--module` argument for the resolved
mapping path without canonicalizing.

Verified by running the shipped helper: with an unrelated file named
`libsofthsm2.so` in the cwd,
`LD_LIBRARY_PATH=/usr/lib/softhsm p11scope-discover --module libsofthsm2.so`
exits 0 and writes `path: "libsofthsm2.so"` with the **decoy's** build-id
(`181a3de4…`) instead of the loaded library's (`f2080ee2…`), while every
`file_offset` came from the real SoftHSM. `check_reuse` re-hashes the decoy and
passes, then `attach.rs:110` hands the bare name to aya, which re-resolves it
independently (aya-0.14.0 `uprobe.rs` `is_basename_only`) — SoftHSM offsets
applied to whatever *that* lookup picks.

Without a decoy the same path yields identity `unavailable`/`reusable:false`,
so `profile` refuses a manifest that `discover` reported as success.

### B4. Short legacy tables are read out of bounds
`crates/discover/src/discover.rs:141` — **fixture-verified**

The legacy `CK_FUNCTION_LIST` walk always reads all 68 base fields regardless
of the version the table reports, via an unchecked `read_unaligned`.

Verified with a fixture returning a 67-pointer (pre-2.01 / malformed) table:
slot 68 read the adjacent `.data.rel.ro` word and the manifest recorded
`C_WaitForSlotEvent → Resolved{object: /usr/lib/x86_64-linux-gnu/libc.so.6,
file_offset: 710480}` — an attach plan that puts a uprobe on **libc's malloc,
process-wide**. With the table ending on a page boundary the helper died
SIGSEGV (exit 139).

The interface path IS bounded (`tables.rs`: `(2, _) => TableSet::Refuse`); the
legacy path reads the `CK_VERSION` at `discover.rs:139` as evidence only and
deliberately walks base-size regardless.

---

## C. Completeness verdict is wrong in both directions

### C1. A failed interface enumeration still renders COMPLETE
`src/render.rs:89` — not personally re-derived

`Evidence::verdict()` never consults `interface_list`. `discover.rs:158-159`
returns `(Acquisition::Error{detail}, vec![], vec![])`, so the manifest holds
only the legacy surface (walk `full`, acquisition `ok`), `surfaces_complete` is
true and `vendor_interfaces == 0`.

The document then emits `"interface_list": "error: ..."` adjacent to
`"completeness": "COMPLETE"`: interface-only functions (`C_LoginUser`,
`C_SessionCancel`, `C_MessageEncryptInit`…) were never planned, never attached
and never counted, yet the report asserts nothing was lost — contradicting
`plan.rs:29-31` ("so a manifest that never finished walking a surface can't be
reported as a complete capture"), because a surface whose *enumeration* failed
produces no `SurfaceSummary` row to be caught by.

### C2. Probe attach order guarantees a permanent PARTIAL
`src/attach.rs:99` — **re-verified**

`for prog_name in ["p11_entry", "p11_return"]` attaches all ~68 entry uprobes
before `p11_return` is even loaded. A call executing in that multi-millisecond
window bumps `entered` (`crates/ebpf/src/main.rs:218-221`) and inserts into
`START` (`:310`) with no uretprobe that can ever fire for it — a uretprobe
attached mid-call cannot hijack an already-pushed return address.

`in_flight = entered - returned` (`metrics.rs:63`) is then permanently nonzero
and `render.rs:92`'s `in_flight_at_end == 0` gate forces
`completeness: PARTIAL` on an otherwise clean capture, while the leaked keys
accumulate toward `START`'s 16384-entry ceiling (past which
`let _ = START.insert(...)` silently drops new calls with no counter of its
own).

**Fix is one line:** reverse the array to `["p11_return", "p11_entry"]` —
`main.rs:324-326` already returns early for a startless return.

---

## D. Gates that do not gate

### D1. The canary map dump is vacuous
`scripts/verify-canaries.sh:80` — not personally re-derived

The privacy gate dumps the BPF maps only after `wait "$WPID"`, when the two
maps that could ever hold per-call captured data (`START`, `EVENTS`) are
structurally empty: `p11_return` removes every `START` entry on return
(`crates/ebpf/src/main.rs:327`) and `EVENTS` is a ring buffer `bpftool` cannot
dump. The committed artifacts confirm it — `target/canaries/mapdump_START.json`
and `mapdump_EVENTS.json` are both `[]`. The remaining 8 dumps are
counter/config maps that by construction never hold argument bytes.

The suite still prints `=== canaries: NONE LEAKED ===`, and
`docs/notes/phase3-canaries.md:99-113` records the resulting claim that `START`
"carries a copy of every decoded scalar … the most direct check that nothing
beyond scalars and type codes ever reached kernel memory." **A BPF program that
wrote every sentinel into `START` on every call would pass identically.**

Compounding it: the mandatory positive control (`:189`) writes its sentinel as
raw ASCII, so the hex-reconstruction path — the only one that can find a
sentinel inside a `bpftool` dump — is never proven; and
`scripts/build-release.sh` never invokes `verify-canaries.sh` at all, though
`README.md:79` calls it a release gate.

### D2. `build.rs` can embed a stale BPF object
`build.rs:72` — reviewer-reproduced

The inner eBPF build is spawned without `--target-dir` but its artifact is
copied from a hardcoded `crates/ebpf/target/...` path.

Reproduced on this checkout: `CARGO_TARGET_DIR=<scratch> P11SCOPE_SMALL_RING=1
cargo check --lib` finished successfully — the inner build correctly produced
the small-ring object (md5 `e36c6479`) in the redirected dir, but `:76`'s
`fs::copy` embedded the **stale Aug-11 object** (md5 `abd0c6c1`) from
`crates/ebpf/target/`. `RING_BYTES` stayed 256 KiB instead of 4096, so Gate
G2's induced-gap test would silently fail to induce gaps.

The stale artifact exists right now
(`crates/ebpf/target/bpfel-unknown-none/release/p11scope-ebpf`, 7136 bytes,
Aug 11 22:12), is gitignored, and is not reached by `cargo clean`. There is no
freshness check, and the guard test at `src/main.rs:542` (len > 1000 + ELF
magic) passes on it.

Same class: `AYA_BUILD_SKIP=1` writes nothing to `OUT_DIR` (fails on a clean
tree, silently reuses a stale object on a dirty one), and `Cargo.lock`,
`rust-toolchain.toml` and `ebpf-common`'s `Cargo.toml` are absent from the
`rerun-if-changed` set.

---

## E. Coverage and release

### E1. Key-management mechanisms are structurally undecodable
`crates/ebpf/src/main.rs:287` — not personally re-derived

The mechanism argument is read only for the seven `*Init` names, so
`C_GenerateKey` (`TEMPLATE_ARG2`) and
`C_GenerateKeyPair`/`C_DeriveKey`/`C_WrapKey`/`C_UnwrapKey` (`SESSION_ARG0`)
are probed but their mechanism is never captured.

Run any app that calls `C_GenerateKey`: `functions[]` shows the calls,
`Event.mechanism` stays `MECH_NONE`, and `mechanisms[]` can never contain
`CKM_AES_KEY_GEN` — while
`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md:41` and `:100-103`
specify exactly that record. The `SESSION_ARG0` members are worse: a
`C_WrapKey` is attributed to whatever `*Init` mechanism is still bound on that
session (see A1), never to its own wrapping mechanism.

Nothing in `evidence` discloses the gap, and unlike the labels/CKA_ID
deviation recorded at outputs spec `:137`, this one is undocumented.

### E2. The released discovery helper cannot be invoked as documented
`scripts/build-release.sh:65` — **re-verified**

The release copies the helper as `p11scope-discover-glibc`/`-musl`, but both
documented ways to invoke it look for a binary named exactly
`p11scope-discover`.

Confirmed on disk: `dist/` holds `p11scope`, `p11scope-discover-glibc`,
`p11scope-discover-musl` — no `p11scope-discover`, and no `ln -s` anywhere in
`scripts/`. `README.md:29` and `docs/usage.md:58` tell the user to run
`p11scope-discover --module ... -o manifest.json` → command not found. The
fallback `dist/p11scope discover --module ...` fails too:
`discover_cmd.rs:43` and `:61` join the bare name `p11scope-discover` for both
the sibling and PATH lookup, so it exits 1 with "cannot execute discovery
helper; searched: …". The one escape hatch (`--helper`) and the
`p11scope discover` subcommand itself appear in no user doc — grep over
README/usage/CHANGELOG/notes returns zero matches.

---

## F. Confirmed but cut by the 15-finding report cap

All were marked CONFIRMED by the reviewer. Listed here so they are not lost.

1. **`src/main.rs:177`** — prints `"0/136 attach attempts failed"` when 136/136
   failed (wrong variable in the format string). The false text is copied
   verbatim into `docs/usage.md:162` and `docs/notes/phase5-unsupported.md:95`.
   *(Re-verified: the literal `0/{}` is in the source.)*
2. **`src/main.rs:436`** — discards every `trace -o` write/flush error, so a
   full disk truncates the trace silently at exit 0; and `println!` panics on
   EPIPE (`| head`), skipping the final drain and the mandatory `LOST` line.
3. **`src/trace.rs:130`** — emits raw pid/tid plus exact per-call latency,
   outside every written justification in the privacy allowlist — whose own
   weak-point #3 predicted exactly this.
4. **`docs/privacy/allowlist-v1.md`** — enforcement citations have drifted;
   ~22 line references now point at unrelated code, systematically in the three
   files the document designates as load-bearing.
5. **Kernel floor misattributed** — the ≥5.15 floor is credited to
   `bpf_get_current_ancestor_cgroup_id` (a 5.7 helper) in `usage.md`,
   `phase5-unsupported.md` and `p11scope --help`. It actually comes from
   `bpf_get_attach_cookie`, which both programs call on every probe regardless
   of scope.
6. **`CHANGELOG.md:12`** — says discovery "reads … straight from the ELF file"
   when it `dlopen`s and runs vendor constructors, contradicting
   `README.md:106`.
7. **`crates/discover/src/discover.rs:18`** — snapshots `/proc/self/maps`
   *before* the provider can lazily `dlopen` its backend (fixture-confirmed: 67
   unmapped entries, empty plan), and aborts entirely on one non-UTF-8 mapping
   anywhere in the process.
8. **`crates/discover/src/maps.rs:42`** — keeps `" (deleted)"` paths, so an
   unlinked co-resident object makes `verify::check_reuse` refuse the manifest
   with no pointer at the cause.
9. **`src/render.rs:284`** — types `capture.module` as a string in metrics mode
   but an object in profile mode.
10. **Stale-artifact reuse** lets `bench-overhead.sh` and
    `verify-fork-scope.sh` certify runs that never happened. The bench
    precondition is met on this checkout right now.
11. **`RC=$?` after `wait` under `set -e`** is dead code in
    `verify-fork-scope.sh` and `verify-oracle.sh`, orphaning a root observer
    with uprobes still attached.
12. **`spike/check.sh`** prints "ALL COUNTS MATCH" when given no arguments at
    all.

---

## Recommended fix order

1. **A1–A5 + C2** — the attribution cluster plus the one-line attach reorder.
   Contained diff, corrupts the headline output today.
2. **B1** — `cgroup_level`. Everything the matrix claims about containers rests
   on it, and the current tests pass only because they all ran in the initial
   namespace.
3. **D1** — re-arm the canary gate to sample maps *during* the workload, and
   make the positive control exercise the hex-reconstruction path. Until this
   is real, no privacy claim in the repo has evidence behind it, and no fix in
   the kernel path can be trusted.
4. **B2–B4** — the discover triad.
5. **C1, D2, E1, E2** and section F.

Item 3 gates items 1 and 4 in practice: both touch the BPF path, and the
suite that is supposed to catch a regression there currently cannot.
