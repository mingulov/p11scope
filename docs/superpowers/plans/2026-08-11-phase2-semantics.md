# Phase 2 — Semantic state machine + `profile` mode + schema v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn per-function counts into *meaning* — which mechanism each operation used, how sessions were opened and closed, what login type was seen — and emit it as a versioned `observed-profile.json` whose evidence section keeps every gap honest.

**Architecture:** The entry probe stashes the call's semantic arguments (session handle, mechanism id, login user type, out-pointer) alongside its timestamp; the return probe pops that, adds `CK_RV` and duration, and emits **one complete event per call** into a ring buffer. Userspace drains the ring buffer, pseudonymizes handles, and drives a per-(process, session) state machine that produces the profile. Aggregate maps from Phase 1b stay exactly as they are — they remain the authority for counts and in-flight, and cross-check the event stream.

**Tech Stack:** As Phase 1b (aya `=0.14.0`, aya-ebpf `=0.2.1`), plus `aya::maps::RingBuf` and `aya_ebpf::maps::RingBuf`.

## Global Constraints

- **Privacy is structural, not a feature.** BPF may read: the session handle (an opaque `CK_ULONG`), the mechanism *type* (`CK_MECHANISM.mechanism`), and the login *user type*. BPF must **never** read `pPin`, `pParameter` contents, key material, data buffers, or any attribute value. Mechanism *parameters* are Phase 3 (they need the allowlist and the canary suite first).
- **Raw handles never appear in output.** Session and object handles are pseudonymized in userspace (`sess#1`, `key#3`) per (pid, module). The mapping table is never written to any artifact.
- Vendor mechanism ids are preserved **verbatim** (e.g. `0x80001042`), never dropped or normalized — Gate G2 requires this for the OBSERVED BUT NOT COVERED category.
- Aggregate maps remain the count authority. If the event stream and the aggregates disagree, the report says so; events are the lossy channel, never silently trusted over the maps.
- Ring-buffer loss is counted and reported. A capture that dropped events can never read `COMPLETE`.
- The evidence widening from Phase 1b's final review carries forward: surface walk/acquisition provenance and vendor-interface presence are already gap conditions and must remain so.
- Kernel floor stays 5.15 (`BPF_MAP_TYPE_RINGBUF` is 5.8; cookies 5.15 — the floor is already the binding one).
- Edition 2024 / rust-version 1.88 for workspace crates; `crates/ebpf*` stay edition 2021.
- Commit style: short prefix + imperative (`ebpf-common:`, `ebpf:`, `scope:`, `plan:`).
- The full workspace suite (44 tests at Phase 1b close) stays green at every commit, and `scripts/verify-attach-e2e.sh` must still end `=== e2e: ALL OK ===`.

## Inherited facts (verified, do not re-derive)

- Phase 1b HEAD is `2b8e3df`; 44 tests green; e2e verified independently by the controller: 9/9 oracle functions exact, 136/136 probes, COMPLETE.
- `UProbeAttachLocation::AbsoluteOffset` takes ELF **file offsets** (pinned, `docs/notes/aya-offset-semantics.md`).
- The attach cookie carries the slot index; one uprobe + one uretprobe serve every slot. `MAX_SLOTS = 256`.
- `ctx.tgid()` is the userspace PID; `ctx.pid()` is the thread id (this bit the project once — do not regress it).
- `RetProbeContext::ret::<T>()` returns `T` directly (not `Option<T>`) in aya-ebpf 0.2.1.
- x86-64 PKCS#11 ABI facts the arg capture depends on:
  - `C_DigestInit(hSession, pMechanism)`; `C_{Sign,Verify,Encrypt,Decrypt}Init(hSession, pMechanism, hKey)` — mechanism pointer is **arg 1**.
  - `CK_MECHANISM { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; }` — `mechanism` is the first 8 bytes at offset 0.
  - `C_OpenSession(slotID, flags, pApplication, Notify, phSession)` — the session handle is written to the **arg 4** out-pointer, so it is only readable in the *return* probe via a pointer stashed at entry.
  - `C_CloseSession(hSession)`, `C_Digest(hSession, …)`, `C_Sign(hSession, …)` — session is **arg 0**.
  - `C_Login(hSession, userType, pPin, ulPinLen)` — `userType` is **arg 1**; `pPin` (arg 2) must never be touched.
- `spike/harness.c` is the Phase 2 oracle as well as Phase 1b's: it performs exactly 10 `C_OpenSession` + 10 `C_CloseSession`, and 50 × (`C_DigestInit` with `CKM_SHA256` = `0x250`, then `C_Digest`) on one session. No login, no token objects.

---

### Task 1: Event and argument types in `crates/ebpf-common`

**Files:**
- Modify: `crates/ebpf-common/src/lib.rs`

**Interfaces:**
- Produces: `FnKind` (u32-valued consts, not a Rust enum — it crosses the map boundary), `CallStart`, `Event`, `MECH_NONE`, `SESSION_NONE`, `USER_TYPE_NONE`, `RING_BYTES`, `PHASE_*` if needed. Tasks 2–6 consume all of them.

The existing `START` map value changes from `u64` to `CallStart`; that is an internal ABI both sides share, so both change together.

- [ ] **Step 1: Add the types**

Append to `crates/ebpf-common/src/lib.rs` (keep everything already there unchanged):

```rust
/// What a slot's function *is*, semantically. Userspace classifies each
/// slot from the manifest's names and publishes this into SLOT_KIND; the
/// BPF programs switch on it to decide which arguments are safe to read.
/// A plain u32 rather than a Rust enum: it crosses the map boundary, and
/// an unknown value must degrade to "no capture", never to UB.
pub mod fnkind {
    pub const OTHER: u32 = 0;
    /// (hSession, pMechanism) — read mechanism type from arg1.
    pub const INIT_WITH_MECH: u32 = 1;
    /// (slotID, flags, pApp, notify, phSession) — session via arg4 out-pointer.
    pub const OPEN_SESSION: u32 = 2;
    /// (hSession, ...) — session is arg0.
    pub const SESSION_ARG0: u32 = 3;
    /// (hSession, userType, pPin, ulPinLen) — userType from arg1. pPin is
    /// NEVER read, in any mode, at any privilege.
    pub const LOGIN: u32 = 4;
}

/// Sentinels. Zero is a legal PKCS#11 value for some of these, so absence
/// gets its own out-of-band marker.
pub const MECH_NONE: u64 = u64::MAX;
pub const SESSION_NONE: u64 = u64::MAX;
pub const USER_TYPE_NONE: u32 = u32::MAX;

/// Ring buffer capacity in bytes. Must be a power of two and page-aligned.
/// 256 KiB holds ~2700 events; the induced-gap test (Task 7) overrides it
/// to force loss deliberately.
pub const RING_BYTES: u32 = 256 * 1024;

/// What the entry probe stashes until the matching return. Replaces the
/// bare timestamp Phase 1b stored.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CallStart {
    pub ts_ns: u64,
    pub session: u64,
    pub mechanism: u64,
    /// `phSession` for C_OpenSession; 0 otherwise. Read only at return.
    pub out_ptr: u64,
    pub user_type: u32,
    pub _pad: u32,
}

/// One completed call. Emitted at return only: a call with no return is
/// visible as in-flight in the aggregate maps, never as a partial event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub ts_ns: u64,
    pub duration_ns: u64,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    /// Raw handle. Pseudonymized in userspace; never written to output.
    pub session: u64,
    pub mechanism: u64,
    pub rv: u64,
    pub slot: u32,
    pub kind: u32,
    pub user_type: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CallStart {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
```

- [ ] **Step 2: Test the layout invariants**

Add to the existing `mod tests`:

```rust
    #[test]
    fn event_and_callstart_have_no_implicit_padding() {
        // Both cross the kernel/userspace boundary as raw bytes; implicit
        // tail padding would read as uninitialized on one side.
        assert_eq!(core::mem::size_of::<CallStart>(), 8 * 4 + 4 + 4);
        assert_eq!(core::mem::size_of::<Event>(), 8 * 7 + 4 * 4);
        assert_eq!(core::mem::align_of::<Event>(), 8);
    }

    #[test]
    fn ring_bytes_is_page_aligned_power_of_two() {
        assert!(RING_BYTES.is_power_of_two());
        assert_eq!(RING_BYTES % 4096, 0);
    }

    #[test]
    fn sentinels_do_not_collide_with_real_values() {
        // CKM_SHA256 = 0x250, CKU_USER = 1, session handles are small.
        assert_ne!(MECH_NONE, 0x250);
        assert_ne!(USER_TYPE_NONE, 1);
        assert_ne!(SESSION_NONE, 0);
    }
```

- [ ] **Step 3: Run and commit**

Run: `cargo test -p p11scope-ebpf-common --features user` → all pass.

```bash
git add -A
git commit -m "ebpf-common: event, call-start, and function-kind types"
```

---

### Task 2: Classify slots into function kinds (userspace)

**Files:**
- Create: `src/kinds.rs`
- Modify: `src/lib.rs` (module decl), `src/plan.rs` (attach `kind` to each Slot)

**Interfaces:**
- Consumes: `p11scope_ebpf_common::fnkind`.
- Produces: `kinds::classify(name: &str) -> u32`; `plan::Slot` gains `pub kind: u32`. Tasks 3–6 consume `Slot::kind`.

An aliased slot carries several names. If they classify differently, the slot must degrade to `OTHER` — reading arg1 as a mechanism pointer when the real function takes a PIN there would be a privacy incident, so ambiguity always loses.

- [ ] **Step 1: Write the classifier with its tests**

`src/kinds.rs`:

```rust
//! Function name → semantic kind. Drives which arguments the BPF programs
//! may read. Anything unrecognized is OTHER (no argument capture), and an
//! aliased slot whose names disagree degrades to OTHER: reading the wrong
//! argument shape could touch a PIN pointer, so ambiguity never guesses.

use p11scope_ebpf_common::fnkind;

pub fn classify(name: &str) -> u32 {
    match name {
        "C_DigestInit" | "C_SignInit" | "C_VerifyInit" | "C_EncryptInit"
        | "C_DecryptInit" | "C_SignRecoverInit" | "C_VerifyRecoverInit" => fnkind::INIT_WITH_MECH,
        "C_OpenSession" => fnkind::OPEN_SESSION,
        "C_Login" => fnkind::LOGIN,
        // Session is arg0 for the operational entry points we care about.
        "C_CloseSession" | "C_CloseAllSessions" | "C_Logout" | "C_GetSessionInfo"
        | "C_Digest" | "C_DigestUpdate" | "C_DigestFinal"
        | "C_Sign" | "C_SignUpdate" | "C_SignFinal"
        | "C_Verify" | "C_VerifyUpdate" | "C_VerifyFinal"
        | "C_Encrypt" | "C_EncryptUpdate" | "C_EncryptFinal"
        | "C_Decrypt" | "C_DecryptUpdate" | "C_DecryptFinal"
        | "C_GenerateKey" | "C_GenerateKeyPair" | "C_WrapKey" | "C_UnwrapKey"
        | "C_DeriveKey" | "C_GenerateRandom" | "C_SeedRandom"
        | "C_FindObjectsInit" | "C_FindObjects" | "C_FindObjectsFinal"
        | "C_GetAttributeValue" | "C_SetAttributeValue"
        | "C_CreateObject" | "C_CopyObject" | "C_DestroyObject" => fnkind::SESSION_ARG0,
        _ => fnkind::OTHER,
    }
}

/// A slot's kind: the shared kind of all its names, or OTHER when they
/// disagree.
pub fn classify_slot(names: &[String]) -> u32 {
    let mut it = names.iter().map(|n| classify(n));
    match it.next() {
        None => fnkind::OTHER,
        Some(first) => {
            if it.all(|k| k == first) { first } else { fnkind::OTHER }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_shapes_classify() {
        assert_eq!(classify("C_DigestInit"), fnkind::INIT_WITH_MECH);
        assert_eq!(classify("C_SignInit"), fnkind::INIT_WITH_MECH);
        assert_eq!(classify("C_OpenSession"), fnkind::OPEN_SESSION);
        assert_eq!(classify("C_Login"), fnkind::LOGIN);
        assert_eq!(classify("C_Digest"), fnkind::SESSION_ARG0);
        assert_eq!(classify("C_Initialize"), fnkind::OTHER);
        assert_eq!(classify("C_WhoKnows"), fnkind::OTHER);
    }

    #[test]
    fn ambiguous_alias_degrades_to_other() {
        // C_Login takes a PIN pointer where an *Init takes a mechanism.
        // Guessing here would be a privacy incident, so it must not guess.
        let names = vec!["C_Login".to_string(), "C_SignInit".to_string()];
        assert_eq!(classify_slot(&names), fnkind::OTHER);
    }

    #[test]
    fn agreeing_alias_keeps_the_kind() {
        let names = vec!["C_SignInit".to_string(), "C_VerifyInit".to_string()];
        assert_eq!(classify_slot(&names), fnkind::INIT_WITH_MECH);
    }

    #[test]
    fn single_name_slot_uses_its_kind() {
        assert_eq!(classify_slot(&["C_OpenSession".to_string()]), fnkind::OPEN_SESSION);
        assert_eq!(classify_slot(&[]), fnkind::OTHER);
    }
}
```

- [ ] **Step 2: Carry the kind on Slot**

In `src/plan.rs`: add `pub kind: u32` to `Slot`, set it in `build` via `crate::kinds::classify_slot(&names)` (after the sort/dedup), and extend the existing plan tests to assert an `C_OpenSession` slot gets `fnkind::OPEN_SESSION`.

- [ ] **Step 3: Run and commit**

Run: `cargo test --workspace` → all green.

```bash
git add -A
git commit -m "scope: classify slots into semantic function kinds"
```

---

### Task 3: BPF argument capture and event emission

**Files:**
- Modify: `crates/ebpf/src/main.rs`

**Interfaces:**
- Produces: two new maps by exact name — `SLOT_KIND` (`Array<u32>`, `MAX_SLOTS` entries) and `EVENTS` (`RingBuf`, `RING_BYTES`); `START`'s value type becomes `CallStart`; a `LOST` counter (`PerCpuArray<u64>`, 1 entry) incremented when a ring-buffer reservation fails. Tasks 4–6 read these.

- [ ] **Step 1: Add the maps**

```rust
use aya_ebpf::maps::RingBuf;
use p11scope_ebpf_common::{CallStart, Event, MECH_NONE, RING_BYTES, SESSION_NONE, USER_TYPE_NONE, fnkind};

#[map]
static SLOT_KIND: Array<u32> = Array::with_max_entries(MAX_SLOTS, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

/// Events that could not be reserved. A capture that dropped events must
/// never read COMPLETE, so this is reported, not swallowed.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
```

Change `START` to `HashMap<StartKey, CallStart>`.

- [ ] **Step 2: Capture arguments at entry**

In `p11_entry`, after the existing bounds/scope checks and the `entered` increment, replace the bare timestamp insert with:

```rust
    let kind = SLOT_KIND.get(slot).copied().unwrap_or(fnkind::OTHER);
    let mut start = CallStart {
        ts_ns: unsafe { helpers::bpf_ktime_get_ns() },
        session: SESSION_NONE,
        mechanism: MECH_NONE,
        out_ptr: 0,
        user_type: USER_TYPE_NONE,
        _pad: 0,
    };
    match kind {
        fnkind::INIT_WITH_MECH => {
            // (hSession, pMechanism, [hKey]) — mechanism TYPE only. The
            // params pointer inside CK_MECHANISM is deliberately not read;
            // parameter decoding is Phase 3, behind the allowlist.
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            if let Some(pmech) = ctx.arg::<u64>(1) {
                if pmech != 0 {
                    // CK_MECHANISM.mechanism is the first CK_ULONG.
                    let mut m: u64 = 0;
                    let ok = unsafe {
                        helpers::bpf_probe_read_user(
                            &mut m as *mut u64 as *mut core::ffi::c_void,
                            core::mem::size_of::<u64>() as u32,
                            pmech as *const core::ffi::c_void,
                        )
                    };
                    if ok == 0 {
                        start.mechanism = m;
                    }
                }
            }
        }
        fnkind::OPEN_SESSION => {
            // phSession is arg4 and is only written by the time the call
            // returns; stash the pointer, read it at return.
            if let Some(p) = ctx.arg::<u64>(4) {
                start.out_ptr = p;
            }
        }
        fnkind::SESSION_ARG0 => {
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
        }
        fnkind::LOGIN => {
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            // userType only. pPin (arg2) and ulPinLen (arg3) are never read.
            if let Some(ut) = ctx.arg::<u64>(1) {
                start.user_type = ut as u32;
            }
        }
        _ => {}
    }
    let _ = START.insert(&key, &start, 0);
```

`ProbeContext::arg::<T>(n)` returns `Option<T>` in aya-ebpf 0.2.1 — verify against the vendored source and adapt if the signature differs, but do not change which arguments are read.

- [ ] **Step 3: Emit one event at return**

In `p11_return`, after popping the start value and updating the aggregates, resolve the out-pointer and emit:

```rust
    let mut session = start.session;
    if start.out_ptr != 0 && rv == 0 {
        // C_OpenSession wrote the handle by now. Only trust it on success.
        let mut s: u64 = 0;
        let ok = unsafe {
            helpers::bpf_probe_read_user(
                &mut s as *mut u64 as *mut core::ffi::c_void,
                core::mem::size_of::<u64>() as u32,
                start.out_ptr as *const core::ffi::c_void,
            )
        };
        if ok == 0 {
            session = s;
        }
    }

    let ev = Event {
        ts_ns: now,
        duration_ns: delta,
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        cgroup_id: unsafe { helpers::bpf_get_current_cgroup_id() },
        session,
        mechanism: start.mechanism,
        rv,
        slot,
        kind: SLOT_KIND.get(slot).copied().unwrap_or(fnkind::OTHER),
        user_type: start.user_type,
        _pad: 0,
    };
    match EVENTS.reserve::<Event>(0) {
        Some(mut e) => {
            e.write(ev);
            e.submit(0);
        }
        None => {
            if let Some(l) = LOST.get_ptr_mut(0) {
                // SAFETY: per-CPU storage, no cross-CPU aliasing.
                unsafe { *l += 1 };
            }
        }
    }
```

Consult the vendored `aya-ebpf-0.2.1/src/maps/ring_buf.rs` for the exact `reserve`/`write`/`submit`/`discard` API and adapt — the shape above is the intent, not a guaranteed signature.

- [ ] **Step 4: Build and verify**

Run the Phase 1b nightly build command for `crates/ebpf`, then confirm the new maps appear in the object's symbol table alongside the existing six. Run `cargo test --workspace` (userspace unaffected so far).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "ebpf: capture safe call arguments and emit completed-call events"
```

---

### Task 4: Publish slot kinds and drain the ring buffer

**Files:**
- Modify: `src/attach.rs` (publish SLOT_KIND before attaching), `src/metrics.rs` (read LOST)
- Create: `src/events.rs`

**Interfaces:**
- Consumes: `plan::Slot::kind`, `p11scope_ebpf_common::{Event, LOST usage}`.
- Produces: `events::Drain::new(&mut Ebpf) -> Result<Drain>`, `Drain::poll(&mut self, f: impl FnMut(Event))`, `metrics::lost_events(&Session) -> Result<u64>`. Tasks 5–7 consume them.

`SLOT_KIND` must be published **before** attach, for the same reason the scope filters are: a probe that fires before its kind is known captures nothing.

- [ ] **Step 1: Publish kinds in `Session::start`**

Immediately after `crate::scope::apply(...)` and before the attach loops:

```rust
        {
            let mut kinds: aya::maps::Array<_, u32> =
                aya::maps::Array::try_from(ebpf.map_mut("SLOT_KIND").context("SLOT_KIND map")?)?;
            for slot in &plan.slots {
                kinds.set(slot.index, slot.kind, 0)?;
            }
        }
```

- [ ] **Step 2: Write the drain**

`src/events.rs` wraps `aya::maps::RingBuf`, converting each raw record into an `Event` by size-checked copy (reject and count any record whose length is not `size_of::<Event>()` rather than transmuting blindly). Expose the count of malformed records as `Drain::malformed()`.

Include a unit test that exercises the size-check logic on a synthetic byte slice (the ring buffer itself needs a live kernel, so test the record decoder as a pure function: `events::decode(bytes: &[u8]) -> Option<Event>`).

- [ ] **Step 3: Read the loss counter**

`metrics::lost_events` sums `LOST` across CPUs, mirroring the existing `STATS` summation.

- [ ] **Step 4: Test and commit**

Run: `cargo test --workspace` → green.

```bash
git add -A
git commit -m "scope: publish slot kinds and drain the event ring buffer"
```

---

### Task 5: Semantic state machine and handle pseudonymization

**Files:**
- Create: `src/semantics.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Event`, `fnkind`, `plan::AttachPlan` (for slot → names).
- Produces: `semantics::State::new(&AttachPlan)`, `State::observe(&Event)`, and the accessors the report needs: `mechanisms() -> &BTreeMap<u64, MechStat>`, `sessions() -> SessionStats`, `logins() -> &BTreeMap<u32, u64>`, `functions() -> &BTreeMap<String, FnStat>`. Task 6 consumes them.

Model:
- **Sessions**: `C_OpenSession` success → allocate the next pseudonym for that (pid, raw handle) and increment open count and current-open gauge; `C_CloseSession` success → decrement, mark the pseudonym closed. Track peak concurrent and the open/close balance. A close for an unknown handle is counted as `unmatched_closes` (evidence, not an error).
- **Mechanisms**: an `INIT_WITH_MECH` call with a mechanism other than `MECH_NONE` records `{mechanism, op_kind}` with call count, error count, and a latency histogram (reuse `bucket_of`). The mechanism value is kept verbatim as `u64` — vendor ids are rendered as `0x…` and never dropped.
- **Operation binding**: the mechanism from an `*Init` on session S becomes the *active operation* for S; the next matching operational call on S (`C_Sign`, `C_Digest`, …) attributes its latency to that mechanism. `*Final`/a new `*Init` clears it. An operational call with no active init is counted as `orphan_ops` — evidence that the capture started mid-operation, never a guess.
- **Login**: `LOGIN` calls record `user_type` counts only. The PIN is never present in the event, by construction.

Pseudonyms are `sess#N` allocated in first-seen order per pid; raw handles live only in the in-memory map and are never serialized.

Write this with unit tests over synthetic `Event` values — no kernel needed. Cover at minimum: open/close balance and peak; a mechanism bound by `*Init` then attributed to a following op; a close with no matching open; an operational call with no active init; a vendor mechanism id surviving verbatim; two pids not sharing pseudonyms.

- [ ] **Step 1–N**: TDD each behavior above (tests first), then implement.

- [ ] **Final step: Commit**

```bash
git add -A
git commit -m "scope: semantic state machine with pseudonymized handles"
```

---

### Task 6: `profile` mode and `observed-profile.json` schema v1

**Files:**
- Modify: `src/render.rs` (add the v1 profile writer alongside the existing metrics writer), `src/main.rs` (`--mode profile` becomes the default; keep `metrics`)
- Create: `docs/schema/observed-profile-v1.md`

**Interfaces:**
- Produces: `render::profile_json(...) -> serde_json::Value` emitting `"schema": "pkcs11-scope/observed-profile/v1"`.

Sections, per the outputs spec and the Gate G2 acceptance table: `capture` (start/end/mode/kernel/module incl. build-id from the manifest), `evidence` (Phase 1b's widened `Evidence` **plus** `event_loss`, `malformed_records`, `orphan_ops`, `unmatched_closes`), `functions` (per name: calls, errors, rv distribution, latency), `mechanisms` (verbatim id, hex rendering, ops, calls, errors, latency; `params: null` with a note that parameter decoding is Phase 3), `sessions` (opened, closed, peak concurrent, balance), `logins` (user-type counts).

`completeness` must additionally become PARTIAL when `event_loss > 0` or `malformed_records > 0`.

`docs/schema/observed-profile-v1.md` documents every field and states explicitly which Gate G2 category each supports.

- [ ] Tests: extend the render tests so each new gap kind (event loss, malformed records) independently forces PARTIAL, and a golden-shape test asserts the v1 document contains each required top-level section.
- [ ] Commit: `scope: observed-profile schema v1 and profile mode`

---

### Task 7: Gate G2 induced-gap test

**Files:**
- Create: `scripts/verify-induced-gaps.sh`, `docs/notes/phase2-induced-gaps.md`

Gate G2 requires proving the report degrades honestly. Induce three gaps in one run and assert each is reported with the correct number, and that the verdict is PARTIAL:

1. **Aliasing** — build a fixture provider (reuse the Task 6 fixture pattern from `crates/discover/tests/fixture/`) whose table points two distinct names at one address; assert the alias group appears and its counts are attributed to the group, not one name.
2. **In-flight at end** — have the workload call a function that blocks past the capture window (a `C_WaitForSlotEvent`-style blocking call, or simply end the capture mid-call); assert `in_flight_at_end >= 1` and that the call is excluded from latency percentiles.
3. **Event loss** — rebuild with a deliberately tiny ring buffer (`RING_BYTES` override via a cfg or an env-driven const in the ebpf crate) and drive a high call rate; assert `event_loss > 0`, that it is reported, and that the aggregate map counts remain correct (the maps are the count authority — this is the cross-check that matters).

Each assertion checks a **number**, not just presence. The script ends `=== induced gaps: ALL OK ===` only when all three degraded exactly as predicted and `completeness == "PARTIAL"`.

`set -eu` on its own line in the body.

- [ ] Commit: `scope: induced-gap verification for gate G2`

---

### Task 8: Roadmap bookkeeping — Gate G2 status

**Files:**
- Modify: `docs/superpowers/plans/ROADMAP.md`

Record Phase 2 completion and map each Gate G2 criterion to its evidence: the schema reviewed against the design spec's acceptance table (cite `docs/schema/observed-profile-v1.md`), and the induced-gap test (cite `scripts/verify-induced-gaps.sh` + `docs/notes/phase2-induced-gaps.md` with real numbers). State any criterion not met as outstanding rather than claiming it.

- [ ] Commit: `plan: record phase 2 status against gate G2 criteria`
