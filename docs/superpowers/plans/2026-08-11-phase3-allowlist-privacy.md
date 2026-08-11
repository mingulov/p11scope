# Phase 3 — Allowlist parameter decoding + privacy enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode the small, explicitly justified set of mechanism parameters and template attribute *types* that migration assessment needs — entirely inside BPF, so nothing outside the allowlist ever reaches userspace — and prove it with a secret-canary suite that fails the build if any sentinel escapes.

**Architecture:** Userspace loads proxy-ng's `MechanismRegistry`, maps each mechanism id to a small shape code, and publishes `MECH_SHAPE` (mechanism id → shape code) before attaching — the same publish-before-attach pattern `SLOT_KIND` already uses. When the entry probe reads a mechanism type it looks up that shape and extracts **only fixed-offset scalar fields** named in the allowlist. Pointer fields inside parameter structs (IV, AAD, key material, attribute values) are never dereferenced. Template handling walks a bounded number of `CK_ATTRIBUTE` entries and takes the `type` field only, plus a boolean value for a tiny policy-attribute set.

**Tech Stack:** As Phase 2, plus `pkcs11-proxy-ng-types` (git dep, same pinned rev as `pkcs11-module`) for `MechanismRegistry`.

## Global Constraints — the privacy contract

This phase is the release-blocking privacy gate (G3). These are not style rules.

- **BPF may dereference exactly these pointers, and nothing else:**
  - `pMechanism + 0` → mechanism type (already Phase 2).
  - `phSession` → session handle on `C_OpenSession` success (already Phase 2).
  - `CK_MECHANISM.pParameter` → **only** at the fixed scalar offsets the allowlist names for that mechanism's shape, and only for shapes on the allowlist.
  - `pTemplate[i].type` → the attribute *type* field only, for `i` below the bounded cap.
  - `pTemplate[i].pValue` → **only** for the tiny policy-attribute allowlist, only when `ulValueLen == 1` (a `CK_BBOOL`), reading exactly 1 byte.
- **Never dereferenced, in any mode, at any privilege:** `pPin`; `CK_GCM_PARAMS.pIv`; `CK_GCM_PARAMS.pAAD`; any `pValue` outside the policy-boolean allowlist; any data, key, signature, digest, wrapped-blob, or random buffer; any `CK_ATTRIBUTE.pValue` for `CKA_VALUE`, `CKA_LABEL`, `CKA_ID`, or any attribute not on the policy allowlist.
- **Unknown shape → decode nothing.** A mechanism whose registry shape is absent, or whose shape is not on this phase's allowlist, records `params: null` with the mechanism id preserved verbatim. Never a partial or best-effort decode.
- **Every allowlisted field carries a written justification** (Task 7's doc). "It's only metadata" is not a justification: PIN *length* leaks policy, a label carries tenant identity, sign input *lengths* can characterize messages. If a field cannot be justified in writing, it does not ship.
- Truncation is evidence: a template longer than the cap, or a parameter struct shorter than expected, is **reported**, never silently trimmed.
- The registry drives *which mechanisms have which shape*; this plan's allowlist drives *which fields of a shape are safe*. Neither is hardcoded into BPF as a mechanism-id list.
- Aggregate maps remain the count authority; parameters are decoration on events, never a count source.
- The canary suite is a release gate: if any sentinel appears in any artifact, the suite fails and the phase is not done.
- Commit style: short prefix + imperative. Full workspace suite (69 tests at Phase 2 close) stays green; `scripts/verify-attach-e2e.sh` and `scripts/verify-induced-gaps.sh` keep passing.

## Inherited facts (verified — do not re-derive)

- Phase 2 HEAD `b78d815`; 69 tests green; profile schema `pkcs11-scope/observed-profile/v1` emits `params: null` with a Phase-3 note.
- `SLOT_KIND` publish-before-attach is in `Session::start`, right after `scope::apply`. `MECH_SHAPE` follows the same placement and reasoning.
- `crates/ebpf/src/main.rs` currently performs exactly two `bpf_probe_read_user` calls (mechanism type, `phSession`), both typed `u64`. A whole-branch privacy review enumerated them; keep that property auditable — every new read must be equally enumerable.
- `aya-ebpf 0.2.1`: `bpf_probe_read_user<T>(src: *const T) -> Result<T, i32>` (typed, reads `size_of::<T>()` bytes). `ProbeContext::arg::<T>(n) -> Option<T>`.
- `pkcs11-proxy-ng-types` at rev `7c5c86043820eb3795f40c65a36ce961cdfd26c5` (same rev as `pkcs11-module`, reachable on `origin/dev`) exposes `mechanism_registry::MechanismRegistry` with `load(Option<&Path>) -> Result<Self, String>`, `param_shape(mech_type: u64) -> Option<&str>`, `is_parameterless(u64) -> bool`, `registered_mechanisms() -> Vec<u64>`, `revision() -> &str`. Shape names are lowercase strings like `"gcm"`, `"rsa_pkcs_pss"`, `"ecdh1_derive"`. Its deps are serde/toml/tracing/zeroize — no dlopen, so the static musl build is unaffected.
- x86-64 PKCS#11 layouts this phase depends on:
  - `CK_RSA_PKCS_PSS_PARAMS { CK_MECHANISM_TYPE hashAlg; CK_RSA_PKCS_MGF_TYPE mgf; CK_ULONG sLen; }` — three `CK_ULONG`s at offsets 0, 8, 16. All scalars.
  - `CK_GCM_PARAMS { CK_BYTE_PTR pIv; CK_ULONG ulIvLen; CK_BYTE_PTR pAAD; CK_ULONG ulAADLen; CK_ULONG ulTagBits; }` — offsets 0, 8, 16, 24, 32. Safe scalars are `ulIvLen` (8), `ulAADLen` (24), `ulTagBits` (32). Offsets 0 and 16 are pointers and are **never** dereferenced.
  - `CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE type; CK_VOID_PTR pValue; CK_ULONG ulValueLen; }` — 24 bytes; `type` at 0, `pValue` at 8, `ulValueLen` at 16.
  - `C_FindObjectsInit(hSession, pTemplate, ulCount)` — template at arg1, count at arg2. `C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey)` — template at arg2, count at arg3.

---

### Task 1: Registry-driven shape publication

**Files:** `Cargo.toml` (add the types git dep), `src/shapes.rs` (new), `src/attach.rs` (publish before attach), `crates/ebpf-common/src/lib.rs` (shape codes + `MAX_MECH_SHAPES`).

Add `pkcs11-proxy-ng-types = { git = "https://github.com/mingulov/pkcs11-proxy-ng", rev = "7c5c860…" }` (same rev as `pkcs11-module`; no path deps ever).

Define shape codes in `ebpf-common` as `u32` consts, mirroring the `fnkind` pattern: `shape::{NONE = 0, RSA_PKCS_PSS = 1, GCM = 2}`. Only shapes this phase decodes get a code; everything else maps to `NONE`.

`src/shapes.rs`: `code_for(shape_name: &str) -> u32` mapping the registry's string to a code (`"rsa_pkcs_pss"`/`"pss"` → RSA_PKCS_PSS, `"gcm"` → GCM, everything else → NONE — check the registry's actual shape spelling for PSS with `MechanismRegistry::param_shape` against a known PSS mechanism id and use whatever it really returns); and `publish(ebpf, &MechanismRegistry) -> Result<usize>` filling a `MECH_SHAPE: HashMap<u64, u32>` map for every registered mechanism whose shape has a code. Record the registry `revision()` for the report.

Tests: `code_for` maps the known names and returns NONE for unknown/absent; a registry loaded with defaults yields a non-empty publish set including at least one GCM and one PSS mechanism (assert by id).

Commit: `scope: publish registry-driven mechanism shapes`

---

### Task 2: Decoded-parameter types

**Files:** `crates/ebpf-common/src/lib.rs`; extends `Event`.

Add to `Event` (keeping `#[repr(C)]`, explicit padding, and the no-implicit-padding test updated):

```
pub shape: u32,        // shape::* actually applied, or NONE
pub p0: u64,           // shape-specific scalar 1
pub p1: u64,           // shape-specific scalar 2
pub p2: u64,           // shape-specific scalar 3
pub attr_types: [u32; MAX_ATTRS],   // template attribute types, MAX_ATTRS = 8
pub attr_count: u32,   // attributes actually captured
pub attr_total: u32,   // ulCount as reported — attr_total > attr_count means truncated
pub attr_bools: u32,   // bitmask: policy-allowlisted booleans observed true
pub attr_bools_seen: u32, // bitmask: which policy booleans were present at all
```

`p0/p1/p2` are interpreted per shape: PSS → (hashAlg, mgf, sLen); GCM → (ulIvLen, ulAADLen, ulTagBits). Document that mapping in the type's doc comment — it is the contract userspace decodes against.

The generic `p0/p1/p2` naming is deliberate: it keeps the wire struct fixed-size and shape-agnostic so adding a shape later needs no ABI change.

Tests: sizes/alignment pinned as before; the mapping documented.

Commit: `ebpf-common: decoded-parameter fields on the event record`

---

### Task 3: BPF parameter decode (RSA-PSS and GCM)

**Files:** `crates/ebpf/src/main.rs`.

In the `INIT_WITH_MECH` arm, after reading the mechanism type, look up `MECH_SHAPE[mech]`. If absent or `NONE`, leave `shape = NONE` and decode nothing. Otherwise read `pParameter` (offset 8 of `CK_MECHANISM`) as a `u64` pointer, and:

- **RSA_PKCS_PSS**: read three `u64`s at `pParameter + 0/8/16` → `p0/p1/p2`.
- **GCM**: read three `u64`s at `pParameter + 8/24/32` → `p0/p1/p2`. Offsets 0 and 16 (`pIv`, `pAAD`) are **never** read.

Every read is a separate typed `u64` `bpf_probe_read_user`. A failed read leaves the corresponding field at a sentinel and sets `shape = NONE` for that event (partial decodes are not emitted).

Also guard: `ulParameterLen` (offset 16 of `CK_MECHANISM`) must be at least the shape's expected size before any parameter read — a provider passing a short buffer must not cause a read past it. Read that length first and bail to `NONE` if too small.

Self-check to include in the report: list every `bpf_probe_read_user` in the file after this change with its offset and justification. The count should be exactly 2 (Phase 2) + 1 (`ulParameterLen`) + 1 (`pParameter` value) + 3 (the shape scalars) — and no read may target offsets 0 or 16 of a GCM params struct.

Commit: `ebpf: decode allowlisted mechanism parameters in-kernel`

---

### Task 4: BPF template attribute-type capture

**Files:** `crates/ebpf-common/src/lib.rs` (policy-boolean allowlist consts), `crates/ebpf/src/main.rs`, `src/kinds.rs` (new kind for template-bearing functions).

Add `fnkind::TEMPLATE_ARG1` (`C_FindObjectsInit`: template arg1, count arg2) and `fnkind::TEMPLATE_ARG2` (`C_GenerateKey`, `C_CreateObject`: template arg2, count arg3). Classify those names accordingly — and note this *moves* them out of `SESSION_ARG0`, so session capture must still happen in the new arms.

In BPF, walk at most `MAX_ATTRS = 8` entries of `pTemplate` (a `#[unroll]`-style bounded loop; the verifier requires a constant bound). For each entry read **only** the `type` field (offset 0 of the 24-byte `CK_ATTRIBUTE`). Record `attr_total` from the count argument so truncation is visible.

For the **policy-boolean allowlist only** — `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_DERIVE` — additionally read `ulValueLen` (offset 16) and, **only if it equals 1**, read exactly one byte at `pValue` (offset 8) as the `CK_BBOOL`. Set the corresponding bit in `attr_bools_seen`, and in `attr_bools` when the byte is non-zero. Any other attribute type: its `pValue` is never touched.

This is the phase's sharpest edge. The `ulValueLen == 1` gate is what keeps a `CKA_LABEL` or `CKA_VALUE` from ever being read even if an attribute type were mis-listed.

Commit: `ebpf: capture template attribute types and policy booleans`

---

### Task 5: Parameters and attributes in the profile

**Files:** `src/semantics.rs`, `src/render.rs`, `docs/schema/observed-profile-v1.md`.

Extend the state machine to carry decoded params per mechanism, and the profile's `mechanisms[]` entries to emit `params` as a shape-tagged object instead of `null` when a shape was applied:

- PSS → `{ "shape": "rsa_pkcs_pss", "hash_alg": <u64>, "hash_alg_hex": "0x…", "mgf": <u64>, "salt_len": <u64> }`
- GCM → `{ "shape": "gcm", "iv_len": <u64>, "aad_len": <u64>, "tag_bits": <u64> }`
- unknown/absent shape → `params: null` with the existing note (unchanged behavior)

Add a `templates` section: per operation, the attribute *types* requested (numeric + hex), the policy booleans observed, and `truncated: true` when `attr_total > attr_count`. Requested-vs-effective language from the design spec applies: these are what the application **asked for**, never asserted as the key's effective policy — say so in the schema doc and in the JSON via a `"requested": true` marker or equivalent.

Truncation and any shape whose decode failed must surface in evidence, and `completeness` gains a `templates_truncated` gap condition.

Bump the schema string to `pkcs11-scope/observed-profile/v1.1` and document the delta (additive only). Update the Gate G2 mapping in the schema doc: the OBSERVED AND VALIDATED / CANDIDATE DIFFERED rows can now claim full parameter combos for the two decoded shapes, and must still disclose that other shapes remain id-only.

Commit: `scope: emit allowlisted parameters and template attribute types`

---

### Task 6: Secret-canary suite (release gate)

**Files:** `scripts/verify-canaries.sh`, `scripts/fixtures/canary_workload.c`, `docs/notes/phase3-canaries.md`.

A workload that plants distinctive, high-entropy sentinels everywhere a secret could live, then a capture, then an exhaustive search for any sentinel in **every** artifact:

- sentinel **PIN** passed to `C_Login`
- sentinel **key material** in a `CKA_VALUE` on `C_CreateObject`
- sentinel **label** in `CKA_LABEL`
- sentinel **plaintext** passed to `C_Digest`/`C_Encrypt`
- sentinel bytes inside a **mechanism parameter blob** (e.g. a GCM IV and AAD — precisely the pointers the allowlist forbids dereferencing)
- sentinel in `CKA_ID`

Artifacts to search: the output JSON, the profiler's stdout/stderr log, and a **BPF map dump** (`bpftool map dump` for every map the program owns — this catches a sentinel that reached kernel memory even if userspace never printed it). Search raw bytes, not just UTF-8, and search for each sentinel's hex representation too.

The suite fails if any sentinel is found anywhere. It must also **prove it can detect a leak**: include a deliberately-planted positive control (e.g. write one sentinel into a scratch file the scanner also searches) so a scanner that silently matches nothing cannot pass. Assert the positive control IS found and the real artifacts are clean.

`set -eu` in the script body. Ends `=== canaries: NONE LEAKED ===` only when the positive control fired and every real artifact was clean.

Commit: `scope: secret-canary suite for the privacy allowlist`

---

### Task 7: Written allowlist justification (Gate G3 input)

**Files:** `docs/privacy/allowlist-v1.md`.

One entry per allowlisted field, each answering: what it is, why an assessor needs it, what an attacker could learn from it, and why that is acceptable. Cover every field: mechanism type; PSS `hashAlg`/`mgf`/`sLen`; GCM `ulIvLen`/`ulAADLen`/`ulTagBits`; login user type; attribute types; each policy boolean; session handle (and why pseudonymization suffices).

Explicitly document the **rejected** candidates and why: PIN length, label contents, `CKA_ID`, sign input lengths, IV/AAD contents, `CKA_VALUE`. The design spec calls these out as tempting-but-unsafe; writing down the refusal is what makes the boundary reviewable.

Also state the enforcement mechanism per field — which are structurally impossible to leak (no field exists), versus which depend on a runtime gate (the `ulValueLen == 1` check), and what test covers each.

Commit: `docs: written justification for the v1 privacy allowlist`

---

### Task 8: Roadmap Gate G3 bookkeeping

**Files:** `docs/superpowers/plans/ROADMAP.md`.

Map each G3 criterion to evidence: canary suite green (cite the script and real output), adversarial allowlist review (cite `docs/privacy/allowlist-v1.md`), and `/security-review` of the decoding paths — the last is human-triggered, so state it as outstanding rather than claiming it. Note that G3 is release-blocking from here on.

Commit: `plan: record phase 3 status against gate G3 criteria`
