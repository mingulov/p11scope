# v1 privacy allowlist — written justification (Gate G3)

This is the Gate G3 input the design spec requires: "metadata" is not
automatically safe, so every field this tool captures gets a written
argument, and every tempting-but-rejected field gets a written refusal. An
adversarial reviewer should be able to check each claim below against the
cited file:line.

Fields were enumerated by reading the code, not from the phase plan: all 11
`bpf_probe_read_user` call sites in `crates/ebpf/src/main.rs`, the `Event`
and `attr_bool` definitions in `crates/ebpf-common/src/lib.rs`, and what
`src/render.rs` actually serializes into `observed-profile.json`. That list
matches the plan's expected field set exactly, with two additions the plan
didn't name explicitly (`pid_tgid`, `cgroup_id` — see "Captured but never
exposed" below) and one important correction to how "session handle" is
usually described (see that entry).

## Enforcement categories

- **structural** — no field exists anywhere in `CallStart`/`Event`/the
  output JSON that could hold the secret, so a leak is impossible by
  construction, independent of any runtime check.
- **runtime-gated** — the field is safe only because a length/null check
  runs before a read. These are the load-bearing lines; each is named
  below with the test that exercises it.

---

## Allowlisted fields

### 1. Mechanism type (`CK_MECHANISM.mechanism`)

- **What it is:** the `CK_MECHANISM_TYPE` (`CK_ULONG`) at offset 0 of the
  `pMechanism` argument to any `*Init` call. Read at
  `crates/ebpf/src/main.rs:246`.
- **Why an assessor needs it:** it is the entire point of the tool — "which
  mechanisms does this application actually drive" is the first question
  a PKCS#11 migration assessment answers, and it is what
  `pkcs11-lab`'s OBSERVED/CANDIDATE-DIFFERED categories join against
  (design spec, "Profile schema requirements").
- **What an attacker could learn:** which cryptographic algorithms are in
  use (e.g. RSA-PSS vs. PKCS#1v1.5, AES-GCM vs. CBC). This is algorithm
  choice, not key material or plaintext.
- **Why that is acceptable:** algorithm identifiers are already exposed by
  every PKCS#11 consumer's configuration, by TLS ciphersuite negotiation
  logs, and by the vendor's own documentation of supported mechanisms; a
  vendor-defined id (e.g. `0x80001042`) reveals only that a proprietary
  mechanism exists, not what it does. Verbatim, never renamed
  (`src/render.rs:295` `mechanism`/`mechanism_hex`).
- **Enforcement:** runtime-gated on `pmech != 0`
  (`crates/ebpf/src/main.rs:244`) — a null pointer is never dereferenced.
  No dedicated canary targets this specific read (it is not secret data),
  but every canary run exercises it as a side effect of driving real
  mechanisms.

### 2. RSA-PSS `hashAlg` / `mgf` / `sLen`

- **What it is:** three `CK_ULONG` scalars from `CK_RSA_PKCS_PSS_PARAMS`
  at offsets 0/8/16 of `pParameter`, read only when the mechanism's
  registry-published shape is `RSA_PKCS_PSS` and `ulParameterLen == 24`
  (`crates/ebpf/src/main.rs:107-135`, the layout match at line 117, reads
  at lines 133-135).
- **Why an assessor needs it:** RSA-PSS's security margin and
  interoperability depend on the hash algorithm, MGF, and salt length
  actually used — a candidate provider that silently truncates the salt
  or swaps the MGF hash is a real migration regression `pkcs11-lab` needs
  to flag, not something a mechanism id alone reveals. Emitted as
  `hash_alg`/`mgf`/`salt_len` (`src/render.rs`, `param_combo_json`'s
  `RSA_PKCS_PSS` arm).
- **What an attacker could learn:** the padding scheme's configuration
  (which is itself a public parameter of the signature; PSS parameters
  are transmitted or standardized alongside the signature in most
  protocols, not secret).
- **Why that is acceptable:** these three values are algorithm
  configuration, not key material or message content — comparable to
  observing a TLS ciphersuite's PRF. No plaintext, digest input, or
  signature ever crosses this boundary.
- **Enforcement:** runtime-gated, three checks in order: `ulParameterLen
  == 24` exactly (`crates/ebpf/src/main.rs`, `decode_params`'s `match
  (sh, param_len)` — not `>=`, for the same reason the GCM guard below was
  tightened to an exact per-layout match), `pParameter != 0`, and all
  three scalar reads must succeed together or nothing is recorded (`if
  let (Ok(a), Ok(b), Ok(c))`). **Coverage gap:** `scripts/verify-canaries.sh`
  now drives a real RSA-PSS `*Init` call (previously the PSS decode path
  was never exercised at all), but still does not plant a short/malformed
  `ulParameterLen` fixture for it the way the GCM case now does — see
  "Summary of weak points" below. Flagged as a follow-up, not a blocker:
  the failure mode of a missing guard here would be an out-of-bounds
  *scalar* read (still bounded to 8 bytes, never attacker buffer
  content), not a secret leak — `CK_RSA_PKCS_PSS_PARAMS` has no pointer
  fields, unlike `CK_GCM_PARAMS`.

### 3. GCM `ulIvLen` / `ulAADLen` / `ulTagBits`

- **What it is:** three `CK_ULONG` scalars from `CK_GCM_PARAMS`, read only
  when the shape is `GCM` and `CK_MECHANISM.ulParameterLen` **exactly**
  matches one of the two known `CK_GCM_PARAMS` layouts
  (`crates/ebpf/src/main.rs`, `decode_params`'s `match (sh, param_len)`).
  `CK_GCM_PARAMS` has two incompatible layouts in the wild: the legacy
  PKCS#11 v2.20 struct (`pIv`@0 `ulIvLen`@8 `pAAD`@16 `ulAADLen`@24
  `ulTagBits`@32, 40 bytes) and the current v2.40/OASIS struct — what
  `cryptoki_sys::CK_GCM_PARAMS` actually is — which inserts `ulIvBits` at
  offset 16 and pushes the rest out (`pIv`@0 `ulIvLen`@8 `ulIvBits`@16
  `pAAD`@24 `ulAADLen`@32 `ulTagBits`@40, 48 bytes). The pointer fields
  (`pIv`, always offset 0; `pAAD`, offset 16 or 24 depending on which
  layout matched) are never read in either case; only the three
  length/count scalars are. An earlier version of this function guarded
  with `ulParameterLen >= 40` instead of an exact per-layout match, which
  let a modern 48-byte struct pass the guard while still using the
  legacy offsets — reading `CK_GCM_PARAMS.pAAD` (a userspace pointer) into
  what the output labeled `aad_len`. Fixed by making the match exact and
  layout-specific; see "Summary of weak points" below for how this was
  found and the coverage this closed.
- **Why an assessor needs it:** IV length and tag length are correctness
  parameters for GCM — a candidate using a non-standard IV length (not
  96 bits) or a truncated tag is a real interoperability/security
  regression to surface, and AAD length (not content) indicates whether
  associated data is used at all. Emitted as `iv_len`/`aad_len`/`tag_bits`,
  tagged with `layout` (`"v2.20"` or `"v2.40"`) so a reader can tell which
  struct shape produced the values (`src/render.rs`'s `param_combo_json`).
- **What an attacker could learn:** the shape of the GCM invocation (IV
  size, whether AAD is present and how long, tag truncation). Never the
  IV bytes, AAD bytes, key, plaintext, ciphertext, or a pointer address.
- **Why that is acceptable:** IV/tag lengths are protocol parameters
  (e.g. TLS record framing implies IV/tag length already), not secrets.
  AAD length alone (without content) is a low-value signal.
- **Enforcement:** runtime-gated, same overall structure as PSS above
  (`ulParameterLen` read and matched, then `pParameter != 0`, then all
  three scalar reads must succeed together or nothing is recorded) but
  with the match now exact per layout, never `>=`. The canary suite
  exercises **both** layouts (a legacy 40-byte call and a modern 48-byte
  call with planted sentinel IV/AAD buffers) plus a malformed-length GCM
  call (`ulParameterLen` matching neither layout), and asserts the
  malformed call renders as a decode failure — not a fabricated combo —
  and that no emitted numeric field looks like a pointer (implausibly
  large, e.g. `> 2^32`). It still verifies the *pointer* fields
  (`pIv`/`pAAD`) are never dereferenced: `CANARY_IV`/`CANARY_AAD`
  sentinels are planted at those exact offsets by
  `scripts/fixtures/canary_workload.c` (see its header comment) and
  `scripts/verify-canaries.sh` scans every output artifact and BPF map
  dump for them.

### 4. Login user type (`CK_USER_TYPE`)

- **What it is:** the `CK_ULONG` at `C_Login`'s arg1, read into
  `start.user_type` (`crates/ebpf/src/main.rs:296-298`). `pPin` (arg2) and
  `ulPinLen` (arg3) are never touched — stated explicitly in the comment
  at `crates/ebpf/src/main.rs:295` and in the `fnkind::LOGIN` doc comment
  (`crates/ebpf-common/src/lib.rs:99-100`: "pPin is NEVER read, in any
  mode, at any privilege").
- **Why an assessor needs it:** whether the application authenticates as
  `CKU_USER` vs `CKU_SO` (or a vendor-context user type) affects which
  operations and objects are reachable, and a migration candidate that
  requires a different login flow is a real compatibility gap.
- **What an attacker could learn:** the *role* the application logs in
  as. Not a secret in any PKCS#11 threat model — roles are a small fixed
  enumeration, not tenant- or identity-specific.
- **Why that is acceptable:** carries no credential material. Counted
  per role, not per call (`src/semantics.rs:308-309`,
  `src/render.rs:525-526`).
- **Enforcement:** structural — there is no field in `CallStart`/`Event`
  that could hold `pPin` or `ulPinLen`; the LOGIN arm's code path
  physically only reads `ctx.arg::<u64>(1)`
  (`crates/ebpf/src/main.rs:296`). Tested by
  `scripts/verify-canaries.sh` via the `CANARY_PIN` sentinel planted in
  `C_Login`'s `pPin` argument by `scripts/fixtures/canary_workload.c`.

### 5. Session handle

- **What it is:** the raw `CK_SESSION_HANDLE` (`CK_ULONG`), captured three
  ways depending on call kind: from `arg0` directly
  (`crates/ebpf/src/main.rs:240-242,264-266,272-274,284-286,292-294`), or
  for `C_OpenSession`, by stashing the `phSession` out-pointer at entry
  and reading it back at return only on success
  (`crates/ebpf/src/main.rs:259-262,353-358`).
- **Why an assessor needs it:** session lifecycle (open/close balance,
  peak concurrency) and per-session operation sequencing
  (`*Init` → operational call → `*Final`) are how the semantic state
  machine attributes a mechanism to a later `C_Sign`/`C_Encrypt` call that
  itself carries no mechanism argument (design spec, "Semantic state
  machine": "`C_Sign` carries no mechanism — `C_SignInit` did").
- **What an attacker could learn, if the raw handle reached output:**
  little on its own (session handles are small integers assigned by the
  provider, not identity-bearing), but a raw handle used *as a
  correlation key* could in principle be joined against other logs from
  the same process to reconstruct call sequencing per real session.
- **Why that is acceptable — and a correction to the plan's framing:**
  the plan describes this as "pseudonymization suffices," implying a
  pseudonym is emitted. In the current code, **no session identifier —
  raw or pseudonymized — is ever emitted to any output artifact.** The
  raw handle crosses the kernel/userspace boundary inside `Event` (it has
  to, to do the correlation), but `src/semantics.rs` immediately consumes
  it into a per-process monotonic pseudonym
  (`src/semantics.rs:224-237`) that itself never leaves the state
  machine: the module doc states "Raw handles live only in the in-memory
  maps below; no accessor on `State` returns one" (`src/semantics.rs:4-5`),
  and `src/render.rs`'s `SessionsOut` carries only aggregate counts —
  `opened`/`closed`/`peak_concurrent`/`balance`
  (`src/render.rs:442-449,518-524`) — with no per-session field anywhere
  in `profile_json`. This is stronger than the plan's stated property,
  not weaker, so it is called out explicitly rather than left to look
  like an inconsistency.
- **Enforcement:** structural for the *output* (no field in any `*Out`
  struct in `src/render.rs` can hold a session identifier); runtime-gated
  for the raw value's brief lifetime inside `Event` (`start.out_ptr != 0
  && rv == 0` before trusting the `C_OpenSession` out-pointer,
  `crates/ebpf/src/main.rs:353-355`). No canary specifically targets this
  (it is not a secret-value leak class), but the two-pid isolation tests
  in `src/semantics.rs` (`two_pids_do_not_share_pseudonyms_or_session_state`,
  around `src/semantics.rs:685-708`) cover the pseudonym-assignment logic
  itself.

### 6. Template attribute types

- **What it is:** the `CK_ATTRIBUTE_TYPE` (`CK_ULONG`) at offset 0 of each
  `CK_ATTRIBUTE` entry in `pTemplate`, for `C_FindObjectsInit`,
  `C_CreateObject`, and `C_GenerateKey`. Read in `walk_template`
  (`crates/ebpf/src/main.rs:156-202`, the type read at line 167). Bounded
  to `MAX_ATTRS = 8` entries per event
  (`crates/ebpf-common/src/lib.rs:207`); `attr_total` still records the
  real count so a longer template shows as truncated evidence rather than
  being silently trimmed (`crates/ebpf/src/main.rs:157`,
  `src/render.rs:65-68` doc comment on `templates_truncated`).
- **Why an assessor needs it:** which attribute *kinds* an application
  asks for when creating/searching/generating objects (e.g. does it
  request `CKA_SENSITIVE`, does it search by `CKA_CLASS`) shapes what a
  candidate provider must support structurally — this is template
  *shape*, independent of any value.
- **What an attacker could learn:** the vocabulary of attributes an
  application's key-management code uses. Not the values, not which
  specific keys/certs/objects are involved.
- **Why that is acceptable:** attribute type constants are a small, public,
  standardized (or vendor-documented) enumeration — knowing that an
  application requests `CKA_EXTRACTABLE` reveals a coding pattern, not a
  secret. Emitted as numeric + hex only (`AttrTypeOut`,
  `src/render.rs:369-373,420-423`), explicitly marked `requested: true`
  (never asserted as effective policy — `src/render.rs:398-400,419`).
- **Enforcement:** structural for the value: the walk reads `pValue` for
  *no* attribute type outside the policy-boolean allowlist — the comment
  at `crates/ebpf/src/main.rs:162-165` states `type` "is the only field
  ever read for a non-allowlisted attribute." Runtime-gated for the loop
  bound itself (constant `MAX_ATTRS`, not the caller-supplied `count`, so
  the verifier can prove termination — `crates/ebpf/src/main.rs:151-153`).
  Tested by `scripts/verify-canaries.sh`: `CANARY_LABEL`/`CANARY_ID`/
  `CANARY_KEY` are planted as `CKA_LABEL`/`CKA_ID`/`CKA_VALUE` values on
  `C_CreateObject` and confirmed absent from every artifact.

### 7. Policy-boolean attributes (11 total)

- **What they are:** a single `CK_BBOOL` byte at `pValue`, read only for
  these 11 attribute types, and only when `ulValueLen == 1`:
  `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_ENCRYPT`,
  `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`,
  `CKA_DERIVE`, `CKA_EXTRACTABLE` (`crates/ebpf-common/src/lib.rs:146-188`,
  the read at `crates/ebpf/src/main.rs:180-199`). Recorded as two
  bitmasks — `attr_bools` (value, when true) and `attr_bools_seen`
  (presence, true or false) — so a name absent from both lists means
  "never requested," a real three-state
  (`crates/ebpf-common/src/lib.rs:232-235`, `src/render.rs:375-386`).
- **Why an assessor needs each one:** these are the capability/policy
  flags a candidate provider must honor identically for a migration to
  be safe — a provider that silently drops a requested `CKA_SENSITIVE`
  or grants `CKA_EXTRACTABLE` when the source didn't is a security
  regression `pkcs11-lab` needs to catch per-mechanism. `CKA_TOKEN` /
  `CKA_PRIVATE` inform object persistence and access-control class;
  `CKA_ENCRYPT`/`CKA_DECRYPT`/`CKA_WRAP`/`CKA_UNWRAP`/`CKA_SIGN`/
  `CKA_VERIFY`/`CKA_DERIVE` are the usage-capability flags that determine
  which mechanisms a key may legally be used with; `CKA_SENSITIVE`/
  `CKA_EXTRACTABLE` are the two attributes that most directly gate
  whether key material can ever leave the token.
- **What an attacker could learn:** a single true/false per policy
  dimension, per template — e.g. "this application asks for
  non-extractable, sensitive, sign-capable keys." This describes a
  security *posture*, not a value; it is the kind of information a
  security architecture document would already state.
- **Why that is acceptable:** it is exactly one bit of information per
  attribute, gated to a fixed, pre-declared, tiny set; no other attribute
  type's value is ever read regardless of its `ulValueLen`. Emitted as
  attribute names only (`observed_true`/`observed_false`,
  `POLICY_BOOL_NAMES` at `src/render.rs:355-367`), explicitly framed as
  "requested," not "effective" (`src/render.rs:540-544`).
- **Enforcement:** runtime-gated — three checks in strict order: type
  must be in `bit_for_attr_type`'s match (`crates/ebpf-common/src/lib.rs:
  153-168`), then `ulValueLen == 1` exactly
  (`crates/ebpf/src/main.rs:183-189`), *then* one byte is read
  (`crates/ebpf/src/main.rs:190-194`). This is the sharpest edge in the
  allowlist — the comment at `crates/ebpf/src/main.rs:177-179` calls the
  length gate "load-bearing: it is what keeps a `CKA_VALUE` or
  `CKA_LABEL` from ever being read even if a type were mis-listed on the
  allowlist." **Directly tested**: `scripts/verify-canaries.sh` /
  `scripts/fixtures/canary_workload.c` plants `CANARY_BOOLLONG` on
  `CKA_TOKEN` with a deliberately-oversized `ulValueLen` (the sentinel
  string's length, not 1) specifically to exercise this gate
  (`scripts/fixtures/canary_workload.c:9-11,103,145-146,155`), and the
  canary scan confirms `CANARY_BOOLLONG` never appears in any artifact.

### 8. Call latency

- **What it is:** `duration_ns` (`now - start.ts_ns`, computed in BPF at
  `crates/ebpf/src/main.rs:322`) and its bucketed/aggregate forms —
  per-slot histograms in the `STATS` map
  (`crates/ebpf/src/main.rs:325-341`) and per-event `duration_ns` fed into
  the semantic state machine's per-mechanism latency
  (`src/render.rs:240-249,304`).
- **Why an assessor needs it:** whether a candidate provider's HSM-backed
  operations perform acceptably (a common migration blocker: a software
  fallback that is 100x slower than the source HSM) is a first-class
  assessment question the design spec's OBSERVED categories exist to
  answer.
- **What an attacker could learn:** operation timing can in principle
  leak coarse information about message length or key size via timing
  side channels in a hostile threat model. This tool exposes latency at
  log2-bucket granularity (`LATENCY_BUCKETS`,
  `crates/ebpf-common/src/lib.rs:11-13`) aggregated over the whole
  capture window, not per-call-with-input-correlation — the design spec
  explicitly rejects a raw per-call trace level that could support that
  ("There is no 'dump every pointer' level, at any privilege").
- **Why that is acceptable:** latency is inherent, observable-from-outside
  behavior of any co-resident or network-adjacent observer (this is not a
  new side channel this tool introduces); the profile/metrics levels only
  ever report bucketed aggregates, never a per-call timestamp correlated
  with input size (input lengths themselves are never captured — see
  rejected candidates below).
- **Enforcement:** structural — `duration_ns` is derived entirely from
  `bpf_ktime_get_ns()` (a kernel clock, not user memory) and never from a
  `bpf_probe_read_user` call.

### 9. `CK_RV` (return code)

- **What it is:** the uretprobe's return value, `ctx.ret()`
  (`crates/ebpf/src/main.rs:323`), counted per-slot
  (`crates/ebpf/src/main.rs:337-339,348-350`) and rendered as hex
  (`src/render.rs:264-268`).
- **Why an assessor needs it:** error-rate per function/mechanism is
  direct evidence of compatibility problems — a candidate that returns
  `CKR_MECHANISM_PARAM_INVALID` where the source never did is exactly the
  OBSERVED-BUT-CANDIDATE-DIFFERED signal the tool exists to surface.
- **What an attacker could learn:** operation success/failure patterns.
  Standard, already-visible-to-the-application return codes; not
  sensitive.
- **Why that is acceptable:** `CK_RV` is a small standardized enum with no
  secret-bearing payload.
- **Enforcement:** structural — comes from `ProbeContext::ret()` on the
  return probe, never from a user-memory read.

---

## Captured but never exposed: `pid_tgid`, `cgroup_id`

- **What they are:** `bpf_get_current_pid_tgid()` and
  `bpf_get_current_cgroup_id()` (kernel helpers, not user-memory reads),
  stored on every `Event` (`crates/ebpf/src/main.rs:363-364`,
  `crates/ebpf-common/src/lib.rs:257-258`).
- **Current status — flagged as weak, not because it leaks, but because
  it is unused:** `pid_tgid` is consumed internally only to key per-process
  state (`src/semantics.rs:156-159`, the `pid()` helper); `cgroup_id` is
  captured into every `Event` but **has no consumer at all** — it is not
  read by `src/semantics.rs`, not read by `src/render.rs`, and does not
  appear anywhere in `observed-profile.json` today (confirmed by
  exhaustive grep of `src/render.rs`). The design spec anticipates a
  future per-container breakdown ("Events also carry process / thread /
  cgroup identity... so the profile can break down calls per container"),
  but that consumer does not exist yet.
- **Recommendation:** since `cgroup_id` is captured but never surfaced,
  there is nothing to justify *today* — no output field exists that could
  leak it, so it needs no allowlist entry of its own yet. When the
  per-container breakdown lands, this field will need its own writeup
  (cgroup id is a low-sensitivity but real identifier — it maps to a
  specific container/pod). Until then this is dead capture, not a privacy
  gap; noted so a future reviewer does not have to rediscover it.

---

## Rejected candidates

Each of these was considered and refused. The refusal is enforced in code,
not merely in this document.

- **PIN contents.** Never read at all: the `LOGIN` arm touches only arg1
  (`crates/ebpf/src/main.rs:296`); arg2 (`pPin`) is never passed to
  `bpf_probe_read_user` anywhere in the file. **Structural.** Canary:
  `CANARY_PIN` (`scripts/verify-canaries.sh`,
  `scripts/fixtures/canary_workload.c`).
- **PIN length.** Same arm — `ulPinLen` (arg3) is likewise never read.
  Refused because the design spec calls this out by name: PIN length
  leaks password-policy information (minimum/fixed PIN length, whether a
  PIN vs. passphrase is in use) that is operationally sensitive even
  though it is "just a number." **Structural** — there is no code path
  that reads arg3, and no field in `CallStart`/`Event` reserved for it.
- **Label contents (`CKA_LABEL`).** Only the attribute *type* is read for
  any non-policy-boolean attribute (`crates/ebpf/src/main.rs:167-171`);
  `CKA_LABEL`'s value is never on the policy-boolean allowlist
  (`crates/ebpf-common/src/lib.rs:172-187` has no entry for it), so its
  `pValue` is never touched. Refused because a label routinely carries
  tenant, certificate, or key-identity information — the design spec
  reserves label disclosure for an explicit opt-in flag, which does not
  exist in the current code (grepped for `label`/`opt-in`/`opt_in` across
  `src/main.rs`; no such flag exists today, so the safe default is the
  only behavior). **Structural.** Canary: `CANARY_LABEL`.
- **`CKA_ID`.** Same reasoning and same mechanism as `CKA_LABEL` — not on
  the policy-boolean allowlist, so only its type is ever recorded, never
  its value. Refused because `CKA_ID` is explicitly called out in the
  design spec as "operationally sensitive" (it is commonly used to
  correlate a key to a certificate or external identity). **Structural.**
  Canary: `CANARY_ID`.
- **`CKA_VALUE`.** Same mechanism — not on the policy-boolean allowlist.
  This is key material itself; the design spec lists it first among
  things "never recorded in any mode." **Structural.** Canary:
  `CANARY_KEY`.
- **GCM IV/AAD contents.** `CK_GCM_PARAMS.pIv` (offset 0, both layouts)
  and `.pAAD` (offset 16 for the legacy v2.20 layout, offset 24 for the
  current v2.40 layout — see the GCM entry above) are pointers to the
  actual bytes; `decode_params` reads only the three length/count
  scalars for whichever layout `ulParameterLen` exactly matches — the
  pointer offsets are never passed to `bpf_probe_read_user` in either
  layout. Refused because IV/AAD bytes can carry structured or identifying
  content
  (nonces are sometimes derived from sequence numbers or identities;
  AAD frequently *is* identity/context data by design). **Structural.**
  Canary: `CANARY_IV`, `CANARY_AAD`.
- **Sign/digest/encrypt input lengths.** The operational calls that carry
  a data pointer and length (`C_Sign`, `C_Digest`, `C_Encrypt`, and their
  `*Update` siblings) classify as `fnkind::SESSION_ARG0`
  (`src/kinds.rs:21-32`), whose BPF arm reads only `ctx.arg::<u64>(0)`
  (the session handle) — `crates/ebpf/src/main.rs:263-267`. No data
  pointer or length argument for these calls is ever read. Refused
  because the design spec calls this out explicitly: "sign *input
  lengths* can characterize messages" — even without content, a length
  can fingerprint a message format or protocol. **Structural** — no field
  in `CallStart`/`Event` exists to hold an input length, and no code path
  reads one. Canary: `CANARY_PLAINTEXT` (planted as `C_Digest`'s `pData`,
  which also proves the pointer itself is never dereferenced, not just
  that a length is withheld).
- **Raw handle values (session, beyond the internal pseudonym).** See the
  "Session handle" entry above — no raw or pseudonymized session
  identifier is emitted to any output today. **Structural**, stronger
  than a mere refusal-on-request: there is no output field capable of
  carrying one.
- **Any attribute value beyond a 1-byte boolean.** Covered by the policy
  boolean entry above — the `ulValueLen == 1` gate refuses any attribute
  whose declared length is not exactly one byte, and even for the 11
  allowlisted types, exactly one byte is ever read. **Runtime-gated**,
  directly tested by the `CANARY_BOOLLONG` case (see policy-boolean entry
  above) — this is the one rejected-candidate class with a canary built
  specifically to attack the gate, not just to confirm absence.

---

## Summary of weak points (for the adversarial reviewer)

Being explicit about the thin spots, per the brief's instruction that
flagging them is what makes this document credible:

1. **GCM's malformed-`ulParameterLen` gap is now closed; PSS's is not.**
   This gap was not hypothetical: the missing GCM canary is exactly what
   let a real defect ship — the pre-fix `decode_params` guarded
   `ulParameterLen >= 40` instead of matching a specific layout, so a
   modern 48-byte `CK_GCM_PARAMS` (the OASIS v2.40 layout, what
   `cryptoki_sys::CK_GCM_PARAMS` actually is) passed the guard and was
   decoded using the legacy 40-byte layout's offsets, reading
   `CK_GCM_PARAMS.pAAD` — a userspace pointer — into the field labeled
   `aad_len`. Every read still returned `Ok`, so the record rendered
   `completeness: COMPLETE` with no signal anything was wrong. Every
   existing canary run used only the 40-byte struct
   (`scripts/fixtures/canary_workload.c`'s original `CK_GCM_PARAMS`), so
   this suite could not have caught it. Fixed by making the offset match
   exact per layout (`(shape::GCM, 40)` / `(shape::GCM, 48)`, `crates/ebpf/src/main.rs`)
   and closing the coverage gap: the canary workload now drives a
   legacy 40-byte call, a modern 48-byte call with its own planted
   sentinel IV/AAD, and a malformed-length call that matches neither
   layout, with `scripts/verify-canaries.sh` asserting the malformed call
   decodes nothing (never a fabricated combo) and that no emitted numeric
   field looks like a pointer. The equivalent PSS gap — a short or
   malformed `ulParameterLen` for `CK_RSA_PKCS_PSS_PARAMS` — remains
   open: the canary suite now exercises the PSS *decode* path at all (it
   previously never did), but does not yet plant an adversarial length
   for it. `CK_RSA_PKCS_PSS_PARAMS` has one layout (three `CK_ULONG`s, no
   pointer fields), so the blast radius of a broken guard there is
   narrower than GCM's was — an out-of-bounds *scalar* read, never a
   pointer disclosure — but it is still a coverage gap to close, not a
   reason to consider this fully closed.
2. **`cgroup_id` is captured with no current consumer.** Not a leak (no
   output field exists for it), but capturing a field with no
   justification-by-use is exactly the pattern this document is supposed
   to prevent. Recommend either wiring it into a future per-container
   breakdown promptly, or dropping the capture until that lands.
3. **The plan's "session handle... pseudonymization suffices" framing is
   more conservative than what the code actually does.** The code doesn't
   need the reviewer to trust pseudonymization at all for v1, since no
   session identifier of any kind reaches output. This is a
   documentation correction in the tool's favor, but it means the *next*
   phase that adds a `trace` mode with per-event session identifiers will
   need a fresh justification — this document's "why pseudonymization
   suffices" reasoning has not actually been exercised by any shipped
   output path yet.

None of the 9 allowlisted field groups above were judged unjustifiable —
each answers a concrete, named migration-assessment question. The three
items above are process/coverage gaps, not fields that should be pulled
from the allowlist.
