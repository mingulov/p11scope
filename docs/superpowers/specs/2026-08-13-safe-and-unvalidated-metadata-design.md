# Safe and unvalidated metadata capture — design

**Date:** 2026-08-13

**Status:** Approved after independent deep review; implementation pending

**Amends:** `docs/superpowers/specs/2026-08-12-v0.1-corrective-release-design.md`

**Implementation plan:**
`docs/superpowers/plans/2026-08-13-safe-and-unvalidated-metadata.md`

## Goal

Keep mechanism profiling useful without letting an arbitrary readable target
pointer become a general metadata-output channel. Safe capture is the default
in every binary. Operators who need the metadata decoders that exist today may
compile and explicitly enable a diagnostic policy for trusted, ABI-valid
workloads.

This design changes pointer-derived metadata capture only. It does not close
or supersede the separately tracked provider-provenance, object-lease,
provider-loading, or teardown-order findings. Implementing it is not, by
itself, a release-readiness claim.

## Precedence over the corrective design

For `allowlisted` capture, this document supersedes the corrective design's
requirements to record rejected initialization requests, every vendor
mechanism id, parameters, templates, policy booleans, and hash-only async-name
authorization. It also supersedes the v1.3 profile-schema requirement.

For `unsafe-unvalidated-metadata`, the previous entry-time mechanism,
parameter, template, and async capture semantics remain unchanged, including
metadata from calls the provider later rejects. Every unrelated corrective
requirement remains in force for both policies.

## Security contract and assumptions

`bpf_probe_read_user` prevents a bad address from faulting the target, but it
cannot prove that readable bytes are a `CK_MECHANISM`, parameter structure,
template, or string. Safe capture therefore contains output rather than
claiming runtime C type validation:

- pointer-derived content can become evidence only through a finite public
  equality oracle: a published/configured mechanism id or one of the 104
  published function names;
- a value that fails either lookup remains only in BPF registers/stack and
  never enters `START`, an event, output, a log, or an error;
- pointer values are never public output;
- failures are categorical counts and never include rejected bytes.

The safe policy still assumes an ABI-valid caller for semantic truth. A caller
can race or mutate `pMechanism`, or put arbitrary numbers directly in ordinary
scalar arguments. The observer cannot prove which bytes a provider consumed.
It reports only a registered id observed at return from a call whose immediate
result was `CKR_OK` or `CKR_PENDING`; it does not call that value
cryptographically or provider-side authenticated.

Successful reads of provider-written `phSession` and async-id scalars require
a conforming provider that writes the promised output on success. They remain
internal correlation keys and are never serialized. A malicious native
provider is already code executing inside the target and is outside this
semantic guarantee.

The diagnostic unsafe policy has a deliberately weaker contract. It never
adds an intentional PIN, key, label, `CKA_ID`, message, signature,
wrapped-object, or arbitrary-buffer decoder, but its existing scalar decoders
follow caller-supplied pointer topology. A malicious caller can alias those
pointers into unrelated readable memory and disclose selected scalar words or
bytes. Unsafe mode is therefore for trusted ABI-valid workloads, not hostile
targets. Only `allowlisted` carries the strong arbitrary-pointer-content
boundary.

Eliminating even the safe policy's finite equality oracles, output-scalar
assumption, and mechanism TOCTOU requires a cooperative provider audit point
after provider-side validation. That is outside a portable uprobe observer.

## Capture policies

### `allowlisted` — default profile and trace

Safe capture retains:

- authenticated function identity, PID/TID and cgroup;
- scalar session/slot identifiers, session flags and login user type;
- return code, latency and aggregate/evidence counters;
- pointer nullness required by operation semantics;
- successful provider-written session and async identifiers, internally only;
- an approved mechanism id after an immediate `CKR_OK` or `CKR_PENDING`;
- bounded exact-match async target identity needed for PKCS #11 3.2 state.

For a mechanism-bearing call, the entry probe records only nullness plus the
raw `pMechanism` address needed by the return probe. This address is transient
privileged metadata in `START`; it is never dereferenced at entry and never
copied to `Event` or public output. On `CKR_OK` or `CKR_PENDING`, the return
probe reads exactly the first `CK_ULONG` with `bpf_probe_read_user`, immediately
checks `MECH_SHAPE` membership, and copies only an approved id into the event.
An unapproved raw value exists only during the lookup. The `START` record is
then removed normally.

The return-time read intentionally prioritizes provider-result gating over a
racy claim that the value is exactly what the provider consumed. `CKR_PENDING`
is captured there because the caller's pointer need not remain live until
completion. The approved id stays in the existing bounded pending state until
the final async result. If the final result is an error, the retained approved
id can still identify that initially pending operation.

Other immediate returns never dereference `pMechanism` and are not attributed
to a requested mechanism. That is a selected-policy limitation, not event
loss, so it does not make the capture `PARTIAL`. After `CKR_OK` or
`CKR_PENDING`, a non-null pointer that is unreadable increments
`semantic_capture_failures`; a readable but unapproved id increments
`unregistered_mechanisms`. Both withhold the value, clear any unsafe binding,
and force `PARTIAL`. Null remains a distinct state for function-specific
null-cancellation rules.

Safe PKCS #11 3.2 async correlation keeps the existing bounded name decoder.
It snapshots at most `FUNCTION_NAME_MAX_BYTES + 2` bytes on the BPF stack,
requires a NUL-terminated exact match to one of the 104 published names, and
persists only its numeric table id. Hash-plus-length is not exact matching: a
hash may select a candidate, but authorization must compare the captured bytes
and length with the canonical name. The smallest preferred representation is
an immutable map keyed by a zero-padded fixed-size `{ length, bytes }` value,
not by an FNV hash. The raw pointer and name never enter `START`, an event, or
output. Null, unreadable, overlong, and unknown names increment existing async
evidence and force `PARTIAL` when correlation is required.

Safe mode does not walk parameter structures or templates and does not read
template boolean values. Those omissions are identified as disabled by policy,
not decode attempts, and therefore do not increment shape/template failure
evidence. It also does not attach template-specific entry or tail-call
programs.

### `unsafe-unvalidated-metadata` — diagnostic profile and trace

This policy preserves exactly the decoder behavior immediately before this
design:

- entry-time, full-width mechanism ids, including unregistered vendor ids and
  requests the provider later rejects;
- RSA-PSS `hashAlg`, `mgf`, and `sLen` for the exact known structure length;
- GCM IV length, AAD length, and tag bits for the exact supported layouts;
- bounded template attribute type ids and the existing eleven one-byte policy
  booleans;
- bounded exact-match standard async function names and current internal async
  correlation data.

It adds no decoder, widens no bound, and emits no pointer value. Invalid
addresses still become evidence rather than target faults. Readable but
semantically unrelated memory can produce decoded scalar metadata, as stated
in the unsafe contract above. A warning describing that risk is printed to
stderr before discovery or attachment.

Preserving the unsafe decoder does not preserve silent capture gaps. Every
fixed pointer offset uses checked arithmetic; overflow records a semantic
capture failure and performs no read. If a template attribute type was
captured but its allowlisted boolean metadata or byte is unreadable, the type
remains captured, the boolean remains unknown, and the failure forces
`PARTIAL`, including for a one-entry or final-entry template.

Mechanism presence is determined only by `capture::MECHANISM_*`, never by a
numeric sentinel comparison. This preserves a real full-width vendor id equal
to `u64::MAX` in state, JSON, and trace.

### `aggregate-only` — metrics

Metrics is a real kernel capture policy, not merely a userspace decision to
leave the ring unread. Entry records only the timestamp needed for aggregate
latency and updates `STATS`; it reads no semantic argument or target pointer.
Return updates `STATS` and `RV_COUNTS`, removes the timestamp record, and does
not reserve or emit an `Event`. The fork tracepoint, semantic state, async name
table, mechanism registry, template maps, and template programs are not used.

Semantic evidence stays zero because capture was deliberately disabled, not
lost. Aggregate map update/start-pairing failures retain their ordinary
evidence and can force `PARTIAL`.

## Mechanism approval registry

`MECH_SHAPE` remains the single membership-and-shape map. The approved set is
the deduplicated union of:

1. every value in
   `pkcs11_proxy_ng_types::PKCS11_3_2_OFFICIAL_MECHANISMS`; and
2. every trusted configured id in `MechanismRegistry::registered_mechanisms()`.

The pinned official inventory currently contains 463 unique published PKCS
#11 3.2 values and is cumulative for published 2.0x, 2.40, 3.0, 3.1, and 3.2
mechanisms. `MechanismRegistry` is a parameter-model/configuration registry,
not the standards-completeness oracle. It supplies an optional decoder shape
and approved configured vendor ids. Every other official id is still inserted
with `shape::NONE`.

The complete union must fit `MAX_MECH_SHAPES`; capacity overflow aborts before
attachment and never truncates. Publication is exact and deduplicated. Safe
capture interprets map presence as approval and the value as an optional shape
only. Unsafe capture records absent ids exactly as today. Userspace loads
parameter-shape expectations only in unsafe mode, so a deliberately omitted
safe decode cannot become a false total-decode failure. This design adds no
registry-path CLI; the current embedded registry is the only configured source.

## Compile-time and runtime gates

Add the off-by-default Cargo feature `unsafe-unvalidated-metadata` to the root
and eBPF crates. The default embedded eBPF object compiles out `decode_params`,
`walk_template`, the unsafe branches, template entry/tail programs, and
`ATTR_BOOL_BITS`. Shared `CallStart`/`Event` layout stays feature-independent so
host/eBPF ABI tests cover both artifacts.

The feature build contains both runtime paths in one eBPF object. With no flag
it attaches the safe generic entry program; with the flag it attaches the
current template variants where required and enables the unsafe parameter
branch. No second object or new dependency is introduced.

`build.rs` reads `CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA` and forwards that
eBPF feature. It builds one combined feature list so the existing
`P11SCOPE_SMALL_RING` test mode and the unsafe feature work together. Required
build cases are default, unsafe, small-ring, and unsafe+small-ring, including
direct embedded-eBPF builds.

The root CLI accepts `--unsafe-unvalidated-metadata` only for `profile` and
`trace`:

- default build, no flag: `allowlisted`;
- default build, flag: refuse during argument validation, before discovery,
  privilege use, or attachment, and name the required Cargo feature;
- feature build, no flag: `allowlisted`;
- feature build, flag: `unsafe-unvalidated-metadata`;
- `profile --mode metrics` plus the flag: refuse;
- `discover`: never accepts the flag.

## Immutable publication before attach

Use one small userspace `CapturePolicy` enum as the sole source of policy bits,
program selection, renderer labels, and warnings. Compose one `CONFIG` word
containing exactly one scope bit and exactly one capture-policy bit. A missing
or conflicting scope/policy combination is rejected by userspace and fails
closed in eBPF.

One owner publishes the complete configuration in this order:

1. scope filters and the composed `CONFIG` word;
2. slot semantics and, where used, async names, mechanism approvals/shapes,
   and boolean attributes;
3. exact readback of the word and every expected policy-map entry, with no
   extras, except for the `CGROUP_FILTER` syscall-readback limitation described
   below;
4. `BPF_MAP_FREEZE` on those immutable data/control maps;
5. program load, with no attachment yet;
6. when the unsafe feature is compiled, populate `TEMPLATE_TAIL` from the
   now-loaded tail program only for an unsafe invocation, read it back, and
   freeze it; safe/aggregate invocations freeze the compiled map empty;
7. attachment.

The immutable control maps are `CONFIG`, `PID_FILTER`, `CGROUP_FILTER`,
`SLOT_SEMANTICS`, `ASYNC_FUNCTIONS`, `MECH_SHAPE`, and, when compiled,
`ATTR_BOOL_BITS` and `TEMPLATE_TAIL`. Compiled optional control maps are frozen
empty when the selected policy does not use them. Ordinary Array/HashMap
controls are declared program-read-only and no eBPF path updates any control
map. Linux rejects `BPF_F_RDONLY_PROG` for fd-array map types, so
`CGROUP_FILTER` (`CgroupArray`) and `TEMPLATE_TAIL` (`ProgramArray`) are explicit
flag exceptions; their map types, absence of a BPF update path, exact
publication checks, and `BPF_MAP_FREEZE` provide the equivalent selected-policy
contract.

`CGROUP_FILTER` is also the sole readback exception: its Linux map type does
not support `BPF_MAP_LOOKUP_ELEM`. Userspace instead validates its map type and
one-entry capacity, retains the already validated source cgroup fd, requires a
successful `set(0, fd)`, freezes the map, and covers effective membership with
the live in-scope/out-of-scope cgroup gate. `TEMPLATE_TAIL` is read back as the
expected loaded program id before it is frozen. Every map is frozen before it
can influence an attached program. Any required publication, supported
readback, or freeze failure aborts. Dynamic data maps such as `START`, `STATS`,
`RV_COUNTS`, `EVENTS`, and `EVIDENCE` are not frozen.

Aya 0.14.0 does not expose its internal `bpf_map_freeze` wrapper. Implement one
private helper in `src/attach.rs` using the already-present `libc` dependency:
match only the expected Aya `Map` variants to their public `MapData::fd()`,
invoke `bpf(BPF_MAP_FREEZE, ...)` with a zero-initialized map-fd attribute, and
return an error naming the map and syscall failure. An unexpected map variant
or any freeze error aborts before attachment. This is a small Linux UAPI shim,
not a reason to add a dependency or fork Aya. The live gate proves it with an
otherwise-valid mutation that returns `EPERM` after freeze and succeeds on an
unfrozen control.

This removes the current risk that separate configuration writers overwrite
scope or policy bits, and prevents a feature build from being switched to
unsafe capture after output was labeled safe.

## Evidence and output contracts

Every presentation identifies policy:

- JSON: required `capture.privacy_mode`;
- live profile/metrics: policy in every frame header;
- trace: `CAPTURE privacy=<mode>` before calls and the same field in the final
  machine-readable `EVIDENCE` record;
- unsafe invocation: an additional stderr warning before discovery/attach.

Allowed values are `allowlisted`, `unsafe-unvalidated-metadata`, and
`aggregate-only`. Labels always come from the immutable userspace enum whose
bits passed publication/readback; they are not inferred later from mutable
maps.

The provenance supervisor owns the exceptional lease-break ending. After it
has killed and reaped the worker, it appends a bounded terminal `EVIDENCE`
record to every writable trace sink with `completeness: "PARTIAL"`, the
immutable `privacy_mode`, `capture_aborted: "object_lease_break"`,
`final_drain: false`, `counters_available: false`, and `event_loss: null`.
Other ordinary evidence fields are absent in this discriminated abort variant
because the supervisor has no BPF state from which to derive them. Normal
terminal evidence has `counters_available: true`. Exit 78 remains authoritative,
and a consumer treats either exit 78 or an absent terminal `EVIDENCE` record as
truncated output. The supervisor does not invent a numeric `LOST` count after
killing the only BPF owner. Profile JSON is written only to a
supervisor-prepared same-directory temporary fd; after a
valid completion record and pidfd-confirmed normal worker exit, the supervisor
releases the leases and atomically publishes it. A lease-broken or abnormal
worker never leaves a valid profile document.

Profile advances from `pkcs11-scope/observed-profile/v1.3` to
`pkcs11-scope/observed-profile/v1.4`. Metrics advances from
`pkcs11-scope/observed-profile/v1-metrics` to
`pkcs11-scope/observed-profile/v1.1-metrics`; consumers dispatch on the exact
schema string.

The v1.4 profile representation is explicit:

- safe mechanism statistics begin only with an init/direct call whose
  immediate result allowed an approved id to be observed; later operation
  calls attributed through that binding are included. Rejected initialization
  requests are not. `functions[]` remains the authority for all calls and
  return codes;
- unsafe mechanism totals retain v1.3 request attribution, including rejected
  initialization attempts;
- safe `mechanisms[].params` is `null` with a note that decoding was disabled
  by `allowlisted`, never a shape failure;
- safe `templates.operations` is empty and `templates.note` says template
  capture was disabled by policy, so emptiness is not evidence that no template
  was used;
- unsafe keeps the existing parameter/template structures and decode-failure
  meanings, but their notes explicitly call the values unvalidated
  pointer-derived metadata rather than describing them as safe or allowlisted.

Reuse `evidence.semantic_capture_failures` for safe mechanism reads after
`CKR_OK`/`CKR_PENDING` that fault. Add `evidence.unregistered_mechanisms` as a
count only. Either forces `PARTIAL`. Policy-disabled parameter/template
capture does not affect completeness. Selecting unsafe does not itself force
`PARTIAL`: completeness means no gaps within the selected policy, while
`privacy_mode` identifies the policy.

The v1.3 and v1-metrics schemas are internal waypoints in the unreleased
corrective tree. If this design lands before the next artifact, the published
migrations are v1.2→v1.4 and v0-metrics→v1.1-metrics. The schema may retain an
internal-waypoint appendix for implementation history, but must not imply that
consumers received an intermediate release. Every migration note states the
semantic and structural differences; older documents are never reinterpreted.

## Verification

### Unprivileged contracts

The ordinary suite pins:

1. all CLI/build combinations and early flag refusal;
2. all legal scope/policy `CONFIG` words and rejection of conflicting bits;
3. exact policy-map publication, readback, capacity failure, and freeze order:
   data policy before program load, tail-call target after load, all before
   attach; object inspection pins `BPF_F_RDONLY_PROG` on ordinary immutable
   Array/HashMap controls and its required absence on the two fd-array maps;
4. exactly 463 official ids at the pinned dependency revision (the test names
   that pin so a dependency update is a deliberate standards-inventory
   decision), cumulative standards coverage, configured vendor union,
   deduplication, `shape::NONE`, capacity refusal, and `u64::MAX` presence by
   capture tag;
5. safe `CKR_OK`/`CKR_PENDING`, failed/unreadable/unregistered/null mechanism
   boundaries and async pending completion;
6. safe byte-exact async names and categorical rejection of unknown names;
   structural coverage proves no hash-only authorization path remains and a
   non-catalog byte string sharing a test-injected legacy hash is rejected;
7. policy-aware shape/template evidence and v1.4/v1.1-metrics JSON, live, and
   trace markers;
8. aggregate-only argument/pointer non-read and zero event emission;
9. default, unsafe, small-ring, and unsafe+small-ring host/eBPF builds with
   unchanged shared ABI sizes;
10. default-object inventory proves unsafe-only programs/maps are absent;
11. unsafe fixed-offset overflow and unreadable allowlisted boolean
    metadata/value failures perform no derived read, retain any already read
    attribute type, and force `PARTIAL`, including at the final entry.

### Approval-gated live canaries

The safe workload passes `pMechanism` pointing to a readable unknown
eight-byte sentinel, has the provider return `CKR_OK`, and proves the sentinel
never appears in observer-owned maps, events, logs, or output. A separate
approved standard-id case proves safe mechanism usefulness. The test resolves
this run's map ids, observes a nonempty `START`, and verifies that its allowed
raw address field is never mistaken for pointee content or emitted publicly.

Malicious-alias fixtures route benign sentinels through every existing pointer
decoder. Safe mode must contain all of them except the documented finite
catalog matches. Unsafe mode must reproduce the existing scalar decodes and
its warning/labels; that lane demonstrates the documented risk rather than
claiming hostile-target safety. Both policies retain ordinary-placement
canaries for PIN, key material, label, `CKA_ID`, plaintext, ciphertext,
signature, wrapped-object, random output, and normal buffers, none of which has
an intentional decoder.

Additional live cases cover safe async exact matching, aggregate-only empty
events, feature co-builds, and the `u64::MAX` trace regression. After attach,
a mutation by exact map id must fail with the frozen-map `EPERM` for every
control map. Each mutation uses an otherwise-valid value or deletes a
populated fd-array entry, and a matched unfrozen control proves the same
operation would otherwise succeed; an invalid cgroup/program fd is not a
freeze test. Ordinary kernel updates to dynamic aggregate/evidence maps must
still work. Missing privilege fails or is reported as unrun according to the
existing gate contract; it is never converted to a pass.

## Release and documentation

The implementation plan's final integration task is the sole owner of README,
usage, privacy allowlist, observed-profile schema, changelog, ROADMAP,
release/matrix scripts, and `tests/release_contracts.rs` for both this design
and provenance-plan Task 6. Execute provenance Tasks 4–5 first, metadata Tasks
1–5 next, then that one integration task, then provenance Task 7. Public
wording makes the safe/unsafe trust distinction prominent and never describes
`bpf_probe_read_user` as pointer validation. The allowlist update explicitly
records the transient raw `START.pMechanism` address, its no-entry-dereference
guard, bounded lifetime, privileged-map exposure, and prohibition from public
output.

Official artifacts use `--no-default-features` in a dedicated
`CARGO_TARGET_DIR`, reject the unsafe flag, and contain no unsafe-only eBPF
program/map inventory. Unsafe canary/diagnostic builds use a different target
directory and are never copied into the release archive.

Before release, the separately open provider provenance, dependency leasing,
`$ORIGIN`/fd loading, and lease-break teardown findings must be fixed and
re-reviewed. The still-open final-review tasks in
`docs/superpowers/plans/2026-08-13-manifest-provenance.md` remain authoritative;
this metadata design does not waive them.

## Alternatives and decision

- Removing all target-pointer reads gives the strongest boundary but loses
  mechanism profiling and PKCS #11 3.2 async correlation.
- Keeping the current decoders as the default preserves detail but cannot be
  safe against pointer aliasing.
- A cooperative provider audit point can authenticate structures but is not a
  general observer for existing providers.

The selected design is the smallest portable compromise: one safe default,
one explicit compile-time-plus-runtime diagnostic escape hatch, one aggregate
path, the existing map inventory and shared event ABI, and no new dependency
or second BPF object.

## Acceptance criteria

- `allowlisted` is the default in every profile/trace-capable build;
  `aggregate-only` is the only metrics policy.
- Default artifacts compile out and cannot activate unsafe decoders.
- Feature plus runtime flag reproduces all and only the pre-design metadata
  decoders and is labeled as unsafe for trusted ABI-valid workloads.
- Safe output contains only approved mechanism ids and exact published async
  target ids; rejected pointer-derived values never persist.
- All 463 published mechanism ids plus trusted configured vendor ids are
  approved without silent capacity loss.
- Policy and registry maps receive every supported exact readback and are
  frozen before they can influence an attached program. `CGROUP_FILTER` uses
  validated type/capacity, successful set, retained source fd, freeze, and the
  live membership gate because its map type has no syscall lookup. Output
  labels cannot diverge from selected policy.
- Metrics performs no semantic pointer read and emits no semantic event.
- Full-width `u64::MAX` mechanism ids render when the capture-state tag says a
  value is present.
- Every JSON, live, and trace output identifies privacy policy and the schema
  migration is explicit.
- Default/feature/co-feature gates pass, and approval-gated canaries pass
  before release.
- Separate provenance and teardown blockers are resolved and re-reviewed; this
  design alone is never used as a release-clearance claim.
