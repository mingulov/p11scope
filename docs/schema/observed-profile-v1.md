# `observed-profile.json` schema v1 / v1.1

**Schema string:** `"pkcs11-scope/observed-profile/v1.1"` (current; `"v1"`
documents describe the schema before Phase 3 landed parameter/template
decoding — see "v1 → v1.1: what changed" below for the exact, additive-only
delta).
**Producer:** `p11scope profile` (default `--mode profile`; `--mode metrics`
instead emits the lighter `pkcs11-scope/observed-profile/v0-metrics`
document — `capture`/`evidence`/`functions` only, no `mechanisms`,
`sessions`, `logins`, or `templates`).
**Rust type:** `render::profile_json(reports, ev, state, capture) ->
serde_json::Value` in `src/render.rs`.

This is the integration boundary described in the
[outputs spec](../superpowers/specs/2026-08-10-pkcs11-scope-outputs.md) and
the [design spec](../superpowers/specs/2026-08-10-pkcs11-scope-design.md)
("Profile schema requirements (drives Gate G2)"): `pkcs11-lab` reads this
file to produce its five migration-assessment categories. Each section
below states explicitly which category it supports.

## Field sourcing: maps vs events

Two independent data paths feed this document, and they answer different
questions:

- **Aggregate BPF maps** (`STATS`, `RV_COUNTS`) are the **count
  authority**. They see every attached call, are never subject to
  ring-buffer loss, and are cheap enough to run unbounded. `functions` is
  built from them exclusively.
- **The event stream** (ring buffer → `events::Drain` → `semantics::State`)
  is the only path that reconstructs *semantic* context — which mechanism
  a session's active operation is using, session open/close pairing, login
  user type — because that requires correlating consecutive calls on the
  same session, which the per-slot aggregate maps cannot express. It is
  subject to ring-buffer loss (`evidence.event_loss`) and per-record
  decode failures (`evidence.malformed_records`). `mechanisms`, `sessions`,
  and `logins` are built from it exclusively; there is no aggregate-map
  equivalent for any of them.
- **The mechanism registry** (`pkcs11-proxy-ng-types::MechanismRegistry`,
  loaded embedded-default, no config-file plumbing) is a third, much
  narrower input: it only affects whether `mechanisms[].note` can tell "no
  allowlisted shape for this id" apart from "an allowlisted shape whose
  decode failed on every call" (`shape_decode_total_failures`, new in
  v1.1) — the same registry `shapes::publish` already used to fill
  `MECH_SHAPE` before attaching. It never adds or removes a mechanism
  entry, changes any count, or supplies any value inside `params`.

Where a reader needs an authoritative call count for a specific function
name, use `functions`, never sum `mechanisms[].calls` — a session's
operational calls (`C_Sign`, `C_Encrypt`, ...) are attributed to the
mechanism they're running under, not counted per function name there.

## Top-level shape

```json
{
  "schema": "pkcs11-scope/observed-profile/v1.1",
  "capture": { "...": "..." },
  "evidence": { "...": "..." },
  "functions": [ { "...": "..." } ],
  "mechanisms": [ { "...": "..." } ],
  "sessions": { "...": "..." },
  "logins": { "...": "..." },
  "templates": { "note": "...", "operations": [ { "...": "..." } ] }
}
```

All seven sections are always present, even when empty (`functions: []`,
`mechanisms: []`, `logins: {}`, `templates.operations: []`) — a consumer
should never need to special-case a missing section. Enforced by
`render::tests::profile_json_has_every_required_top_level_section`.

## `capture`

| Field | Type | Meaning |
| --- | --- | --- |
| `start` | string (RFC3339 UTC) | Wall-clock capture start. |
| `end` | string (RFC3339 UTC) | Wall-clock capture end (write time). |
| `mode` | string | Always `"profile"` in this document. |
| `kernel` | string | `uname -r` (`/proc/sys/kernel/osrelease`), for correlating capture behavior with kernel version. |
| `module.path` | string | The `--module` / manifest `module_path` dlopen target. |
| `module.build_id` | string or `null` | The primary module object's identity value from the manifest (`ObjectRecord.identity.value` for the object whose path equals `module_path`) — a GNU build-ID hex string when available, a SHA-256 fallback digest otherwise, or `null` when the manifest recorded `Unavailable`. Lets a profile be matched back to the exact provider binary later, independent of file path. |

**Gate G2:** `capture.start`/`capture.end` are the capture-window metadata
the **UNKNOWN** category needs — anything not seen in this window reads as
"not observed in this window", never as "not needed".

## `evidence`

Widened from Phase 1b's `render::Evidence` (unchanged fields carry the same
meaning as in the `v0-metrics` document):

| Field | Type | Meaning |
| --- | --- | --- |
| `table_entries` | number | Function records seen across every walked manifest surface. |
| `slots` | number | Unique `{object, file_offset}` attach targets planned. |
| `attached_probes` | number | Probes successfully attached (2 per fully-attached slot). |
| `attach_failures` | array of strings | One message per failed attach. |
| `aliased` | array of arrays of strings | Slots whose counts belong to a name group, not one name. |
| `skipped` | array of `{name, reason}` | Manifest entries with no attachable target. |
| `in_flight_at_end` | number | Calls entered but not returned by capture end. |
| `surfaces` | array of `{source, walk, acquisition, functions}` | Per-manifest-surface discovery provenance. |
| `vendor_interfaces` | number | Present-but-undecoded vendor interfaces. |
| `interface_list` | string | Outcome of the manifest's `C_GetInterfaceList` enumeration. |
| **`event_loss`** | number | *(new in v1)* Ring-buffer events the kernel could not reserve space for (`metrics::lost_events`), summed across the whole capture. Always `0` in `--mode metrics`, which never drains the ring buffer. |
| **`malformed_records`** | number | *(new in v1)* Ring-buffer records rejected by `events::decode`'s size check — the writer/reader layout drifted mid-capture. Always `0` in `--mode metrics`. |
| **`orphan_ops`** | number | *(new in v1)* Operational calls (`C_Sign`, `C_Encrypt`, ...) observed with no active `*Init` on their session — expected when the capture attaches mid-operation. Informational: does **not** affect `completeness`. |
| **`unmatched_closes`** | number | *(new in v1)* `C_CloseSession` calls observed with no matching open. Same: informational, does not affect `completeness`. |
| **`shape_decode_failures`** | number | *(new in v1.1)* `*Init` calls whose parameter decode did not apply (`Event::shape == shape::NONE`), counted for every mechanism id **known to have an allowlisted shape** this capture (`semantics::State::shape_decode_failures`) — either because it decoded successfully at least once elsewhere (the signal available even without registry access), or because `p11scope profile` published a shape for that id (`shapes::expected_shapes`, wired into `semantics::State::set_mech_shapes`; see `mechanisms[].params` below). A call count, informational: does **not** affect `completeness` by itself, since an inconsistent (sometimes decodes, sometimes doesn't) decode may reflect provider-side parameter validation rather than a capture defect. For the subset of this signal that *does* gate `completeness` — mechanisms that decoded on **zero** calls despite having a published shape — see `shape_decode_total_failures`. |
| **`shape_decode_total_failures`** | number | *(new in v1.1)* Count of **mechanism ids** (not calls) with a published shape whose decode **never once succeeded** this capture (`semantics::State::total_shape_decode_failures`) — e.g. every `C_EncryptInit` for `CKM_AES_GCM` hits the `ulParameterLen` guard because a nonstandard provider passes a shorter/differently-laid-out `CK_GCM_PARAMS`. Unlike `shape_decode_failures`, this **does** gate `completeness`: a mechanism id known (via the registry) to have a decodable shape, that never once decoded, is a real decode regression — wrong offsets, a too-short parameter buffer, or an unfaulted page, consistently — not ordinary provider-side rejection variance. Such a mechanism still renders `params: null` in `mechanisms[]`, but with a distinct `note` that says so explicitly rather than the "not attempted here" wording (see `mechanisms[].params` below). Always `0` in `--mode metrics`. |
| **`templates_truncated`** | boolean | *(new in v1.1)* True when any `templates.operations[]` entry observed `attr_total > attr_count` — the template had more entries than the per-event `MAX_ATTRS` (8) cap, **or** the in-kernel walk stopped early because a `bpf_probe_read_user` failed mid-template (an unreadable `pTemplate`/entry) — this field does not distinguish which cause. A short template (well under 8 entries) can still set this if the walk hit a read failure; do not assume ">8 entries" is the only cause. Unlike the two informational counters above, this **does** gate `completeness`: either cause is lost evidence, not merely context. Always `false` in `--mode metrics`, which never drains the ring buffer or builds `templates`. |
| `completeness` | `"COMPLETE"` or `"PARTIAL"` | See below. |

**Completeness verdict.** `COMPLETE` requires every one of: no attach
failures, no skipped entries, no aliasing, no in-flight calls, every
surface fully walked with a successful acquisition, no undecoded vendor
interfaces, `event_loss == 0`, `malformed_records == 0`, `templates_truncated
== false`, **and (new in v1.1) `shape_decode_total_failures == 0`**. Any
other gap — including a nonzero `event_loss`, `malformed_records`,
`templates_truncated == true`, or `shape_decode_total_failures > 0` —
forces `PARTIAL`. `orphan_ops`, `unmatched_closes`, and
`shape_decode_failures` are reported for visibility but never flip the
verdict on their own: they are expected consequences of attaching
mid-operation, or of provider-side parameter handling that fails
*inconsistently*, not evidence the capture itself lost anything. A
mechanism failing *consistently* (`shape_decode_total_failures`) is
different — see that field's row above. Enforced by
`render::tests::any_gap_forces_partial`,
`render::tests::orphan_ops_and_unmatched_closes_do_not_affect_completeness`,
`render::tests::profile_json_template_truncation_forces_partial_and_evidence_field`,
and `render::tests::total_decode_failure_forces_partial_with_an_honest_note`.

**Gate G2:** the whole `evidence` section, together with `capture`, is what
keeps **UNKNOWN** honest — a reader can tell "not observed because it
didn't happen" from "not observed because the capture had gaps".

## `functions`

Array, one entry per attach **slot** (aliased slots — several logical
names sharing one address — appear once, as a group), **sourced from the
aggregate maps**:

| Field | Type | Meaning |
| --- | --- | --- |
| `names` | array of strings | Every function name resolving to this slot. |
| `aliased` | boolean | `true` when ≥2 distinct names share this slot. |
| `calls` | number | Completed calls (entry and return both observed). |
| `errors` | number | Of those, how many returned a nonzero `CK_RV`. |
| `in_flight` | number | Entered but not yet returned at read time. |
| `latency_ns` | object | See "Latency shape" below. |
| `rv_counts` | object | `CK_RV` (formatted `"0xHHHHHHHH"`) → count. |

**Gate G2:** per-function call/error counts feed **OBSERVED AND
VALIDATED** and **OBSERVED BUT CANDIDATE DIFFERED** (both want exact
call/error counts alongside the mechanism match).

## `mechanisms`

Array, one entry per distinct mechanism id observed, **sourced from the
semantic state machine** (event-derived; no aggregate-map equivalent
exists for per-mechanism breakdown):

| Field | Type | Meaning |
| --- | --- | --- |
| `mechanism` | number | The `CK_MECHANISM_TYPE` value, verbatim — vendor-defined ids (e.g. `0x80001042`) survive unchanged, never dropped or renamed. |
| `mechanism_hex` | string | The same value, hex-formatted (`"0x80001042"`), for display/matching convenience. |
| `ops` | array of strings | Operation categories this id was seen initializing: `"digest"`, `"sign"`, `"verify"`, `"encrypt"`, `"decrypt"`, `"sign_recover"`, `"verify_recover"`. A set, not a scalar — the same id can legally serve more than one operation. Empty when the id was only ever seen driving an orphan operational call (no `*Init` observed this capture — see `evidence.orphan_ops`). |
| `calls` | number | Completed calls attributed to this mechanism: its `*Init` calls plus the operational calls (`C_Sign`, `C_SignUpdate`, `C_SignFinal`, ...) run under it. |
| `errors` | number | Of those, how many returned nonzero `CK_RV`. |
| `latency_ns` | object | See "Latency shape" below. |
| `params` | `null` or array | *(behavior changed in v1.1 — see below)* |
| `note` | string | Human-readable restatement of the `params` value's meaning. |

**`params` in v1.1.** `null` when no allowlisted parameter shape ever
decoded for this mechanism id in this capture. Two distinct causes
collapse into the same `null` value, but `note` now tells them apart
(both `note` strings are exact — match on them, don't parse `params`
alone to infer which case applies):

- **No allowlisted shape for this mechanism id.** The ordinary, expected
  case for most mechanisms — its registry shape isn't one of the two this
  phase decodes (or it has no registered shape at all). `note`:
  `"parameter decoding is Phase 3; not attempted here, never a partial
  decode"` — **unchanged from v1's `params: null` behavior**, same
  wording as before. Does not affect `completeness`.
- **An allowlisted shape whose decode failed on every call.** This
  mechanism id *is* one of the two shapes this phase decodes — `p11scope`
  published it into `MECH_SHAPE` from the registry — but not one observed
  `*Init` call for it decoded successfully this capture (a provider
  parameter-layout mismatch, an `ulParameterLen` that's always too short,
  an unfaulted `pParameter` page every time, ...). `note`: `"this
  mechanism has an allowlisted parameter shape, but every decode attempt
  failed in this capture (see evidence.shape_decode_total_failures and
  evidence.shape_decode_failures) — never a partial decode"`. This
  mechanism also forces `evidence.shape_decode_total_failures > 0` and
  `completeness: PARTIAL` — read "not attempted" in the first bullet's
  note as never applying here; this is "attempted and failed," a real
  decode regression, not the benign case.

Distinguishing these needs the mechanism registry (which id → shape was
published), not just the event stream — `semantics::State::set_mech_shapes`
carries that from `shapes::expected_shapes`, called once in `main.rs`
alongside the existing `Session::start` registry load. A consumer of an
older, unpatched build (or a `State` a caller never called
`set_mech_shapes` on) only ever sees the first, benign note — this is a
safe default, not silent data loss: the mechanism's absence from
`params`/non-null combos is still visible, just not yet labeled as a
regression.

Otherwise `params` is an **array** of shape-tagged parameter-combination
objects — one entry per **distinct** combination of decoded scalar values
observed on this mechanism's `*Init` calls, each carrying its own `count`.
This is deliberately not a single object, an average, or a "latest wins"
value: migration assessment needs the actual combos a mechanism was driven
with (e.g. "this mechanism was called with a 96-bit tag 40 times and a
128-bit tag once" is different evidence from "this mechanism used a
128-bit tag"). Two shapes decode in this phase:

```json
// RSA-PKCS-PSS (CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, ...)
{ "shape": "rsa_pkcs_pss", "hash_alg": 592, "hash_alg_hex": "0x250",
  "mgf": 1, "salt_len": 32, "count": 40 }

// AES-GCM (CKM_AES_GCM)
{ "shape": "gcm", "iv_len": 12, "aad_len": 0, "tag_bits": 128, "count": 1 }
```

| Shape | Fields | Source (`CK_*_PARAMS` field) |
| --- | --- | --- |
| `rsa_pkcs_pss` | `hash_alg`, `hash_alg_hex`, `mgf`, `salt_len` | `hashAlg`, `mgf`, `sLen` |
| `gcm` | `iv_len`, `aad_len`, `tag_bits` | `ulIvLen`, `ulAADLen`, `ulTagBits` |

Both shapes' fields are scalars read directly at fixed offsets in-kernel;
no pointer field (`CK_GCM_PARAMS.pIv`/`pAAD`, PSS has none) is ever
dereferenced. Every combo is recorded regardless of the `*Init` call's
`CK_RV` — same rationale as `mechanisms[].calls`: the application
genuinely requested these parameters, and that request is the evidence,
independent of whether the operation succeeded.

**Gate G2 — narrower than v1's gap, not closed for every shape.**
`mechanism`/`mechanism_hex` verbatim preservation is exactly what
**OBSERVED BUT NOT COVERED BY CORPUS** needs (raw vendor ids preserved,
never dropped). For the two decoded shapes (`rsa_pkcs_pss`, `gcm`),
**OBSERVED AND VALIDATED** / **OBSERVED BUT CANDIDATE DIFFERED** can now
join on the full key the design spec's acceptance table wants: **mechanism
+ parameter combo** (hash/MGF/salt, or GCM IV/AAD/tag lengths), not just
mechanism id. For every other shape — including mechanisms the registry
marks parameterless, or shapes not on this phase's allowlist (e.g.
`ecdh1_derive`) — `params` stays `null` and a `pkcs11-lab` consumer can
still only join **by mechanism id**. Report this precisely: id-only for
undecoded shapes is a known, disclosed v1.1 limitation, not those
categories being unsupported.

## `sessions`

Single object, **sourced from the semantic state machine**:

| Field | Type | Meaning |
| --- | --- | --- |
| `opened` | number | `C_OpenSession` calls that returned `CKR_OK`. |
| `closed` | number | `C_CloseSession` calls that matched a currently-open session and returned `CKR_OK`. Does not include `evidence.unmatched_closes`. |
| `peak_concurrent` | number | The highest number of sessions open at once, at any point in the capture. |
| `balance` | number | `opened - closed`: sessions still open (or leaked) at capture end. |

**Gate G2:** supports the session-leak / login-frequency diagnostic use
case from the outputs spec ("Is the app leaking sessions?"); not one of
the five `pkcs11-lab` categories directly, but referenced there as
capture-quality context.

## `logins`

Object mapping the observed `CK_USER_TYPE` value, stringified (e.g.
`"1"` for `CKU_USER`, `"0"` for `CKU_SO`, `"2"` for
`CKU_CONTEXT_SPECIFIC`), to the number of successful `C_Login` calls seen
with that user type. v1 does not carry a `CKU_*` name registry (no new
dependency was added for it — see the task's global constraints), so
readers must map the numeric key themselves; the raw values match the
PKCS#11 header constants exactly.

## `templates` *(new in v1.1)*

```json
{
  "note": "every field here is what the application asked for via a CK_ATTRIBUTE template — never asserted as the key's effective policy; the provider may reject, ignore, or override any of it (see the `requested` marker on each operation)",
  "operations": [
    {
      "names": ["C_FindObjectsInit"],
      "aliased": false,
      "requested": true,
      "attr_types": [
        { "attr_type": 1, "attr_type_hex": "0x1" },
        { "attr_type": 258, "attr_type_hex": "0x102" }
      ],
      "policy_booleans": { "observed_true": ["CKA_TOKEN"], "observed_false": ["CKA_PRIVATE"] },
      "truncated": false
    }
  ]
}
```

**Requested, never effective — the load-bearing caveat.** Everything in
this section is what the application put in a `CK_ATTRIBUTE` template when
calling `C_FindObjectsInit`, `C_CreateObject`, or `C_GenerateKey`. It is
**never** the key's actual, effective policy: the provider may silently
reject the call, ignore an attribute it doesn't support, or apply a
different default than what was asked for. `templates.note` states this in
prose once at the section level; each operation additionally carries
`"requested": true` as an explicit, machine-checkable marker — a consumer
joining this data into a policy decision must not skip past the prose note
and treat it as ground truth.

`templates.operations` is an array, one entry per template-bearing attach
**slot observed at least once** (aliased slots — several names sharing one
address — appear once, as a group, same convention as `functions[]`),
**sourced from the semantic state machine**. Unlike `functions[]` — which
lists every planned slot from the aggregate maps, calls or not — a slot
with zero observed template calls is simply absent here, the same
"observed, not planned" convention `mechanisms[]` already uses:

| Field | Type | Meaning |
| --- | --- | --- |
| `names` | array of strings | Every function name resolving to this slot: `C_FindObjectsInit`, `C_CreateObject`, or `C_GenerateKey` (or an alias group of them). |
| `aliased` | boolean | `true` when ≥2 distinct names share this slot. |
| `requested` | boolean | Always `true` — see the caveat above. |
| `attr_types` | array of `{attr_type, attr_type_hex}` | The **union** of `CK_ATTRIBUTE_TYPE` values requested across every observed call for this operation. Never a value — only the type field of each template entry is captured, except the policy-boolean allowlist below. Capped at 8 distinct-slot entries per call (`MAX_ATTRS`); see `truncated`. |
| `policy_booleans.observed_true` | array of strings | `CKA_*` names (from the fixed policy-boolean allowlist — `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`, `CKA_EXTRACTABLE`) observed present-and-true (`CK_BBOOL` byte nonzero) on at least one call. |
| `policy_booleans.observed_false` | array of strings | The same allowlist, names observed present-and-**false** on at least one call. Independent of `observed_true` — a name can legitimately appear in **both** when different calls asked for different values; that is real, distinguishable evidence, not a conflict to resolve. A name absent from both lists was never present in a requested template at all in this capture — a genuine three-state (true / false / absent), never a boolean default standing in for "absent". |
| `truncated` | boolean | `true` when any observed call had `attr_total > attr_count`. Two distinct causes collapse into this one field: the application's template had more entries than the capture's per-event cap (`MAX_ATTRS = 8`) could record, **or** the in-kernel walk (`walk_template`) stopped early after a `bpf_probe_read_user` failure on some entry — a 2- or 3-attribute template can trigger this exactly the same way an 8+-entry one does. Either way, some requested attribute types were not captured — genuinely lost evidence, not a benign "long template" note. Also sets `evidence.templates_truncated` and forces `completeness: PARTIAL` (see `evidence` above). |

No `CK_ATTRIBUTE.pValue` is ever read except the single `CK_BBOOL` byte for
an allowlisted boolean attribute with `ulValueLen == 1` — never
`CKA_VALUE`, `CKA_LABEL`, `CKA_ID`, or any other attribute's value, at any
privilege, in any mode.

**Gate G2:** `templates` is diagnostic/policy context, not one of the five
`pkcs11-lab` migration-assessment categories directly — it answers "what
attribute policy did the application ask providers to enforce", which
`pkcs11-lab` can use alongside the mechanism join to flag a requested
policy the candidate provider doesn't support, but it is not itself a
join key.

## Latency shape

`functions[].latency_ns` and `mechanisms[].latency_ns` share one shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `approximate` | boolean | Always `true` — see below. |
| `p50`, `p95`, `p99` | number or `null` | Log2-bucket-approximated percentile, in nanoseconds; `null` when there were zero observations. |
| `total` | number | **Exact** sum of observed durations, in nanoseconds. |
| `max` | number | **Exact** maximum observed duration, in nanoseconds. |

The percentiles are bucket lower bounds (`bucket_of`/`percentile_ns` in
`src/metrics.rs`), not exact quantiles — cheap enough for BPF aggregation,
but a lower-bound approximation, which `approximate: true` flags
explicitly so no consumer mistakes it for an exact value. `total`/`max`
are exact because both maps (`SlotStats`) and the semantic state machine
(`MechStat`) accumulate them directly from each event's `duration_ns`,
with no bucketing loss.

## What v1.1 deliberately omits

Per the design spec's privacy model: no raw handle values, no PIN, no
`CKA_VALUE`/key-material/IV/AAD/signature/digest/wrapped-blob/random-buffer
bytes, no `CKA_LABEL`/`CKA_ID` values (attribute *types* only — an id/label
*type* can appear in `templates.operations[].attr_types`, its *value*
never can), no mechanism-parameter bytes outside the two allowlisted
shapes (`rsa_pkcs_pss`, `gcm` — every other shape stays `params: null`,
id-only). A document with zero mechanisms, zero sessions, and
`templates.operations: []` is a legitimate output for a target that never
called into PKCS#11 during the window — check `evidence.completeness` and
`capture.start`/`end` before concluding the target doesn't use those
features at all.

## v1 → v1.1: what changed

Purely additive — every v1 field keeps its v1 meaning; a v1 consumer that
ignores unknown fields reads a v1.1 document unchanged except for the
schema string itself.

- `schema` is now `"pkcs11-scope/observed-profile/v1.1"`.
- `mechanisms[].params`, always `null` in v1, can now be a non-null
  **array** of shape-tagged combo objects — see "`params` in v1.1" above.
  A v1 consumer that only ever saw `null` and ignored the field is
  unaffected; a consumer that asserted `params` is always `null` needs
  updating.
- `evidence` gained `shape_decode_failures` (informational call count),
  `shape_decode_total_failures` (mechanism count; a new `completeness`
  gap condition — nonzero forces `PARTIAL`), and `templates_truncated`
  (boolean; also a new `completeness` gap condition).
- A new top-level `templates` section was added.

No v1.1 field removes or renames anything v1 defined.
