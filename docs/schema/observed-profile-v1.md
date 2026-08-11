# `observed-profile.json` schema v1

**Schema string:** `"pkcs11-scope/observed-profile/v1"`
**Producer:** `p11scope profile` (default `--mode profile`; `--mode metrics`
instead emits the lighter `pkcs11-scope/observed-profile/v0-metrics`
document — `capture`/`evidence`/`functions` only, no `mechanisms`,
`sessions`, or `logins`).
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

Where a reader needs an authoritative call count for a specific function
name, use `functions`, never sum `mechanisms[].calls` — a session's
operational calls (`C_Sign`, `C_Encrypt`, ...) are attributed to the
mechanism they're running under, not counted per function name there.

## Top-level shape

```json
{
  "schema": "pkcs11-scope/observed-profile/v1",
  "capture": { "...": "..." },
  "evidence": { "...": "..." },
  "functions": [ { "...": "..." } ],
  "mechanisms": [ { "...": "..." } ],
  "sessions": { "...": "..." },
  "logins": { "...": "..." }
}
```

All six sections are always present, even when empty (`functions: []`,
`mechanisms: []`, `logins: {}`) — a v1 consumer should never need to
special-case a missing section. Enforced by
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
| `completeness` | `"COMPLETE"` or `"PARTIAL"` | See below. |

**Completeness verdict.** `COMPLETE` requires every one of: no attach
failures, no skipped entries, no aliasing, no in-flight calls, every
surface fully walked with a successful acquisition, no undecoded vendor
interfaces, **and (new in v1) `event_loss == 0` and `malformed_records ==
0`**. Any other gap — including a nonzero `event_loss` or
`malformed_records` — forces `PARTIAL`. `orphan_ops` and
`unmatched_closes` are reported for visibility but never flip the verdict:
they are an expected consequence of attaching after the target process
already had operations or sessions in progress, not evidence the capture
itself lost anything. Enforced by `render::tests::any_gap_forces_partial`
and `render::tests::orphan_ops_and_unmatched_closes_do_not_affect_completeness`.

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
| `params` | `null` | **Always `null` in v1.** Mechanism-parameter decoding (RSA-PSS hash/MGF/salt length, GCM IV/tag length, ...) is Phase 3 work, gated on the allowlist-based decoder. v1 never attempts a partial decode. |
| `note` | string | Human-readable restatement of the `params: null` reason. |

**Gate G2 — and its known v1 gap.** `mechanism`/`mechanism_hex` verbatim
preservation is exactly what **OBSERVED BUT NOT COVERED BY CORPUS** needs
(raw vendor ids preserved, not dropped). `mechanism` + `calls`/`errors`
also let a `pkcs11-lab` join happen **by mechanism id** for **OBSERVED AND
VALIDATED** / **OBSERVED BUT CANDIDATE DIFFERED** — but both of those
categories, per the design spec's acceptance table, ultimately want a join
keyed on **mechanism + full parameter combo** (hash/MGF/salt, GCM
lengths), and v1's `params` is unconditionally `null`. Until Phase 3 lands
parameter decoding, a `pkcs11-lab` consumer can only join on mechanism id,
not on the full parameter combo — report this precisely as a v1
limitation, not as those categories being unsupported.

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

## What v1 deliberately omits

Per the design spec's privacy model and v1 scope: no raw handle values, no
`CKA_VALUE`/PIN/key-material contents, no mechanism parameter bytes (only
the allowlisted decode is ever planned, and it isn't implemented yet — see
`mechanisms[].params` above), no attribute/template sections (those are a
later phase, not part of this v1 document), no labels/`CKA_ID` (opt-in
flag, not default). A v1 document with zero mechanisms and zero sessions
is a legitimate output for a target that never called into PKCS#11 during
the window — check `evidence.completeness` and `capture.start`/`end`
before concluding the target doesn't use those features at all.
