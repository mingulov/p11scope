# Safe and unvalidated metadata capture — design

**Date:** 2026-08-13

**Status:** Approved design; awaiting written-spec review

**Amends:** `docs/superpowers/specs/2026-08-12-v0.1-corrective-release-design.md`

## Goal

Keep the default observer useful for mechanism profiling without allowing an
arbitrary readable target pointer to become a raw metadata output channel.
Operators who deliberately need the metadata decoders that exist today can
compile and explicitly enable a diagnostic policy. Neither policy adds a PIN,
key, label, `CKA_ID`, message, signature, wrapped-object, or arbitrary-buffer
decoder.

This design addresses pointer-derived metadata capture only. It does not close
or supersede separate provenance, object-lease, teardown-order, or provider
loading findings.

## Security boundary

`bpf_probe_read_user` makes a userspace read non-faulting for the observer, but
it cannot prove that a readable C pointer identifies a `CK_MECHANISM`, parameter
structure, template, or string. The safe policy therefore relies on output
containment rather than claiming runtime C type validation:

- a target pointer is dereferenced only where this design says so;
- an unregistered pointer-derived scalar never enters `START`, the event ring,
  a report, a trace, a log, or an error message;
- failures are categorical evidence and never include the rejected value;
- the manifest/provenance, PID/cgroup, bounded-read, and evidence controls apply
  in both policies.

The remaining generic-observer limit is explicit: an ABI-malicious caller can
still combine provider success with the finite public mechanism registry as a
bounded equality oracle. Eliminating even that oracle requires a cooperative
provider audit point after provider-side validation and is outside a portable
uprobe observer.

## Capture policies

### `allowlisted` — default

The default policy retains metadata that does not follow an application-owned
input pointer:

- authenticated function identity, PID/TID and cgroup;
- scalar session/slot identifiers, session flags and login user type;
- return code, latency and aggregate/evidence counters;
- pointer nullness required by operation semantics;
- successful provider-written session and async identifiers, internally only;
- a provider-accepted, non-null mechanism id only after registry membership
  succeeds.

For a mechanism-bearing call, entry capture stores the protocol pointer but
does not dereference it. On `CKR_OK` or `CKR_PENDING`, the return probe reads
exactly the first `CK_ULONG`, immediately checks membership in the published
mechanism registry, and stores only an approved id. `CKR_PENDING` must be read
at this boundary because later async completion may occur after the caller's
pointer lifetime. The approved id remains pending until the existing async
state machine receives the final result. A null mechanism remains a distinct
state so the existing function-specific null-cancellation rules continue to
work.

Returns other than `CKR_OK` and `CKR_PENDING` do not dereference `pMechanism`
and are not attributed to a requested mechanism. That is an intentional
privacy-policy limitation, not an event gap, and does not itself make the
capture `PARTIAL`. If an accepted call has an unreadable or unregistered
non-null mechanism, the observer clears or withholds any binding that cannot
safely be reconstructed, increments evidence, and reports `PARTIAL` without
retaining the raw value.

Safe mode does not dereference mechanism parameter structures, templates,
template boolean values, or async-name input pointers. Those fields are absent,
not guessed. Existing successful provider-output scalar reads remain internal
and are never serialized.

### `unsafe-unvalidated-metadata` — diagnostic opt-in

This policy preserves exactly the pointer-derived metadata decoders present
before this design:

- full-width mechanism ids, including unregistered vendor ids;
- RSA-PSS `hashAlg`, `mgf`, and `sLen` for the exact known structure length;
- GCM IV length, AAD length, and tag bits for the exact supported layouts;
- bounded template attribute type ids and the existing eleven one-byte policy
  booleans;
- exact-match standard async function names and existing internal async
  correlation data.

It does not add a decoder, widen a bound, emit pointer values, or make any
currently forbidden buffer readable. The same `bpf_probe_read_user` failure
handling remains in force, so invalid addresses produce evidence rather than a
probe-induced target fault. Values from readable but semantically unrelated
memory may be reported; that is the reason the policy is named `unsafe`.

## Compile-time and runtime gates

Add the off-by-default Cargo feature `unsafe-unvalidated-metadata` to the root
and eBPF crates. `build.rs` propagates the root feature to the embedded eBPF
build, following the existing `small-ring` feature pattern.

The root CLI recognizes `--unsafe-unvalidated-metadata` for semantic `profile`
and `trace` captures:

- default build, no flag: run `allowlisted`;
- default build, flag present: refuse before discovery, privilege use, or
  attachment and name the required Cargo feature;
- feature build, no flag: run `allowlisted`;
- feature build, flag present: run `unsafe-unvalidated-metadata`;
- `profile --mode metrics` plus the flag: refuse because metrics mode performs
  no semantic pointer decoding;
- `discover` never accepts the flag.

The feature build contains both runtime paths in one eBPF object. Userspace
sets a new `CONFIG` flag only for the explicit unsafe invocation. The flag is
published before any probe attaches; publication failure aborts attachment.
The feature-disabled eBPF build has no reachable unsafe path. No second eBPF
object or new dependency is introduced.

## Mechanism registry

Reuse `MECH_SHAPE` rather than add another map. Userspace publishes every id
from the existing shared `MechanismRegistry`; mechanisms without a supported
parameter decoder carry `shape::NONE`. Map presence means that an id is
approved, while the value still selects an optional parameter decoder.

Safe capture distinguishes absence from `shape::NONE`. Unsafe capture retains
the current behavior: an absent id is still recorded and merely receives no
parameter decode. A future trusted registry-override path may approve a vendor
id without changing this policy or the eBPF ABI, but this design does not add
that CLI plumbing.

## Evidence and output contracts

Add `capture.privacy_mode` to every JSON report. Its value is
`allowlisted`, `unsafe-unvalidated-metadata`, or `aggregate-only` for metrics.
The profile schema advances from `v1.3` to `v1.4`; the additive metrics schema
remains `v1-metrics`.

Trace writes one persistent `CAPTURE privacy=<mode>` record before call records.
Unsafe capture also prints a clear warning to stderr before attachment. Output
tagging is unconditional in a feature build and cannot be suppressed.

Reuse `evidence.semantic_capture_failures` for safe mechanism read failures.
Add `evidence.unregistered_mechanisms` as a count only; it never contains an id.
Either condition on a provider-accepted call forces `PARTIAL`. Deliberately
choosing the unsafe policy does not force `PARTIAL`: completeness describes
gaps in the selected policy, while `capture.privacy_mode` describes that
policy.

## Verification

The non-privileged suite covers:

1. the default build rejects the unsafe flag and names the Cargo feature;
2. a feature build without the flag selects `allowlisted` and leaves the
   runtime policy bit clear;
3. a feature build with the flag sets the bit before any probe attaches and
   labels JSON/trace output;
4. `metrics` rejects the flag and reports `aggregate-only` otherwise;
5. every shared-registry mechanism is published, including ids whose shape is
   `NONE`, while absence remains distinguishable;
6. a known mechanism on `CKR_OK` appears in safe mode, while `CKR_PENDING`
   retains the approved id for the existing async completion path;
7. failed, unreadable, and successful-but-unregistered mechanisms never expose
   their raw values in safe events or output;
8. parameters, templates, booleans and async-name metadata are absent in safe
   mode and retain their previous results in unsafe mode;
9. schema and trace contract tests pin every privacy-mode marker.

The release canary runs both policies against the existing live-map scanner.
Safe mode plants an unknown readable mechanism sentinel and proves it appears
in neither output nor the observer-owned `START` and event maps. Unsafe mode
proves every existing metadata decoder remains available. Both runs plant and
reject PIN, key material, label, `CKA_ID`, plaintext, ciphertext, signature,
wrapped-object, random-output and ordinary-buffer sentinels. Intentionally
decoded metadata is not treated as a forbidden unsafe-mode canary.

The ordinary Rust format, check, test and clippy gates run for the default and
feature builds. The embedded eBPF crate is built in both feature states. Live
privileged canaries remain approval-gated under `AGENTS.md`.

## Documentation and release

Update the README, usage guide, privacy allowlist and observed-profile schema
document together. The public promise remains absolute for PINs, keys and raw
buffers in every build; it no longer implies that an explicitly unsafe build
validates all decoded metadata pointers.

Official release artifacts are built explicitly without default features and
must reject the unsafe flag. The release script contains a contract check for
that property. Unsafe diagnostic builds are operator-built and visibly tagged;
they are not substituted into the ordinary release archive.

## Acceptance criteria

- Safe execution is the default in every build.
- Official binaries contain no reachable unsafe metadata path.
- The unsafe feature plus runtime flag reproduces all and only the metadata
  decoders that existed before this design.
- Unregistered raw mechanism values never persist in safe mode.
- No policy can request or emit a PIN, key, label, `CKA_ID`, protocol buffer,
  plaintext, ciphertext, signature, wrapped object, or arbitrary memory dump.
- Every output identifies its privacy policy.
- Default and feature build gates pass, and the approval-gated dual-policy
  canary passes before release.
