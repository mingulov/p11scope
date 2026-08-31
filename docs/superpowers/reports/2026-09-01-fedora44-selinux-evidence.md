# Fedora 44 SELinux-Enforcing evidence

Date: 2026-09-01

## Decision

PASS for the post-MVP Fedora portability smoke on product commit
`1d3837b5fcc561abb741e48656139113674731fc` (tree
`c930a52c4cb2234f25d7c2c85e1e0f7179bb58b9`). This is not a public-release
decision.

The guest was Fedora Cloud 44 on kernel `6.19.10-300.fc44.x86_64`, with the
targeted SELinux policy `Enforcing` throughout. The official base image was
GPG-verified before use. Its SHA-256 remained
`28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`
before and after the campaign.

## Exact candidate and build gates

- Complete Git bundle SHA-256:
  `391542563d7ba1b23a3aa0f560ccea57eb367af161be41d3238ec1ccebfb3a57`.
- Rust `1.88` format, locked workspace check, locked all-target tests, and
  locked all-target Clippy with warnings denied: all exit `0` in the guest.
- Exact Fedora release observer SHA-256:
  `b250c621d757b4516db9a578dfba6c4d72594d31c9a7d121f17c0678069ded60`.

## Runtime results

- Runtime-built Fedora SoftHSM capture: PASS. The manifest-backed metrics
  oracle observed `136/136` probes and 68 slots. The report remains `PARTIAL`
  because Fedora's SoftHSM table is built outside file-backed scan data; the
  explicit manifest supplies the accepted legacy surface.
- Initial mapped-provider export regression: PASS. The current deterministic
  provider exercised `C_GetFunctionList`, `C_GetInterfaceList`, and
  `C_GetInterface` in both constructor and application phases. The final row
  recorded `208/208` probes, 104 slots, 104 table entries, one exact standard
  interface, zero attach/discovery/event losses, a settled child, and the
  expected scan-only `PARTIAL` verdict.
- Inspect/doctor: PASS for the intended mapped-provider and host-diagnostic
  lanes. The unprivileged host-only doctor correctly reported capture
  unavailable without BPF capabilities; the privileged runtime lanes above
  proved attachment separately.
- Privacy canaries: PASS for all seven profile/trace/metrics policy lanes and
  the hostile live controls.
- SELinux audit: zero AVC/USER_AVC records were present after the accepted
  runtime row. `/sys/fs/bpf` had no campaign residue.

The focused initial-export harness retained four finite non-pass attempts
before the accepted fifth attempt. Attempt 1 placed fixture-only environment
variables outside the documented owned-child allowlist. Attempts 2-3 proved
the product result but used a historical oracle with obsolete schema/privacy
labels. Attempt 4 passed that semantic/privacy oracle but used a substring
marker count. Attempt 5 used the documented `/usr/bin/env` child boundary,
explicitly normalized only the two known metrics-mode labels for the older
oracle, used exact-line marker counts, and exited `0`. No product source was
changed during these harness corrections.

## Cleanup and evidence

The VM powered off normally. `qemu-img check` reported no overlay errors, and
the base-image hash was unchanged. The disposable overlay is not evidence and
is excluded from portable transfer packages.

Host evidence root (generated, intentionally outside Git tracking):

`.superpowers/sdd/2026-08-31-fedora44-selinux/evidence/final-1d3837b/`

Its relative-file manifest is `SHA256SUMS`, with SHA-256
`96f65972858d169d05a42ceb3dca7ddf804bfa56e412db069991c76e93335c9a`.
The finite root includes the signed Fedora checksum, verification inputs,
guest preflight, candidate-bundle digest, and host closeout record; it excludes
the base image, overlay, seed ISO, serial log, and SSH credentials.

## Remaining scope

The Fedora induced-gap C UAPI helper and capability-tier expected-row oracle
remain test-infrastructure portability follow-ups from the earlier diagnostic
attempt. They do not contradict the exact final workspace gates, core capture,
initial-export row, inspect/doctor, canaries, cleanup, or SELinux result.

Exact-tip hosted CI, refreshed container/Kubernetes/Knative campaigns, the
remaining medium/low static findings, release receipt, push, tag, and public
release remain pending.
