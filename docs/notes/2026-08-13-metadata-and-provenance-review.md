# Review + gap analysis — safe-metadata design and manifest-provenance plan

**Date:** 2026-08-13
**Reviewed:**
- `docs/superpowers/specs/2026-08-13-safe-and-unvalidated-metadata-design.md` at `cdebf09`
- `docs/superpowers/plans/2026-08-13-manifest-provenance.md` at `cdebf09`

**Initial verdict:** both documents are technically strong and internally coherent. Four
gaps are blocking, five substantive. One suspected blocker was measured and
turned out to be a non-issue — see G5.

## Maintainer adjudication

The detailed review below is preserved as received. This table is the
authoritative disposition after checking the exact source and amending the
documents:

| Finding | Disposition and durable resolution |
| --- | --- |
| G1 | **Valid.** The metadata design and implementation plan now require a private `src/attach.rs` `BPF_MAP_FREEZE` syscall shim using the existing `libc`, with named fail-closed errors and a live `EPERM`/unfrozen-control gate. |
| G2 | **Valid.** Added `docs/superpowers/plans/2026-08-13-safe-and-unvalidated-metadata.md` with six reviewable tasks and exact execution gates. |
| G3 | **Valid.** After worker death, the supervisor writes a bounded terminal trace `EVIDENCE` record (`PARTIAL`, lease-break reason, no final drain, unknown loss), while profile output is atomically published only on normal completion. Exit 78 or a missing terminal record means truncated output. |
| G4 | **Valid.** Ordering is provenance Tasks 4–5, metadata Tasks 1–5, one metadata-owned integrated public/release Task 6, then provenance Task 7. |
| G5 | **Partly valid.** Overlay is no longer pre-excluded; each matrix lane must prove leases and record filesystem/lease-timeout evidence. The supplied Docker-overlay2 result is preliminary because its transcript was not retained and the privileged lane was not rerun here. |
| G6 | **Partly valid.** The private directory now has a root-owned `/run/p11scope` location and dirfd authority. Deterministic fd numbers are unnecessary: links must be created only after final inherited numbers are fixed, whether preserved or assigned with collision-checked `dup3`. |
| G7 | **Partly valid/stale.** The corrective design already required root or `CAP_LEASE`; the provenance plan now states the same for a dedicated service uid and the measured capability matrix remains pending rerun. |
| G8 | **Valid.** The privacy allowlist now names the transient raw `START.pMechanism` address, return-only finite lookup, lifetime, privileged exposure, public-output ban, and exact-map canary. |
| G9 | **Partly valid.** The schema already called v1.3/v1-metrics interim; the design, schema, and changelog now make the direct published migrations v1.2→v1.4 and v0-metrics→v1.1-metrics explicit if no intermediate artifact ships. |

The smaller findings are also carried into the plans: an exact-schema dispatch
statement, a happy-path single-thread pre-fork test, named fixed review classes,
and a comment tying the 463-id assertion to the pinned dependency revision.

---

## Verified before opining

Facts I checked against source rather than accepting:

| Claim | Status |
| --- | --- |
| `PKCS11_3_2_OFFICIAL_MECHANISMS` has 463 unique ids | **exact** — 463 entries at pinned rev `a2aab6c` |
| Union must fit `MAX_MECH_SHAPES` | `MAX_MECH_SHAPES = 1024`; 463 official ids leave at most 561 slots for distinct configured vendor ids, so overflow remains a tested refusal path |
| 104 published function names / name bound | `MAX_SLOTS = 512`, `FUNCTION_NAME_MAX_BYTES = 27` = `C_GetSessionValidationFlags` exactly |
| "no new dependency" | holds — `pkcs11-proxy-ng-types` is already `Cargo.toml:23` |
| fork tracepoint unspecified | **false alarm** — specified at corrective design:317 with fork-safe-surface reasoning |
| pidfd budget + fallback | implemented: `src/process.rs` `Mode::{PidFd, ProcStat, Untracked}`, `MAX_TRACKED`, `RESERVED_FDS` |
| metrics schema id | now `v1-metrics` (the `v0.1-metrics` bump flagged in the earlier review was fixed) |
| manifest chain v2→v3→v4 | documented at corrective design:660; tree is at `/3` |
| overlayfs read leases | **supplied preliminary measurement: works** — transcript not retained; per-lane release gate still required, see G5 |

---

## Blocking

### G1. `BPF_MAP_FREEZE` has no public aya API

The metadata design's entire "Immutable publication before attach" section rests
on freezing eight named maps (`CONFIG`, `PID_FILTER`, `CGROUP_FILTER`,
`SLOT_SEMANTICS`, `ASYNC_FUNCTIONS`, `MECH_SHAPE`, `ATTR_BOOL_BITS`,
`TEMPLATE_TAIL`), with freeze ordering as publication steps 4 and 6, an
acceptance criterion, and verification item 3.

In aya 0.14.0 `bpf_map_freeze` is `pub(crate)` (`sys/bpf.rs:413`) and is reached
only from `MapData::finalize()` for `.rodata` sections (`maps/mod.rs:918`).
There is no public freeze API anywhere in the crate.

It is not impossible — `MapData::fd()` is public (`maps/mod.rs:1017`), so a
hand-rolled `bpf(2)` syscall with cmd `BPF_MAP_FREEZE` on that fd is roughly ten
lines of `unsafe`. But neither document specifies it, both assert "no new
dependency" as though freezing were an available primitive, and an implementer
will otherwise discover this mid-task and improvise. Specify the shim, where it
lives, and its error contract.

### G2. The metadata design has no implementation plan

Status is "Approved after independent deep review; implementation pending." It
changes kernel code, the CLI, Cargo features, `build.rs`, two schemas, the
evidence model, and the canary suite. The only plan on the table covers
provenance and leasing. Under this project's own workflow (brainstorming →
writing-plans → subagent-driven-development) there is nothing to execute
task-by-task. This is the largest structural gap.

### G3. Lease break versus mandatory loss reporting — direct contract conflict

Plan Task 5: on SIGIO the supervisor "sends uncatchable `SIGKILL` through the
worker pidfd" and returns exit 78.

Metadata design: trace must carry `privacy=<mode>` "in the final
machine-readable `EVIDENCE` record." The corrective design makes the loss line
mandatory — "a trace never silently pretends completeness."

`SIGKILL` means no final drain, no `EVIDENCE` record, and no `LOST` line. A
lease break therefore produces a silently short trace whose only signal is an
exit code the consumer may never see. Nothing in either document says what to
conclude from that.

Needs an explicit contract: either the supervisor writes a terminal record to
the `-o` sink after the worker is confirmed dead, or the docs state that exit 78
means the output is truncated and incomplete by construction. As written this is
precisely the failure class the evidence model exists to prevent.

### G4. Two documents own the same release surface, with no ordering

Metadata "Release and documentation" and plan Task 6 both modify `README.md`,
`docs/usage.md`, `docs/privacy/allowlist-v1.md`, `ROADMAP.md`, release/matrix
scripts, and `tests/release_contracts.rs`, and both mandate re-running the
approval-gated lanes. The release build also gains constraints from both:
`--no-default-features` plus a dedicated `CARGO_TARGET_DIR` (metadata), and a
root-owned sibling helper plus safe-copy provenance staging (plan). Declare one
downstream of the other.

---

## Substantive

### G5. The overlay/FUSE lease disclaimer is untested, and for overlayfs it is wrong

Plan Global Constraints:

> unsupported/network/FUSE/overlay cases that cannot establish the required
> lease are refused, not downgraded

No task determines whether they can. I measured it: `F_SETLEASE(F_RDLCK)` on a
container file reached through `/proc/<pid>/root/` on Docker `overlay2`
**succeeds** from host root.

So the container matrix — Docker, kind, shared-layer, Knative, i.e. the tool's
headline environment — is not killed by the lease requirement. Good news the
plan does not know. Replace the disclaimer with a gate that asserts lease
acquisition per matrix lane and records the kernel's `lease-break-time` (which
Task 5's final step already wants). As written the constraint invites an
implementer to pre-emptively exclude the environment that matters most.

### G6. Private library directory: unspecified location and fd numbering

Task 2 requires "a root-owned mode-0511 directory containing one unambiguous
root-created SONAME link to `/proc/self/fd/<runtime-fd>` for every retained
dependency." Two things are missing:

1. **Where it lives.** There is no anonymous-directory primitive; this has to be
   `mkdtemp` somewhere, and the filesystem choice is part of the security
   argument, not an implementation detail.
2. **Fd numbering.** `/proc/self/fd/<n>` inside a symlink resolves in the
   *helper* after exec, so the link text bakes in the helper's fd numbers. The
   parent must `dup2` every retained runtime fd to deterministic numbers before
   exec and clear `FD_CLOEXEC` on exactly those. The plan says close-on-exec
   state is "set deliberately" but never pins the numbering — which is the part
   that silently breaks.

### G7. A non-root supervisor cannot take leases

The plan permits the supervisor to run under "a dedicated service uid."
`F_SETLEASE` requires file ownership or `CAP_LEASE`, and a service uid owns
neither the provider nor the system libraries in the provenance closure. Either
restrict lease-bearing runs to root, or add `CAP_LEASE` to the required
capability set — which changes the measured privilege table (host is
`CAP_SYS_ADMIN` alone today).

### G8. Safe mode puts a raw user pointer in `START`, and the allowlist doesn't list it

The metadata design has the entry probe record "the raw `pMechanism` address
needed by the return probe … transient privileged metadata in `START`." That is
a new kernel-resident capture of a target address.

The canary gate does cover it — it "verifies that its allowed raw address field
is never mistaken for pointee content or emitted publicly," which is the right
test. But "Release and documentation" does not enumerate an allowlist row for
it. Allowlist drift was finding F4 of the review that triggered this whole
effort; name the row explicitly.

### G9. Profile `v1.3` may never ship

The corrective design advances the profile to `v1.3`; this design advances it to
`v1.4` before `v1.3` is released. If both land in one release, consumers see
`v1.2 → v1.4` and the mandated "v1.3→v1.4 migration note" documents a transition
nobody experiences.

State which versions are published artifacts and which are internal waypoints.
The manifest chain already does this (corrective design:660 narrates
`/2 → /3 → /4`); the profile chain does not.

---

## Smaller

- The metadata design says "consumers dispatch on the exact schema string,"
  which makes the major/minor split in `v1.4` and `v1.1-metrics` decorative.
  Fine — but say it once in the schema doc so nobody infers compatibility from
  the number.
- Plan Task 5 requires single-threadedness at fork via `/proc/self/task`. Good.
  Nothing states whether `signal_hook` registration or aya's loader has already
  spawned a thread by that point; the check catches it at runtime, but an
  unprivileged test asserting thread count at the fork point is cheaper than
  discovering it in a privileged lane.
- Task 7's final step ("require zero findings in the fixed class") improves on
  the corrective design's unfalsifiable acceptance #6 by scoping it — but "the
  fixed class" is undefined. Name the classes.
- Verification item 4 pins "exactly 463 official ids," coupling the test to the
  pinned git rev. That is the intent, and it is correct; worth a comment in the
  test so a future dependency bump reads as a decision rather than a break.

---

## Design points worth keeping

Not everything needs changing; these are non-obvious and correct:

- **Finite public equality oracle** as the safe-capture boundary — pointer-derived
  bytes become evidence only by matching a published mechanism id or one of 104
  published names — is a genuinely sound containment story, and the document is
  honest that `bpf_probe_read_user` is fault-avoidance, not type validation.
- **Rejecting hash-only async authorization** in favour of byte-and-length exact
  match, with structural coverage proving no hash-only path remains.
- **Return-time mechanism read gated on `CKR_OK`/`CKR_PENDING`**, with the TOCTOU
  weakness stated rather than papered over.
- **`aggregate-only` as a real kernel policy** rather than a userspace decision
  not to read the ring — that is what makes "metrics reads no argument" a
  checkable claim.
- Plan: **content identity is explicitly insufficient** during stabilization
  ("a pathname can be retargeted to a distinct byte-identical but unleased
  inode") — exactly the right distinction, and the A/B-inode-cycle retry bound
  follows from it.
