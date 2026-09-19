<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# cgroup-256 D: merge the same open file across mount namespaces (kill the false collision nuke)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A provider file shared across mount namespaces (container bind-mounts the host's provider, same inode) attaches once instead of wiping the whole collision group to 0 slots. Same-path-different-bytes with distinct inodes already attaches per identity (measured); this plan fixes the same-file case without weakening the no-misattribution guarantee.

**Architecture:** `PinnedObjects` aggregation stays the choke point; the ordinary-identity equality gains a same-open-file escape: same `ObjectKey` + equal pin + equal non-empty sha256 + same kernel file (fstat `st_dev`+`st_ino` on the two retained fds) merges despite differing `mount_id`. Everything else keeps failing closed.

**Tech Stack:** Rust 1.88 (`cargo +1.88`), `src/discovery/identity.rs`, existing `identity.rs` test fixtures.

**Spec:** controller-measured 2026-09-17 on main `e8ced60` (evidence: `.superpowers/sdd/2026-09-16-cgroup-256-d-cross-ns/evidence/`, branch-local, gitignored):
- `nsd-same-file.json`: same file (56:1994533, softhsm) preloaded in two mount namespaces, one cgroup capture → **0 slots, 0 probes, empty discovery**, skip `physical identity is ambiguous; the collision group was not attached`. Temporary-instrumentation build proved the rejected key is the provider with identical bytes/sha/pin on both sides, differing ONLY in `mount_id` (bind-mount/ns mount table). This is the defect.
- `nsd-different-bytes.json`: same path, different bytes AND different inodes (softhsm vs p11-kit-trust) → both attach (136 slots / 272 probes); the one ambiguity skip there is ld.so (same file, two mount tables) — same defect, harmless victim. Post-fix this skip must ALSO disappear (acceptance: zero `physical identity is ambiguous` skips in both repros — controller-verified, not implementer: needs sudo).

## Global Constraints

- Toolchain is exactly `cargo +1.88`; every cargo invocation carries `--locked` and `--offline`.
- Focused tests: `cargo +1.88 test --locked --offline -p p11scope --lib <filter>`; full suite before every commit: `cargo +1.88 test --locked --offline --workspace --all-targets`; plus `cargo +1.88 fmt --all -- --check`, `cargo +1.88 clippy --locked --offline --workspace --all-targets -- -D warnings` clean.
- TDD red-green-refactor for every behavior change; watch each test fail first.
- No `sudo`, no timing/probe runs, no network: subagents never run privileged commands. Live post-fix verification is controller-only.
- Branch is `fix/d-cross-namespace`, worktree `.worktrees/fix-d-cross-namespace`; never commit on main; never push.
- No-misattribution guarantee holds and EXTENDS: same path, different bytes across namespaces must never merge (existing tests pin this — they must all stay green unchanged); the new escape merges only when the two retained fds are provably the same kernel file AND the content identity agrees.
- `docs/usage.md` documents the behavior change (see Task 2).

## File structure

- `src/discovery/identity.rs` — owns `ordinary_identity_equal` (:796), `insert_entry_with_aliases` (:685), `reject_key` (:744), `exactly_matches` (:589, second equality consumer), fixtures `view_pin` (:1707, opens `/dev/null`) / `pin_set` / `image_pins` (:2032).
- `src/discovery/identity.rs` tests module — all new behavior tests; the 7 `mount_id += 1` tests (lines 2195, 2573, 2642, 2676, 2698, 2706, 2770) are individually dispositioned in Task 1.
- `docs/usage.md` — one-paragraph behavior update.

## Task 1: Same-open-file merge escape (the fix)

**Files:**
- Modify: `src/discovery/identity.rs` (equality + insert path + fixtures as needed).
- Test: `src/discovery/identity.rs` tests module.

**Interfaces:**
- Consumes: `Entry.file: Arc<std::fs::File>` (both sides already opened — fstat, never re-resolve a path); `Entry.pin: Pin`; `Entry.sha256: String`; `entry.raw.key: ObjectKey`.
- Produces: merge (return existing id + alias the raw) when ALL hold: same `ObjectKey`, `pin` equal, `sha256` equal and non-empty on both, and fstat `(st_dev, st_ino)` equal on the two files. `mount_id` is not consulted by this escape. Every other same-key collision keeps today's `reject_key` path byte-for-byte (same skip text, same `ambiguous_keys`/`rejected_keys` bookkeeping).
- `exactly_matches` inherits the escape through the shared equality (same file IS the same attach target) — verify its callers still behave (Step 1 lists them).

**Design notes the implementer must respect:**
- The escape needs the two fds; `ordinary_identity_equal(&Entry, &Entry)` already takes both entries, so the fstat fits there or in a helper it calls. Do NOT change `MappingFileKey` (maps-comparable representation is load-bearing for loader arming: `open_view_object` docs) and do NOT substitute `st_dev` into any key — the fstat comparison is a same-file PROOF at merge time only.
- fstat failure on either side fails closed (no merge). `/dev/null` fixture fds all share one `(st_dev, st_ino)` — any test forging distinct files MUST use distinct real files (e.g. two `tempfile`s or `/dev/null` vs `/dev/zero`); reusing `/dev/null` for a "different files" case silently tests the same-file case.
- `build_id`: not consulted (sha256 equality already proves same bytes).

- [ ] **Step 1: Disposition every mount_id-sensitive test and equality caller.** (a) Read all 7 `mount_id += 1` tests (2187, ~2560, ~2630, ~2665, ~2690, ~2700, ~2760 — verify names while reading) and report for each: merge or reject under the NEW contract, and why (same vs forged backing file). (b) `grep -rn "exactly_matches" src/ crates/` and list every caller; confirm the escape is safe for each (same file = same attach target) or report otherwise. (c) Read `insert_entry_with_aliases` (:685–742) fully and report the exact insertion point of the escape. **Tripwire:** if any caller needs mount_id-distinct entries to stay distinct for CORRECTNESS (not just conservatism), STOP and report — do not implement.
- [ ] **Step 2: Write the failing tests.** In the `identity.rs` tests module, using real files (see fixture note above):
```rust
#[test]
fn absorbing_same_open_file_across_mount_namespaces_merges() {
    // Same temp file opened twice (two fds, one kernel file), same key/pin/sha,
    // mount_id differs (two mount tables): absorb merges to 1 pinned, 0 skips.
}
#[test]
fn absorbing_same_key_distinct_files_still_rejects_the_collision_group() {
    // Two temp files with IDENTICAL bytes (the btrfs-clone shape): forged same
    // ObjectKey, equal pin+sha, mount_id differs, fstat (st_dev,st_ino) differs:
    // absorb rejects (0 pinned, 1 ambiguity skip) exactly like today.
}
#[test]
fn absorbing_same_key_unavailable_digest_still_rejects() {
    // Same key, same backing file, but one side sha256 empty (hashing skipped):
    // absorb rejects — no merge without proven bytes.
}
```
Adapt fixture construction to the file (extend `view_pin`/`pin_set` with a file parameter or build `Entry` directly — report the choice); the assertions (pinned counts, skip counts, skip text `physical identity is ambiguous`) do not change. Also update `absorbing_incomparable_same_key_candidates_rejects_the_collision_group` (:2187): its two `/dev/null` fixtures are the SAME backing file, so under the new contract it MERGES — rewrite it into the merge case (rename to say so) and move its reject assertions into the distinct-files test above. Report any OTHER of the 7 tests whose expectations change, with before/after reasoning — no silent expectation edits.
- [ ] **Step 3: Run them to verify they fail.** `cargo +1.88 test --locked --offline -p p11scope --lib identity::tests::absorbing_same`. Expected: FAIL (merge test finds 0 pinned + ambiguity skip; distinct-file/unavailable tests already pass — they pin today's behavior, which is the point).
- [ ] **Step 4: Minimal implementation.** Add the same-open-file escape per Interfaces. No other behavior change: `reject_key`, skip text, bookkeeping, overlay heuristic, and manifest paths untouched.
- [ ] **Step 5: Full module tests + the 7.** `cargo +1.88 test --locked --offline -p p11scope --lib discovery::identity` green, including all no-misattribution tests (`two_mounts_of_one_filesystem_image_are_not_merged`, `two_different_files_sharing_an_inode_number_are_never_merged`, `one_dependency_reached_through_two_mounts_is_one_ambiguous_slot`) UNCHANGED-green.
- [ ] **Step 6: Full suite, fmt, clippy.** Green, per Global Constraints.
- [ ] **Step 7: Commit.** `git add` only touched files; `git commit -m "fix: merge same open file across mount namespaces (D)"` with a body citing the measured 0-slot repro and the gates.

## Task 2: Document the behavior change

- [ ] **Step 1: Update `docs/usage.md`.** Next to the "Ordinary-file candidates merge only after comparable opened-file identity and digest agree; an incomparable collision group fails closed" paragraph (~line 349): add that the same file observed through two mount namespaces (container sharing the host's provider) merges by open-file identity + digest instead of failing the group — one sentence, no new flags (there are none).
- [ ] **Step 2: Amend or follow-up commit?** Follow-up commit (`docs: ...`), so the behavior commit stays pure. Gates: fmt only (docs), but run the focused identity tests once more to be safe.

## Task 3 (controller-only): live post-fix verification + review dispatch

Not for subagents. The controller rebuilds, re-runs BOTH repros (same-file pair → slots>0, both modules attached, zero ambiguity skips; different-bytes pair → both attached, zero ambiguity skips incl. ld.so), then dispatches the independent review. No dispatch.

## Self-review (controller, against the spec)

1. Spec coverage: same-file wipe → Task 1 escape; ld.so false skip → same escape (verify in Task 3); different-bytes per-identity attach → already worked, pinned by existing tests + Task 3 re-verification. E (loader arming) is out of scope for this plan. No gaps.
2. Placeholder scan: no TBD/TODO; every step names exact files, line numbers, commands, and assertions. Test-name adaptation is fenced to fixture construction only, with the assertions frozen.
3. Contract consistency: merge requires key+pin+sha+same-fd (four conjuncts); `mount_id` kept in the representation but not consulted by the escape; `st_dev` never enters a key (loader-arming maps matching preserved); fstat failure fails closed; skip text and bookkeeping unchanged for true collisions.
