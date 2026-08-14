# Manifest Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-08-14): Tasks 1–6 implemented and independently reviewed;
Task 7 open.** The deep-review findings that motivated Tasks 4–7 — provider
loading through `/proc/self/fd` changing `$ORIGIN`, a top-level-only lease
failing to protect lazy dependencies, and observer-owned `_exit` not ordering
teardown — are closed in the tree. Per-slice reviews recorded 0 Critical and
0 Important findings, and Task 6's privileged host and container lanes were
run under explicit approval and passed. Task 7's final cross-cutting re-review
has **not** run; until it does, this is reviewed work pending its release
gate, not release clearance. Slice-by-slice evidence, including every deferred
Minor, is in `.superpowers/sdd/2026-08-13-manifest-provenance/`.

**Goal:** Refuse every attach plan whose PKCS #11 function name-to-offset mapping cannot be reproduced from the explicitly selected provider immediately before attachment.

**Architecture:** Keep the manifest as evidence and a proposed plan, but make
fresh unprivileged discovery the authorization source. Pin and execute the
trusted helper by fd, but pass the provider by its validated absolute path so
the dynamic loader preserves `$ORIGIN`. A bounded preliminary discovery
inventories the complete file-backed executable mapping closure. The parent
opens and read-leases that closure, then repeats discovery until one complete
pass ran with every observed object already leased; churn or an unsupported
object fails closed. Only that pass may authorize function mappings. Candidate
attach objects are independently pinned and leased for the complete capture.
Before any BPF load, the original CLI process becomes a minimal lease
supervisor and forks the capture worker. On a break the supervisor kills and
pidfd-waits the worker, then releases the last lease references and exits 78.
The supervisor never owns a BPF fd.

**Tech Stack:** Rust 1.88, edition 2024, Linux `/proc/self/fd`, existing manifest/discovery crates, standard library plus existing `libc`.

**Execution order:** Complete Tasks 4–5 here, then Tasks 1–5 in
`2026-08-13-safe-and-unvalidated-metadata.md`. Its Task 6 is the sole integrated
owner of the shared public/release surface and consumes Task 6 below. Finish
with Task 7 here.

## Global Constraints

- Never attach from a raw manifest alone and do not add a `--trust-manifest` bypass.
- Require the operator to name `--provenance-module` on every attach; an untrusted manifest cannot select its own provider authority.
- Preserve PKCS #11 2.0x, 2.40, 3.0, 3.1, 3.2, and known-prefix behavior already encoded by `pkcs11-module::tables_for`.
- Compare identities and offsets, not ASLR addresses, object IDs, path spelling, or volatile diagnostic text.
- Continue to reject stale or non-executable attach objects through `verify::check_reuse` and keep their file descriptors pinned through attach.
- Require enforceable Linux read leases. Candidate attach objects are leased
  from identity verification through capture; provenance-closure objects are
  leased before the authoritative pass through its comparison. Refuse an
  existing writer, lease failure, or break notification. This release supports
  regular files whose read-lease behavior passes the live gate. Overlay is not
  categorically unsupported: every Docker, shared-layer, kind, and Knative
  lane must positively prove leases on its actual provider, attach objects,
  and authorization runtime closure, and record filesystem type plus
  `/proc/sys/fs/lease-break-time`. Any lane or network/FUSE filesystem that
  cannot establish the required leases is refused and is not claimed, never
  downgraded.
- Preserve provider loader semantics: never `dlopen` a provider through
  `/proc/self/fd`; use its validated absolute path and test `$ORIGIN`/lazy
  dependencies.
- Authorize only from a bounded pass in which every file-backed executable
  mapping was leased before that pass began. Include the helper/runtime
  mappings in the closure rather than guessing which dependency influenced a
  provider table.
- The observer must not load provider code in its own address space.
- Treat the helper's pre-provider dynamic-loader chain as part of the security
  oracle. Hostile-target authorization requires the official fully static
  observer so this validation itself has no dynamic pre-main chain. Before
  helper exec, that observer opens, verifies, and read-leases the interpreter
  and every recursively resolved runtime object. It invokes the pinned loader
  fd directly with a private fd-backed library directory; the pinned helper fd
  is its program. Glibc cache lookup is inhibited, and every initial
  `DT_NEEDED` name is present in that private directory so neither loader falls
  through to an unverified source before main. Empty environment remains
  mandatory. Reject `DT_RPATH`/`DT_RUNPATH`, slash-containing `DT_NEEDED`,
  dynamic audit/filter/auxiliary-library tags, nonempty system preloads, an
  unknown loader flavor, or a runtime path/ancestor writable outside root. A
  dynamic observer or same-uid capability build remains a trusted-workload
  lane only. Host-root runtime compromise remains outside the boundary.
- No new runtime dependency, pointer capture, or privacy-allowlist expansion.
- Advance to manifest v4 with mandatory whole-file SHA-256 and a bounded
  provenance-object closure because producer-chosen GNU build IDs cannot
  authenticate byte-identical safe copies and v3 cannot describe all objects
  that must be leased before authoritative discovery.
- The selected provider is still assumed to be honest native code. Deliberate
  load-forge-unload behavior is malicious-provider behavior, not a filesystem
  race a generic post-load mapping inventory can prove away.
- For a hostile observed process, the lease supervisor must run under a host
  identity the workload cannot signal or ptrace (normally host root against a
  non-root workload, or a dedicated service uid with `CAP_LEASE` for every
  provider/helper/interpreter/runtime object it does not own). A same-uid
  file-capability launch is supported only for trusted workloads: Linux
  `SIGSTOP`/`SIGKILL`
  cannot be masked, so same-uid signal authority is incompatible with the
  hostile-target continuity claim. Host root/`CAP_KILL` and kernel compromise
  remain outside the boundary.
- Preserve all unrelated working-tree changes; do not commit without explicit approval.
- Use a unique root-owned per-run directory below a validated root-owned,
  non-group/world-writable `/run/p11scope`: parent mode 0755, run directory
  mode 0511. Authority is its retained directory fd, not later pathname
  lookup. Root removes it after helper exit; stale entries are never reused.

---

### Task 1: Canonical provenance gate

**Files:**
- Modify: `src/verify.rs`
- Test: `tests/reuse.rs`

**Interfaces:**
- Produces: `verify::check_provenance(candidate: &Manifest, discovered: &Manifest) -> Result<(), Vec<String>>`
- Consumes: manifests already structurally validated by the same trust-boundary module.

- [x] Add a regression that constructs a structurally valid, identity-valid manifest but redirects canonical `C_EncryptInit` to executable code in a second real ELF object. Assert `check_reuse` accepts the object facts and `check_provenance` rejects the forged role-to-offset mapping.
- [x] Run `cargo +1.88 test --locked --test reuse forged_function_role -- --exact` and confirm RED because the provenance API is absent.
- [x] Implement the smallest canonical projection covering module/object identities, interface-list status, surface source/version/classification/flags/acquisition/walk, every function name and normalized resolution, and vendor-interface facts. Normalize object IDs through identity; ignore path spelling, identity notes, lossy/error prose, and alias groups derivable from function mappings.
- [x] Add a positive regression where byte-identical attach and discovery copies have different paths and volatile diagnostic text; assert provenance succeeds.
- [x] Run the two focused tests and `cargo +1.88 test --locked --test reuse`.

### Task 2: Trusted bounded rediscovery

**Files:**
- Modify: `src/discover_cmd.rs`
- Modify: `src/main.rs`
- Test: `src/discover_cmd.rs`
- Test: `tests/reuse.rs`

**Interfaces:**
- Produces: `discover_cmd::rediscover(module: &Path) -> anyhow::Result<Manifest>`.
- Consumes: only the `p11scope-discover` sibling of the running executable; never PATH or an operator-selected helper.

- [x] Add focused tests for helper trust: regular executable, correct owner for the effective identity, and no group/world write bit. Add a bounded-reader test proving byte 16 MiB + 1 is rejected.
- [x] Run the focused tests and confirm RED because trusted rediscovery is absent.
- [x] Open the sibling helper once, validate metadata on that descriptor, and execute `/proc/self/fd/<n>` so a pathname retarget cannot replace it. Require root ownership when effective UID is root; otherwise require current effective-UID ownership. Give the oracle an empty environment, discard untrusted stderr, reuse the existing privilege-drop hook, cap stdout at `verify::MAX_MANIFEST_BYTES`, and kill/reap its process group after 30 seconds.
- [x] Make hostile-target oracle launch available only from the official
  fully static observer. Using the existing ELF reader, parse the already
  pinned helper and its absolute `PT_INTERP` before exec. Recognize only the
  supported glibc and musl x86-64 loaders; open and validate the interpreter
  and every search-directory component as root-owned and not group/world
  writable. Reject nonempty `/etc/ld.so.preload`, unexpected musl path config,
  `DT_RPATH`/`DT_RUNPATH`, slash-containing `DT_NEEDED`, and dynamic
  audit/filter/auxiliary tags on every object in the runtime closure.
- [x] Resolve `DT_NEEDED` recursively, before exec, using the exact ordered
  trusted host directories supported by the recognized loader adapter.
  Open each selected file once, verify its SONAME/device/inode/regular-file
  ownership and mode from that fd, acquire a read lease, and retain every fd
  through helper exit and authorization. Bound object count, recursion depth,
  and total bytes; reject duplicate SONAME ambiguity or any unresolved object.
  Official artifacts permit only the platform loader/libc and the toolchain's
  required unwind library.
- [x] Execute the pinned interpreter fd directly, not the helper and not an
  interpreter pathname. Build a root-owned mode-0511 directory containing one
  unambiguous root-created SONAME link to `/proc/self/fd/<runtime-fd>` for every
  retained dependency; it is traversable after UID drop but never writable by
  the helper identity. Retain its directory fd and pass
  `/proc/self/fd/<directory-fd>` as the sole `--library-path` plus
  `/proc/self/fd/<helper-fd>` as the program; for glibc also pass
  `--inhibit-cache`, while musl's explicit path is accepted only after tests
  prove the complete initial closure never falls through to its system path.
  Create it as the per-run directory specified in Global Constraints. Finalize
  inherited descriptor numbers before creating any `/proc/self/fd/<n>` link:
  either preserve the actual numbers across fork/exec or use `dup3` into a
  collision-checked reserved range. Numeric determinism is not required, but
  each link must name the exact descriptor the child inherits. Clear
  `FD_CLOEXEC` only on the allowlisted helper, interpreter, directory, runtime,
  and control fds. Revalidate the directory fd, entries, descriptor numbers,
  and every target fd after fork and before releasing the exec barrier. This
  makes every possible pre-main constructor come from an inode that was
  authorized and leased before it could execute.
- [x] Keep a parent/helper control-fd handshake as confirmation, not authority.
  At the first instruction under helper control and before `dlopen`, the helper
  waits while the parent independently inventories `/proc/<helper-pid>/maps`.
  Require the exact pre-authorized helper/interpreter/runtime inode set and no
  extra file-backed executable mapping, then release the provider load. Failure
  to inspect procfs or any mismatch is refusal. The helper itself keeps the
  validated owner rule (root for a privileged observer, current euid otherwise).
- [x] Keep the post-drop helper non-dumpable. Remove the current
  `PR_SET_DUMPABLE=1`; after dropping every uid/gid/capability and setting
  `NO_NEW_PRIVS`, open `/proc/self/mem` from the helper itself. Linux permits
  same-thread-group self access before the dumpability check; pin this on the
  5.15 floor and supported kernels, and refuse if the open fails. Never inherit
  a pre-exec self-memory fd because it refers to the pre-exec address space.
- [x] Replace the first pass's provider `/proc/self/fd` route: read-lease and
  validate the provenance module, but pass its absolute path to the pinned
  helper. Revalidate that path against the leased seed before and after each
  pass. Parse only schema-v4 JSON and retain the existing timeout, output cap,
  process-group cleanup, privilege drop, and helper-metadata checks.
- [x] Extend `load_plan` to run `check_reuse`, trusted rediscovery, and `check_provenance` before `plan::build`; no attach path may bypass this sequence.
- [x] Require `--provenance-module <absolute-provider-or-copy>` on `profile` and `trace`, so an untrusted manifest cannot select its own authority and namespace-rewritten attach paths can use a byte-identical safe copy.
- [x] Re-run focused library and CLI tests, including a malicious pre-main
  constructor that hides/unmaps its origin, hostile helper/transitive RPATH,
  preload/audit injection, writable interpreter/runtime, unknown loader,
  pre-provider handshake failure, same-uid ptrace/output-forgery attempts,
  SONAME-link retarget attempts after UID drop, non-dumpable self-memory reads,
  `$ORIGIN`, and dependency churn, after the superseding stable-closure work
  below. The malicious constructor must never execute because its inode is
  rejected before exec; same-uid signals may cause refusal/DoS but never an
  accepted forged oracle result.

### Task 3: Operational contract and release lanes

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/privacy/allowlist-v1.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: affected `scripts/*.sh` and `scripts/matrix/*.sh`
- Test: `tests/release_contracts.rs`

**Interfaces:**
- Consumes: `--provenance-module` and sibling-helper trust from Task 2.

- [x] Document the exact boundary: stored manifests are untrusted proposed plans; fresh table provenance is mandatory; `COMPLETE` describes capture completeness, not semantic honesty of malicious native code.
- [x] Stage a root-owned sibling helper in privileged release scripts, and pass a safe-copy provenance module in namespace-rewritten Docker, kind, shared-layer, and Knative lanes.
- [x] Follow and then reject symlinks when staging Docker safe copies, so `/usr/lib/...` provider links become regular byte copies rather than dangling host links.
- [x] Stage any `$ORIGIN` siblings required by the selected provider; a lone
  top-level copy is not a valid provenance fixture for a provider whose loader
  contract includes adjacent objects.
- [x] Replace source-text-only assertions with the smallest executable or behavioral contracts available for helper trust and forged-manifest refusal.
- [x] Run shell syntax checks and `cargo +1.88 test --locked --test release_contracts`.

### Task 4: Stable provenance closure and `$ORIGIN`

**Files:**
- Modify: `crates/manifest/src/manifest.rs`
- Modify: `crates/discover/src/discover.rs`
- Modify: `src/discover_cmd.rs`
- Modify: `src/verify.rs`
- Test: `crates/discover/tests/lazy_dependency.rs`
- Test: `tests/reuse.rs`

**Interfaces:**
- Produces: manifest v4 `provenance_objects`, recording stable whole-file
  identity plus the pass-local mapped device/inode for every file-backed
  executable mapping present after surface acquisition.
- Produces: `discover_cmd::rediscover_stable`, which returns only a manifest
  produced by a pass whose complete provenance closure was leased beforehand.

- [x] Record the complete executable mapping closure, not only objects that own
  final function pointers. Open each path once, compare the fd's device/inode
  with the mapping, and derive SHA/build identity from that same fd. An
  unopenable, deleted, identity-mismatched, or over-cap mapping makes the pass
  ineligible for authorization.
- [x] Keep attach objects and provenance-only objects separate so short-lived
  authorization leases do not turn every helper/system library into a
  capture-lifetime attach lease. During stabilization, match every fresh
  mapping by its exact device/inode to the parent's already-open, already-leased
  fd. Content identity is insufficient here: a pathname can be retargeted to a
  distinct byte-identical but unleased inode. Ignore path spelling, ASLR
  address, diagnostic text, and dense id. The candidate's recorded closure is
  evidence, never authority; only the pre-leased fresh closure authorizes its
  table projection.
- [x] Run an unprivileged preliminary pass using the absolute provider path,
  open/validate/lease every reported provenance object in the parent, then
  rediscover. If the next pass maps any device/inode not already represented by
  a retained lease fd, add that exact inode's lease and repeat even when its
  bytes equal an existing object. Retain prior-pass leases until stabilization
  completes so an A/B inode cycle cannot evade the bound. Accept only when
  every exact mapped inode in a pass was already leased before that pass began;
  bound the loop to 8 passes and existing object/byte/output limits. Churn,
  disappearance, seed-module replacement, or capacity exhaustion fails closed.
- [x] Block lease-break signals and consume them synchronously during closure
  stabilization. A notification or failed `F_GETLEASE` recheck invalidates the
  pass before any BPF program is loaded. Stable SHA-based/path-independent
  comparison is used only later for the candidate/final manifest security
  projection, never to prove that a discovery-pass inode was leased.
- [x] Compare the candidate security projection only with that final pass.
  Hold provenance-closure leases through comparison; hold independently
  verified candidate attach-object leases through attach and capture.
- [x] Add a wrapper/backend regression proving direct absolute loading retains
  `$ORIGIN`, the old provider-fd route fails the fixture, an unleased lazy
  dependency cannot authorize offsets, one newly discovered dependency causes
  a bounded retry, a byte-identical inode replacement also forces a retry, and
  perpetual or A/B inode churn refuses without attachment.

### Task 5: Lease supervisor and ordered shutdown

**Files:**
- Modify: `src/verify.rs`
- Modify: `src/attach.rs`
- Modify: `src/main.rs`
- Test: `tests/lease_break.rs`

- [x] Block SIGIO, SIGINT, and SIGTERM in the original CLI process before lease
  acquisition and consume them with `signalfd`. After authorization and before
  BPF load, keep that process as the lease supervisor and fork one capture
  worker. Both retain candidate lease fds; only the worker receives verified
  attach state and may load BPF. Require `/proc/self/task` to prove the process
  is single-threaded at fork; otherwise refuse. Add no daemon, service, thread,
  or dependency.
- [x] Prepare output before fork. For trace, the supervisor retains duplicate
  fds for stdout and any `-o` regular file and gives the worker its own
  duplicates. For profile `-o`, create one same-directory, create-new temporary
  file; the worker receives only its fd while the supervisor retains the temp
  and final paths. Do not expose the final profile pathname until normal
  completion. Cleanup removes an unpublished temp file.
- [x] Set every lease's `F_SETOWN` to the supervisor. Fork behind a socketpair
  start barrier: the worker first sets `PR_SET_PDEATHSIG=SIGKILL`, rechecks its
  parent pid, and blocks; while the unreaped child PID cannot be reused, the
  supervisor opens its pidfd, rechecks every `F_GETLEASE`, then releases the
  barrier. The worker inherits SIGIO blocked and cannot become its recipient.
  No BPF load occurs before those checks.
- [x] On SIGIO or a failed lease recheck, the supervisor sends uncatchable
  `SIGKILL` through the worker pidfd and waits for pidfd readability/process
  exit before releasing its lease fds. This works even when the worker is
  blocked or stopped. Only after process exit has kernel-closed every BPF link
  may the supervisor release the last lease references. It then appends the
  bounded terminal trace-abort `EVIDENCE` record defined by the safe-metadata
  design and returns exit 78; output I/O is not allowed to consume the kernel's
  lease-break deadline. The supervisor retains a duplicate of each trace sink
  and the immutable privacy-policy label, but no BPF fd or semantic state. Prefix
  the record with a newline because the killed worker may have stopped
  mid-line. When `-o` is present, delivery to that regular-file sink is
  mandatory and flushed; stdout is best-effort with a bounded nonblocking/poll
  write so a full pipe cannot delay lease release. No numeric `LOST` value is
  invented. Profile output uses a temporary file and atomic publish only after
  normal completion; lease break never leaves a normal profile JSON.
- [x] On normal completion, the worker writes and flushes final output,
  explicitly drops `Session`, sends a small completion record, and exits. For
  profile output, it writes and syncs only the supervisor-prepared temp fd; the
  supervisor waits for the valid completion record and pidfd-confirmed exit,
  releases the last lease references, then atomically renames that temp to the
  final path. An absent/malformed record or abnormal exit removes the temp.
  Output I/O therefore never holds a broken lease open. The supervisor then
  mirrors the worker status. It forwards operator SIGINT/SIGTERM
  without releasing leases early: SIGINT uses the existing clean-output path;
  SIGTERM retains terminating semantics/status. The worker explicitly unblocks
  those signals after installing/resetting its handlers. A bounded `SIGKILL`
  fallback prevents a stuck worker from consuming the lease-break deadline.
  Worker error and panic paths use process exit, not Rust drop order, as the
  final teardown proof.
- [x] An unexpected supervisor exit requests fail-stop worker teardown through
  `PDEATHSIG`, and the setup race is validated, but this is availability
  hardening rather than the lease/BPF ordering proof: the dying worker's own fd
  close order is not controlled. The hostile-target guarantee therefore relies
  on the unsignalable/unptraceable supervisor identity contract above and does
  not cover supervisor death caused by host root, the kernel/OOM manager, or a
  supervisor memory-safety failure. Do not claim it for a same-uid
  capability-only run.
- [x] Add unprivileged supervisor/protocol/exit-code/drop-order tests and an
  approval-gated live case with a real attached probe plus waiting writer. The
  writer must not proceed until the worker pidfd is readable and the
  probe/link is demonstrably gone. Include SIGIO, normal exit, observer
  SIGKILL/SIGSTOP, supervisor death during deliberately blocked attach/output,
  parent-death setup race, multithreaded-fork refusal, operator signals, and
  attach-time break cases. Add a happy-path assertion that the process has
  exactly one thread at the real pre-fork point after signal setup and loader
  preparation; retain the multithreaded refusal test. Exercise a blocked trace
  stdout and prove exit 78/lease release remain bounded while the regular-file
  sink receives the terminal abort record.
- [x] Hostile kernel/root behavior and the kernel's configured lease-break
  timeout remain outside user-space proof. Record the observed timeout in gate
  evidence and require every tested shutdown path to complete well inside it.

### Task 6: Inputs to the consolidated public/release task

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/privacy/allowlist-v1.md`
- Modify: `docs/superpowers/plans/ROADMAP.md`
- Modify: affected release/matrix scripts
- Test: `tests/release_contracts.rs`

- [x] Hand these requirements to Task 6 of
  `2026-08-13-safe-and-unvalidated-metadata.md`; do not edit or gate the shared
  release surface in a separate pass.
- [x] Remove claims that the first provenance pass already closed same-inode
  dependency mutation or ordered lease-break teardown.
- [x] Document absolute-path `$ORIGIN` behavior, manifest v4 migration,
  bounded closure stabilization, safe-copy sibling requirements, and the
  trusted helper-loader chain, honest-provider assumption, and same-uid signal
  limitation.
- [x] Make every container/shared-layer fixture copy the resolved provider and
  its required adjacent dependency closure as regular files, then rerun all
  approval-gated changed lanes. Each lane must also prove read-lease
  acquisition for every actual attach/provenance runtime object and record its
  filesystem type and configured lease-break timeout. A supplied preliminary
  Docker-overlay2 observation says this succeeds, but it is not release
  evidence until the repository gate records it.

### Task 7: Final verification

**Files:**
- Review only: the complete current diff and trust-boundary call graph.

- [ ] Run the forged-manifest, lazy-dependency, `$ORIGIN`, same-inode rewrite,
  churn, and ordered-teardown regressions and confirm refusal occurs before
  `plan::build`/`Session::start` or before a writer proceeds, as applicable.
- [ ] Run all four `AGENTS.md` gates on the final tree.
- [ ] Re-review helper replacement, output exhaustion, path/ID/diagnostic normalization, container safe-copy, and equivalent `profile`/`trace` sinks.
- [ ] Re-review same-inode mutation, lease acquisition/break handling, empty oracle environment, deadline/process-group cleanup, and post-attach/final-output stability checks.
- [ ] Re-run the final maximum code review and require zero findings in these
  fixed classes: manifest self-authorization/forged function roles; helper
  replacement and pre-main runtime injection; provider, dependency, path,
  inode, and same-inode content mutation; `$ORIGIN` and closure churn; lease
  acquisition, break, and teardown ordering; terminal trace-abort evidence;
  same-uid signal/ptrace authority; and safe/unsafe pointer-alias privacy plus
  immutable policy publication. Report privileged/container experiments as
  unrun unless separately approved.
