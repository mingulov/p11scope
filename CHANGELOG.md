<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

All notable changes to p11scope are recorded here. Versions follow
[Semantic Versioning](https://semver.org/). Report schema identifiers are
versioned separately and are opaque, exact dispatch keys.

## [0.2.0] - UNRELEASED

Module/caller inventory and usage observation, Kubernetes deployment, and
fail-closed PID-namespace and privilege handling. See
[docs/known-limitations.md](docs/known-limitations.md) for the v0.2.0 limits.

### Added

- `p11scope inventory [--pid <n> | --system]`: answers "which module is used
  by whom" over one snapshot pass or a `--duration` window. Reports callers
  (per process incarnation), modules (per physical object), and caller/module
  edges with usage coverage, lifecycle, and explicit gaps. `--json` prints
  the `p11scope/inventory/v1` document
  ([docs/schema/inventory-v1.md](docs/schema/inventory-v1.md)); `-o <out.json>`
  writes it atomically; `--dashboard` runs the live read-only dashboard
  (scrollable edge table, coverage header, bounded log tail; degrades honestly
  to snapshots on a pipe, never ANSI); `--event-log <f.jsonl>` appends the
  versioned JSONL observation-event stream
  ([docs/schema/inventory-events-v1.md](docs/schema/inventory-events-v1.md))
  with size rotation and retention accounting.
- `inventory --capture auto|scan|native` (default `auto`): the scan lane reads
  `/proc` only (every edge's usage coverage reads `unknown`, never a zero as
  fact); the native lane loads the Inventory BPF object, attaches every
  admitted provider entry, and binds each positive use to the exact caller
  image (`witnessed`) or reports module-level use by an unidentified caller.
  An edge whose entries were all attached under proven health reads
  `watched_no_use`. `native` that cannot start is an error naming why; `auto`
  falls back to scan with a named gap. Witness-only in this release: no
  per-call counts (see Known limitations).
- Native caller binding: each `CALLER_USE` witness binds through a task-cookie
  query on the incarnation's held pidfd, recorded after admission, with no
  exec or lifecycle loss since and no competing image. New JSON:
  `modules[].unbound_use`, `observation.native_witnesses` (rows/bound/unbound
  census with per-reason codes and per-row placement), exec retirement
  (`exec_retired`), exec-coverage gating, and the `ambiguous shared endpoint`
  rule. Zero false joins is the hard bar.
- The native lane attaches through uprobe-multi groups where a functional
  probe (never a version check) shows support: one immutable link per provider
  object per extend (8–96 entries per link, sized near 200 ms per attach), so
  hundreds of entries detach in well under a second on 6.12/7.x and
  `observation.retirement` reads `closed`. New
  `inventory --attach-backend auto|multi|singles`; `observation.attach`
  discloses selection, mechanism, fallback reason and PID-scope filter.
  `--pid` uses Multi only where the kernel pid filter is proven to cover every
  thread, else per-offset links bound to the target.
- The native lane drains the kernel lifecycle ring every 10 ms, including
  while a pass collects `/proc` on a worker thread; a found loss starts a
  bounded recovery rescan at once and stays reported.
  `observation.lifecycle` counts records, ring loss, malformed records, failed
  drains and recovery rescans.
- The event stream emits `edge_observed` in production (both lanes): a record
  when an edge is new or its class changes, at most 4,096 per pass with the
  rest counted and carried, plus one exact sweep before `ended`, so a replayed
  stream equals the snapshot. Each distinct gap is published once per run
  (`gaps[].repeats`, `gap_recorded`/`gap_repeated`, `ended.edges_unretained`).
- `inventory --system` and `inspect --system` attribute callers past
  `--max-scan-pids`: the cap bounds deep scans only; every other process
  whose maps show a pinned provider object is attributed after a like-for-like
  `map_files` proof (pidfd and start-time pin, maps re-read, exe identity
  unchanged). New `maps_matched` / `not_selected` states, `mapping.evidence`
  (`deep_scan`/`maps_match`), the reshaped `scan` block, and per-category
  `maps attribution` losses. The proof needs `CAP_SYS_ADMIN` or
  `CAP_CHECKPOINT_RESTORE` to follow `map_files`; without it nothing is
  attributed by maps and the `maps attribution` losses say so.
- Per-edge semantic summaries (S1): `edges[].semantics` labels plus per-edge
  `mechanisms` and `operations` aggregates where an authorized feed observed
  them; scan-only edges stay `unknown (semantic capture withheld)`.
  Same-file double-load detection latches affected edges to unknown with a
  named gap.
- `inventory --max-gaps <n>` (1–65,536; default 1,024): retained gap history
  bound; gaps past it count in `gaps_suppressed`, never silently.
- `P11SCOPE_STAGE_TIMINGS=1` prints per-pass inventory stage timings to
  stderr. `profile`/`trace` discovery gains per-stage timing, queue-age and
  resource evidence (`evidence.scheduling`).
- Kubernetes: `deploy/k8s` is a least-privilege node DaemonSet (drop ALL plus
  `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, hostPID, read-only cgroupfs,
  capped `/tmp`, read-only root, seccomp `RuntimeDefault`, no token, no RBAC)
  with numbered manifests and a privilege rationale; `k8s-profile-entry`
  targets a pod by `--pod-uid` (or `--cid`) and refuses ambiguous matches;
  `scripts/kind-e2e.sh` is the committed kind end-to-end test with ledgered
  workloads and concurrent per-pod captures.
- `p11scope inventory` publishes caller `pid`, `start_time` and `image.exe`
  (owner ruling FB-PRIV): `/proc`-derived caller identity, documented in the
  inventory schema and in the allowlist-v3 "Inventory caller identity"
  section, which is implemented in this release (the rest of v3 stays
  proposed; allowlist v1/v2 remain the implemented capture contracts). Nothing
  new is captured: every field comes from `/proc` reads the scan lane
  already makes.

### Changed

- Classic `profile`/`trace` `--attach-backend auto` is decided by functional
  probes, not the 6.9 version floor: multi only where the probe links one
  (and, under `--pid`, only where it also proves the kernel pid filter).
  New `evidence.attach_backend` in profile reports and the trace terminal
  record discloses the selection, any fallback reason and the `--pid` scope
  filter; a fallback is also printed on stderr before the readiness line.
- A written capture can now be `COMPLETE`. The Detailed stop gate refuses new
  BPF callbacks and waits for admitted ones to finish; when quiescence is
  proven, both terminal drains reach their quiescence positions with no record
  past them, and the build is x86_64, `evidence.drain_proven` is true and a
  clean run reports `COMPLETE` (`verdict_detail: "clean_proven"`). New
  `evidence.stop_quiescence`; the trace terminal `EVIDENCE` carries the sealed
  verdict with `final_drain` equal to `drain_proven`. Every other terminal
  document stays `PARTIAL` (owner ruling B).
- A trace stopped by its event cap (`--max-events` or the 10,000,000 default)
  stays `PARTIAL` with cause `trace_truncated`, even behind a proven drain.
- The classic `inventory` loop ends cleanly on SIGINT/SIGTERM/SIGHUP: the
  stream's `ended`, the `-o` document and stdout are still written. The native
  stop writes the report first (at most 10 s of retirement wait), then finishes
  the detach after the report; a second signal once the report is written exits
  at once and the kernel releases the remaining links.
- The dashboard services the native lane through the same loop as the classic
  path and draws only inside service ticks with a non-blocking frame writer: a
  stalled terminal never delays capture. Shed frames are counted and reported;
  stderr diagnostics go to the log tail while the dashboard owns the screen.
- Every profile `mechanisms[]` row whose `params` is `null` now says why in
  `params_omitted` (`policy`, `no_shape`, `decode_failed`).
- The flat scan-cap gap is replaced by `discovery capped` (only when something
  stayed unexamined) or an `attribution complete` note; `scan.status` reads
  `complete` past the cap when nothing was left unexamined and nothing was lost.
- `docs/usage.md` documents the symlink policy (inputs follow and pin;
  outputs never follow), the cleanup progress lines, `cleanup incomplete` and
  exit 130, and the PID-namespace and paranoid ≥ 3 behavior.

### Fixed

- PID namespaces: an observer outside the initial PID namespace no longer
  publishes a silent zero claiming exact observation. p11scope reads its PID
  namespace and checks the mounted `/proc` is that namespace's own; on either
  mismatch it refuses `--pid`/`run`/`inventory --pid` with
  `pid-namespace-mismatch`, marks `--cgroup`/`--system` `PARTIAL` with cause
  `pid_namespace`/`proc_namespace_mismatch`, and carries `pid_namespace`
  (`observer`, `kernel_pids`, `proc_pids`) in every document plus a `doctor`
  row. A `/proc` with no entry for the observer refuses every capture
  except `inventory --system`, which warns and carries the `pid namespace`
  gap.
- `perf_event_paranoid >= 3`: `doctor` and the refusal now name the sysctl and
  `CAP_SYS_ADMIN` (the uretprobe self-probe and live-discovery probes attach
  through `perf_event_open`, which paranoid ≥ 3 refuses without it) instead of
  a lockdown/LSM/seccomp hint. Capabilities are judged where the kernel checks
  them (child user namespaces told plainly; unreadable `CapEff` no longer
  reported as dropped `CAP_SYS_ADMIN`).
- A second Ctrl-C while probe links close returns through the stop path:
  exit 130, the published report intact, post-cleanup reporting and
  destructors run. A failed capture still prints its live discovery-noise
  summary.
- A trace `-o` file that does not exist yet is created unnamed (`O_TMPFILE`)
  and linked at its name only once attached; filesystems without `O_TMPFILE`
  keep create-then-remove. An existing trace file is truncated only after
  attach; a failed start leaves a previous file as it was.
- Frozen watches render as `watch ended` / `capture ended`, never `Armed`;
  retiring/retired reads re-poll custody; pre-stop custody loss freezes
  watches at the last clean read; system-scope lifecycle loss demotes watches
  stickily; watches are withheld once the caller-use pair set saturates.
- The k8s pod-cgroup resolution is anchored at the kubelet hierarchy root and
  rejects decoy paths; the DaemonSet docs require `CAP_CHECKPOINT_RESTORE`
  when dropping `SYS_ADMIN` (past-cap `map_files` proofs need one of the two).

### Security

- Under `--pid`, classic `profile`/`trace` no longer links pid 0: uprobe-multi
  links name the target where the kernel pid filter is proven, else per-offset
  links bound to the target. This closes the PID-reuse exposure and stops the
  ~3.6 µs/call cost in unrelated processes mapping the provider (two probes
  per call on a `-O0` fixture, measured on host 7.0).
- Fail-closed PID-namespace handling above (silent-zero → refusal/lossy
  `PARTIAL`); no new PIDs are trusted across namespace boundaries.
- `(dev, ino)` object keys are not trusted alone on filesystems where they
  are not unique: maps-match attribution proves every range through
  `/proc/<pid>/map_files` like-for-like against a self-mapping of the held
  object (btrfs subvolumes, overlay with xino=off), and deep scans refuse a
  path-swapped object under the same maps key. The range-proof skip applies
  only on ext2/3/4, XFS, squashfs and EROFS; tmpfs was removed from that
  allowlist (32-bit wrapping inodes).
- `p11scope-discover -o` publishes private (0600) and atomically, and refuses
  symlink/FIFO/socket/device/directory names and non-sticky world-writable
  directories. A `--manifest` that changes size while read is refused.
- Spawned children close inherited descriptors (`close_range`, with a fallback
  that enumerates only after refusal), so a sibling test's child can no longer
  hold another child's exec pipe open past its deadline.
- The k8s entry script requires pod-cgroup depth/shape to match a kubelet QoS
  layout and rejects candidate paths with control characters.
- The static observer now links musl 1.2.5 with Rust's CVE-2026-6042 and
  CVE-2026-40200 patches (was musl 1.2.3).

### Removed

- The Rust 1.88 MSRV: the release compiler (`.release-rust-version`,
  currently 1.98.1) is the only supported toolchain. The 1.88 CI job and
  floor assertions are gone; the digest-pinned helper build containers and
  the release licence notices move to `rust:1.98.1` (f737b13).
  `rust-version` fields name the release major.minor (`crates/ebpf-common`
  stays at 1.97 with the pinned BPF nightly until the C7 bump).
- `k8s-profile-entry` API mode (`--pod NAME`, `--namespace`, `--container`)
  and its curl/jq dependency, `deploy/k8s/rbac.yaml` (observer Role) and
  `deploy/k8s/holder.yaml`. Pod targeting is by `--pod-uid`/`--cid` from the
  node's cgroup tree; the observer has no API token and no RBAC.
- `scripts/verify-k8s-attach.sh`, replaced by `scripts/kind-e2e.sh`.

### Known limitations

See [docs/known-limitations.md](docs/known-limitations.md) for the v0.2.0
user-facing limits (kernel tiers, scale, loss and coverage, scopes, counting,
platform, packaging). The v0.1.0 limits below stay for that release.

### Qualification of this release

Kernels: 5.15.221, Ubuntu 6.8.0-142, 6.12.111, 7.2.6, via
`scripts/qualify-release-matrix.sh` (vng guests, release binaries, Rust
1.98.1). The qualified binaries were built from `24f233c`; the release
candidate differs from that tree only in the classic `--pid` attach path,
`--event-log` hardening, the `--duration` bound, a doctor refusal-string
wording correction, and the 0.2.0 version bump. The classic `--pid` path
was separately vng-qualified 9/9 on all 4 kernels.

Checks, per kernel: `--version`, `doctor` capability tier T1
(`capture available`), the public CLI matrix 13/0, the inventory scan
lane, native backend selection (per-offset with the disclosed probe
reason on 5.15, uprobe-multi on 6.8+), and the pid filter. The
privileged library runner passes 61/61 cells on 6.8+ and 57/61 on 5.15
(see [docs/known-limitations.md](docs/known-limitations.md): physical-identity
controls and non-leader exec handling are unqualified on 5.15). The
native C8 oracle, after the oracle fix on this branch (exec-chain rows
counted, dashboard frames compared at their own pass), leaves only the 3
C6 attested-delivery cells unmet on each kernel — `inventory` has no
`--manifest` flag, so attested delivery cannot be exercised.

Re-run from the repo root (release binaries for `<RC>` staged as
`p11scope`, `p11scope-lib`, `p11scope-bpfmulti` in the bin dir):

```sh
export CARGO_BUILD_JOBS=4 TMPDIR=/var/tmp/p11scope-ws-tmp
scripts/qualify-release-matrix.sh --rev <RC> --bin-dir /home/user/.cache/p11scope-vng/rc-qualify-bins-<RC>
```

Still to land: the short measurement tier (M0, M1 at 4,096 processes, M4
churn, C5.6 pool — `TBD-MEASURED` in
[docs/known-limitations.md](docs/known-limitations.md) until they land).
Explicitly out of scope for v0.2.0: a long soak and a v0.1.0 comparison
(see [docs/known-limitations.md](docs/known-limitations.md)).

## [0.1.0]

First release. p11scope is a passive, non-interposing PKCS#11 observer for
Linux: it attaches eBPF uprobes to a running application's PKCS#11 provider at
offsets discovered from the provider's own function table, and reports which
functions, return values and latencies it observed — without replacing the
module, changing the application's configuration, or calling into the
provider during capture.

### Commands

- `p11scope doctor` — read-only preflight. Loads the real embedded BPF object,
  performs a self-uprobe, and reports one finite availability tier (T0–T4)
  for the host and an optional `--pid`/`--cgroup` target.
- `p11scope inspect --pid PID` — read-only discovery report: mapped providers,
  function-table surfaces, interface discovery and pinned file identities
  (`--json` for machine output). It loads no BPF and makes no PKCS#11 calls.
- `p11scope profile` — aggregate function, return-value and latency counts for
  a `--pid`, a `--cgroup` (and every descendant cgroup), or the whole machine
  (`--system`). `--mode metrics` reads the aggregate maps only and reads no
  call arguments in the kernel.
- `p11scope trace` — one line per completed call for a bounded window, ending
  in a machine-readable evidence record.
- `p11scope run [--pause never|auto|always] [--trace] -- CMD` — starts an owned
  command and starts capture before releasing it, so providers the command
  loads later are hooked through the loader/export path.
- `p11scope-discover --module /abs/path/provider.so [-o manifest.json]` — the
  optional offline helper. It executes provider code in its own unprivileged
  process and writes a `p11scope-manifest/5` manifest. The observer never runs
  it; passing its output with `--manifest` is an explicit operator attestation
  of function names and offsets.
- `--version` on both binaries prints the release version.

### Discovery

- Manifest-free memory-scan discovery of providers already mapped by the
  target, including stripped providers with no `C_*` symbols. Cumulative
  function-table support: PKCS#11 2.00, 2.01–2.40, 3.0, 3.1 and all 104 slots
  of the final 3.2 interface. Alternate, null or unreadable interface names
  are walked only as independently corroborated known prefixes.
- A newer minor version of a known major (a 2.x table after 2.40, a 3.x
  table after 3.2) is walked as a known prefix. The memory scan, the export
  path and `p11scope-discover` all read the 68 or 104 slots of the newest
  known layout. The appended slots are not hooked: the report names them as
  a surface gap and stays `PARTIAL`. A table with a new major version is not
  walked.
- Discovery continues while a capture runs: loader hooks on the five built-in
  entry points (`C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`,
  `NSC_GetFunctionList`, `FC_GetFunctionList`, plus `--hook-symbol`) pick up
  providers loaded after attach.
- System and cgroup inventory refreshes rotate bounded admission attempts
  past unreadable processes, allowing later callers to be considered without
  increasing the per-tick count or time limits.
- Every accepted provider file is opened once, pinned by descriptor and
  SHA-256, and re-checked with `fstat` before, during and after capture; a
  change sets `evidence.provider_changed` and forces `PARTIAL`.
- Static probes default to one multi-uprobe link per attach group on kernels
  6.9+ when the kernel accepts multi, falling back to per-offset links if it
  does not; below 6.9 the default uses per-offset links
  (`--attach-backend auto|multi|singles`).

### Reports and evidence

- `profile` writes `p11scope/observed-profile/v3` and `profile --mode metrics`
  writes `p11scope/observed-profile/v3-metrics`
  ([docs/schema/observed-profile-v3.md](docs/schema/observed-profile-v3.md),
  with a JSON Schema beside it). Optional discovery input is
  `p11scope-manifest/5`.
- Function-level call, error, return-value and latency counts come from the
  kernel aggregate maps (`STATS`, `RV_COUNTS`), which are the count authority:
  per-call event loss is counted and disclosed but never changes them.
- Every report carries finite gap counters and a verdict. A written report's
  terminal verdict is always `PARTIAL`: detaching a perf link does not wait
  for BPF callbacks already running on another CPU, so no terminal snapshot
  can prove a final drain. `evidence.verdict_detail` says what is behind it —
  `clean_but_unproven` (no gap), `attribution_only` (counts exact; a name,
  owner, mechanism or semantic interpretation withheld) or `concrete_gap`
  (an observation loss or degraded semantics) — and `evidence.gap_classes`
  lists the causing fields per class (`observation`, `attribution`,
  `semantics`). The live evidence line names the same reason.
- Manifest-free (scan-only) function slots are semantics-unverified and
  count-only; mechanism, session and lifecycle semantics need an accepted
  `--manifest`. They still carry standard function names when the provider's
  own `.dynsym` exports every standard name exactly where its table points
  (`discovery[].tables[].linkage: "exports"`); otherwise a row reads
  `unknown#<ordinal>`. Every row carries its exact target
  (`functions[].target`: pinned object identity and file offset) and the
  table positions that reach it (`functions[].ordinals`).
- `evidence.kernel_control` discloses the in-kernel accounting state: a
  `capture_halted` flag with finite reason names, and counts of owner
  admission and identity refusals. Any of them forces a concrete-gap
  `PARTIAL`, and p11scope prints one stderr line when capture halts.

### Privacy boundary

- The default capture policy is `allowlisted`: pointer-derived bytes reach
  output only by exact membership in a finite published set (a registered
  mechanism id or one of the 104 published function names). There is no
  decoder for PINs, key material, `CKA_VALUE`, labels, `CKA_ID`, plaintext,
  ciphertext, signatures, wrapped blobs, random output, raw mechanism bytes,
  raw session handles or ordinary buffers. Under this policy every mechanism
  has `params: null` and `templates.operations` is empty.
- The older unvalidated decoders exist only in a build with the
  off-by-default `unsafe-unvalidated-metadata` Cargo feature *and* an explicit
  `--unsafe-unvalidated-metadata` flag. The release artifact is built with
  `--no-default-features` and cannot enable them. That feature build loads on
  every qualified kernel including 5.15.
- The field-by-field inventory is
  [docs/privacy/allowlist-v1.md](docs/privacy/allowlist-v1.md) plus the
  [allowlist-v2.md](docs/privacy/allowlist-v2.md) extension. The secret-canary
  suite (`scripts/verify-canaries.sh`) plants sentinel PINs, keys, labels and
  buffers and scans every output and observer-owned BPF map for them.

### Safety

- On kernels where a uretprobe makes the target issue `__NR_uretprobe`, a
  seccomp-confined target could be killed by being observed. p11scope probes
  the kernel with its own child and refuses to attach to a confined target on
  an affected kernel unless `--allow-uretprobe-on-confined-target` is given;
  `doctor` reports the row.
- `run` never releases a root child: under `sudo` it drops the child to the
  invoking `SUDO_UID`/`SUDO_GID` account with no capabilities, `no_new_privs`,
  a small environment allowlist and no unrelated inherited descriptors.

### Fixed limits of the release build

- 512 physical probe-target (attach) slots per capture. Slots are lifetime
  allocations: a slot retired by an exiting provider is not reused
  (`slots` vs `active_slots`).
- 256 loader contexts per capture for late-load (`dlopen`) tracking.
- One capture-wide 512 MiB attempted-I/O budget for memory scans and
  scan-sourced file hashes, at most 256 MiB per scan/hash operation; 512
  accepted table candidates, 53,248 decoded table entries and 512 interface
  records. `--cgroup` and `--system` deep-scan at most 256 processes per pass
  by default (`--max-scan-pids`). Manifest inputs are capped at 16 MiB per
  manifest, 256 MiB per object and 512 MiB per manifest.
- Kernel-side capture state: a lifetime budget of 16,384 process identities
  per `profile`/`trace` capture (never reused; under `--cgroup` and
  `--system` every process created in scope spends them, whether or not it
  calls PKCS#11) and at most 16,448 threads with an in-flight call at once.
  Exhaustion is counted in `evidence.kernel_control`
  (`identity_budget_exhausted`, `owner_admission_failures`).
- The per-call event ring defaults to 4 MiB (`--ring-bytes`, 4K–64M); the
  live-discovery ring is 64 KiB for a named process and 2 MiB for
  `--cgroup`/`--system` captures. `trace` stops at 10,000,000 events
  unless `--max-events` sets another cap.
- Any bounded omission is reported and forces `PARTIAL`. The
  `wide-detailed-2112` Cargo feature builds a 2,112-slot profile from source;
  it is not the release artifact's profile.

### Platform and privileges

- x86-64 Linux, kernel 5.15 or newer. p11scope does not check the kernel
  version itself; an unsupported kernel fails with a named cause and a hint.
  Qualified kernels: Ubuntu 5.15.0-187, 6.1.188, 6.6.157, Ubuntu 6.8.0-142,
  6.12.111 and 7.2.6 (per-probe links below 6.9, uprobe-multi from 6.9),
  plus Ubuntu 7.0.0-31 on the host; see
  [Qualification of this release](#qualification-of-this-release).
- Capture needs root (`sudo`) or file capabilities on the observer binary.
  The attach floor is backend-dependent: the default tries uprobe-multi on
  kernels ≥ 6.9 and falls back to per-probe links if multi is unsupported.
  With multi active, `CAP_BPF` + `CAP_PERFMON` suffice to attach at
  `perf_event_paranoid=4` (measured 136/136); on the per-probe `perf_event`
  path a restrictive `perf_event_paranoid` needs
  `CAP_SYS_ADMIN`. Scanning a same-UID non-descendant also needs
  `CAP_SYS_PTRACE` under Yama `ptrace_scope=1`. See
  [docs/usage.md](docs/usage.md#privileges-per-environment).

### Release artifacts

- `p11scope-0.1.0-x86_64-linux-musl.tar.gz` — the statically linked observer
  with the BPF object embedded; the executable has no shared-library runtime
  dependencies.
- `p11scope-discover-0.1.0-x86_64-linux-gnu.tar.gz` and
  `p11scope-discover-0.1.0-x86_64-linux-musl.tar.gz` — optional, dynamically
  linked discovery helpers. Use the one matching the provider's ABI and C
  library; a static helper cannot `dlopen` a provider.
- `p11scope-0.1.0-source.tar.gz` — committed source plus the two pinned Aya
  archives. The remaining locked Cargo dependencies require network access or
  a pre-populated cache; toolchains and operating-system build tools are
  separate prerequisites.
- `RELEASE.json` and `SHA256SUMS` — release provenance and checksums for the
  public assets. The three binary bundles include project licenses, applicable
  third-party notices and build provenance. `scripts/build-release.sh` builds
  and verifies the binaries, remapping build-host paths so they do not embed
  the builder's home or checkout directory.
- Licensing: the observer is GPL-3.0-or-later and the BPF programs are
  GPL-2.0-only. `crates/ebpf-common`, which is compiled into both, is
  GPL-2.0-or-later.

### Known limitations

1. **Capacity.** The 512 slots are shared by every provider in the capture.
   `--pid`, `run` and captures aimed with `--module` admit providers in
   discovery order. `--cgroup`/`--system` captures without `--module` admit
   each provider whole or not at all, by value (`--manifest` providers, then
   corroborated tables, then heuristic finds, proxy closure arrays last), and
   heuristic finds may not use the last 128 slots (25%), kept for
   corroborated providers found later. A refused provider, or a refused growth
   of an admitted one, is reported with what holds the slots and forces
   `PARTIAL`.
2. **`--system` is a preview.** Whole-machine capture shares the 512 slots
   with every ambient provider on the host (NSS, `p11-kit-trust`, p11-kit
   proxies, …), takes seconds to start, and on busy hosts loses live-discovery
   records (reported as loss). Aim it with `--system --module <path>`. Long
   `--cgroup`/`--system` captures of busy hosts can spend the 16,384-identity
   budget (about an hour at 5 new processes per second); later processes are
   then counted only as identity refusals. Measured on a desktop host
   (Ubuntu, kernel 7.0): the scan took 2.7 s and admitted four providers
   (272 slots, 544 probes) with exact SoftHSM2 counts, and refused the
   `libp11-kit` proxies whole, each needing about 6,000 more slots than the
   512 available.
3. **Coverage window.** Calls made before attach are not observed. Under
   `profile`/`trace --pid` and `run --pause never`, the first calls after a
   late `dlopen` can be missed before that provider's probes land.
   `run --pause auto` holds the child at each loader hit until the new
   provider's probes are attached: in qualification it captured every call
   of a child that `dlopen`s SoftHSM2 (2,000 iterations of six functions,
   plus setup), on the host and on all six vng kernels. A workload that exits
   within milliseconds can still end before attach completes. Manifest-free
   captures are count-only by design.
4. **Exec.** A `--pid` target that calls `exec` is not re-bound to the new
   image.
5. **Not observed.** Statically linked providers, JIT-generated or anonymous
   function tables, vendor-only interfaces (count-only or unknown), and calls
   through unsupported surfaces.
6. **Trace output** has no provider column; PIDs are host-namespace PIDs.
7. **Containers and Kubernetes.** `deploy/k8s` is an example, not a
   published image. Docker, shared-layer, kind and Knative capture is
   supported and passed on the release candidate; see
   [Qualification of this release](#qualification-of-this-release).
8. **`run` under `sudo`** clears supplementary groups, so a workload that
   needs an HSM/device group should be observed with `profile`/`trace` or run
   with a capability-carrying observer instead.
9. **Overhead** against SoftHSM2 `C_GenerateRandom` called back to back
   (about 0.8 µs per unobserved call) is about 4.1 µs added per call in
   `metrics` mode (6.3x wall clock), 6.8 µs in `profile` mode (9.7x) and
   5.5 µs under `trace` (8.0x). This is a worst case, not an envelope. With
   the default 4 MiB ring no per-call event was lost at that rate; aggregate
   counts stay exact even when events are lost. See
   [docs/usage.md](docs/usage.md#overhead-measured).
10. **Not claimed.** Continuous system inventory, caller attribution,
    capacity growth, cumulative counters across all providers by default,
    operation-level semantics beyond attested manifests, a first-use
    guarantee, supported event rates, long-duration/soak behaviour, and
    AArch64.

### Fixed during release-readiness work (2026-09-26)

Fixes to defects found while qualifying this release, before it was tagged:

- `run --pause auto` of a command that exits before its deferred loader scan
  keeps the capture and writes the report instead of failing with none.
- A `--pid` or `run` capture whose target exits while live discovery is
  arming or preflighting ends normally with its report instead of failing.
- Already-loaded providers are named: tables whose ordinals agree with the
  provider's own exports get standard function names instead of `unknown`
  rows, and every row carries its exact target and ordinals.
- The verdict is split: a clean scan-only capture reads `attribution_only`
  rather than `concrete_gap`; the terminal verdict is judged on the final
  output accounting; the live line names why it is `PARTIAL`.
- `--cgroup`/`--system` admission is by value and whole-module with a
  capacity reserve, so ambient proxies (p11-kit) can no longer take every
  slot and starve the provider of interest; refusals name the slot holders
  and `--module`.
- A multi-process capture starts once and retires views that go stale
  meanwhile; a view's mount table is read once per scan; attach cells a
  candidate allocated but never linked are given back.
- In-kernel call-owner accounting no longer breaks under multi-core
  contention (it could halt all capture), and its state is disclosed in
  `evidence.kernel_control`; interface flags are published only as a finite
  class.
- `-o` refuses names that are not regular files (directories, `/dev/null`,
  FIFOs, sockets, symlinks) instead of replacing them, and keeps a previous
  trace file until the capture has attached; a closed stdout or stderr pipe
  no longer panics; Ctrl-C during startup is honoured without leaving
  temporary files; `inspect` of a target whose maps cannot be read exits 1
  instead of reporting no modules.
- `p11scope-discover --version`; release builds no longer embed build-host
  paths; hosted CI can run its manual release-preview job.
- A second SIGINT arriving within 100 ms of the first counts as one stop,
  not a second Ctrl-C, so a supervisor that delivers the signal twice no
  longer aborts cleanup.
- Refusing a writable `-o` directory now names who can write it, its mode,
  the missing sticky bit and the fix (`chmod g-w,o-w`).
- The profile live display redraws only when stdout is a terminal; into a
  file, a pipe or a service log only the final frame is printed, once, as
  plain text.
- Non-UTF-8 arguments no longer panic: path flags keep their exact bytes
  and `run` passes its command through byte for byte.
- `--cgroup` refuses a path that is not a cgroup v2 directory before any
  capture work, so capture and `doctor` agree.
- `doctor --extra-strict` passes a capable host: the three build-limit rows
  are listed as not counted, sysctl rows are `ok` when the process holds
  the lifting capability, and the verdict line no longer reads as if `run`
  cannot work.
- A BPF self-probe refused for lack of privilege is reported as missing
  privilege (run with sudo; `p11scope doctor` shows what the host allows),
  never as a seccomp-hazard refusal offering the override.
- Owned pauses chain: every confirmed stop installs a successor while the
  child is still stopped, so a provider's table publication is applied
  inside the causal cycle; a chain that ends with a table unpublished
  reports `PARTIAL` instead of running it silently unpaused.
  `attach_gap_ms` is no longer erased by deferred scans settled at process
  exit.
- `--cgroup`/`--system` captures load a 2 MiB discovery ring (about 2,260
  records) instead of 64 KiB, stage it into a bounded FIFO on every tick,
  wake on either ring, and read loop-end discovery loss fresh from the
  producer counters.
- An armed loader that never fired (zero hits) is no longer an observation
  gap: `loader_discovery` dlopen timing counts as a gap only when the
  loader actually fired.
- A live discovery frame runs under a 100 ms work budget and defers the
  rest of its work, in order, to the next frame; the stop flag is checked
  between items.
- Loader timing a full pause covered is `pause_protected`, not a gap:
  `loader_discovery` `dlopen_timing`, `initial_set_timing` and
  `initial_set_capture` each gain a `pause_protected` count, and the
  duplicate initial-set `skipped` entry is gone.
- Once probes are attached, `profile` and `trace` print one stderr line
  (`p11scope: capturing: N probe(s) attached; stop with Ctrl-C`), so
  scripts and supervisors wait for readiness instead of guessing with
  sleeps.
- Trace lines and `attach_failures[]` evidence escape target-controlled
  names and paths exactly like the terminal diagnostic and `inspect`.
- `profile` without `--duration` prints a one-line stderr notice that it
  captures until interrupted, matching `trace`.
- `-o -` means stdout for `trace` (and `run --trace`); `profile` refuses it
  as a usage error. No command ever creates a file literally named `-`.
- Stricter usage errors (exit 2): a repeated scalar flag, an empty-string
  option value, `--pid 0`, and a zero `--duration` are each refused naming
  the flag.
- On Linux 6.13+, every classic uprobe program keeps the task's kernel
  stack instead of the shared per-CPU private stack, fixing same-CPU
  preemption corrupting frames and halting capture with owner
  `start_key_mismatch`.
- The 6.9+ uprobe-multi endpoint programs opt out through their own empty
  `STACK_GUARD` program array, so sessions load on kernels that require
  program-array users to share the expected attach type.
- Each thread's in-kernel owner storage is created once and retained idle
  instead of allocated and freed per call, fixing refused calls under
  multi-threaded load with no per-call allocation on the hot path.
- `evidence.kernel_control.owner_poison` names exactly which owner
  bookkeeping invariant failed: `start_key_mismatch`,
  `start_count_mismatch`, `start_row_missing` and `directory_mismatch`
  sub-reasons beside `bookkeeping_failed`.
- The doctor `kernel.perf_event_paranoid` row is backend-aware: `ok` on
  uprobe-multi kernels (≥ 6.9) where paranoid gates nothing, keeping its
  warning and `CAP_SYS_ADMIN` lift on the per-probe path.
- Frame deferrals are counted in `scheduling.discovery_deferrals` as
  scheduling evidence, never a loss; only work still undone after the
  terminal drain is a loss.
- Queuing a polling rescan no longer forces `PARTIAL` by itself: only a
  rescan that finds a provider gained unwatched publishes a loss; a poll
  that finds nothing publishes nothing, and failed or retired polls are
  forgotten exactly once.
- On kernels before 6.8, providers on overlayfs are attached instead of
  refused. This covers containers on Debian 12, Amazon Linux 2023 and
  Container-Optimized OS, which previously captured zero modules.
  - The cause: `/proc/<pid>/maps` on those kernels names the backing
    layer's device, while the opened file names the overlay's device.
  - The check stays exact: p11scope accepts the file only when the kernel
    maps it at the target's device and inode.
  - `p11scope-discover` applies the same check, so it runs inside such
    containers, and its manifests work with `--manifest` there.
- A build compiled with the `unsafe-unvalidated-metadata` feature loads on
  uprobe-multi kernels (≥ 6.9) again. It failed there with `Invalid argument`,
  because kernels with the CVE-2025-40123 fix require every program sharing a
  program array to have the same attach type. The release build does not
  include that code and was not affected.
- The same feature build now loads on Ubuntu 5.15. Its
  `p11_entry_template_types` program exceeded that kernel's
  1,000,000-instruction verifier limit, because the types-only walk ran as a
  local subprogram the verifier re-explored per caller state. The walk now
  runs behind its own verified-once global, like the full template walk, with
  identical captured output. The release build does not include that code and
  was not affected.

### Qualification of this release

The runs below are pre-release evidence, not a claim that the final tagged
binary or source export passed these lanes. The public-command and Docker,
shared-layer, kind and fork-scope lanes ran on 2026-09-28 against candidate
`a7800dd`, using the static musl observer built by the official
`scripts/build-release.sh` path (SHA-256
`9da91f3a60c8404741303841fe2a02df77c4607768f0cdce454ad5730f1ed022`).
The release gate, privileged library suite, Knative lane and privacy canaries
built their own binaries from that tree. The later unsafe-feature verifier
fix has separate verification below; it does not retroactively change the
identity of the earlier artifact. The
[v0.1.0 GitHub release notes](https://github.com/mingulov/p11scope/releases/tag/v0.1.0)
record the exact tagged commit, hosted CI, final artifact checksums and any
qualification performed on those final bytes.

- `scripts/release-gate.sh --profile both`, fresh target directory: PASS.
- Public-command qualification (`scripts/qualify-public-cli.sh`: exact
  per-function counts for `profile`/`metrics`/`trace --pid`, `run` of a
  short-lived and of a `dlopen`ing child, a multi-thread exactness cell,
  `--system`, SIGINT publication, `-o` FIFO refusal): 12/12 on the host
  (Ubuntu 7.0.0-31) and 12/12 in virtme-ng guests on Ubuntu 5.15.0-187,
  6.1.188, 6.6.157, Ubuntu 6.8.0-142, 6.12.111 and 7.2.6.
- Privileged library suite (`scripts/run-privileged-lib-tests.sh`): 42
  passed, 0 failed on the host, on Ubuntu 5.15 and on Ubuntu 6.8. Five tests
  that need an external harness were skipped, the same five on each kernel.
- Container lanes on the host: Docker, shared image layer, kind pod,
  fork-scope and Knative scale-from-zero, all passed with exact counts.
- Privacy canaries (`scripts/verify-canaries.sh`): all 12 lanes OK, no
  leak.
- Overhead re-bench (`scripts/bench-overhead.sh`, host): all 15 observed
  samples valid; the numbers are in Known limitations item 9.
- `unsafe-unvalidated-metadata` 5.15 verifier fix (vng, root): the feature
  build's `doctor` program preflight passes on Ubuntu 5.15.0-187 and 6.8.0-142
  and on mainline 5.15.221, 6.1.188, 6.6.157, 6.12.111, 7.0.14 and 7.2.6. On
  Ubuntu 5.15 the pre-fix object fails at `p11_entry_template_types` with
  E2BIG (1,000,001 instructions processed). An unsafe `run` of a SoftHSM
  `pkcs11-tool -O` workload records identical template operations and
  per-function call counts with the fixed build on Ubuntu 5.15, and with both
  builds on Ubuntu 6.8 and mainline 5.15, with no event loss.

### Pre-release development history

Before this entry, this file described internal milestones (an early
schema-v1.2 MVP, a corrective lease/provenance lane that was later removed,
and the productization slices that led to schema v3). None of them was
released, and several of their statements no longer describe the product.
They are superseded by this entry and remain in the Git history of this file.
