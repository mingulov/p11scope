<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Changelog

All notable changes to p11scope are recorded here. Versions follow
[Semantic Versioning](https://semver.org/). Report schema identifiers are
versioned separately and are opaque, exact dispatch keys.

## [Unreleased]

### Known limitations

- On a busy host, a long `inventory --system --key-operations`
  capture can stop recording key operations partway through; the
  report stays PARTIAL with exact counts and no lost calls. Since
  0.8.0 the lane re-arms past a transient Audited-phase refusal (up
  to 32 abandoned quanta per run, each named), and refusals at other
  phases still stop the lane with the phase named. Rerun the capture
  or narrow the scope (`--pid`).

## [0.7.0] - 2026-11-13

### Added

- Kernel file-open learning under `--system` (`profile`/`trace`):
  providers loaded by one-shot tools are learned generically (any
  vendor, any path), listed with the program that first loaded them,
  and attached so later runs in the same capture are caught; the first
  use stays a named gap (`first_loaded_by`, `learned_*` evidence,
  `learned provider file` rows).
- `inventory --event-log -` streams the versioned JSONL event lines to
  stdout (same schema, never interleaved; the text summary moves to
  stderr), and `--event-interval <dur>` adds periodic `totals`
  snapshots to file and stdout streams alike.
- The observer image is published as `ghcr.io/mingulov/p11scope:<version>`
  on releases (see `RELEASING.md` step 7.4), built from the verified
  release tarball with licenses, notices and `RELEASE.json` inside, for
  one-host Docker use and the Kubernetes DaemonSet. Its
  entrypoint is now `p11scope`, so plain `docker run IMAGE <p11scope args>`
  reaches the observer; this changes behaviour for `docker run IMAGE`
  with in-cluster entry-script arguments (address the entry script by
  explicit name instead).
- Callers running under an interpreter carry an app label beside it:
  `python3 [backup.py]`, `java [app.jar]`.
- Callers show their launcher chain: one hop (`from backup.sh`) by
  default, up to four in `-v` and JSON (`launched_by`).
- Linux 7.4-rc2 joins the tested kernel matrix.
- A forwarding layer's whole table set is watched when the probe
  budget allows, so calls through pre-attach tables count and the
  layer's own calls separate from application calls.
- A container copy-up attributes both sides of the file: the witness-proven
  pre-copy-up lower file gets its own module row carrying
  `"layer": "pre_copy_up"` in JSON (`(file before copy-up)` in verbose
  text), so stale-mapping calls count on the lower edge.
- Failed calls explain themselves per caller: the trace tail carries
  a `CALLER ERROR REASONS` section naming each failing
  caller-and-function pair with its return codes and counts, and
  profile output explains per-function failures with CKR names.
- `p11scope inventory cbom input.json -o out.cdx.json` converts a
  saved inventory or profile report offline to a CycloneDX 1.6 bill
  of materials; it reads only the published JSON and captures
  nothing new.
- Short-lived tracking (`--track-short-lived`) now covers trace,
  metrics, pid and run captures, including the owned tree under
  `run`.
- Every `mechanisms[]` and `cgroups[].mechanisms[]` JSON row carries
  `name`: the `CKM_*` name when the id is a known standard or listed
  vendor mechanism, else null, never guessed.
- A documented least-privilege container recipe (no `--privileged`,
  no `CAP_SYS_ADMIN`): `--cap-drop ALL` plus `BPF`, `PERFMON`,
  `CHECKPOINT_RESTORE`, `SYS_PTRACE` and `DAC_READ_SEARCH` under the
  Docker default seccomp profile (Docker 24+) or the Kubernetes
  `RuntimeDefault` profile captures exactly like the shipped set,
  with `deploy/seccomp-p11scope.json` (vendored Docker default plus
  one `bpf()` allow) for older engines, custom daemon defaults and
  Kubernetes `Localhost` profiles. The shipped `SYS_ADMIN` default is
  unchanged.
- AppArmor-enforcing hosts get `deploy/apparmor-p11scope` (the Docker
  default profile plus one `ptrace (read, trace) peer=unconfined`
  rule), which captures the least-privilege matrix exactly without
  `apparmor=unconfined`; SELinux-enforcing hosts need no extra flag
  (`--pid=host` containers run as `spc_t`, zero AVCs; full-multiset
  exactness shown on the reference host 8/8 plus the Fedora five-cap
  twin, Fedora system-shipped 7/8 with one noise-only surplus leg),
  and Pod Security Admission keeps demanding the `privileged`
  level for both capability sets (measured denials name hostPID, the
  capabilities and the hostPath volume).
- Pid-scope captures name the program after an exec: when a `profile
  --pid` or `metrics --pid` target execs another program during the
  capture, the report keeps the attach-time program in
  `capture.caller.exe` and discloses the end-of-capture program in
  the new `capture.caller.exec_to_exe` field, and the text output
  names both programs. A transition is claimed only when the
  executable file identity changed between the two reads through one
  held descriptor (a rename or unlink alone claims nothing), and
  nothing is claimed when the end read cannot be tied to the target.
- A browser started after a background PKCS#11 process now gets
  per-key tracking: when its exact image binds within a bounded
  grace, its shed-taint lifts and tracking starts above the
  unattributed pre-bind calls. Images with a genuine contradiction,
  or proven only by another exec of the same process, stay refused.
- Per-key tracking now rules out LTO kernels on hosts without
  `/boot/config-*`: the check reads the running kernel's own
  `/proc/config.gz` first, then the boot file, then the modules
  tree's `.config` (only with a release proof). Arch and NixOS hosts
  are covered; a kernel whose LTO status cannot be verified still
  refuses. (New dependency: `flate2` for gzip decoding.)
- `inventory --system --key-operations` without `--manifest` shows
  per-key rows once the scan seal seats: longer captures and narrowed
  scopes (`--pid`, `--module`) seal with no flag, and `--cgroup`
  captures attempt the seal. Short runs that end first carry a `key
  operations unavailable` gap naming the seal state and the remedies
  instead of the misleading `needs --manifest` line.
- Quiet Docker and `--cgroup` captures no longer report PARTIAL when
  post-ready completion attached only publication hooks: the window
  files a gap only when counting coverage was added. Scan-only
  captures with layout evidence now read COMPLETE instead of PARTIAL.
- Text output prints full provider paths with their container origins
  in ASCII-only text, so large-host inventories name the exact file;
  narrow cells keep the provider name visible.
- Verified linker-interposition forwards keep the standard-layout
  proof: a getter slot forwarded into another object stays count-only
  itself while own-object slots publish their mechanism names, so
  p11-kit-proxy interposition no longer refuses the whole table.
- File learning under `--system` marks through shadowing mounts and
  file binds, so providers under an overlay or a bind-mounted file are
  learned; automount triggers and device binds are skipped, and the
  mark pass is bounded so a hung mount cannot stall the capture.
- Discovery runs faster at scale: a lazily built raw-key index and
  by-ID pin lookup join more calls (scale cell: 14 of 16 passes vs
  12 of 14, 31% more joined calls), and cheaper bind (about 4x) and
  projection (about 2x) steps cut per-call cost.
- System-wide captures examine up to 1,024 user processes in detail
  (was 256), sharing one examination per exact library set, with a
  counted gap naming what was not examined; kernel threads never
  consume slots.
- Captures no longer hit the file-descriptor wall: the soft limit is
  raised at startup with a fixed reserve held back, and the reserve is
  sampled once per tick, failing open.
- Library-handle pressure waits and retries instead of dropping work
  (one scan pin per physical file, deferred handles retried first).
- Live discovery looks only at user processes, so kernel threads no
  longer cause "new processes pending" skips on busy hosts.

### Changed

- Detailed per-call capture now plans 2,112 attach slots (was 512), so a
  busy desktop watches every provider — including Firefox's `libsoftokn3.so`
  and `p11-kit-trust.so` — instead of refusing them for slots. The wider
  profile costs about 5.7 MiB more locked kernel memory at 12 CPUs (about
  7.5 MB of per-CPU counters in all). `--no-default-features` still builds
  the 512-slot comparison profile. Counter modes ship in the wide build
  on their fixed bank geometry, and the production journal ships at the
  wide Detailed geometry.
- Retired attach slots are reused once their occupant is gone and its
  counts are final: a provider that leaves and returns reoccupies its own
  slots, so process churn no longer burns the lifetime budget. A provider
  that still does not fit whole attaches its most important functions with
  a named `(provider_partial)` gap instead of being refused whole, small
  providers decide first within their class, and whole capacity refusals
  are named in the default output, not just `-v`.
- The lifetime identity budget is **262,144 tickets per capture** (was
  16,384): system-wide captures on busy hosts stay sighted for hours
  instead of minutes (about 3.6 hours at 20 new processes/s). Tickets
  are still never reused; a spent budget is still disclosed with counts
  on every surface (`identity_budget_exhausted`, `identity_unavailable`).
  Packing trade-off: the identity cookie now packs 262,144-valued tickets
  with 44-bit incarnations (was 16,384-valued tickets with 48-bit
  incarnations); 2^44 incarnations per ticket is not reachable in practice.
- The semantic-state key budget is **262,144 keys per capture** (was
  16,384): churn-heavy nodes keep per-pod attribution (a kind churn
  cell admitted only 98 of 451 pods before). Live-state keys (open
  sessions, active ops, find state, per-process pseudonym counters)
  are returned to the budget where their entries are removed, so
  short-lived churn cannot spend it; report rows stay kept and stay
  counted. The enforced limit is now named in the report itself
  (`evidence.semantic_key_budget` in JSON, the spent budget beside
  the verbose session-tracking gaps), and refusals still count in
  `semantic_state_drops`.
- The default EVENTS ring is 32 MiB (was 4 MiB) for `profile`, `trace`
  and `run` in profile and trace modes, and the key-operations (Joint)
  lane's ring is 32 MiB (was 16 MiB). `--mode metrics` (with or without
  `--counter-mode`) writes no per-call records and keeps 4 MiB. The 4 MiB ring held about 21 ms of records at the fastest
  measured call rate and could overflow during a short drain gap on a
  fast host; 32 MiB holds about 170 ms there and about 470 ms at 190,000
  calls/s. It costs about 29 MB more locked kernel memory per capture
  (about 34 MB in all; one ring per capture, shared by all CPUs) in
  the per-call modes.
  `--ring-bytes` still accepts 4K to 64M, and `--help` now states the
  default.
- When a run's command exits with a full ring, the final drain of its
  remaining events gets more time (it now grows with the ring's
  contents), and if it still runs out of time the report is published
  with a stderr line `root_tail_incomplete: deadline; remaining=N`
  instead of the run failing without a report. The remaining events are
  still counted.
- The Kubernetes DaemonSet's memory request is now 128Mi (was 64Mi):
  each concurrent capture holds about 34 MB of ring memory.
- `p11scope run` now pauses by default (`--pause auto`): a first run
  holds the child at loader hits until its probes attach, so early
  calls are counted instead of missed. `--pause never` stays available
  for runs that must not delay the child, and an `auto` pause that
  cannot start degrades to an unpaused run with a named gap instead of
  failing the child.
- Killing the observer with SIGKILL during a paused `run` writes no
  report (no handler can run); a child the pause held stopped resumes
  when the observer dies, through its SIGCONT parent-death signal (see
  `docs/usage.md` and `docs/known-limitations.md`).
- A stop that lands inside an active `auto` pause cycle now ends the
  run by signal with its report instead of a `pause coordination
  cancelled` error; the cancelled attempt counts one partial.
- Empty captures explain themselves instead of showing a bare empty
  view: the concise gaps block ranks count-explaining gaps first, the
  limits line says "recorded, 0 attached" for scan-only inventories,
  and discovery stops read as discovery events, never file counts.
- A stopped pass-0 collection is kept as scan-only inventory under
  every scope (`--pid`/`--system`/`--cgroup`) (modules and callers
  shown, counts not attached) instead of being discarded.
- On hosts without usable `uprobe_multi`, `inventory --system` and
  `inventory --cgroup` with the default `--capture auto` now exit 0 with
  a PARTIAL scan report carrying the `native usage feed unavailable` gap
  (was: exit 1 with no report).
- Under `run`, an exhausted `--max-events` budget hands a live child back
  running and exits 0 (was: the child was terminated and the run exited
  143); the report carries the truncation marker. A capture error
  likewise hands a live child back running instead of killing it, still
  exiting 1 with the error and the surviving PID on stderr.
- Under `run`, an expired `--duration` whose pause cleanup failed now
  resumes and hands the live child back instead of killing it (unless
  `--kill-on-timeout` was given), exiting 1 with the cleanup error and the
  surviving PID on stderr.
- A `run` whose `--pause always` cycle is refused keeps its report:
  the sealed report names the refused pause instead of the run
  failing without one.
- Every observed mechanism id is shown with its counts: standard ids
  and 53 listed vendor ids (NSS, CloudHSM, YubiHSM, Luna) keep their
  `CKM_*` names as a display-only layer over the generic per-number
  counts, other ids at or above `0x80000000` show as
  `vendor-defined 0x…` with the exact number, and other unknown ids
  show as `unknown 0x…`. Previously only standard ids and a fixed
  list of NSS vendor ids were named and anything else showed as a
  bare number. The per-id table holds 256 distinct ids per capture;
  further observations shed into the named
  `evidence.mechanism_id_overflow` count and force `PARTIAL`, never
  silently.
- Known vendor mechanism ids resolve display-only `CKM_*` names over
  the generic per-number counts: 41 NSS ids plus 6 CloudHSM, 4 Luna
  and 2 YubiHSM ids. Removing the name table would change only the
  displayed name, never counts, publication or row presence.

### Fixed

- `inventory --system` binds usage on hosts with many endpoints (was:
  zero rows with `not_attached`).
- stdout/stderr keep working under sudo with the tightened kept
  capability set.
- The empty-report heading names refused providers ("none attached (N
  found, refused)") instead of claiming "no modules discovered" beside
  the stderr refusal line; a proxy closure still awaiting publication
  keeps the nothing-discovered heading.
- The nested-capture refusal says "no countable modules" instead of
  "found no PKCS#11 modules", and the discovery-stop hint lists stop
  reasons without repeating the subject.
- A scoped (`--cgroup`) capture on an overlay filesystem publishes
  the scan-found module as PARTIAL with its named gap when the
  file-identity witness is unavailable (was: the module was refused
  and the capture could show no countable endpoints).
- Transient admission-deferral scan refusals settle when the endpoint
  is admitted instead of staying refused (was: up to 2 endpoints
  reported as refused at very high call rates).
- A nested observer's `--system` capture starts on an idle node and keeps
  watching — an empty run reports PARTIAL with the `pid_namespace` cause
  until providers appear, then counts them — instead of refusing with
  `pid-namespace-mismatch` when zero modules are mapped at start.
- A nested capture that sees only its own container (`docker run`
  without `--pid=host`) warns at start and in the report ("only this
  container is visible; run with --pid=host to see the host") instead
  of silently covering the container alone. Views with other processes
  visible (kind nodes) are unchanged.
- `doctor` on the static release build samples the host's loader facts
  from init when the observer itself is statically linked, instead of
  warning that the loader is unbound on every host.
- A stalled stderr no longer stalls the capture: diagnostics shed
  with counts instead of blocking when stderr is a full pipe or
  terminal, and a capture with no free file descriptor still prints
  its refusal instead of exiting silently.
- System-wide captures no longer count kernel-thread exits as lost
  processes, retry loader attaches blocked by a racing exit, replace
  stale thread-ID entries when the loader binds, and disclose failed
  cleanup detaches as named gaps instead of dropping them.
- Guest and cgroup captures classify stopped and refused work
  correctly: returns that predate continuity are not counted, failed
  retirements count as unmatched, and retired refused joins count as
  semantic instead of unmatched.
- A stale manifest grants no semantic authority: replacement tables
  lend names only, never semantics, and non-standard, disagreeing or
  forged replacements stay count-only.
- System-wide runs no longer count p11scope's own short-lived
  self-check helper as a pending process.

### Corrections

- In v0.6.0, keys created during the capture that never got a
  label were summarised instead of listed: re-measured 2026-11-10
  on a 5-vCPU Fedora host (kernel 7.2.9, SoftHSM 2.7.0-rc1), the
  published v0.6.0, rc-5 and rc-8 all show 0 per-key rows at 6,250
  calls/s for 60 s. v0.7.0 lists such keys as per-key rows labelled
  `unknown`: on the development host at 6,250 calls/s for 60 s the
  cell shows one row with 187,499 started / 187,499 completed.
  Reruns on the remaining hosts are pending.
  On small VMs where hook events are missed, the affected key stays
  unattributable for the rest of the capture with a named gap;
  plain-path counts stay exact.
  See [Key-tracking rate ceiling](docs/known-limitations.md#key-tracking-rate-ceiling).
- In v0.6.0, a long `--system` capture on a host that starts and
  ends many processes used growing observer memory (about 1.2 GB for
  an hour on a busy host). v0.7.0 caps the capture file caches and
  restores the scan pin layer on every live rebind instead of
  stacking it: 15-minute churn soaks stay flat at 368 MB peak
  (VmHWM) on the musl static observer and 322 MB on glibc.
  See [Observer memory grows under heavy process churn](docs/known-limitations.md#observer-memory-grows-under-heavy-process-churn);
  bounded memory is planned for 0.8.0.

### Known limitations

The v0.7.0 limits live in
[docs/known-limitations.md](docs/known-limitations.md#known-limitations-in-070).

- A manifest capture watching around four thousand endpoints or more
  can shed calls with exact counted causes while per-endpoint detail
  stays empty, and the run can exit nonzero. This is a known bug in
  v0.7.0, not a host problem; a fix is planned for 0.8.0. Narrow the
  scope (`--pid` or `--cgroup`) to avoid it.
- On a busy host, a multi-threaded program that exits during a
  `--system` capture may be counted as one lost library-load link
  (`task_uprobe_link_losses`); the count errs on the side of reporting
  a loss. Planned for a later release.
- Above about 6,000 key operations per second, per-key rows can
  arrive seconds late and part of a window shows as exact named
  counts instead of per-call rows. Exact per-call rows past 6,250/s
  wait for the event reader planned for 0.8.0.
- A one-shot tool's first use of a provider no running program holds
  is still missed under `--system`; later runs in the same capture are
  caught by kernel file-open learning. Wrap such tools in
  `sudo p11scope run --user $USER -- <tool>` (or pass `--prearm-module
  PATH`) when first-run coverage matters.
- Diagnostics on stderr can be lost silently in three cases:
  p11scope running as a different user than the owner of the terminal
  or pipe it writes to, an extremely low open-files limit (about 4)
  with stdout redirected and stderr a pipe, and a very slow stderr
  reader (some lines dropped without a count). Capture data and the
  report file are unaffected; fixes are planned for 0.8.0.
- On a busy host, a long `inventory --system --key-operations`
  capture can stop recording key operations partway through; the
  report stays PARTIAL with exact counts and no lost calls. Rerun
  the capture or narrow the scope (`--pid`); a fix is planned
  for 0.8.0.

### Qualification of this release

The full qualification facts live in the [verification
record](docs/releases/v0.7.0.md#verification-record). The
final-candidate gate:

| Check | Measured result |
| --- | --- |
| Final candidate (source `00147d894`) | `ci.yml` ([43462011892](https://github.com/mingulov/p11scope/actions/runs/43462011892)), `privileged-tests.yml` ([43462011701](https://github.com/mingulov/p11scope/actions/runs/43462011701)) and `bpf-kernels.yml` ([43462011694](https://github.com/mingulov/p11scope/actions/runs/43462011694)) green on the exact candidate source (privileged needed a second attempt for one guest cell after a runner KVM-permission setup failure); `package-preview.yml` ([43472492183](https://github.com/mingulov/p11scope/actions/runs/43472492183), capture_mode=both) green including install-test and attest; `container-publish.yml` ([43477455945](https://github.com/mingulov/p11scope/actions/runs/43477455945)) green. Result: QUALIFIED. |

## [0.6.0] - 2026-11-06

v0.6.0 answers "which application used which key, and how": inventory
captures gain opt-in live key operations with per-category counts, and a
counter capture can promote one endpoint to full detail while the rest
stays aggregate. It also runs on newer kernels, proves more provider
tables complete instead of calling them PARTIAL, and hardens large
system scans and short `run` captures.

Live capture still requires a Linux x86-64 host with usable
`uprobe_multi` load and self-link capability under the current
credentials, normally Linux 6.6+ or a working backport (the same gate as
v0.5.0). Help, version, inspect, discovery, saved report read/diff and
genuine `inventory --capture scan` remain usable without the live gate.
User-facing limits live in
[docs/known-limitations.md](docs/known-limitations.md#known-limitations-in-060).

### Added

- `p11scope inventory --key-operations` opts in to live per-key tracking
  (default off; needs `--capture auto` or `native`). No manifest is
  needed when the tables qualify by standard interface linkage, an
  observed live function-list return, or a scan-proved sole complete
  table; anything else needs a rerun with `--manifest`. Ordinary builds
  now carry the journal and
  the birth marker, so no special build is needed; `P11SCOPE_JOURNAL=0`
  or `P11SCOPE_BIRTH_MARKER=0` builds without them. When rows populate,
  the snapshot carries a summary such as `key operations: rev 1
  populated; 1 session, 3 objects; sign 1 completed, 0 returned errors,
  2 active operations`, and the JSON report carries the per-session,
  per-object and per-category rows under `object_observations`. Attaching to an
  already-running process works: rows cover operations that start after
  the attach, earlier operations are counted in named gaps, and a key
  first seen before the attach reads `type unknown (not established
  while observed)`, never dropped. Starting the observer first also
  works, and
  no restart is needed either way. Views never stop as a whole:
  operations the observer cannot attribute with certainty are counted
  in named `not attributed` reasons instead of ending tracking; see
  [known limitations](docs/known-limitations.md#known-limitations-in-060).
- `--select-endpoint <FUNCTION>` names one endpoint function (for example
  `C_Sign`) for full detail while a `profile` or `run` metrics capture
  with `--counter-mode` keeps counting everything else in the aggregate.
  Only `--pid` and owned-`run` scopes resolve; `--cgroup` and `--system`
  refuse by name. The name resolves once at start, the attempt is
  recorded in the report's additive `selected_detail` evidence object,
  and aggregate and detail counts are never summed.
- Repeatable `--exclude-module <path-or-name>` for `inspect`, `run`,
  `profile`, `trace` and `inventory` in every scope: the opposite of
  `--module`. Discovery stays automatic, except excluded files get no
  probes and use no slots. A full path excludes exactly that file by
  identity (a different file at the same path elsewhere is not
  excluded); a bare name excludes every file with that file name or ELF
  soname. Excluded files are listed as "excluded by you" (never
  silent), and the rest of the capture can still be `exact`. A
  `--prearm-module` or `--manifest` input that matches an exclusion is
  refused at startup (exit 2).
- Provider tables whose readable prefix is proven complete are reported
  with a full walk instead of PARTIAL. A 68-entry legacy table stamped
  PKCS#11 3.0-3.2 (such as SoftHSM 2.7, which reports 3.2) now reads
  complete on the discovery, manifest and inventory paths when every
  readable word checks out; when the proof fails, the report stays
  honestly PARTIAL. The `pkcs11-types`/`pkcs11-module` crates move from
  the pinned Git revision to the crates.io 0.2.3 release; the approved
  mechanism union grows from 463 to 465 entries (two proposed 3.3
  external-mu registrations).
- 7.3 support: live capture resolves the 7.3 exec-release hook (the
  `exec_mmap` exit) and the 7-argument `copy_vma` from host BTF, and the
  BPF kernel matrix loads every program on 7.3.1. A kernel whose hook
  shapes match none of the known prototypes refuses the hooks by name.
- Native inventory captures now report kernel event-ring loss. The
  report's `observation.semantic_capture.events_lost` holds the
  cumulative total, the `semantic calls:` stop line carries the same
  total as `lost`, and a `native capture events lost` gap names the
  loss. If the kernel's loss counter cannot be read, the report carries
  a `native capture events loss unknown` gap instead, and the count
  catches up on the next successful read.
- A same-address unload and reload between two scans is now disclosed
  instead of silent: the inventory report carries an additive
  `instance_reload_not_excluded` object with the module and instance
  references and the two counts. A finalize/initialize cycle inside one
  load still reads as one instance.
- A provider that loads while the capture stops is no longer dropped
  silently: the report names the newcomer in a gap, on both the live
  discovery path and `inventory --system`.
- With `--track-short-lived`, short-lived exits carry exit-time
  mapping verdicts: at exit the kernel reports the watched-provider
  slots it had recorded for the process, published as a
  `gap_exit_mappings` split beside `pid_descendant_gaps`. `mapped`
  means a slot named a watched provider file with no disqualifying
  refusal; everything else reads `unknown`. There is no "did not map"
  claim.
- Inventory pre-arm inputs are now pinned and reported: `prearm[]`
  carries one interval row per `--prearm-module` input with its watch
  state. A quiet pre-armed interval is a stated watch interval, not
  proven-exact coverage, except on an owned `run` that meets the proven
  bound.
- `p11scope run --user <name|uid>` (root only, like `strace -u`) starts
  the command as that account instead of the sudo invoker, with its
  supplementary groups from the account database (glibc may return only
  the primary group) and home environment (`HOME`/`USER`/`LOGNAME`/
  `SHELL` from its passwd entry, `XDG_RUNTIME_DIR` when
  `/run/user/<uid>` is provably its own (otherwise unset), `MAIL`
  dropped). Only `root` or `0` select uid 0; any other name or spelling
  resolving to uid 0 is refused as an unknown account. Without root,
  for an unknown account, when its group list cannot be resolved, or for
  a set-id observer it refuses with a plain message (exit 2) before
  anything starts; `-v` prints `running <cmd> as <user> (uid <uid>)`.
  The default is unchanged: under sudo the invoker, otherwise the
  observer itself.

### Changed

- An owned `run` child inherits the observer's environment unchanged
  (replacing the 0.5.x small allowlist), so the workload behaves as
  without p11scope. Only p11scope's own control inputs are withheld by
  name — the whole `SUDO_*` namespace and `P11SCOPE_*` — with one
  stderr line under -v naming them; apart from PATH, used to find CMD,
  values of inherited variables are never inspected or logged. Note sudo
  itself resets the environment first (pass application variables with
  `sudo --preserve-env=NAME` or as `env NAME=value ...` after the `--`),
  while anything exported in a root shell now reaches the unprivileged child.

- Terminal text is concise by default on every user-facing command
  (`inspect`, `inventory`, `profile`, `run`): the main results, one
  coverage status line, and a `run with -v for details` hint.
  `-v` / `--verbose` shows the full detail (every gap and reason,
  evidence, per-slot data, timing) plus informational stderr notes, and
  `--quiet` prints only the summary head. `--json` and `-o` are always
  complete. Default gap names are plain words; the machine names stay in
  JSON, and in `-v` beside the plain words. Informational stderr notes
  are suppressed by default; errors, actionable warnings, and the
  one-line readiness/outcome signals stay.
- Births under `--pid` are bound to the target's kernel start time, not
  the PID number, so a later process reusing the same PID gains no
  marker row or charge. Lifecycle records stay admitted by PID number by
  design; the consumer demotes stale ones.
- Startup checks the return-probe hazard with a small self-probe program
  instead of the full capture object, so the full object is verified
  once per start.
- Ring sizes grow where measured loss required it: the inventory
  lifecycle ring is 8 MiB, and captures with the key-operations lane
  load a 16 MiB event ring (12 MiB more locked kernel memory than the
  4 MiB default, about 1.9 s of 10,000 calls/s between reads). Costs are
  disclosed in the operator's guide.
- The forwarding layer (such as the p11-kit proxy) never crowds out
  real providers: it is admitted by what it publishes — only tables
  the application actually received attach, taking no heuristic
  slots. Calls it forwards are counted at the attached backend
  providers, named with counts on the gap line; calls the layer
  answered itself, including its errors, appear only on the separate
  forwarding line, and one layer call that reaches several providers
  counts at each. When nothing is published yet, a named gap says so
  and the capture continues; an operator-named layer keeps a
  reserve-capped prefix for the remote-client case. Under inventory,
  counter and broad admission a closure array that does not fit whole
  is refused whole with its demand stated. A real provider that still
  does not fit is admitted on the leading prefix that fits, with a
  named partial gap, and refused whole only when not even its
  strongest table fits.
- Inventory's endpoint budget rises to a 32768 default and a 131072
  maximum (`--max-endpoints`, 1–131072), so a host with several
  p11-kit copies (about 20K endpoints) is covered by
  `inventory --system` with no flag. The raise is measured on
  uprobe_multi hosts; Detailed's 512-slot budget and the counter
  modes' 8192 planner ceiling are unchanged.
- A discovery pass that cannot yet scan a caller (usually one with no
  observed call yet) now reports a `semantic admission deferred` note
  instead of a refusal: tracking starts at a later pass and waiting
  calls are counted. Calls past the 1,024-call waiting queue, or from
  callers never admitted, are still shed and reported as loss.

### Fixed

- `doctor` no longer spends minutes test-loading capture programs on
  kernels without uprobe_multi (for example Linux 6.1, where it took
  about 4 minutes). Live capture refuses there anyway, so those checks
  now read `skipped: this check loads capture programs, which need
  uprobe-multi` and the verdict stays capture unavailable.
- DONTUNMAP moves missed on kernels with the 6-argument copy_vma are now
  tracked (this affected 0.5.0 on 6.18.58 and current 6.6/6.12/7.2
  stable heads). The move hook read a fixed argument slot, so an
  `MREMAP_DONTUNMAP` move of a watched provider mapping went unnoticed;
  it now reads the returned mapping on every `copy_vma` shape.
- The Detailed capture object loads on Linux 7.4-rc1. Two intentional
  upstream verifier changes (new return-value checks and widened loop
  analysis) had refused it; the object is restructured without changing
  what it captures, which also cut verifier load substantially on 6.6
  through 7.3.
- Aimed captures admit first-come with no shared-scope reserve: `--pid`,
  or `--module` naming the providers to capture, admits in discovery
  order, while unaimed system/cgroup captures keep the reserve for late
  providers. Previously, under the old 8,192-endpoint ceiling, an aimed
  capture stalled at the 6,144 heuristic ceiling.
- `inspect --system --module` mirrors capture admission: an aimed
  inspection admits first-come (an over-budget provider admits its
  strongest prefix with the spill disclosed) instead of refusing whole
  modules at the shared reserve.
- Short `run` captures usually report full coverage now: the first stop
  sample waits until the child is seen stopped, and threads born after
  the pause are dated against the last provider-hook attach. OpenSC
  `--pause auto` runs report full coverage in quiet testing (50/50 on
  Fedora); occasional partials under heavy load stay disclosed.
- On busy hosts, skipped mapping hooks no longer stop counting for good:
  each skip raises a new fault era, calls across the skip are shed with
  counts and a named cause, and key operations the observer cannot
  attribute with certainty are counted in named `not attributed`
  reasons while exact rows continue for the rest.
- An owned `run` child that exits in the window no longer always voids
  the selected-endpoint detail: exits the observer can tie to the ended
  process count as exit-only and the detail renders the calls made
  before the exit. A short child that loads and exits at once can still
  void intermittently (about 1 in 10 runs locally); see known
  limitations.
- A refused attach slot no longer risks its neighbors: the slot is
  quarantined with its detach reason while unrelated slots keep
  admitting.
- An oversized mechanism approval union publishes its official-first
  subset and counts the rest, instead of refusing the capture.
- One bad `--manifest` object or `--prearm-module` path gaps only
  itself with a named reason; the capture keeps its good inputs and
  reads `PARTIAL` instead of aborting.
- A live discovery-ring failure keeps the prefix already pulled and
  gaps the rest, instead of dropping the tick.
- A stale rebuild the new scan cannot cover gaps with a named reason
  instead of aborting.
- `run --pause always` collects unpaused with a named gap when the arm
  fails, instead of failing the run.
- `sudo p11scope run -- tool` starts `tool` as the invoking user with
  the invoker's supplementary groups and home environment, as if the
  user had run it directly: groups come from the account database
  (glibc may return only the primary group; HSM and device-group
  providers keep working), `HOME`/`USER`/`LOGNAME`/`SHELL` from the
  invoker's passwd entry, and `XDG_RUNTIME_DIR` from `/run/user/<uid>`
  when that directory exists and is owned by the invoker (otherwise
  unset). The child keeps `no_new_privs` with clear capabilities. New
  `-v`/`--verbose` flag for `run` prints the restored identity as
  `running <cmd> as <user> (uid <uid>) (groups and home restored)`;
  without it `run` stays quiet about the identity. An account the
  observer cannot resolve refuses with a plain message before anything
  starts (DR-56).

### Known limitations

The v0.6.0 limits live in
[docs/known-limitations.md](docs/known-limitations.md#known-limitations-in-060).
Known issues in this release. Rate, latency and start-up figures below
were measured on the integration lane (see Qualification for the source
SHA behind each check the release rounds re-measured):

- Key operations sustain 6,250 calls/s for 60 s with exact rows; plain
  counts stay exact at 10,000 calls/s. 10,000 calls/s sustained for key
  operations is planned for 0.7.0.
- Key-operation rows lag their calls: p99 about 1.6-1.9 s against the
  1.5 s target.
- Key-operation tracking may not start in about 1 in 4 runs; plain
  counts are unaffected and a named gap says so.
- On busy hosts, skipped kernel mapping hooks shed counted calls and
  count unattributable key operations in named `not attributed`
  reasons.
- A foreign call still in flight at the seal is counted in named `not
  attributed` reasons; exact per-key rows continue for operations the
  observer can attribute with certainty.
- Past 16,448 refused processes, new untracked callers keep the plain
  per-call view with a named reason (about 14 hours at one new
  foreign client every 3 s).
- About 0.5% of `run` captures on overloaded hosts miss startup
  entirely and report incomplete with a named cause; never a wrong
  count.
- A child process can use a provider before it is watched; affected
  runs are marked incomplete.
- Container providers carry named unproven cases (multi-node clusters,
  CRI-O and the cgroupfs driver are not exercised).
- The overlay-identity witness proves up to 8 refused callers per scan
  and per pass; past the budget, callers take turns across passes
  while the rest keep the named `original_file_unproven` loss.
- Strict speed claims apply only on 6.6+ kernels with uprobe_multi;
  older kernels stay correct and finite, not fast.
- Per-key rows cover operations that start after the attach; earlier
  operations are counted in named gaps, and a key first seen before
  the attach reads `type unknown (not established while observed)`.
  No restart is needed: attaching to an already-running application
  and starting the observer first both work.
- Counts through the p11-kit proxy can include the backend's own
  internal calls and miss calls made before the attach; direct
  providers are exact.
- The key-operations reason can latch `authority_lost` ("per-key
  tracking stopped") while exact rows continue; read the rows and
  the `not attributed` counts.
- `inventory --pid` misses a short-lived caller's use; its calls
  fold to the module as unattributed use. Use `profile --pid` for
  one-shot flows.
- `run` (and `profile --pid`) observe exactly the started command,
  never its descendants. Capture multi-process workloads with
  `inventory --system` (or `--cgroup`).

### Qualification of this release

The following scoped checks qualify the release candidate. Each row
names the source SHA it was measured on; SHAs differ because each
round measured on its own tip. The last row is the final-candidate gate:

| Check | Measured result |
| --- | --- |
| Privileged library campaign and quiet pressure set on Fedora 7.2.9 (source `762b289d7`, RC round 2) | Campaign 211/214: the 3 reds pin text RC2 intentionally changed (concise renderer), capture healthy in all three; pressure 5/5 under quiet exclusive; earlier reds closed except the `inventory --pid` one-shot shape, which stays a known issue (see Known limitations). |
| Strict browser cells and demo rehearsal on Fedora 7.2.9 (source `762b289d7`) | 48/48 strict browser cells; demo 4/4 in both orders (Firefox and Chromium) at the exact 60 s task command; an earlier rehearsal miss root-caused to the rehearsal script on `40808c51e` (script fix, no product change). |
| SoftHSM and Kryoptic sign flows on Fedora 7.2.9 (source `762b289d7`) | `run` and `profile --pid` PASS on both providers; the `inventory --pid` one-shot shape is a known issue (see Known limitations). |
| Guest kernel matrix CLI and inventory on 6.6.157, 6.12.111, 6.18.58, 7.0.14 and 7.3.1 (sources `762b289d7`, `324ac067f`) | CLI 23 pass, 0 fail, 1 nonqualifying, 5 expected-fail on every kernel with byte-identical summaries; inventory overlay+cap FAIL systematic on `762b289d7` (predates the overlay-witness fix), PASS on all 5 kernels on `324ac067f` (RC round 3). |
| Local release gates (sources `e2fd74b67`, `762b289d7`, `08906062e`, RC rounds 1-3) | fmt, check and clippy green; main library suite 7988/8129/8213 passed with 0 failed; `artifact_contracts` 202/202/202; Python suites 122/122; privileged no-route collect cell PASS. |
| Hosted CI on the round tips | `ci`, `privileged-tests` and `bpf-kernels` runs queued per round and not awaited there (round 3: 42235605621, 42235605493, 42235605637 on `08906062e`); round-2 CI on `762b289d7` failed all three workflows in areas the rounds never touched, triaged in the CI lane. The binding CI record is the final-candidate gate below. |
| Final candidate (source `a29f3c7fa`, RC round 6) | `ci.yml` ([42378274697](https://github.com/mingulov/p11scope/actions/runs/42378274697)), `privileged-tests.yml` ([42378274819](https://github.com/mingulov/p11scope/actions/runs/42378274819)) and `bpf-kernels.yml` ([42378274784](https://github.com/mingulov/p11scope/actions/runs/42378274784)) green on the exact candidate source; `package-preview.yml` ([42382646860](https://github.com/mingulov/p11scope/actions/runs/42382646860), capture_mode=both) green including install-test and attest. Result: QUALIFIED. |

The full privacy matrix and extracted-package recipient checks are separate
release gates. The limitation disclosures above also apply to successful
captures.

## [0.5.0]

Live capture requires a Linux x86-64 host with usable `uprobe_multi` load and
self-link capability under the current credentials, normally Linux 6.6+ or a
working backport. Capability is tested, never admitted by version. Missing
capability refuses with `uprobe-multi-required` before capture, output changes
or a user workload starts, including explicit `--attach-backend singles`.
Safe scoped Singles remains available on eligible hosts; PID Multi additionally
requires a proven kernel PID filter. Help, version, inspect, discovery, saved
report read/diff and genuine `inventory --capture scan` remain usable without
the live gate. Non-Multi live support may be reconsidered around 0.9.x; no
release commitment is made.

v0.5.0: official release builds read object attributes by default (FULL),
with the P0 build staying an explicit option. Text inventory snapshots
carry a `key operations:` summary line, over-budget inventory plans name
`--max-endpoints`, `--counter-mode` selections aggregate in the kernel
on eligible LP64 hosts. Discovery handles kernel threads and can retain a
single surviving thread's process view after an already-observed leader exits.
Groups first met after leader exit remain unadmitted.
User-facing limits live in
[docs/known-limitations.md](docs/known-limitations.md).

The older startup/refusal numbers retained in this entry are historical
measurements from before the host policy above, not current old-host support
or a product startup SLA.

### Scale and --system

- An inventory plan that exceeds the endpoint budget below 8,192 now names
  the fix: the refusal ends with `raise --max-endpoints (up to 8192)`.
  At the 8,192 maximum the hint is omitted.
- System scans treat kernel threads as verified absence: a thread with no
  memory mappings and the kernel-thread flag is recorded as having no
  providers instead of an error.

### Inventory output

- Text snapshots carry a `key operations:` summary line. This version
  never reports key operations, so it always reads `key operations:
  not reported by this version (planned for 0.6.0)`; per-category
  completed/failed/active counts are planned for 0.6.0. JSON reports
  `object_observations.status: "unavailable"` with reason
  `journal_unavailable` and empty object/key-operation rows.
- A combined key label is withheld when the class and key type are
  incompatible, instead of printing a misleading label.
- Edwards and Montgomery key types are recognized at their standard
  numbers in FULL object reads.

### Identity and containers

- Discovery can use a retained single live survivor after an already-observed
  leader exits, and confirms member-carrying reads through that member's
  executable. Groups first met after leader exit and groups with multiple live
  survivors remain unadmitted in live capture.
- The example Kubernetes DaemonSet raises the observer memory limit to
  768Mi.
- Knative qualification requires exact warm counts (1,200/1,200 observed).
  The first cold request observed 84/1,200 before probes attached, with no
  kernel event loss; this remains a disclosed coverage limitation.

### Privacy and capture

- The FULL object-attribute read set is approved in
  [allowlist-v3](docs/privacy/allowlist-v3.md): class, key type, token
  flag, value length, RSA modulus bits and finite EC parameters, with
  the result rules, retention table and publication section. Nothing
  else in v3 grants capture.
- `--counter-mode counts|timestamps|latency` selects kernel-aggregated
  capture for `profile`/`run` with `--mode metrics` on eligible LP64 hosts,
  subject to independent verifier, feature and memory limits. A refused
  start exits nonzero without a report or starting the requested workload.
- Startup readiness bounds are disclosed harness parameters, never a
  product cold-start SLA; see [known limitations](docs/known-limitations.md).

### Packaging

- Official release builds are FULL by default (object-attribute capture
  on); `--capture-mode p0` selects the P0 variant for the
  verifier-budget lane.
- Release packages record the capture mode and feature set in
  `RELEASE.json`.
- Update current host builds to Rust 1.99.1. Preserve the pinned BPF nightly,
  linker and historical 1.98.1 baseline; CI selects the host transition
  explicitly and gives each source/configuration its own build target.
- Bind compiler notices to the selected release and refresh verified Rust,
  LLVM runtime and helper-image inputs. Image/package metadata checks do not
  replace the separate installed and packaging qualification.

### Fixed

- Return-probe attachment requires the functional kernel safety assessment
  even when the process leader has no seccomp filter. Shared Detailed capture
  paths enforce the same check, covering filtered siblings and filters
  installed after attachment.
- An ordinary native-retirement refusal during a `--manifest` capture writes
  the incomplete report and returns nonzero on the first stop. Original
  ownership remains quarantined and replacement admission remains blocked.
- Provider discovery retains usable function entries independently of version
  labels, including 68-entry legacy tables labelled 3.2, sparse tables and
  acquired all-NULL tables. Unavailable words and unusable targets remain
  explicit; they no longer erase other usable entries. Partial manifests
  preserve their observed ordinals and useful targets without claiming a
  complete table or stronger semantic authority.
- `inspect` and discovery refuse corrupt ELF segments and validate mmap
  segment ranges instead of misreading them.

### Known limitations

The v0.5.0 limits live in
[docs/known-limitations.md](docs/known-limitations.md#known-limitations-v050).
Known issues in this release:

- Strict scale and speed limits apply to captures actually using Multi.
  Safe scoped Singles on an eligible host stays correct, finite and disclosed.
- Historical startup measurements remain historical; declared readiness
  bounds are harness parameters, not a product cold-start SLA.
- Counter modes need an eligible LP64 host and independent load/feature/memory
  checks. Stock pre-Multi hosts refuse early with `uprobe-multi-required`;
  no user workload starts.
- Per-call profile/trace capture stays fixed at 512 attach slots
  (2,112 only in the WIDE source build); counter banks share one
  65,536-entry return-value pool.
- A capture follows at most 256 provider loads and tracks at most
  16,384 program images; past either limit the report carries a named
  gap. Stopping a very large capture can refuse its fixed graph pool
  and end as a finite incomplete stop.
- Processes already running when the capture attached lose their
  first burst of calls; tools that exit before their first binding
  cannot join.
- A same-address unload and reload between two scans shows one
  instance, as does a finalize/initialize cycle inside one load.
- In containers, a process that loaded a provider before a copy-up is
  attributed to the copied-up file and its later calls are missed;
  restart such processes.
- A provider first loaded mid-capture can lose the calls made before
  its watch begins; the JSON states the unwatched window.
- A `profile` or `trace` output has no per-run marker for calls made
  before a provider's probes landed; inside a nested PID namespace
  attach can take up to about 7 s.
- A timed run shorter than the first full pass reports 0 callers with a
  `no complete collection pass` gap.
- Short-lived processes missed at system scale are counted only as
  gaps; their calls through attached providers still count.
- This version reports no key operations (planned for 0.6.0);
  mechanisms and API results are reported as before.
- A process whose main thread had already exited when first met is not
  admitted, and its calls are not counted.
- Loader inspection still pending when process custody ends can remain
  unavailable and produce a `discovery_truncated` gap; call counts are independent.
- A post-exec instance whose semantics cannot be proven appears as a
  named gap, not a joined instance.
- Historical 5.15 per-copy attribution and non-leader exec results remain
  unqualified; stock 5.15 is outside current live support and refuses with
  `uprobe-multi-required`.
- A load, one call, unload burst inside about 1 ms reads the same as
  no calls unless the child is held with `run --pause auto` or kept
  alive past attach.
- System identity checks through the userspace backend have a measured btrfs
  regression. The comparison on Fedora Linux 7.2.9 used GNU builds at
  `b58ef1b5`, compiled with Rust 1.99.1, and 400 processes × 8 mock providers
  over 10 matched rounds with
  equal coverage. Confirm-stage p95 rose from 66.600 to 84.055 ms (+26.21%);
  whole-pass p95 rose from 255.444 to 288.012 ms (+12.75%). These are scoped
  measurements, not bounds for every host. The default `auto` backend uses
  kernel identity where available; further speed work is planned for 0.5.x.
- In long system-wide runs, a live publication that stops making
  progress is abandoned after 6 seconds with a named gap; the capture
  keeps running and coverage reads partial.
- On some overlayfs setups before Linux 6.8, a provider whose /proc
  maps rendering cannot be proven carries an explicit unproven-maps
  note, and callers mapping it may stay unbound.
- The final 1,800-second SYSTEM+manifest soak passed on Fedora Linux 7.2.9
  with a 1,860-second observation window, exact physical call counts and a
  proven final drain. Semantic sheds and named-budget refusals remain disclosed
  in [known limitations](docs/known-limitations.md). The earlier failed run
  remains historical; 4 h and 24 h runs remain unqualified.

### Qualification of this release

The following scoped checks passed during release preparation:

| Environment | Checked behavior |
| --- | --- |
| Linux 6.6.157, 6.12.111 and 6.18.58 guests | 75 BPF roots per kernel: object loading and the declared verifier budgets. |
| Linux 7.0.0-38-generic | Four IA32 object canaries: FULL and P0 completion and blocked START, with exact counts, privacy checks and owned cleanup. |
| Fedora Linux 7.2.9 | Filtered-sibling and late-filter return-probe safety, short and 1,800-second SYSTEM+manifest soaks. |
| Ubuntu 26.04 GitHub-hosted runner | PID/system × metrics/profile capture: 20,000 exact calls per cell, zero event loss and proven final drain. |

Complete host CI, coverage, the full privacy matrix and extracted-package
recipient checks are separate release gates. The limitation disclosures above
also apply to successful captures.

## [0.4.0] - 2026-10-21

v0.4.0: `inventory --cgroup` scope, offline `inventory
diff` comparison, inventory diagnostics, executable naming for trace and
inspect output, opt-in caller cgroup metadata, explicit endpoint and
identity-proof controls, and hardened final-output semantics. The
object-attribute capture is not enabled in v0.4.0: the release bytes
build with the attribute gate shut (P0-only), so no BPF program reads
object attributes. Every profile, metrics and trace document discloses
this as structured evidence (`evidence.object_capture.available: false`,
`reason: "not_enabled"`), and `p11scope doctor` names it in its
`object-attribute capture` row. Counts, mechanisms and all other P0 facts
are exact; only attribute semantics are withheld. FULL capture stays the
default for diet/qualification work and returns when it fits the verifier
budget (policy: [docs/privacy/allowlist-v3.md](docs/privacy/allowlist-v3.md)).
Limits below live in [docs/known-limitations.md](docs/known-limitations.md).

### Added

- `p11scope inventory --cgroup <path>` observes a cgroup subtree, including
  descendants, across scan/auto/native and the existing output modes.
  Discovery retains the selected root, requires initial PID numbering with
  matching procfs, and reports bounded partial work as explicit gaps. Quiet
  cgroup usage stays `unknown`: endpoint membership samples do not prove
  continuous residency and cannot authorize `watched_no_use`. Scoped native
  owner admission stays deferred, and public live cgroup qualification
  remains a development gate. See
  [docs/schema/inventory-v1.md](docs/schema/inventory-v1.md#cgroup-scope).
- `p11scope inventory diff before.json after.json` compares two saved
  inventory v1 snapshots as an ordinary user: no live process lookup, no
  provider load, no capture privileges. Readable text groups observations
  by recorded application path and module content; `--json` emits one
  `p11scope/inventory-diff/v1` document and `-o` saves it atomically.
  Counts stay separate per-window lower bounds (no deltas are inferred),
  and absence never proves removal. See
  [docs/schema/inventory-diff-v1.md](docs/schema/inventory-diff-v1.md) and
  [docs/usage.md](docs/usage.md#offline-inventory-comparison).
- `inventory --diagnostics <f.jsonl>` with optional `--diagnostics-pid <n>`
  records a separate JSONL file explaining native count reads, ownership
  changes, allocations and withheld growth (`--capture native` or `auto`;
  explicit `scan` is refused). Two rolling buffers retain recent history
  under fixed budgets; the footer reports spans, eviction, filtering and
  settlement independently. Delivery is atomic and private (0600),
  independent of the other final sinks. See
  [docs/schema/inventory-diagnostics-v1.md](docs/schema/inventory-diagnostics-v1.md).
- Trace rows carry an executable label when p11scope can establish which
  process image made the call, else `Unknown executable` with the retained
  PID/TID; previously printed rows are never renamed later. Cgroup traces
  need calls on both sides of a validated sample, and installed cgroup
  naming checks are still in progress. See the [trace privacy
  contract](docs/privacy/allowlist-v3.md#trace-executable-labels-p5u-2026-10-09).
- `inspect --pid --json` gains additive `application`/`application_status`
  fields naming the observed executable (path, device, inode, mtime, start
  time) or a finite reason when naming is withheld; text output shows the
  same detail. Consumers that ignore unknown fields stay compatible. See
  [docs/schema/inspect-v1.md](docs/schema/inspect-v1.md).
- `inventory --caller-metadata=cgroup` opts in to finite sampled caller
  context from the original retained process's cgroup membership
  (canonical container IDs and pod UIDs as lexical hints, never proof of
  orchestrator ownership). The default `none` opens no metadata files, and
  a genuine native caller-use binding is required. Installed
  multi-container/pod qualification remains open. See the [DR04
  contract](docs/privacy/allowlist-v3.md#dr04-caller-metadata-2026-10-18).
- `inventory --max-endpoints <n>` (1..=8192; 4096 when absent) selects the
  capture-lifetime physical endpoint budget, reported in
  `budgets.inventory_endpoints`; IDs are append-only and unloading a
  provider never refunds capacity. The 8192 upper bound is a candidate
  policy limit, not a measured release envelope.
- `inventory --system --identity-backend auto|userspace|kernel` selects the
  system-sweep identity proof backend, disclosed in
  `observation.identity`. Explicit `kernel` validates numbering, BTF,
  strict load and a functional probe before capture starts, or refuses
  with a named reason before any capture output is created. An explicit
  value under `--pid` or `--cgroup` is a usage error.
- Repeatable `inventory --manifest <m.json>` retains explicit operator
  inputs to prepare a separate attested Detailed subset under `--capture
  auto` or `native` (`scan` plus a manifest is an argument error before
  output files open). The inventory document and event stream carry the
  additive instance projection (`instances[]`, `semantic_edges[]`,
  `observation.semantic_capture`, `instance_observed` and
  `semantic_edge_observed`); preparation alone does not activate positive
  instance delivery.
- The metrics lane now carries `attach_backend` like the profile lane
  (selection disclosure only; metrics gains no selection verdict
  authority), and static probe detach/reattach history is published
  through `skipped` records with two fixed reasons. `edge_observed`
  gains additive `identity_context`.
- The dashboard scrolls with `j`/`k` and cycles summary/evidence/gaps
  with `tab`. At small sizes a compact summary keeps one
  executable/module pair visible; below the useful compact size the view
  asks for a larger terminal.

### Changed

- Inventory text snapshots lead with an application/module overview:
  detailed retained paths, identities, states and coverage follow. The
  application label is the observed executable's basename (an interpreter
  stays `python3`, `java`, ...); missing names read `Unknown executable`
  or `Unknown module`; retired images say `Application executed a new
  image` and exited callers say `Process exited`.
- Final outputs are attempted independently. After `started`, a returned
  event-log error retires that writer while observation continues to its
  ordinary stop; the atomic `-o` commit and stdout are still attempted,
  any returned sink error gives exit 1 with sink-specific diagnostics,
  and `ended` is never fabricated or retried. On pipes, FIFOs and
  terminals, five seconds without a positive write fails stdout with
  exit 1; a later delivered stop signal cancels final output while the
  signal already used to stop capture permits healthy output. The native
  stop line now reads `p11scope: output attempts finished; ...`.
- Stderr diagnostics run through a bounded sink: a stopped or closed
  stderr sheds them instead of stalling capture, and delivery never
  determines the exit status.
- `p11scope-discover` prints expanded usage guidance and a `Manifest
  written ...` stderr line naming the explicit `--manifest` attestation
  the result still needs.

### Fixed

- A returned event-log error no longer loses the `-o` report (C5.4 I-4):
  the writer retires, the independent report and stdout are attempted,
  and each failed sink is identified. A readable `ended` alone still does
  not confirm successful sync.
- A run stopped with zero completed passes records a `no complete
  collection pass` scope gap plus one informational stderr line instead
  of exiting 0 with 0 passes, 0 callers and 0 gaps; exit 0, output
  schemas and gap accounting are preserved.

### Security

- `inventory --cgroup` refuses with `pid-namespace-mismatch` when the
  observer's PID namespace or `/proc` does not match, extending the
  fail-closed PID-namespace handling to the new scope; the refusal
  precedes report, event and diagnostic output creation.

## [0.3.0] - 2026-10-08

Per-edge entry counts end to end (DR-02 closed): the native inventory lane
publishes saturating lower-bound entry counts with first/last-seen
timestamps across the JSON document, the event stream, and the dashboard;
load-instance continuity with sharded discovery; a 2 MiB lifecycle ring
with fill telemetry; and the stale-quiet label fix.

### Added

- E16 execution-surface qualification checks that discovery finds, or
  explicitly refuses, PKCS#11 code in six shapes. A control provider and a
  synthetic client-side HSM proxy (socketpair only, no remote HSM) are
  admitted with exact endpoint counts. A table linked statically into an
  executable, and one reached only through `Vendor_GetFunctionList`, are
  admitted under `--module` as 104 identity-pinned count-only endpoints.
  Exports without a table get an explicit no-table record. Anonymous JIT
  code is never admitted. Unhinted `--system` skips the static,
  vendor-only and direct-export shapes without a record. E16 measures this
  as a coverage gap rather than claiming coverage. The new parts:
  - fixtures under `tests/fixtures/e16/` that share one hold protocol;
  - `tests/e16_execution_surfaces.rs`;
  - `scripts/qualify-e16-surfaces.py`, a provenance-bound privileged
    runner built on the receipt seams, whose `--self-test` runs in CI;
  - `tests/python/test_e16_oracle.py`, with a regression for each of the
    eight archived-runner defects.

  On the host, the hinted campaign passes all six surfaces. The
  system-mixed campaign stops at UNKNOWN because the 512-slot attach
  ceiling refused one surface. No product code changed. See
  [docs/qualification/e16-execution-surfaces.md](docs/qualification/e16-execution-surfaces.md).

- The native inventory lane publishes per-edge entry counts: an edge whose
  CALLER_USE row binds to an admitted caller incarnation reads `counted`
  with a saturating lower-bound `count` of entries since the pair's first
  record (including calls that returned errors), `since_ns` at that first
  record, and `last_seen_ns` at pass resolution — in the JSON document, the
  `edge_observed` event stream, and the dashboard/pager alike. A pair
  insert failure (the CALLER_USE map was full) reads `unknown` with the new
  reason `uncounted`, never 0, naming the `PairInsertFailure` evidence; no
  watch starts again in that capture. `edge_observed` also emits count
  changes at most once per edge per 10 s with the latest count; class
  changes still go out at once and the final sweep stays exact. See
  [docs/schema/inventory-v1.md](docs/schema/inventory-v1.md) and
  [docs/privacy/allowlist-v3.md](docs/privacy/allowlist-v3.md).

- The native inventory oracle checks per-edge counts against the workload
  ledger: P1/P2 edges read `counted` (even the unattested copy) with the
  exact attach-side count when the feed covers every in-window call, and
  must-fail fixtures cover above-ledger, published-0, absent-as-0 and
  pre-admission-counted outputs. DR-02 is closed by the M2 cost gate
  (counting overhead immaterial on every cell over 250 ABBA samples; 0
  count errors over 80 on-arm samples). See
  [docs/known-limitations.md](docs/known-limitations.md).

### Changed

- A process is a caller of a provider only through an executable mapping
  of it (owner ruling, C7 A6). Past the deep-scan cap, `inventory --system`
  now proves and counts only the executable (`x`) ranges of a provider in
  another process's `/proc/<pid>/maps`; ranges without `x` are neither
  proven nor counted. A process that maps a provider file only without `x`
  (a scanner `mmap`-ing it read-only) is no longer attributed as a caller,
  and is not an attribution loss or a coverage gap. A maps-key collision
  (btrfs subvolumes) on a data range no longer costs an edge whose
  executable range is proven to be the held file. Deep scans already
  required an executable mapping, so both paths now apply one rule. No edge
  is reported without a passed like-for-like proof, as before, and the
  schema is unchanged. Proof reads drop to about one per mapped library;
  the pass-time effect is not measured yet. See
  [docs/known-limitations.md](docs/known-limitations.md).
- The Inventory objects' lifecycle ring is 2 MiB (about 2,260 records),
  up from 64 KiB: at 1,000 exec/s with 448 processes the M4 cell reads
  zero ring loss, zero demoted edges and zero recovery rescans. The
  Detailed path keeps its 64 KiB compiled ring. Each Inventory drain
  records its producer-minus-consumer high-water fill, printed on the
  `P11SCOPE_STAGE_TIMINGS=1` pass lines and the stop line as bytes and
  ring share; the schema is unchanged (no new `observation.lifecycle`
  key). See [docs/known-limitations.md](docs/known-limitations.md).
- Past the deep-scan cap, `inventory --system` runs the phase-1 maps
  sweep and the confirmation reads on up to 4 threads (the observer's
  usable CPUs), each over a contiguous range of at least 256 processes. The
  reads of each thread are replayed in pid order against the capture
  budget, so attribution, losses, gaps and budget ceilings are exactly
  the serial ones; only wall time changes. The proof-stat pool now runs
  only on the serial path. Interleaved serial and sharded runs on one
  host at 4,096 processes cut the pass p95 from about 1.06–1.09 s to
  about 0.61 s on 4 CPUs and from about 1.06 s to about 0.75 s on 2 CPUs
  (one core with SMT), with identical output; these numbers are
  indicative.
  The phase-1 maps sweep of `--cgroup` and `--system` capture discovery
  past `--max-scan-pids` is sharded the same way.
  `P11SCOPE_SHARD_THREADS=1` (diagnostic) forces the serial path. See
  [docs/known-limitations.md](docs/known-limitations.md).

### Fixed

- Live inventory reads no longer show a stale `quiet` while a first use
  waits for its decision (DR-LIVE-LABEL-LAG). While the binder holds a
  read-but-undecided witness row of a watched caller's pid on the edge's
  module, the edge reads `unknown`/`pending_first_use`
  (`capture coverage lost | activity unknown | entries ?`) on the
  dashboard and in mid-run `edge_observed` records, and the watch's
  proven-clean instant is not extended over the row. Once the row binds
  the edge reads `witnessed` (or the unbound reason when it does not);
  the `-o` snapshot and the final sweep are unchanged and exact. The
  native oracle now compares every dashboard frame with the edge state
  at that frame's pass from the event stream. See
  [docs/known-limitations.md](docs/known-limitations.md).

## [0.2.0] - 2026-10-05

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

- `--system` identity proofs: the proof-stat pool (the bounded `map_files`
  proof workers) engages only for a batch of 128 or more ranges. Typical
  per-process batches are 30–45 ranges, so by default a pass runs the
  serial path, which measured faster: a quiet-window A/B at 4,096
  processes against the qualified cut (pool from 8 ranges) saved about
  230 ms per pass at 2 CPUs (1,797 ms vs 1,568 ms pass p95) and about
  625 ms at 4 CPUs (2,220 ms vs 1,595 ms), nearly all in the confirm
  stage. Results are identical by construction; only wall time changes.
  Indicative single-host numbers (2 physical cores with SMT, Linux 7.0,
  btrfs).
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

- `inventory -o <out.json>` buffers the JSON write: a 4,096-process run
  issued about 557,000 `write` calls for the output file and now about
  2,100, and the pause before exit dropped from about 3.5 s to about
  0.1 s on that host. The document is unchanged.
- `p11scope-discover` re-reads its own `/proc/self/maps` (up to 4 times)
  when another thread's `mmap` tore the snapshot, instead of refusing
  with "unsorted or overlapping"; a provider that starts mapping threads
  during discovery no longer fails it. A parse error is never retried.
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
  the release licence notices move to `rust:1.98.1`.
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
1.98.1). The qualified binaries were built from `f824046`; the release
candidate differs from that tree only in the classic `--pid` attach path,
`--event-log` hardening, the `--duration` bound, a doctor refusal-string
wording correction, the 128-range proof-stat pool threshold, the
buffered `-o` write, the retried `p11scope-discover` self-maps read,
CI and test-fixture fixes, and the 0.2.0 version. The classic `--pid`
path was separately vng-qualified 9/9 on all 4 kernels.

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
scripts/qualify-release-matrix.sh --rev <RC> --bin-dir ~/.cache/p11scope-vng/rc-qualify-bins-<RC>
```

The short measurement tier: M0 PASS (29 of 29 units valid, and 43 of 43
in the re-measure); M1 pass p95 on this release's code ~0.30 s at 448
processes and ~1.61 s (native) / ~1.70 s (scan) at 4,096, over the 1 s
target at 4,096; M4 lossless at 100 exec/s and ~100 ring records/min
lost at 1,000 exec/s (448 processes, native lane); proof-stat pool A/B
as under Changed. See
[docs/known-limitations.md](docs/known-limitations.md) for the numbers
and method. Explicitly out of scope for v0.2.0: a long soak and a v0.1.0
comparison (see [docs/known-limitations.md](docs/known-limitations.md)).

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
