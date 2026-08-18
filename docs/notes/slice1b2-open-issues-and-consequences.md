# Slice 1b-2 open issues, consequences, and next evidence

Date: 2026-08-18

This is a living engineering note for the live-discovery and `run -- command`
slice. It separates a completed negative result from an incomplete run and
keeps spike evidence distinct from production support.

## Current status (supersedes older status wording below)

The superseding corrective design is complete and independently approved at
commit `fd3a0e1cdeaaf9e134d827af90d9af4252675969` in the isolated development
worktree. The final review found 0 Critical, 0 Important, and 0 Minor design
defects. This is design approval, not product support.

| Work item | Current result | Consequence |
| --- | --- | --- |
| Gate A: four discovery programs | `TIMEOUT / INCOMPLETE` on both 5.15 and 6.8; exactly 3/4 accepted records | The existing fourth-program shape is not promotable. The approved constant-offset initializer and final unchanged A/B object still must be implemented and rerun. |
| Gate B: pause/attach timing | Historical Jammy variance; Noble passed; a later Jammy run also passed | The old sample loop did not actually wait for its stated 100 ms bound. The corrected 100 ms aggregate oracle is designed but UNRUN, so pause remains default `never` and unprotected capture remains `PARTIAL`. |
| Gate C: loader/glibc timing | Direct current-build controls complete; corrected product-shaped campaign UNRUN | Exact fixed-glibc, negative glibc 2.35/2.39, musl, DT_NEEDED, and `dlopen` controls must run before any loader capability is promoted. |
| Slice 1b-1 semantic authority | Owner-approved; TDD implementation in progress | An accepted explicit manifest attests only its exact pinned object + offset + canonical name. Scan-only claims remain count-only/PARTIAL. Final implementation review and gates are still pending. |

No kernel bisection is currently required. The next work is implementation of
the approved finite gates, followed by the same frozen artifacts on the two
required kernels.

## What works with and without a manifest

A p11scope manifest is a versioned JSON description of a provider that records
the provider objects, validated identities, PKCS#11 function-table surfaces,
canonical function names, and ELF file offsets. `p11scope-discover` can create
one offline by loading the provider in the helper process. At capture time,
p11scope opens and hash-pins the described files; it does not trust a pathname
or a digest alone.

The manifest is optional:

| Capture situation | What works | Limitation |
| --- | --- | --- |
| No manifest; provider already mapped when capture attaches | The memory scan can find provider-shaped tables and attach by exact pinned object/file offset. Calls, CK_RV values, errors, and latency remain observable. | Scan-derived names are heuristic, so they are count-only, semantic interpretation is disabled, and output is `PARTIAL`. |
| Accepted explicit manifest | Exact accepted object + offset + canonical-name claims may use normal semantic descriptors. | It describes known provider bytes; it does not prove that a provider loaded later was observed. Stale, conflicting, incomparable, or uncovered claims fail closed or remain `PARTIAL`. |
| Docker or Kubernetes target whose provider is already mapped | The same process/cgroup scan works when `/proc` visibility, namespace identity, and BPF/uprobe permissions permit it. Shared overlay inodes can be attached once for multiple containers/pods. | Node/cgroup scope and overlay identity uncertainty are reported. Cluster-wide deployment is not yet shipped. |
| Provider inode first becomes known through `dlopen` after attach | Not detected by the current one-shot Slice 1b-1 scan. | Slice 1b-2 loader/export hooks and dynamic slot attachment are required. A manifest cannot retroactively make the missed interval complete. |

Therefore p11scope can run without a manifest today, including against
permitted container processes, but it cannot yet promise that every provider
loaded dynamically after attachment is detected. The upstream glibc change
discussed below can improve one future hook on qualified builds; it does not
remove the need for the live-discovery engine or its completeness evidence.

There is one important existing-inode case: an uprobe already attached to a
provider inode can observe that same inode when another in-scope process or pod
maps it later, such as a shared container image layer. Slice 1b-2 is needed
when the provider inode/table itself was unknown and unattached at capture
startup.

## What `TIMEOUT / INCOMPLETE` means

The Gate A runner had to load four discovery programs and then write exactly
one verifier-result record for each load plus a finalized runner status.

On both required kernels, the first three programs loaded. The fourth program,
`interface_list_return`, did not return from `BPF_PROG_LOAD` within the fixed
120-second lane bound. Consequently:

- the run is **not PASS**;
- it is **not a canonical FAIL**, because the fourth result and final runner
  status do not exist;
- the partial files prove only that the complete object was not usable within
  the supported bound;
- absence of a rejection record must not be reported as acceptance.

The exact observations are:

| Guest | Actual kernel from raw evidence | Tracked result | Longer diagnostic |
| --- | --- | --- | --- |
| Ubuntu 22.04 Jammy | `5.15.0-187-generic` | 120.004 s, 3/4 accepted records, no final status | fourth load returned after about 202.1 s with verifier `ENOSPC`; rendered verifier text was 16,777,679 bytes |
| Ubuntu 24.04 Noble | `6.8.0-137-generic` | 120.004 s, 3/4 accepted records, no final status | still 3/4 after 600.004 s |

The frozen Task 2 prose report says `6.8.0-71-generic`; its own raw
`environment.txt` and all three Noble verifier records say
`6.8.0-137-generic`. The raw evidence is authoritative, and the report typo
is retained here as a known artifact defect rather than rewritten silently.

## Current issue register

### I1. `interface_list_return` is not verifier-compatible in its current shape

**Status:** confirmed component; corrective design approved, implementation
and rerun pending.

The failing program combines an 896-byte ring-buffer record, bounded
interface iteration (`< 16`), bounded function-pointer reads (`< 104`), name
classification, protected user reads, and failure accounting. The first three
programs load on both kernels; only this combined interface-return program
does not complete in the supported bound. Moving one interface iteration into
a non-inlined BPF subprogram did not make it complete.

The 16,777,679-byte Jammy log has 331,885 lines and ends while repeatedly
verifying instructions 318–322 in frame 3: a compiler-generated `u8` store
loop over `alloc_mem(..., 896)`. That is the source's exact 112-`u64`
initialization lowered to a byte-wise zeroing loop. There is no final invalid
access or bounds diagnostic before the log fills; `ENOSPC` is the verifier log
buffer being exhausted during state exploration, not host/guest disk space.
The same 896-byte emitter loads when called once for a function list, so the
problem is most likely the large initialization/table-read worker under the
bounded 16-interface fan-out rather than the record size alone.

**Consequence:** the current BPF record/control-flow shape cannot be copied
into production. Raising the timeout merely waits longer for an unusable
program and does not make production startup acceptable.

**Next evidence:** implement the approved flat constant-offset initializer and
semantic disassembly guard, then run the final unchanged A/B object on 5.15
and 6.8 while recording load duration, result, error chain, and bounded private
verifier-log facts. If it remains NON-PASS, stop and revise the design from the
new verifier evidence. Do not silently lower the 16-interface or 104-function
ceilings, and do not add tail-call/chunk machinery speculatively.

### I2. The diagnostic verifier log conflicts with the evidence cap

**Status:** confirmed harness/design contradiction.

Aya retries verifier loads with increasing log buffers. The Jammy rejection
rendered 16,777,679 bytes, while the gate permits at most 8 MiB for the
verifier log and 16 MiB total. The diagnostic therefore cannot be promoted to
a canonical tracked FAIL.

**Consequence:** the existing result remains `TIMEOUT / INCOMPLETE`. Increasing
the production evidence cap would expose a large kernel diagnostic and would
not solve verifier compatibility.

**Next evidence:** the approved design keeps full raw verifier text private and
uses bounded finite failure facts (program, errno, duration, completeness,
known original size, and private-log digest). Implement and test that contract;
never claim the bounded summary is the full verifier log.

### I3. The glibc loader-hook timing assumption is false for the two tested distro builds

**Status:** reproduced on Ubuntu glibc 2.35 and 2.39; upstream-fix build untested.

For both tested builds, the first post-`RT_ADD` `_dl_debug_state` callback with
`r_state == RT_CONSISTENT` occurred while the fixture's ordinary
`R_X86_64_64` data relocation still read as zero. The relocation became valid
at the constructor. The fixture used `RTLD_NOW`, so this was not a lazy PLT
case.

The glibc bug 31986 record is directly relevant. Upstream commit
`43db5e2c0672cae7edea7c9685b22317eae25471` says it moved
`RT_CONSISTENT` after relocation processing, and follow-up commit
`ac73067cb7a328bf106ecd041c020fc61be7e087` corrected the corresponding
`map_complete` probe. The record says these fixes were already in the upstream
tree by February 2025. The observed distro behavior means p11scope cannot infer
those semantics from the glibc version, distro age, or host age alone; it must
qualify the exact loader and companion-libc build.

Source: <https://sourceware.org/pipermail/glibc-bugs/2025-February/059039.html>

An older glibc discussion records the underlying portability problem:
`RT_CONSISTENT` historically described consistency of the link-map list, not a
portable promise that relocations were complete. Source:
<https://sourceware.org/pipermail/glibc-bugs/2009-November/010531.html>

**Consequence:** glibc `_dl_debug_state` cannot currently promise a zero-gap,
pre-constructor attachment point on the supported Ubuntu 22.04/24.04 builds.
`dlopen` return is later still and necessarily misses constructor-first calls.

**Next evidence:** run the same direct-memory witness against:

1. an upstream glibc build proven to contain both commits;
2. any supported distro package that backports them;
3. one exact package without them as the negative control.

Record the loader build ID and commit/backport provenance. Select hook behavior
by verified loader identity/capability, not by a broad `glibc >= X` rule.

### I4. musl hook support is exact-build evidence, not an ABI guarantee

**Status:** PASS only for Alpine 3.24.1 / musl 1.2.6.

That exact loader exports weak/default `_dl_debug_state`, and the direct
relocation witness was usable before the constructor.

**Consequence:** production must resolve and validate the hook for each loader
inode/build ID. Absence or an unusable offset is a named unavailable state,
not permission to guess an offset. A `dlopen` return fallback remains
constructor-blind.

### I5. Loader events must be hints, not proof of a stable one-event lifecycle

**Status:** design requirement highlighted by glibc bug 31986.

The real-world case includes audit modules, recursive `dlopen`/`dlmopen`, the
same DSO in multiple namespaces, and loader re-entry while link-map state is
changing.

**Consequence:** p11scope must not call into the provider or loader from the
hook. A hook should enqueue a bounded event; userspace should coalesce bursts,
rescan a stable view, compare exact mapping identities, attach idempotently,
and purge stale/ambiguous modules. Repeated `RT_ADD`/`RT_DELETE` cycles and
namespace-local instances must not double-attach or cross-attribute.

### I6. No-ptrace production discovery is still feasible, but the spike did not prove it

**Status:** architectural path available; production path unimplemented.

The loader timing spike used `/proc/<pid>/mem` only to obtain an independent,
direct experimental witness. Production eBPF hooks can use
`bpf_probe_read_user` at the target hook to read `r_state`, export return
values, interface descriptors, and function tables. That kernel-context read
does not require `CAP_SYS_PTRACE` or `/proc/<pid>/mem`.

**Consequence:** Slice 1b-2 can remove ptrace as a discovery dependency, but it
still needs the privileges accepted by BPF/uprobe attachment on the host
(`CAP_BPF` plus `CAP_PERFMON` where sufficient, otherwise `CAP_SYS_ADMIN`). A
BPF read failure must produce bounded unavailable/PARTIAL evidence; it must not
fall back silently to procfs.

### I7. Pause/resume timing is not yet an empirical result

**Status:** the historical runner and evidence are complete but inconsistent:
Task 3 produced Jammy FAIL at run 19 and Noble PASS 20/20; Task 4 produced
PASS 20/20 on both. The corrective analysis found that the old runner sampled
near 1 ms and 2 ms but never actually waited up to its declared 100 ms bound.
The corrected design is approved; its campaign is UNRUN.

`bpf_send_signal(SIGSTOP) == 0` means the request was accepted, not that the
thread group was already stopped. Gate B therefore requires two exact all-`T`
task snapshots, no post-hook marker before resume, one late attach, a third
stopped snapshot, then exactly one `pidfd_send_signal(SIGCONT)` through the
original pidfd. It runs 20 fresh children per kernel.

**Consequence:** pause cannot be advertised as zero-gap or safe-by-default.
The corrected runner must use the real 100 ms observation loop, aggregate
transition evidence, reserve-before-signal ordering, exact queue closure, and
the original pidfd for cleanup. Pause remains default `never`; an unprotected
live window is truthfully `PARTIAL`. Only `run -- command` children are
eligible; external numeric PIDs must never be paused because PID reuse can
target an unrelated process.

### I8. Dynamic attach and evidence semantics are still production work

**Status:** planned, not implemented.

The current attach engine freezes slot-indexed semantics before attachment.
Live discovery needs fixed descriptors plus per-link attach cookies, dynamic
slot allocation, a separate 64-KiB discovery ring, idempotent extension of the
plan, and module-ambiguity purge.

**Consequence:** even a passing hook/verifier spike does not mean Slice 1b-2 is
shipped. `run -- command`, pause configuration, attach-gap evidence,
discovery-ring loss, read/state failures, truncation, and child-liveness fields
must all be implemented, schema-checked, privacy-reviewed, and tested.

### I9. Existing one-shot discovery still misses late modules

**Status:** known current-product limitation.

Slice 1b-1 scans only at attachment time. A later `dlopen` is not discovered.

**Consequence:** current `profile`, `metrics`, and `trace` output can be
correctly PARTIAL while omitting a provider loaded later. Documentation must
continue to state this until live hooks and the discovery engine are present.

## Exact change packages

These are separate changes. A successful result in one package does not close
the others.

### P1. Make Gate A verifier-compatible

- Replace the verifier-hostile record-initialization/control-flow shape in
  `interface_list_return` while preserving the literal 16-interface and
  104-function ceilings, four-map spike boundary, raw-write privacy rules, and
  failure accounting.
- Keep bounded verifier diagnostics as private digest/size/category facts;
  never publish or require a multi-megabyte raw verifier log.
- Accept only an unchanged object that produces all four finalized program
  results inside the supported startup bound on both 5.15 and 6.8.

Do not call a longer timeout a fix. A compiler/linker unroll option, a different
zero-initialization shape, or a bounded program split may be researched, but it
must preserve the same observable limits and be re-reviewed before changing
the frozen gate.

### P2. Make Gate B pause timing repeatable

- Use one capture-level pause owner and one original pidfd per fresh child.
- Reserve the event before requesting `SIGSTOP`; record request acceptance
  separately from two observed all-stopped snapshots.
- Observe for the real approved 100 ms bound, perform one late attach, retain
  the attach gap, require the stopped post-attach snapshot, and resume exactly
  once even on every failure path.
- Run 20 fresh children per kernel with the exact aggregate oracle. Any event
  loss, missing snapshot, unsafe cleanup, or cross-run variance is a negative
  result or `PARTIAL`, not something to filter away.

The first research step is repeatability/root-cause data on the existing 5.15
variance—not a broad kernel bisection. Useful variables are scheduler/TCG
timing, `/proc/<pid>/task/*/stat` transition timing, group-stop observation,
pidfd resume ordering, and exact sample timestamps.

### P3. Qualify loader hooks per exact build

- Build and hash one glibc candidate containing `43db5e2c...` and
  `ac73067c...`, including its exact loader and companion libc identities.
- Run product-shaped eBPF uprobes on every `_dl_debug_state` hit. Read `r_state`
  and the relocation witness with `bpf_probe_read_user`; do not depend on
  `/proc/<pid>/mem` or ptrace in the product design.
- Test `DT_NEEDED` initial loading and `dlopen` separately, with a constructor
  sentinel, current glibc 2.35/2.39 negatives, and the exact musl positive.
- Promote only a capability tuple that passes the complete 12-row Gate C
  matrix. An unlisted or negative build remains scan/manifest fallback and
  `PARTIAL`.

The upstream commits make a qualified newer glibc a credible solution, but
they are not proof that an arbitrary newer machine or package contains the
needed ordering.

### P4. Add the production live-discovery engine

- Convert loader/export hook records into bounded hints; never call provider or
  loader code from a hook.
- Coalesce events in userspace, rescan a stable retained process view, compare
  exact opened identities, allocate dynamic slots, attach idempotently with
  attach cookies, and purge stale or ambiguous module instances.
- Preserve loss/read/state/truncation/attach-gap evidence. A late provider can
  be reported as discovered only after this flow succeeds.

This is the change that eventually enables providers first loaded after
capture startup in host, Docker, and Kubernetes scopes. Gate C alone only
qualifies an event source.

### P5. Finish the current Slice 1b-1 authority change

- Scan-only exact claims become count-only and force `PARTIAL`.
- An explicit accepted manifest attests only the exact pinned object + offset +
  canonical name; raw key, path, digest, proximity, or a neighboring manifest
  claim cannot transfer authority.
- Conflicts and stale fallbacks remain conservative.

This owner-approved work is currently in TDD implementation. It makes current
manifest-free behavior honest; it does not implement late discovery.

## Suggested external research questions

1. Which exact compiler-generated paths dominate verifier states in
   `interface_list_return`, and which minimal code-generation change removes
   them without lowering the 16/104 bounds or privacy checks?
2. Does an exact glibc build containing both bug-31986 commits produce a usable
   `_dl_debug_state` hit after relocation and before constructors for `dlopen`?
3. Which released distro packages contain those exact fixes or backports, as
   proven by source provenance/build ID rather than version inference?
4. Why did byte-identical Jammy Gate B evidence fail once and pass later, and
   does the corrected 100 ms aggregate oracle produce a stable 20/20 result?
5. Can the final frozen A/B/C artifacts pass unchanged on both required
   kernels without raising timeouts, evidence caps, or privileges?

The useful handoff from external research is raw, reproducible evidence:
exact source commit/package, build IDs and SHA-256 values, kernel, toolchain,
commands, bounded logs, constructor/relocation witnesses, and negative
controls. Version-only conclusions or one successful retry are not enough.

## Do we need more kernels?

Not as the immediate next move. The two required compatibility endpoints—an
Ubuntu 5.15 kernel and an Ubuntu 6.8 kernel—already reproduce the same
fourth-program bottleneck. Adding several arbitrary kernels would add cost
without isolating which program feature causes it.

The efficient order is:

1. finish and independently review the approved Slice 1b-1 semantic-authority
   implementation;
2. implement the approved Gate A constant-offset initializer and corrected
   Gate B 100 ms aggregate oracle;
3. rerun the final unchanged A/B artifact on the existing 5.15 and 6.8 guests;
4. run the approved Gate C controls, including one exact fixed-glibc build;
5. add another kernel only if the same frozen artifact differs between the two
   mandatory endpoints or new verifier evidence makes the distinction useful.

The libc matrix is different: one additional glibc build containing the
upstream bug-31986 commits is necessary because it tests a specific loader
semantic, not a kernel-verifier variation.

## Product decision implied by current evidence

Slice 1b-2 should continue, but the present large `interface_list_return`
program and unconditional glibc hook assumption must not be promoted into
production. The likely product model remains:

- live discovery is best-effort and always exposes completeness evidence;
- pause is an explicit `run` option until timing proves a stronger default;
- loader hooks enqueue hints and userspace performs exact-identity rescans;
- export return hooks provide corroborating table discoveries;
- `attach_gap_ms` is measured and reported, never assumed zero;
- no-ptrace BPF-side reads are the production path;
- unsupported loader/verifier combinations fail closed or remain PARTIAL.

The semantic-authority owner gate is resolved: scan-only tables are
heuristic/count-only/PARTIAL and excluded from semantic P11Lab joins; exact
live acquisition or an accepted exact pinned operator-manifest claim may grant
semantic authority. Its implementation and independent review remain open.

## Authoritative evidence pointers

- Kernel Gate A report:
  `/home/user/src/m/pkcs11-scope-codex-slice1b-1/.superpowers/sdd/slice1b2-kernel-spike-design/task-2-report.md`
- Independent Gate A review:
  `/home/user/src/m/pkcs11-scope-codex-slice1b-1/.superpowers/sdd/slice1b2-kernel-spike-design/task-2-review.md`
- Gate B report/review:
  `/home/user/src/m/pkcs11-scope-codex-slice1b-1/.superpowers/sdd/slice1b2-kernel-spike-design/task-3-{report,review}.md`
- Loader/libc report:
  `~/src/m/pkcs11-scope-evidence/slice1b2/analyses/slice1b2-loader-spikes.md`
- Loader corrective analysis:
  `~/src/m/pkcs11-scope-evidence/slice1b2/analyses/slice1b2-loader-corrective-analysis.md`
- Slice 1b-1 semantic-authority contract:
  `/home/user/src/m/pkcs11-scope-codex-slice1b-1/docs/superpowers/specs/2026-08-18-slice1b1-semantic-authority-contract.md`
- Approved corrective design:
  `/home/user/src/m/pkcs11-scope-codex-slice1b-1/docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md`
- Final corrective-design review:
  `~/src/m/pkcs11-scope-evidence/slice1b2/analyses/slice1b2-corrective-spec-review.md`
- Raw Gate A evidence:
  `~/src/m/pkcs11-scope-evidence/slice1b2/gate-a/p11scope-slice1b2-task2-fd98a02-gatea-{jammy,noble}-evidence`
- Raw longer diagnostics:
  `~/src/m/pkcs11-scope-evidence/slice1b2/gate-a/p11scope-slice1b2-task2-fd98a02-diagnostic-*`
- Tracked loader witness harness: `spike/slice1b2-loader/`
  (evidence-root layout and pinned digests: `docs/notes/slice1b2/README.md`)
