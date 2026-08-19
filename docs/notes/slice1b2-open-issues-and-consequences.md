# Slice 1b-2 open issues, consequences, and next evidence

Date: 2026-08-18

This is a living engineering note for the live-discovery and `run -- command`
slice. It separates a completed negative result from an incomplete run and
keeps spike evidence distinct from production support.

## Current status (supersedes older status wording below)

The corrective research implementation is complete through Task 8 at commit
`a227dabe7ab0fb62eee6ec9cca1f4afbad46eb03`. Task 9 was deliberately skipped
after Task 8 resolved decision D3. This is spike evidence, not product support.

The later pause-protocol disposition supersedes the older promotion wording
below. The `a227dab` Gate B campaign used a winner-side busy wait and is not a
product candidate. A later no-busy-wait frozen campaign recorded 120/120, all
as outcome B, but controller and independent review found owner-2 cleanup,
outcome-A causal-deadline, and oracle-contract defects. Both campaigns remain
immutable feasibility evidence. Promotion is blocked; the amended campaign is
UNRUN and is governed by
`docs/superpowers/specs/2026-08-19-slice1b2-no-busy-wait-pause-amendment.md`.

| Work item | Current result | Consequence |
| --- | --- | --- |
| Gate A: four discovery programs | **PASS** on Jammy 5.15 and Noble 6.8 with the final frozen A/B object | The constant-offset record initializer removed the verifier-state explosion without lowering the 16-interface or 104-function limits. |
| Gate B: pause/attach timing | Two frozen campaigns recorded **120/120**, but neither is promotable | The first used a busy wait; the later no-delay campaign was outcome-B-only and has reviewed lifecycle/oracle defects. The amended campaign is `UNRUN`. The same frozen Noble lanes under TCG remain `TIMEOUT / INCOMPLETE`; STATS-only still proves the verifier accepts the program under sufficient acceleration. |
| Loader event path | **PASS** on Jammy 5.15 and Noble 6.8 | The ptrace-free `_dl_debug_state` uprobe works on both; 5.15 uses the validated runtime-IP fallback because `bpf_get_func_ip` returns zero there. |
| Attach-first experiment | **160/160 retained attempts validated** across host and Noble | One pause covers exported providers. Hidden-table constructor calls escape with one pause but are covered with the measured second pause. Task 9's timing catalog is not on the critical path. |
| Slice 1b-1 semantic authority | Owner-approved implementation exists on the recovery line; integration remains separate | An accepted explicit manifest attests only its exact pinned object + offset + canonical name. Scan-only claims remain count-only/PARTIAL. |

No kernel bisection is required. The remaining work is production integration:
land Slice 1b-1, implement the reviewed no-busy-wait A/B pause protocol, rerun
its full campaign, then implement the live discovery engine, dynamic
attachment, and completeness evidence. KVM is required for the supported
120-second research gate; TCG is retained as an explicit unsupported speed
result, not a kernel or BPF failure.

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

This section describes the retained pre-corrective Gate A campaign. The final
flat-initializer Gate A campaign passes on both required kernels.

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

**Status:** resolved in the spike; final Gate A PASS on both required kernels.

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

**Resolution:** 112 straight-line constant-offset `u64` stores plus the
semantic disassembly guard produced final object `e4973fd0…`; all four
programs and the exact Gate A oracle passed on 5.15 and 6.8. The 16/104 limits,
four-map boundary, record layout, and failure accounting were unchanged.

### I2. The diagnostic verifier log conflicts with the evidence cap

**Status:** bounded diagnostic works; frozen verbose campaign limitation remains.

Aya retries verifier loads with increasing log buffers. The Jammy rejection
rendered 16,777,679 bytes, while the gate permits at most 8 MiB for the
verifier log and 16 MiB total. The diagnostic therefore cannot be promoted to
a canonical tracked FAIL.

**Resolution and consequence:** STATS-only diagnostics retain bounded finite
facts. On the final object, Noble accepted the large Gate B `signal_return`
program with 150,091 verified instructions in 1028 ms under KVM and 253,049 ms
under TCG. All three frozen `VERBOSE | STATS` TCG lanes stalled beyond 120
seconds before their first result; those historical lanes stay
`TIMEOUT / INCOMPLETE`. The unchanged frozen KVM campaign completed 120/120.

### I3. The glibc loader-hook timing assumption is false for the two tested distro builds

**Status:** reproduced negatives and released fixed-build positives complete.

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

**Resolution:** `dlopen` remains negative on glibc 2.35/2.39 and is positive on
source-proven Debian 13 glibc 2.41 and Ubuntu 26.04 glibc 2.43. `initial_set`
is positive on all five tested glibc/musl controls. Selection remains by exact
loader/libc identity and provenance, never a version comparison. Task 8 then
showed that the two-pause attach-first protocol covers hidden-table constructor
calls without putting a relocation-timing catalog on the product critical path.

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

### I6. No-ptrace production discovery is feasible and proved by the spike

**Status:** ptrace-free event source PASS on both required kernels; production
integration remains unimplemented.

The loader timing spike used `/proc/<pid>/mem` only to obtain an independent,
direct experimental witness. Production eBPF hooks can use
`bpf_probe_read_user` at the target hook to read `r_state`, export return
values, interface descriptors, and function tables. That kernel-context read
does not require `CAP_SYS_PTRACE` or `/proc/<pid>/mem`.

The final loader artifact observed `RT_ADD → RT_CONSISTENT` on both guests,
validated its cookie/registry and no-cookie negative, and used a runtime-IP
fallback on 5.15 where `bpf_get_func_ip` returns zero for the uprobe.

**Consequence:** Slice 1b-2 can remove ptrace as a discovery dependency, but it
still needs the privileges accepted by BPF/uprobe attachment on the host
(`CAP_BPF` plus `CAP_PERFMON` where sufficient, otherwise `CAP_SYS_ADMIN`). A
BPF read failure must produce bounded unavailable/PARTIAL evidence; it must not
fall back silently to procfs.

### I7. Pause/resume timing is now an empirical result

**Status:** feasibility exercised; promotion blocked. The older busy-wait KVM
campaign and the later no-delay, outcome-B-only campaign each recorded 120/120,
but neither satisfies the reviewed product contract. The separate Noble TCG
campaign is `TIMEOUT / INCOMPLETE` before trials, while its STATS diagnostic
accepts both BPF programs after 253 seconds. Task 8 independently completed
160/160 host/Noble attempts.

`bpf_send_signal(SIGSTOP) == 0` means the request was accepted, not that the
thread group was already stopped. Gate B therefore requires two exact all-`T`
task snapshots, no post-hook marker before resume, one late attach, a third
stopped snapshot, then exactly one `pidfd_send_signal(SIGCONT)` through the
original pidfd. It runs 20 fresh children per kernel.

**Consequence:** one pause is sufficient for exported-provider symbols but not
for hidden table functions: constructor calls escaped in all 40 one-pause
hidden attempts. A second owned pause attached all 104 slots before the call in
all 40 host/Noble attempts. Production must implement the amended no-busy-wait
A/B lifecycle, keep pause opt-in, expose the live window as `PARTIAL` when
unprotected, and stop only owned `run -- command` children through the original
pidfd. A fresh reviewed campaign is mandatory before promotion.

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

### P1. Make Gate A verifier-compatible — research complete

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

### P2. Make Gate B pause timing repeatable — feasibility shown, promotion blocked

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

The reviewed no-busy-wait amendment supersedes this historical recipe. Its
implementation, oracle, freeze, and full six-lane campaign remain `UNRUN`.

### P3. Qualify loader hooks per exact build — precontrols complete

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

The recovery line contains the owner-approved implementation, but its landing
and final integration review remain separate. It makes current manifest-free
behavior honest; it does not implement late discovery.

## P4/P5 production handoff

- **P5 first:** the recovery line contains the semantic-authority work starting
  at `906753a`; land it only after its separate final review and gates.
- **P4 next:** after P5 lands, implement `discovery::Engine`, dynamic slots and
  attach cookies, completeness/loss evidence, and the explicit two-pause
  `run -- command` policy. D3 is **no**, so corrective-design §7.2 catalog
  promotion, §8.3 rows 1/4/5–8, and §11 step 2 move off the product critical
  path into optional diagnostics. The every-hit loader event source and
  attach-first/two-pause path remain required product inputs.

## Research questions and results

1. The byte-loop initializer dominated verifier states. Straight-line
   constant-offset stores pass without lowering the 16/104 bounds.
2. Source-proven glibc 2.41 and 2.43 produce the usable post-relocation
   `dlopen` hit; glibc 2.35/2.39 remain negative controls.
3. Debian 13 and Ubuntu 26.04 provide the tested fixed packages, bound by
   source provenance, loader/libc hashes, and runtime witnesses.
4. The retained KVM campaigns demonstrated pause feasibility, but their
   busy-wait or reviewed lifecycle/oracle defects block promotion. TCG is too
   slow for the 120-second frozen loader bound, not a BPF rejection.
5. The retained A/B and loader artifacts ran on both required kernels under
   KVM. Task 8 additionally passed all 160 host/Noble attempts; the amended
   Gate B artifact and campaign remain `UNRUN`.

The useful handoff from external research is raw, reproducible evidence:
exact source commit/package, build IDs and SHA-256 values, kernel, toolchain,
commands, bounded logs, constructor/relocation witnesses, and negative
controls. Version-only conclusions or one successful retry are not enough.

## Do we need more kernels?

No. The same final A/B and loader artifacts pass on the required Ubuntu 5.15
and 6.8 endpoints. Add a kernel only when product integration differs on those
two endpoints or a supported deployment introduces a new compatibility floor.
Loader qualification remains per exact loader/libc identity, not per kernel.

## Product decision implied by current evidence

Slice 1b-2 should continue using the proved flat initializer and ptrace-free
every-hit loader hook, then implement and re-prove the reviewed no-busy-wait
A/B pause protocol. It must not promote either retained pause campaign or an
unqualified glibc timing assumption. The product model is:

- live discovery is best-effort and always exposes completeness evidence;
- pause is an explicit `run` option until timing proves a stronger default;
- loader hooks enqueue hints and userspace performs exact-identity rescans;
- export return hooks provide corroborating table discoveries;
- `attach_gap_ms` is measured and reported, never assumed zero;
- no-ptrace BPF-side reads are the production path;
- unsupported loader/verifier combinations fail closed or remain PARTIAL.

The semantic-authority policy is resolved: scan-only tables are
heuristic/count-only/PARTIAL and excluded from semantic P11Lab joins; exact
live acquisition or an accepted exact pinned operator-manifest claim may grant
semantic authority. Landing that recovery-line implementation remains separate.

## Authoritative evidence pointers

- Final evidence inventory: `~/src/m/pkcs11-scope-evidence/slice1b2/MANIFEST.sha256`
  (`dee02a5418bea166aa22eaaebd1bc13cd68d6fd9822f27c53fa7970835954d86`)
- Final Gate A/B bundles and campaigns:
  `~/src/m/pkcs11-scope-evidence/slice1b2/{bundles/final-a227dab-bundle,gate-a/final-a227dab-kvm-*,gate-b/final-a227dab-kvm-*}`
- Final loader event campaigns:
  `~/src/m/pkcs11-scope-evidence/slice1b2/loader-artifact/{jammy,noble}-a227dab`
- Final attach-first experiment: `~/src/m/pkcs11-scope-evidence/slice1b2/task8/`
  and `docs/notes/slice1b2/attach-first-vs-timing-catalog.md`

Historical design and negative evidence remain at:

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
