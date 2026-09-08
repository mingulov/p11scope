# Proper ia32 compatibility implementation plan

> Use executing-plans, systematic-debugging when a gate fails, and
> verification-before-completion. One writer per coupled file set; only one
> Cargo-heavy command at a time. Review writers after they stop.

**Owner decision:** 2026-09-07, following the requested Astra xhigh research:
"yes just support it properly (do that needed check etc)". This supersedes the
same-day ia32 deferral. Linux x86-64 host; conventional LP64 and ia32 targets.
No push, tag or publication. Privileged/VM/container qualification is authorized.

**Design:** Reuse provider facts and the existing scope lifecycle. Add explicit
layout operations to the shared module crate, target-sized memory readers,
ELF32 interpreter support and same-bitness helpers. Prefer per-hit execution
mode from host pt_regs after qualification; compile shared-source specialized
entry points only if verifier evidence requires them. Keep public capture
structures, privacy allowlist, generation authority and finite bounds intact.

**Verified inputs:** scope ABI research at 25c4335/fe46b37; current integration
base aebf73e. Proxy dev and scope dependency both a2aab6cd. Clang independently
validated all104 function offsets on Linux64/32 and packed Windows64, plus
mechanism/interface/attribute sizes and glibc r_state offset24/12,width4.
Kernel5.15 implements compat uprobes and CS-based mode recognition, but the
proposed Aya readers/no_std split have not been compiled or run. Research
report is retained under p11scope-ws/incoming/2026-09-07-abi-research.

## 1. Decisive compat-kernel gate

- [x] Add a bounded native32/64 fixture and ordinary-caller driver using
  installed tracing tools. Exact known seven arguments, entry/return pairing,
  success/vendor RVs, execution mode, loader IP/state and x64 control.
- [x] Run an unprivileged checker self-test with rejected wrong arguments,
  wrong return normalization and missing returns. Review the actual script.
- [x] Run on host and an exact5.15 qualification guest; record tool/kernel
  versions, stdout/stderr, process status, source hash and cleanup.
- [x] Include a timeout-bounded process-scoped ASLR/endbr32 XOL case where
  supported. Never change host-wide ASLR. Unsupported test prerequisites are
  non-PASS, with precise remaining question.
- [ ] Follow the tracing-tool gate with the actual Aya producer/readers and
  verifier contracts before declaring product feasibility established.

The initial fixture files are scripts/matrix/verify-ia32-compat.sh and
scripts/matrix/ia32-compat-harness.c. This gate is a kernel check; it does not
qualify scope merely because bpftrace can trace the fixture.

## 2. Close the independent export nesting defect

Actual proxy runtime at aebf73e produced exactly3 state failures. Holding the
workload alive past capture did not change it. Separate tracing observed
proxy C_GetFunctionList entry → SoftHSM entry → SoftHSM return → proxy return.
Existing non-selection cookies encode only symbol ID, colliding in the BPF
state key. Preserve the zero-loss oracle.

- [x] Shared checked cookie = object_id:u32 | context_case:u8 | hook_id:u24.
  Keep full cookie as state identity and emit only decoded symbol ID.
- [x] Update both FunctionList and InterfaceList producer paths and planning;
  preserve selection cookies/domain, deterministic retry and terminal replay.
- [x] Test boundaries, same-site reuse, distinct sites/contexts, start rollback
  and terminal exact-snapshot behavior. No new allocator or stack-frame ABI.
- [x] Rerun the real proxy oracle and a nested InterfaceList fixture; require
  zero state/read/ring loss and exact table evidence. Same-site recursion is
  a separate pre-existing loss behavior, not claimed solved by this fix.
- [x] Four gates and independent review before integration.

Owned coupled files for this patch: crates/ebpf-common/src/lib.rs,
crates/ebpf/src/main.rs, src/discovery/engine.rs, tests/artifact_contracts.rs.
The kernel-gate writer owns only its two new script/fixture files.

## 3. Shared target-layout facts

- [x] In proxy-ng crates/module, retain native API behavior and the single
  field/version catalog. Add explicit Linux layout/ordinal/pointer operations.
- [x] Expose a dependency-free layout surface for no_std consumers using a
  small feature boundary; verify it in the separate BPF workspace before
  choosing the final organization. Do not import wire/backend policy.
- [x] C and Rust tests:104 fields,67/68/92/104 prefixes, truncated final words,
  interface stride, native API compatibility and unknown-version boundaries.
- [x] Local cross-repo commit/pin only after review; keep release source bundle
  self-contained until remote publication is authorized. No hidden path patch
  may masquerade as the final dependency revision.
- [x] Before repinning, prove unpublished-source restoration: include the exact
  reviewed proxy revision and both workspace dependency sets in the bundle.
  Use standard Cargo vendoring with the BPF manifest included via --sync,
  recording its source-replacement configuration and source checksums. From
  fresh extraction with an empty CARGO_HOME and no original Git caches, run
  locked/offline checks for both workspaces and all helper builds using the
  declared toolchain/sysroot inputs. If this mechanism cannot cover the BPF
  build inputs, resolve that closure before adopting the new pin; an original
  machine's warm cache is never acceptance evidence.

## 4. Coherent observer implementation

- [ ] crates/manifest/src/elf.rs: classify little-endian ELF64/EM_X86_64 and
  ELF32/EM_386; reject x32/foreign/endian mismatch. ABI follows retained object
  identity through discovery and each dependency attach target.
- [ ] src/discovery/scan.rs: parameterize span_bytes, exact_table_bytes,
  exact_table_addresses, decode_candidate, detect_tables and scan_interfaces.
  Preserve candidate/read/work caps, padding policy and maps-stability checks.
- [ ] src/discovery/engine.rs::read_selection_table: target-sized header and
  exact pointer reread in both identity brackets. Never trust manifest ABI.
- [ ] BPF main.rs::arg_u64: checked ia32 four-byte entry-stack reads; keep x64
  register indices constant. Use host pt_regs layout for both targets.
  Define the accepted execution-mode selectors explicitly: unknown selectors
  must authorize no ABI-dependent reads and must produce a named refusal/loss,
  never default to either ABI. Test that negative path. Keep x32 rejection in
  pinned ELF identity; document nonconventional/PARAVIRT selector treatment.
- [ ] Normalize ia32 RV low32 before all success/error/accounting uses. Adapt
  output pointers/counts, export/table/interface-list/selection/tail-call reads,
  mechanisms and handle outputs. Keep record fields and maps at existing widths.
- [ ] Parameterize the existing diagnostic PSS/GCM/template readers, exact
  lengths and type→length→single-byte capture ordering; no privacy expansion.
- [ ] Both interpreter parsers: ELF32; loader cookie points directly to actual
  r_state, removing fixed+24. Retain musl optional-state/every-hit behavior;
  never dereference _dl_debug_addr as a direct r_debug structure.
- [ ] Preserve owned prearm/first-hit binding, cgroup/mixed-ABI contexts,
  64→32→64 exec, stale-record rejection, module replacement and terminal drain.

Do not open ELF32 product admission until dependent readers and selection/
loader paths are coherent. Keep low-level preparation independently testable.

## 5. Helper and runtime closure

- [ ] Same-bitness i686 glibc and dynamically linked musl discovery helpers;
  unchanged native64 helper and static x64 observer. Verify actual dlopen and
  finite interface-selection evidence, not merely cross-compilation.
- [ ] Real ia32 providers/fixtures: manifest, scan-only, exported tables,
  interface lists/selection, late dlopen, owned startup before constructors,
  dependency targets, mixed cgroups, exec and unload/reload/path replacement.
- [ ] Four-byte values at readable-page boundaries, adjacent secret canaries,
  poisoned upper RV bits, hostile aliases/names and unregistered mechanisms.
- [ ] Exact entered/returned/consumed counts, RVs, metadata and loss counters;
  all relevant x64 controls. Kernel5.15 and6.8 plus declared musl32 environment.
- [ ] Independent review-to-zero and Rust1.88 fmt/check/test/clippy; exact BPF
  object/verifier inventory reflects any measured program changes.

## 6. Release integration

- [ ] Publish exact PASS/FAIL/UNRUN rows and supported ABI/environment statement.
- [ ] Resume W5 policy/container qualification and W6 kernel/product oracles.
- [ ] W8-A closes the final architecture/maintainability review and justified
  redesigns across BPF, userspace, scripts and tests; rerun affected ABI and
  runtime gates after corrections. See the
  [architecture design](../specs/2026-09-07-final-architecture-and-test-design.md).
- [ ] W8 repeats final-tip qualification, docs truth pass, review, literal
  receipt and fresh-extracted checksummed portable/source bundle.

No static-only substitute, lost selection/loader behavior, silent unsafe
fallback, weakened oracle or unrun qualifier may be called proper support.
A failed prerequisite changes the next investigation, not the requested goal.

## Measured verifier integration decision (2026-09-07)

The global 80-byte full-template output boundary plus restored local types-only
reader leaves only ordinary entry above Linux 5.15's verifier budget. The
combined diagnostic object `cdf34c2b` loads 17/17 programs on the host and
16/17 on 5.15; the private forced-ia32 control `9e4a997f` loads 17/17 on both.
Earlier forced-LP64 ordinary entry also passed. These are load-only controls,
not runtime capture qualification.

Proceed with one additional diagnostic-only `p11_entry_ia32`, sharing the
ordinary entry implementation with its LP64 specialization. Resolve routing
from `PinnedObjects::abi_for(slot.object)` before any attachment; the slot
names the actual target, including dependency targets. Preserve per-hit CS
validation and refuse unknown or target-incompatible modes before reads or
counting. Diagnostic binaries must route correctly under all capture policies.
Keep the default mixed-ABI entry and template families intact. Classify the
new program as an entry for pairing, replacement and entry-before-return
teardown; retain existing maps, cookies, records and ABI-refusal counter.
Require actual default 13/13 and diagnostic 18/18 loads on both kernels,
independent review and both-width runtime oracles before declaring closure.

## Later kernel and incompatibility qualification (owner request, 2026-09-07)

After closing the current 5.15 diagnostic verifier issue, carry both target
ABIs through the existing W6 matrix. Reuse the same fixtures and checkers;
do not create a separate ABI test framework or infer support from a newer
kernel number. This amendment schedules checks, not completed evidence.

**Owner clarification (2026-09-07):** ia32 is a required ABI axis on every
testable x86-64 kernel/configuration row, including optional rows when run,
not a sample confined to the kernels listed below. Each runnable positive
row must exercise both native64 and ia32 with the same applicable acceptance
oracles: actual default/diagnostic BPF load and attachment, counts/RVs,
metadata/privacy, selection/loader and lifecycle behavior. The table sets
execution priority, not an exemption for other kernels. In particular this
includes the existing 6.17-azure and filtered-target 6.11 rows, the current
host, and Debian 6.1 or other additions when available.

If the environment cannot execute ia32, record the exact prerequisite and
test the applicable refusal separately; that cannot establish positive ia32
support. A decoder/verifier failure on an otherwise eligible row remains a
failure to fix, not a reason to reclassify it as untestable. Required rows
with missing positive evidence remain open release gates. Report results per
ABI and exact kernel/configuration; no sampled or version-wide support claim.

- [ ] Before the ia32 filtered-target row, adapt the existing
  `scripts/matrix/uretprobe-seccomp-harness.c` and driver: the audit-architecture
  guard currently hardcodes x86-64 and the syscall-335 diagnostic is native64
  specific. Verify per-ABI syscall/filter assumptions, unprobed loop survival
  and a deliberately blocked control before interpreting probe-induced death.
  Compiling the current fixture with `-m32` alone is not a valid ia32 oracle.

| Priority | Environment | ABI qualification |
| --- | --- | --- |
| W7 core | Ubuntu 22.04 / 5.15 and Ubuntu 24.04 / 6.8 | Actual native64 and ia32 capture, default and diagnostic objects, selection/loader behavior, boundary/canary tests and exec transitions. |
| W6 required backport row | CentOS Stream 9 / 5.14.0-741.el9, the previously tested build | Repeat native64 and qualify ia32 with actual default/diagnostic objects, capture and lifecycle oracles. Assert capability-based admission despite the older version number. Record this exact distribution; it does not establish direct RHEL 9 qualification. |
| W6 existing portability row | Fedora 44 / 6.19 with SELinux enforcing | Repeat both ABIs on the candidate and distinguish policy denials from decoder or verifier failures. |
| W6 addition | Ubuntu 22.04 GA `5.15.0-25-generic`, package `5.15.0-25.25`, selected on 2026-09-08 | Start with actual-object verification and bounded native64/ia32 captures; deepen failed or differing paths. Signed-index package acquisition verified; boot and execution remain UNRUN. |

The additional 5.15 row uses the original Jammy GA build to exercise an early
5.15 verifier/backport baseline alongside `5.15.0-187-generic`. Canonical's
[package record](https://launchpad.net/ubuntu/jammy/+package/linux-image-5.15.0-25-generic)
identifies the release build. Exact image and modules URLs on the Ubuntu archive
both answered HTTP 200 in the selection preflight. Subsequently the Jammy
InRelease signature verified against the installed Ubuntu archive keyring,
the package index matched its signed SHA-256, and both downloaded packages
matched their exact index sizes and hashes. This establishes acquisition,
not boot or runtime qualification. Use a separate owned test environment. Preserve the
existing 187 guest and its recorded results. Required positive and refusal
controls remain unchanged; failure does not silently remove this row.

The signed packages have also been extracted privately without installation.
Their configuration enables ia32 emulation, uprobes and BTF. Exact extracted
BTF SHA-256 is `a5baeefda0d449e9070af8d9e129b075633681d7dd80036d11628bd9965e7d2d`;
the private cookie producer successfully relocates its three field accesses to
this early layout (tgid2388/group_leader2448), distinct from the187 guest and
host. Evidence: private architecture root `k2-ga-extracted-_heynfr5/offline-btf/`.
This is file-only preparation and private mechanism evidence; verifier, boot,
product capture and both target ABI runtime checks remain UNRUN.

The [existing kernel/config matrix](../../notes/2026-09-05-kernel-and-config-test-matrix.md)
already makes the CentOS Stream 9 backport row required and records a prior
136/136 native capture with zero losses. That is historical evidence, not
current ia32 qualification. This explicit row supersedes the initial generic
"exploratory pre-5.15 backport" wording: acceptance follows actual capabilities
and exact-build qualification, not a blanket rejection of 5.14 version strings.
The other required W6 kernel/config rows remain required.

Record the exact distro/kernel build, available kernel configuration including
IA32 emulation, libc/loader and helper ABI, toolchain and object hashes for
every row. Retain native64 controls. A successful BPF load alone is not runtime
ABI qualification; unavailable prerequisites leave the dependent question
UNRUN rather than passing an expected-refusal test.

Include explicit incompatibility controls: an environment without usable IA32
emulation; missing 32-bit ELF interpreter; opposite-width helper/provider;
x32, foreign-machine and wrong-endian ELF inputs; and unsupported execution
selectors. Record whether refusal comes from the kernel, loader, helper or
observer. Assert the existing named failure/loss contract and no guessed ABI
decoding or stale attribution. Synthetic parser/selector checks must remain
distinguished from actual execution on a configured kernel.

Reuse W5 for container seccomp/SELinux restrictions and W7 lifecycle fixtures
for mixed-ABI cgroups and 64→32→64 exec. W8 repeats required final-candidate
rows and publishes measured compatibility and limitations; exploratory rows
do not silently expand release support or replace existing required gates.

## Prerequisite checkpoint (2026-09-07)

The final kernel gate passed all four rows on host 7.0.0-30-generic with
bpftrace 0.20.2 and guest 5.15.0-187-generic with bpftrace 0.14.0-1:
native x64, invalid-user-read control, ia32 core and ia32 process-ASLR-disabled
endbr32 stepping. Both runs used identical script/harness hashes; every
fixture, bystander, tracer and cleanup status was zero. Exact seven arguments,
RVs, selectors and ordinal loader states matched. Upper-word poisoning remains
a synthetic checker negative, not a product-runtime result.

Jammy required its matching bpftrace debug-symbol package before even a minimal
BEGIN probe worked. Its redundant `-p` option also caused missing loader hits;
removing only that option passed the unchanged oracle. Explicit PID predicates,
bystander exclusion, timeout and cleanup remain. The precise bpftrace internal
cause is unresolved; neither CPU pinning nor an END counter supported the
initial transport hypothesis. No product ABI fallback was introduced.

The real proxy plus direct nested FunctionList/InterfaceList runtime passed
at 3b68e94 with zero discovery state/read/ring loss and exact two-provider table,
interface and call evidence. All four Rust 1.88 gates passed at f069c4e (1,107 tests, zero failures or
ignored tests). These results do not constitute final W7 or release qualification.

Shared target facts are reviewed and locally committed in proxy-ng at
cbf3d019c43cf424d92a5d2033c6714c9f866f65. Native and no-default-feature tests ran
on x64 and i686; 49 inventory checks passed. An independent C-header comparison
matched all 104 API-produced offsets and seven size/interface assertions for
each Linux layout. At that checkpoint scope still pinned a2aab6cd; the source
restoration prerequisite below subsequently allowed the W7 worktree to adopt
the reviewed revision. Coherent observer integration remains in progress.

Raw prerequisite evidence is retained under
`p11scope-ws/incoming/2026-09-07-abi-qualification/`; module results under
`incoming/2026-09-07-abi-research/`; proxy and canonical-gate results under
`incoming/2026-09-07-release-local/`. These are prerequisite receipts, not W8.

## Source restoration and helper checkpoint (2026-09-07)

Standard Cargo vendoring includes the root workspace, the separate BPF
workspace, and the pinned nightly rust-src workspace. The third source archive
contains the exact reviewed proxy Git bundle and both locked dependency sets.
From fresh extraction with a newly created CARGO_HOME, locked/offline root
all-target checks (including actual BPF compilation), native helper Clippy, and
all four dynamic helper release builds passed. Cargo created its registry
marker but no Git checkout, registry index or crate-source cache. No registry
package versions changed in the scope lockfiles.

The helper's fixed query flags now use native CK_FLAGS; native unsigned words
widen losslessly to manifest u64 values. Native32 and native64 fixture builds
select the test executable's pointer width. Fourteen fixture tests passed on
each of x64 and i686, including selection, lazy dependency loading and
page-boundary/version-matrix cases. The unknown-flags expectation uses the
highest native CK_FLAGS bit, matching the unchanged C fixture on both ABIs.

Actual glibc32, glibc64, musl32 and musl64 helpers each loaded a matching provider,
passed the existing 68/92/104 version-matrix oracle and produced exactly ten
successful bounded selection queries. All four opposite-width loads refused
without writing a manifest. The musl proof uses declared private toolchains:
signed musl 1.2.6 with its published qsort/iconv patches, GCC multilib, and
Alpine 3.22 libgcc 14.2.0-r6 for each architecture. Its private interpreter and
library paths qualify source builds, not final portable release packaging.

Earlier failures remain recorded: missing rust-src registry dependencies;
four helper flag-width type mismatches; private musl configuration's assumed
prefixed binutils; and missing musl libgcc at dynamic link. The final successful
commands resolve those inputs without using the original Git/crate cache or
weakening the provider oracle. Exact archives, hashes, logs, source/toolchain
identities and helper captures are under
`p11scope-ws/incoming/2026-09-07-abi-source-closure/`.

The producer and userspace implementation must still meet Stages 4–5. In
particular, the loader's existing file-offset symbol lookup misses `_r_debug`
when it lies in BSS. The implementation must retain strict file-backed hook
offsets while locating the complete four-byte r_state field in bounded ELF
loadable memory, then encode that actual field address in the existing cookie.
