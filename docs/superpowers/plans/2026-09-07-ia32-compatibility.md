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
- [ ] Expose a dependency-free layout surface for no_std consumers using a
  small feature boundary; verify it in the separate BPF workspace before
  choosing the final organization. Do not import wire/backend policy.
- [x] C and Rust tests:104 fields,67/68/92/104 prefixes, truncated final words,
  interface stride, native API compatibility and unknown-version boundaries.
- [ ] Local cross-repo commit/pin only after review; keep release source bundle
  self-contained until remote publication is authorized. No hidden path patch
  may masquerade as the final dependency revision.
- [ ] Before repinning, prove unpublished-source restoration: include the exact
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
- [ ] W8 repeats final-tip qualification, docs truth pass, review, literal
  receipt and fresh-extracted checksummed portable/source bundle.

No static-only substitute, lost selection/loader behavior, silent unsafe
fallback, weakened oracle or unrun qualifier may be called proper support.
A failed prerequisite changes the next investigation, not the requested goal.

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
each Linux layout. Scope still pins a2aab6cd: unpublished-source restoration,
actual BPF compilation and coherent observer integration remain next.

Raw prerequisite evidence is retained under
`p11scope-ws/incoming/2026-09-07-abi-qualification/`; module results under
`incoming/2026-09-07-abi-research/`; proxy and canonical-gate results under
`incoming/2026-09-07-release-local/`. These are prerequisite receipts, not W8.
