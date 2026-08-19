# Slice 1b-2 private evidence root — layout and pinned digests

Raw and generated evidence for the Slice 1b-2 gates is **never tracked in
git**. It lives outside the tree under
`~/src/m/pkcs11-scope-evidence/slice1b2/` (mode `0700`), is enumerated by a
SHA-256 manifest, and this file carries only digests, pointers, and finite
facts. Nothing under that root is release output; private spike bundles are
separately permissioned (corrective design §9.4).

## Historical research-plan handoff (2026-08-19)

The exact results below remain immutable, but their former promotion wording
is superseded. The `a227dab` Gate B object used a winner-side busy wait. A later
no-busy-wait frozen campaign recorded 120/120, all as outcome B, but controller
and independent review found owner-2 cleanup, outcome-A causal-deadline, and
oracle-contract defects. Neither campaign is product evidence. Promotion is
blocked; the amended campaign is `UNRUN` under
`docs/superpowers/specs/2026-08-19-slice1b2-no-busy-wait-pause-amendment.md`.

Final source commit `a227dabe7ab0fb62eee6ec9cca1f4afbad46eb03`:

- A/B BPF `e4973fd03ffb4d24cd81ab6c84c395ad18c90e23e28ae782c48328f4fce8b069`:
  Gate A PASS on Jammy 5.15 and Noble 6.8; Gate B KVM campaign PASS 120/120
  (three boots × 20 per kernel). Confirmed-stop latency min/median/max was
  1175/1250/3132 µs on Jammy and 1200/1245/3973 µs on Noble.
- The same Noble Gate B campaign under TCG is retained as
  `TIMEOUT / INCOMPLETE` (three boots, no first verifier record within 120 s).
  STATS-only diagnostic accepted `signal_return` with 150,091 verified
  instructions in 1028 ms under KVM and 253,049 ms under TCG. KVM is therefore
  the supported research-gate accelerator; the BPF was not rejected.
- Loader BPF `0bc026b49db29f5e6beb220ca988b9a1da8af071c912109eab94bb6a9e74a877`:
  ptrace-free event path PASS on both kernels, including the 5.15 runtime-IP
  fallback and the no-cookie negative.
- Task 8: 160/160 independently validated attempts across host 7.0 and Noble
  6.8. One pause covers exported symbols; hidden table constructor calls
  escaped 40/40 one-pause attempts and were covered 40/40 with a second owned
  pause. Decision D3 is **no**: Task 9's timing catalog is skipped on the
  critical path. See `attach-first-vs-timing-catalog.md`.

This completed the historical research plan, not Slice 1b-2 product support.
P4 remains: land Slice 1b-1, implement and re-prove the amended no-busy-wait
A/B lifecycle, then implement `discovery::Engine`, dynamic slots/cookies, and
loss/completeness evidence.

The remaining sections preserve the earlier campaigns and failure progression
for provenance. Their `UNRUN`, `FAIL`, and `TIMEOUT / INCOMPLETE` results stay
valid for those exact campaign identities; the final handoff is additional
evidence from later frozen artifacts.

## Evidence root layout

| Path (under `~/src/m/pkcs11-scope-evidence/slice1b2/`) | Contents |
| --- | --- |
| `analyses/` | The four design-pinned corrective analyses plus every other retained `slice1b2-*.md` analysis/report from `/tmp` (raw addresses and paths inside; private) |
| `gate-a/` | Retained Gate A six-file evidence exports and `.sha256` inventories (jammy, noble), the retained longer-diagnostic exports, and the D2 diagnostic lane run dirs (`diag-*`; disposable `runtime.qcow2` overlays deleted after each verified clean shutdown — retained bases were hash-pinned before/after in `retained.*.sha256`) |
| `gate-b/` | Gate B evidence exports and run dirs (Task 5 campaign `final6-*`, retained iteration/failing-run evidence `final1`–`final5`, `task4-*`) |
| `loader/` | Loader witness harness canonical round-2 transcripts and artifacts (`loader/round2/`), retained round-1 diagnostics (`loader/round1/`), round-3 released-glibc precontrols (`loader/round3/`) |
| `loader-artifact/` | Task 7 loader-event lanes (`{jammy,noble}-20ecebd/`: five-file exports + `.sha256`) |
| `task8/` | Final host/Noble attach-first evidence for exported/hidden providers with one/two pauses |
| `bundles/` | Frozen execution bundles, including final `final-a227dab-bundle/`, `loader-a227dab-bundle/`, and the bounded `gateb-stats-a227dab-bundle/` diagnostic |
| `diagnostics/` | Bounded STATS-only diagnostics and their exact private patch/bundle identities; never canonical gate replacements |
| `MANIFEST.sha256` | SHA-256 of every file in the root except itself (3,196 files after Task 8). Digest: `dee02a5418bea166aa22eaaebd1bc13cd68d6fd9822f27c53fa7970835954d86` |

The tracked, scrubbed witness harness itself is `spike/slice1b2-loader/`
(repo-relative `run-lanes.sh`, lane-filterable, driven by
`P11SCOPE_LOADER_EVIDENCE` which defaults to the `loader/` directory above).

## Design-pinned inputs (corrective design §2)

| Analysis (under `analyses/`) | SHA-256 |
| --- | --- |
| `slice1b2-gatea-corrective-analysis.md` | `a8578527c2e63aaffe73f0233823570e4bde491286a7f95d4f2a4e929dfa79a8` |
| `slice1b2-gateb-variance-analysis.md` | `2abc938c0516f4403a655da0bcee15cc0ec49afcb3d3a131982910759efee3c8` |
| `slice1b2-loader-corrective-analysis.md` | `89ed5bf3d52912e596be49b13396216e1cf40a4e31120358cf7820d567e74374` |
| `slice1b2-corrective-design-cross-review.md` | `31ca2a2ffc8de95fc4c3439dd650ae69dc5a7759fbe4b59ab464d56991b55557` |

Retained decisive binary evidence (digests in the corrective design §2):
final six-program spike BPF object `d405edee…` is inside
`bundles/task4-37c5b41-bundle/slice1b2-kernel-ebpf`; canonical loader
transcripts are under `loader/round2/`.

## Historical pre-corrective gate status

- **Gate A (four discovery programs):** `TIMEOUT / INCOMPLETE` on both 5.15
  and 6.8; exactly 3/4 accepted records. The existing fourth-program shape is
  not promotable; the approved flat 112-store initializer must be implemented
  and rerun on the final unchanged A/B object.
- **Gate B (pause/attach timing):** historical Jammy variance (Task 3 FAIL at
  run 19, later Jammy PASS 20/20, Noble PASS). The old runner never actually
  waited its stated 100 ms; the corrected 100 ms aggregate oracle is designed
  but UNRUN — pause stays default `never`, unprotected capture stays
  `PARTIAL`.
- **Gate C (loader/glibc timing):** direct current-build controls complete
  (musl positive; glibc 2.35/2.39 negatives); corrected product-shaped
  campaign UNRUN.
- **Slice 1b-1 semantic authority:** owner-approved; implementation in
  progress on the recovery branch. Not touched by the Slice 1b-2 plan.

## Diagnostic (D2, STATS-only) results

`run.sh diag-lane` (D2-approved diagnostic; **never** the frozen
`VERBOSE | STATS` gate — the tracked Gate A result remains
`TIMEOUT / INCOMPLETE`) ran on the retained frozen object
(`d405edee…`) re-frozen with the `gate-a-diag` runner
(`bundles/diag-9da22b6-bundle/`, source `9da22b6`). One line per program in
each `diag.jsonl` under `gate-a/diag-*`:

| Lane | Kernel (guest) | Accel | boot-to-SSH | `interface_list_return` verdict |
| --- | --- | --- | --- | --- |
| jammy KVM | 5.15.0-187-generic | kvm | 13.7 s | rejected, errno 7 (E2BIG) in 1326 ms |
| noble KVM | 6.8.0-137-generic | kvm | 13.9 s | rejected, errno 7 (E2BIG) in 1094 ms |
| jammy TCG | 5.15.0-187-generic | tcg | 55.7 s | rejected, errno 7 (E2BIG) in 13883 ms |
| noble TCG | 6.8.0-137-generic | tcg | 86.2 s | rejected, errno 7 (E2BIG) in 17880 ms |
| host (root, not an endpoint) | 7.0.0-28-generic | — | — | rejected, errno 7 (E2BIG) in 3292 ms |

Finite failure facts (I2): errno `7` (E2BIG), `BPF program is too large.
Processed 1000001 insns (limit 1000000)` — identical verdict text on all five
lanes. Bounded stats per lane (jammy KVM / noble KVM+noble TCG / host):
`max_states_per_insn` 41/40/41, `total_states` 17742/10754/10774,
`peak_states` 7707/9404/1004, `mark_read` 78/76/0, stack depth
`32+56+40+0`. `verified_insns` (accepted programs, 6.8/7.0; `null` on 5.15):
`function_list_entry` 33, `interface_list_entry` 33,
`function_list_return` 11175 (11159 host) — the per-fan-out cost basis for
research question 1: 16 × 11175 ≈ 179k processed insns, far under the 1 M
limit, predicting Task 3's flat initializer fits without touching the
16/104 ceilings.

The rejection is real and deterministic; what TCG inflated was duration and,
via Aya's `VERBOSE` retry loop, the historical 16,777,679-byte log whose
`ENOSPC` hid this first-attempt errno. Even under TCG the STATS-only lane
finishes with the canonical verdict (Noble TCG 17.9 s vs the historical
"no verdict inside 600 s").

### After Task 3's flat initializer (diagnostic; tracked Gate A rerun is Task 5)

With the 112 flat `write_volatile` zero stores (object
`896c8205…`, bundle `bundles/flatinit-f4baac0-bundle/`, source `f4baac0`;
`check-init-shape.py` PASS is part of `build-bpf`), the same diagnostic lane
accepts **all four programs on both kernels**:

| Lane | Kernel | `interface_list_return` | `function_list_return` insns |
| --- | --- | --- | --- |
| jammy KVM | 5.15.0-187 | accepted in 150 ms (insns `null` on 5.15) | `null` |
| noble KVM | 6.8.0-137 | accepted in 38 ms, **149,033 verified insns** | 2,629 |

149,033 processed insns is 6.7× under the 1 M limit — the ×16 prediction
basis above held (predicted ≈179k). The `function_list_return` shrink
(11,175 → 2,629) confirms the memset-shaped initializer was also that
program's dominant cost. No ceiling, cap, timeout, or oracle value changed.

## KVM lane (D1 one-time enablement; Task 1)

`P11SCOPE_SPIKE_ACCEL=kvm` selects `-accel kvm -cpu host` (default stays
`tcg`, the frozen behaviour); every lane records `host-accel.txt`, guest
`virt.txt` (`kvm` under KVM, `qemu` under TCG), and `boot-to-ssh.txt`.
Enablement: persistent `usermod -aG kvm user` (lanes launched through
`sg kvm -c '…'`; a non-persistent `setfacl` grant was wiped by udev re-sync
and is not relied upon). KVM and TCG lanes are different campaign identities
and are never mixed inside one campaign. One-time provision under KVM:
3 m 44 s total (boot-to-SSH 27 s). Per-guest boot-to-SSH figures are in the
diagnostic table above (kvm 13.7/13.9 s vs tcg 55.7/86.2 s; both < 60 s
under KVM as expected).

## Retained earlier A/B campaign (Task 5)

Frozen bundle `bundles/final6-9daeb53-bundle/` (source `9daeb53`):
`slice1b2-kernel-ebpf` `fa3b6e13e87e16419793c2156220212776ebd29d223cd124f5363e3c710f3bfc`,
`slice1b2-runner` `3982fa59c78f3eef87d18af48703866f1856d74ed08de226b0c3902db112573a`,
`slice1b2-fixture` `a07b3469f33c96d8df1ebcd31dae763abd8b80fb7bc57b8f755005930d05ecf3`
(guest-built), `source-elf.manifest` `77483986d0db7946541fa54b498b43ee416628790a3ff5c993baa47da1081f6d`.
Campaign `20260818T223024`, all lanes under one accelerator (**kvm**, recorded
in each run dir's `host-accel.txt`/`virt.txt`); 16/104 ceilings and every
oracle value unchanged. One post-freeze harness-only fix `8090f26`
(zombie-qemu cleanup race; no kernel/runner/fixture byte changed):

- diag `diag-final6-{jammy,noble}-kvm-…`: PASS, all four programs accepted.
- Gate A `final6-gatea-{jammy,noble}-kvm-…`: PASS (4 accepted programs,
  5 cases, 4 maps each).
- Gate B jammy `final6-jammy-kvm-…-boot{1,2,3}`: 3×20 = **60/60 PASS**.
- Gate B noble `final6-noble-kvm-…-boot{1,2,3}` + `…-boot1b` (rerun):
  boot1 was **semantic 20/20 PASS** (`runner-status.txt status=PASS`) but its
  lane exit was FAIL rc=1 — the pre-fix zombie-qemu cleanup crash aborted
  after evidence export (post-shutdown immutability checks missing for that
  boot; evidence retained under the boot1 dir). boots 2/3 and the clean
  rerun boot1b: **60/60 PASS** with full post-checks.
- Gate B totals: **120/120 semantic PASS** across 5.15 and 6.8.
- Confirmation timing (winner→both-stopped sample gap, µs): jammy
  min/median/max 1079/1146/1526; noble 1120/1141/1494 (80 runs incl.
  boot1). Winner split jammy 30/30, noble 44/36 — the symmetric CAS wins
  from either hook.

Three fixture/oracle races were root-caused and fixed before the final
campaign (`fa07ee3` marker barrier, `d0c3e6a` Gate A maps-read retry,
`7207d1d` oracle case-ID order), then the decisive Gate B hook-phase race:
ftrace ground truth (iter5/iter6 traces under `gate-b/final5-*` and
`/tmp` iteration logs; preserved in the failing-run evidence) shows the
CAS loser reaching return-to-user with the group stop already pending —
its deferred uprobe handler never runs, so its record is never submitted
(`second signal record timeout`). Fixes, in order: `f90d2af`/`98ba017`
user-mode spin barrier + pre-positioned release (50%→~75% completion),
`1c970d2` CPU pinning + RT worker + `taskset -c 0` lane runners (~38%
under load), and the decisive `9daeb53` bounded **winner-side delay** in
`signal_return` (50,000 ktime polls between the owner CAS and the single
`bpf_send_signal(19)`, verifier-provable on 5.15 where a wall-clock loop
is rejected as infinite; iteration `iter7`: 8×20 = 160/160 PASS on
jammy before the campaign).

## Loader precontrols (Task 6) and event-path facts (Task 7)

### Task 6 — released-glibc controls and DT_NEEDED precontrols (COMPLETE)

Harness commits `d374bb2` (lanes/kind/provenance), `fedcb1e` (dl-open.c discovery
depth fix), `cfb9975` (provenance grep widened to the signalling lines); full
provenance in `glibc-31986-provenance.md`.

Lanes run from committed HEADs on `spike/slice1b2-gates`; transcripts at
`loader/<lane>-<kind>-transcript.log`, per-run artifacts under `loader/round3/artifacts/<lane>-<kind>/`
(the round-2 snapshot is preserved untouched). Container names `p11scope-slice1b2-r3-*`.

- **Step 2 (dlopen, new lanes)**: `glibc-241-debian13` (libc6 2.41-12+deb13u3) **PASS**
  and `glibc-24x-ubuntu2604` (libc6 2.43-2ubuntu2.3) **PASS** — first post-`RT_ADD`
  `RT_CONSISTENT` witness `PASS_EQUAL` before ctor; source provenance shows
  `_dl_relocate_object` (dl-open.c:486) before `_dl_debug_change_state (r, RT_CONSISTENT)`
  (dl-open.c:784) in the as-shipped 2.41 source; no reverting patch.
  A first attempt (`glibc-241-debian13-dlopen-attempt1-harness-bug.log`) BLOCKED on a
  harness bug (find depth); preserved.
- **Step 4 (initial_set, all five lanes)**: **PASS ×5** — 2.35, 2.39, 2.41, 2.43, musl.
  Each glibc transcript retains the earlier startup hit as `PRE_MAPPING`
  (`r_state=1`, witness `BLOCKED`) before the decisive `RT_CONSISTENT` hit.
  This confirms the bug-31986 defect is **dlopen-path-specific**: startup signals
  `RT_CONSISTENT` after relocation on every glibc tested (as the `43db5e2c` commit
  message states), while the round-2 dlopen transcripts keep `FAIL_ZERO` on 2.35/2.39.
- Round-2 history (dlopen kind) unchanged: 2.35/2.39 `FAIL` (`FAIL_ZERO`), musl `PASS`.

(Task 7 below.)

### Task 7 — initial ptrace-free loader event rounds (historical)

Artifact crates `spike/slice1b2-loader-bpf/` (own aya-ebpf crate: `dl_debug_state`
uprobe on the 896-byte `DiscoveryRecord`, kind LOADER=3, §7.3 cookie
validation, 112 flat volatile zero stores guarded by `check-init-shape.py`,
§5.3 owner-CAS pause path, every-hit record) and `spike/slice1b2-loader-host/`
(own Rust 1.88 runner: cookie round-trip, 256-slot monotonic registry,
pre-exec attach through the fixture `PT_INTERP`, §8.1 no-cookie negative,
own `run.sh` lanes; the A/B `spike/slice1b2-kernel/` artifact is untouched —
freeze boundary respected). Commits `7b33632`..`23f853a` (highlights:
`9ba2ade` lane-kernel prefix match fix, `6d53950` `.bss` `_r_debug` + exec-gated
bias + invalid-cause counters, `20ecebd` facts row categories, `eee28e9`
validator startup-only `loader_sha256`, `23f853a` export-dir cleanup).

Frozen bundle `bundles/loader-20ecebd-bundle/` (source commit `20ecebd`):
`slice1b2-loader-bpf` `e20988ad8504a47bf27c0d6e1de6dd354634508ae5c246acfac671b0b6f95e60`,
`slice1b2-runner` `bbf43c23889f807019dd7bb2b5ba471358676c016557f3fad210343dcb673298`,
`slice1b2-fixture` `f84b8aace82bbb18fa2c96ec05eddafbfedbef09102429e00292d70155d1a872`,
`source-elf.manifest` `b07be4204ceb129458137189b942e921b77c72ef1db7139a721e6c02c1347342`.
Lane evidence under `loader-artifact/{jammy,noble}-20ecebd/` (final lanes run
from `23f853a` harness; the runner/bpf bytes are the frozen `20ecebd` bundle).

- **Noble 6.8 (glibc 2.39), KVM: PASS.** `loader-diag` accepted; startup flow:
  2 hits with `r_states == [1, 0]` (`RT_ADD` then `RT_CONSISTENT`),
  `formula_holds` (hook IP == load bias + `_dl_debug_state` vaddr),
  `derived_debug_address_ok` (hook IP + cookie delta == load bias + `_r_debug`
  vaddr), 0 invalid records, 0 read failures, START empty at exit, registry
  decodable after tombstone; no-cookie negative: exactly one
  `loader_context_invalid` record, `cookie_zero_hits == 1`, no IP/state/case-id
  operation. `runner-status`: `PASS / none`.
- **Jammy 5.15 (glibc 2.35), KVM: FAIL(oracle) — kernel limitation proven.**
  The program loads (diag PASS), cookies ARE delivered (`cookie_zero_hits == 0`),
  the `.bss` `_r_debug` delta is carried (`state_present_delta == true`), the
  no-cookie negative PASSES, but `func_ip_zero_hits == 2`: **`bpf_get_func_ip`
  returns 0 for perf uprobes on 5.15.0-187**, so both startup records take the
  `loader_context_invalid` path (status 0x04) and the formula/r_state oracles
  cannot hold. This is a first-class endpoint fact for D3: a 5.15-compatible
  hook-IP derivation (e.g. reading `pt_regs.ip` from the probe context) would
  be a spec change, not taken unilaterally.
- Fix provenance (earlier lanes under `bundles/loader-{9ba2ade,6d53950}-bundle/`,
  preserved): `state_present_delta == false` on both guests was the host-side
  `.bss` rejection; `formula_holds == false` on 6.8 was the pre-`execve` bias
  poll reading the runner-inherited loader mapping (now gated on
  `/proc/<pid>/exe` == fixture).

The final `7cfda3d` correction validates the x86-64 runtime-IP fallback on
5.15 without accepting arbitrary hook addresses. The re-frozen `a227dab`
loader bundle then passed Jammy and Noble, including the no-cookie negative;
those final results and hashes are in the handoff at the top of this file.
