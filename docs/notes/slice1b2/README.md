# Slice 1b-2 private evidence root — layout and pinned digests

Raw and generated evidence for the Slice 1b-2 gates is **never tracked in
git**. It lives outside the tree under
`~/src/m/pkcs11-scope-evidence/slice1b2/` (mode `0700`), is enumerated by a
SHA-256 manifest, and this file carries only digests, pointers, and finite
facts. Nothing under that root is release output; private spike bundles are
separately permissioned (corrective design §9.4).

## Evidence root layout

| Path (under `~/src/m/pkcs11-scope-evidence/slice1b2/`) | Contents |
| --- | --- |
| `analyses/` | The four design-pinned corrective analyses plus every other retained `slice1b2-*.md` analysis/report from `/tmp` (raw addresses and paths inside; private) |
| `gate-a/` | Retained Gate A six-file evidence exports and `.sha256` inventories (jammy, noble), the retained longer-diagnostic exports, and the D2 diagnostic lane run dirs (`diag-*`; disposable `runtime.qcow2` overlays deleted after each verified clean shutdown — retained bases were hash-pinned before/after in `retained.*.sha256`) |
| `gate-b/` | Gate B exports (appended when produced) |
| `loader/` | Loader witness harness canonical round-2 transcripts and artifacts (`loader/round2/`), retained round-1 diagnostics (`loader/round1/`) |
| `bundles/` | Frozen execution bundles (`task4-37c5b41-bundle/`: runner, fixture, `slice1b2-kernel-ebpf`, manifests; `diag-9da22b6-bundle/`: same BPF + fixture bytes re-frozen with the `gate-a-diag` runner) |
| `MANIFEST.sha256` | SHA-256 of every file in the root except itself. Digest: `a7b8d0ba62b0b9a528fd77dc937d58020abf74559815d3a1a06f80abad0b0bf7` |

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

## Gate status (two lines each, from the open-issues note)

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

## Final A/B campaign (Task 5)

(filled by Task 5: frozen bundle digests, campaign identity incl. `accel`,
per-kernel results.)

## Loader precontrols (Task 6) and event-path facts (Task 7)

(filled by Tasks 6–7.)
