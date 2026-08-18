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
| `gate-a/` | Retained Gate A six-file evidence exports and `.sha256` inventories (jammy, noble) and the retained longer-diagnostic exports |
| `gate-b/` | Gate B exports (appended when produced) |
| `loader/` | Loader witness harness canonical round-2 transcripts and artifacts (`loader/round2/`), retained round-1 diagnostics (`loader/round1/`) |
| `bundles/` | Frozen execution bundles (`task4-37c5b41-bundle/`: runner, fixture, `slice1b2-kernel-ebpf`, manifests) |
| `MANIFEST.sha256` | SHA-256 of every file in the root except itself. Digest: `28ff46e109d4c528319d796617ba3338ed65bb9f4c2833f5441026991c57894b` |

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

(filled by Task 2; diagnostic lanes are never promoted to tracked gate
results.)

## Final A/B campaign (Task 5)

(filled by Task 5: frozen bundle digests, campaign identity incl. `accel`,
per-kernel results.)

## Loader precontrols (Task 6) and event-path facts (Task 7)

(filled by Tasks 6–7.)
