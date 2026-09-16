# Cgroup-256 follow-up: the I/O byte ceiling binds first (plain builds)

Date: 2026-09-16. Follows `2026-09-16-cgroup-256-trace-everything.md`, whose
kill chain (512-candidate ceiling, observed in a `--features
skip-attribution` build) is NOT what binds first in plain builds.

## Corrected kill chain (measured, A/B)

- Branch (`refactor/extraction-rename` @ 3c9b32f, Tasks 1–4) vs main
  (pre-fix), same root-cgroup capture (~390–556 procs): IDENTICAL outcome —
  0 slots, 0 probes, 0 tables, `uniq_found=False`. Tasks 1–4 did not regress
  anything (single-pid control identical: 136 slots / 272 probes before and
  after) but did not fix the symptom either.
- Refusal census of the branch run: 225 of 226 refusals are
  `initial mapping validation unavailable: capture attempted-I/O ceiling
  reached`. The 512 MB `total_bytes` budget dies before anything decodes.
- Single-variable flip: `total_bytes` 512 MB → 16 GB (diagnostic only,
  reverted, never committed): same binary, same scope → 3 providers
  (p11-kit-trust + 2× softhsm), 204 slots, 408 probes, 6092 table entries.
  Evidence: `/tmp/256-noio-16gb.json` (vs `/tmp/256-scale-post-tasks.json`
  at 512 MB and `/tmp/256-scale-main-prefix.json` for main).
- Small-scope controls: smartcard-only cgroup (1 proc) → full discovery on
  the branch binary; shell scope (45 procs, no providers) → correctly empty.
  The cgroup deep path works; scale kills it via I/O accounting.

## Implied real fix (Fix A2, not yet built)

Identity-dedup must cover READS (bytes), not just candidate counts. The
512 MB is dominated by whole-file reads (per-view hashing of the same
shared objects — e.g. libc ×390 views), not by per-view mem-table bytes
(mem bytes legitimately differ per process due to relocation and must
still be read per view). Durable fix: cache file hashes/bytes by
(device, inode) per capture; first read charges, repeats are free.
Raising the ceiling is diagnostic only, not the fix.

## Incidental bugs found (same session, new-flag path)

- `--max-scan-pids 600` dies with `capture process-view capacity 256 is
  exhausted`: the view-ID allocator ceiling (const 256) ignores the
  configured cap, so any cap above 256 live views is unreachable.
- That exhaustion is FATAL (exit 1, no `-o` evidence file) instead of a
  published PARTIAL. Exhaustion must degrade to evidence, never to nothing.
