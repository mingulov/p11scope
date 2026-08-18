# glibc 31986 fix provenance — released-package controls (Slice 1b-2, Task 6)

This note records why the two new container lanes count as **fixed-glibc controls** for
the discovery-engine design (spec §7.2/§8.1): the rule is that a *version* only selects
which lanes run; **source provenance plus the runtime witness classify**. The runtime
witness is the GDB `/proc/<pid>/mem` direct read (`gdb-direct-witness.py`) over the
same `fixture_relocated_puts` relocation used by every loader lane.

## The two upstream commits

- `43db5e2c0672cae7edea7c9685b22317eae25471` (2024-10-25) —
  "elf: Signal RT_CONSISTENT after relocation processing in dlopen (bug 31986)"
- `ac73067c` (2024-10-25; short SHA as recorded at plan time) —
  "elf: Fix map_complete Systemtap probe in dl_open_worker" (follow-up to the first)

## Containment in glibc 2.41

Verified during plan approval (2026-08-18) via the GitHub mirror compare API: both
commits are 263/264 commits *after* the `glibc-2.40` tag and ancestors of the
`glibc-2.41` tag, i.e. **first released in glibc 2.41** (released 2025-01-30,
<https://sourceware.org/pipermail/libc-announce/2025/000045.html>). No glibc clone is
kept on the evidence host; the compare output recorded at plan time is the containment
proof of record. Consequence: glibc 2.35 (Jammy) and 2.39 (Noble) do **not** contain
the fix; glibc ≥ 2.41 does, unless a distribution reverts it (checked below).

Corollary used by the `initial_set` precontrol: the `43db5e2c` commit message states
that startup (`elf/rtld.c`, end of `dl_main`) already signalled `RT_CONSISTENT` after
relocation — so the DT_NEEDED/initial-set lane is expected positive even on 2.35/2.39,
isolating the defect to the `dlopen` path.

## Image pinning (Step 1)

| lane | image ref (pinned) | RepoDigest | ImageId |
|---|---|---|---|
| `glibc-241-debian13` | `debian:13` | `debian@sha256:34cd9e9fd437c0a095ec39cb2e73422c9f30821b0d0848ed74fd0d43bae4d958` | `sha256:826a5616954ee645ca5c165d4c8c960d4d8d444347838cf7bdc1ac555385358b` |
| `glibc-24x-ubuntu2604` | `ubuntu:26.04` | `ubuntu@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03` | `sha256:86a1a31fdd84f2dc79bd6d92272100d4369b085790753bc521069eab663074e9` |

Debian 13 ships libc6 2.41 (<https://packages.debian.org/trixie/libc6>); Ubuntu 26.04
ships a later glibc (precontrol/spare only — the single fixed-glibc candidate for any
follow-on work is Debian 13).

## Runtime source provenance (filled from the Step 2/Step 4 transcripts)

PENDING — recorded per lane after the lanes run: `LIBC6_VERSION`, `GNU_LIBC_VERSION`,
source-package `.dsc` SHA-256 and version, the `PROVENANCE_DL_OPEN_BEGIN/END`
neighbourhood of `elf/dl-open.c` from `apt-get source glibc` inside the container
(confirming the post-fix ordering — the `RT_CONSISTENT`/`_dl_debug_state` call after
relocation processing), the `debian/patches` scan for any `dl-open.c`-touching patch,
and loader/libc SHA-256 + build IDs.

## Runtime witness results (filled from the Step 2/Step 4 transcripts)

PENDING — `GDB_FINAL_CLASSIFICATION` per lane × load kind, including the three
pre-existing lanes (round-2 history: 2.35 and 2.39 `dlopen` lanes classify
`FAIL`/`FAIL_ZERO` — the bug-31986 signature; musl `PASS`).
