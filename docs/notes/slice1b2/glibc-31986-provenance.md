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

All facts below come from `PROVENANCE_*` / `OBJECT_IDENTITY` lines recorded inside each
container by `inside.sh` (transcripts under the evidence root `loader/`). `apt-get
source glibc` runs with `deb-src` enabled and **unpacks with the distribution patches
applied**, so the `elf/dl-open.c` line numbers cited below are the final,
as-shipped source — a reverting patch would have to appear in those lines to matter.

### glibc-241-debian13 (the fixed-glibc candidate)

- `LIBC6_VERSION=2.41-12+deb13u3`, `GNU_LIBC_VERSION=glibc 2.41`
- source package `glibc_2.41-12+deb13u3.dsc`, SHA-256 `aa1ab10010fcf169454a5c6a123094a3997392922593d86a3a5adc180a07ca40`
- `elf/dl-open.c` ordering (transcript `PROVENANCE_DL_OPEN_BEGIN/END`): relocation
  processing `_dl_relocate_object` at line 486 precedes the debugger signal
  `_dl_debug_state` at line 784
  — **post-fix ordering present**. In 2.41 the signal is wrapped in
  `_dl_debug_change_state (r, RT_CONSISTENT)` (43db5e2c's shape).
- `debian/patches` touching `elf/dl-open.c`: only `git-updates.diff` (Debian's catch-all
  upstream-cherry-pick bundle); the unpacked (patched) source above already carries the
  fix, so no revert.
- loader/libc (per `OBJECT_IDENTITY`):
  `libc.so.6` SHA-256 `fa430b8f298f817a266046af84a77533185ad6fc4406c7d3787b5a0a0c207826`,
  build ID `c495b62edadd6c356265942ec1282d98058a7b41`;
  `ld-linux-x86-64.so.2` SHA-256 `438c546d8e8cc48496bf3a95f753051afd9db66a629a74e31a9ded71586b56e0`,
  build ID `c591a5df63f461bfdafb01908ca16845b375fa37`.

### glibc-24x-ubuntu2604 (precontrol/spare)

- `LIBC6_VERSION=2.43-2ubuntu2.3`, `GNU_LIBC_VERSION=glibc 2.43`
- `glibc_2.43-2ubuntu2.3.dsc`, SHA-256 `03960a632c77159f4281f46d8c9bead7d9754fa46b30b354361d76f876eb3ef8`
- same post-fix ordering shape as 2.41 (`_dl_relocate_object` … `_dl_debug_change_state (RT_CONSISTENT)`).
- patches touching `dl-open.c`: only `git-updates.diff`, and there merely in a
  documentation line (`+#: elf/dl-close.c:363 elf/dl-open.c:297`) — no revert.
- `libc.so.6` SHA-256 `a3947513a02831ec692ebf13053c07614882ab54a2101fb91a1b15724062ed0c`,
  build ID `240c8909736b31f963346aca80667fd00c551e32`;
  `ld-linux-x86-64.so.2` SHA-256 `c5e80a563850d6ab5c2f2482e4202d9c1b71fbf44854b8c399e63527202c64e1`,
  build ID `d4bfd49ced9d6e19bb77f23bf6872b8d270a9712`.

### glibc-235-ubuntu2204 / glibc-239-ubuntu2404 (unfixed precontrols)

- 2.35: `LIBC6_VERSION=2.35-0ubuntu3.14`, `glibc_2.35-0ubuntu3.14.dsc` SHA-256
  `664a969f5ee1041221a3771e8a2956124a54ec40948287c34991a0a87d0fa0a4`;
  `libc.so.6` build ID `22ca0a83a4004122e30a69b597be96e134068616`, loader build ID
  `63cab9adbb271847e9c8d0baa6305bb80d6ada2e`.
- 2.39: `LIBC6_VERSION=2.39-0ubuntu8.8`, `glibc_2.39-0ubuntu8.8.dsc` SHA-256
  `69c09b540d03e56b3adee7c4af98b862bfc36789795c9e21d37e58e699f57b00`;
  `libc.so.6` build ID `328820b908de8ea1ef79afa8995e302e819163d7`, loader build ID
  `f58808c9c8a388055b126492a1706d732761f86e`.
- Contrast (2.35 transcript): the debugger signal sits at `dl-open.c` lines 620–621
  (`r->r_state = RT_CONSISTENT; _dl_debug_state ();`) **before** relocation processing
  at lines 689/702 (`_dl_relocate_object`) — the pre-fix ordering, i.e. the bug 31986
  signature is visible in the as-shipped source of both lanes. No
  `debian/patches` file touches `dl-open.c` in either (scan: NONE).

## Runtime witness results (Step 2 = dlopen kind, Step 4 = initial_set kind)

| lane | glibc | `dlopen` | `initial_set` |
|---|---|---|---|
| `glibc-241-debian13` | 2.41 | **PASS** (`PASS_EQUAL` at first post-`RT_ADD` `RT_CONSISTENT`, before ctor) | **PASS** |
| `glibc-24x-ubuntu2604` | 2.43 | **PASS** (same shape) | **PASS** |
| `glibc-235-ubuntu2204` | 2.35 | **FAIL** (`FAIL_ZERO`, round-2 canonical transcript) | **PASS** |
| `glibc-239-ubuntu2404` | 2.39 | **FAIL** (`FAIL_ZERO`, round-2 canonical transcript) | **PASS** |
| `musl-alpine3241` | musl | **PASS** (round-2 canonical transcript) | **PASS** |

Reading: the defect is confirmed **dlopen-path-specific**. The startup (`initial_set`)
path signals `RT_CONSISTENT` after relocation on every glibc tested (including the
unfixed 2.35/2.39), exactly as the `43db5e2c` commit message states; the dlopen path
is fixed first in 2.41 (Debian 13 = the released fixed-glibc control; Ubuntu 26.04's
2.43 concurs). Each `initial_set` glibc transcript retains the earlier startup hit as
`PRE_MAPPING` (`r_state=1`, witness `BLOCKED`, DSO mapping not yet exact-matched)
before the decisive `RT_CONSISTENT` hit, per the precontrol definition. No FAIL/BLOCKED
in any `initial_set` lane; the two new `dlopen` lanes PASS — no first-class finding
against the fix.
