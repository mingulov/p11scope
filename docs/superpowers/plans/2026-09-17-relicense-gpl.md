# Re-license to GPL-3.0-or-later (+ GPL-2.0-only BPF) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-license p11scope per the owner's spec: userspace/docs/scripts GPL-3.0-or-later, BPF programs GPL-2.0-only, CLA-style contribution policy, no commercial/dual-licensing mention.

**Architecture:** Mechanical, fully offline change: license texts from `/usr/share/common-licenses/` (verified present), SPDX headers via scripted insertion with per-file verification, manifest/license-doc updates, and a license meta-test pinning the new shape. BPF `SEC("license")` verified on the built object with readelf.

**Tech Stack:** Shell scripting, SPDX headers, `/usr/share/common-licenses/GPL-3` + `GPL-2` texts.

**Spec:** `/home/user/src/m/bpf_lic.md` (owner's re-license directive, Russian original — key lines: repo = userspace Rust GPL-3.0-or-later, docs/scripts GPL-3.0-or-later, BPF programs GPL-2.0-only; `LICENSE` with GPLv3 text + `LICENSES/GPL-2.0-only.txt`; per-file SPDX tags; CLA granting broad sublicensing/relicensing rights; README must NOT mention commercial/dual licensing).

## Global Constraints

- Fully offline: license texts ONLY from `/usr/share/common-licenses/` (verify SHA against a second local copy if one exists — `find / -name "GPL-3" 2>/dev/null` — else record single-source).
- Every `cargo test`/`build` invocation prefixed with `TMPDIR=/var/tmp/p11scope-ws-tmp`; toolchain `cargo +1.88 --locked --offline`.
- SPDX header formats (exact):
  - Rust: `//! SPDX-License-Identifier: GPL-3.0-or-later` as the FIRST line (crate docs stay below).
  - Python: `# SPDX-License-Identifier: GPL-3.0-or-later` after shebang (or first line).
  - Shell: `# SPDX-License-Identifier: GPL-3.0-or-later` after shebang.
  - Markdown: `<!-- SPDX-License-Identifier: GPL-3.0-or-later -->` as the FIRST line.
  - BPF files (`crates/ebpf/src/main.rs`, `scripts/native/dump-task-storage.bpf.c`): same formats with `GPL-2.0-only`.
- No `sudo`, no network, no new dependencies. Branch `fix/relicense-gpl`, worktree `.worktrees/fix-relicense-gpl`; never commit on main; never push.
- /tmp EDQUOT is a known environmental gate hazard: triage per `known-flakes.md`, preserve full logs, never weaken seal tests.

---

## Task 1: License texts + manifests + README + contribution policy

**Files:**
- Create: `LICENSE` (GPL-3 verbatim), `LICENSES/GPL-2.0-only.txt` (GPL-2 verbatim), `CONTRIBUTING.md` (CLA-style policy per spec: public license lines + "Contributions: CLA granting broad sublicensing/relicensing rights" + DCO-style sign-off mechanics WITHOUT claiming DCO grants relicensing).
- Modify: 5 `Cargo.toml` `license` fields (root + discover + ebpf-common + manifest → `GPL-3.0-or-later`; `crates/ebpf` → `GPL-2.0-only`); `README.md` License section (GPL-3.0-or-later + BPF note + pointer to CONTRIBUTING; NO commercial/dual mention).
- Delete: `LICENSE-MIT`, `LICENSE-APACHE` (`git rm`).

**Interfaces:**
- Consumes: nothing.
- Produces: the legal surface; Task 2 headers reference these identifiers.

Recon-owned counts (verify): 5 Cargo.toml files with `^license` lines; README license section at :304-307.

- [ ] **Step 1: Copy texts.** `cp /usr/share/common-licenses/GPL-3 LICENSE`, `mkdir LICENSES && cp .../GPL-2 LICENSES/GPL-2.0-only.txt`. Verify first/last lines match the source.
- [ ] **Step 2: Cargo fields.** Update the 5 manifests. Run `cargo +1.88 metadata --locked --offline --format-version 1 >/dev/null` to prove manifests still parse.
- [ ] **Step 3: README + CONTRIBUTING.** Rewrite License section; write policy doc (keep it short: license lines, CLA requirement, how to sign, no commercial language).
- [ ] **Step 4: `git rm` old texts.** Grep tree for `LICENSE-MIT|LICENSE-APACHE|MIT OR Apache` — must be empty (historical plan prose exempt ONLY if it quotes history; list each exemption in the report).
- [ ] **Step 5: Commit.** `docs: re-license to GPL-3.0-or-later (+ GPL-2.0-only BPF)`.

## Task 2: Per-file SPDX headers (scripted + verified)

**Files:**
- Modify: all tracked `*.rs` (recon: 74), `*.py` (149), `*.sh` (36), `*.md` (281) — implementer MUST enumerate from `git ls-files` (recon counts are advisory).

**Interfaces:**
- Consumes: Task 1 identifiers.
- Produces: every in-scope file carries the exact header; BPF files carry GPL-2.0-only.

- [ ] **Step 1: Enumerate from `git ls-files`** by extension. Exclusions (record each): files under `preserved/`, generated `third-party/src` (untracked anyway), vendored fixture data (e.g. `.c` fixtures that are test INPUT — headers there would corrupt tests; verify each exclusion by showing the test that reads it).
- [ ] **Step 2: Insertion script** (temp file under /var/tmp, NOT committed): idempotent (skip files already carrying any `SPDX-License-Identifier`), correct comment syntax per extension, shebang-aware.
- [ ] **Step 3: Run + verify.** Post-run grep: every in-scope file matches `SPDX-License-Identifier: GPL-3.0-or-later` (or `-2.0-only` for the 2 BPF files); zero files with the old dual header (there were none — confirm).
- [ ] **Step 4: Prove no breakage.** `cargo +1.88 fmt --all -- --check` (headers must not break fmt — `//!` first-line is fmt-stable, verify), `py_compile` every touched `.py`, `bash -n` every touched `.sh`.
- [ ] **Step 5: Commit.** `docs: add per-file SPDX headers`.

## Task 3: BPF license section proof

**Files:** none (evidence task; code change only if the section is wrong).

- [ ] **Step 1: Rebuild the BPF object** per `docs/development.md` (pinned nightly + bpf-linker).
- [ ] **Step 2: `readelf -p license` (or `llvm-objdump -s -j license`)** on the built object: must show `GPL`. Record verbatim.
- [ ] **Step 3: If missing/wrong**, add the aya license declaration following the crate's existing pattern (verify how aya emits it first — read the aya-0.14.0-p1 source in third-party); rebuild; re-verify. Commit only if code changed.

## Task 4: License meta-test + gates + merge review

**Files:**
- Modify: `tests/artifact_contracts.rs` (new `license_headers_*` test: every tracked in-scope file carries an SPDX header; Cargo license fields match the policy; `LICENSE` + `LICENSES/GPL-2.0-only.txt` exist; old texts absent).

- [ ] **Step 1: Failing-first test** (assert against temp-dir fixtures, never by breaking the tree). RED on fixtures, GREEN on tree.
- [ ] **Step 2: Full suite ×2** (TMPDIR-prefixed), fmt + clippy clean. Record counts + logs.
- [ ] **Step 3: Final review + merge** to main (local merge pre-approved; never push), retire branch/worktree per finishing-a-development-branch.

## Self-review (controller, against the spec)

1. Spec coverage: GPL-3.0-or-later userspace/docs/scripts → Tasks 1–2; GPL-2.0-only BPF + `SEC("license")` → Tasks 2–3; LICENSE + LICENSES/ → Task 1; SPDX tags → Task 2; CLA policy → Task 1; no commercial mention → Task 1 (explicit check). No gaps.
2. Placeholder scan: no TBD/TODO; header formats, counts, and proof commands exact; fixture-data exclusions fenced per-file.
3. Contract consistency: TMPDIR/toolchain/branch identical everywhere; offline-only texts; fmt/py_compile/bash-n proof after headers.
