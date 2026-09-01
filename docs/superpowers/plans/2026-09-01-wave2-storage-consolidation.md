# Wave 2 — Storage Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Follow the Agent execution protocol in `ROADMAP.md` §"Release program" — re-verify every file:line anchor below before executing (they were verified 2026-09-01 at HEAD fb3dffc).

**Goal:** Enforce the owner's two-directory rule — everything durable lives in `/home/user/src/m/pkcs11-scope` (public) or `/home/user/src/m/p11scope-ws` (workspace) — by migrating referenced artifacts, repointing live references, and putting `p11scope-ws` under real git custody, without falsifying historical records or deleting any original.

**Architecture:** Copy-verify-repoint, never move-and-hope: originals in `~/.local/state/p11scope` (11 GB) and `~/p11scope-vm-bases` (1.6 GB) stay in place until the owner approves deletion; migration is rsync/cp + sha256 verification + reference updates. Historical documents keep their old absolute paths (they record where things were AT THE TIME); one relocation record maps old roots → new roots, and only *live navigation* (the evidence index) and *live scripts* are repointed. `p11scope-ws` git tracks text/metadata/manifests; large binaries are gitignored but sha256-manifested.

**Tech Stack:** bash/coreutils, rsync, git. No Rust code changes; the four cargo gates still run (repo convention).

**Spec:** `docs/superpowers/specs/2026-09-01-release-requirements-and-goal.md` §4 (binding rules 1–5) and §6; `docs/superpowers/specs/2026-09-01-p11scope-release-prd.md` §9.6.

## Global Constraints

- Entry gate: Wave 1 merged to `main` (its Task 9 already rescued the Stage 3A3 trove, mirrored `findings.json`, made the initial `p11scope-ws` commit, and fenced `.superpowers/sdd/`). Every W2 step is idempotent against that: check-then-do, skip what W1 already did.
- **Never delete or move an original.** Copy + verify only. Deletion of the old roots is a separate owner-gated decision recorded at closeout (Task 6).
- **Never rewrite history**: a tracked doc that *records* an old absolute path as evidence of a past run keeps it verbatim. Only live navigation and executable scripts are repointed.
- Do not commit large binaries into `p11scope-ws` git: `*.tar.zst`, `*.qcow2`, `*.img`, VM disks — gitignored, listed in `MANIFEST.sha256` instead.
- SSH private keys (`~/p11scope-vm-bases/id_ed25519`) are copied with mode 0600 into `p11scope-ws/vm-bases/`; **rotation is owner-gated and NOT performed here** — record it as an open item.
- Four canonical gates after every commit (`CLAUDE.md` §Checks).
- Branch `hardening/wave2-storage` off `main`; one commit per task; merge after review-to-zero.

---

### Task 1: Inventory and classification manifest

**Files:**
- Create: `/home/user/src/m/p11scope-ws/preserved/<execution date>-storage-relocation/INVENTORY.md` (dates in this plan written `<execution date>` are filled at execution)

- [ ] **Step 0 (preflight):** `df -h /home` — require ≥15 GB free before any copy (copy-don't-move needs headroom for up to ~12.6 GB of duplicates on an 83%-full filesystem); if short, STOP and ask the owner which originals to migrate first. Set `p11scope-ws` git identity from the public repo's config (`git -C p11scope-ws config user.name/user.email` to match `pkcs11-scope`'s).
- [ ] **Step 1:** Enumerate tracked references (expected baseline, re-verify against the W1-merged tree — classification happens ONCE, post-W1): `git grep -n '\.local/state\|p11scope-vm-bases\|pkcs11-scope-evidence\|/tmp/p11scope\|home/user' -- .` — 27 files at fb3dffc. Classify each hit **by content, not filename**, into: **(a) live script** (`scripts/matrix/verify-oracle.sh:6,:42` — hardcoded `/home/user/src/m/pkcs11-check-ws/pkcs11-check`; `spike/slice1b2-loader/run-lanes.sh:6` — env-overridable, defaults through the `pkcs11-scope-evidence` symlink), **(b) live navigation/authority pointer to a migrated artifact** — repoint or annotate (`docs/superpowers/reports/2026-08-31-productization-evidence-index.md:92,:101,:158,:192,:232`; `ROADMAP.md:215`'s `task4-lane13-…/facts.log` pointer; the wave-1 plan's own `Spec:` pointer at its lines 7/11 — a LIVE plan, repoint to the `p11scope-ws` mirror), **(c) historical record** — keep verbatim (most of the ~19 docs/notes + closed plans/reports), **(d) ephemeral-by-design or test fixture** — document, don't change (`/tmp/p11scope*` work roots in `spike/*/run.sh` + `spike/*/src/main.rs`; `scripts/verify-task4-lane16.sh:195` is a negative-test fixture STRING, not a path), **(e) already compliant / states the rule** — nothing to do (the requirements spec §4 quoting the old roots as prohibited; `docs/notes/slice1b2/README.md:318,:351` pointing inside `p11scope-ws`). Every hit lands in exactly one class; a hit fitting none goes to INVENTORY.md as OPEN with a proposed class for review.
- [ ] **Step 2:** Enumerate the storage roots (names, sizes, dates — no content dumps): `~/.local/state/p11scope/*` (lane02 evidence dirs, mvp-semantic attempt dirs, mvp-candidate freezes, `security-scan-3e10be9/`, `retired-generated-slice1b2-finish/`, `pkcs11-scope-portable-{90a03ac,3d3ba05,b86d4d5}.tar.zst`, **and `fedora44-base` — a VM base living in the wrong root; it goes to `p11scope-ws/vm-bases/`, NOT `preserved/`**), `~/p11scope-vm-bases/*` (`jammy`, `noble`, `logs`, `fix1-20260817`, `id_ed25519{,.pub}` — note: NO fedora44-base here). **REFERENCED means:** named by any tracked file in the W1-merged tree (git grep) OR by the evidence index. All 8 currently-referenced items were verified to exist on 2026-09-01; if a referenced original is MISSING at execution time, record it as MISSING in INVENTORY.md and the relocation record — do not fail the wave.
- [ ] **Step 3:** Write `INVENTORY.md` with the classification, sizes, and the migration decision per item (migrate / leave-for-owner-deletion / ephemeral). Commit it in `p11scope-ws`.

### Task 2: Migrate referenced durable artifacts into `p11scope-ws`

- [ ] **Step 1:** For every item marked REFERENCED in Task 1, `rsync -a` to this FIXED destination map (no other categories — an unmapped item goes to INVENTORY.md as OPEN): the sdd trove → `p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` (**same path W1 T9 used — check first, skip if present; never a second copy under another name**); `security-scan-3e10be9/` → `p11scope-ws/preserved/security-scan-3e10be9/` (W1 mirrored `findings.json` there — copy the rest of the dir beside it); the three portable tarballs + checksum files → `p11scope-ws/preserved/portable/`; referenced evidence roots (mvp-semantic-*, mvp-candidate-*) → `p11scope-ws/preserved/evidence-roots/<original-name>/`; `fedora44-base` → `p11scope-ws/vm-bases/fedora44-base/`. `retired-generated-slice1b2-finish/` is the sdd trove's SOURCE — after the trove copy is verified, the rest of it is classified in INVENTORY.md, not blanket-copied.
- [ ] **Step 2:** Verify: `diff -r` or sha256 per file against originals; write `MANIFEST.sha256` per destination directory.
- [ ] **Step 3:** Migrate `~/p11scope-vm-bases/` → `p11scope-ws/vm-bases/` (rsync -a, preserve modes; keys 0600, dir 0700). Verify sizes + sha256 of the keypair and each base image.
- [ ] **Step 4:** Ensure `p11scope-ws/.gitignore` covers ALL large trees BEFORE any further commit: `incoming/` (9.6 GB of capture roots), `vm-bases/`, `preserved/evidence-roots/`, `preserved/portable/`, `*.tar.zst`, `*.qcow2`, `*.img`. (W1 T9's amended Step 5 creates this file before the initial commit — verify it exists and extend it; if a large tree was EVER committed, stop and ask the owner before any history surgery.) Then commit in `p11scope-ws`: text, metadata, and `MANIFEST.sha256` files only — the manifests are how gitignored binaries stay accounted for.

### Task 3: Repoint live references

**Files:**
- Modify: `scripts/matrix/verify-oracle.sh` (:6 comment, :42), `docs/superpowers/reports/2026-08-31-productization-evidence-index.md` (:92,:101,:158,:192,:232), `docs/superpowers/plans/ROADMAP.md` (:215 facts.log pointer), `docs/superpowers/plans/2026-09-01-release-hardening-wave1-findings.md` (lines 7/11 Spec pointer)

- [ ] **Step 1:** `verify-oracle.sh:42` → `PKCS11_CHECK_DIR=${PKCS11_CHECK_DIR:-$HOME/src/m/pkcs11-check-ws/pkcs11-check}` (env-overridable). **Two flags for the record, not for silent settling:** (i) `pkcs11-check-ws` is a third directory — it is a sibling *project checkout*, not p11scope data, but under a literal reading of spec §4 rule 1 this is an exception the owner must ratify (Task 4 records it as OWNER-PENDING). (ii) The script's provenance ledger (`:160-177`, `git -C "$PKCS11_CHECK_DIR" rev-parse HEAD` + `pip freeze`) binds the receipt to whatever checkout the env names — that is correct (content-bound, not path-bound), but note that pre-existing lane-11 receipts pin the OLD script hash, so a rerun is needed; the `sh -n` gate (`tests/artifact_contracts.rs:2267`) and the self-test string pin (`:2493-2494`) both survive the edit (verified 2026-09-01).
- [ ] **Step 2:** Live navigation/authority pointers to migrated artifacts (class (b) from Task 1): the five evidence-index lines, `ROADMAP.md:215`, and the wave-1 plan's `Spec:` pointer → repoint to the new `p11scope-ws/preserved/...` paths, each with one appended clause "(originally under `~/.local/state/p11scope/`, relocated <execution date>)" — navigation stays truthful without falsifying provenance.
- [ ] **Step 3:** Symlink decision (spec §4.5): KEEP both shims — `/home/user/src/m/pkcs11-scope-evidence` → `p11scope-ws/evidence` and `p11scope-ws/source` → the repo. They already comply with the two-directory rule (both endpoints inside the two roots) and `run-lanes.sh:6` resolves through the first. Record the decision in the relocation record.
- [ ] **Step 4:** Full gates; commit `chore: repoint live references to the two-directory layout`.

### Task 4: Relocation record

- [ ] **Step 1:** Write `docs/superpowers/reports/<execution date>-storage-relocation.md` (public, small): the two-directory rule, the old-root → new-root map, the keep-both-symlinks decision, the historical-docs-keep-old-paths policy (the working interpretation of spec §6's storage bullet — surfaced for owner ratification, PRD §9.6 note), the `pkcs11-check-ws` third-directory exception (OWNER-PENDING), a pointer to `p11scope-ws/preserved/.../INVENTORY.md`, and the open owner-gated items (delete old roots; rotate VM SSH keys).
- [ ] **Step 2:** Gates; commit.

### Task 5: Custody verification

- [ ] **Step 1:** Assert: `p11scope-ws` has ≥1 commit and a clean status after the migration commits; `git -C p11scope-ws log --oneline | head`.
- [ ] **Step 2:** Assert no tracked file's *executable or live-navigation* path resolves into `~/.local/state`, `~/p11scope-vm-bases`, or `/tmp` (re-run the Task 1 grep; every remaining hit must be classified (c) historical or (d) ephemeral in INVENTORY.md — zero unclassified).
- [ ] **Step 3:** Spot-restore test: pick one migrated evidence file, verify its sha256 matches both the manifest and the original.

### Task 6: Review-to-zero and closeout

- [ ] **Step 1:** Two independent review agents per the ROADMAP protocol: (a) rule-compliance review (does anything durable still depend on a non-durable root? was any history rewritten?), (b) custody review (manifests complete, perms right, nothing large in ws git). Triage, fix, repeat until a cycle accepts zero findings.
- [ ] **Step 2:** Merge to `main`; gates on `main`.
- [ ] **Step 3:** Present the owner-gated deletion list (old roots with sizes: `~/.local/state/p11scope` ~11 GB, `~/p11scope-vm-bases` ~1.6 GB) and the key-rotation item. **Stop — do not delete or rotate.**
- [ ] **Step 4:** Update memory: two-directory rule ENFORCED as of `<tip>`; originals await owner deletion; keys await rotation.
