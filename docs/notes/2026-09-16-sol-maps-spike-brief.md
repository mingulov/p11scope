<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Implement: an invalid maps snapshot must not read as an absent mapping

Repo: this worktree. Work only here. Read
`.superpowers/sdd/w7-continuation-2026-09-12/HOUSE-RULES.md` first and obey it — it IS
present in this worktree.

**Precedence: these CONTROLLER RULINGS > HOUSE-RULES.md > DESIGN.md.** If an instruction is
ambiguous or contradictory, do the safer thing and say so in REPORT.md — do not stall.

## The defect (controller-verified; do not re-litigate)

`crates/manifest/src/maps.rs:190` rejects a snapshot with any inverted or overlapping pair
by returning `None`, and `maps.rs:261` turns that into `Resolved::Unmapped` for EVERY
address:

    pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved {
        MapIndex::new(maps).map_or(Resolved::Unmapped, |index| index.resolve(vaddr))
    }

So "I could not read a coherent map" is reported as "this address is not mapped". That is a
definite negative where there was no observation — the thing this project forbids.

`DESIGN.md` is the APPROVED design, written by a deep reviewer and adjudicated by the
controller. Implement it. Do not redesign it.

## CONTROLLER RULINGS

**RULING 1 — implement the FALLIBLE API from DESIGN.md §2, not a `Resolved::Indeterminate`
variant.** DESIGN.md VERIFIED that a new enum variant would be silently swallowed by the
wildcard branches at `discover.rs:195` and `:275`, the `if let` at `:289`, and the
`let ... else` at `:1173`. Only changing the return type forces every caller to confront it:

    MapIndex::new(&[MapEntry]) -> Result<MapIndex<'_>, InvalidMapSnapshot>
    maps::resolve(&[MapEntry], u64) -> Result<Resolved, InvalidMapSnapshot>
    MapIndex::resolve(&self, u64) -> Resolved        // stays infallible

`Ok(Resolved::Unmapped)` must mean absence in an ACCEPTED snapshot, and nothing else.

**RULING 2 — also fix the adjacent overflow collapse at `maps.rs:244`.** Offset overflow
currently returns `Unmapped` too. Validate representability of each absolute-file mapping's
last-byte offset (`file_offset + (end - start - 1)`) during construction and remove the
overflow-to-`Unmapped` fallback, so `Unmapped` has exactly one meaning. Leaving it would
keep a second collapse of the same kind.

**RULING 3 — do NOT expand scope.** DESIGN.md §4 notes existing duplicated index
construction in the live inventory path (`engine.rs:8607` and `694/698`). That is NOT this
defect. Do not refactor it, and do not touch budget or performance behaviour.

**RULING 4 — the live scan path is already safe and must stay unchanged in behaviour.**
DESIGN.md §4 VERIFIED that the P-2 bracket (`scan.rs:1623/1918/1951`) and
`read_selection_table` (`engine.rs:8870`) already refuse explicitly on a bad index. Your
change must not alter what those paths report. The genuinely exposed callers are the offline
helper's free-resolver sites in `crates/discover`, plus the weaker offline selection bracket
(`discover.rs:789/812/1213`) where an anonymous overlap can pass the comparison.

**RULING 5 — make NO claim about `legacy_layout_matrix_covers_200_through_32`.** Its
attribution is CANNOT DETERMINE and must stay that way. Do not describe this as fixing that
test, in code comments, test names, or your report.

**RULING 6 — no migration may reintroduce the collapse.** Reject `.unwrap_or(Resolved::Unmapped)`,
`.ok()` followed by absence handling, and `if let Ok(File ..)` with an unreported fallthrough.
Use the existing `ProviderChanged` refusal category for failed maps validation in the offline
selection bracket, consistent with `discover.rs:815`.

## Rules

- **Mutation-first proof is mandatory.** For each behavioural claim: write the test, run it
  against the UNFIXED code, capture the literal failure, apply the fix, capture the literal
  pass. Paste both into REPORT.md. A claimed RED you did not run is a failed task.
- The decisive RED: a snapshot containing an overlapping pair must be DISTINGUISHABLE from a
  snapshot in which the address is genuinely absent. A test where both produce the same
  observable outcome proves nothing.
- **An absent thing is never a pass.** Every refusal must be recorded, never silent.
- **A fixture built from the same assumption as the code under test cannot falsify that
  assumption.** Build the invalid-snapshot inputs independently of the validator.
- Include a positive control: a VALID snapshot with a genuinely absent address must still
  report absence, unchanged.
- Do NOT commit. Leave the change in the working tree.

## Verification — FOCUSED RUNS ONLY

**Do NOT run workspace-wide `cargo test`/`clippy`/`check`** — HOUSE-RULES §2 forbids it and
the controller runs that gate serialized. Use the form in HOUSE-RULES §3, e.g.

    mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-manifest --lib -- <name>
    mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope-discover --lib -- <name>

and ASSERT THE COUNT, not just the exit code — a mistyped filter yields "0 passed" and looks
exactly like success. Report each run's literal `test result:` line.

## Report

Append to `REPORT.md` as you go: what changed by file:line; every RED capture with its
matching GREEN; the count of call sites you migrated and any you could not; anything
unproven, stated plainly; and any ruling you believe is wrong — state it, do not act on it.
