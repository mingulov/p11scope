<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Tracked known-failing list (0.7.2)

`tests/known-failing.json` (schema `p11scope/known-failing/v1`) is the one
typed exception list for tests that fail for a named known issue. It is
never a mechanism for declaring an ordinary regression expected.
`scripts/check-known-failing.py` validates the list statically (the
`scripts` CI job) and judges typed result documents (`--results`) in the
jobs that produce them.

## Row schema

Required fields: `path`, `test`, `cell`, `issues`, `target`, `runner`,
`signature`, `lane`, `mode`, `reason`, `last_green_sha`. Optional fields:
`hosts`, `since`, `evidence`, `invocation`.

- `path`: clean repository-relative POSIX path of the test file or cell script.
- `test`: exact test id: Rust `module::path::name`, Python
  `Class.test_name`, or a cell name.
- `cell`: stable typed cell token. For `cell:` runners it must equal
  `test`; when the signature carries a `cell` field it must equal the
  row `cell`.
- `issues`: nonempty unique list of `KI-nn` ids. One row may cover two
  issues.
- `target`: `0.7.3` or `0.8.0`. A row expires at its target release:
  once `docs/releases/v<target>.md` exists without the exact draft
  marker line (`Status: draft (not released)`), the row is refused.
  Draft-marked notes are not a release.
- `runner`: `privileged-lib`, `python-suite`,
  `python-suite-strict-browser`, or `cell:<script>`. The strict-browser
  runner is the strict browser-cells CI stream, selected by
  `P11SCOPE_KNOWN_FAILING_RUNNER`; rows naming it are judged only
  there. There is no `host-matrix` runner: the schema as implemented
  is accepted (controller ruling, fix4 brief N8).
- `signature`: nonempty nested record of typed values only (snake-case
  field names, enum-like leaves, never log text), with a mandatory
  `branch` naming the typed failure branch. A bare producer state or
  scope token is refused as a branch: Python rows need a test-raised
  `p11scope_signature`.
- `lane`: the lane that owns the fix. `reason`: nonempty printable
  plain human text. `last_green_sha`: newest passing commit, 40-hex.
- `hosts`: optional unique nonempty subset of `github`, `vng`,
  `fedora`, `fedora-sm1`. Rows naming `fedora` or `fedora-sm1` are
  refused: no CI job judges those hosts, so rule 4 (a stale row
  fails) is unenforceable there. They stay KI prose until a host
  judge exists.
- `mode`: `always` (must fail; a pass is a stale row) or `intermittent`
  (may pass; a failure must match `signature` exactly, type-sensitive).
- Every row has a CI judge. A `python-suite` or
  `python-suite-strict-browser` row needs `github` in `hosts`, or no
  `hosts` (suite streams are judged only with host `github`; the
  browser-cells job judges the strict-browser stream). A `cell:` row
  needs a workflow invocation with the same
  `--known-failing-runner` and a compatible host (`"$kf_host"` matches
  any host). A `cell:` row's `path` equals its runner script, except
  `.rs` rows whose typed path comes from `tests/ignored-tests.json`.
  The static check proves a typed stream exists for the runner and
  host; cell selection itself is enforced at judgment, where a row
  whose cell the stream never selects fails as a listed row with no
  terminal result.

`privileged-lib` rows are refused until the privileged summary counts
`XFAIL` rows: a typed row prints `XFAIL`, which `Prove full coverage`
does not count today, so the first such row would turn that job red.

## Static rules

1. Every row names a test that exists at `path` (executable discovery:
   unittest ids, `--list-cells`, or cargo libtest `--list`).
2. Every row issue is a named known issue with `test: true` in the
   typed registry, and every `test: true` issue has at least one row.
   Exact equality both ways. Until the 0.7.2 section lands, only an
   empty list is valid; once `docs/releases/v0.7.2.md` exists the
   typed registry must exist, and zero `test: true` issues means zero
   rows is valid.
3. Runner-declaration unification (row-to-workflow) is deferred to
   0.7.3 (controller ruling 2026-11-25 21:17). Only the reverse holds:
   no undeclared `--expected-failure` / `--intermittent-failure`
   cells. Repeated declarations for one runner/results stream must
   agree in every selection category, including `--require-file`.
4. A row with `mode: always` that passes fails its job.
5. A failure with a different `signature` is an ordinary failure.
6. Adding a row needs an owner-approved known issue. Regressions never
   go on the list.

`--results` judgment skips executable discovery (the `scripts` job
already runs the static check) and requires a complete one-to-one
typed selection/results document. Unlisted `skipped` / `not_applicable`
results are neutral and printed as counts; they never excuse a
listed row. Every JSON input the gate reads (the list, both
registries, suite fragments, result documents) is admitted only
through strict typed JSON: duplicate keys, wrong types and
undecodable bytes are typed refusals, and a missing or unreadable
required file fails closed with a named error instead of an empty
mapping. The ignored-test inventory validator reads through the
same strict loader. Every input is fully parsed and validated
into typed records before any lookup or matching: no early return
on the first match and no lazy validation. An unreadable
directory, an unreadable file, an unknown file, a parse failure or
a malformed entry anywhere is a typed refusal of the whole gate,
never a skip and never partial evidence. Every directory the gate
scans accounts for every file in its population:
`.github/workflows` admits only `.yml`/`.yaml` files (anything
else is refused, and an unlistable directory is refused), every
`tests/python/test_*.py` file must be registered, and every
scanned `.rs` source must list and decode (enumeration failures
are refused). The suite registry is parsed as data, so `RUN` in
`scripts/run-python-suites.py` must stay a top-level literal list
of `(nonempty name, string args)` pairs, and one malformed entry
refuses the whole registry. A malformed or ambiguous ignored-test
site likewise refuses the registry instead of mapping around it.
Typed records nest at most 32 levels; deeper inputs are refused.
Every gate entry point turns any operational exception into a
typed refusal with a nonzero exit, never a traceback.

## Known-issue registry block (exact format)

The release-docs lane owns `docs/known-limitations.md`. The block below
is the exact format the checker parses; copy it verbatim. `test` is
true if and only if the issue has a typed row in
`tests/known-failing.json` (a legacy `--expected-failure` declaration
is not a row). Issues without a row keep `test: false` with prose.

```markdown
## Known limitations in 0.7.2

<!-- p11scope-known-issues-v1
{"schema":"p11scope/known-issues/v1","issues":[{"id":"KI-01","test":false}]}
-->

### KI-01

Plain-word limitation text. Where a host-limited or parked test exists
but has no typed row, say so in prose ("no typed row until a host
judge exists", "test lands with the lane") instead of marking
`test: true`.
```

Rules the checker enforces on the block: exactly one marker comment in
the section, strict JSON, top level exactly `schema` + `issues`, every
issue exactly `id` + boolean `test`, no duplicate ids, and every
registered id has a matching `### KI-nn` heading and vice versa.

The registry lands in the same commit as the `v0.8.0.md` -> `v0.7.2.md`
rename, or before it: once `docs/releases/v0.7.2.md` exists the checker
refuses a tree without the registry.

## 0.7.2 row dispositions (plan section d.3)

| # | Test | Issue | Disposition |
|---|---|---|---|
| 1 | `LiveOuterCells.test_rpo_proxy_outer_exact` (wrapper part) | KI-02 | Not shipped: test file absent from the tree; failure is fedora/fedora-sm1-only with no host judge. KI prose only. |
| 2 | `LiveOuterCells.test_rpo_opensc_outer` | KI-02, KI-03 | Same as 1. KI prose only. |
| 3 | New strict proxy-layer cell on the fedora shape | KI-01 | Same as 1; test still to be written. KI prose only. |
| 4 | `BrowserFirefoxCC.test_ff_cc_sign_attributed_under_run_default` | KI-04 | Dropped: test lives only on the parked `v080-firefox-cc-sign` branch (21:17 ruling). |
| 5 | `test_system_default_covers_browser_children` | KI-08 | Not shipped: lane did not park and the test is absent from the tree. |
| 6 | `test_cr_first_with_background_provider_covers_browser` | KI-11 | Dropped: test lives only on the parked `v080-chromium-bootstrap` branch (21:17 ruling). |
| 7 | `test_cr_first_ec_with_background_provider_covers_browser` | KI-11 | Same as 6. |
| 8 | `native_system_trickle_counts_every_post_attach_call_lp64` | KI-06 | Not shipped: lane did not park and the test is absent from the tree. |
| 9 | CR-RUN-DEFAULT cell | KI-24 | Not shipped: lane did not park and the cell is absent from the tree. |
| 10 | cell `mt-exact` (`scripts/qualify-public-cli.sh`) | KI-12 | Not shipped: `hosts: ["fedora-sm1"]` is refused without a host judge; the script has no `--list-cells` inventory either. KI prose only. |
| 11 | `privileged_run_tree_arming_exhaustion_still_stages_and_counts` (`tests/run_tree.rs`) | KI-13 | Not shipped: its known failure is a legacy `--intermittent-failure` cell whose default typed signature carries no `branch`, so no typed row signature can match it; qualifying it needs a sidecar producer. KI prose only. |

No other 0.7.2 failures need rows: every other d.3 issue either has no
committed failing test ("no test yet" prose) or is owned by a later
lane. FF-NOMOD (`BrowserCells.test_ff_nomod_observes_nothing`) gets a
row post-tag (controller ruling 2026-11-25 17:02).

## Python-suite producer notes

`scripts/typed-python-suite.py` runs each suite in-process under a
patched unittest and records the outer selection plus terminal states.
A `setUpClass` / `setUpModule` `SkipTest` marks that scope's selected
tests `skipped` with branch `class_skip` / `module_skip` (neutral, the
job stays green). A `setUpClass` error leaves its tests `not_run` and
the fragment incomplete (the job stays red). Skip reasons are never
copied into typed records. `scripts/run-python-suites.py` merges the
fragments and adds per-suite `<suite-process>` / `<suite-events>`
integrity rows before the checker judges the document. The merged
`<suite-process>` row is failed unless the fragment's self-reported
`process_exit` equals the outer-observed returncode, so a teardown
crash after the fragment write cannot pass as green.

## Follow-ups

- Stream identity: implemented. The strict browser-cells CI job merges
  its typed results with runner `python-suite-strict-browser` (via
  `P11SCOPE_KNOWN_FAILING_RUNNER`), and rows naming that runner are
  judged only in that stream — never in the plain `python-suite`
  scripts stream, where their live cells skip. A row still applies to
  every result stream with the same runner and host.
- FF-NOMOD row: done. The browser job runs the suite under
  `typed-python-suite.py` via `scripts/run-python-suites.py
  test_browser_cells.py` with the strict-browser runner identity, and
  the judgment absorbs matching `KnownFailure`s as expected failures.
  The post-tag FF-NOMOD row and its CR-RUN-NODELAY sibling are the
  first stream-scoped rows (KI-25, KI-26).
