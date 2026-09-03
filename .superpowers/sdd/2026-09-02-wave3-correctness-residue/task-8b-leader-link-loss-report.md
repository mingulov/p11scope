# Task 8b — leader-link-loss report

BASE: `45d61ae8517a40dfffb430ae87a336663792bfaf`
HEAD: `8ca14e9515219f801fab00cd4c4ea9883b1865f4` (implementation commit)

ROOT_CAUSE: A matched `DISCOVERY_KIND_LEADER_EXIT` was dispatched directly as
an ordinary expected removal. That discarded the distinction between a whole
process-group exit and a leader task exit while workers remained, and left no
sticky aggregate or selection-coverage consequence for the latter.

RED_EVIDENCE:

- `cargo +1.88 test --locked leader_exit_assessment_settles_once_and_terminalizes_pending_views`
  initially failed with only the intended missing settlement seam symbols
  (`E0425` for the settlement functions and `E0433` for the enum).

FILES_CHANGED:

- `src/discovery/engine.rs`: generation-bound pending/settled assessment,
  once-per-view counter, conservative retirement, selection closure, terminal
  promotion, and lifecycle tests.
- `src/render.rs`, `src/run.rs`, `src/trace.rs`: public evidence field,
  completeness gate, metrics-v3 schema, and renderer tests.
- `scripts/check-capture-evidence.py`, `scripts/verify-canaries.sh`,
  `scripts/verify-task4-lane16.sh`: exact counter/schema validators and
  fixtures; v2-metrics remains an explicit historical compatibility shape.
- `tests/artifact_contracts.rs`, `tests/run_lifecycle.rs`: updated exact
  evidence fixtures/assertions.
- `docs/schema/observed-profile-v3.md`, `docs/privacy/allowlist-v2.md`,
  `docs/usage.md`, `README.md`, `CHANGELOG.md`: current schema/privacy/usage
  contract updates.

TESTS:

- `cargo +1.88 test --locked leader_exit_` — 3 unit tests and 2 matching
  artifact tests passed.
- `cargo +1.88 test --locked every_discovery_loss_serializes_nonzero_and_independently_forces_partial` — passed.
- `cargo +1.88 test --locked every_capture_document_publishes_the_live_discovery_evidence_fields` — passed.
- `cargo +1.88 test --locked evidence_for_keeps_distinct_discovery_losses_across_all_renderers` — passed.
- `cargo +1.88 test --locked --test artifact_contracts` — all 83 tests passed.
- `python3 scripts/check-capture-evidence.py --self-test` — passed, including
  the historical v2-metrics fixture.
- `scripts/verify-canaries.sh --self-test` — passed.
- `scripts/verify-task4-lane16.sh --self-test` — passed.
- `cargo +1.88 fmt --all -- --check`, `git diff --check` — passed.
- `sha256sum docs/privacy/allowlist-v1.md` —
  `0cb4983d239c8c182d9c0ba632cde87ff9031ff22c7c9cab9edf4af43474797f`.

DEFERRED: Full workspace gates, privileged/runtime/container/VM/CI/network
qualification, release work, and process-creation behavior remain untouched.

RISKS: Runtime behavior against a real task-uprobe leader-exit/worker-survival
race remains unqualified in the local non-privileged lane. An unresolved
generation check is conservatively retained during live discovery and promoted
to one link-loss count at terminal finalization.
