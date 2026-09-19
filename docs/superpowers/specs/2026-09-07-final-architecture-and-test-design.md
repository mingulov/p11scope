<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Final architecture and test maintainability design

Owner-approved scope, 2026-09-07: fix the identified test architecture and
process-ownership problems; review BPF, Rust userspace and supporting scripts
with Astra xhigh; redesign where evidence warrants it. This is a mandatory
release-preparation gate. It does not authorize publication.

## Release position

Architecture work starts during W7 so corrections precede expensive runtime
qualification. W7, W5 and W6 retain their existing product obligations.
**W8-A: final architecture and maintainability closure** is an explicit entry
step before W8's final qualification, receipt and bundle assembly. Changes to
a qualified path invalidate its affected evidence and return to that gate.
Architecture review cannot substitute for kernel, ABI or lifecycle execution.

The primary owns requirements, triage, design decisions, integration and
acceptance. Three bounded Astra xhigh reviews cover BPF/attachment, Rust
userspace, and production scripts. Their recommendations are evidence inputs;
the combined design receives independent review before its implementation.
Verified defects and already-approved test corrections can proceed in their
own reviewed slices without waiting for unrelated findings.

## Findings established by the initial test review

These are structural findings and focused experiments, not a claim that every
test or production path has received exhaustive correctness review.

| ID | Evidence | Required correction |
| --- | --- | --- |
| AR-01 | `tests/proc_access.rs::same_uid_non_descendant` and `tests/discovery_scan.rs::an_unreadable_proc_mem_is_reported_as_unavailable_not_as_an_error` discover fixtures with global `pgrep` and can signal every match. | Private launch identity, bounded readiness, identity-pinned cleanup, automatic resource ownership; preserve the real non-descendant access test. |
| AR-02 | `tests/artifact_contracts.rs` has 99 actual tests in 10,251 lines. `tests/task4_build_subjects.rs` has 18 tests in 23,711 lines, with 20,717 lines of embedded Python. | Native-language test files, direct execution and named cases; preserve Cargo gate coverage. |
| AR-03 | Descriptor-publication marker checks accept a comment-only body containing the six expected strings. Decoder formatting broke a signature assertion; a retirement check uses a fixed 400-byte lookback. | Replace implementation spelling with observable behavior or compiled-artifact checks, retaining old checks until replacement negatives prove equivalent coverage. |
| AR-04 | A candidate-discovery driver contains 9,428 Python lines; lane-13 finalization combines many scenarios in one roughly 1,100-line Rust test. | Separate independently runnable scenarios with fresh state and explicit failure identity. Preserve scenarios whose ordering itself is the contract. |
| AR-05 | Task-4 drivers contain repeated identity-snapshot/import mechanics and inconsistent temporary-resource cleanup. | Share only demonstrated fixture mechanics; use scoped cleanup. Preserve independent golden vectors, raw-record decoders and identity comparisons. |

The broad inventory also covers test-bearing Rust modules, integration files,
fixture files and script self-tests. Most core Rust tests already exercise
production behavior through ordinary functions, `ScriptedSession` or `FakeIo`.
Those boundaries are useful. File size alone is not a defect.

## Chosen architecture

Tests live with the language and responsibility they exercise:

| Kind | Placement and execution | Boundary |
| --- | --- | --- |
| Rust unit behavior | Existing module tests; separate Rust test modules when navigation benefits | Call production functions and existing injected I/O/session seams. |
| Rust integration behavior | Existing named `tests/*.rs` targets | Public APIs, real CLI results, filesystem/process behavior. |
| Python behavior | `tests/python/test_*.py`, standard-library `unittest` | Import the actual production file explicitly; independent inputs and expectations. |
| Shell behavior | `tests/shell/test_*.sh`, direct shell invocation and a thin named Cargo bridge | Exercise actual script entry points/helpers; same-UID shims belong with test fixtures, not privileged release lanes. |
| Shell/C fixtures | Ordinary files under `tests/fixtures/`, grouped by responsibility | Execute the actual shell entry point or narrow existing helper; compile real C fixtures where needed. |
| Artifact contracts | Rust tests or existing object checkers | Actual embedded BPF object, BTF, ABI layout, map/program inventory, privacy boundary. |
| Privileged qualification | Existing explicit scripts and receipts | Actual selected kernel/configuration, ABI, captures, loss and lifecycle; never implied by a unit-test pass. |

Keep thin, named Cargo wrappers for migrated Python/shell families. Cargo
remains the required entry point; direct language commands provide fast local
selection and diagnostics. A wrapper passes paths/arguments, invokes the
native test, and reports failure; it must not embed a second test program.
Preserve exact existing test names where CI or frozen commands depend on them.
Wrappers select the required native case identities explicitly. Missing or
skipped required cases fail the gate; a child exit status of zero by itself
does not establish that the required cases ran. Use normal unittest selectors
and result status, not a new registry or runner framework.

Use standard-library `unittest` selection, subtests and scoped cleanup rather
than a new test framework, registry or configurable runner. Direct invocation
is `python3 -I tests/python/test_NAME.py -v`; a class or method can be selected
with the standard unittest CLI. The Python documentation describes these
[native test and selection facilities](https://docs.python.org/3/library/unittest.html).

Preserve isolated Python. Load reviewed files by explicit paths; do not make
tests or production depend on ambient `PYTHONPATH`, user site packages or cwd
import resolution. Python's
[isolated mode](https://docs.python.org/3/using/cmdline.html#cmdoption-I)
is part of the existing release boundary, not an obstacle to remove.

KISS means ordinary files/functions and the existing build tools. DRY applies
to repeated setup, fixture construction, ownership and cleanup. It does not
justify deriving expected bytes from the encoder being tested, reusing the
production parser as its independent oracle, or merging distinct ownership
states because their current code happens to look similar. Existing dependency
injection stays where it permits deterministic failure/lifecycle tests; no
new general interfaces are introduced merely to claim a design pattern.

## Migration and source authority

Move test code before changing production helper boundaries. The new process
snapshot test can execute the existing production heredoc from a normal Python
file; extracting that production helper is a separate decision. Native tests
become directly runnable immediately, while production authority stays intact.

Moving production Python from `scripts/lib.sh` requires updating every exact
source input list, including `scripts/matrix/verify-knative.sh`. Moving native
Task-4 driver code requires updating its `input_paths` custody inventory.
`scripts/build-release.sh` hashing all tracked files does not repair a separate
lane's explicit input list. Tests must prove that changing or omitting the
new input changes or invalidates the affected receipt.

Do not simplify away BPF verifier requirements. Global diagnostic helper BTF,
narrow output projections, explicit initialization and ABI entry specialization
have measured kernel constraints. Remove repetitive BPF code only after an
isolated experiment passes the same object inventory and actual kernels, then
repeat affected runtime/privacy oracles on the integrated result.

## Acceptance

The [architecture closure plan and finding ledger](../plans/2026-09-07-architecture-closure.md)
is the single record for owners, patch scope, acceptance and affected gates.
Repair an oracle before trusting its new qualification result, and establish
fixture process ownership before running the broader affected suite.

- Each fix has a reproduced failure or concrete structural baseline, a scoped
  patch and independent review. Preserve all existing refusal/failure cases.
- Migrated tests run directly and through the existing Cargo gate. Record case
  identities before/after; reject empty selection or missing expected cases.
- Cases pass individually and in their supported suite/concurrency mode.
  Monkeypatch-heavy tests retain fresh modules/state or separate processes.
- Injected failure still restores ordinary fixtures; native ptrace/pidfd/
  subreaper watchdog containment remains intact. No global-match signaling or
  deletion is allowed. A separately owned same-command process must survive.
- Behavioral replacements reject missing writes, incorrect readback, skipped
  refusal and stale lifecycle authority. Harmless formatting/comment changes
  do not determine the verdict.
- Preserve source-custody coverage, independent raw-record decoding, privacy
  allowlist v1, default/diagnostic distinctions and exact ABI inventories.
- Run the four Rust 1.88 gates after integration, native language checks, and
  affected kernel/ABI/container/runtime gates. Review the integrated architecture
  and gap ledger to zero before W8 assembly. No open accepted finding is hidden
  by a maintainability label or marked complete from source inspection alone.

## Alternatives rejected

A file-only split is a useful first migration step but does not by itself fix
source-spelling assertions or coupled scenarios. A wholesale framework or
production rewrite would change too many trust boundaries at once. The chosen
incremental approach provides independently reviewable improvements while
preserving the original behavior and its evidence.
