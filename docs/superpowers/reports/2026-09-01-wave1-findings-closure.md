# Release Hardening Wave 1 — Findings Closure

## Outcome

Wave 1 closes the eight findings from static security scan `3e10be9` on
`hardening/findings-wave1`, based on `main`
`5d251b76b33b14839a7147e14b5ccd1348855587`. The final code tip is
`e79284388e30e3c5b296a30dd7505ea427628384` (43 commits). The Rust 1.88
offline gates at that tip all passed: fmt, check, 937 tests with zero failures,
and clippy with warnings denied.

Task 11 is clean under the accepted threat model. The bounded review at
`a0a25d7` found four High blockers. Round 4 closed them at `e66434e`,
`c198212`, and `330c81d`. A final diff review then found one static two-hop
symlink/newline mis-binding in the cargo-home ledger; `e792843` closed it with
a RED/GREEN process test and mutation proof. A fresh review found the static
bypass closed and raised only a transient malicious same-UID swap/restore
race, which the ratified Task 4 receipt architecture explicitly excludes.
There are no accepted W1 blockers remaining.

Review count: three completed full/pair cycles (Task 11 cycles 1 and 2, plus
the bounded full-diff pair that replaced the scheduled-but-UNRUN cycle 3) and
two completed scoped final reads (`330c81d` and `e792843`).

`docs/privacy/allowlist-v1.md` is unchanged across the wave.

## Finding closure matrix

| Finding | Closure commits | Representative regression evidence |
| --- | --- | --- |
| `csf_f5953ae` helper fd/loader-env confinement | `03b4a78`, `40e995f`, `3affa0f` | planted fd/loader environment, proc fallback, and overflowing-fd refusal tests |
| `csf_ad79ebb` cumulative trace bound | `0d73280`, `a08877e`, `5c638be`, `2106ebe`, `972eaa2` | bounded output, owned-child settlement, quantum polling, terminal truncation |
| `csf_b8067e3` terminal control escaping | `6611131`, `be8cc07`, `eaaa90b`, `e3e8933` | all text sinks plus C0, DEL, and C1 pins |
| `csf_c94c662` output ancestry | `4108a4c` | symlink, writable ancestor, owner, fallback, and parent-component refusals |
| `csf_6f180d5` cgroup descriptor retention | `5a4ff3b`, `71030fd`, `3903d82` | retained-fd walk, operator-path reporting, and publication tests |
| `csf_ce5962b` discovery work/maps/deadline budget | `bf32500`, `315b90a`, `f5d38fb`, `928decb`, `e3e8933`, `0d48fb6`, `662d349`, `972eaa2`, `330c81d` | bounded maps reads, one charged index per live snapshot, stop-aware admission, production refusal oracle |
| `csf_014eb65` release input trust | `4237ca9`, `91f3d8a`, `5220535`, `6540801`, `c198212`, `e792843` | sealed command/environment inventory, cargo-home/sysroot closure, missing-musl refusal, canonical-newline refusal |
| `csf_19fb2f` Lane 14 literal evidence binding | `43c1ab5`, `f71b8d5`, `5220535`, `a0a25d7`, `e66434e` | literal capture/checker binding, locale guard, isolated Python across reached scripts |

The six external shadow blockers are closed by `2106ebe` (bounded live and
trace drains), `e86c0fe` (container cleanup by immutable created ID),
`0d48fb6`/`662d349`/`972eaa2`/`330c81d` (charged shared `MapIndex` and
stop-aware admission), and the release-chain commits listed above.

## Verification

At code tip `e792843`, `CARGO_NET_OFFLINE=true`:

- `cargo +1.88 fmt --all -- --check`: PASS.
- `cargo +1.88 check --locked --workspace --all-targets`: PASS.
- `cargo +1.88 test --locked --workspace --all-targets`: PASS, 937/0.
- `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`: PASS.

At corrected round-4 tip `330c81d`, the directly affected live lanes also
passed: privacy canaries 7/7 including hostile START/fault controls; attach
scan and corroborated modes 136/136; Docker glibc/musl discovery including
SoftHSM fixtures and exact-ID cleanup; and the pinned offline musl build,
which produced a static PIE without `rustup target add`. No lane needed a code
change to run under the sealed 51-command environment.

The earlier `7edc70f` test failure is superseded evidence, not hidden: two
lifecycle tests timed out and a third test was vacuous because C1 added `-I`
without shifting three test-wrapper argv parsers. `e66434e` includes the root
fix; focused tests and the complete 937-test gate then passed.

Historical product defect: `-o` output was broken under old Docker seccomp
because every failed `openat2` call was treated as a hard error. `4108a4c`
added the ENOSYS/EPERM no-follow directory-walk fallback and pinned equivalent
symlink refusal in both paths.

## Private custody

| Item | Private commit | Binding |
| --- | --- | --- |
| Task 0 Stage 3A3/scanner custody | `6a5e7e715354b5463034e2688fccb176e9d1bfb8` | 145 tracked private files |
| Codex shadow-review package | `5f6c341` | manifest SHA-256 `8a94d7a39419aef507b9d74858e4081f5a70f1c0e53b0d5bd4daa678f5996922` |
| Owner main-checkout patch | `9e7e5f3` | patch SHA-256 `b71885979925d3715e03181cf847d1801a17100906d56574288ab73a4c917529` |
| Complete W1 SDD trove | `9a433b5d606783de7ad4cd6da85bb2dea7cf6663` | 91 files; typed manifest readback PASS; manifest SHA-256 `563ecb05b365fc6d4b0d9d014b8dd471db0a019ec70692bd276e4d0f8cdbc5d9` |

The owner's main-checkout patch remains unmerged. It must be hash-verified and
stashed immediately before the pre-approved local W1 merge.

## Explicitly unrun

- Full release body: the intended A2 preflight refuses while
  `~/.cargo/config.toml` exists; the real run remains W8 work.
- Hosted CI (W4), kind/Knative and matrix containers (W5), and VM/kernel
  matrix (W6).
- Privileged real-BPF max-one trace benchmark.
- Owned-descendant SoftHSM timing/calibration fixture.
- Task-4-specific live seccomp fallback and Task-5-specific cgroup runtime
  confirmations; later W1 live lanes exercised overlapping paths but were not
  relabelled as those task-specific gates.
- External network other than the separately owner-approved W5/W6 image pulls.

## Deferred findings and process debt

- W5: historical/matrix `find|sort|head` receipt binding and container cleanup
  pre-registration patterns.
- W8: measure/fix the predicted stale static-smoke checker mode; run the first
  full sealed release body, which is the 51-command inventory completeness
  proof.
- Security backlog: Docker daemon/image identity (Medium); Unicode format
  characters in terminal paths, stopped-capture redundant maps reads, and git
  configuration/index-bit provenance (Low). The capture-copy race and
  malicious same-UID evidence/symlink rewrites remain outside the accepted
  receipt threat model. The real-tab evidence-root defect was fixed in
  `c198212`.
- Test-quality backlog: self-test rows are executable documentation rather
  than independent guards; command-inventory completeness is execution-proven;
  CI needs an explicit 51-tool image/package contract; one live maps test has
  a one-mapping parallelism margin. The one-index regression and mutation
  attribution issues were corrected in W1 records/tests.
- W2 begins with the private handoff's storage-state-machine corrections.
  At W2 exit, move W7 before provisional W5/W6 qualification so the ia32
  uprobe-path change does not force both expensive qualification waves to run
  twice.

The release-driver receipt records private provenance including HOME and PATH;
that evidence remains 0700/0600 private custody and is not public telemetry.
No capture field or schema was broadened.

## Integration and authority

This report is the branch closeout; the merge has not yet occurred. The owner
pre-approved a local `--no-ff` merge after this docs tip passes the four gates
and the final public/private review. Merged `main` must pass the same gates.
Nothing was pushed, tagged, packaged, published, or released by W1.

Memory update: **SKIPPED** because there was no explicit contemporaneous owner
request to write memory.
