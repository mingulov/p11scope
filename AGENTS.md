<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Repository guide

## Sources of truth

- Start with `README.md`; use the approved spec/plan under `docs/superpowers/`.
- `docs/superpowers/plans/ROADMAP.md` defines phase order and gates.

## Working agreements

- Keep changes scoped and preserve unrelated work.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly.
- Keep Rust 1.88, edition 2024, and Linux x86-64-first support.
- Do not track generated output. Get explicit approval for privileged or container experiments.

## History

- Work must live in commits, not in the working tree: dev branches, worktrees, and task branches always contain the commits for the work done on them — otherwise history is lost.
- Committing finished, verified work is authorized by default, on any branch.
- Rewriting history (amend, rebase, reset) and pushing require explicit user agreement.
- Commit messages follow repo style: `<area>: <imperative summary>` (`fix: …`, `feat: …`, `refactor: …`, `test: …`, `docs: …`).

## Checks

Test temp I/O goes to /var/tmp/p11scope-ws-tmp (big disk, sticky-trusted; create 0700 if missing), never tmpfs /tmp (EDQUOT at scale): prefix test runs with TMPDIR as below.
```sh
mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.88 check --locked --workspace --all-targets
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.88 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --workspace --all-targets -- -D warnings
```
