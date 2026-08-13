# Repository guide

## Sources of truth

- Start with `README.md`; use the approved spec/plan under `docs/superpowers/`.
- `docs/superpowers/plans/ROADMAP.md` defines phase order and gates.

## Working agreements

- Keep changes scoped and preserve unrelated work.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly.
- Keep Rust 1.88, edition 2024, and Linux x86-64-first support.
- Do not track generated output. Get explicit approval for privileged or container experiments.

## Checks

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
```
