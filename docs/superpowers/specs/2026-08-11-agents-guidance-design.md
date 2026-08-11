# Concise Repository Agent Guidance Design

## Goal

Speed up new coding-agent sessions with a short, stable repository working
contract. The guide must orient an agent toward the right sources, constraints,
and verification commands without duplicating project status or architecture.

## Guidance shape

Create one root `AGENTS.md`, following the official OpenAI recommendation to
keep repository-wide basics at the project root and use concise rules. Organize
it into three small sections:

1. **Sources of truth** — route agents to `README.md`, the relevant approved
   specification or plan under `docs/superpowers/`, and
   `docs/superpowers/plans/ROADMAP.md` for phase ordering.
2. **Working agreements** — keep changes scoped, preserve the profiling privacy
   contract, retain the Rust 1.88 MSRV and Linux x86-64-first target, avoid
   tracked generated output, and require explicit authorization for privileged
   tracing or container experiments.
3. **Checks** — list the formatting, Rust 1.88 build/test, and Clippy commands
   expected before completion:

   ```sh
   cargo fmt --all -- --check
   cargo +1.88 check --locked --all-targets
   cargo +1.88 test --locked --all-targets
   cargo +1.88 clippy --locked --all-targets -- -D warnings
   ```

Do not include a current-status summary, architecture overview, roadmap recap,
phase-specific implementation detail, or nested instruction files.

## Compatibility file

Add `CLAUDE.md` as the relative symlink `CLAUDE.md -> AGENTS.md`. There is one
canonical instruction file and therefore no duplicated guidance to drift.

## Verification

- Confirm `AGENTS.md` is a regular, non-empty Markdown file with no placeholders.
- Confirm `CLAUDE.md` is a relative symlink whose target is exactly `AGENTS.md`.
- Run `git diff --check`.
- Run the commands documented in `AGENTS.md` and report their actual results.
