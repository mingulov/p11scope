# Agent configuration

The default is Astra High for the primary, with three responsibility-based
roles: `p11scope_explorer`, `p11scope_implementer`, and `p11scope_reviewer`.
Their files deliberately omit `model` and `model_reasoning_effort`. The parent
selects both explicitly for each spawn using the live model allowlist.
Luna Medium is the fallback for an otherwise unspecified child, not a mandate
to use Luna for implementation or review. `review_model` remains Sol; it does
not select the custom reviewer role's model.

Start a **new session** in this checkout to load the renamed roles and policy:

```sh
repo_root=$(git rev-parse --show-toplevel)
codex --strict-config -C "$repo_root"
```

Existing conversations retain their already-loaded instructions and tool
definitions. Resuming one is not a reliable configuration migration.

## Choosing resources

The current trial uses these per-spawn starting choices:

| Work | Model and effort |
| --- | --- |
| Literal searches and inventories | Luna Low/Medium |
| Bounded exploration requiring interpretation | Astra Medium |
| Routine implementation | Sol Medium |
| Demanding review, lifecycle or concurrency investigation | Astra High |
| Routine review or Astra unavailable/excluded by resource limits | Sol High |

These are adjustable heuristics, not benchmark-proven optima. Report model
substitutions. A narrow mechanical patch may use Luna. Role files remain
unpinned: the trial changes routing instructions, not enforced role defaults.
Keep requirements and integration decisions in the primary. Delegate only when
the independent task or review justifies another context.

Evaluate the trial on useful findings, missed issues/rework, elapsed time and
reported usage across comparable tasks. A successful spawn alone does not
establish that Astra Medium/High is better than the earlier routing.

For a lower-resource session while retaining the new flexible roles:

```sh
repo_root=$(git rev-parse --show-toplevel)
codex --strict-config -C "$repo_root" \
  -m gpt-5.6-sol -c 'model_reasoning_effort="medium"' \
  -c 'agents.max_concurrent_threads_per_session=2' \
  'Use Sol and Luna only for this session, with at most two concurrent children. Choose effort per task; do not escalate to Astra.'
```

This is not the exact historical configuration. To restore that, use the backup
below. Model availability, subscription usage and total cost are not established
by a valid configuration or these routing recommendations.

## Exact backup and restore

The four original files are preserved byte-for-byte in the local, Git-ignored
directory `backups/pre-astra-20260907.6tkL6O/`: Sol Medium primary, Luna High
explorer, Luna XHigh worker, Sol XHigh reviewer, and the original instructions.
This backup intentionally excludes user-level configuration and credentials.
Copy it separately if you need it on another machine; Git does not carry it.

Close other sessions using this checkout before switching. From the repository
root, preserve the current setup and restore the older one:

```sh
task_saved=$(mktemp -d .codex/backups/before-restore.XXXXXX) &&
mv .codex/config.toml .codex/agents "$task_saved/" &&
cp -a .codex/backups/pre-astra-20260907.6tkL6O/config.toml \
  .codex/backups/pre-astra-20260907.6tkL6O/agents .codex/
```

The saved directory contains the newer configuration for switching back with
the same preserve-then-copy procedure. Keep both files and the whole `agents`
directory together: copying only `config.toml` leaves incompatible role names.
Start a new Codex session after restoring. The saved files also allow recovery
if the copy step fails. This procedure changes tracked configuration files but
does not stage or commit them.

## Gap analysis (2026-09-07)

| Gap | Resolution or remaining boundary |
| --- | --- |
| Roles pinned model and effort despite requesting explicit spawn overrides | Removed both pins and renamed roles by responsibility. |
| Previous effort choices were presented too confidently | Routing guidance is explicitly heuristic; no comparative benchmark validates this exact mix. |
| Astra parent could silently pass its resource settings to children | Explicit model and effort required; Luna Medium remains a fallback. |
| Role names coupled behavior to a model | The same explorer, implementer or reviewer can use different available models. |
| New roles absent from an existing session's tools | Start a new session; never invent unavailable tool role names. A reported built-in-role substitution is allowed. |
| Follow-up text mistaken for changing inference settings | Policy does not treat prose as a runtime configuration update. |
| Unbounded delegation and budget exhaustion | No recursive delegation without an assigned plan; exhausted tasks return partial evidence and the unresolved question. |
| Writer collisions and competing Cargo jobs | Retained disjoint file ownership, serialized Cargo-heavy checks and review after writing stops. |
| Reviewer self-report mistaken for verification | Primary verifies evidence, results and acceptance gates; role names do not prove actual runtime routing. |
| A blocked check incorrectly reported a negative finding in the smoke test | All roles now require verified/partial/blocked status and exact errors. A check that could not execute leaves its intended question unknown; an executed check's failure is evidence to evaluate. This instruction is not an enforcement mechanism. |
| Role sandbox labels mistaken for confinement | Live parent permission overrides still apply. Use an enforced read-only parent mode when confinement matters. This configuration does not change session permissions. |
| A resource profile might silently lose to project settings | CLI overrides provide the one-off route; exact restore replaces configuration and roles together. |
| Global or nested configuration changes effective values | Global files are preserved; validate from the intended working directory. Nested worktrees may have closer project overrides. |
| Privacy or release guarantees could drift | Existing allowlist, no-privilege rule and repository acceptance gates remain in force. Configuration validation is not product qualification. |

The 12-child ceiling is retained; it is not a target or an account usage cap.
Models, effort and budgets still need to match each assignment. Assignments
must name the exact files/symbols, write ownership, required behavior, checks,
command budget and return format (evidence, changes, checks, unresolved risks).

## Verification and sources

Use installed Codex strict configuration loading and `config/read` to check
effective values. Parse every role as TOML and check that names match filenames,
the required fields exist, and neither model nor effort is pinned. Check the
live model allowlist before spawning. An actual child result is needed to claim
successful child execution; parsing alone is not an inference or latency test.

- [Custom roles and spawn precedence](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Project, profile and CLI precedence](https://learn.chatgpt.com/docs/config-file/config-basic)

Validation on Codex 0.153.4:

- Strict app-server `config/read` resolved Astra High, Luna Medium fallback,
  and 12 children; CLI overrides resolved the documented Sol Medium launch.
- All three role files parsed and had no model/effort assignments. The legacy
  backup matched all four original files byte-for-byte. A temporary-directory
  rehearsal restored the legacy pair and retained the current pair exactly.
- A fresh CLI session discovered `p11scope_explorer` and received results from
  two sequential children. Recorded child turn contexts selected `gpt-5.6-luna`
  at `low` and `medium`, respectively. This verifies client-side selection,
  not backend attestation or comparative model quality.
- Both children failed their file-read commands before execution with
  `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. Their returned
  `pins_absent: false` was unsupported and rejected; the direct TOML parse
  establishes that pins are absent. No sandbox bypass was attempted. Shell
  execution in that read-only environment remains blocked independently of
  the configuration. The added error-reporting instruction has not been
  demonstrated to prevent every such model error.
- Independent Sol review of the initial change found no issues. Follow-up
  review refined the smoke-test reporting rule to distinguish infrastructure
  blocking execution from a meaningful failure returned by an executed check.

No Cargo or privileged/container experiments are needed for these configuration
changes, and none were run. Product runtime qualification is unaffected.
