# Phase 5 Task 4 — unsupported-environment behavior

The docs will state a kernel floor of >= 5.15 and describe lockdown/
capability behavior. This note records what actually happens today, for
each case this host can induce, and improves the messages that were
unclear before fixing them — not after, so the "before" text below is
real, not a strawman.

This host: kernel `7.0.0-28-generic`, `kernel.perf_event_paranoid = 4`,
BTF present (`/sys/kernel/btf/vmlinux`), no lockdown LSM loaded. Same
host, same tooling (`capsh`/`setpriv`) as
`docs/notes/phase4-privileges.md`.

## What changed (the fix)

Two real bugs were found while reproducing these cases and fixed in
`src/attach.rs` / `src/main.rs`, not just described:

1. **The actual OS error was being silently dropped.** aya's
   `ProgramError::SyscallError` is `#[error(transparent)]`; formatting it
   with plain `{e}` prints only `` `perf_event_open` failed `` — the
   `EPERM`/`EACCES` detail that explains *why* lives one level down in
   `.source()` and was never read. `src/attach.rs` now has an
   `error_chain()` helper that walks the full `.source()` chain (the
   `std::error::Error` equivalent of what `anyhow`'s `{:#}` already did
   for the map-creation path), so every per-slot attach failure now
   carries the real OS error text.
2. **No message named what was actually missing.** Every early failure
   in `Session::start` (map creation, program load — reachable only in
   an unsupported environment on a correctly-built binary) now gets one
   actionable hint appended, naming the concrete things to check
   (capabilities, lockdown, kernel floor, BTF, `perf_event_paranoid`).
   Separately, when every individual uprobe attach fails (the
   `perf_event_open`-only failure mode, further along than map
   creation), `report_attach_failures()` in `main.rs` — shared by
   `profile` and `trace` — adds one synthesized summary line instead of
   leaving the operator to infer a cause from N identical per-slot
   lines. The per-slot lines themselves are kept (they are real
   evidence for a genuinely PARTIAL, not fully failed, capture); this is
   additive, not a replacement.

Neither fix changes exit codes or the JSON evidence shape — only text —
so `scripts/matrix/verify-fork-scope.sh` (which already asserts the 0-
and 136-attached-probe cases numerically from the `-o` JSON) needed no
changes and was re-run clean after the fix (see "Verification" below).

## Cases induced on this host

### 1. Unprivileged (no `CAP_BPF`/`CAP_SYS_ADMIN`, no relevant sysctl change)

`--pid` against a bare `sleep 30 &`, no capabilities at all.

Before the fix:
```
p11scope: starting attach session: loading BPF object: map error: failed to create map `START`: failed to create map `START`: Operation not permitted (os error 1)
```
(exit code 1 — already fatal, already showed the real OS error via
`anyhow`'s `{:#}` in `main()`, but named no cause.)

**After the fix** (real output, this host):
```
p11scope: starting attach session: loading BPF object: map error: failed to create map `STATS`: failed to create map `STATS`: Operation not permitted (os error 1)
hint: this usually means the environment cannot load or attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF (/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See docs/notes/phase5-unsupported.md for what each looks like when observed.
```
Exit code: 1. (The map name in the error varies run to run — aya creates
maps in declaration order and the first one to fail is whichever one it
gets to first; both `START` and `STATS` were observed across runs. Not
significant; still the same `Operation not permitted` cause either way.)

### 2. `CAP_BPF` + `CAP_PERFMON` only, no `CAP_SYS_ADMIN` — this host's `perf_event_paranoid = 4` finding

Same reproduction as `docs/notes/phase4-privileges.md`: map creation now
succeeds (those two capabilities are enough for that stage), but every
individual `perf_event_open` for the uprobes is refused. This **is** the
"restrictive `perf_event_paranoid`" case — Ubuntu's `paranoid = 4` here
is a hardening level beyond upstream's 0-3 range that requires
`CAP_SYS_ADMIN` specifically, overriding the `CAP_PERFMON` bypass
upstream kernels document. See phase4-privileges.md for why; not
re-derived here.

Before the fix, all 136 per-slot lines read (no OS error visible):
```
attach failed (slot 0): p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: `perf_event_open` failed
```
...repeated for all 136 slots, then the tool continued running,
redrawing a live `Evidence: 0/136 probes attached ... → PARTIAL` frame
every second, exiting 0 at `--duration`.

**After the fix** (real output, this host): the per-slot lines now carry
the real OS error, and a summary line follows the 136th one:
```
attach failed (slot 0): p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: `perf_event_open` failed: Permission denied (os error 13)
...
attach failed (slot 67): p11_return at /usr/lib/softhsm/libsofthsm2.so+0x27b30: `perf_event_open` failed: Permission denied (os error 13)
p11scope: 0/136 attach attempts failed, every one the same way — this almost always means the environment cannot attach BPF uprobes at all: missing CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive kernel.perf_event_paranoid sysctl. First underlying error: p11_entry at /usr/lib/softhsm/libsofthsm2.so+0x265b0: `perf_event_open` failed: Permission denied (os error 13)
```
Then the same live `Evidence: 0/136 probes attached ... → PARTIAL` frame
as before (the JSON evidence contract is unchanged — `PARTIAL` was
already correct and never read as healthy; only the stderr text
changed). Exit code: 0 (unchanged — a partial capture with real,
reported evidence is not a crash, and `scripts/matrix/verify-fork-scope.sh`
depends on this run succeeding and writing its `-o` JSON to assert
`attached_probes == 0` numerically).

### 3. `CAP_SYS_ADMIN` alone — succeeds (control case, confirms no regression)

```
Evidence: 136/136 probes attached · 68 slots · 0 aliased · 0 skipped · 0 in-flight → COMPLETE
```
Re-run after the fix to confirm the success path is untouched.

### 4. Missing BTF — not inducible here

`/sys/kernel/btf/vmlinux` exists on this host (`CONFIG_DEBUG_INFO_BTF`
enabled in the running kernel's build) and there is no supported way to
hide or remove it without a different kernel build/boot, which is out of
scope for this environment. **Not induced; not faked.** aya's own load
path (`Ebpf::load`) is the thing that would surface a missing-BTF
failure — it would land in `Session::start`'s early-failure branch,
which is exactly the branch `UNSUPPORTED_ENV_HINT` above now covers
(the hint text names BTF explicitly). Untested claim, flagged as such.

### 5. Kernel below the 5.15 floor — not inducible here

This host runs `7.0.0-28-generic`, far above the floor. Downgrading the
running kernel is out of scope for this environment (no VM/container
with an older kernel readily available here). **Not induced; not
faked.** The 5.15 floor comes from the attach-cookie design used by every
uprobe/uretprobe; cgroup filtering now uses native `CgroupArray` membership.
This
tool does not runtime-check the kernel version anywhere in the code, so
on a kernel that lacks a feature it depends on, the failure mode is
whatever aya's `Ebpf::load()`/program-load path produces for that
specific missing feature (most likely a `LoadError` with a verifier
message, or a missing-helper error at load time) — again landing in
`Session::start`'s early-failure branch and getting the same hint.
**This is the weakest-verified claim in this note**: the *floor number*
(5.15) is not independently re-derived here, only inherited from the
Phase 4 plan text; the *failure path* it would hit is architecturally
clear (same early-failure branch as every other case above) but was not
observed on a real sub-5.15 kernel.

### 6. Lockdown mode — not inducible here

No lockdown LSM is loaded on this kernel build
(`/sys/module/lockdown/parameters/lockdown` does not exist here — most
Ubuntu desktop kernels ship it as a loadable/optional LSM, not always
active). **Not induced; not faked.** Kernel lockdown (`confidentiality`
mode) blocks BPF loading via the kernel's own `security_locked_down()`
checks inside `bpf()`/`perf_event_open()`, which — same as every case
above — would be a failure in `Session::start`'s early phase or in the
per-slot attach loop, both already covered by the improved messages.

## Verification

After the fix: `cargo test --release --workspace` (109 tests, all
green), `scripts/verify-attach-e2e.sh`,
`scripts/matrix/verify-fork-scope.sh` (re-runs cases 1-3 above as part
of its own privilege sweep, with real numeric assertions on
`attached_probes`), `scripts/verify-induced-gaps.sh`, and
`scripts/verify-canaries.sh` all re-run clean — the message-text changes
do not alter any exit code or JSON evidence shape those scripts depend
on.

## Summary

| Case | Inducible here? | Message quality after this task |
| --- | --- | --- |
| Unprivileged (no `CAP_BPF`/`CAP_SYS_ADMIN`) | Yes | Fatal, exit 1, real OS error + actionable hint naming caps/lockdown/kernel floor/BTF/paranoid |
| Restrictive `perf_event_paranoid` (`CAP_BPF`+`CAP_PERFMON`, no `CAP_SYS_ADMIN`) | Yes | Per-slot real OS error (`Permission denied`) + one synthesized actionable summary; `evidence.completeness = PARTIAL`, `attached_probes = 0` |
| Missing BTF | No — BTF present, can't remove without a different kernel build | Same early-failure branch + hint would fire; not observed |
| Kernel < 5.15 | No — this host is far above the floor | Same early-failure branch would likely fire; not observed, weakest claim in this note |
| Kernel lockdown | No — lockdown LSM not loaded on this kernel | Same early-failure/per-slot branches would fire; not observed |

None of the induced cases produce a panic, a raw verifier dump, or a
silent zero-count capture that reads as healthy — the two genuinely
unclear messages found while reproducing these (the swallowed OS error,
and 136 repeated lines with no named cause) were real bugs, now fixed.
