<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# p11scope overview

Find which running Linux applications use PKCS#11 providers, then inspect their
observed calls, errors, latency and bounded metadata — **without replacing the
provider or changing each application's configuration**.

`p11scope` is a system-wide PKCS#11 observability tool built on eBPF uprobes.
Its inventory connects applications to physical provider files and separates
loaded libraries from observed use. From that view, select a process or
provider for profiling, tracing and mechanism diagnostics. Discovery uses
available function-table or export evidence, including stripped providers
when their tables can be acquired; probes attach by file offset. Saved inventory
snapshots support offline comparison; detailed profiles support investigation.

> **Status: v0.6.0** answers "which application used which key, and how":
> inventory captures gain opt-in live key operations with per-category
> counts (`inventory --key-operations`), a counter capture can promote
> one endpoint to full detail (`--select-endpoint`), repeatable
> `--exclude-module` skips named providers, more provider tables prove
> complete instead of reading PARTIAL, text output is concise by default
> with `-v` for details, and live capture resolves 7.3 while the
> Detailed object loads on 7.4-rc1. Read the
> [known limitations](../CHANGELOG.md#known-limitations) and
> [docs/known-limitations.md](known-limitations.md) before relying on a
> capture. `--system` selects whole-machine scope;
> [CHANGELOG.md](../CHANGELOG.md#qualification-of-this-release) records what
> this release was qualified on.

Live capture requires a Linux x86-64 host with usable `uprobe_multi` load and
self-link capability under the current credentials, normally Linux 6.6+ or a
working backport. Capability is tested, never admitted by version. Missing
capability refuses before capture, output changes
or a user workload starts, including explicit `--attach-backend singles`.
Safe scoped Singles remains available on eligible hosts; PID Multi additionally
requires a proven kernel PID filter. Help, version, inspect, discovery, saved
report read/diff and genuine `inventory --capture scan` remain usable without
the live gate. Non-Multi live support may be reconsidered around 0.9.x; no
release commitment is made.

Omitting `--counter-mode` keeps existing metrics behavior. Explicit
`counts`, `timestamps` and `latency` aggregate in the kernel on eligible LP64
hosts, subject to mode-specific verifier and memory limits.

Function-table versions are metadata, not proof of allocated storage. An
observed legacy getter supplies at most the known 68 entries, including when
its table reports version 3.2. Discovery preserves usable functions in short
or sparse acquired tables, including around NULL or unusable entries, with
their actual ordinals. An acquired all-NULL table is a valid empty observation;
unread words never become NULL. Available known interface extensions can also
be retained, without guessing extra API fields from a longer allocation.
Actual gaps remain explicit in coverage.

Standard function names require evidence for the ordinal layout; other valid
targets remain useful as unknown, count-only observations. Alternate, null or
unreadable interface names alone do not discard those targets. The explicit
offline helper makes ten fixed `C_GetInterface` queries when that export is
available and never calls `C_Initialize`; live observation remains passive.
## First useful result

After installing, check host readiness, then start with a whole-machine
inventory and inspect a process you found there. Below is real output
from the v0.6.0 release binary on Ubuntu 26.04 (kernel 7.0.0-38,
`perf_event_paranoid=4`, lockdown `integrity`); the `--system` window
is shortened to 15 s here and the `--pid` target is a long-lived
SoftHSM caller:

```sh
sudo p11scope doctor
```

```
Doctor: requested-lane checks passed.
verdict: capture available; run initial-set capture not in this build (run reports stay PARTIAL; run itself works)
target loader build ............... warn  unbound
debug-state hook .................. warn  unavailable
loader-state live read ............ warn  unavailable
Next: sudo p11scope profile --pid <PID> (or doctor --pid <PID> to check a target).
run with -v for details
```

```sh
sudo p11scope inventory --system --duration 15s
```

```
inventory system (2 passes, 179 callers, 5 provider files, 29 edges)
coverage: PARTIAL — 304 gaps, 0 refused, 0 more not shown
key operations: not reported (per-key tracking is off)
libp11-kit.so.0.4.5: mapped by 1 application (snapd-desktop-integration); activity unknown
libp11-kit.so.0.4.8: mapped by 24 applications (NetworkManager, chronyd, cups-browsed, …); activity unknown
libp11-kit.so.0.4.8: mapped by 2 applications (cups-proxyd, cupsd); activity unknown
opensc-pkcs11.so: mapped by 1 application (gsd-smartcard); activity unknown
p11-kit-trust.so: mapped by 1 application (gsd-smartcard); activity unknown
limits: 179 callers, 5 provider files, 29 edges (0 refused); 19607 functions watched of 32768 (0 refused). Full budget detail: -v or --json.
gaps: 26 × maps attribution — maps 1 shared object no deep scan examined this pass; it may be an undiscovered provider; 11 × /home/user/.local/bin/muse-bin-1.4.14-R7309.1 — object is 414927192 bytes; limit is 268435456; 11 × maps attribution — maps 3 shared objects no deep scan examined this pass; each may be an undiscovered provider; 213 × unloaded libraries — mapped files were deleted (not loss); and 35 more (--json has every item)
run with -v for details
```

```sh
sudo p11scope inventory --pid 920308 --duration 15s
```

```
inventory pid:920308 (15 passes, 1 caller, 1 provider file, 1 edge)
coverage: PARTIAL — 1 gap, 0 refused, 0 more not shown
key operations: not reported (per-key tracking is off)
libsofthsm2.so: mapped by 1 application (python3.14); 30 entries observed
limits: 1 caller, 1 provider file, 1 edge (0 refused); 68 functions watched of 32768 (0 refused). Full budget detail: -v or --json.
gaps: 1 × process identity checked from /proc (PID and start time), not by the kernel — some processes were identified from /proc only (--json has every item)
run with -v for details
```

If a command refuses instead of capturing, see
[troubleshooting](troubleshooting.md). For a recorded profile
instead of a live inventory (`12345` below is a placeholder):

```sh
sudo p11scope profile --pid 12345 --duration 30s -o diagnostic-profile.json
```

Terminal text is concise by default — main results, one coverage line, and a
hint. Add `-v` / `--verbose` for full detail (every gap and reason, evidence,
timing) or `--quiet` for the summary head; `--json` and `-o` are always
complete. See [output verbosity](usage.md#text-output-concise-by-default--v-for-detail).

Inventory holds up to 131,072 physical endpoint IDs with
`--max-endpoints`; `inventory --system` on hosts with uprobe_multi defaults
to 32,768. An endpoint is a provider object plus function
offset, not a process. Detailed per-call capture has a separate 512-slot limit
in release builds. These are different modes and budgets; unloading does not
refund Inventory IDs during a capture.

| Input | What it adds | What it does not establish |
| --- | --- | --- |
| Automatic discovery | Mapped providers, observed usage and physical entry counts; `profile`/`trace` add observed return values and timing | Complete coverage of every process or early call; names need separate layout/export evidence |
| An explicitly accepted `--manifest` for the exact provider | Named offsets and admitted mechanism/API semantics | Trust in arbitrary provider code or recovery of calls before attachment |
| FULL attribute capture | The approved bounded attribute reads | Public live per-key results: unavailable in v0.5.0; v0.6.0 reports them through the opt-in `inventory --key-operations` ([limits](known-limitations.md#known-limitations-in-060)) |

A mapped library is not proof of use. Zero observed calls or zero event loss
does not establish that no calls happened before probes attached. Check the
reported watch interval and gaps; `profile` and `trace` currently lack a
separate pre-attachment marker. See the [coverage limits](known-limitations.md).

Counts describe provider API entries or completed calls, as labelled. A call
through a forwarding layer such as p11-kit and then a backend can be observed
at both providers. Adding those counts does not give a count of distinct HSM
operations; queries, retries and multipart calls also differ from completed
cryptographic operations.

See [CHANGELOG.md](../CHANGELOG.md) for what each release contains and its
known limitations, [Install](install.md#install) to build and install it, and
[docs/usage.md](usage.md) for the full operator's guide (privileges,
kernel floor, overhead, and the evidence/completeness model — every
quantitative claim there cites the script that measured it).
The v0.6.0 user-facing limits live in
[docs/known-limitations.md](known-limitations.md).

Saved inventories can be compared offline with
`p11scope inventory diff before.json after.json`. The readable report groups
observations by recorded application path and module content; `--json` and
`-o comparison.json` provide the [diff schema](schema/inventory-diff-v1.md).
Counts describe independent windows, and absence does not prove removal.
See [offline comparison examples](usage.md#offline-inventory-comparison).
One saved inventory or profile converts offline to a CycloneDX 1.6
cryptographic bill of materials with
`p11scope inventory cbom input.json -o out.cdx.json`
([export guide](usage.md#offline-cbom-export)).

Two newer capture flags: `--track-short-lived` (profile,
default off) is extensive mode: the kernel records exec-time executable identity
so unmatched exits gain bounded static-linkage hints, arming only on Detailed
profile `--cgroup`/`--system` captures and refused beside `--counter-mode`
and beside `run`
([options](usage.md#more-capture-options)). `--prearm-module
<provider.so>` (profile, trace, run, inventory; repeatable) pins a provider file
before any mapping and pre-arms its proved offsets; under inventory the inputs
are pinned and retained while Detailed-subset activation still follows
([pre-arming](usage.md#pre-arming-providers-with---prearm-module)).

Development inventory also accepts `--cgroup /sys/fs/cgroup/owned.scope`, including
descendants, across scan/auto/native and the existing output modes. Discovery
retains the selected root, requires initial PID numbering with matching procfs,
and reports bounded partial work explicitly. Idle cgroup usage remains unknown;
endpoint membership samples do not prove continuous residency. Scoped native
owner admission runs on `--cgroup` with `--capture auto` or `native`: while the
native lane stays active, each completed cgroup transaction commits at most one
staged native owner under its final-sample permit (activations first, refreshes
after); activations that miss the permit or the transaction keep scan-pinned
fallback, and deferred refreshes keep prior owner facts for a later pass.
`--capture scan` starts no native lane, so nothing commits there.
Public live cgroup qualification remains a development gate.
## Why

- **System-wide visibility** — find which applications map and actually call
  PKCS#11 providers, distinguish observed use from unknown or unwatched
  activity, and compare saved inventories. Start with `inventory --system`,
  then narrow the investigation to an application or provider.
- **Black-box diagnostics** — "this app intermittently fails against our HSM;
  what is it actually doing?" Calls, return codes, latency distributions,
  concurrency, session lifecycle — with zero app changes.
- **Migration workload evidence** — which PKCS#11 functions did the
  application exercise during this window? With explicitly attested function
  semantics, the profile also reports admitted mechanism and lifecycle
  evidence. Compare that observed coverage with
  [pkcs11-check](https://github.com/mingulov/pkcs11-check) results for a
  candidate provider. The default capture does not decode mechanism parameter
  combinations or attribute templates, so it cannot establish parameter-level
  migration compatibility.

  Start with a passive diagnostic capture. This manifest-free path retains
  aggregate function counts, return values and latency; scanned slots are
  semantics-unverified and count-only. File-data scans can miss tables held
  only in runtime allocation. A manifest built with `p11scope-discover`
  supplies explicit targets when discovery has no observed publication (see
  [known limitations](known-limitations.md#runtime-built-function-tables-need-publication-evidence-or-a-manifest)).
  Rows carry standard function names when a typed legacy return, an exact
  `"PKCS 11"` interface or an accepted manifest establishes the ordinal layout,
  or when the provider's own `.dynsym` agrees exactly with every retained
  non-NULL target (`linkage: "exports"`). Without name evidence, rows read
  `unknown#<ordinal>`, never a guessed name. `doctor` and
  `inspect` need the same privileges as a capture to assess or read another
  user's process:

  ```bash
  sudo p11scope doctor --pid 12345
  sudo p11scope inspect --pid 12345
  sudo p11scope profile --pid 12345 --duration 60 -o diagnostic-profile.json
  ```

  Whole-machine capture needs no PID or cgroup path;
  `--module` aims it at one provider:

  ```bash
  sudo p11scope profile --system --duration 60 -o system-profile.json
  sudo p11scope profile --system --module /usr/lib/softhsm/libsofthsm2.so \
    --duration 60 -o softhsm-profile.json
  ```

  For semantic capture, follow the separate
  [attested workflow](usage.md#attested-semantic-capture). The optional
  `p11scope-discover` helper executes provider code in its own unprivileged
  process and must match the provider's ABI/libc. Passing `--manifest` is
  explicit operator attestation of exact accepted function-name/offset claims;
  generating a file or matching its hash does not make that decision for you.

  Automated combination with candidate-provider test results is the planned
  integration with [p11lab](https://github.com/mingulov/p11lab).
  An unobserved call or missing metadata remains unknown.

  Full quickstart, real command output, and `trace` mode:
  [docs/usage.md](usage.md#quickstart).

## Why not just pkcs11-spy?

Use a shim when you own the application's launch; use p11scope when
you need to watch software you cannot restart or reconfigure. The
trade-offs are structural:

| | pkcs11-spy / pkcs11-logger / vendor loggers | ltrace / `LD_PRELOAD` interposition | p11scope |
| --- | --- | --- | --- |
| How it sees calls | A logging module the application must load instead of (or in front of) the real provider | ptrace/`LD_PRELOAD` tracing of one process tree | eBPF uprobes on the providers already mapped, attached from outside |
| App restart / config change | Yes: point the app at the shim and restart it | Yes: start under the tracer (or ptrace-attach per PID) | No: attaches to running processes and containers, with a whole-system view |
| Scope | That app's calls through that module only | That process tree only | Whole machine, cgroup, or PID, including containers sharing the provider file |
| Secrets in output | The log records call arguments, so PINs, buffers and key material can land in the log | Same: full argument capture | Never read: no PIN/key/payload decoder in the capture path ([what it does NOT decode](#what-it-does-not-intentionally-decode)) |
| Per-key use (which key, how) | Hand-correlate log lines | Same | Opt-in per-key rows (`inventory --key-operations`); Firefox/Chromium tested end to end, see [tested providers and applications](#tested-providers-and-applications) |

The costs of the p11scope side are real: live capture needs root or
the [listed capabilities](usage.md#privileges-per-environment)
on Linux 6.6+ x86-64, and probes add about 3.3 µs per call —
roughly a 5x wall-clock slowdown on the worst-case SoftHSM2 hammer
workload, negligible against millisecond-scale HSM calls
([measured overhead](usage.md#overhead-measured)). The shims
stay the right tool for single-app debugging on any kernel as an
ordinary user — p11scope's own real-provider harness judges its
reports against pkcs11-spy logs as the independent ledger
(`tests/fixtures/real-providers/README.md`).

## Tested providers and applications

Tested means a recorded run on the named version, not "should work".
Anything else is marked honestly; point p11scope at it and report
what you see.

| Provider | Status | Evidence |
| --- | --- | --- |
| SoftHSM2 2.6 | Tested | Real-provider cells (`pkcs11-tool`, `p11tool`, `certutil` workloads under `run`; Fedora + Ubuntu pins in `tests/fixtures/real-providers/expected-causes.json`) and the live `inventory --pid` run in [First useful result](#first-useful-result) |
| SoftHSM2 2.7 | Should work | Same `C_GetFunctionList`-only exports as 2.6 (`nm -D`; `tests/fixtures/real-providers/README.md`); compat wave pending |
| Kryoptic | Tested | `run` and `profile --pid` sign flows PASS on Fedora 7.2.9 ([qualification](../CHANGELOG.md#qualification-of-this-release)) |
| p11-kit-trust | Tested | Real-provider `trust list` cell, Fedora + Ubuntu pins |
| p11-kit proxy | Should work | Forwarding-layer accounting is implemented and documented in the [operator's guide](usage.md); dedicated transparency cells are not in the release qualification |
| OpenSC with a token | Not yet | No reader or virtual-reader path (W3-2 finding 4, `scripts/qualify-real-providers.sh`) |
| opencryptoki | Not yet | Cells exist but carry no pins yet |
| tpm2-pkcs11, NSS softoken, wolfPKCS11, BouncyHsm, FreeHSM, Haskoki, cloud/hardware HSMs | Not yet | No recorded runs; compat waves pending |

| Application | Status | Evidence |
| --- | --- | --- |
| Firefox, Chromium (Playwright 1.64.0 pinned builds) | Tested | 48/48 strict browser cells plus the demo in both orders ([qualification](../CHANGELOG.md#qualification-of-this-release)) |
| pkcs11-tool (OpenSC 0.27.1-2.fc44, 0.27.0~rc1-1) | Tested | Real-provider cell plus metrics twin, pins in `expected-causes.json` |
| p11tool (GnuTLS 3.8.13-1.fc44, 3.8.12-2ubuntu1.1) | Tested | Same |
| certutil (NSS 3.130.0-1.fc44, 2:3.120-1ubuntu2.2) | Tested | Same |
| `trust list` (p11-kit 0.26.5-1.fc44, 0.26.2-2) | Tested | Same |
| OpenSSH, Java SunPKCS11, OpenVPN, curl, Thunderbird, systemd-cryptenroll, git signing, Vault/K8s integrations | Not yet | No recorded runs |

Pins are version-specific: a new tool release needs a new pin before
it counts as tested (`expected-causes.json`: the ratchet). Several
pins are provisional (single-sample, awaiting quiet-host
confirmation); the ratchet still applies in full. One-shot
CLI use under `inventory --system` stays degraded in v0.6.0 —
short-lived callers may never bind to a caller row; see
[known limitations](known-limitations.md#known-limitations-in-060).

## What it does NOT intentionally decode

There is no decoder or dump switch for PINs, key material, `CKA_VALUE`, labels,
`CKA_ID`, plaintext, ciphertext, signatures, wrapped blobs, random output, raw
mechanism byte arrays, raw session handles, or ordinary buffers.

The default capture policy is `allowlisted`. For function metadata it is safe
against a caller that aliases a metadata pointer into unrelated readable
memory: pointer-derived function metadata becomes output only by *exact*
membership in the 104 published function names, and other values in that
field are dropped in the kernel. Mechanism ids are public constants: the
observer publishes the numeric id with call/error counts (registered ids by
registry membership; others as bare numbers, never decoded, never named —
see the allowlist-v3 row on unregistered mechanism id publication). Ids
above `0xFFFFFFFF` count in the total only. That is a
containment boundary, not pointer validation —
`bpf_probe_read_user` avoids faults, it does not check types.

FULL release builds additionally perform the approved bounded reads of
`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN`, `CKA_VALUE_LEN`, `CKA_MODULUS_BITS`
and finite `CKA_EC_PARAMS` values for attested object calls under `allowlisted`,
with descriptor, ABI, span and result checks. P0 skips these six attribute-value
reads. FULL keeps them enabled in `profile`, `trace` and `run` with
`--manifest`; those commands publish no object facts.

Discovery reads the target's `/proc/<pid>/maps` and bounded bytes of its
readable provider mappings via `/proc/<pid>/mem` (function tables, interface
descriptors, offsets); interface-name bytes are classified in userspace and
profile, metrics and trace publish only finite classification consequences.
`inspect` and an explicit offline manifest can show bounded discovered names.
Reports can include application/module paths and requested cgroup metadata;
these can identify workloads even though secret bytes are excluded.

The previous unvalidated parameter/template decoders still exist, but only
behind **both** an off-by-default Cargo feature and an explicit
`--unsafe-unvalidated-metadata` flag; the flag alone cannot enable code that is
absent from the shipped eBPF object, and `metrics` mode refuses it outright.
The official builder selects `--no-default-features --features
stub-object-attributes` for P0; packaging fails if the unsafe path is reachable.

The field-by-field inventory is
[docs/privacy/allowlist-v1.md](privacy/allowlist-v1.md), extended by
[docs/privacy/allowlist-v2.md](privacy/allowlist-v2.md) (interface
selection, attach mechanism, descendant rebuild, task-uprobe loss and ABI
refusal evidence). The explicitly approved sections of
[allowlist v3](privacy/allowlist-v3.md#h7-e4-attribute-capture-2026-10-20)
extend that boundary for the internal FULL producer, including these six
attribute reads; its header identifies the other reviewed sections. Remaining
proposals grant no capture authority or public object projection. The boundary
is backed by a secret-canary suite (`scripts/verify-canaries.sh`) that plants
sentinel PINs, key material, and buffer contents in a real workload and scans every output
artifact and every observer-owned BPF map for leaks — including hostile-alias
lanes, secret/unterminated/hostile-alias `C_GetInterface` names, and the
transient raw `pMechanism` address the return probe needs.

The `doctor` command, given an explicit `--pid`, reads that process's
executable header, memory map and the export names of its mapped executables
to check capture readiness. It reads nothing else, keeps nothing after the
check, and publishes only readiness verdicts (including how many mapped
executables look like providers).

See the [quickstart](usage.md#quickstart) for the CLI, live output, and
trace lines, and [the v3 schema](schema/observed-profile-v3.md) for the
report format.

## Honest claims

- Zero application changes, no PKCS#11 interposition, attachable to running
  processes and containers. Discovery scans the providers already mapped at
  attach and keeps watching for later loads while the capture runs. Calls
  *before* attach are outside the capture window, and the first calls after a
  late `dlopen` can be missed before that provider's probes land. A suitable
  manifest can still supply offsets when one already exists and can be
  hash-matched (and corroborated when the provider is mapped). **Not**
  "undetectable", **not** zero overhead: measured at roughly a **5x
  wall-clock slowdown** against unobserved SoftHSM2 — deliberately the worst
  case, since its microsecond-scale software crypto makes probe overhead
  proportionally largest; the same ~3.3µs absolute overhead is negligible
  against a millisecond-scale network HSM
  (`scripts/bench-overhead.sh`, `docs/notes/phase5-overhead.md`; full numbers
  and the event-loss finding at high call rates: [docs/usage.md](usage.md#overhead-measured)).
- Requires elevated privileges, kernel-version-dependent, x86-64 first. Live
  capture requires general Multi host capability; a safe scoped per-probe
  backend can still be selected on an eligible host. With multi active,
  `CAP_BPF`+`CAP_PERFMON`
  suffice for the static probes of an unconfined `--pid` target at
  `kernel.perf_event_paranoid=4` (measured 136/136); full capture at
  paranoid ≥ 3 needs `CAP_SYS_ADMIN`, and on the per-probe `perf_event`
  path a restrictive paranoid needs `CAP_SYS_ADMIN` too. Manifest-free
  scanning of a same-UID non-descendant
  additionally needs `CAP_SYS_PTRACE` under Yama `ptrace_scope=1`, or
  equivalently a descendant target / `--manifest`. Root normally supplies
  these permissions; user namespace, seccomp, LSM and lockdown policy can
  still refuse capture.
  No `CAP_LEASE`, no `fs.suid_dumpable=0`, no root-owned trusted exec dir
  ([measured matrix](usage.md#privileges-per-environment)).
  Live host capability is tested, with a one-line refusal on failure;
  other unsupported configurations fail with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- `inspect` shows every provider-shaped module mapped by the target; an
  optional `--module` only narrows that set. A target whose memory maps it
  cannot read is an error (exit 1), never an empty module list. On the
  measured p11-kit stack, the one-shot `inspect` verdict leaves p11-kit's
  closure array unattached by design — only its published tables would
  attach, and none of the lookalike tables is published yet — while the
  later-fitting SoftHSM2 backend attaches; the report is explicitly
  `PARTIAL`, not a claim that the proxy layer was captured. A live capture
  instead admits the forwarding layer by what it publishes (below), with
  an unpublished layer staying a named gap while the capture continues.
- Detailed per-call capture has 512 attach slots in release builds; this is
  separate from Inventory's endpoint budget (32,768 by default on
  `inventory --system` with uprobe_multi, up to 131,072 with
  `--max-endpoints`) and the explicit aggregate counter modes. Detailed
  `--pid`, `run`, and any capture aimed with `--module` admit providers in
  discovery order. A recognized forwarding layer (such as the p11-kit proxy
  closure array) is decided after every provider and admitted by what it
  publishes: only tables the application actually received attach, taking
  no heuristic slots, so the layer can never crowd out a real provider.
  Calls it forwards are counted at the attached backend providers, named
  with counts on the gap line; calls the layer answered itself, including
  its errors, appear only on the separate forwarding line, and one layer
  call that reaches several providers counts at each. Single-table
  forwarding shims (such as `pkcs11-spy`) are corroborated providers, not
  closure arrays: declare them with `--forwarding-module <path-or-name>`
  for the same split, else their calls count per layer with a `Possible
  forwarding` hint when two layers coincide. An operator-named
  layer (`--module <path>`) is the sole exception: it keeps a
  reserve-capped leading-templates prefix, because a remote client's
  tables are handed out before any export probe can observe the return.
  The prefix leaves at least the reserve (128 of 512 slots) free, so one
  later standard function list (at most 104 entries) always fits. Under
  inventory, counter and broad admission a closure array that does not
  fit whole is refused whole with its demand stated. A `--cgroup` or `--system`
  capture without `--module` admits each provider by value —
  `--manifest` providers first, then providers whose function table
  is corroborated, then heuristic finds, forwarding layers last. An
  ordinary provider that does not fit is admitted on the leading prefix
  that fits with a named partial gap; operator-attested (`--manifest`)
  modules stay whole-only. Heuristic finds may not use the last
  128 slots (25%), which stay free for corroborated providers found later in
  the capture. A refusal names what holds the slots; in such a shared capture
  it also names the reserve and suggests `--module`. The terminal report names
  every refused or partially covered module with its reason.
- Kernel-side state has fixed limits too: a lifetime budget of 16,384 process
  identities per `profile`/`trace` capture (under `--cgroup` and `--system`
  every process created in scope spends them) and 16,448 concurrent in-flight
  call owners. Exhaustion, and any in-kernel accounting fault that halts
  capture, is disclosed in `evidence.kernel_control` (`capture_halted`,
  `identity_budget_exhausted`) and forces `PARTIAL`.
- Discovery has one capture-wide 512 MiB attempted-I/O allowance shared by
  memory scans and scan-sourced file hashes across all selected processes and
  retries, with at most 256 MiB per scan/hash operation. It also stops at 512 accepted
  table candidates, 53,248 decoded entries, 512 interface records, 256 cgroup
  members, and the selected capture policy's attach capacity (512 for release
  Detailed capture; Inventory has its separate endpoint budget). Any bounded omission is evidence and forces
  `PARTIAL`; a retry never renews the allowance.
- A named PID's generation is retained through scan, pin, and attach and is
  rechecked before and after session creation. Cgroup members use the same
  retained generation and ownership records; a stale member's contributions
  are removed and the one-shot plan is rebuilt from already-opened stable
  inputs. Incomparable ordinary-file identities fail closed. The overlay-only
  byte-identical collapse remains an explicit uncertainty that forces
  `PARTIAL`.
- Optional manifest staleness falls back per object only when one exact,
  scan-opened table covers every dropped claim and survives final planning.
  Malformed input, permissions/arbitrary I/O, incomparable identity, invalid
  offsets, and stale sole sources remain fatal. Discovery interface names are
  read at most 64 bytes and never beyond their containing readable VMA; only
  escaped names appear in `inspect`, and capture output never contains the
  bytes.
- **Profiles, never replays.** It has only the bounded metadata decoders listed
  in the field allowlist and no intentional secret/buffer decoder. Under the
  default `allowlisted` policy this holds against hostile pointer placement,
  not merely trusted ABI-valid callers.
- **Privacy-first 1.0 boundary.** The default release reports bounded function,
  registered-mechanism, return-code, latency, and lifecycle evidence. By
  default it does not correlate object handles (the opt-in `inventory
  --key-operations` adds per-key rows) and does not promise symbolic
  `CKA_CLASS` or `CKA_KEY_TYPE` output. The existing unsafe diagnostic build
  does not enlarge the default allowlist.
- A trace is evidence about the observed window only; the profile includes an
  explicit evidence-quality/completeness section (attach failures, aliased
  functions, event loss) — `COMPLETE`/`PARTIAL`, never silently confident.
  **A terminal snapshot is `COMPLETE` only behind a proven stop**: detaching a
  perf link does not wait for BPF callbacks already running on another CPU,
  so the final drain counts as proven (`evidence.drain_proven`) only when the
  stop gate observed quiescence and no record arrived past it, on x86_64
  (`evidence.stop_quiescence` says which); otherwise the terminal verdict is
  `PARTIAL`. `evidence.verdict_detail` says what is behind a `PARTIAL`:
  `clean_but_unproven` (no gap; only the final drain is unproven),
  `attribution_only` (counts are exact; a name, owner, mechanism or semantic
  interpretation is withheld, as for every count-only scanned slot), or
  `concrete_gap` (an observation loss or degraded semantics), and
  `evidence.gap_classes` names the fields that caused it. The live evidence
  line states the same reason. Absence of a call means "not observed in
  this window," never "the application cannot do it"; aliased table entries are
  ambiguous by construction; requested attributes are what the app asked for,
  not the key's effective policy. Full honest-claims section:
  [docs/usage.md](usage.md#honest-claims).
- The schema is `p11scope/observed-profile/v3` for `profile` and
  `p11scope/observed-profile/v3-metrics` for `metrics`, with optional
  discovery input at `p11scope-manifest/5`, documented at
  [docs/schema/observed-profile-v3.md](schema/observed-profile-v3.md).
  Schema ids are opaque exact dispatch keys; the major/minor spelling grants
  no compatibility.

## Containers and Kubernetes

Uprobes bind to the file inode. When containers share the same underlying
provider file and are within the capture scope, one attachment can observe
their calls after the probes are installed, including calls from later pods.
Separate overlay instances and copy-up need additional identity handling;
they do not inherit that guarantee. A process retaining a pre-copy-up mapping
reads `unknown` with the `original_file_unproven` gap, and its later calls
past the copy-up are missed, on both identity backends. See the
[copy-up limitation and restart workaround](known-limitations.md#overlay-xinocopy-up-identity-divergences-d-c7-2d-c7-3).

The v0.5.0 Knative warm capture observed 1,200/1,200 calls. Its cold first
request started before attachment and only 84/1,200 calls were observed,
despite zero kernel event loss. This is a disclosed coverage limit, not
complete cold-start capture. Historical `overlay2` checks are in
`docs/notes/phase4-matrix.md`: on the v0.1.0 release candidate the Docker,
shared-layer, kind-pod, fork-scope and Knative lanes all passed with exact
counts (host kernel 7.0; see the
[v0.1.0 notes](https://github.com/mingulov/p11scope/releases/tag/v0.1.0)).
This release's qualification is
[CHANGELOG.md](../CHANGELOG.md#qualification-of-this-release).
`deploy/k8s` is a least-privilege node DaemonSet built from this tree (not a
published image or an operator), with a committed kind end-to-end test
(`scripts/kind-e2e.sh`); see [deploy/k8s/README.md](../deploy/k8s/README.md) for
the privileges it needs and why.

Manifest-free discovery collapses matching overlay mappings in that common
shared-layer case so the kernel point is attached once. Overlayfs classification,
inode metadata, and identical bytes do not prove physical identity across separate
overlay instances, so every such collapse is published as uncertainty and forces
`PARTIAL`; a distinct byte-identical instance could otherwise be under-counted.

Initial discovery and `p11scope inspect` scan provider tables already mapped in
the target and make zero PKCS #11 calls. The explicit unprivileged
`p11scope-discover` helper alone performs exactly ten bounded `C_GetInterface`
compatibility queries when that export is available and never calls
`C_Initialize`. For a command the observer owns, `p11scope run`
starts capture before releasing the child and loader/export hooks react to
later loads. The
optional unprivileged helper (`p11scope-discover`) can prepare a manifest
offline while the same provider identity is available; a manifest cannot be
conjured after a missed capture to make that window complete.

Provider identity is pinned by SHA-256 at attach and re-checked (`fstat`
ino/size/ctime) before, during, and after capture; a change during capture
sets `evidence.provider_changed`, which forces the report `PARTIAL`. Profile
output is published atomically (private temp beside the target, fsync,
rename). `-o` names a regular file: a directory, a device node such as
`/dev/null`, a FIFO, a socket or a symbolic link is refused before the capture
starts, never replaced.

Memory scanning is heuristic discovery. Live and terminal evidence are PARTIAL
while scan-only semantic claims remain. P11Lab joins reject scan-only and
conflict modules; an accepted manifest may authorize only its exact pinned
object, offset, and canonical function name. `p11scope run` never
implicitly releases a root child: a non-root observer keeps its UID/GID while
losing capabilities, and a sudo-root observer requires valid non-root
`SUDO_UID`/`SUDO_GID` values naming one existing non-root account and drops to
them before the release barrier. Root without that explicit target (or
`--user`) and set-id invocations are refused; those environment values
select the target account but do not authenticate that the launcher was
`sudo`. The child also receives `no_new_privs`, no capabilities, the
observer's environment unchanged
except `SUDO_*`/`P11SCOPE_*` control variables (named on stderr under -v when
withheld), and no unrelated inherited file descriptors. Its executable is opened
by the observer (root under sudo) before fork and executed by descriptor, so
the target account needs no directory search permission on its path; scripts
must be invoked through an explicit ELF interpreter such as `/bin/sh script`.
The sudo path restores the invoker's supplementary groups from the account
database (glibc may return only the primary group) and home environment
(`HOME`/`USER`/`LOGNAME`/`SHELL` from the passwd entry, `XDG_RUNTIME_DIR`
when `/run/user/<uid>` is the invoker's own, otherwise unset), so
HSM/device-group workloads run as if launched directly; `-v` prints the
restored identity.

The [v0.3.0 GitHub release notes](https://github.com/mingulov/p11scope/releases/tag/v0.3.0)
identify final tagged-artifact qualification and hosted CI. The
[changelog](../CHANGELOG.md#qualification-of-this-release) and earlier campaign
records in `docs/` retain revision-specific historical evidence.

When used, the helper recreates the table in its own process; it never reads or
injects into the observed process. Uprobes are bound to the verified target
inode and file offset, and the PID/cgroup guard executes before argument
capture.

## Project family

| Component | Responsibility |
| --- | --- |
| [pkcs11-check](https://github.com/mingulov/pkcs11-check) | Actively exercises and validates a provider |
| **p11scope** | Passively observes real application behavior |
| [pkcs11-components](https://github.com/mingulov/pkcs11-components/) | Shared PKCS#11 ABI layouts, module acquisition and mechanism metadata |
| [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) | Remote PKCS#11 access through a daemon and client shim |
| [p11lab](https://github.com/mingulov/p11lab) | Planned integration: combine observed profiles and provider test results into migration assessments |

Integration boundary: the versioned `observed-profile.json` schema. The
userspace side is Rust and reuses pkcs11-components' PKCS#11 core (official
name tables, mechanism registry, module-loading FFI) rather than duplicating
it; the eBPF observer itself is new code.
