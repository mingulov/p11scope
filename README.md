<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# p11scope

Observe the real PKCS#11 dependency surface of a running Linux application —
functions, mechanisms, errors, latency and safe policy metadata — **without
replacing its module or changing its configuration**.

`p11scope` is a non-interposing PKCS#11 workload profiler and diagnostic
observer built on eBPF uprobes. It discovers the provider's actual function
table (including stripped providers with no `C_*` symbols), attaches probes by
file offset, and produces a versioned `observed-profile.json` for migration
assessment and incident diagnostics.

> **Status: v0.2.0**, the first release of the existing commands: `doctor`,
> `inspect`, `profile` (including `--mode metrics`), `trace`, and `run`, with
> memory-scan discovery, multi-module capture, and schema v3. Read the
> [known limitations](CHANGELOG.md#known-limitations) before relying on a
> capture; `--system` is a preview. The [v0.1.0 GitHub release notes](https://github.com/mingulov/p11scope/releases/tag/v0.1.0)
> identify tagged-artifact qualification and hosted CI;
> [CHANGELOG.md](CHANGELOG.md#qualification-of-this-release) preserves
> revision-specific pre-release evidence.

Function-table support is cumulative: legacy PKCS #11 2.00, every 2.01–2.40
table, and standard 3.0, 3.1, and 3.2 interfaces (all 104 slots published in
the final 3.2 header). A newer minor version (after 2.40 or 3.2) is read up to
the slots of the newest known layout; the report names the rest as a surface
gap and stays `PARTIAL`. Exact `"PKCS 11"` interface names take the normal path.
Alternate, null, or unreadable names are not discarded: discovery accepts a
bounded known prefix only when the table is independently corroborated by the
module's standard exports or legacy table, records that evidence as `PARTIAL`,
and leaves deceptive/vendor tables undecoded. The explicit offline helper
performs ten fixed `C_GetInterface` queries before any provider initialization;
live observation remains passive.

See [CHANGELOG.md](CHANGELOG.md) for what v0.1.0 contains and its known
limitations, [Install](#install) to build and install it, and
[docs/usage.md](docs/usage.md) for the full operator's guide (privileges,
kernel floor, overhead, and the evidence/completeness model — every
quantitative claim there cites the script that measured it).

## Building from source

The root manifest selects two patched crates reconstructed from
`third-party/sources.json`; their generated trees are intentionally absent from
Git. Mise selects the project's Rust 1.98.1 toolchain, and `scripts/cargo.sh`
prepares the generated sources before executing Cargo:

```sh
mise install
mise exec -- ./scripts/cargo.sh +1.98.1 build --locked
```

The stable toolchain version is single-sourced from `.release-rust-version`
(currently 1.98.1), which `mise.toml`, CI, and the build scripts all read. It is the only
supported toolchain (no older MSRV); it is bumped as new stable Rust releases
ship.

Preparation downloads only the recipe-pinned crates.io archives and verifies
their hashes, ordered patches, final tree hashes, and receipts. For an offline
or frozen build, place the exact archives (`aya-0.14.0.crate` and
`aya-obj-0.3.0.crate`, per `third-party/sources.json`) in
`third-party/archives/` first, or
run `python3 -I scripts/prepare-dependencies.py --archive-dir DIRECTORY`, then
use `mise exec -- ./scripts/cargo.sh +1.98.1 build --locked --offline`. An
ordinary fresh checkout therefore needs archive access. A plain Git checkout
or GitHub's automatic source archive excludes the generated trees, receipts
and local archive cache. All locked registry packages and the fixed
[pkcs11-components](https://github.com/mingulov/pkcs11-components/) Git revision
(`d0a47c7`) are separate Cargo inputs and
must already be cached for an offline build from that checkout. The release's
source export embeds the two exact pinned Aya archives, but fetching the
remaining locked Cargo dependencies requires network access or a populated
cache. A separate full offline export can embed the complete dependency
payload; see below.

For a self-contained full source export and its fixed unprivileged recipient
bootstrap, use Python >=3.11, or Python 3.10 with the distro `python3-tomli`
package installed and verified before disconnection; see [the offline build
guide](docs/build-offline.md).

See [development setup](docs/development.md) for the Ubuntu 26.04 primary-host
packages, pinned Rust/BPF tools, and canonical checks. Ubuntu 26.04 is a
development host choice, not a product runtime dependency. The command above
is a debug build of every binary; [Install](#install) describes the release
assets and local release-mode builds.

## Install

p11scope v0.1.0 is distributed through the
[GitHub release](https://github.com/mingulov/p11scope/releases/tag/v0.1.0)
as a static x86-64 Linux observer bundle, optional glibc and musl discovery
helper bundles, and a source export. Download `SHA256SUMS` with the bundle you
choose. The release also provides `RELEASE.json` with curated provenance;
each bundle contains its license notices and a copy of that record.

| Bundle | Use |
| --- | --- |
| `p11scope-0.1.0-x86_64-linux-musl.tar.gz` | Static observer, with the eBPF object embedded; needed for capture. |
| `p11scope-discover-0.1.0-x86_64-linux-gnu.tar.gz` | Optional helper for 64-bit glibc providers. |
| `p11scope-discover-0.1.0-x86_64-linux-musl.tar.gz` | Optional helper for 64-bit musl providers. |

For example, download the observer and `SHA256SUMS` into a private directory,
then verify the archive before extraction:

```sh
download_dir=$(mktemp -d /var/tmp/p11scope-install.XXXXXX)
cd "$download_dir"
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.1.0/p11scope-0.1.0-x86_64-linux-musl.tar.gz
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.1.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf p11scope-0.1.0-x86_64-linux-musl.tar.gz
sudo install -m 0755 p11scope-0.1.0-x86_64-linux-musl/p11scope /usr/local/bin/p11scope
p11scope --version
sudo p11scope doctor
```

Keep the extracted bundle with its licenses, notices and `RELEASE.json` as
the record of the binary you installed.

To use attested semantic capture, download and verify the helper bundle for
the provider's C library, then extract and install its `p11scope-discover`
executable in the same way. Run `p11scope-discover --version` and the helper
itself as an ordinary user; never give it file capabilities or a set-id bit.
The observer needs Linux x86-64 and the kernel and privilege requirements
below. The helper needs the matching provider ABI and libc; a 32-bit provider
requires a separately built 32-bit helper.

The release also includes `p11scope-0.1.0-source.tar.gz`. It contains the
committed source and the two pinned Aya archives needed to reconstruct the
local patches. Building it still needs network access for the remaining
locked Cargo dependencies, plus the Rust/BPF and host build tools described
above. The [offline build guide](docs/build-offline.md) describes an optional
full export assembled separately.

### Build locally from source

`cargo install` is not supported: the root manifest patches two crates whose
trees `scripts/prepare-dependencies.py` generates. The official artifacts are
built and verified by `scripts/build-release.sh` (see
[RELEASING.md](RELEASING.md)); the commands below are local build examples.

**Build prerequisites** (x86-64 Linux; Ubuntu package names): the pinned
toolchains from [docs/development.md](docs/development.md). The scripts select
the stable toolchain as `+1.98.1`, and the static observer needs its musl
target:

```sh
sudo apt-get install -y build-essential clang-18 llvm python3 git
rustup toolchain install 1.98.1 --profile minimal
rustup target add --toolchain 1.98.1 x86_64-unknown-linux-musl
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
cargo +1.98.1 install bpf-linker --version 0.10.4 --locked
```

**Observer (`p11scope`).** A static musl binary with the BPF object embedded;
it never loads a provider, so one binary serves supported x86-64 Linux hosts:

```sh
RUSTFLAGS='-C target-feature=+crt-static' ./scripts/cargo.sh +1.98.1 build \
  --locked --release --no-default-features \
  --target x86_64-unknown-linux-musl --bin p11scope
sudo install -m 0755 target/x86_64-unknown-linux-musl/release/p11scope /usr/local/bin/
```

**Optional helper (`p11scope-discover`).** Needed only for
[attested semantic capture](docs/usage.md#attested-semantic-capture). It loads
the provider with `dlopen`, so it is dynamically linked and must match the
provider's C library: build it on (or in a container of) a glibc system for
glibc providers, and on a musl system such as Alpine for musl providers.

```sh
./scripts/cargo.sh +1.98.1 build --locked --release -p p11scope-discover
sudo install -m 0755 target/release/p11scope-discover /usr/local/bin/
```

The helper runs unprivileged and drops groups, IDs, and capabilities before
loading provider code. Never give it capabilities or a set-id bit.

**Kernel and privileges.** Linux 5.15 or newer with BTF
(`/sys/kernel/btf/vmlinux`). Captures need root (`sudo p11scope ...`) or file
capabilities on the observer. The attach floor is backend-dependent: on
kernels ≥ 6.9 the default first attempts uprobe-multi links and falls back
to per-probe links if multi is unsupported. With multi active,
`CAP_BPF`+`CAP_PERFMON` suffice (measured 136/136 at
`perf_event_paranoid=4`); on the per-probe `perf_event` path a restrictive
paranoid needs `CAP_SYS_ADMIN`
([measured matrix](docs/usage.md#privileges-per-environment)). The full set is:

```sh
sudo setcap 'cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep' \
  /usr/local/bin/p11scope
```

Anyone who can execute a capability-carrying observer can observe other
users' processes, so restrict who may execute it (for example, a dedicated
group and mode `0750`).

**Check the install:**

```sh
p11scope --version
sudo p11scope doctor
```

If you installed the optional helper, also run
`p11scope-discover --version` as your normal user.

## Why

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
  semantics-unverified and count-only. Rows carry standard function names
  when the provider's own `.dynsym` exports every standard name exactly where
  its function table points (`linkage: "exports"`, as SoftHSM2 does);
  otherwise they read `unknown#<ordinal>`, never a guessed name. `doctor` and
  `inspect` need the same privileges as a capture to assess or read another
  user's process:

  ```bash
  sudo p11scope doctor --pid 12345
  sudo p11scope inspect --pid 12345
  sudo p11scope profile --pid 12345 --duration 60 -o diagnostic-profile.json
  ```

  Whole-machine capture (a preview in v0.1.0) needs no PID or cgroup path;
  `--module` aims it at one provider:

  ```bash
  sudo p11scope profile --system --duration 60 -o system-profile.json
  sudo p11scope profile --system --module /usr/lib/softhsm/libsofthsm2.so \
    --duration 60 -o softhsm-profile.json
  ```

  For semantic capture, follow the separate
  [attested workflow](docs/usage.md#attested-semantic-capture). The optional
  `p11scope-discover` helper executes provider code in its own unprivileged
  process and must match the provider's ABI/libc. Passing `--manifest` is
  explicit operator attestation of exact accepted function-name/offset claims;
  generating a file or matching its hash does not make that decision for you.

  Automated combination with candidate-provider test results is the planned
  integration with [p11lab](https://github.com/mingulov/p11lab).
  An unobserved call or missing metadata remains unknown.

  Full quickstart, real command output, and `trace` mode:
  [docs/usage.md](docs/usage.md#quickstart).

## What it does NOT intentionally decode

There is no decoder or dump switch for PINs, key material, `CKA_VALUE`, labels,
`CKA_ID`, plaintext, ciphertext, signatures, wrapped blobs, random output, raw
mechanism byte arrays, raw session handles, or ordinary buffers.

The default capture policy is `allowlisted`, and it is safe against a caller
that aliases a metadata pointer into unrelated readable memory. Pointer-derived
bytes become output only by *exact* membership in a finite published set: a
mechanism id in the registry, or one of the 104 published function names.
Anything else is dropped in the kernel. That is a containment boundary, not
pointer validation — `bpf_probe_read_user` avoids faults, it does not check
types.

The previous unvalidated parameter/template decoders still exist, but only
behind **both** an off-by-default Cargo feature and an explicit
`--unsafe-unvalidated-metadata` flag; the flag alone cannot enable code that is
absent from the shipped eBPF object, and `metrics` mode refuses it outright.
The official release artifact is built `--no-default-features`, so packaging
fails if the unsafe path is reachable at all.

The field-by-field inventory is
[docs/privacy/allowlist-v1.md](docs/privacy/allowlist-v1.md), extended by
[docs/privacy/allowlist-v2.md](docs/privacy/allowlist-v2.md) (interface
selection, attach mechanism, descendant rebuild, task-uprobe loss and ABI
refusal evidence). It is backed by a secret-canary suite (`scripts/verify-canaries.sh`) that plants sentinel PINs,
key material, and buffer contents in a real workload and scans every output
artifact and every observer-owned BPF map for leaks — including hostile-alias
lanes, secret/unterminated/hostile-alias `C_GetInterface` names, and the
transient raw `pMechanism` address the return probe needs.

See the [quickstart](docs/usage.md#quickstart) for the CLI, live output, and
trace lines, and [the v3 schema](docs/schema/observed-profile-v3.md) for the
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
  and the event-loss finding at high call rates: [docs/usage.md](docs/usage.md#overhead-measured)).
- Requires elevated privileges, kernel-version-dependent, x86-64 first. The
  default attempts uprobe-multi on kernels ≥ 6.9, with per-probe fallback if
  the kernel refuses multi. With multi active, `CAP_BPF`+`CAP_PERFMON`
  suffice to attach at `kernel.perf_event_paranoid=4` (measured 136/136);
  on the per-probe `perf_event` path a restrictive paranoid needs
  `CAP_SYS_ADMIN`. Manifest-free scanning of a same-UID non-descendant
  additionally needs `CAP_SYS_PTRACE` under Yama `ptrace_scope=1`, or
  equivalently a descendant target / `--manifest`. Root works everywhere.
  No `CAP_LEASE`, no `fs.suid_dumpable=0`, no root-owned trusted exec dir
  ([measured matrix](docs/usage.md#privileges-per-environment)).
  Kernel floor ≥5.15; on an unsupported environment the tool fails with a
  named cause and a hint, never a panic or a raw verifier dump
  (`docs/notes/phase5-unsupported.md`).
- `inspect` shows every provider-shaped module mapped by the target; an
  optional `--module` only narrows that set. A target whose memory maps it
  cannot read is an error (exit 1), never an empty module list. On the
  measured p11-kit stack, p11-kit's fixed closure array exceeds the 512-slot
  ceiling and is refused whole, while the later-fitting SoftHSM2 backend
  attaches; the report is explicitly `PARTIAL`, not a claim that the proxy
  layer was captured.
- A capture has 512 attach slots. `--pid`, `run`, and any capture aimed with
  `--module` admit providers in discovery order. A `--cgroup` or `--system`
  capture without `--module` admits each provider whole or not at all, by
  value — `--manifest` providers first, then providers whose function table
  is corroborated, then heuristic finds, proxy closure arrays last. Heuristic
  finds and closure arrays may not use the last 128 slots (25%), which stay
  free for corroborated providers found later in the capture. A refusal names
  what holds the slots; in such a shared capture it also names the reserve and
  suggests `--module`.
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
  members, and 512 attach slots. Any bounded omission is evidence and forces
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
  registered-mechanism, return-code, latency, and lifecycle evidence. It does
  not correlate object handles and does not promise symbolic `CKA_CLASS` or
  `CKA_KEY_TYPE` output. The existing unsafe diagnostic build does not enlarge
  the default allowlist.
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
  [docs/usage.md](docs/usage.md#honest-claims).
- The schema is `p11scope/observed-profile/v3` for `profile` and
  `p11scope/observed-profile/v3-metrics` for `metrics`, with optional
  discovery input at `p11scope-manifest/5`, documented at
  [docs/schema/observed-profile-v3.md](docs/schema/observed-profile-v3.md).
  Schema ids are opaque exact dispatch keys; the major/minor spelling grants
  no compatibility.

## Containers and Kubernetes

Uprobes bind to the file inode, so attaching to a provider `.so` in a shared
image layer observes every container on that node using that layer —
including pods started later (e.g. Knative scale-from-zero). That
inode-sharing property is the headline bet; it depends on the `overlay2`
storage driver and is validated, with exact call counts, against a real
Docker container, two containers sharing one image layer, a Kubernetes pod
(kind), and a Knative service's scale-from-zero cold start
(`docs/notes/phase4-matrix.md`). On the v0.1.0 release candidate the Docker,
shared-layer, kind-pod, fork-scope and Knative lanes all passed with exact
counts (host kernel 7.0; see
[CHANGELOG.md](CHANGELOG.md#qualification-of-this-release)).
`deploy/k8s` is a least-privilege node DaemonSet built from this tree (not a
published image or an operator), with a committed kind end-to-end test
(`scripts/kind-e2e.sh`); see [deploy/k8s/README.md](deploy/k8s/README.md) for
the privileges it needs and why.

Manifest-free discovery collapses matching overlay mappings in that common
shared-layer case so the kernel point is attached once. Overlayfs classification,
inode metadata, and identical bytes do not prove physical identity across separate
overlay instances, so every such collapse is published as uncertainty and forces
`PARTIAL`; a distinct byte-identical instance could otherwise be under-counted.

Initial discovery and `p11scope inspect` scan provider tables already mapped in
the target and make zero PKCS #11 calls. The explicit unprivileged
`p11scope-discover` helper alone performs exactly ten bounded `C_GetInterface`
compatibility queries before any provider initialization. For a command the observer owns, `p11scope run`
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
them before the release barrier. Root without that explicit target and set-id
invocations are refused; those environment values select the target account
but do not authenticate that the launcher was `sudo`. The child also receives
`no_new_privs`, no capabilities, a small environment allowlist, and no
unrelated inherited file descriptors. Its executable is opened before fork
and executed by descriptor; scripts must be invoked through an explicit ELF
interpreter such as `/bin/sh script`.
For now, the sudo path clears supplementary groups, so workloads needing an
HSM/device group should use an already-running target until explicit run-as
group selection is implemented.

The [v0.1.0 GitHub release notes](https://github.com/mingulov/p11scope/releases/tag/v0.1.0)
identify final tagged-artifact qualification and hosted CI. The
[changelog](CHANGELOG.md#qualification-of-this-release) and earlier campaign
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

## License

Public license: GPL-3.0-or-later — see [LICENSE](LICENSE).
BPF sources: GPL-2.0-only — see
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).
Shared BPF/userspace definitions (`crates/ebpf-common`): GPL-2.0-or-later — see
[LICENSES/GPL-2.0-or-later.txt](LICENSES/GPL-2.0-or-later.txt). This crate is
compiled into both the BPF object the kernel loads (used there under GPL-2.0)
and the observer (used there under GPL-3.0).

Per-file SPDX tags (`GPL-3.0-or-later` for userspace, docs, and scripts;
`GPL-2.0-only` for BPF programs; `GPL-2.0-or-later` for `crates/ebpf-common`)
remove any ambiguity.

Contributions require a CLA granting broad sublicensing/relicensing rights;
see [CONTRIBUTING.md](CONTRIBUTING.md).
