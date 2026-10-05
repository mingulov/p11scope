<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# E16 execution surfaces

E16 asks whether discovery finds, or honestly refuses, PKCS#11 code in
shapes other than an ordinary provider library with an exported factory.
It keeps three facts apart: what discovery planned, what the live capture
counted, and what the fixture independently executed. A process exit, a
discovery message, an attach count or another module's traffic never
substitutes for the owned call ledger, and a pathname or a function name is
never an identity.

## Surfaces

Every fixture lives under `tests/fixtures/e16/` (the control reuses
`tests/fixtures/live-discovery-provider.c`). Each driver calls one resolved
endpoint; for table shapes that endpoint is table position 0, reported under
the label `table[0]` because a position is not a name.

| Surface | Shape | Hinted (`--pid` + `--module`) | Unhinted `--system` |
| --- | --- | --- | --- |
| control | exported 3.2 table, standard factories | admitted; exact endpoint counts | admitted; exact endpoint counts |
| synthetic HSM proxy | standard client table whose entries forward over an owned socketpair | admitted like the control | admitted like the control |
| static provider | 104-entry table and `C_GetFunctionList` linked into the executable, not in `.dynsym` | 104 identity-pinned count-only endpoints | not scanned: coverage gap, no record |
| vendor-only factory | standard table, only `Vendor_GetFunctionList` exported | 104 identity-pinned count-only endpoints | not scanned: coverage gap, no record |
| direct exports | `C_Initialize`, `C_GenerateRandom` and others exported, no factory, no table | explicit no-table record; nothing attributed | not scanned: coverage gap, no record |
| anonymous JIT | `mov eax,0; ret` in an anonymous r-x page | nothing admitted; capture stays `PARTIAL`; the image's own no-table record is a separate fact | nothing admitted |

Static and vendor tables are valid standard-layout tables. A hidden or
vendor-named factory is no reason to refuse scan admission, and no reason to
invent names or semantics either: every admitted endpoint is count-only
(`semantic_authorized == false`, names `["unknown"]`).

Unhinted `--system` reads an object's memory only when its `.dynsym`
defines a registry factory (`C_GetFunctionList`, `C_GetInterfaceList`,
`C_GetInterface`, `NSC_GetFunctionList`, `FC_GetFunctionList`, or a
`--hook-symbol`). The static, vendor-only and direct-export shapes are
therefore skipped there without any skip record. That is a coverage gap,
not an explicit refusal: E16 measures it so it stays visible. `--module`
(and, for a vendor factory, `--hook-symbol Vendor_GetFunctionList`) is the
way to cover such an object.

Anonymous executable memory is outside the file-backed candidate universe:
calls into it are neither discovered nor attributed (see
[known limitations](../known-limitations.md), copied code). Discovery never
reads anonymous mappings; their cost is one maps line each.

### Synthetic boundaries

- The HSM proxy is synthetic. Its transport is a socketpair inside the client
  process: no server, network or remote HSM exists, and none is observed,
  benchmarked or claimed. It shows only what a client-side probe sees of a
  proxy provider: that the client call happened and what it returned.
- The direct-export stubs share one `CK_RV name(void *)` shape. They establish
  an execution shape, not PKCS#11 ABI or semantic conformance.
- The JIT trampoline is x86-64 machine code.

## The hold protocol

All drivers share `tests/fixtures/e16/e16_protocol.h`. Every record is one
whole stderr line, written with partial-write and `EINTR` retries:

```text
P11SCOPE_E16 ready pid=<pid> starttime=<ticks> endpoint=0x<hex> image=0x<hex> calls=<n>
[P11SCOPE_E16_HOLD=1: one byte 'G' from stdin, else exit 92]
P11SCOPE_E16 call <label> <index> rv=<rv>      (index 0..n-1; rv != 0 exits 6)
P11SCOPE_E16 done calls=<n>
[P11SCOPE_E16_HOLD=1: one byte 'X' from stdin, else exit 93]
```

`endpoint` is the exact address the call loop invokes and `image` an address
in the driver executable. Everything that resolves the endpoint happens
before `ready`. Provider witness lines (`P11SCOPE_E16 provider ...`) may
interleave and carry no protocol meaning.

## Unprivileged characterization

`tests/e16_execution_surfaces.rs` builds every fixture, checks its
dynamic-export shape with `readelf`, holds each driver at the GO gate, and
runs `Engine::discover` against that child only (plan, no BPF). It checks
the module's `{dev, ino}` against the child's own `/proc/<pid>/maps`
rendering of the endpoint mapping, the digest against the fixture bytes,
and that one planned slot sits at the endpoint's exact file offset. It then
releases GO, checks the ledger and requires exit 0. A last test pins the
protocol's fail-closed exits.

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp mise exec -- ./scripts/cargo.sh +1.98.1 \
  test --locked --test e16_execution_surfaces
python3 -I tests/python/test_e16_oracle.py -v
python3 -I scripts/qualify-e16-surfaces.py --self-test
```

These are discovery and runner facts. They are not live counts.

## Live runner

`scripts/qualify-e16-surfaces.py` replaces the rejected archived
`verify-e16.py`. It reuses the existing seams rather than adding another
authority: `scripts/system-scope-receipt.py` for map_files pins, process
birth checks and pidfd teardown, `scripts/system-scope-measure.py` for the
mapping/opened-file identity bridge, and `scripts/check-capture-evidence.py`
for the report row contract.

```sh
# 1. As the checkout owner, from a clean commit: bind the built observer.
mise exec -- ./scripts/cargo.sh +1.98.1 build --locked --release --bin p11scope
python3 -I scripts/qualify-e16-surfaces.py provenance \
  --observer target/release/p11scope \
  --bpf-object target/release/build/p11scope-<hash>/out/p11scope-ebpf \
  --out /var/tmp/p11scope-ws-tmp/e16-provenance.json
# 2. As root: run one campaign into a new private directory.
sudo -n flock /var/tmp/p11scope-ws-tmp/privileged.lock \
  python3 -I scripts/qualify-e16-surfaces.py run --campaign hinted \
  --observer target/release/p11scope \
  --provenance /var/tmp/p11scope-ws-tmp/e16-provenance.json \
  --artifacts /var/tmp/p11scope-ws-tmp/e16-hinted-<stamp>
# 3. Re-verify from the retained bytes. The directory is private to its
#    creator (root after step 2), so reading it back needs the same account.
sudo -n python3 -I scripts/qualify-e16-surfaces.py verify --artifacts <dir>
```

`--campaign system-mixed` runs all six surfaces plus a foreign-traffic
driver at once under one unhinted `profile --system`. The foreign driver
calls a byte-identical copy of the control provider (same digest, different
inode) a different number of times. Its calls must appear on its own row and
never on the control's.

Each cell is judged against a fixed table in the runner, never against the
record's own claims. The rules close the eight defects the H1 review found
in the archived runner. Each has a regression in
`tests/python/test_e16_oracle.py`:

1. **Physical selection.** Rows are selected by the receipt's joined
   `{dev, ino, sha256}`, the endpoint's file offset and the executed
   ordinal. Names are recorded, never required. A foreign, ambiguous or
   unresolved owner never satisfies a cell.
2. **Identity before GO.** The endpoint mapping is pinned through map_files
   while the driver is held before GO. Before release the runner re-reads the
   addressed mapping and proves that the fixture path still names the pinned
   object. A same-path replacement, even with identical bytes, is refused.
3. **Observer provenance.** `provenance` runs unprivileged from a clean
   checkout. It records the commit, the digests of the runner, helper and
   fixture sources, the release compiler found in the binary, and each BPF
   object proved embedded at a fixed offset. `run` validates all of it
   before loading or launching anything, freezes a private copy and re-hashes
   that copy around every launch. An unrelated or changed binary, a dirty or
   unbound source, or a BPF object not embedded in this binary is refused.
4. **Bounded reads.** Driver output is read nonblocking, with byte, line and
   absolute-time bounds. Partial transcripts are kept. Silence, a partial
   line, early EOF and oversize all end as UNKNOWN on time.
5. **Lifecycle order.** GO goes only after the observer that printed the
   readiness line is proven still running. Release goes only after that
   observer exited and the retained workload passed its checks. The
   timeline is recorded and verified.
6. **Raw reduction.** Counts and refusals come from attributable report
   rows. A direct-export refusal must be the public no-table record and the
   only no-table diagnostic, naming the owned object. A foreign-only skip,
   foreign counts, missing output, unexpected owned rows or a wrong device
   domain leaves the cell UNKNOWN.
7. **Separate outcomes.** Every driver and observer exit code, signal,
   timeout and cleanup is kept and judged on its own. `[0, -15]` is a
   failure, not zero.
8. **Private evidence.** Every ancestor of `--artifacts` is opened without
   following links. Each must be a directory, not group- or world-writable
   unless sticky, and owned by the caller, root, or (as root) a real
   `SUDO_UID` account. These are the `src/output.rs` rules. Only then is the
   final directory created, exclusively and 0700. An existing directory is
   refused, never reused or re-permissioned.

A record verifies only if it matches the exact campaign: every required run
and cell, with nothing omitted, duplicated or relabeled. Every artifact must
match its digest, and cells re-derived from the bytes must equal the
recorded cells. `verify` repeats the same check on the retained directory.

### What a PASS means, and does not

A hinted PASS shows that a frozen, provenance-bound observer counted an
owned endpoint exactly on this kernel, or refused or bounded it as the
table says. The capture's `completeness` is still recorded and can
legitimately be `PARTIAL`: count-only slots withhold semantics. Aggregate
rows are the count authority, and the runner requires that the observer
exited normally after its duration. Producer quiescence after detach is
whatever the capture's own settlement fields report; E16 does not upgrade
it.

A system-mixed PASS adds three things. Unhinted discovery on a live host
counted the control and proxy endpoints exactly. Byte-identical foreign
traffic stayed foreign. The gap shapes stayed silent without being
attributed. It does not show that static, vendor-only or direct-export
providers are covered by unhinted `--system`; they are not.

## Live results

Host run, 2026-10-05: Linux 7.0.0-34-generic x86-64, as root under
`sudo -n flock /var/tmp/p11scope-ws-tmp/privileged.lock`. The observer was a
glibc release build of commit `2ecef5c`, bound by `provenance` (three
embedded BPF objects, rustc 1.98.1). The observer sources did not change
between that commit and this document. Each campaign re-verified with
`verify` from its retained directory. Calls: 16 per driver, 23 foreign.

**Hinted campaign (`--pid` + `--module`, one run per surface): six of six
PASS.**

| Surface | Owned rows | Endpoint row | Other owned rows | Probes |
| --- | --- | --- | --- | --- |
| control | 104 | 16 entered, 16 returned, ordinal 0, names `C_Initialize` | 103, 0 calls | 208 |
| synthetic HSM proxy | 104 | 16/16, ordinal 0, `unknown` | 103, 0 calls | 208 |
| static provider | 104 | 16/16, ordinal 0, `unknown` | 103, 0 calls | 208 |
| vendor-only factory | 104 | 16/16, ordinal 0, `unknown` | 103, 0 calls | 208 |
| direct exports | 0 | public no-table record, bound to the hint | none | 0 |
| anonymous JIT | 0 | none; the image's own no-table record present | none | 0 |

Every capture is `PARTIAL`, for the documented reasons: count-only slots
(`semantic_unverified_slots`) and `interface_selection`. Stop quiescence was
proven. Each per-PID observer reached readiness in about 2.6 s. Every
driver and observer exited 0.

**System-mixed campaign (one unhinted `profile --system`, about 470
processes on the host): UNKNOWN, one cell short of PASS.**

- control: PASS, 16/16 on its own row.
- foreign traffic: PASS. 23/23 landed on the byte-identical copy's own row
  (same digest, different inode) and none on the control's.
- static, vendor-only, direct exports: PASS as the measured unhinted gap. No
  owned rows and no records, as the surfaces table says.
- anonymous JIT: PASS (nothing admitted).
- synthetic HSM proxy: UNKNOWN. The observer refused it explicitly in
  `evidence.modules_skipped`: "module needs 104 more; only 512 attach slots
  are available; 449 are in use". The slots were held by the host's own
  providers (OpenSC 105, SoftHSM) and by the control and foreign copies.
  The host's p11-kit modules were refused the same way. The runner names
  this refusal and never counts it as coverage.

The UNKNOWN is the correct verdict: the proxy's calls were not measured. It
is not a discovery defect. It is the 512-slot attach ceiling
(`MAX_SLOTS`) applied to every admitted full table on the machine, in
discovery order.

Observer cost for that run, from its own stderr: scan 3.1 s, bind 2.9 s,
plan 3.9 s, projection 8.2 s, attach 0.6 s, readiness at 18.1 s, 898 probes,
RSS 318 MB at exit, longest tick 828 ms, and 11 s to detach 222 links.

## Discovery cost at scale

None of the E16 shapes adds scan work to unhinted `--system`:

- Anonymous executable memory is never grouped or read. It costs one maps
  line each. Measured unprivileged with `inspect --pid` on a process that
  loads the control provider and maps N separate anonymous r-x pages:

  | Anonymous pages | Maps lines | Wall time | Max RSS |
  | --- | --- | --- | --- |
  | 0 | 30 | 8 ms | 6.8 MB |
  | 30,000 | 60,030 | 140 ms | 21 MB |
  | 100,000 | 200,030 | 434 ms | 57 MB |

  The cost is linear, about 2.1 µs and 0.25 KB per maps line. A hinted scan
  costs the same. `inspect` reads `/proc/<pid>/maps` twice; one kernel read
  of the 200,030-line file takes 0.13 s.
- Static, vendor-only and direct-export objects are never memory-scanned
  unhinted. Their cost is one cached `.dynsym` read per object. The cost is
  coverage, not time.
- A hinted object, including a static executable, has all of its data
  mappings read (up to 256 MiB per mapping, under the global scan budget).
  Per-surface `inspect --pid` stays at 4 to 6 ms for these fixtures.
- The binding constraint at scale is the 512 attach slots, not scan time.
  A full 3.x table takes 104 slots, so one `--system` capture admits about
  four full providers. Later admissions are refused explicitly.

## Not yet qualified

- The kernel matrix. The C7.6 vng matrix must run both campaigns on each
  supported kernel tier: 5.15 per-offset links, 6.1, 6.6 and 6.8+ uprobe-multi.
  It must also run the `inspect`/`doctor` discovery cells. System-mixed needs
  a guest without other PKCS#11 providers, or fewer than about 300 attach
  slots in use, before it can reach PASS.
- An installed release artifact (musl static-pie) instead of a glibc
  development build.
- Container and pod cells (overlay identity) and a busy-host soak.
- A real remote HSM or network proxy. The fixture is synthetic by design.
