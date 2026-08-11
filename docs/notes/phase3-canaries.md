# Phase 3 — Gate G3 secret-canary suite

`scripts/verify-canaries.sh` is the release gate that decides whether the
Phase 3 privacy allowlist can be trusted: it plants a distinct,
high-entropy sentinel in every place a secret could live, drives a real
capture against SoftHSM2, and then searches for every sentinel — as raw
bytes and as hex — in every artifact the capture produced, including a BPF
map dump for every map the program owns. It also proves the scanner itself
works, via a mandatory positive control, before trusting any clean result.

Run twice on this host (kernel `7.0.0-28-generic`); both runs ended
`=== canaries: NONE LEAKED ===` with the same shape.

## Sentinels

`scripts/fixtures/canary_workload.c` and the scanner in
`scripts/verify-canaries.sh` hardcode the same eight sentinels (each a
distinct, random 16+ byte pattern — kept in sync between the two files by
inspection, not by parameter-passing, matching how other scripts in this
repo hardcode shared expectations):

| Sentinel | Bytes | Where planted |
|---|---|---|
| `PIN` | 43 | `C_Login` — `pPin`/`ulPinLen` |
| `KEY` | 43 | `C_CreateObject` — `CKA_VALUE` |
| `LABEL` | 45 | `C_CreateObject` — `CKA_LABEL` |
| `ID` | 42 | `C_CreateObject` — `CKA_ID` |
| `PLAINTEXT` | 49 | `C_Digest` — input data |
| `IV` | 42 | `C_EncryptInit` (`CKM_AES_GCM`) — `CK_GCM_PARAMS.pIv` (offset 0) |
| `AAD` | 43 | `C_EncryptInit` (`CKM_AES_GCM`) — `CK_GCM_PARAMS.pAAD` (offset 16) |
| `BOOLLONG` | 48 | `C_CreateObject` — `CKA_TOKEN` with `ulValueLen = 48` (deliberately `!= 1`, to probe the gate) |

`IV` and `AAD` sit at exactly the two `CK_GCM_PARAMS` offsets (0 and 16)
the allowlist forbids dereferencing — the plan calls these out by name.
`BOOLLONG` targets the `ulValueLen == 1` gate specifically: `CKA_TOKEN` is
on the policy-boolean allowlist, so if the gate were missing or
off-by-something, this is the field that would leak.

## Workload

`scripts/fixtures/canary_workload.c` (pattern: `spike/harness.c`, indirect
calls through the module's own `CK_FUNCTION_LIST`) drives SoftHSM2
directly — no fixture provider was needed. Every one of the six required
entry points (`C_Login`, `C_CreateObject`, `C_DigestInit`/`C_Digest`,
`C_EncryptInit`) is part of the real v2.40 API SoftHSM2 exports, so the
uprobes fire regardless of whether the call subsequently succeeds. Several
calls are *expected* to fail (wrong PIN, a garbled boolean length, an
invalid key handle) — per the task brief, that is fine and even useful:
the entry probe reads its arguments before the real implementation gets a
chance to validate or crash on them.

Observed per-call return codes (`target/canaries/profile.log`):

```
C_Login -> 0xa0            (CKR_PIN_INCORRECT — sentinel is not the real PIN)
C_CreateObject -> 0x101    (CKR_ATTRIBUTE_VALUE_INVALID — malformed CKA_TOKEN length)
C_EncryptInit -> 0x82      (CKR_KEY_HANDLE_INVALID — CreateObject above didn't produce a key)
C_CloseSession -> 0x0
C_Finalize -> 0x0
```

All five calls landed with the sentinels live in argument memory; the
entry uprobes fire independent of these outcomes.

**Proof the interesting code paths actually ran** (not just that the scan
found nothing): `target/canaries/observed.json` shows the GCM shape decode
fired for real —

```json
{
  "mechanism_hex": "0x1087",
  "ops": ["encrypt"],
  "params": [{ "shape": "gcm", "iv_len": 42, "aad_len": 43, "tag_bits": 128 }]
}
```

`iv_len`/`aad_len` (42/43) are exactly the `IV`/`AAD` sentinel lengths —
confirming the BPF program read `ulIvLen`/`ulAADLen`/`ulTagBits` (offsets
8/24/32) while `pIv`/`pAAD` (offsets 0/16, holding the sentinel *pointers*)
were never dereferenced. And the `templates` section shows the
`ulValueLen == 1` gate held: `CKA_TOKEN`'s type (`0x1`) is recorded in
`attr_types`, but `policy_booleans.observed_true`/`observed_false` are both
empty — the malformed 48-byte boolean was never read, not even classified
as "seen", exactly as the gate is supposed to behave.

## Artifacts scanned

- `target/canaries/observed.json` — the output profile JSON (`--mode profile`).
- `target/canaries/profile.log` — the profiler's combined stdout/stderr.
- A BPF map dump (`bpftool map dump id <id> -j`) for **every map owned by
  this run's `p11_entry`/`p11_return` programs**, discovered via a
  before/after `bpftool prog show --json` diff around the attach point
  (see "Environment quirk" below) — 10 maps: `CGROUP_FILTER`, `CONFIG`,
  `EVENTS`, `LOST`, `MECH_SHAPE`, `PID_FILTER`, `RV_COUNTS`, `SLOT_KIND`,
  `START`, `STATS`. Maps are dumped immediately after the workload process
  exits but while the profiler (and therefore its BPF programs and maps)
  is still attached — a map dumped after the profiler exits reads nothing,
  since its fds and the kernel objects they hold alive are gone.
  `START` in particular carries a copy of every decoded scalar
  (`p0`/`p1`/`p2`, `attr_types`, session/mechanism ids) for calls that had
  entered but not yet returned at dump time — the most direct check that
  nothing beyond scalars and type codes ever reached kernel memory.

  `EVENTS` is a ring buffer; `bpftool map dump` structurally cannot
  iterate `BPF_MAP_TYPE_RINGBUF` contents (it always reports `[]` and
  exits non-zero, independent of whether anything was ever posted) — the
  scanner treats that as valid, not a failure, and still dumps it for
  completeness. This is not a coverage gap: `Event`/`CallStart` (the
  records the ring buffer and `START` carry) hold only scalars and type
  codes by construction, never raw pointer-fetched bytes, so `START`
  (a real hash map, genuinely dumpable) gives the same assurance `EVENTS`
  would if it could be dumped, and the consumed ring content that
  userspace did read is already covered by `observed.json`/`profile.log`.

Each artifact is searched for every sentinel two ways: as literal raw
bytes, and as the sentinel's own lowercase/uppercase hex text. The BPF map
dumps get a third, structural check: bpftool's JSON encodes every map byte
as an individual `"0xHH"` token, so the scanner also reassembles those
tokens back into the raw bytes they represent (in file order) and searches
that reconstruction — this is what actually proves a sentinel never
reached a map's key or value bytes, independent of the JSON's exact
formatting.

## Positive control

Before trusting any "clean" result, the script writes the `PIN` sentinel
into a scratch file (`target/canaries/positive_control.txt`, not one of
the real capture artifacts) and runs it through the exact same detection
function used on the real artifacts. Both runs on this host:

```
positive control OK: scanner found {'PIN'} in target/canaries/positive_control.txt
```

If this assertion had failed, the script would exit non-zero before
scanning anything else — a scanner that cannot find a sentinel it was
just handed cannot be trusted to report "clean" on the real artifacts
either.

## Result

```
$ bash scripts/verify-canaries.sh
...
this run's programs: [(6971, 'p11_entry'), (7040, 'p11_return')]
dumped 10 maps: CGROUP_FILTER, CONFIG, EVENTS, LOST, MECH_SHAPE, PID_FILTER, RV_COUNTS, SLOT_KIND, START, STATS
...
Evidence: 136/136 probes attached · 68 slots · 0 aliased · 0 skipped · 0 in-flight → COMPLETE
=== scan every artifact for every sentinel ===
positive control OK: scanner found {'PIN'} in target/canaries/positive_control.txt
scanned 2 text artifacts and 10 BPF map dumps (CGROUP_FILTER, CONFIG, EVENTS, LOST, MECH_SHAPE, PID_FILTER, RV_COUNTS, SLOT_KIND, START, STATS) for 8 sentinels
=== canaries: NONE LEAKED ===
```

Zero sentinels found in any real artifact, on both runs. No genuine leak
was found: the plan's privacy contract (only fixed-offset scalars and
attribute *types* are ever read; `pPin`, `CK_GCM_PARAMS.pIv`/`pAAD`, and
every `pValue` outside the length-gated policy-boolean allowlist are never
dereferenced) held under this suite's attempts to break it.

## Environment quirk (not a suite defect)

This sandbox's kernel retains stray `p11_entry`/`p11_return` program
copies from earlier, unrelated captures — their prog fds end up held open
by PID 1 well after the owning `p11scope` process has exited, for reasons
outside this script's control. Matching BPF programs by name alone would
risk dumping (and misattributing a "leak" to) a foreign, unrelated
program's maps left over from a previous run. The script works around
this by snapshotting `bpftool prog show --json` immediately before
starting its own profiler and again right after attach completes, then
only dumping maps owned by programs that are new in the second snapshot.
An earlier draft that matched by name alone was observed to pick up one
stale leftover pair (doubling every map name in the dump list); the
before/after diff fixed it — confirmed clean (exactly 10 maps, no
duplicates) on both final runs.

## Verification

- `bash scripts/verify-canaries.sh` — twice, both `=== canaries: NONE LEAKED ===`.
- `bash scripts/verify-attach-e2e.sh` — unaffected, still `=== e2e: ALL OK ===`
  (136/136 probes, `COMPLETE`).
- `cargo test --workspace --release` — 89 tests green, unchanged (this
  task added no Rust code).

## Files

- `scripts/verify-canaries.sh` — the suite: build, SoftHSM2 token setup,
  attach + run the canary workload, dump every BPF map the program owns,
  scan every artifact, positive control. `set -eu` as an explicit body
  line.
- `scripts/fixtures/canary_workload.c` — plants the eight sentinels
  against a real SoftHSM2 module.
