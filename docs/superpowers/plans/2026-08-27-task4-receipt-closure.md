# Task 4 Remaining-Lane Receipt Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task by task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the remaining production Task 4 lanes emit private,
source-bound, terminal evidence without changing their product oracles, then
run exactly once and serially: 07, 09, 10, 11, 14, Lane 16 `never`, Lane 16
`auto`.

**Architecture:** Use one gate-only sealed receipt envelope implemented by one
private Python-stdlib helper. Existing lane checkers remain the domain oracles;
the envelope validates only declaration equality, custody, provenance, resource
lifecycle, replay isolation, privacy scanning, sealing, and terminal
publication. Seven committed contracts for six lanes define the required
inventory.
Product Rust/BPF, public schemas, privacy policy, lane oracles, and runtime order
do not change.

**Tech Stack:** POSIX shell, existing Python 3/JQ oracles, Rust 1.88 edition
2024 artifact contracts, Linux x86-64, `flock`, Docker/systemd/eBPF only in the
later authorized runtime stage.

**Spec:**
`docs/superpowers/plans/2026-08-25-slice1b2-next-gates.md` Task 4,
`docs/superpowers/plans/2026-08-19-slice1b2-production.md` owned-run
cardinalities, and `docs/superpowers/plans/ROADMAP.md` topology ruling.

## Global constraints

- Preserve `docs/privacy/allowlist-v1.md`; do not broaden capture or public
  evidence vocabulary.
- Preserve Rust 1.88, edition 2024, and Linux x86-64-first support.
- Modify no product Rust/BPF, Cargo manifest/lock/config/toolchain, public
  schema, privacy policy, common shell library, README, or public usage file.
  A narrowly pinned replay-only checker adapter is permitted only under the
  authoritative sealed-envelope amendment below.
- Run at most one Cargo-heavy command at a time.
- Runtime lanes stay `UNRUN` until this plan is reviewed, committed,
  implemented, verified, independently reviewed, and committed.
- Run each production lane once. There is no automatic retry, resume, evidence
  replacement, or inference of PASS from an absent receipt.
- Sol xhigh architecture/correctness review is mandatory. Per the user's
  requested important-decision policy, focused Terra and Luna reviews must also
  agree before the plan and implementation gates advance.

## Accepted sealed-envelope amendment (2026-08-28; authoritative)

The accepted
[Task 4 Receipt Architecture Decision](../reports/2026-08-28-task4-receipt-architecture-decision.md)
is incorporated here as normative implementation authority. If this section or
the retained lane matrix conflicts with superseded receipt text, the decision
and this section control.

### Scope and files

Create one private Python-stdlib helper, `scripts/task4-receipt.py`, one shared
privacy scanner, six lane-owned checker scripts, and seven committed contracts
beneath `scripts/task4-contracts/`: `lane07.json`, `lane09.json`, `lane10.json`,
`lane11.json`, `lane14.json`, `lane16-never.json`, and `lane16-auto.json`.
The six normal drivers keep lane-specific collection and immutable-identity
cleanup, but replace inline predicates only after mutation-equivalent lane
checkers exist and replace local receipt wrappers with the common envelope.
`scripts/verify-discover-containers.sh` may retain only Lane 14 resource/artifact
production and registration. No receipt helper or Rust test interprets PKCS #11
counts, lane facts, or PASS semantics.

The checker files are exactly `scripts/check-privacy-surfaces.py` and
`scripts/check-task4-lane07.py`, `scripts/check-task4-lane09.py`,
`scripts/check-task4-lane10.py`, `scripts/check-task4-lane11.py`,
`scripts/check-task4-lane14.py`, and `scripts/check-task4-lane16.py`. Existing
`check-capture-evidence.py`, `check-bpf-map-defs.py`, and
`scripts/fixtures/discover-manifest.jq` retain their current semantic scope.

### Canonical bounds and schemas

All JSON is UTF-8 with no surrogate code point, no float, and integer values
only where the schema permits them. Parsing uses `json.loads` with a
duplicate-rejecting `object_pairs_hook`, rejecting `parse_constant`, and a
`parse_float` that rejects every float token. Generation uses
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False)`, followed by UTF-8 encoding and one LF. JSONL uses the same
encoding, one LF-terminated object per record, and gap-free `seq` values
starting at zero.

- `contract.json` is at most 1 MiB.
- `receipt.json`, `resources.jsonl`, and `artifacts.jsonl` are each at most
  8 MiB and, where applicable, 4096 records.
- Each JSONL record is at most 16 KiB; each string is at most 4096 UTF-8 bytes.
- Labels match `[a-z][a-z0-9_.-]{0,63}`.
- Retained paths match `[A-Za-z0-9._/-]{1,4096}`, are relative, contain no
  empty, `.` or `..` component, and artifact paths begin with `artifacts/`.
- SHA-256 values are exactly 64 lowercase hexadecimal characters.
- Every artifact declaration has `1 <= max_bytes <= 4294967296`; no undeclared
  retained file is permitted. `stdout.log`, `stderr.log`, and `checker.log` are
  each at most 64 MiB; `verdict` and `status` are at most four bytes; and
  `seal.sha256` is at most 16 MiB.

Before checker implementation, seven non-executable inventory blueprints live
only beneath `docs/superpowers/contracts/task4/`. A blueprint has the exact
runtime-contract keys below plus `unresolved_interfaces`; `schema` is
`p11scope-task4-contract-blueprint-v1`. The helper rejects this schema with exit
77 before root creation.

`unresolved_interfaces` has 0..3 records per blueprint, sorted by label, each
with exactly:

```text
bindings, executable, kind, label, locator, self_test
```

`kind` is `lane-checker|privacy-scanner|envelope-helper`. `label` names exactly
one declared tracked input of kind `checker|helper`; `locator` equals that
input's repository-relative locator; `executable` names the interpreter/direct
input used by `self_test`; and `self_test` is 1..512 `literal|input` `ArgToken`
values. Self-test use is exactly `executable==label` with zero matching input
tokens, or a different executable with exactly one matching input token.

`bindings` has 1..4096 records for checker/scanner kinds and is empty for the
helper. Each record has exactly `argv,checker,executable,role`, is sorted by
checker, and exactly repeats one `CheckerDecl`. Every reference is exactly one
of: executable equals the interface label with zero matching input tokens, or
executable differs and argv contains exactly one matching input token. Mixed or
repeated references are schema errors. The binding set equals every declaration
with either form and has no duplicate checker. A CheckerDecl may appear once in
multiple interface records when it names each distinct interface exactly once.
Thus one shared scanner/interpreter binds every explicit scanner-mode invocation
without wrappers, and the Lane 14 domain checker can bind its own script plus
the scanner. No interface record shares a label or locator. The union is the
only forward-reference set. Existing paths do not discharge absent CLIs or
failing tests.

Discharge resolves exact bytes at the promotion commit, validates the bound
input and all checker bindings, expands binding/self-test argv under the normal
token rules, and requires the self-test to exit zero without privilege, containers,
network, Cargo, or a lane body. Promotion removes the array, changes only
`schema` to `p11scope-task4-contract-v1`, and preserves every other canonical
value byte-for-byte. The envelope helper has no checker binding and must resolve
before any runtime manifest promotes.

A runtime lane contract has exactly these top-level keys:

```text
artifacts, checkers, driver, environment, inputs, lane, privacy_surfaces,
replay_adapter, requested_mode, resources, schema
```

`schema` is `p11scope-task4-contract-v1`; `lane` is one of
`07|09|10|11|14|16`; `driver` references an input whose kind is `driver`.
`requested_mode` is required: it is JSON null for lanes 07/09/10/11/14 and is
exactly `never|auto` for Lane 16. The two Lane 16 contracts have the same lane
but distinct requested modes.
Arrays contain 0..4096 entries unless a tighter bound is stated and have
exactly these fields:

```text
InputDecl: execution, kind, label, locator, origin, retained_path
EnvironmentDecl: evidence, name, value
CheckerDecl: argv, executable, label, role
ArgToken: kind, value
ReplayAdapterDecl: argv, checker, executable, label
ResourceDecl: class, identity_scheme, label
ArtifactDecl: checker_roles, label, max_bytes, path, privacy, producer
PrivacySurfaceDecl: exclusions, scanner, target, target_kind
```

The declaration vocabulary is closed:

- input `kind` is
  `driver|source|checker|helper|adapter|interpreter|dependency|tool|configuration`;
  `origin` is `tracked|external-pinned|external-copied`; a tracked locator is a
  repository-relative path and an external locator is absolute. A replay-
  required checker, adapter, interpreter, script, or dependency always has a
  caller-owned `nlink=1` retained copy at `inputs/LABEL`, even when tracked;
  `retained_path` is that path. Other tracked or external-pinned collection
  inputs use JSON null; other external-copied inputs use an `inputs/` path;
- input `execution` is `none|direct|interpreter-argument`. A replay-required
  direct binary is retained mode 0700 and may be a checker `executable`; an
  interpreter-fed script is retained mode 0600, must appear as an input argv
  token, and cannot be the executable. Every other retained input is mode 0600.
  Contract validation rejects all other execution/mode combinations;
- environment `name` matches `[A-Z][A-Z0-9_]{0,63}` and `evidence` is
  `absent|literal|sha256|root-relative`; `value` is respectively JSON null, the
  exact authorized string, a lowercase SHA-256, or a retained relative path;
  the contract lists every consumed variable;
- checker `role` is `domain|privacy`; `executable` references a checker,
  adapter, or interpreter input; `argv` contains 1..512 tokens;
- argument `kind` is `literal|artifact|input|common`; a literal is bounded
  UTF-8 without NUL, artifact/input values reference labels, and common value
  is exactly `checker.log|stdout.log|stderr.log`;
- resource `class` is
  `process|process-group|container|image|cgroup|bpf-link|bpf-map|mount|network|file|directory|token-store`;
  `identity_scheme` is
  `pid-starttime|sid-leader-starttime|container-id|image-id|cgroup-id|bpf-id|mount-id|netns-id|dev-ino`;
- artifact `checker_roles` is the sorted unique list of checker labels that
  must consume the artifact; `producer` references the driver input or a
  resource label; `privacy` is `none|scan|structural-trace|quarantine-only`;
- a privacy surface has target kind `artifact|common`; an artifact target
  references one label, while a common target is one of the three common logs.
  It references one privacy-role checker. `exclusions` is
  `none|trace-pid-tid-positions`. The latter is legal only for trace artifacts
  and means the structural scanner excludes exactly the two
  PID/TID positions permitted by `allowlist-v1.md`, not whole lines or files.

Identity schemes are fixed by class: process=`pid-starttime`,
process-group=`sid-leader-starttime`, container=`container-id`, image=`image-id`,
cgroup=`cgroup-id`, BPF link/map=`bpf-id`, mount=`mount-id`,
network=`netns-id`, file/directory/token-store=`dev-ino`, and
no other pairing is valid.

`replay_adapter` contains zero or one declaration and its `checker` references
one checker label. Every reference resolves inside the same contract. Labels
and paths are unique; arrays are sorted by label or bytewise path. Runtime
output cannot add, remove, or redefine a declaration. The contract fixes all
required cardinalities.

For each checker, expand argv deterministically: literal bytes are unchanged;
an artifact becomes the root-relative declared path, an input becomes its
descriptor-pinned or retained path, and a common token becomes that root-
relative common path. The set
of artifact labels appearing as `artifact` tokens, counting each exactly once,
must equal the set of contract artifacts naming that checker in
`checker_roles`. The adapter, when present, is included in this expansion but
cannot change the equality. Checker output or runtime file-open observations
may corroborate consumption but cannot define or shrink this required set.
The privacy-surface set exactly equals artifacts whose privacy value is
`scan|structural-trace`, union exactly one target for each of the three common
logs. Each artifact scanner must also appear in that artifact's
`checker_roles` and argv equality, and each common-log scanner argv names that
common token exactly once.
Exactly one privacy checker targets `checker.log`; it is the terminal log
auditor described below.
Every non-file live surface, including live `START` map state, is first retained
as a declared bounded artifact; there is no live-state-only privacy target.
`quarantine-only` can occur only in a
nonzero failed receipt and can never contribute to status zero or promotion.

The shared scanner is `scripts/check-privacy-surfaces.py`, with exact CLI:

```text
check-privacy-surfaces.py --self-test
check-privacy-surfaces.py json PATH...
check-privacy-surfaces.py trace --exclude trace-pid-tid-positions PATH...
check-privacy-surfaces.py map-json PATH...
check-privacy-surfaces.py bytes PATH...
check-privacy-surfaces.py workload-log PATH...
check-privacy-surfaces.py checker-log PATH
```

Inputs are explicit files, never directories or globs. Normal modes return 0
clean, 1 only for a forbidden value in well-formed input, 2 usage, and 3 for
malformed input, I/O failure, or bound violation, with empty stdout and bounded stderr;
`checker-log` accepts exactly one file and is silent. Every mode has a planted
positive self-test. `map-json` scans source bytes plus bytes reconstructed from
duplicate-free JSON of depth at most 6. Its root is either a bpftool entry array
whose every entry has exactly `{key,value}` or `{key,values}`, or the exact
positive-control object `{"value":[BYTE...]}`. `key` and scalar `value` are
nonempty arrays of lowercase `0x[0-9a-f]{2}` strings. `values` is a nonempty
list of exact `cpu,value` objects; CPU is unique, strictly increasing, and in
0..1048575, and each value array is nonempty. Unknown/missing members or other
shapes fail; an empty root array is valid for an empty map. Arrays decode in
document order. Float, invalid source UTF-8, duplicate key, depth/bound overflow
fail; reconstructed bytes have no UTF-8 constraint. The retained control uses ordinary
`map-json`, must return 1, and is not a privacy surface.

Lane 14's canary/privacy subset is the exact 194-row
[crosswalk](../reports/2026-08-28-lane14-canary-surface-crosswalk.md): 191 scan
targets, two input-only discovery manifests, and one must-detect positive
control. It is not the entire Lane 14 artifact set; distribution, attach,
protocol, release, and smoke artifacts are separate literal blueprint rows.
The control artifact has privacy `none` and names the Lane 14 domain checker in
`checker_roles`. That checker argv includes both its own script input and the
shared scanner input, invokes `map-json` on the retained control, requires exact
scanner result 1 with bounded diagnostics, and returns its ordinary zero only
after that must-detect result. Result 0, 2, 3, signal, timeout, missing
consumption, or any other result is non-pass. Mutation tests include both a
well-formed sentinel-free control (scanner 0) and malformed control (scanner 3);
no global expected-result field is added.

Each resource-journal record is exactly one of:

```text
requested: class, label, locator, nonce, seq, state
resolved: class, identity, label, nonce, resolution, seq, state
cleanup: class, identity, label, nonce, result, seq, state
absent: class, identity, label, nonce, query, result, seq, state
```

`nonce` is 128 random bits encoded as 32 lowercase hexadecimal characters.
`identity` contains exactly `scheme,value`; `resolution` is
`created|reconciled`; cleanup `result` is `removed|already-absent|failed`; and
absent `result` is a JSON boolean.

`state` is the literal record name. `locator` has exactly `kind,value`, with
class-fixed kinds: process/process-group=`argv-sha256`, container/image/network
=`name`, cgroup/mount/file/directory/token-store=`path`, and BPF link/map=`label`.
Names/labels use the label grammar; paths use the retained-path grammar; hashes
use the SHA-256 grammar. Identity `value` is a closed object by scheme:

```text
pid-starttime: pid,starttime
sid-leader-starttime: leader_pid,leader_starttime,sid
container-id|image-id|cgroup-id|bpf-id|mount-id|netns-id: id
dev-ino: dev,ino
```

PIDs, starttimes, device numbers, and inode numbers are canonical positive
integers; `sid` is a canonical positive integer; `id` is 1..4096 bytes matching `[A-Za-z0-9:._/-]+`. `query` has
exactly `method,target`; method is fixed by scheme as
`pidfd|session-snapshot|runtime-id|cgroupfs-id|bpf-id|mountinfo-id|netns-id|lstat-dev-ino`,
and target exactly repeats the resolved identity value. No free-form identity,
locator, or query field is accepted. The only successful transition is:

```text
pid-starttime -> pidfd
sid-leader-starttime -> session-snapshot
container-id|image-id -> runtime-id
cgroup-id -> cgroupfs-id
bpf-id -> bpf-id
mount-id -> mountinfo-id
netns-id -> netns-id
dev-ino -> lstat-dev-ino
```

```text
declared -> requested -> resolved(created|reconciled) -> cleanup -> absent(true)
```

`requested` is durable before creation and `resolved` before activation or
handoff. A create-before-resolve crash may append `resolved(reconciled)` only
when the nonce selects exactly one owned candidate. Otherwise the journal is an
incomplete non-pass prefix and no mutable name authorizes deletion. Crash
recovery is lane-owned; the helper validates records and never infers deletion.
Status zero requires every declared resource to reach `absent(true)` exactly
once with no duplicate, skipped, reordered, identity-changing, or later row.

Each artifact-journal record has exactly:

```text
acquired, checker_roles, label, path, portable, producer, seq
```

`acquired` contains exactly `dev,gid,ino,mode,nlink,size,uid`; `portable`
contains exactly `sha256,size`. Each artifact is a caller-owned mode-0600
regular file with `nlink=1`, beneath the retained root, inside its declared
bound. The declared and recorded artifact sets must be exactly equal.

`receipt.json` has exactly these top-level keys:

```text
checks, contract, environment, git, inputs, invocation, lane, lock,
requested_mode, schema, times
```

`schema` is `p11scope-task4-receipt-v1`; `lane` equals the contract and
`requested_mode` exactly equals the contract value. For Lane 16, the driver's
sole mode token and the lane checker's sole mode literal equal that value; for
other lanes no mode token is permitted. Contract/receipt/driver/checker mismatch
is non-pass.
`contract` contains exactly `path,sha256`. `invocation` contains exactly
`argv,cwd,gid,uid`. `git` contains exactly
`clean_end,clean_start,head,tracked_sha256,tree`, with both cleanliness values
true. `times` contains exactly `end_utc,start_utc` in canonical UTC RFC 3339.
`environment` is a name-sorted exact-set array of records
`evidence,name,value`; value is JSON null for absent, the authorized literal or
lowercase SHA-256, or the retained relative path for root-relative. A
root-relative value is opened beneath root FD 8 and identity-revalidated like
an input. `inputs` is a label-sorted exact-set array of records
`end,label,locator,retained,start`; start/end each contain exactly
`dev,ino,mode,nlink,sha256,size`. `retained` is JSON null or exactly
`path,sha256,size` and is mandatory when `retained_path` is non-null. Every
contract input appears once, no other input appears, tracked input hashes equal
their recorded HEAD blobs, and retained identity is independently revalidated.
`lock` contains exactly `dev,ino,path` for the retained campaign-lock identity;
it is common execution authority, not a lane resource and is not removed by a
receipt.

`checks` follows replay order—domain labels, privacy labels other than the
terminal log auditor, then that auditor—and has exactly one record per contract checker with fields
`argv,executable,label,log_end,log_sha256,log_start,result`. `argv` is the exact
expanded replay argv; executable is the retained input label; result is a
canonical 0..255 integer; log offsets are canonical byte offsets into
`checker.log`; and `log_sha256` covers that checker's canonical framed record.
Adapter identity and expanded argv are included in the associated checker
record. Missing, duplicate, reordered, or additional checker records are
invalid.

### Driver/helper ownership protocol

The lane driver is the sole parent and resource owner. Before any root mutation
it validates the public invocation and clean environment, installs its
EXIT/HUP/INT/TERM finalization trap, and acquires nonblocking FD 9 on
`CAMPAIGN/.task4.lock`. `CAMPAIGN` is the caller-owned mode-0700 canonical
parent of all lane roots; the lock is an `O_NOFOLLOW|O_CREAT` mode-0600 regular
file whose dev/inode is retained. Contention or invalid lock exits 77 before a
root, body, Cargo, container, network, or runtime command. FD 9 remains held
through terminal exit.

The driver retains campaign-parent dirfd 5, artifact-journal FD 6,
resource-journal FD 7, root dirfd 8, and lock FD 9. It invokes only these helper
operations:

```text
task4-receipt.py init CONTRACT --parent-fd 5 --name ROOT_NAME --lock-fd 9
task4-receipt.py artifact --root-fd 8 --journal-fd 6 --label LABEL
task4-receipt.py journal --fd 7 --state requested|resolved|cleanup|absent ...
task4-receipt.py validate-contract CONTRACT
task4-receipt.py finalize --parent-fd 5 --name ROOT_NAME --root-fd 8 \
  --artifacts-fd 6 --resources-fd 7 --lock-fd 9 \
  --start-sha256 START_SHA256 --intent CODE
task4-receipt.py verify-copy ROOT_COPY
task4-receipt.py --self-test
```

The driver opens the canonical caller-owned mode-0700 campaign parent as FD 5
with no-follow component checks. `init` descriptor-validates the committed
contract, FD 5, and FD 9. `ROOT_NAME` is one 1..255-byte ASCII component
matching `[A-Za-z0-9][A-Za-z0-9._-]*`; NUL, slash, `.`, and `..` are rejected
before mutation by both init and finalize. Init creates it relative to FD 5
race-free mode 0700, then creates caller-owned mode-0700 `inputs/` and
`artifacts/` directories with `nlink>=2`, records and revalidates their
dev/inode/mode/owner, copies the canonical contract and replay-required inputs;
creates
caller-owned mode-0600 `nlink=1` stdout/stderr, both empty journals, and
`receipt.json.pending` containing the canonical start ledger; fsyncs files and
directories; and returns
`ROOT_DEV:ROOT_INO<TAB>START_SHA256<LF>`. The driver opens the root relative to
FD 5 with `openat(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` as FD 8, requires
parent-relative `lstat` to equal FD 8 `fstat`, and retains the returned start
digest outside the root. Finalize identity-checks
that pending object, requires its original bytes to match `START_SHA256`, then replaces its bytes
with the complete receipt after replay, fsyncs it, and renames it no-replace to
`receipt.json`; failure or leftover pending state prevents status. Any
partial-init failure either identity-removes its empty root or leaves
missing status/non-pass; it never continues by pathname.

FDs 5-9 are close-on-exec during lane work and are closed in every external
child except the named FD 7 resource-journal inheritance. Immediately before
the final helper `exec`, the driver clears close-on-exec only for FDs 5-9; the
helper revalidates all five before use.

The driver opens `stdout.log`/`stderr.log` as retained FDs 3/4 and
`artifacts.jsonl`/`resources.jsonl` as retained append FDs 6/7, all relative to
FD 8 with `O_NOFOLLOW` and exact identity checks. It serializes every journal
operation. Nested resource creators inherit only FD 7 and call `journal`; all
other children close FDs 5-9 and body stdout/stderr is captured only through
FDs 3/4. A requested append returns only after fsync and before creation;
resolved returns only after fsync and before activation or handoff.

After producing a declared artifact and before any checker consumes it, the
driver calls `artifact`. That operation opens the contract-declared path
relative to FD 8, rejects links/special files/identity drift, streams its
bounded SHA-256, rechecks the same FD identity, appends and fsyncs the typed
acquisition row through FD 6, and returns. Finalization repeats the same checks
and requires acquisition and final identities/hashes plus exact declared-set
equality. Runtime scanning without an acquisition record cannot authorize an
artifact.

The same-shell driver body performs lane work. Its trap reaps owned children,
executes lane-specific cleanup using only immutable identities already held by
the driver, appends cleanup/absence rows when identity is known, and treats any
uncertainty as non-pass. The helper never starts, signals, or deletes a lane
resource. After cleanup, the driver closes body-only descriptors and `exec`s
`task4-receipt.py finalize` with FDs 5-9, `START_SHA256`, and `CODE`; FDs 3/4
are fsynced and closed first. Finalize revalidates FD 8 against `ROOT_NAME`
through FD 5 and retains FD 5 and FD 9 through final publication and process
exit. No public environment
or CLI body-reentry mode exists. Signals retain shell exit codes HUP=129,
INT=130, TERM=143 after
cleanup. Unexpected consumed-run failure uses 97. A proven pre-consumption
refusal exits 77 with no root or status. Success is 0. For every completed
owned root, `verdict == status == process exit`; status 77 is never published.
`CODE` is exactly `0|97|129|130|143`; validator, replay, privacy, provenance,
resource, seal, or publication failure may upgrade 0 to 97 but can never
downgrade a nonzero intent.

The campaign lock is caller-owned, mode 0600, regular, and `nlink=1`. Before
root claim and immediately before publication, pathname `lstat` relative to FD
5 must equal FD 9 `fstat` in dev/inode/uid/gid/mode/nlink. Replacement, unlink,
or mismatch is non-pass and cannot publish zero.

`journal` accepts the exact typed fields of the selected transition, not a
free-form JSON record. A completed non-pass journal may end at requested alone,
at resolved, or after cleanup/absent failure. Once immutable identity is known,
cleanup and absence rows are mandatory whenever the owner remains capable of
finalization. `cleanup(failed)` is followed by `absent(true|false)`;
`absent(false)` is always non-pass. Only
`cleanup(removed|already-absent),absent(true)` can contribute to status zero.
Catastrophic owner death yields missing status and never a pass.

### Authority, provenance, replay, and terminal protocol

`contract.json` is the canonical copy of the descriptor-pinned committed lane
contract. The envelope binds its repository path and SHA-256 before body
execution. It records exact invocation identity and start/end ledgers for every
consumed source, input, checker, adapter, interpreter, dependency, tool, and
configuration. The tracked index/worktree is clean at start and end; every
consumed tracked file matches its HEAD blob through a no-follow descriptor.
Repository-untracked executables and Cargo/container build inputs are rejected.
Mutable external inputs are descriptor-pinned or copied before use.

The contract, not checker output, defines required inventory. Checker zero is
necessary but insufficient. Lane 16's reviewed fixed validator is the sole
non-standalone domain oracle. A collection-coupled checker may use the
contract's single replay-only adapter only to map retained labels into its
existing checker invocation. The adapter collects nothing, adds no predicate,
accepts no missing input, and is pinned and reviewed like a checker; this is the
only exception to the checker-freeze rule.

After descendants are reaped and every resource is absent, replay runs in the
original private root over read-only, contract-registered retained inputs and
writes only to `checker.log.pending`, an `O_EXCL|O_NOFOLLOW` mode-0600 bounded
file. Domain checkers execute in label order, followed by privacy checkers in
label order except the `checker.log` auditor. The helper captures each checker's raw
stdout/stderr and appends one canonical JSONL record with exactly
`label,result,stderr_b64,stdout_b64`; decoded combined bytes and the whole log
remain within 64 MiB. This framed log is fsynced and renamed no-replace to the
mandatory `checker.log` even when a checker exits nonzero. If the mandatory log cannot be created or published, no
authoritative status is published. Original repository paths and services are
unavailable; network, privilege, Cargo, Docker, systemd,
collection commands, globs, mutable imports, and undeclared paths are
tripwired. A copied sealed envelope must independently revalidate and replay
from a different absolute path.

After that publication, the terminal log auditor reads canonical
`checker.log`; its own
stdout/stderr must be empty and is never appended to the file it audits. Its
exit and zero-length log range are recorded in `checks`, with `log_sha256` equal
to SHA-256 of empty bytes. The result is sealed through `receipt.json`; it never
modifies the audited log.

`verify-copy` opens the copied sealed root read-only, creates one bounded
caller-owned mode-0700 scratch directory beside—not inside—the copy, runs all
replay checkers with outputs captured there, and compares canonical check
results and framed log bytes with sealed `receipt.json` and `checker.log`. It
identity-removes scratch afterward and never mutates the copied root. Scratch
creation, overflow, cleanup, or comparison uncertainty is failure.

After the last checker, finalize revalidates every retained input and artifact
again before writing receipt check records, verdict, or seal. `stdout.log` and
`stderr.log` are created only by `init`, captured through FDs 3/4, fsynced and
identity-revalidated by finalize, and never repaired or synthesized. Their
absence, replacement, overflow, or write/fsync uncertainty prevents status.

`seal.sha256` contains one
`SHA256<TAB>SIZE<TAB>RELATIVE_PATH<LF>` row per regular retained file in stable
bytewise path order, excluding only `seal.sha256` and `status`. Mandatory common
sealed entries are `contract.json`, `receipt.json`, both JSONL journals, every
retained `inputs/` copy, every contract artifact, `checker.log`, `stdout.log`,
`stderr.log`, and `verdict`.
Logs and verdict are not extra domain artifacts. No other retained file exists.

Terminal order is: reap; identity-bound cleanup and absence; provenance and
inventory revalidation; checker replay and privacy validation; write/fsync the
exact ASCII bytes `CODE<LF>` to `verdict`, seal, and root; create
`ROOT/status.pending`, write the same exact
sealed verdict, fsync it and the root; publish `status` with
`renameat2(RENAME_NOREPLACE)` as the final namespace mutation; fsync the root;
exit without mutation. Every consumer revalidates the seal and exact terminal
delta. Any collision, unavailable no-replace rename, fsync failure, mismatch,
missing status, or later mutation is non-pass.

The Python-stdlib-only rule permits one minimal `ctypes` binding to libc
`renameat2`; missing symbols, `ENOSYS`, or any fallback without no-replace
semantics is non-pass. No third-party package or external rename utility is
allowed. The binding loads libc with `use_errno=True`, declares integer dirfd
and flags plus byte-pointer pathname ABI types, uses retained root dirfd for
both directories, and passes exactly `RENAME_NOREPLACE`.

### Implementation and test sequence

1. After independent Sol, Terra, and Luna acceptance, make one docs-only
   authority change containing exactly the accepted decision report, Lane 14
   crosswalk, this closure plan, the next-gates qualification, and ROADMAP
   amendment. Exclude the rejected schema draft and unrelated OpenSSL report.
2. Write and independently review seven inventory-complete blueprints and the
   Lane 14 crosswalk, including every literal artifact path, evidenced bound,
   checker role, privacy surface, resource class/identity, replay argv, input,
   environment value, and cardinality. Only exact `unresolved_interfaces`
   records may refer forward. Lane 14 must separately enumerate every required
   profile, log, map, live `START`, trace, attach, discover, distribution,
   protocol, release, smoke, and canary surface. No helper implementation starts
   before this gate passes.
3. The sole `tests/artifact_contracts.rs` owner adds rootless blueprint rejection
   and seven absent-interface RED rows, one per future manifest. The exact first
   focused command is:

   ```sh
   cargo +1.88 test --locked --test artifact_contracts \
     task4_contract_ -- --nocapture
   ```

   It fails only on the seven named absent checker/scanner interfaces; static
   rows validate the blueprint key set and forward-reference bindings without
   calling a helper. Stop the writer and review before any checker
   implementation. The later helper core RED/GREEN proves blueprint schema
   exits 77 before root creation.
4. Sequential sole writers implement, self-test, stop, and receive independent
   review for `check-privacy-surfaces.py`, then the Lane 07, 09, 10, 11, 14,
   and 16 checker files. Before removing an inline predicate, a mutation test
   names its sole replacement checker. Each writer runs its exact script with
   `--self-test`, followed by exactly one Rust row from
   `task4_contract_privacy`, `task4_contract_lane07`,
   `task4_contract_lane09`, `task4_contract_lane10`,
   `task4_contract_lane11`, `task4_contract_lane14`, and
   `task4_contract_lane16`, using the same fixed Cargo prefix as step 3. The
   aggregate `task4_contract_` filter becomes GREEN only after Lane 16 review.
5. The sole Rust-test owner adds `task4_receipt_envelope_contracts_core` RED and
   stops for review. The sole helper owner then implements the helper. Its real-
   process self-test proves blueprint schema exits 77 before root creation and
   covers at least: manifest
   A+B versus a zero checker using only A; unique and ambiguous
   create-before-resolve death; replay after original inputs/services disappear;
   copied-root replay; mutation of every authority class; unsafe roots;
   descriptor leaks; signal boundaries; cleanup/absence failure; early,
   duplicate, or replaced status; rename collision/unavailability; and
   post-publication mutation.
6. Re-review all blueprints against exact checker and helper bytes, require zero
   unresolved records, and promote seven runtime contracts while changing only
   the schema and removing `unresolved_interfaces`.
7. Migrate Lane 07 first and independently review exact registration/replay;
   migrate 09, 10, 11, all Lane 14 scripts as one group, and Lane 16 serially,
   replacing rather than layering local receipts. Each cycle is lane RED,
   minimal implementation, focused GREEN, writer stop, and independent review.
   Ownership returns to the primary before touching any stopped writer's file.
   Preserve every checker and retained lane-matrix predicate.
8. Run helper/contract/driver self-tests, shell syntax checks, the focused Rust
   contract, then all four canonical Rust checks. Stop the writer and obtain
   independent lifecycle, provenance, privacy, and oracle review before runtime.
9. Compatibility-check frozen Lane 02 without rerunning it. Do not amend or
   rerun Lane 13 history. Run remaining lanes once in order: 07, 09, 10, 11,
   14, 16-never, 16-auto; stop at the first UNRUN/NON-PASS. Preserve downstream
   order: fresh r3; 9.2d with the existing Lane 02 and single Lane 13
   frozen-candidate negative-control positions; 9.3; 9.4 review; exact-tip CI;
   Task 10.

Writer ownership is sequential: (1) seven blueprints plus Lane 14 crosswalk;
(2) `tests/artifact_contracts.rs` interface RED; (3) privacy scanner; (4-9) one
lane checker each for 07, 09, 10, 11, 14, and 16; (10)
`tests/artifact_contracts.rs` core RED; (11) `scripts/task4-receipt.py`; (12)
blueprint promotion; (13-18) Lane 07, 09, 10, 11, all Lane 14 scripts as one
group, then Lane 16.
A reviewer starts only after its writer stops. Ownership returns to the primary
at every stop, and later edits require a new explicit owner. After each driver
migration, run only its named lane row and require GREEN; the aggregate
`task4_receipt_envelope_contracts` filter becomes GREEN only after both Lane 16
modes. Every self-test is rootless and trips any Cargo, Docker, sudo, systemd,
BPF attach, network, or real lane-body command. Canonical Cargo checks remain
serial.

The frozen Lane 02 section and Lane 07/09/10/11/14/16 contract matrix below
remain domain authority. The Lane 13 topology ruling remains unchanged.

### Rejected live-observer descriptor design (historical, non-authoritative)

This descriptor-observer design is retained only as threat-case history. It is
superseded by the sealed-envelope amendment and must not be implemented. The
Lane 13 disposition beginning below remains authoritative and unchanged.

The unanimous architecture reconciliation fixes the shell-visible descriptor
mapping and supersedes any conflicting numeric label in this plan. The mapping
is control `FD 3`, events `FD 4`, observer `FD 5`, creator `FD 6`, main facts
`FD 7`, nested facts `FD 8`, and common lock `FD 9`; the reserved range is
`FD 3-9`. This changes no schema bytes, schema digest, privacy policy, or
capture vocabulary.

| Process or mode | Descriptor inheritance and allocation |
|---|---|
| Observed supervisor | `FD 3` control FIFO, `FD 4` events FIFO, and `FD 5` observer stream. The observed anchor passes only `FD 5`; the supervisor closes inherited `FD 3/4/6-9` before opening the two FIFOs as `FD 3/4`. |
| Case owner/publisher | Inherits only the case `FD 3/4` control/events pair and, for a receipt case as applicable, owns main facts/nested facts/lock as `FD 7/8/9`. The execed publisher keeps `FD 3/4` only through `publisher-entered` and its acknowledged final command, then closes both before terminal publication and retains only the applicable `FD 7/8/9`. It never inherits `FD 5/6`. |
| Lane 14 creator | Closes inherited `FD 3-9`, opens and identity-validates the artifacts directory transiently, creates facts through that directory, moves the facts descriptor to fresh local `FD 6`, and closes every transient before ready publication. Its observable ready/wait state is exactly standard FDs plus FD 6. The receipt parent imports FD 6 into FD 8 only after the ready record and identity checks. |
| Receipt parent/publisher | Owns main facts `FD 7`, Lane 14 nested facts `FD 8` when applicable, and common lock `FD 9`; those descriptors remain through terminal publication. |
| Hardened launcher/child | Gets a fresh local `FD 3` only after its external boundary closes inherited `FD 3-9`, writes and validates the PID handoff, then closes FD 3 before exec; the target payload receives no reserved descriptor. |
| Other external/fake command | Closes every reserved descriptor `FD 3-9` before execution; no descriptor outside the named owner/supervisor/creator exceptions is accepted. |

Standalone and normal modes close inherited `FD 3-9` before their own
allocations. Every Task 3B driver acceptance runs through the real observed
session, which validates supervisor `FD 3/4/5` identities, each case's protocol
`FD 3/4` and absence of `FD 5/6` before receipt allocation, the publisher's
two descriptor phases, and the Lane 14 creator `FD 6` to parent `FD 8`
handoff. A synthetic protocol emitter is RED-only and never acceptance. A
Bash/proc bridge for the observer protocol is rejected;
`/proc/$creator_pid/fd/6` is permitted only for the reviewed Lane 14 creator
handoff above.

Lane 13 is outside this descriptor amendment and the current ten-file Task 3B
implementation range. Its checker/lifecycle authority remains commit
`34357b5dda71c670250dd3ab336b29c801120d5b` (tree
`ae3346e4b8e137f430f010d0937bcf186cfcff39`) and its final
invocation/contract authority remains commit
`fd3d08ad9bd2f58508eda1ee4a50882c0633d850` (tree
`0decc4dee974707468b5758107fb055c30d44d7d`). The attempt-6 receipt is
`/home/user/.local/state/p11scope/task4-lane13-a2fd9ee-20260826T2135EEST/facts.log`
with SHA-256
`b96cbed6cbc2963dab2c5963b5c52f6378d9bef313479b83a56c259df79b94f3`,
exact HEAD `a2fd9ee8eddfaff34b3fb6b65267688b5a90aa03`, and tree
`f90e2dfe8dbd0a211f9e32055a37ff7320080b88`. Its evidenced preattached-provider
capture remains 136/136 probes with expected cold-pod calls. Its bound
command/script ledger, Kind/Knative releases/images, provider hash/build ID,
kernel/storage, node/workload topology, and clean start/end inputs remain
immutable. The checker and invocation are not rerun or amended here. Future 9.2d negative-control
classification permits only candidate and gate identity to differ, each equal
to the independently reviewed pre-run r3 manifest; any other mismatch is
UNRUN/review before outcome classification. Attempt 6 is not rerun. The one
9.2d frozen-candidate control retains exactly one overlay plus one unavailable
and is `UNSUPPORTED/NON-PASS` outside the unchanged zero-unavailable Lane-13
PASS oracle; Lane 13 PASS is not an unlock condition. This plan neither changes
nor requires a common Task-4 lock in `scripts/matrix/verify-knative.sh`. Any
later FD migration requires new roadmap, ledger, review, and freeze authority
after that unchanged negative control.

---

## Frozen baseline and Lane 02 disposition

The required fresh production Task 4 sequence already began with Lane 02 at
source HEAD `91e21496ae4e7d151c050a9dee2e8547d2d6cb75`, tree
`ecc619edc63194599328fc1ad926c301da717e0e`. The single production root is:

```text
/home/user/.local/state/p11scope/task4-500ms-20260827/lane02
```

Its `facts.log` is mode 0600, device/inode `43:16617428`, and SHA-256:

```text
03d39635a879ae5d3dcc22a6689f579c5a0d6644f68051fdd21cbfb587e255d8
```

It contains exactly six invocations and terminal status zero. It remains the
Lane 02 result in this same Task 4 board at its recorded HEAD; it is never
relabelled as final-HEAD or CI evidence.

Before any later runtime lane, write a compatibility report beneath the common
campaign parent that records both HEADs and proves mechanically that the final
receipt-only diff changes none of:

- `scripts/verify-task4-lane02.sh`, `scripts/check-capture-evidence.py`,
  `scripts/lib.sh`, `scripts/cleanup-traps.sh`, `spike/harness.c`, or
  `spike/expected.txt`;
- product Rust/BPF, `build.rs`, Cargo manifests/locks/config/toolchains; or
- any file whose bytes contributed to the recorded `p11scope`, harness,
  provider, config, or Cargo-configuration identities.

The compatibility report must rehash the immutable Lane 02 facts file and
validate the six exact tuples `(initial-set|dlopen) × (never|auto|always)`.
Every row retains `68/68/136`, the exact positive counts from
`spike/expected.txt` plus one `C_GetFunctionList`, exactly one authorized
sanitized timing projection, and zero required loss/ambiguity/in-flight
counters. `never` retains `none/0/0/0`; `auto|always` retains `sigstop` with
attempts equal confirmed and at least one, partial zero. Any overlap or mismatch
invalidates compatibility and requires new reviewed authority. It does **not** authorize an
automatic Lane 02 rerun: another run would create twelve Task 4 attempts and
contradict the exact-six cardinality.

## Rejected lane-local receipt design (historical, non-authoritative)

Everything from this heading up to, but not including, the retained lane-matrix
heading is historical design evidence and is not implementation authority. In particular, the
`facts-v1`, live observer/FD-5 protocol, duplicated local wrappers, and nested
facts protocol are rejected.

### Normal drivers

The six normal drivers and their seven literal invocations are:

```sh
sh scripts/verify-induced-gaps.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-shared-layer.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-fork-scope.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-oracle.sh ABSENT_ABSOLUTE_ROOT
sh scripts/build-release.sh ABSENT_ABSOLUTE_ROOT
sh scripts/verify-task4-lane16.sh ABSENT_ABSOLUTE_ROOT never
sh scripts/verify-task4-lane16.sh ABSENT_ABSOLUTE_ROOT auto
```

Every modified/new normal driver also accepts exactly:

```sh
sh SCRIPT --self-test
```

The evidence root must be an absent absolute path outside the worktree. Its
canonical parent must already exist, be caller-owned mode 0700, and have no
symlink component. After atomic ownership checks, the driver creates the root
mode 0700 and uses this fixed layout:

```text
ROOT/
  facts.log
  stdout.log
  stderr.log
  artifacts/
  work/
  status
```

Regular evidence/configuration files are 0600. Private binaries in `work/` are
caller-owned mode 0700 only while executed; their retained copies and all other
non-executed artifacts are 0600. `status` is a single decimal line and is written
exactly once as the final filesystem operation: `0` means receipt and lane
oracle PASS, `77` means prerequisite/infrastructure `UNRUN` before product
consumption, and every other value is `NON-PASS`. Invalid root authority
returns 77 without touching the path. A prerequisite failure after root
creation may retain preflight facts plus final status 77, but may not create a
product capture or owned runtime resource.

Each owning Linux shell enables noclobber and creates absent `facts.log` itself
with `umask 077; set -C; exec 7>"$ROOT/facts.log"`, which supplies exclusive
`O_CREAT|O_EXCL` semantics without a child-to-parent FD handoff. It immediately
disables noclobber only where existing body behavior requires it, validates the
FD via `/proc/$$/fd/7` against pathname `lstat`, and requires a caller-owned
0600 regular file with `nlink=1`. Existing files and symlinks therefore fail;
the self-test syscall/identity cases freeze this Linux shell behavior. FD 7 is
write-only and remains held through terminal publication; hashing reopens its
procfs magic link read-only and compares the new FD identity with retained FD 7
and pathname identity before use. Every facts append and final `terminal_status_intent`
uses FD 7. Lane 14 additionally holds nested `artifacts/discover.facts` as FD 8.
Lock FD 9 is reserved for the common lock.
Every ordinary external tool, Cargo/runtime command, wrapper payload, and fake
command is invoked with `3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-`. The only exceptions
are the initial `flock` operation using FD 9, the narrowly named inline facts
writer using FD 7, the Lane 14 creator/handoff steps using FD 6/8, self-test
owner/publisher control using FD 3/4, the self-test supervisor using FD 3/4,
the transient Python group anchor while it passes FD 5, the self-test
witness link shared by the Rust peer and supervisor FD 5,
and the final terminal publisher using FD 7/8/9. The terminal publisher performs revalidation with Python stdlib and
spawns no child; any defensive subprocess API must set `close_fds=True`. Fixture
commands inspect `/proc/self/fd` and fail if a reserved descriptor leaks.

Set `CAMPAIGN=$(dirname -- "$ROOT")` only after the root parent has been
canonicalized and validated; it is that caller-owned mode-0700 parent, not an
environment override. Every normal driver opens the same
`$CAMPAIGN/.task4.lock`, mode 0600, and takes a
nonblocking exclusive `flock` before inspecting or mutating shared Cargo,
Docker, systemd, cgroup, or target state. It holds the lock through terminal
status. The receipt records the lock dev/inode and holder PID/starttime. This is
one common overlap guard, not a receipt framework.

Create `artifacts/` and `work/` as caller-owned mode-0700 directories and
record/revalidate their device/inode identities. No other top-level directory
is allowed.

### Lane 14 nested facts

`build-release.sh` alone owns the Lane 14 root and terminal status. Its exact
nested call is:

```sh
sh scripts/verify-discover-containers.sh \
  --lane14-facts "$ROOT/artifacts/discover.facts"
```

The child accepts only that option or `--self-test`. It requires an absent
regular-file path directly beneath the already-validated Lane 14 `artifacts/`
directory. The stopped-writer amendment below supersedes the earlier direct
pathname-create/open wording: the child publishes a bounded journal and
payload, then the parent obtains the final facts object through the reviewed
creator/descriptor handoff. The child records facts but no terminal status and
returns nonzero on any cleanup or identity uncertainty. Any missing, replaced,
malformed, multiply linked, or identity-inconsistent object is nonzero.
`--lane14-facts` names and binds the intended final destination but the child
does not open it. The exact protocol paths are:

```text
$ROOT/work/discover.resource-journal
$ROOT/work/discover.payload
$ROOT/work/discover.ready.pending
$ROOT/work/discover.ready
$ROOT/work/discover.ack.pending
$ROOT/work/discover.ack
$ROOT/artifacts/discover.facts
```

The journal and payload are child outputs; the creator/parent own ready and
acknowledgement; the terminal publisher imports the first two and
identity-cleans all six private protocol files before committing status.

| Path | Creator | Mode and exact content | Cleanup owner / failure |
|---|---|---|---|
| `work/discover.resource-journal` | nested child, before first resource | first open is 0600 `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY`; later appends are `O_WRONLY|O_APPEND|O_NOFOLLOW` only after identity comparison; one header, then exactly one requested, resolved-or-uncertain, cleanup, and absence record per declared indexed resource, followed by one terminal record | terminal publisher removes by retained identity after import; malformed/missing/uncertain is non-pass |
| `work/discover.payload` | nested child finalizer | 0600 `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY` regular, exactly one canonical payload containing child PID/starttime/session, journal identity/digest/count, declared resource count, fact-key counts, cleanup summary, terminal result | terminal publisher removes by retained identity; missing/replaced/duplicate is non-pass |
| `work/discover.ready.pending` | facts creator | 0600 `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY`, exactly one ready record before atomic no-replace publication | creator removes only its still-matching pending object on failure; otherwise it must be absent before status |
| `work/discover.ready` | facts creator by no-replace rename | 0600 regular, exactly one version/nonce/parent PID+starttime/creator PID+starttime/creator-FD-6/facts-identity record | terminal publisher identity-cleans after validated handoff; five-second timeout, parent mismatch, or creator death is non-pass |
| `work/discover.ack.pending` | parent | 0600 `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY`, exactly one acknowledgement record before atomic no-replace publication | parent removes only its still-matching pending object on failure; otherwise it must be absent before status |
| `work/discover.ack` | parent by no-replace rename | 0600 regular, exactly one matching version/nonce/generations/creator-FD-6/parent-FD-8/facts-identity record | terminal publisher identity-cleans after creator reap; five-second timeout, mismatch, or parent death makes creator exit and is non-pass |
| `artifacts/discover.facts` | pinned creator, imported by terminal publisher through FD 8 | 0600 regular, `nlink=1`, one canonical bounded Lane 14 fact stream with exact allowed-key cardinalities | retained; replacement/mutation/import/fsync uncertainty is non-pass and prevents status |

All protocol objects are caller-owned, bounded by the facts limits below, and
must be absent initially including as dangling symlinks. A failure is status 77
only if it is proven before `CONSUMED`; afterward it is non-pass or, if terminal
publication cannot safely run, an absent authoritative status.

### Lane 14 private-work and terminal-authority amendment

`build-release.sh` accepts only `ABSENT_ABSOLUTE_ROOT` or `--self-test`.
Receipt-mode body execution is an internal same-shell function reachable only
after validated-root creation, the common lock, source binding, and terminal
authority are established. There is no public environment/body re-entry flag,
body subshell, or body-local `EXIT` trap. The sole receipt finalizer first runs
release-body cleanup; cleanup uncertainty upgrades terminal status and cannot
replace or bypass finalization.

Every mutable Lane 14 path is a fixed descendant of the validated root:

```text
WORK=$ROOT/work
DIST=$WORK/dist
OFFICIAL_TARGET=$WORK/release-official
CANARY_WORK=$WORK/canaries
ATTACH_WORK=$WORK
DISCOVER_BASE=$WORK
DISCOVER_WORK=$DISCOVER_BASE/discover
```

`DIST` and `OFFICIAL_TARGET` are derived values, never environment overrides.
The parent invokes `verify-canaries.sh` with `P11SCOPE_TASK4_WORK` fixed to
`$CANARY_WORK`, invokes `verify-attach-e2e.sh` with it fixed to `$ATTACH_WORK`,
and invokes the discover child with `P11SCOPE_TASK4_WORK` fixed to
`$DISCOVER_BASE`; that child's established interface derives the exact
`$DISCOVER_WORK`. The canary diagnostic
BPF is consumed only from `$CANARY_WORK/feature-build/...`. The two nested
scripts preserve their historical standalone defaults when the variable is
absent, require an explicitly supplied work path to be absolute, and never
compose an absolute work path as `$PWD/$WORK`. No receipt-mode mutation or
lookup may use `target/canaries`, `target/e2e`, or another caller-selected
path.

Receipt-mode body cleanup is one non-trapping `release_body_cleanup` function
called exactly once by the terminal finalizer. The receipt branch does not
source `cleanup-traps.sh`, install another body `EXIT` trap, or call `exit` from
body cleanup. A cleanup failure upgrades the one terminal status written last.

## Receipt lifecycle and provenance contract

After root creation, each normal driver installs one finalizer covering every
exit path. The finalizer performs, in order:

1. retain the body/oracle result without printing a lane PASS;
2. clean only resources whose immutable identities were recorded and synced;
3. query and prove absence of every owned resource;
4. revalidate the evidence root, every mutable input, source HEAD/tree, tracked
   cleanliness, and all recorded hashes;
5. reject foreign or missing terminal artifacts and validate the allowed tree;
6. upgrade a zero body result to nonzero on cleanup/query/input uncertainty;
7. `sync` retained facts/artifacts; and
8. write exactly one `$ROOT/status` line last and return that value.

Existing `ALL OK` text is emitted only after finalization or renamed `body
oracle OK`; the decimal terminal status is the sole lane verdict.

Every receipt records start/end UTC, literal argv, cwd, uid/gid, kernel, HEAD,
tree, tracked cleanliness, source/input start and end ledgers, and:

- root and eBPF Cargo locks, `build.rs`, Cargo configs, eBPF toolchain file;
- stable/nightly `cargo` and `rustc`, sysroot, rust-src, rust-lld, clang/LLVM,
  linker, compiler, Docker/systemd/bpftool versions when consumed;
- cleared or recorded build-affecting environment, including all induced-gap
  feature variables;
- provider realpath/dev/inode/mode/owner/size/SHA-256/build ID;
- exact actual observer, discover helper, workload, checker, and BPF object
  dev/inode/size/SHA-256 before use and again at finalization; and
- exact Docker base/image/container IDs and available digests, process
  PID/starttime/session, systemd invocation/unit, and cgroup identity.

Mutable regular files are opened first and hashed/stat'ed through
`/proc/$$/fd/N`; the same descriptor is used or copied into private `work/`
before consumption. Pathname-only rehashing is insufficient. Docker cleanup
targets the recorded container/image ID, never a reusable name or tag. Process
cleanup uses PID plus starttime/pidfd verification. Cgroup/systemd cleanup uses
the exact recorded invocation identity and path. Identity mismatch prevents
destructive cleanup, makes the receipt nonzero, and retains diagnostic facts.

Tracked source must be clean using `git diff --quiet` and
`git diff --cached --quiet`; HEAD/tree recording uses
`--untracked-files=no`. Untracked files are never executed or build/Docker
inputs. Reject an untracked path within any consumed Cargo or Docker context.
A reviewed non-input exception outside those contexts is allowed only when its
path and SHA-256 are recorded; the existing OpenSSL feasibility report is such
an exception. The separately committed receipt plan is not untracked during
implementation/runtime.

### Rejected stopped-writer lifecycle repair (historical, non-authoritative)

The stopped-writer review at implementation HEAD
`1330630d1af58d5f61c21c258d23babc8acc1135` rejected Task 4 advancement. The
current self-tests are green but model state in toy Python rather than execute
the real shell finalizers. The current scripts can publish zero before later
filesystem failures, install terminal authority after mutations, expose
rootless body bypasses, use pathname-only facts, under-record consumed inputs,
and leave cleanup ownership split across processes. This amendment supersedes
every conflicting lifecycle, facts-publication, and status-publication sentence
above. Runtime remains prohibited until the repaired implementation passes the
new real-fixture tests and stopped-writer review.

Each normal driver executes its receipt body in the owning shell. Lanes 07, 09,
10, and 11 remove `P11SCOPE_TASK4_BODY`; no normal driver has a public body
re-entry path. After parent authority validation but before the first root
creation/claim mutation, the owner initializes state and installs one
partial-state-tolerant `EXIT` finalizer plus separate `INT`, `HUP`, and `TERM`
handlers. The owner tracks at least `ROOT_OWNED`, `ROOT_CLAIMING`, `LOCKED`,
`CONSUMED`, `FINALIZER_RUNNING`, an explicit `REGISTRATION_ACTIVE`, and every
registered resource. A
status of 77 is permitted only while `CONSUMED=0` and before any owned runtime
resource is created. Outside a registration checkpoint, a catchable signal
enters the one finalizer immediately. During a checkpoint it latches until that
same requested/resolved registration is durably completed or recorded as
uncertain, then enters the finalizer; it never waits for a later unrelated
registration.

Before creating an owned process, cgroup, unit, container, image, BPF object,
token, or other runtime resource, append and `fsync` its unique requested
identity. After creation but before activation or cleanup eligibility, append
and `fsync` its resolved immutable identity. Cleanup addresses only that
resolved identity, records the result, and query-proves final absence. A raw PID
or mutable name is never cleanup authority. PID cleanup binds PID plus
starttime; Docker binds IDs/digests; systemd/cgroup cleanup binds the exact unit,
invocation, and cgroup identity. Identity uncertainty preserves diagnostics and
forces non-pass. The finalizer never suppresses cleanup failure and never
repairs mode drift with `chmod` or a generic `find`; it rejects drift.

Resources that normally start immediately use existing native staging instead
of an unregistrable launch. Docker uses `create`, records/fsyncs the container
ID, then `start`. A systemd or ordinary child starts a minimal private wrapper
blocked on a fixed private FIFO; the parent records/fsyncs PID/starttime,
session, unit/invocation, and cgroup identities before releasing the wrapper.
The wrapper command and FIFO are themselves fixed, identity-recorded inputs.
The observer process owns its internal BPF link lifecycle; the receipt registers
the stopped observer generation before release, later inventories only resolved
owned BPF IDs, and never attempts pathname/name cleanup of an unregistered BPF
object. SoftHSM configuration/token requests are journaled before initialization
and resolved private directory/file identities are recorded before use.
Docker image builds record/fsync a unique requested tag and label before build,
then resolve/fsync the immutable image ID/digest before use. An interrupted build
must reconcile exactly one matching immutable ID; zero or multiple matches are
recorded as uncertain, forbid destructive image cleanup, and force non-pass.

All receipt paths use the already absolute `$ROOT`, `$ROOT/work`, and
`$ROOT/artifacts` values. No `$PWD/$WORK`, glob-selected `*observed*`, first-file
selection, or stdout-as-capture substitution is allowed. Every retained artifact
has one fixed name, expected type, identity, cardinality, and consumer. Rename
all pre-finalization `ALL OK` output to `body oracle OK`.

The finalizer completes cleanup, absence proofs, source/input/root/tree/facts
revalidation, exact artifact inventory, and retained-data synchronization before
status publication. It then `exec`s one bounded inline Python terminal
publisher. That publisher:

1. blocks or controls catchable signals for the commit window;
2. revalidates the root/work/artifacts/lock identities and every retained facts
   descriptor and digest;
3. appends `terminal_status_intent` through retained main facts FD 7, `fsync`s
   it, and freshly revalidates descriptor/path identity and digest (and Lane 14
   nested facts FD 8/path/digest);
4. historical draft used `ROOT/status.pending` with
   `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600,
   writes one decimal line, and `fsync`s it and the work/root directory FDs;
5. revalidates immediately before commit;
6. calls the Linux x86-64 libc `renameat2` symbol through Python stdlib
   `ctypes.CDLL(None, use_errno=True)` with `RENAME_NOREPLACE=1`, making that
   rename from the work dirfd to the root dirfd the final filesystem operation;
   and
7. immediately calls `os._exit(published_value)`.

There is no `os.rename`, syscall-number, or replacing-rename fallback. Missing
`renameat2`, `ENOSYS`, a collision, or any other failure before the rename
leaves no authoritative status and exits nonzero. The final facts record is
`terminal_status_intent`; no fact claims that publication succeeded. Main facts
FD 7, Lane 14 nested facts FD 8, and lock FD 9 remain open through
a successful rename and close only implicitly in `os._exit`. Availability or
descriptor-handoff failure is 77 only before consumption and otherwise
non-pass.

#### Bounded common facts grammar

Facts are versioned, canonical, length-bounded records with fixed keys and exact
per-key cardinalities. They contain no free-form environment dump, secrets, or
arbitrary container filesystem content. Every normal receipt records:

- schema/version; literal selected argv; clean-environment proof; UTC start/end;
  UID/GID; kernel; source HEAD/tree; explicit tracked and untracked status at
  start/end; and the reviewed non-input exception ledger;
- start/end ledgers for each consumed file with
  `dev:ino:uid:gid:mode:nlink:size:sha256`, plus ELF build ID where applicable;
- root, artifacts, work, lock, lock-holder PID/starttime, and terminal publisher
  identities;
- resolved path, identity/hash, and version for each consumed tool; explicit
  build inputs/config/toolchain; only consumed environment variables and proof
  that forbidden build variables were absent;
- body/signal result; each requested and resolved resource identity; cleanup
  result; final absence; exact named artifact inventory; and
  `terminal_status_intent`.

The literal grammar is one ASCII line per record:

```text
facts-v1<TAB>SEQUENCE<TAB>KEY<TAB>VALUE<LF>
```

`SEQUENCE` is an unsigned canonical decimal increasing from zero without gaps.
`KEY` matches `[a-z0-9][a-z0-9_.-]{0,63}`. `VALUE` is UTF-8 projected to ASCII:
bytes outside `0x20..0x7e`, plus `%` and tab, are uppercase `%HH` encoded. A line
is at most 4096 bytes, a facts object at most 8 MiB and 4096 records. Literal
non-indexed keys occur exactly once. Repeated tools, inputs, resources, and
artifacts use zero-padded indexed keys (`resource.000.requested`,
`resource.000.resolved`, and so on), with one declared count key and no missing
or duplicate index. Each lane's self-test freezes its complete allowed-key and
cardinality table; unknown keys or free-form text are invalid.

<!-- FACT_SCHEMA_V1_BEGIN -->
The complete non-indexed common key set is
`schema.sha256`, `receipt.argv`, `receipt.cwd`, `receipt.clean_env`, `time.start_utc`, `time.end_utc`,
`host.uid`, `host.gid`, `host.kernel`, `source.head.start`, `source.head.end`,
`source.tree.start`, `source.tree.end`, `source.tracked.start`,
`source.tracked.end`, `source.untracked.start`, `source.untracked.end`,
`source.exception_count`, `root.identity.start`, `root.identity.end`,
`artifacts.identity.start`, `artifacts.identity.end`, `work.identity.start`,
`work.identity.end`, `lock.identity`, `lock.holder_pid`,
`lock.holder_starttime`, `tool.count`, `input.count`, `build_env.count`,
`resource.count`, `artifact.count`, `body.result`, `signal.result`, and
`terminal_status_intent`. The only indexed key families are
`source.exception.NNN`, `tool.NNN`, `input.NNN.start`, `input.NNN.end`,
`build_env.NNN`, `resource.NNN.requested`, `resource.NNN.resolved`,
`resource.NNN.cleanup`, `resource.NNN.absence`, `artifact.NNN.creation`,
`artifact.NNN.final`, and the lane groups in the table below. Each count equals
the number of complete zero-based indexed groups; every listed field has
cardinality one and no other key is accepted.

| Lane | Lane-group count keys and required indexed groups |
|---|---|
| 07 | `lane07.case_count=6`; `lane07.case.NNN.{name,capture,manifest,checker,exit,observer,bpf,map_before,map_after,oracle}` for NNN 000..005; `lane07.map_count=8`; `lane07.map.NNN.{name,before,after}` for NNN 000..007 |
| 09 | `lane09.capture_count=3`; `lane09.capture.NNN.{name,capture,checker,cgroup,product,harness,expected,provider_view,oracle}` for NNN 000..002; `lane09.base_count=1`; `lane09.base.000.{requested,resolved}`; `lane09.image_count=1`; `lane09.image.000.{requested,resolved,cleanup,absence}`; `lane09.container_count=2`; `lane09.container.NNN.{requested,resolved,pid,cleanup,absence}` for NNN 000..001 |
| 10 | `lane10.fork_count=1`; `lane10.fork.000.{capture,oracle,fifo,unit,cgroup,process}`; `lane10.capability_count=4`; `lane10.capability.NNN.{caps,argv,exit,document,log,scan_relation}` for NNN 000..003 |
| 11 | `lane11.report_count=2`; `lane11.report.NNN.{name,creation,final,snapshot}` for NNN 000..001 (`report.jsonl`, `results.json` in that order); `lane11.private_count=3`; `lane11.private.000.{name,creation,snapshot,removal,absence}` is state, 001 policy, 002 derived cache; `lane11.oracle_count=1`; `lane11.oracle.000.{capture,subset,unit,cgroup,process}` |
| 14 | `lane14.canary_count=10`; `lane14.canary.NNN.{name,artifacts,oracle}` for the seven fixed matrix lanes then three fixed start/fault lanes in source order; `lane14.image_count=3`; `lane14.image.NNN.{requested,resolved,packages,cleanup,absence}` for bookworm, Ubuntu, Alpine; `lane14.container_count=3`; `lane14.container.NNN.{requested,resolved,pid,cleanup,absence}` for glibc-build, glibc-run, musl-build; `lane14.smoke_count=6`; `lane14.smoke.NNN.{name,input,output,oracle}` for glibc-container, musl-container, host-glibc, packaged-helper, attach-e2e, static-attach; `lane14.dist_count=4`; `lane14.dist.NNN.{name,creation,final,build_id,linkage}` in the plan's fixed distribution order; `lane14.protocol_count=1`; `lane14.protocol.000.{journal,payload,ready,ack,creator,facts,cleanup}` |
| 16 | `lane16.row_count=1`; `lane16.row.000.{hammer,checker,provider,cargo,config,softhsm,observer,bpf,capture,aggregate,pause,loss,ambiguity,in_flight,child,cleanup,absence}` |

Brace notation expands to literal keys in the shown suffix order; it is not part
of the wire format. These are the only lane key families and every displayed
count is numeric and fixed before `CONSUMED`. Values combine their named
subfields in one canonical, length-bounded record with a lane-local fixed field
order. `schema.sha256` occurs exactly once and its value is the authoritative
digest below. A mismatch is non-pass.
<!-- FACT_SCHEMA_V1_END -->

The authoritative schema digest is the SHA-256 of the UTF-8 bytes strictly
between the two marker lines above, including final newlines:
`e212fd00c0e3063c206688524c2a395bd44c7bb2f3fecd22abe0df712b817250`. Task 3B RED tests and every driver embed and
report that literal digest; changing any key, order, or count requires a
separately reviewed plan amendment and new digest.

#### Self-test-only real-finalizer fixture protocol

The public interface remains exactly `--self-test`; it accepts no case selector,
fault environment, or extra argument. Standalone self-test creates one private
mode-0700 temporary parent and requires neither
`P11SCOPE_TASK4_SELF_TEST_WORK`, `P11SCOPE_TASK4_SELF_TEST_ANCHOR_PGID`, nor FD
5. The Rust-observed form instead requires all three: an existing, empty,
caller-owned mode-0700 absolute `P11SCOPE_TASK4_SELF_TEST_WORK` parent, inherited
FD 5, and the anchor PGID below. Any incomplete combination is an exit-2
rejection before mutation. These inputs are accepted only by the exact
one-argument `--self-test` branch, and normal mode rejects all three. The branch creates a fixed
fake-command directory and one subprocess per declared case by forking a shell
subshell that calls the same receipt-owner/body/finalizer functions as normal mode. Lexical shell variables select the fake
body and fault point only inside that subshell. Normal receipt mode forcibly
sets those variables to `none`, resets `PATH` to the validated normal command
set, and rejects extra arguments, so caller environment cannot activate a test
seam.

The fake-command boundary replaces only the named Cargo/runtime/tool commands;
root validation, trap installation, receipt mutation, resource journal,
cleanup/query logic, facts parser, inline terminal publisher, and status commit
are the production code. The self-test supervisor creates two mode-0600 FIFOs
at `$P11SCOPE_TASK4_SELF_TEST_WORK/control.in` and
`$P11SCOPE_TASK4_SELF_TEST_WORK/events.out` in observed mode, or at the same
relative names under its standalone parent. The FIFOs are supervisor-created,
caller-UID-owned mode-0600 objects. It opens
both ends read/write before forking, retaining control/events as supervisor FDs
3/4. The supervisor itself rejects symlink/non-FIFO/wrong-owner/wrong-mode/
wrong-link-count paths and requires pathname `lstat` to match FD `fstat` after
creation, before every child, and before identity cleanup. The case subshell
inherits child control-input FD 3 and event-output FD 4 directly, then closes
FD 5 before calling the receipt owner; driver-private FD 6 remains distinct.
Normal receipt mode closes inherited FDs 3 through 9 before validation and
ignores all inherited test variables. Fake external commands receive
`3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-`; only the receipt owner and its execed
terminal publisher retain child FDs 3/4 plus the applicable receipt FDs 7/8/9,
while only the supervisor retains FDs 3/4 and its side of FD 5. Case children
close FD 5.

Each FIFO frame is one bounded ASCII line:

```text
selftest-v1<TAB>NONCE<TAB>CASE<TAB>SEQUENCE<TAB>event|command<TAB>NAME<LF>
```

The child writes increasing `event` frames to FD 4; the supervisor alone writes
increasing `command` frames to FD 3. The two FIFOs are campaign-wide: they are
created once before the first case, reused by every exactly reaped case, then
closed and identity-removed before the supervisor's final completion event.
Nonce/case/direction/sequence mismatch,
unexpected EOF, malformed/duplicate frame, or timeout fails that case and kills
then reaps only the pinned child generation. `continue` and the fixed fault
commands `facts-write`, `facts-fsync`, `dir-fsync`, `mode-drift`, `inventory`,
`pending-write`, `pending-fsync`, `rename-collision`, and
`rename-unavailable` are the only commands. Events expose exact barriers before
and after requested/resolved registration and before terminal rename. The
supervisor pins each child PID/starttime and waits for the exact event. In the
Rust-observed form it forwards each named lifecycle barrier to FD 5, waits for
Rust's acknowledgement, and only then sends the requested `INT`/`HUP`/`TERM`
directly to that generation or writes its `continue`/fault command,
and bounds every internal frame wait at five monotonic seconds. Non-publisher
children close FDs 3/4 immediately after their final protocol point. For the
execed terminal publisher, `publisher-entered` is sent on FD 4 and its final
command is read on FD 3. It records that command without applying the fault,
closes both descriptors, and sends `SIGSTOP` to itself before the first
terminal-publication mutation. The supervisor waits for the exact pinned
generation to enter the stopped state, proves FDs 3/4 absent, and compares the
complete bounded root/work/artifacts inventory plus every retained object's
identity, size, digest, canonical content, and case-specific expected status
state with its
`publisher-entered` snapshot. It then emits the supervisor-generated
`publisher-isolated` frame to Rust. Rust independently proves the stopped
generation, FD absence, retained FD 7/8/9 identities as applicable, and the
same exact pre/post inventory/content equality. Only after Rust
acknowledges that frame does the supervisor send `SIGCONT`; the publisher may
then apply the recorded fault command and enter terminal publication. Missing
stop, identity drift, mutation, timeout, or failed continuation is non-pass and
causes pinned-generation cleanup. The supervisor emits
`case-reaped` only after exact child reap, retains that case root until Rust
acknowledges the frame, then identity-removes it. After the final case it closes
3/4 and removes only identity-matching FIFOs before `complete`.
Every case reports only canonical `selftest-v1<TAB>case<TAB>expected<TAB>actual`
rows followed by `selftest-v1<TAB>complete`; the Rust contract rejects missing,
duplicate, or unexpected rows. No Cargo, Docker, systemd, sudo, eBPF, provider,
or release command may escape the fake boundary.

The Rust artifact contract is the independent live observer, not the tested
reporter. It creates a `UnixStream::pair`; both originals are close-on-exec.
Rust records the child endpoint's socket identity before dropping its copy.
In `pre_exec` for the group anchor described below, Rust uses only
async-signal-safe `dup2`/`close`/`fcntl`: if the child endpoint is not already
5 it duplicates it to 5 and closes the original; if it is already 5 it only
clears `FD_CLOEXEC`; every other surplus stream copy is closed. Rust retains the
non-inheritable unnumbered peer and drops its child-end copy immediately after
spawn. The anchor hands FD 5 to the shell using the exact `Popen` sequence
below. FD 5 is optional for standalone self-test but mandatory for this
acceptance gate. Its presence requires the dedicated work parent above. Case
children and every external/fake command close FD 5; only the Rust peer and
shell supervisor retain their endpoints.

Rust generates a 64-lowercase-hex nonce from 32 bytes read from `/dev/urandom`
and starts the exchange. The stream is incrementally line-framed: no message
boundary is inferred from a read. Every line is printable ASCII plus tabs, ends
in one LF, and is at most 1024 bytes including LF; partial EOF, oversize, extra,
or malformed lines fail. Rust-to-supervisor and supervisor-to-Rust waits are
each bounded at five monotonic seconds. Directions and grammar are exact:

```text
Rust -> supervisor: audit-v1<TAB>NONCE<TAB>challenge<LF>
supervisor -> Rust: audit-v1<TAB>NONCE<TAB>SEQUENCE<TAB>supervisor-ready<TAB>SUPERVISOR_PID<TAB>SUPERVISOR_STARTTIME<TAB>PARENT_DEV:INO<TAB>CONTROL_DEV:INO<TAB>EVENTS_DEV:INO<LF>
supervisor -> Rust: audit-v1<TAB>NONCE<TAB>SEQUENCE<TAB>case-started|owner-entered|finalizer-entered|publisher-entered|publisher-isolated|case-reaped<TAB>ORDINAL<TAB>CASE<TAB>CHILD_PID<TAB>CHILD_STARTTIME<TAB>ROOT_DEV:INO_OR_NONE<TAB>RECEIPT_STATUS<TAB>CHILD_WAIT_STATUS<TAB>PUBLISHER_EXE_DEV:INO_OR_DASH<LF>
supervisor -> Rust: audit-v1<TAB>NONCE<TAB>SEQUENCE<TAB>complete<TAB>CASE_COUNT<LF>
Rust -> supervisor: audit-v1<TAB>NONCE<TAB>SEQUENCE<TAB>ack<LF>
```

All numeric fields are canonical unsigned decimal; every `dev:ino` is two such
decimals separated by one colon. The case alphabet is exactly the canonical
table. Sequence begins at zero, increases only for supervisor frames, and the
ack repeats rather than consumes that sequence. The Rust case table freezes the
exact ordered lifecycle sequence for every case: `case-started` and
`case-reaped` are mandatory, while owner/finalizer/publisher events occur only
when that case is expected to reach them. The total supervisor-frame count is
exactly two plus the sum of those frozen per-case sequence lengths.
It may never exceed `6 * CASE_COUNT + 2`; EOF or another frame after the exact
`complete` is failure. Missing/malformed ack or any five-second ack timeout makes
the supervisor kill and reap its pinned case child, identity-clean only owned
fixtures, and exit nonzero; the Rust anchor remains available for group cleanup.
`RECEIPT_STATUS` is the literal non-semantic placeholder `none` before reap;
Rust derives every live status assertion from its filesystem snapshot, so this
placeholder does not assert absence and also applies to the planned I97 live
frames. At `case-reaped` the field is semantic and is `none`, `invalid`, or
canonical decimal 0..255 exactly as the authoritative classes below require.
`CHILD_WAIT_STATUS` is `none` before reap and canonical decimal 0..255 at
`case-reaped`; signal waits use POSIX shell values 128 plus the signal number.
The publisher executable field is `-` except at `publisher-entered` and
`publisher-isolated`, where both frames name the same pinned terminal
interpreter identity; the root
field is `none` until an owned root exists.

At `case-reaped`, `none` means `lstat(root/status)` is `ENOENT`. `invalid` means
the path is not an authoritative terminal receipt, with an exact case oracle: `early-status`
retains the original caller-UID-owned mode-0600 `nlink=1` regular `0\n` inode
whose creation precedes `publisher-entered`; `duplicate-status` retains one
such regular inode containing exactly `0\n0\n`; and `foreign-terminal-artifact`
retains the substituted inode and its recorded foreign identity. Rust validates
those identities, contents, modes, link counts, and ordering itself; none is
accepted as a decimal receipt.

The following ordered classes are plan-authoritative and exhaustive; matching
stops at the first class. `full` means `case-started`, `owner-entered`,
`finalizer-entered`, `publisher-entered`, `publisher-isolated`, `case-reaped`;
`refusal` means only
`case-started`, `case-reaped`. A refusal has no owned root or receipt status.
A full case has no root at `case-started` and the same exact owned root at every
later live event.

| Class | Exact membership rule | Sequence | Receipt at reap | Child wait |
|---|---|---|---|---|
| P77 | `existing-root-rejected-status-77-no-touch-before-body`, `nonprivate-parent-rejected-status-77-no-touch-before-body`, `symlink-root-rejected-status-77-no-touch-before-body`, `foreign-root-rejected-status-77-no-touch-before-body`, `root-preflight-blocks-body-cargo-runtime`, `lock-contention-status-77-blocks-body-cargo-runtime`, `rootless-invalid-root-and-poisoned-environment-reach-no-mutator`, `public-body-reentry-rejected`, `explicit-pwd-work-composition-rejected-before-mutation`, `stdout-capture-substitution-rejected`, `glob-first-observed-selection-rejected`, `find-mode-repair-rejected`, every Lane-11 case ending `-rejected-before-mutation`, `caller-path-overrides-rejected-before-mutation`, `bare-observer-rejected`, `path-observer-rejected`, `outside-ROOT-work-target-release-observer-rejected`, `cargo-not-Rust-1.88-rejected`, `cargo-without-locked-workspace-release-rejected` | refusal | `none` | 77 |
| N97 | `missing-status-rejected`, `success-pending-write-failure-rejected-nonzero-status-last-once`, `success-pending-fsync-failure-rejected-nonzero-status-last-once`, `terminal-renameat2-noreplace-collision-rejected`, `terminal-renameat2-unavailable-rejected` | full | `none` | 97 |
| I97 | `early-status-rejected`, `duplicate-status-rejected`, `foreign-terminal-artifact-rejected` | full | `invalid` | 97 |
| SIGINT | every common case beginning `signal-INT-` | full | 130 | 130 |
| SIGHUP | every common case beginning `signal-HUP-` | full | 129 | 129 |
| SIGTERM | every common case beginning `signal-TERM-` | full | 143 | 143 |
| R97 | every remaining canonical name that ends in `-rejected`, contains `-rejected-`, or contains `-mutation-rejected`, and the exact cases `cleanup-failure-upgrades-terminal-status-and-is-written-last`, `cleanup-failure-upgrades-one-status-written-last`, `absence-query-failure-upgrades-terminal-status-and-is-written-last`, and `identity-mismatch-upgrades-terminal-status-and-is-written-last` | full | 97 | 97 |
| S0 | every remaining canonical case | full | 0 | 0 |

The Rust table expands these syntactic first-match rules and asserts that every
canonical case matches exactly one class. Thus, for example,
`initial-isolation-state-rejected` is R97/full, while the retained evidence
value `start-failures-8-exact-accepted` is S0/full.

At `supervisor-ready`, Rust proves the pinned supervisor PID/starttime, supplied
parent identity, and distinct supervisor-created caller-UID-owned mode-0600
`control.in`/`events.out`
FIFOs. It uses `symlink_metadata` on those exact paths, rejects symlinks and
non-FIFOs, requires `nlink=1`, and matches each reported `dev:ino` both to that
path and to `/proc/SUPERVISOR_PID/fd/3` or `/proc/SUPERVISOR_PID/fd/4`. It also
matches `/proc/SUPERVISOR_PID/fd/5` to the Rust-recorded child socket identity
and requires that same FD 5 identity through every frame including `complete`.
For each case, Rust derives the supervisor-owned sandbox `cases/NNN` and the
candidate receipt root `cases/NNN/root` from the zero-based ordinal. The
child's mandatory `case-started` and every expected `owner-entered`,
`finalizer-entered`, and execed terminal publisher `publisher-entered` are
blocking FD-4 barriers: child event,
supervisor validation and FD-5 forward, Rust live validation and ack, then the
supervisor's FD-3 `continue`/fault command. Rust revalidates the pinned child
generation and `/proc/PID/fd/3` plus `/proc/PID/fd/4` against the campaign
FIFO identities at every live barrier. At `case-started`, Rust checks the
case's frozen precondition and proves that no unplanned owned mutation occurred.
When the frame names a root identity, Rust also revalidates it. Owner and
finalizer require mode 0700 and no status. Publisher additionally requires
`/proc/PID/exe` to
differ from the pinned shell identity and match the pre-resolved terminal
Python interpreter identity reported in its frame. Rust requires publisher FDs
3/4 present at `publisher-entered`. The supervisor-generated
`publisher-isolated` barrier follows the close-and-stop sequence above; both
observers require FDs 3/4 absent, applicable FDs 7/8/9 unchanged, the exact
publisher generation stopped, the case-specific expected status state
unchanged, and no inventory, facts,
nested-facts, journal, payload, ready/ack protocol, or other retained-content
mutation between the bounded `publisher-entered` and `publisher-isolated`
snapshots before the acknowledged `SIGCONT`. Normal full cases require status
absent at both snapshots. I97 cases instead require their exact planned invalid
status inode/type/mode/link/content or foreign identity captured at
`publisher-entered` and byte- and identity-unchanged at `publisher-isolated`;
the live-frame `RECEIPT_STATUS` remains `none` until reap. At `case-reaped`, the
supervisor has reaped the child; Rust proves that generation absent and checks
the expected terminal status, tree, facts, and ownership before ack permits
root deletion. `complete` follows all case-root deletions and FIFO cleanup; Rust
checks both FIFO paths absent and every case reaped before acknowledging it.

The observed work inventory is exact. `$P11SCOPE_TASK4_SELF_TEST_WORK/cases`
is one supervisor-created mode-0700 directory. Before each `case-started`, the
work parent contains only `control.in`, `events.out`, and `cases`; `cases`
contains only the current supervisor-created `NNN` sandbox. That sandbox is
mode 0700 except in `nonprivate-parent-rejected-status-77-no-touch-before-body`,
where it is mode 0755. Its allowed entries are only the case's frozen P77 input:
`root` as the required directory/symlink/unauthorized object, or
`.task4.lock` for contention; otherwise it is empty and `root` is absent.
`foreign-root` is a caller-UID-owned object created by the Rust harness whose
identity is deliberately absent from the current run's requested/authorized
registry; it never means unavailable foreign Unix ownership. Rust creates or
authorizes each named negative fixture before the child proceeds, records its
identity/content, and checks that no other entry appears.

For P77 cases with a Rust-created `root` or `.task4.lock` entry, Rust validates
that entry byte- and identity-unchanged, removes only that entry, and only then
acknowledges `case-reaped`; the tested supervisor never removes or repairs it.
For the non-private-parent case, Rust validates that the sandbox remains mode
0755 and leaves sandbox removal to the supervisor. Fixtureless P77 cases require
an empty sandbox. For every other class, the supervisor removes only the `root` it created after Rust's
`case-reaped` ack. The supervisor then removes its now-empty `NNN` sandbox.
Rust proves the preceding sandbox absent before acknowledging the next
`case-started`, or before `complete` for the last case. Before `complete`, the supervisor removes `cases` and
the two FIFOs, leaving the supplied parent empty and at its original identity.

The three Lane-14 helpers use a separate exact four-frame sequence after the
same challenge; no FIFO or case frame is used:

```text
audit-v1<TAB>NONCE<TAB>0<TAB>helper-work-ready<TAB>HELPER<TAB>PID<TAB>STARTTIME<TAB>HELPER_ROOT_DEV:INO<LF>
audit-v1<TAB>NONCE<TAB>1<TAB>helper-body-complete<TAB>HELPER<TAB>PID<TAB>STARTTIME<TAB>OUTPUT_DEV:INO<TAB>SECOND_OUTPUT_DEV:INO_OR_DASH<LF>
audit-v1<TAB>NONCE<TAB>2<TAB>helper-cleanup-complete<TAB>HELPER<TAB>PID<TAB>STARTTIME<LF>
audit-v1<TAB>NONCE<TAB>3<TAB>complete<TAB>1<LF>
```

Every helper frame blocks for the same exact ack. Rust supplies a distinct
empty mode-0700 absolute `P11SCOPE_TASK4_SELF_TEST_WORK` parent and pins its
identity separately; `HELPER_ROOT_DEV:INO` identifies only the helper-created
`helper` child. The helper creates only that mode-0700 child, reports it at
`helper-work-ready`, and Rust validates its containment and the helper
generation. Before each mutation and frame, the helper itself revalidates the
supplied parent and helper-child path/type/owner/mode/link count against their
pinned identities; mismatch is nonzero without cleanup by stale pathname.
Canary creates exactly `helper/canaries.result`, containing
`selftest-v1<TAB>NONCE<TAB>canaries<TAB>result<TAB>OK<LF>`; attach creates
exactly `helper/attach-e2e.result`, containing
`selftest-v1<TAB>NONCE<TAB>attach-e2e<TAB>result<TAB>OK<LF>`. Each is a
caller-UID-owned mode-0600 regular file with `nlink=1` and is the sole helper
child entry.

Discover instead executes one fake-resource requested/resolved/cleanup/absence
lifecycle through the production journal/payload routines. Its sole entries are
mode-0600, caller-UID-owned, `nlink=1` regular files
`helper/discover.facts.journal` and `helper/discover.facts.payload`. The journal
has exactly these bounded records, where PID/starttime are the pinned fake child
that receives the fixture's normal cleanup request, exits 0, is reaped, and is
proved absent before `helper-body-complete`:

```text
journal-v1<TAB>0<TAB>resource.000.requested<TAB>fake-container:test<LF>
journal-v1<TAB>1<TAB>resource.000.resolved<TAB>pid=PID,starttime=STARTTIME<LF>
journal-v1<TAB>2<TAB>resource.000.cleanup<TAB>0<LF>
journal-v1<TAB>3<TAB>resource.000.absence<TAB>true<LF>
```

The payload has exactly these records; `DEV:INO`, `SHA256`, PID/starttime, and
the wait value are independently recomputed by Rust:

```text
payload-v1<TAB>0<TAB>journal.identity<TAB>DEV:INO<LF>
payload-v1<TAB>1<TAB>journal.sha256<TAB>SHA256<LF>
payload-v1<TAB>2<TAB>resource.count<TAB>1<LF>
payload-v1<TAB>3<TAB>resource.000.pid<TAB>PID<LF>
payload-v1<TAB>4<TAB>resource.000.starttime<TAB>STARTTIME<LF>
payload-v1<TAB>5<TAB>resource.000.cleanup<TAB>0<LF>
payload-v1<TAB>6<TAB>resource.000.absence<TAB>true<LF>
payload-v1<TAB>7<TAB>child.wait<TAB>0<LF>
```

The first output identity is the single canary/attach result or discover
journal; only discover uses the second identity for its payload.
At `helper-body-complete`, Rust validates the exact object inventory and, for
discover, both contents and that no helper-owned child remains in the anchored
process group. The helper then
identity-removes only its result objects and `helper` child and emits
`helper-cleanup-complete`; Rust requires them absent and the supplied parent
empty at its original identity. The helper never removes that supplied parent.
After `complete`, Rust reaps the helper and requires the whole process group
absent. Any identity, inventory, content, cleanup, ack, or group-absence failure
is nonzero and leaves no success report.

The Rust harness launches a fixed inline Python group anchor as the direct child
with `std::os::unix::process::CommandExt::process_group(0)`; Rust verifies the
resulting anchor PID equals PGID before the challenge. The anchor starts the
observed `/bin/sh SCRIPT --self-test` supervisor in the same group with
`subprocess.Popen(..., close_fds=True, pass_fds=(5,))`. FD 5 is already
inheritable from Rust's handoff; immediately after successful `Popen` the anchor
closes its FD-5 copy, and on `Popen` failure it closes FD 5 and exits 125. It
sets `P11SCOPE_TASK4_SELF_TEST_ANCHOR_PGID` to its canonical decimal PID only in
that observed shell environment; the exact self-test branch validates it
against `getpgrp`, normal/standalone mode rejects it, and fake commands inherit
it unchanged for their own `getpgrp()` check. It
waits for the shell and preserves its wait status: Python return codes 0..255
remain unchanged, while `-SIGNAL` becomes `128 + SIGNAL`; after the residue
checks below the anchor uses `os._exit` with that canonical value. After the shell exits, the
anchor takes two `/proc` snapshots 10 ms apart for members of its PGID,
excluding itself. It exits with the shell status only after both are empty. If
either is nonempty, it reports one bounded diagnostic and blocks without
spawning further children until Rust kills the group. Rust pins
the anchor PID/starttime/PGID before issuing the challenge and separately pins
the supervisor from `supervisor-ready`. On protocol failure, timeout, output
excess, or residue, Rust revalidates the live anchor, sends `SIGKILL` to the
negative PGID, reaps the anchor, and requires the group absent. Normal completion
requires anchor reap, the preserved shell status, and group absence. The anchor
is test harness, not product code, and is never used by normal or standalone
self-test. Self-test source and every fake command are forbidden to call
`setsid`, `setpgid`, `unshare`, or otherwise leave the anchor's process group;
after rejecting an inherited anchor variable, standalone self-test records its
current PGID in a private expected-PGID value inherited by fakes. Observed mode
instead validates the anchor-supplied value. Fake commands assert
`getpgrp() == EXPECTED_PGID` before any simulated action.

Stdout and stderr go to separate exclusive mode-0600 temporary files; Rust
polls each at no more than 1 MiB, kills on excess, then reads them after reap,
so pipe-held descendants cannot block collection. Rust's mode-0700 temporary
`HARNESS` contains only `work`, `fake-bin`, `report.tsv`, `audit.trace`,
`stdout`, `stderr`, and `tripwire.log`; every retained object's type, mode,
owner, link count, and bound is validated. Rust alone creates
`$HARNESS/audit.trace` with create-new/no-follow semantics,
caller ownership, mode 0600, and `nlink=1`; it appends only frames that passed
the live checks, caps the file at 1 MiB, and fsyncs it after `complete`.
Challenge and ack messages are never retained; every validated supervisor frame
is retained byte-for-byte. On protocol failure Rust fsyncs and closes the valid
prefix without adding `complete`, preserves it as a non-success diagnostic, and
kills/reaps through the anchor. The
validated `complete` frame is appended and fsynced before Rust sends its final
ack. The summary report retains its existing 8-MiB cap. A dynamic marker-complete,
digest-correct, exhaustive reporter launched inside the same tripwire-only
environment but without a valid FD-5 exchange must fail at
`supervisor-ready`, with no receipt mutation, fake command, or process residue.
Separately, a synthetic reporter that inherits valid FD 5, creates and opens
FDs 3/4, and emits canonical-looking frames but lacks the named production
owner/finalizer/root state must be rejected before Rust acknowledges the first
state-dependent frame. Passing the transport fixture alone is never driver
acceptance.
Extra-argument probes use that same environment and require nonzero, zero
frames, zero tripwire entries, zero mutation, and no process residue. This
observer raises regression confidence against dead-code/toy reporters; it is
not claimed as proof against a deliberately malicious replacement that
reproduces the entire OS-visible protocol.

Generated artifacts record creation and final identities. Source, configuration,
provider, observer, BPF, harness, checker, and capture identities are revalidated
at the end, not merely named. Per-lane facts additionally include:

- Lane 07: default/ring/state/freeze observer and BPF builds; provider and
  fixtures; exact eight-map inventories; named freeze and G1-G5
  captures/manifests/checkers/exits; unit/cgroup/PID identities and absence.
- Lane 09: Docker client/server/storage; requested/resolved base ID/digest and
  rootfs; built image ID/digest; both container IDs/image IDs/PID generations;
  provider identities in both views; broad/A/B cgroups; product, harness,
  expected file, checker; three named captures/logs; final absence.
- Lane 10: provider, product, discover, two harnesses, manifest, expected file;
  ptrace/perf/tracefs/DAC; unit/cgroup/process/FIFO; fork capture; four exact
  capability rows; scan/uncorroborated relation; final absence.
- Lane 11: sibling HEAD/tree and explicitly empty tracked/untracked status at
  start/end; sibling root/project/venv/bin/Python/package identities; default
  state/policy absence including dangling symlinks; private state/policy/cache;
  product/BPF/provider/manifest; unit/cgroup/PIDs; raw reports, capture, subset;
  retained state snapshots and identity-clean removal/absence.
- Lane 14: nested scripts/checkers/source; toolchains/config; image
  IDs/digests/package projections; container/process identities; journal,
  payload, creator handoff; canary/e2e/static evidence; official observer/BPF;
  four-file distribution; static-smoke PIDs; final absence.
- Lane 16: hammer/checker/provider/Cargo source/config; SoftHSM config/token;
  observer/BPF/hammer start/end; clean argv/env; named capture/checker;
  aggregate `evidence.module_ambiguous == 0`; pause/loss/ambiguity/in-flight
  fields; final identities and child absence.

#### Lane 14 journal, payload, and retained descriptor

The nested discover child is pinned by PID/starttime/session and never receives
the final facts FD. Before its first owned resource it creates a bounded,
versioned resource journal. After its exclusive first creation, each journal
append is a one-shot inline Python `O_WRONLY|O_APPEND|O_NOFOLLOW` operation that
requires the original journal identity, compares pre/post `lstat` versus
`fstat`, validates the canonical record, and `fsync`s. The child records requested identity before
creation and resolved container/image/PID/starttime/unit/cgroup identity before
activation or cleanup eligibility. Its finalizer identity-cleans and
query-proves absence, hashes the journal, and exclusively publishes one bounded
payload containing creator/file identities, journal digest, exact fact
cardinalities, cleanup results, and terminal child result. The parent pins and
waits the child and retains journal/payload on uncertainty.

Only after the complete Lane 14 body and ordinary cleanup/absence, the parent
starts a short-lived pinned creator. The creator first closes inherited FDs 3
through 9. It transiently opens the artifacts directory with no-follow
directory semantics and requires its expected identity; through that FD it
opens absent `discover.facts` with `O_CREAT|O_EXCL|O_NOFOLLOW|O_RDWR`, mode
0600, validates regular/owner/nlink/identity, moves the facts descriptor to FD
6, and closes the directory and every other transient before it atomically
publishes a nonce-bound ready
record using `renameat2(RENAME_NOREPLACE)`. The ready record contains protocol
version, nonce, parent and creator PID/starttime, FD number, and facts identity.
It waits boundedly for a matching atomic acknowledgement while polling parent
PID/starttime.

The parent uses `$!` plus pinned creator starttime, validates the ready record,
opens `/proc/$creator_pid/fd/6` into parent FD 8, and compares FD 8
`fstat`, pathname `lstat`, and ready identity before and after creator-generation
checks. It atomically publishes the matching acknowledgement, waits/reaps the
exact creator, and immediately `exec`s the terminal publisher. No intervening
or unrelated external command inherits FD 8; the execed terminal publisher is
the sole intended inheritor. Numeric PID reuse is not authority.

The observed Lane 14 mutation table snapshots `/proc/$creator_pid/fd` and
requires exactly standard FDs plus FD 6, proves every other reserved descriptor
absent, matches creator FD 6 to parent FD 8 before and after generation checks,
and rejects any extra descriptor or importer other than that parent.

Inside that terminal publisher, validate journal, payload, ready,
acknowledgement, schemas, nonces, cardinalities, sizes, identities, and digests;
import their canonical representation through FD 8 and `fsync` it; then remove
only identity-matching private protocol files. Revalidate final source/input,
root/work/artifacts, facts FD/path/hash, exact inventory, and cleanup absence;
record `terminal_status_intent`; synchronize retained data; and perform the
terminal status protocol above. Main facts FD 7, nested facts FD 8, and lock FD
9 remain open through the final rename. Creator/IPC cleanup is
PID/starttime-bound. Parent death or `SIGKILL` may leave diagnostics, but never
a valid status receipt.

## Lane contract matrix (retained domain authority)

### Lane 07 — induced gaps

**Driver:** `scripts/verify-induced-gaps.sh`.

**Prerequisites before consumption:** `gcc`, SoftHSM2, Python 3, Rust 1.88,
nightly/eBPF LLVM toolchain, `bpftool`, `systemd-run`, `sudo -n`, provider, and
the existing dump-helper self-test. If the current second-DISCOVERY-ringbuf
`dump-owned-bpf-maps.py`/`bpftool` path cannot inspect the owned maps (including
the known rc 244 class), exit 77 before `init`, root creation, consumption, or
the six production cases.

**Artifacts/oracle:** retain fixture/provider/BPF identities, before/after map
inventories and dumps, cgroup and PID/starttime identities, and every capture,
manifest, checker log, and exit for freeze plus G1 aliasing, G2 in-flight, G3
event loss, G4 START loss, and G5 RV loss. Preserve the existing freeze and
G1–G5 oracle byte-for-byte. Its literal shapes are G1 `160/93/186`, G2
`68/2/4`, G3 `68/68/136`, and G4/G5 `988/104/208` for
`table_entries/slots/attached_probes`. G3 retains exact positive calls
`C_GetFunctionList=1`, `C_Initialize=1`, `C_Finalize=1`, `C_GetSlotList=1`,
`C_OpenSession=1`, `C_CloseSession=1`, `C_GenerateRandom=200000`; G4 retains
`in_flight_at_end=9` and `start_insert_failures=8`; G5 retains 11 calls,
`rv_update_failures=9`, `unregistered_mechanisms=6`, and `async_orphans=1`.
The freeze control requires the existing exact eight-map inventory: `CONFIG`,
`PID_FILTER`, `CGROUP_FILTER`, `DESCRIPTORS`, `ASYNC_FUNCTIONS`, `MECH_SHAPE`,
`ATTR_BOOL_BITS`, and `TEMPLATE_TAIL`. Final absence covers observer/workload
processes, cgroup/unit, and owned BPF objects.

### Lane 09 — shared Docker layer

**Driver:** `scripts/matrix/verify-shared-layer.sh`.

**Prerequisites before consumption:** Docker client/daemon/storage, `gcc`,
SoftHSM2, Python 3, Rust 1.88, `sudo -n`, resolved base image, and writable
private evidence work. This receipt plan supersedes the earlier Lane 09 UNRUN
status only after its implementation commit passes review. Any missing or
invalid prerequisite exits 77 before `init`, root creation, Docker, or other
consumption.

**Artifacts/oracle:** put all disposable work under `$ROOT/work`; retain Docker
client/server/storage facts, requested and resolved base, built image ID/digest,
both container IDs and process generations, provider content/build identity and
both filesystem views, broad and leaf cgroups, product/harness identities, and
three captures/checker logs. Preserve exactly: broad sees two workloads and one
uncertainty; `a-only` and `b-only` each see one workload and zero uncertainty.
Each capture is `68/68/136`; broad positive function counts are exactly twice
`spike/expected.txt` plus `C_GetFunctionList=2`, while each leaf is exactly the
file plus `C_GetFunctionList=1`. Prove exact container IDs, image ID, processes,
and cgroups absent.

### Lane 10 — fork scope and capability relationships

**Driver:** `scripts/matrix/verify-fork-scope.sh`.

**Prerequisites before consumption:** cgroup v2, systemd, `capsh`, tracefs/DAC
context, `gcc`, SoftHSM2, Python 3, Rust 1.88, provider, and `sudo -n`. If the
intended capability row cannot be formed because tracefs or DAC infrastructure
is unavailable, exit 77 before `init`, root creation, or capture rather than fabricating a
relationship.

**Artifacts/oracle:** retain product/discover/provider/harness/manifest/expected
identities, one fork row and exact-count result, and exactly four measured
capability rows with literal capability sets, status, documents, and logs.
The fork row is `68/68/136`, with exact positive counts from
`scripts/matrix/fork-expected.txt`: `C_CloseSession=4`, `C_Digest=20`,
`C_DigestInit=20`, `C_Finalize=5`, `C_GetInfo=1`, `C_GetSlotList=4`,
`C_Initialize=5`, and `C_OpenSession=4`, plus the existing manifest-only
`C_GetFunctionList` bootstrap relation.
Retain ptrace/perf/tracefs context and the measured
`scan_unavailable`/`discovery_uncorroborated` relationship. Preserve the current
`terminal_capture_is_clean(..., uncorroborated=1)` assertion unchanged. Only a
fresh otherwise-valid mismatch may authorize a later, separately reviewed
oracle amendment; recording the measured relationship does not itself amend or
supersede that candidate hard-coded assertion. Prove target processes,
cgroup/unit, and FIFO absent.

### Lane 11 — independent pkcs11-check oracle

**Driver:** `scripts/matrix/verify-oracle.sh`.

**Prerequisites before consumption:** exact sibling
`/home/user/src/m/pkcs11-check-ws/pkcs11-check`, its executable `.venv`, cgroup
v2/systemd, SoftHSM2, Python 3, Rust 1.88, provider, and `sudo -n`. Both sibling
`.pkcs11-check-isolation-state.json` and
`.pkcs11-check-isolation-policy.json` must be absent initially, including as
dangling symlinks; otherwise exit 77 before `init` or root creation and never
delete them.

**Artifacts/oracle:** use
`cargo +1.88 build --locked --release --workspace`. Retain equal start/end
sibling HEAD/tree plus explicitly empty tracked and untracked status ledgers,
lock/project/venv file identities, installed-package projection, default
state/policy absence, provider/product/BPF identities, raw oracle reports,
manifest/capture/log, and derived subset summary. Invoke the sibling CLI with
its native `--state-file` and `--policy-file` options using exactly:

```text
$ROOT/work/isolation-state.json
$ROOT/work/isolation-policy.json
```

Its exact derived report-record cache is
`$ROOT/work/.isolation-state.json.report-records`. Retain validated snapshots,
then remove only those three private objects proven to have been created by this
invocation, after regular-file/directory/dev/inode/owner validation; require all
private and both sibling defaults absent at finalization. Any sibling, venv,
package, state, policy, cache, tracked, or untracked ledger mutation invalidates
the lane. Preserve the current subset and terminal-capture oracles; current
aggregate totals are not frozen acceptance counts.

### Lane 14 — release build

**Driver:** `scripts/build-release.sh`; nested facts producer:
`scripts/verify-discover-containers.sh`.

**Prerequisites before consumption:** `file`, `jq`, `setpriv`, Python 3,
Rust 1.88 stable and required nightly/eBPF toolchain, musl target and linker,
`gcc`, Docker client/daemon, `sudo -n`, SoftHSM2, resolved build images, and the
dump-helper/bpftool path used by nested gates. If the known second-DISCOVERY
ringbuf inspection cannot run, exit 77 before `init`, root creation, or
consuming release evidence.
This plan supersedes the earlier Lane 14 UNRUN status only after implementation
review.

**Artifacts/oracle:** put mutable build/dist work beneath `$ROOT/work`; retain
all nested script/checker hashes, toolchain/target/vendor/config inputs,
official observer/BPF and final distribution inventory, canary/e2e/static-smoke
evidence, three resolved build-image IDs/digests and package projections,
nested container IDs, and the bound nested facts file. Preserve every existing
release oracle. The final inventory is exactly four executables:
`p11scope`, `p11scope-discover`, `p11scope-discover-glibc`, and
`p11scope-discover-musl`; `p11scope` is static musl and rejects the unsafe flag,
the two glibc names are byte-identical, and the musl helper is dynamically
linked. Ubuntu glibc, Alpine musl, packaged-helper, and host helper smokes each
retain 68 SoftHSM records; the deterministic fixture retains the exact
68/92/104 table shapes; the packaged static attach smoke retains
`68/68/136` and exact `spike/expected.txt` plus one `C_GetFunctionList`.
Prove containers, images owned by ID, target processes, and observer absent.
`build-release.sh` is the only terminal owner.

### Lane 16 — two fixed structural rows

**Driver:** new `scripts/verify-task4-lane16.sh`.

**Prerequisites before consumption:** `gcc`, `sudo -n`, SoftHSM2, Python 3,
Rust 1.88, provider, `scripts/fixtures/hammer.c`, and
`scripts/check-capture-evidence.py`. Missing current-head binary inputs,
checker, compiler/toolchain, provider, or `sudo -n` exits 77 before `init`, root
creation, build, or capture. Reject inherited build-affecting Cargo/Rust/compiler environment using
the same fixed list as Lane 02.

**Build/config:** create `$ROOT/work/tokens` mode 0700 and
`$ROOT/work/softhsm2.conf` mode 0600, initialize one private SoftHSM token, and
record/revalidate both. Build only with:

```sh
CARGO_TARGET_DIR="$ROOT/work/target" \
  cargo +1.88 build --locked --release --workspace
gcc -O0 -o "$ROOT/work/hammer" scripts/fixtures/hammer.c -ldl
```

The observer is exactly `$ROOT/work/target/release/p11scope`; a bare
`p11scope`, PATH lookup, unpinned/unlocked Cargo build, or observer outside that
private target is invalid. Record/revalidate the observer's
dev/inode/size/SHA-256 and every Cargo/source input.

**Workload:** validate `MODE` by `case "$MODE" in never|auto) ;; *) exit 2 ;;
esac`, then run exactly one requested row through the existing verified-root
launcher with the literal product shape and a clean environment:

```sh
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" \
  "$ROOT/work/target/release/p11scope" run \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --mode metrics --duration 30 --kill-on-timeout --pause "$MODE" \
  -o "$ROOT/artifacts/observed.json" -- \
  "$ROOT/work/hammer" \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 200000
```

The driver contains one fixed-arity gate-only validator; it is not a new public
checker or product PASS framework. Each of the separate `never` and `auto`
invocations must independently exit zero and require exactly the complete
authoritative predicate list:

- 68 table entries, 68 slots, and 136/136 entry/return probes;
- exactly one authorized sanitized
  `{"name":"discovery subject","reason":"discovery unavailable"}` timing
  projection;
- `event_loss == 0`; `discovery_ring_loss == 0`,
  `discovery_state_failures == 0`, `discovery_read_failures == 0`, and
  `discovery_truncated == 0`;
- `module_ambiguous == 0`, `session_cancel_ambiguities == 0`,
  `auth_state_ambiguities == 0`, and `fork_state_ambiguities == 0`;
- `in_flight_at_end == 0`, `pending_at_end == 0`, and the owned-run
  `child_still_running` field is present and false;
- `never`: `none/0/0/0`; and
- `auto`: `sigstop`, `pause_attempts = pause_confirmed >= 1`,
  `pause_partial = 0`.

There is no unavailable-loader predicate for Lane 16. Lane 02 deterministic
counts do not apply. `200000` defines the workload but is not an acceptance
count; `G3`, `136175`, function-call totals, timing, latency, median, and
performance values are non-authoritative.

## Historical rejected task appendix — do not execute

Every checkbox, command, file list, task, and commit instruction below through
the superseded Task 4 section is preserved only as review history. None is
executable authority.

### Superseded file structure and ownership

Commit this plan alone first so its commit is the implementation authority.
The later implementation commit modifies exactly:

- `scripts/verify-induced-gaps.sh` — Lane 07 receipt/finalizer/self-test;
- `scripts/matrix/verify-shared-layer.sh` — Lane 09 receipt and ID cleanup;
- `scripts/matrix/verify-fork-scope.sh` — Lane 10 receipt only;
- `scripts/matrix/verify-oracle.sh` — Lane 11 isolation/receipt and pinned Cargo;
- `scripts/build-release.sh` — sole Lane 14 receipt/finalizer;
- `scripts/verify-canaries.sh` — Lane 14-private canary work propagation;
- `scripts/verify-attach-e2e.sh` — Lane 14-private attach work propagation;
- `scripts/verify-discover-containers.sh` — Lane 14-private nested facts;
- `scripts/verify-task4-lane16.sh` — Lane 16 workload/structural validator;
- `tests/artifact_contracts.rs` — table-driven lifecycle and lane mutations.

Historical rule, now superseded: this design prohibited a shared receipt
helper. The authoritative amendment instead permits exactly one private
stdlib-Python envelope while leaving lane-specific resource ownership local.

---

### Superseded Task 1: prior plan-commit sequence

**Files:**
- Create: `docs/superpowers/plans/2026-08-27-task4-receipt-closure.md`

**Produces:** One immutable implementation authority, separate from all code.

- [ ] **Step 1: Run plan self-review**

Compare every Lane 16 predicate with the production plan, confirm Lane 10's
current oracle remains unchanged, scan for prohibited placeholder language from
the writing-plans skill, and run `git diff --check`.

- [ ] **Step 2: Obtain independent approval**

Sol xhigh reviews architecture/security/lifecycle; Terra reviews executable
contracts and sequencing; Luna inventories literal paths/cardinalities. All
three must return PASS with no unresolved critical/important issue.

- [ ] **Step 3: Commit only the plan**

```sh
git add docs/superpowers/plans/2026-08-27-task4-receipt-closure.md
git commit -m "docs: plan remaining Task 4 receipts"
```

Do not add the unrelated OpenSSL report.

### Superseded Task 2: live-observer RED contracts

**Files:**
- Modify: `tests/artifact_contracts.rs`

**Consumes:** The exact normal/nested interfaces and root schema above.

**Produces:** One table-driven contract over all seven production drivers
(unchanged Lane 02 plus modified 07/09/10/11/14/16), plus lane-specific
cardinality/identity mutations.

- [ ] **Step 1: Add the table and prove RED**

For each modified normal driver, invoke `sh SCRIPT --self-test` and require its
success marker. Pin Lane 02's existing self-test unchanged. Run:

```sh
cargo +1.88 test --locked --test artifact_contracts task4_receipt -- --nocapture
```

Expected before implementation: FAIL because five scripts lack the interface
and Lane 16 does not exist.

- [ ] **Step 2: Encode lifecycle mutations**

Each lane-local self-test uses fake external commands and a temporary private
parent/root. It must cover complete success, input mutation before finalization,
body success plus cleanup/query failure, existing/non-private/symlink/foreign
root, missing ephemeral identity, and status-last ordering. Artifact contracts
must reject missing/early/duplicate status, changed HEAD/input ledger, foreign
terminal artifacts, missing capture/checker evidence, or a runtime/Cargo command
started during root-preflight rejection.

The behavioral table also holds `$CAMPAIGN/.task4.lock` from a separate fake
owner and proves every normal driver fails before body/Cargo/runtime execution;
after releasing that exact lock, the same driver's success fixture proceeds.

- [ ] **Step 3: Encode exact lane mutations**

Reject missing/duplicate G1–G5 or freeze artifacts; wrong Lane 09 broad/leaf
cardinality or IDs; wrong Lane 10 fork/four-row relationship; Lane 11 sibling
state or ledger mutation; Lane 14 missing/replaced nested facts; and either
Lane 16 structural-row mutation. Accept Lane 16 changes limited to
call/timing/performance values. Reject a Lane 16 bare/PATH observer,
unpinned/unlocked Cargo invocation, observer outside
`$ROOT/work/target/release`, or missing observer/Cargo identity ledger.

- [ ] **Step 4: Encode the Lane 14 containment amendment**

Replace the historical `OFFICIAL_TARGET=target/release-official` assertion
with the relational safe-only contract
`OFFICIAL_TARGET="$WORK/release-official"`, while retaining the isolated
`CARGO_TARGET_DIR`, `--no-default-features`, and unsafe-flag rejection checks.
The real `build-release.sh --self-test` boundary and source contracts must
add mutations proving all of the following:

- no `P11SCOPE_TASK4_BODY` dispatch or public body re-entry exists;
- a rootless, invalid-root, or poisoned-environment invocation reaches no
  mutator;
- caller `P11SCOPE_TASK4_DIST` and
  `P11SCOPE_TASK4_OFFICIAL_TARGET` values cannot redirect output;
- there is one receipt `EXIT`/finalizer owner and body cleanup failure produces
  one nonzero status written last;
- the exact `WORK`, `CANARY_WORK`, `ATTACH_WORK`, `DISCOVER_BASE`,
  `DISCOVER_WORK`, `DIST`, and `OFFICIAL_TARGET` relationships above hold;
- supplied nested work paths must be absolute, their legacy defaults remain
  available when absent, and no `$PWD/$WORK` composition remains; and
- canary, attach, discover, diagnostic-BPF, distribution, and official-build
  paths cannot escape `$ROOT/work` or use receipt-mode `target/canaries` and
  `target/e2e` paths; and
- a rootless hardened-child fixture enters with FDs 3 through 9 absent, opens
  its own PID-handoff FD 3, validates that descriptor's local file identity,
  closes it before exec, and proves that no control FIFO or other receipt
  descriptor reaches the target payload.

### Superseded Task 3: duplicated lane-local receipts

**Files:**
- Modify/Create: exactly the nine scripts listed under file ownership.

**Consumes:** Task 2 tests and existing lane oracles.

**Produces:** The exact interfaces, receipts, identity-bound cleanup, and
self-tests above with no product/checker/public-schema changes.

- [ ] **Step 1: Implement common-shaped code locally**

Use only POSIX shell, existing `scripts/lib.sh` functions, `flock`, `stat`,
`sha256sum`, `/proc`, and current Python/JQ code. Repeat the small validation
sequence inside each owner; do not create a helper file or new dependency.

- [ ] **Step 2: Preserve each body oracle**

Move work beneath the private root, wrap existing body execution, replace
mutable-name cleanup with recorded immutable identity cleanup, and retain
current assertions. For Lane 10 do not change `uncorroborated=1`. For Lane 11
pin Cargo and enforce state ownership. For Lane 14 use the internal same-shell
body and fixed private-work path map above, and pass only the private facts
path. Add the exact Lane 16 validator above.

- [ ] **Step 3: Run focused GREEN checks**

```sh
sh -n scripts/verify-induced-gaps.sh
sh -n scripts/matrix/verify-shared-layer.sh
sh -n scripts/matrix/verify-fork-scope.sh
sh -n scripts/matrix/verify-oracle.sh
sh -n scripts/build-release.sh
sh -n scripts/verify-canaries.sh
sh -n scripts/verify-attach-e2e.sh
sh -n scripts/verify-discover-containers.sh
sh -n scripts/verify-task4-lane16.sh
sh scripts/verify-induced-gaps.sh --self-test
sh scripts/matrix/verify-shared-layer.sh --self-test
sh scripts/matrix/verify-fork-scope.sh --self-test
sh scripts/matrix/verify-oracle.sh --self-test
sh scripts/build-release.sh --self-test
sh scripts/verify-canaries.sh --self-test
sh scripts/verify-attach-e2e.sh --self-test
sh scripts/verify-discover-containers.sh --self-test
sh scripts/verify-task4-lane16.sh --self-test
cargo +1.88 test --locked --test artifact_contracts task4_receipt -- --nocapture
```

No Docker, sudo, systemd, eBPF attachment, or production evidence is consumed
by these self-tests.

### Superseded Task 3A: prior Lane 14 containment sequence

This task follows the fresh canonical-suite finding at exact HEAD `47a4632`.
Commit this plan-only authority amendment before changing code.

**Files:**
- Modify exactly `scripts/build-release.sh`, `scripts/verify-canaries.sh`,
  `scripts/verify-attach-e2e.sh`, and `tests/artifact_contracts.rs`.

- [ ] **Step 1: Capture focused RED**

Add the Task 2 Step 4 contracts without weakening the existing receipt cases.
Run the focused artifact contract and require failure on the current public
re-entry/path escapes or obsolete official-target literal, never on a fixture
error or real runtime command.

- [ ] **Step 2: Implement the same-shell correction**

Remove public body re-entry and caller-selected distribution/official paths.
Call the release body only from the validated receipt owner, derive the fixed
path map above, propagate exact nested paths, make absolute work safe, and give
body cleanup to the one finalizer. Preserve every existing release oracle and
the nested discover facts authority.

- [ ] **Step 3: Focused GREEN and four-file commit**

Run shell syntax/self-tests for the three scripts, the focused artifact
contract, then the full canonical sequence serially. After stopped-writer
review, commit exactly the four corrective files:

```sh
git add scripts/build-release.sh scripts/verify-canaries.sh \
  scripts/verify-attach-e2e.sh tests/artifact_contracts.rs
git commit -m "fix: confine Lane 14 release work"
```

### Superseded Task 3B: live-observer lifecycle sequence

This task follows the unanimous stopped-writer rejection at exact HEAD
`1330630d1af58d5f61c21c258d23babc8acc1135`. The already committed ten-file
implementation inventory is unchanged; this task repairs those same files in
place. Commit this plan amendment alone before changing implementation.

**Files:** Modify only the existing ten-file implementation inventory under
File structure and ownership. Writers are sequential and own disjoint files;
review begins only after each writer stops.

| Order | Sole writer ownership | Acceptance before next row |
|---|---|---|
| 1 | `tests/artifact_contracts.rs` | intended real-finalizer RED, writer stopped, Sol/Terra/Luna review |
| 2 | `scripts/verify-task4-lane16.sh` | syntax, self-test, focused GREEN, writer stopped, three reviews |
| 3 | `scripts/verify-induced-gaps.sh` | same focused gate and three reviews |
| 4 | `scripts/matrix/verify-shared-layer.sh` | same focused gate and three reviews |
| 5 | `scripts/matrix/verify-fork-scope.sh` | same focused gate and three reviews |
| 6 | `scripts/matrix/verify-oracle.sh` | same focused gate plus exact sibling-state tests and three reviews |
| 7 | `scripts/verify-canaries.sh` | private-path self-test, stopped writer, three reviews |
| 8 | `scripts/verify-attach-e2e.sh` | private-path self-test, stopped writer, three reviews |
| 9 | `scripts/verify-discover-containers.sh` | child journal/payload fixtures, stopped writer, three reviews |
| 10 | `scripts/build-release.sh` | parent creator/FD-8/terminal fixtures, stopped writer, three reviews |

No later writer edits an earlier row's file. If review requires such a change,
return ownership to that row, stop all other writers, repair, rerun its gate,
and repeat all three reviews before resuming.

- [ ] **Step 1: Replace toy models with RED real-finalizer fixtures**

In `tests/artifact_contracts.rs`, execute each actual script `--self-test` path
against fake external commands and private temporary roots. The self-test must
exercise the production root owner and finalizer, with only runtime bodies
substituted at the named command boundary. First require RED for:

- success followed by facts `fsync`, directory `fsync`, mode, inventory, or
  status-stage failure: no zero receipt and no early/duplicate status;
- `INT`, `HUP`, and `TERM` before and after durable requested/resolved resource
  registration; cleanup failure; absence-query failure; and identity mismatch;
- invalid/existing/symlink/non-private roots and held campaign lock reaching no
  Cargo/runtime/body mutator;
- input, HEAD/tree, tracked, untracked, provider, observer, BPF, harness,
  checker, capture, or artifact mutation before terminal publication;
- absence of every public body bypass, `$PWD/$WORK`, glob/first-observed
  selection, stdout capture substitution, `find` mode repair, and pre-finalizer
  root mutation; fake commands and descendants also prove FD 3 through 9
  are closed outside the named protocol exceptions;
- terminal `renameat2(RENAME_NOREPLACE)` collision/unavailability and proof that
  its successful rename is the last filesystem mutation before exit;
- exact bounded fact keys/cardinalities and named artifacts for every lane;
- Lane 11 unchanged dirty sibling, untracked sibling input, dangling default
  state/policy symlink, incorrect default filename, missing native state/policy
  arguments, wrong derived cache, and foreign private object; and
- Lane 14 journal append/`fsync`, requested-before-create,
  resolved-before-activation, child cleanup uncertainty, malformed/replaced
  journal or payload, creator PID/starttime reuse, nonce/ready/ack/FD identity
  mismatch, parent death before ack, exact creator descriptor inventory, FD 8
  leakage, and final facts replacement;
- every real Task 3B driver through the observed session, rejecting direct
  marker-only success; and a valid-FD-5 synthetic reporter that opens FDs 3/4
  and emits canonical-looking frames without production owner/finalizer/root
  state, rejected before the first state-dependent acknowledgement; and
- an early facts/protocol mutation after `publisher-entered` but before
  close-and-stop, rejected at `publisher-isolated` with no acknowledgement or
  terminal receipt.

For Lane 16, reject a missing aggregate
`evidence.module_ambiguous == 0`, changed observer/hammer/config/provider/capture
identity, and an owned child surviving finalization. Keep one focused Cargo test
command at a time and prove the failure is the intended contract, not fixture
setup or a real privileged command.

- [ ] **Step 2: Implement Lane 16 as the reference owner**

Repair `scripts/verify-task4-lane16.sh` first: immediate finalizer, state
latches, durable resource registration, bounded facts, complete aggregate
predicate, final input revalidation, identity-bound cleanup/absence, exact
artifact inventory, and execed terminal publisher. Run its shell syntax,
self-test, and focused artifact contract. Stop its writer and obtain Sol xhigh,
Terra, and Luna review before copying the proven local pattern.

- [ ] **Step 3: Repair Lanes 07, 09, 10, and 11 sequentially**

Use one writer per script, in that order. Remove public body re-entry, execute
the body in the owner shell, install terminal authority before mutation, use
absolute receipt paths, register resources durably, bind cleanup to immutable
identity, retain exact named artifacts, emit the lane-specific bounded facts,
and use the reviewed terminal publisher. Preserve every existing lane oracle.
For Lane 11 additionally use the corrected sibling defaults and exact private
state/policy/cache contract above. After each stopped writer, run syntax,
self-test, focused artifact tests, and independent three-model review; repair
before advancing.

- [ ] **Step 4: Repair Lane 14 and nested facts last**

Keep the existing fixed private work relationships in `build-release.sh`,
`verify-canaries.sh`, and `verify-attach-e2e.sh`. Implement the child
journal/payload and parent creator/FD-8 protocol exactly as amended above in
`verify-discover-containers.sh` and `build-release.sh`. Perform all remaining
import, protocol-file cleanup, final revalidation, synchronization, and status
publication inside the execed terminal publisher. No intervening or unrelated
command inherits FD 8; the terminal publisher is its sole intended inheritor.
Run only rootless fixtures until stopped-writer Sol xhigh, Terra, and Luna
agree.

- [ ] **Step 5: Canonical verification and cumulative review**

Run every script syntax/self-test, the focused artifact contract, then the full
canonical Rust sequence serially. Freeze and review exactly the cumulative ten
implementation files from `bf4cbcf..HEAD` plus this separately committed plan
authority. Runtime remains `UNRUN` until Task 4 below passes unanimously.

### Superseded Task 4: prior implementation review

**Files:** The cumulative exact ten-file implementation range only. The range
through exact HEAD `1330630d1af58d5f61c21c258d23babc8acc1135` is rejected and
must not advance to runtime. Task 3B supplies the stopped-writer lifecycle,
provenance, Lane 11, Lane 14, and Lane 16 corrections within the same inventory.

**Produces:** One reviewed cumulative gate-only range ending in the final Task
3B correction commit.

- [ ] **Step 1: Run canonical verification serially**

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git diff --check
```

- [ ] **Step 2: Stop the writer and review**

Sol xhigh reviews cleanup authority, terminal reachability, source binding, and
oracle preservation. Terra reviews command/root/lock/runtime sequencing. Luna
checks file inventory, literal cardinalities, and no out-of-scope change. Fix
and repeat until all agree.

- [ ] **Step 3: Freeze the exact cumulative gate-only range**

```sh
git diff --name-only bf4cbcf..HEAD -- scripts tests/artifact_contracts.rs
# Require exactly the ten files in File structure and ownership.
# The separately committed plan amendment is authority, not implementation.
# Historical rejected rule: no shared helper. Do not execute this old task.
```

### Task 5: Prove Lane 02 compatibility and run remaining Task 4 lanes

**Files:** Generated private evidence only; no Git changes unless fresh evidence
reproduces a separately reviewed oracle defect.

**Produces:** One serial, source-bound Task 4 board or a terminal stop at the
first `UNRUN`/`NON-PASS`.

- [ ] **Step 1: Freeze implementation tip and Lane 02 compatibility**

Create the compatibility report described above, revalidate the Lane 02 root,
and stop on overlap/mismatch. Do not rerun Lane 02 automatically.

- [ ] **Step 2: Run lanes once in exact order**

Use one new absent root for 07, 09, 10, 11, and 14, then one new absent root for
each Lane 16 mode. Hold the common campaign lock and stop immediately on an
exit 77 before root creation, nonzero status, missing status, body/oracle
failure, input drift, cleanup
uncertainty, or privacy failure. Do not run any later lane after a stop.

- [ ] **Step 3: Independent evidence review and freeze**

Review exact roots, hashes, cardinalities, cleanup, privacy, and current-source
qualification. Amend only a fresh reproduced mismatch under separate review.
Only a clean reviewed board unlocks r3 and 9.2d; it does not itself claim
9.3, CI, Task 10, release, or whole-project completion.
