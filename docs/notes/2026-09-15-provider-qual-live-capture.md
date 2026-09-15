# Provider qualification: live capture on Fedora 44 guest (6.19.10-300.fc44)

Date: 2026-09-15. Guest: Fedora 44 cloud image, kernel 6.19.10-300.fc44.x86_64,
SELinux enforcing. Observer: `p11scope-rel` (static-PIE) + file capabilities
`cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep`
(unprivileged `p11scope` user, groups intact — REQUIRED for group-gated
providers such as opencryptoki's 0660 SYSV SHM; `sudo run` drops groups and
breaks token access by design).

Qual-only PINs (all four providers): user `1234`, SO `87654321`.

## Invocation rules learned (guest sessions are inconsistent)

- `$HOME` flips between `/home/p11scope` and `/home/user` across ssh
  sessions. Always use absolute `/home/p11scope/...` paths.
- `KRYOPTIC_CONF` must be the FILE path
  (`/home/p11scope/.config/kryoptic/token.conf`), not the directory.
  Without it, kryoptic falls back to `$HOME`-relative lookup (flaky, see above).
- `certutil -N -d sql:DIR` requires DIR to pre-exist (else
  `SEC_ERROR_BAD_DATABASE`, even as root). Same failure if `-d` points at a
  path built from a wrong `$HOME`.
- Never pipe `certutil -S` into `head` (SIGPIPE/head deadlock spins at ~100%
  CPU); run unpiped. RSA-2048 keygen in this guest is pathologically slow
  (7+ min CPU spin observed); the NSS qual DB ships with NO cert for now.

## Per-provider live-capture verdicts (all unprivileged + file caps)

Guest capture JSONs live in guest `/tmp` (`oc-pause.json`, `oc-holder.json`,
`sh-tool.json`, `sh-holder.json`, `kryo-tool.json`, `kryo-holder.json`,
`kryo-pid.json`, `nss-pre.json`, `sh-cgroup.json`, `sh-full3.json`).

- opencryptoki (swtok `qualtok`, slot 0): WORKS via `run --pause auto` on an
  ELF that dlopens the shim (`pkcsconf -t`, holder workload).
  208/208 probes, 104 slots, real `C_Initialize/C_GetSlotList/C_GetTokenInfo/
  C_Finalize` calls, 0 errors. Token re-initialized 2026-09-15 with known
  PINs (backup of previous empty store at guest `/tmp/swtok-backup.tgz`).
  First post-dlopen call can be missed while attach completes.
- SoftHSM2 (`qual` slot 0 PIN unknown — untouched; `qual2` slot 1 PIN 1234):
  PARTIAL by design. `run --pause auto` on ELF (`pkcs11-tool -T`, holder)
  attaches the `C_GetFunctionList` export hook (2/2 probes, 1 slot, call
  captured) but the runtime-built heap table is outside the file-backed scan:
  `function table unavailable in file-backed data` (verbatim skip).
  `--hook-symbol` cannot extend this — hooks are table-handout points only
  (`src/discovery/hooks.rs`: builtins = standard three + NSS NSC_/FC_).
- Kryoptic 1.5.2 (`qualkryo` slot 1 + `qualryo2` slot 2, sqlite, PIN 1234):
  WORKS but noisy. `run --pause auto` on ELF holder: 354/354 probes,
  177 slots, 10 real functions captured (`C_Initialize`, `C_GetSlotList`,
  `C_GetTokenInfo`, `C_OpenSession`, `C_Login`, `C_Logout`, `C_CloseSession`,
  `C_Finalize`, `C_GetFunctionList` x2 rows) — plus PHANTOM slots: e.g.
  `C_EncryptUpdate` 6984 calls / 6506 err, second `C_GetFunctionList` row
  1000/1000 err, `event_loss` 7581. The 2.1 MB Rust .so decodes pointer
  arrays that look like 48/66/68/92/104-entry tables; phantom rows show
  huge counts + all-errors, real rows show expected counts + 0 err.
  Analyst heuristic: counts stable across runs are real. `profile --pid` on
  a settled process is the reliable path (184/184 probes, 0 skipped, real
  session calls); `run` on a short python check is silent (scan lands while
  the loader is mid-flight).
- NSS softokn 3.127 (DB `/home/p11scope/.pki/nssdb`, password 1234 since
  2026-09-15; empty-password backup at `.pki/nssdb-empty-bak`):
  WORKS via `LD_PRELOAD=libsoftokn3.so` + `run --pause never` on the holder
  with explicit `-c "configdir='sql:...' ..."` init args: 424/424 probes,
  212 slots, real `C_CloseAllSessions` x2 + `C_Finalize` x1, 0 errors.
  (Table decode count varies run to run: 426 vs 424 — same phantom
  instability as kryoptic, milder.) User login lives on slot index 1
  (`NSS Certificate DB`); slot 0 (`NSS Generic Crypto Services`) rejects
  `CKU_USER` with `CKR_USER_TYPE_INVALID`. pkcs11-check needs
  `--slot 1` + `P11TEST_PIN`.
- Jammy 5.15.0-187-generic lane (`vm-operational/2026-09-15-jammy-515`,
  SSH 2247): SoftHSM **2.6.1** decodes a **68-entry v2.40 table via scan**
  (136/136 probes, real `C_Logout/C_CloseSession/C_Finalize` captured).
  The "runtime-built table" boundary is VERSION-dependent: 2.6.1 has a
  file-backed static table, Fedora's 2.7 build does not. Same observer
  binary both lanes (sha `0b078837`). Jammy setup notes: image was 2.2G
  (apt died with ENOSPC) → `qemu-img resize +12G`, `rm apt lists`,
  `growpart`, `resize2fs` → 14G; apt needs `Acquire::ForceIPv4` (v6
  stalls); universe was missing from the partial update.

## Discovery-matrix model (evidenced 2026-09-15)

- `run --pause auto` + ELF: catches dlopen; scan quality depends on loader
  settledness (opencryptoki clean, kryoptic messy).
- `profile --pid`: needs the module mapped AND settled at attach; blind to
  later dlopens (0/0/0, no rescan for unbound loaders). Export hooks do NOT
  lower under `profile` (need the run path); table slots do.
- `run --pause never`: loses short-lived dlopen races (pkcsconf: 0 modules,
  2 skipped); works with `LD_PRELOAD`.
- `run --pause always`: REFUSED everything in one test (`process generation
  changed before target access` on every object) — suspected generation-guard
  bug, needs host-side repro.
- python targets: loader never binds under `run` (`discovery unavailable`);
  `profile` works via settled table scan only.

## Gaps / bugs filed from this session (host-side work)

1. `--pause auto` + softokn load cascade HANGS: child `T` in
   `do_signal_stop`, observer `S` in `hrtimer_nanosleep` (retry loop) for
   10+ min, SIGTERM ignored, SIGKILL wedged observer in `D` inside
   `uprobe_unregister_sync <- synchronize_rcu_tasks_trace` until the stopped
   child was reaped (kill -9), then both gone. Product must SIGCONT its
   paused child on the exit path (and handle SIGTERM while paused).
   Trigger: `./holder libsoftokn3.so` (NSS dep cascade). No JSON written.
   UPDATE 2026-09-15 (host repro + partial fix): reproduced the shape on
   host with `run --pause always` + a dlopen-loop fixture (kernel
   7.0.0-31, file-caps binary): SIGTERM mid-pause left observer `D` +
   child `T`; both gone ~3 s later, cleanup failed with `pause
   coordination cancelled`, no JSON. Root-caused one layer: NEITHER
   graceful settle path (`settle_after_signal_with_grace`,
   `terminate_with_grace`) ever SIGCONTed — a stopped child cannot
   observe the forwarded SIGTERM, so it burned both grace windows (or
   the full 5 s grace) and died by SIGKILL (137). Fixed with
   `OwnedChild::resume_if_stopped` (pidfd SIGCONT, best-effort, no-op
   when running) called first in both paths; pinned by two RED→GREEN
   unit tests (`signal_settlement_resumes_a_stopped_child_before_
   forwarding_sigterm`: was 137/0.67 s, now 143/0.12 s;
   `graceful_termination_resumes_a_stopped_child_before_sigterm`: was
   137/5.1 s, now 143/fast). Full `--lib` suite: 818 pass; the 10
   failures are outside the change (8 discovery-engine fixture drift +
   1 `/bin/sleep`-shim env failure proven off-path + 1 parallel-load
   flake that passes in isolation). REMAINING on this item: the
   coordinator-cancel error text still says "refused rather than
   capturing unpaused" on signal exits (misleading, cosmetic), and the
   ~3 s D-state detach wedge is kernel-side (shorter once the child is
   resumed first, but not eliminated by this fix).
2. Kryoptic phantom tables (false-positive decodes on Rust .rodata) +
   `event_loss` under-reporting pressure (7581 lost vs ~10 real). Consider
   multi-run stability scoring (feature, not a fix).
   UPDATE 2026-09-15 (event_loss ground-truth audit, guest runs ev-b/ev-d/
   ev-e/ev-f + tracefs uprobe): the counter is EXACT, no fix needed.
   Trace burst N=100000: kernel entered 100003, drained 26436,
   entered-drained = 73567 = reported `event_loss` precisely
   (COUNT_EVIDENCE line in the trace carries both sides). Aggregates
   stayed exact under loss (2000/2000 at loss 1222; 100000/100000 in
   metrics mode). Tracefs uprobe cross-check: 20000/20000 entries,
   matching the fixture's own count. The "7581 vs ~10 real" was
   analyst confusion: loss counts ring RECORDS (per-call events as
   seen at the uprobe, phantom-storm events included — the kryoptic
   run fired 6984 phantom calls), not semantic rows; low-rate loss
   (36 at paced 1500) is real drain-cadence dynamics (profile 1s
   ticks vs trace 200ms — same workload showed 0 in trace mode).
   Metrics mode reports 0 always by construction (ring never drained,
   counter zeroed at run.rs:2101) — now documented in usage.md.
   Side observations (not loss bugs): a real +1 extra C_Finalize
   (entered+returned, unattributed — opencryptoki self-call or
   observer-induced); Fedora SoftHSM 2.7 still 0/0 (known
   version boundary — audit ran on opencryptoki, 208/104 clean).
2b. `run --pause always` refused EVERYTHING on one Kryoptic workload
   (`process generation changed before target access` on libc, libm,
   the provider, opensc, and the tool itself, plus the memory scan).
   Suspected generation-guard over-triggering when the child is stopped
   at every load; needs a host-side repro, not a doc fix.
   UPDATE 2026-09-15 (guest repro): dlopen-loop driver against
   libkryoptic + `p11scope-rel run --pause always` → exit 1, `0/0
   probes attached`, same always-refusal (guest `~/pause2b.log`; no
   `generation changed` lines this time). Reclassified: with zero
   discovered slots there is nothing to protect, and always-refusal is
   the DESIGNED response (pinned by
   `explicit_always_refuses_rather_than_completing_unpaused`). The real
   gap is one layer down — discovery yields no usable table on the
   Kryoptic churn workload (see phantom-table item 2 above). Not a
   pause bug; do not "fix" the refusal.
3. `doctor` row `uprobe attach (own libc)` FAILed for the static-PIE
   binary (`no executable libc.so mapping in /proc/self/maps`) — FIXED
   2026-09-15: row renamed `uprobe attach (self)`; no libc mapping now
   falls back to the observer's own entry point
   (`manifest::elf::entry_file_offset` + integration test in both
   linkages + `libc_path_in_maps` unit test). Verified live on both
   guests: row `ok`, tier flips T0 offline → T1 host attach. Fixed
   binary (musl static, sha `e76ecbcd`) regression-captured jammy
   SoftHSM identically (136/136).
4. `C_Finalize` err=1 in opencryptoki captures (double-finalize on the
   dlclose path — benign, counted honestly).
5. Fixture `.so` (tests/fixtures, 104 file-backed slots, `/home/p11scope/`
   on the 6.19 guest): scan decodes the REAL table (names align with
   source), 208/208 probes attach with zero failures — and ZERO events
   arrive (`raw_calls:0` in `--trace` mode), although the driver provably
   executes the probed functions. Kernel tracefs uprobe on the same
   file+offset FIRES (`fx: (0x7f...)`, ctor+app hits). So p11scope's BPF
   attach/event path is broken for this target while working for
   `/usr/lib64` providers in the same guest. Same inode/dev/fs (btrfs),
   same `per-offset` mechanism, same addresses the tracefs probe used.
   Suspect PID/process-tracking filter on the BPF side (check
   `process_tracking_*` counters), not the file. Crisp repro: build
   fixtures in-guest, `LD_PRELOAD` + `P11SCOPE_FIXTURE_GATE=1` +
   `P11SCOPE_FIXTURE_REPEAT=200` + `run --trace --pause never`.
   (Also learned: the fixture driver only ever calls the three handout
   surfaces, never table slots — a fixture-capture lane needs REPEAT plus
   working handout/export probes.)

## pkcs11-check suites (0.1.9, `--isolation none --skip-slow`, qual tokens)

REQUIRED PRE-STEP (missed in the first qual pass, corrected 2026-09-15):
`pkcs11-check fetch-data all` BEFORE any suite run. Without it the
vector-gated tests (wycheproof/cctv/acvp/x509-limbo markers) silently skip
and the skip counts below overstate coverage. Gate:

```bash
pkcs11-check fetch-data --status   # all four sources must show ✓
pkcs11-check doctor -m <module>    # reports "vector data fetched (...)"
```

Verified 2026-09-15 on the Fedora guest: all four sources ✓
(wycheproof, cctv, acvp, x509-limbo). Vector-subset re-runs below.

- Kryoptic vector subset (`--marker 'wycheproof or cctv'`, same flags/PINs,
  guest `~/vec-kryo-wc.log` → `suites/vec-kryo-wc.log`): 27 failed,
  27226 passed, 21067 skipped, 19410 xfailed (971 s). The 27 failures are
  ONE cluster, all `test_wycheproof_aes.py::test_aes_key_wrap[tc*-invalid]`:
  Kryoptic's AES-KW unwrap ACCEPTED forged wrapped blobs — a real
  security-relevant finding the vector-less qual could not produce.
  Remaining skips are provider-capability skips, not missing vectors
  (probed: `test_wycheproof_dsa.py` skips are `DSA_SHA224/SHA256 not
  supported`; `test_cctv_ed25519.py` re-run: 914/914 passed, 0 skipped).
- Kryoptic ACVP subset (`--marker acvp`, guest `~/vec-kryo-acvp.log` →
  `suites/vec-kryo-acvp.log`): 4 failed, 27074 passed, 6493 skipped,
  4754 xfailed (250 s). All 4 failures are `TestEdDsaKeyVer`
  (Ed25519 tc1/tc4, Ed448 tc6/tc8): the module ACCEPTED INVALID EdDSA
  keys — second real finding, same "accepts invalid input" shape as AES-KW.
- Kryoptic x509 path run (`testcases/x509`, `suites/vec-kryo-x509.log`):
  1729 passed, 1 skipped (3.3 s); limbo-only re-run: 1689/1689 passed.
  x509-limbo vectors fully exercised, no failures.
- SoftHSM2 vector subset (`--marker 'wycheproof or cctv'`, `--isolation
  file`, guest `~/vec-sh-wc-file.log` → `suites/vec-sh-wc-file.log`):
  8182 passed, 9731 skipped, 2214 xfailed, 0 failed on the 12 files that
  ran to completion — plus THREE crashed files and one in-process abort
  (`suites/vec-sh-wc-abort.log`):
  - `test_wycheproof.py`: `test_aes_gcm[tc311-invalid]` → SIGABRT inside
    SoftHSM (`decrypt_single`, abort log frame `raw/api.py:637 _call`).
  - `test_wycheproof_ecdh.py`: `test_ecdh[ecdh_brainpoolP224r1_test.json:
    tc1-valid]` → SIGSEGV in `derive_key` (C_DeriveKey); C stack names
    `libsofthsm2.so`. All other ECDH curves pass (bisected per curve).
  - `test_wycheproof_ecdsa.py`: `test_ecdsa_wycheproof[
    ecdsa_brainpoolP224r1_sha224_test.json:tc1-valid]` → SIGSEGV.
    Pattern: SoftHSM 2.6.1 cannot do brainpoolP224r1 at all — first
    valid vector kills the process; all other ECDSA curves pass
    (~8.8k passed across secp groups).
  - Process lesson: `--isolation test` with explicit path targets (and
    with `--match`) collects ZERO tests — file isolation is the working
    crash-survival mode; `--isolation auto` promotes crashed files to
    per-test but at ~110 units/min it is infeasible for 44k units
    (killed at 832/44356). Crashing nodes were bisected with
    `--isolation none` + `--match` instead.
- SoftHSM2 x509 path run: 1729 passed, 1 skipped — identical to Kryoptic.
- SoftHSM2 ACVP subset (`--marker acvp`, `--isolation file`,
  `suites/vec-sh-acvp.log`): 3303 passed, 1288 skipped, 121 xfailed,
  0 failed, 0 crashed files — but the SAME 4 `TestEdDsaKeyVer` failures
  as Kryoptic (Ed25519 tc1/tc4, Ed448 tc6/tc8). Cross-provider
  reproduction: two independent providers accept the same invalid EdDSA
  keys, so this is provider leniency, not a test artifact.
- opencryptoki vector run (`--marker 'wycheproof or cctv or acvp'`,
  `--isolation file`, slotd active, `suites/vec-oc-wca.log`): 50504
  passed, 25397 skipped, 1257 xfailed, 0 crashed files, 148 unique
  failures in two clusters: 144x `test_aes_cbc_pkcs5[tc*-invalid]`
  ("Invalid AES-CBC vector decrypted successfully" — padding leniency)
  plus the SAME 4 `TestEdDsaKeyVer` invalid-key acceptances. Three
  independent providers now accept the same invalid EdDSA keys.
- NSS: vectors change nothing there — the suite stays ENVIRONMENTAL
  (pkcs11-check 0.1.9 cannot pass NSS init args; see above), documented
  as such, not re-run.

- SoftHSM2 qual2 full: 61 failed, 1884 passed, 2275 skipped, 280 xfailed,
  8 errors (71 s). Failures cluster in adversarial suites: ffi_length
  (25), arithmetic_overflow (18), keygen/mech_negative/cve (12) — leniency
  where strict rejection is demanded; plus real-looking `test_unwrapped_key_
  cannot_unset_sensitive`, wrong-key-type derives, GCM IV reuse.
- Kryoptic full: 103 failed, 2716 passed, 2964 skipped, 632 xfailed,
  8 errors (498 s). Clusters: mech_negative wrong-key-type (24), operation
  termination after failure (11), message-interface params (10),
  buffer-too-small guards (4), SP800-108 KDF vectors (4), null-pointer (3);
  earlier: public session creating private objects, `C_SessionCancel`
  SIGSEGV (dmesg-confirmed traps in libsofthsm2/libc from crasher
  subprocesses are expected artifacts).
- The 8 benchmark ERRORs on both providers = missing `pytest-benchmark`
  in the guest (fixed: pip installed 2026-09-15).
- opencryptoki full (`--isolation file`, guest `/tmp/oc-full2.log`): 54
  FAILED — wrong-key-type derives (13), template-count overflows (8),
  corrupted-unwrap KWP (8); security singletons: private-key extraction,
  tookan unwrap extractable, OAEP error uniformity, GCM IV reuse. First
  `--isolation none` attempt died mid-run on a REAL swtok SIGSEGV
  (`test_wild_oversized_bool_attr`, in-process shim; slotd unaffected —
  daemon/shim split confirmed, slotd still `active`, qualtok healthy).
- Kryoptic full (`--isolation none`, 498 s): 103 failed / 2716 passed /
  2964 skipped / 632 xfailed / 8 errors — see clusters in triage.
- NSS pkcs11-check suite: ENVIRONMENTAL LIMITATION, not a verdict.
  pkcs11-check 0.1.9 cannot pass NSS init args, so softokn always opens
  its NULL-init default DB — which is not the qual DB no matter what
  (`$HOME`, cwd, and even replacing `/etc/pki/nssdb` with the qual DB
  all still fail login; holder with explicit
  `configdir='sql:/home/p11scope/.pki/nssdb'` logs in fine with the same
  PIN, proving the DB and PIN are good). Runs: empty-password DB +
  slot 0 → 6463 setup ERRORs (`CKR_USER_TYPE_INVALID`); password DB +
  `--slot 1` → 5619 setup ERRORs (`CKR_PIN_INCORRECT` against the wrong
  DB) + 123 FAILED (cascade noise). System `/etc/pki/nssdb` was briefly
  swapped during diagnosis and RESTORED from backup (verified readable).
  NSS coverage stands on holder captures, `info` (232 mechs, v3.2
  incl. vendor interfaces), slot listing, and explicit-configdir login.
  One REAL softokn finding anyway: SIGSEGV on NULL encrypt/decrypt args
  (`test_null_argument_rejection_terminates_encrypt_decrypt_operation`,
  `--isolation none` run).
- dmesg traps corroborate the crasher subprocesses (GPFs in
  libsofthsm2, segfaults in libc) — expected `--isolation none`
  artifacts, contained by `file` isolation.
- `version_matrix` host tests: 4/4 green. No `P2-verifier` artifact
  exists anywhere in the tree (old slice work-package label, not a tool).

## Environment notes

- `nss-tools` installed in guest (dnf, network OK). `pytest-benchmark`
  installed (pip). `gcc` present. holder.c (manual-qual driver, not a repo
  fixture) lives at guest `~/holder.c` and host
  `vm-operational/2026-09-15-provider-qual/holder.c`.
- Guest cgroup delegation: unprivileged write to an owned
  `/sys/fs/cgroup/p11qual/cgroup.procs` is DENIED (reason undetermined —
  SELinux suspect); sudo-migration of a running PID works. `profile
  --cgroup` on an empty cgroup yields 0/0/0 (correct, no members).
- pkcsslotd is systemd-managed; restart after token wipe works; SHM
  re-created by the daemon.

## NSS slot1 verdict (2026-09-15; first run INVALID, rerun launched)

- `~/vec-nss-slot1.log` (sealed 07:31Z, 50m13s): **invalid run** — 123
  failed, 39 passed, 7607 skipped, **105915 errors**, every error
  `CKR_PIN_INCORRECT` at fixture setup (`login_user`, `fixtures.py:171`)
  from test #1 onward. A `P11TEST_PIN` was set against a token that
  cannot take it.
- Mechanism (strace-proven): pkcs11-check calls `C_Initialize(NULL)`
  (`core/loader.py:193,308`); NULL-init softoken opens NO database file
  (no cert9/key4/pkcs11.txt anywhere — ephemeral in-memory token), so
  any non-empty-PIN `C_Login` fails. Disproven along the way:
  cwd-as-configdir (fresh 1234-PIN DB in cwd still fails), and
  `~/.pki/nssdb` involvement (never touched by the suite; the old DB
  with its lost PIN is backed up at guest
  `~/.pki/nssdb-lostpin-bak/`, fresh 1234 DBs at `~/.pki/nssdb/` and
  `~/nssdb-run/` are irrelevant to the suite path).
- Docker-lane equivalence: `test-nss` sets `PKCS11_CHECK_MODULE` +
  `SLOT=1` and NO pin (`Dockerfile:59-60`, `run-pkcs11-check.sh`
  passes `--pin` only when set) → `pin=None` → no login attempts.
  The `/var/lib/nss` certutil setup in the Dockerfile is vestigial to
  the suite (nothing passes a configdir). "NSS-as-oracle" envelope on
  this guest = ephemeral token, login-less surface; login-capable NSS
  runs need init-args support in pkcs11-check (other repo — follow-up,
  not this workspace).
- Rerun (docker-equivalent, no `P11TEST_PIN`), finished 08:03Z, all
  652 units: **600 passed, 51 failed, 1 empty** (state-file verdict —
  the runner exited silently after unit 652 with no grand summary, no
  traceback, no OOM trace; other-repo finale gap, verdict recovered
  from `.pkcs11-check-isolation-state.json` + worker lines).
  Test-level: **38,655 passed, 210 failed, 0 errors**, 54,107 skipped
  (no-login surface), 2,523 xfailed — 99.46% of executed tests pass.
  The 210 failures cluster in wycheproof ECDH (29) / ML-DSA (8),
  security/ FFI-boundary strictness (82), ckr/ error-path RV
  expectations (37), and v3.x message-API negatives — provider-vs-
  oracle expectation divergences, zero harness errors. Triaging each
  as NSS behavior vs oracle over-assertion is pkcs11-check-domain
  work (other repo), not this workspace. VERDICT: NSS-as-oracle on
  ephemeral slot 1 runs clean and passes at 99.5% with the failure
  list above as the characterized delta.
