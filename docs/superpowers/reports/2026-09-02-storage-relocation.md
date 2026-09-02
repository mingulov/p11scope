# Storage relocation record

Date: 2026-09-02 (Europe/Helsinki)

## Rule and result

Durable p11scope state now lives under exactly two roots:

- `/home/user/src/m/pkcs11-scope` — public project source and tracked public
  documentation.
- `/home/user/src/m/p11scope-ws` — private evidence, VM inputs, archives,
  custody metadata, and workspace Git history.

At public revision `8ff322e25d69fb8d8776e9de8434a8d513ea3e5b`
and private revision `39c9feecaeef557cdd5ae6a92b95a135b8f4f117`,
all tracked live-navigation pointers and retained-input defaults use those
roots, except the separate project-checkout decision recorded below. Historical
records retain the paths that were true when their work ran.

The exhaustive private inventory and per-item decisions are in
`/home/user/src/m/p11scope-ws/preserved/2026-09-02-storage-relocation/INVENTORY.md`.
The same directory holds the Task 2 receipt, reviewed migration helper, and
eight adjacent typed manifests. No large migrated payload was added to Git.

## Relocation map

| Original | Durable destination | Disposition |
| --- | --- | --- |
| Three evidence-index semantic roots under `/home/user/.local/state/p11scope/` | `/home/user/src/m/p11scope-ws/preserved/evidence-roots/<original-name>/` | Exact copy and typed readback |
| Lane 13 `task4-lane13-a2fd9ee-20260826T2135EEST/facts.log` | `/home/user/src/m/p11scope-ws/preserved/evidence-roots/task4-lane13-a2fd9ee-20260826T2135EEST/facts.log` | Exact file copy; mode and pinned hash verified |
| `pkcs11-scope-portable-{3d3ba05,90a03ac,b86d4d5}.tar.zst{,.sha256}` | `/home/user/src/m/p11scope-ws/preserved/portable/` | One exact six-file transaction |
| `/home/user/.local/state/p11scope/security-scan-3e10be9/` | `/home/user/src/m/p11scope-ws/preserved/security-scan-3e10be9/` | Approved subset completion to eight source files plus the existing custody manifest |
| Task 4 SDD subtree inside `retired-generated-slice1b2-finish` | `/home/user/src/m/p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` | Existing byte-identical W1 custody copy accepted as a 0700/0600 no-op |
| `/home/user/p11scope-vm-bases/` | `/home/user/src/m/p11scope-ws/vm-bases/` | Complete 12-directory/127-file legacy tree copied |
| `/home/user/.local/state/p11scope/fedora44-base/` | `/home/user/src/m/p11scope-ws/vm-bases/fedora44-base/` | Added in the same combined VM transaction |

Items classified as diagnostic, superseded, generated, or unpacked duplicates
were not blanket-copied. They remain at the old root only until the owner makes
the deletion decision below; no live authority pointer depends on them.

## Symlinks retained

Both approved compatibility shims already resolve wholly inside the two roots
and remain unchanged:

- `/home/user/src/m/pkcs11-scope-evidence` →
  `/home/user/src/m/p11scope-ws/evidence`
- `/home/user/src/m/p11scope-ws/source` →
  `/home/user/src/m/pkcs11-scope`

## Policy decisions pending owner ratification

Historical plans and reports keep old absolute paths verbatim because those
paths are provenance facts, not executable navigation. The live evidence index
and ROADMAP authority pointer carry the new path plus the old-root annotation.
This is the working interpretation of the storage wording in the release
requirements §6 and PRD §9.6; owner ratification remains explicit.

`scripts/matrix/verify-oracle.sh` defaults `PKCS11_CHECK_DIR` to
`$HOME/src/m/pkcs11-check-ws/pkcs11-check`. That is a separate sibling project
checkout, not p11scope data, and its Git revision plus environment are bound in
the lane receipt. Treating project checkouts as outside the two-directory data
rule is **OWNER-PENDING**; the path remains environment-overridable.

## Owner-gated follow-up

- Delete neither old root yet. Current apparent sizes are 10,905,331,203 bytes
  for `/home/user/.local/state/p11scope` and 1,714,727,520 bytes for
  `/home/user/p11scope-vm-bases`.
- Rotate the copied VM SSH key only with explicit owner authority. The private
  key remains mode 0600; the public key remains mode 0444.

Nothing was deleted, moved, rotated, pushed, tagged, or published during this
relocation.
