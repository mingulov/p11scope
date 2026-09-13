# Slice 1b-2 third-kernel amendment

**Status:** Accepted on owner instruction to cover additional kernels and
PKCS#11 3.x providers in qualification. Amends the frozen campaign parameters
only.

## 1. Scope and authority

The binding corrective design remains
`2026-08-18-slice1b2-corrective-live-discovery-design.md`, with the pause state
machine superseded by `2026-08-19-slice1b2-no-busy-wait-pause-amendment.md` and
the campaign's standing superseded by
`2026-08-19-slice1b2-d3-scope-amendment.md`.

This amendment supersedes exactly one thing: the two-kernel shape of the frozen
relocation-witness campaign declared in the D3 scope amendment §4.3 and §7 —
"240 children per kernel, 480 primary attempts total" and "both kernels".

It does not change the campaign's standing. D3=`no` left that campaign dormant
and off the Slice 1b-2 product critical path, and it stays there. Nothing in
this amendment puts campaign evidence on the release path, promotes results
into a compiled-in timing catalog, or weakens §9.2 completeness, loader/context
validation, exact identity, pause closure, privacy, or the production kernel
gates.

## 2. Why a third kernel

Two kernels is the smallest set that can show a release-to-release difference.
It is not a set that can show a distribution difference, and the observations
that motivated this amendment are distribution-shaped:

- **PKCS#11 3.x is only reachable off Ubuntu.** Of the providers packaged for
  Ubuntu 26.04, only nss-softokn answers `C_GetInterface` with the 3.2/104
  table; opencryptoki 3.26 stops at 3.0/92. Fedora 44 packages kryoptic —
  a 3.x-native provider with no Ubuntu package — alongside nss-softokn and
  opencryptoki 3.27, and all three answer 3.2/104. The 3.x interface path is
  the product's newest discovery surface and the two-kernel set exercises one
  provider on it.
- **The conservative walk had no shipping witness.** SoftHSM 2.7.0-rc1, as
  packaged by Fedora 44, declares table version 3.2 and then populates only the
  68 entries through `C_WaitForSlotEvent`. p11scope records
  `walk: known_prefix` and declines to walk 104 slots into adjacent memory.
  Before this provider, that path was exercised only by our own fixtures.
- **`/etc/os-release` is now load-bearing.** The provider matrix oracle is keyed
  by environment profile (`scripts/verify-provider-matrix.sh`). A campaign that
  never leaves one distribution cannot detect a profile that silently stops
  matching.

Fedora 44's cloud image boots 6.19, which also widens the kernel span: 5.15
(Ubuntu 22.04 LTS), 6.8 (Ubuntu 24.04 LTS), 6.19 (Fedora 44).

## 3. Frozen parameters

`FROZEN_KERNELS` is amended from two entries to three, and each entry now
carries its own base provenance rather than sharing one hardcoded Ubuntu label:

| Name | Release prefix | Base provenance |
| --- | --- | --- |
| `jammy` | `5.15.` | retained Ubuntu cloud image overlay base |
| `noble` | `6.8.` | retained Ubuntu cloud image overlay base |
| `fedora` | `6.19.` | retained Fedora cloud image overlay base |

The grid per kernel is unchanged: 2 load kinds x 2 table kinds x 3 pause
policies x 20 children = 240 primary attempts, plus 20 forced `dlopen_return`
fallback attempts. Across three kernels:

- **720 primary attempts** (was 480)
- **60 forced-fallback attempts** (was 40)
- **780 counted attempts total**

`FROZEN_DEADLINES.campaign_seconds` rises from 43200 to 64800. The budget is a
cap the runner honours, not a schedule; half again as many attempts needs half
again as much wall clock. `attempt_seconds` (120) and `pause_poll_ms` (1) are
unchanged, as are `FROZEN_CAPS` and `FROZEN_TOPOLOGY`.

## 4. Freeze ordering

These are freeze-time parameters. They are declared here, and in
`scripts/check-live-discovery-evidence.py`, before the campaign's first
privileged run. Adding a kernel after a campaign has run would either invalidate
that campaign's execution manifest or force a second, non-comparable one.

No campaign has been run at the time of this amendment. The validator's
`--self-test` reports `campaign PASS: complete: 780 attempts, 3 kernels PASS`
against synthetic rows; that is an oracle check, not campaign evidence.

## 5. Refusals this amendment must keep

The validator's frozen-manifest mutation lanes are tightened, not merely
renumbered:

- a manifest declaring **two** kernels is now refused (the boundary moved from
  one to two; refusing a one-kernel manifest no longer proves the current shape);
- three distinct names and three distinct release prefixes are required;
- `primary_attempts` must be 720 and `fallback_attempts` 60;
- each kernel's `base.source` must be non-empty, and a Fedora base may not
  claim Ubuntu provenance.

An absent kernel lane is UNRUN, never a pass. A campaign that reaches rows for
two of the three kernels is an incomplete campaign, not a two-kernel campaign.
