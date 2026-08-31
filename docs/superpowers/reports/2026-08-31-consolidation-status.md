# Consolidation and release status

Updated: 2026-09-01

## Decision

The local MVP is runtime-qualified, but the project is not ready for a public
release. Jammy 5.15 and Noble 6.8 passed the same six-row semantic, privacy,
and cleanup campaign. Fedora 44 kernel 6.19 then passed the exact
`1d3837b` workspace, core capture, initial-export, inspect/doctor, privacy, and
SELinux-Enforcing portability gates. The exact `3e10be9` static security
review's high owned-child finding is closed; lower-severity release follow-ups
remain open.

`main` is the only authoritative product tree. Merge `4b626c38` makes the
seven unique diagnostic/productization worktree tips reachable from `main`
with an unchanged product tree. Accepted code was already integrated normally;
experimental and rejected trees remain history, not product contents.

## MVP versus release

- MVP: implemented and locally runtime-qualified on kernels 5.15 and 6.8; the
  narrower post-MVP portability smoke passed on Fedora 44 kernel 6.19.
- Host observation: implemented and evidenced.
- Docker/kind/Knative: implemented with historical accepted evidence; not
  rerun on the exact final candidate.
- Packaging: static safe-only observer and local glibc discover builds pass;
  the complete privileged/container release receipt is not yet accepted.
- Security: exact-candidate static scan complete; the high owned-child finding
  is remediated and independently accepted, with lower-severity remediation
  pending.
- Fedora/SELinux: exact `1d3837b` product evidence passed with SELinux
  `Enforcing`; see the
  [Fedora report](2026-09-01-fedora44-selinux-evidence.md).
- CI/publication: exact-tip hosted CI, push, tag, and release are not
  performed.

The historical 9.2d/9.3/9.4 high-volume campaign is post-MVP hardening. Its
UNRUN state is preserved; it does not erase the accepted six-row MVP result.

## Next order

1. Refresh the complete portable `main` bundle and finite evidence archive.
2. Fix the release-relevant cgroup, bounded-scan, output, and build-receipt
   controls with focused tests.
3. Rerun exact-tip hosted CI and the complete release receipt.
4. Refresh container/Kubernetes evidence only for release qualification.

Raw VM/security artifacts stay outside Git under mode-restricted evidence
roots. The `90a03ac` portable archive below is a preserved predecessor, not
the current transfer package. A refreshed complete `main` bundle and finite
evidence archive must be generated after this status commit; its adjacent
checksum file is authoritative because an archive cannot contain its own
final hash.
