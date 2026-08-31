# Consolidation and release status

Updated: 2026-08-31

## Decision

The local MVP is runtime-qualified, but the project is not ready for a public
release. Jammy 5.15 and Noble 6.8 passed the same six-row semantic, privacy,
and cleanup campaign. The exact `3e10be9` static security review then found a
release-blocking owned-child privilege boundary plus eight lower-severity
follow-ups.

`main` is the only authoritative product tree. Merge `4b626c38` makes the
seven unique diagnostic/productization worktree tips reachable from `main`
with an unchanged product tree. Accepted code was already integrated normally;
experimental and rejected trees remain history, not product contents.

## MVP versus release

- MVP: implemented and locally runtime-qualified on kernels 5.15 and 6.8.
- Host observation: implemented and evidenced.
- Docker/kind/Knative: implemented with historical accepted evidence; not
  rerun on the exact final candidate.
- Packaging: static safe-only observer and local glibc discover builds pass;
  the complete privileged/container release receipt is not yet accepted.
- Security: exact-candidate static scan complete, remediation pending.
- CI/publication: exact-tip CI, push, tag, and release are not performed.

The historical 9.2d/9.3/9.4 high-volume campaign is post-MVP hardening. Its
UNRUN state is preserved; it does not erase the accepted six-row MVP result.

## Next order

1. Fix the owned-child privilege boundary.
2. Fix the release-relevant cgroup, bounded-scan, output, and build-receipt
   controls with focused tests.
3. Rerun exact-tip local gates, CI, and the complete release receipt.
4. Run the approved Fedora QEMU portability smoke with SELinux `Enforcing`.
5. Review the remaining lower-severity findings and continue from `main`.

Raw VM/security artifacts stay outside Git under mode-restricted evidence
roots. A checksummed portable archive and Git bundle accompany this record;
their adjacent checksum manifest is authoritative because an archive cannot
contain its own final hash.

- archive: `/home/user/.local/state/p11scope/pkcs11-scope-portable-90a03ac.tar.zst`
- archive SHA-256: `e4d6cf6294d7717c5b89cd38bec3a608e1fc8d8696a3f86f074a6bbcb4c2d6cf`
- complete `main` bundle SHA-256: `a08004436f85f1e14517c9a68ec756d319e2b6e4bbdfa5e98d5678895685785d`
- internal manifest SHA-256: `b9f8f6171d0820b9a8e98def82ba804000bf174a6cf5ff1c04e6fdc69ea0ea71`
