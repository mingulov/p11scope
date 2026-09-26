<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Contributing to p11scope

## License

```text
Public license: GPL-3.0-or-later
BPF sources: GPL-2.0-only
Shared BPF/userspace ABI (crates/ebpf-common): GPL-2.0-only OR GPL-3.0-or-later
```

Userspace code, docs, and scripts are licensed under GPL-3.0-or-later
(see `LICENSE`); BPF programs are licensed under GPL-2.0-only
(see `LICENSES/GPL-2.0-only.txt`). The shared ABI crate `crates/ebpf-common`
is compiled into both the GPL-2.0-only BPF object and the GPL-3.0-or-later
observer, so it is offered under either license
(`GPL-2.0-only OR GPL-3.0-or-later`). Per-file SPDX tags state which applies
to each file.

## Contributions

```text
Contributions: CLA granting broad sublicensing/relicensing rights
```

By contributing, you agree that your contribution is made under the license
of the files you touch (above), and that you grant the project broad rights
to sublicense and relicense your contribution, including under future or
additional licenses. This grant is what allows the project to relicense
freely later; a sign-off alone does not grant it.

## How to sign

Add a `Signed-off-by:` trailer to each commit (`git commit -s`):

```text
Signed-off-by: Your Name <you@example.com>
```

The sign-off certifies that you wrote the contribution or otherwise have the
right to submit it under the terms above, and that you agree to the
contribution terms in this file.
