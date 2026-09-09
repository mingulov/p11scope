# Build a full source export offline

The full source export contains the complete Cargo dependency payload but does
not contain Rust toolchains or operating-system build tools. Install Rust 1.88,
`nightly-2026-05-20` with `rust-src`, `bpf-linker`, Clang/LLVM, the native C
toolchain, Python 3, Git, and ordinary POSIX shell/archive tools before the
machine is disconnected. `rustup` and `bpf-linker` must be in the same
canonical executable directory.

Extract the full export, change to its top-level directory, and choose a new,
canonical absolute work path outside the extracted tree:

```sh
sh scripts/build-offline.sh /absolute/new/private-work
```

The work path may contain spaces but must not contain `:`, because it forms the
first entry in the build-only executable search path.

The bootstrap refuses inherited Cargo source/build settings, Rust wrappers and
flags, compiler overrides, prepared-build variables, small-map settings, and
competing Cargo configuration files. It selects the installed stable and
nightly tools with rustup auto-install disabled, creates a fresh private Cargo
home and target, verifies and reconstructs the embedded payload, and calls the
fixed prepared product build with locked and offline behavior. It repeats the
source, payload, recipe, configuration, prepared-tree custody, and tool checks
after the build. The verified prepared trees and their stable lock remain in
the extracted source so a later invocation can reuse them without repair.

On success, the target is under `WORK/target` and the deterministic audit
record is `WORK/evidence/build-offline.json`. The record contains tool and
input digests and the fixed logical build command. It contains no source-export
producer path or timestamp. A failed invocation removes only the fresh private
work root it created; an existing path is always refused and preserved.
