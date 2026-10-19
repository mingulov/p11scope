<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Package recipient checklist (G25 installed artifact acceptance)

Clean-context verification of the official release assets. Run against the
final candidate's `*-public-assets` directory; record every command,
binary SHA-256, and outcome. Adapted from RELEASING.md steps 5-6; version
numbers below are placeholders for the v0.4 values T11 sets live.

## 0. Inputs present

- [ ] Receipt root with `facts.log` (`terminal_status` 0,
  `checker_status` 0, `head` == candidate SHA), `stdout.log`,
  `stderr.log`, `artifacts/`, `work/dist/` holding `p11scope`,
  `p11scope-discover-glibc`, `p11scope-discover-musl`,
  `p11scope-discover`.
- [ ] Public assets: three versioned `.tar.gz` (observer musl, discover
  gnu, discover musl), source tarball, top-level `RELEASE.json`,
  `SHA256SUMS`. glibc and musl helpers remain separately labeled.

## 1. Ledger and provenance

```sh
(cd <public-assets> && sha256sum --check SHA256SUMS)
python3 -c "import json;print(json.load(open('<public-assets>/RELEASE.json'))['schema'])"
sha256sum <receipt>/work/dist/p11scope*   # bind bytes to every later lane
```

- [ ] `SHA256SUMS` verifies all four archives + `RELEASE.json`.
- [ ] `RELEASE.json` provenance matches the receipt (builder, toolchains,
  source SHA); no private receipt paths leak into public metadata.

## 2. Per-archive clean extract

```sh
rx=$(mktemp -d /var/tmp/p11scope-recipient.XXXXXX); chmod 700 "$rx"
for a in <public-assets>/*.tar.gz; do
  d="$rx/$(basename "$a" .tar.gz)"; mkdir -m 700 "$d"
  tar --same-permissions --no-same-owner -xzf "$a" -C "$d"
  find "$d" -printf '%m %y %p\n' | sort
done
```

- [ ] One same-named top-level directory per archive; executable named
  `p11scope` / `p11scope-discover` mode `0755`; license texts + `notices/`
  + `RELEASE.json` present; member set exactly as intended.

## 3. Executable smoke (right binary, right host)

```sh
"$rx"/<observer-dir>/p11scope --version
"$rx"/<observer-dir>/p11scope --help | head -20
file "$rx"/<observer-dir>/p11scope        # static / static-pie, no interpreter
ldd "$rx"/<observer-dir>/p11scope 2>&1    # "statically linked" / "not a dynamic executable"
file "$rx"/<gnu-dir>/p11scope-discover    # dynamically linked, glibc
```

- [ ] Version/help/provenance answer from the EXTRACTED bytes (record the
  executed absolute path; `test_release_recipient_uses_selected_binary`
  automates this once implemented — GAP C8).
- [ ] musl dynamic helper smoke runs on a compatible musl host/container;
  archive inspection still happens on the build host.

## 4. Installed journeys on packaged bytes

- [ ] G14 applicable RSA ledger journey, G20 applicable E16 journey, G22
  applicable all-mode journey — each against the extracted observer +
  matching libc helper, with nonempty expected labels and false-name
  twins where applicable. A lane that builds its own binary stays source
  qualification.

## 5. Refusal twins (actionable, not silent)

- [ ] Wrong libc helper, missing dependency, changed package input each
  produce the documented actionable refusal (record stderr + exit code).

## 6. Source recipient

```sh
src=$(mktemp -d /var/tmp/p11scope-source-recipient.XXXXXX)
tar --same-permissions --no-same-owner -xzf <source-tarball> -C "$src"
(cd "$src/p11scope-source" && python3 -I scripts/prepare-dependencies.py --offline)
# then the pinned-toolchain release build per RELEASING.md step 6
```

- [ ] Included Aya archives reconstruct without downloading them; the
  recipient build uses pinned toolchains; remaining locked-dependency
  fetches are expected (schema-v1 export is not full offline).
