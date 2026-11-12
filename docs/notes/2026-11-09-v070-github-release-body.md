<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v0.7.0 GitHub release body — DRAFT (owner edits before posting)

> Draft for the GitHub release page. Concise by owner rule; every claim
> below is merged on the draft base (`346d2c875`) and sourced in
> `CHANGELOG.md`, `docs/` or the tree. Unmerged lane claims from
> `task/v070-relnotes` (launcher chain, 10k key-ops rate, threaded exact
> totals, whole-table forwarding watch, sudo stdio keeps, drain-order
> system fix, perf numbers) are deliberately absent; add them only if
> they land before the cut. Body shape follows `RELEASING.md` step 7.3.
> Quickstart verified 2026-11-12 on a `346d2c875` release build (dev
> host lu26, kernel 7.0.0-38-generic): `doctor` exit 0 in 11.62 s
> ("capture available"); `inventory --system --duration 15s` exit 0
> (honest PARTIAL on the loaded host: 191 callers, 159 gaps);
> `profile --pid 1 --duration 30s` exit 0 (honest empty result,
> JSON written).

---

## p11scope v0.7.0 — [publication date]

Find which running Linux applications use PKCS#11 providers, then inspect
their observed calls, errors, latency and bounded metadata — without
replacing the provider or changing each application's configuration.

v0.7.0 answers "which program called my token?": callers running under an
interpreter now carry an app label (`python3 [backup.py]`,
`java [app.jar]`), so the answer names the application, not just the runtime.

What is new vs 0.6.0:

- App labels name the script, module or jar behind interpreter callers
  (`python3 [backup.py]`, `java [app.jar]`); display-only, never identity.
- `inventory --event-log -` streams the JSONL observation events to
  stdout, and `--event-interval <dur>` adds periodic `totals` snapshots.
- Container image `ghcr.io/mingulov/p11scope:0.7.0` for one-host Docker
  use and the Kubernetes DaemonSet (tag appears at publish).
- Linux 7.4-rc1 joins the BPF kernel matrix (6.6–7.3 plus 7.4-rc1).
- New real-client coverage: OpenSSL PKCS#11 clients, pkcs11-tool in the
  privileged campaign, pkcs11-spy forwarding at system scale.
- Docs pack: troubleshooting page, real first-run output, "why not just
  pkcs11-spy?", a tested provider/application list, and a concise front page.

Known issues: [CHANGELOG entry](https://github.com/mingulov/p11scope/blob/v0.7.0/CHANGELOG.md)
(currently the v0.6.0 list; the v0.7.0 list lands at the cut).

Install (bundles, DEB/RPM, helpers and source export under this tag):

```sh
download_dir=$(mktemp -d /var/tmp/p11scope-install.XXXXXX)
cd "$download_dir"
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/p11scope-0.7.0-x86_64-linux-musl.tar.gz
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf p11scope-0.7.0-x86_64-linux-musl.tar.gz
sudo install -m 0755 p11scope-0.7.0-x86_64-linux-musl/p11scope /usr/local/bin/p11scope
```

Quickstart (verified on the release line; [full version](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/usage.md#quickstart)
sets up a throwaway SoftHSM token in about two minutes):

```sh
sudo p11scope doctor
sudo p11scope inventory --system --duration 15s
sudo p11scope profile --pid <PID> --duration 30s -o diagnostic-profile.json
```

(`doctor` loads its BPF preflight on every run, so expect about 10 s with
no interim output; that is normal. Replace `<PID>` with a real process id.)

Verify downloads with `SHA256SUMS` (it covers the four archives plus
`RELEASE.json`); every release file carries a GitHub build-provenance
attestation. The tag is annotated.

- Full changes: [CHANGELOG](https://github.com/mingulov/p11scope/blob/v0.7.0/CHANGELOG.md).
- Docs: [operator's guide](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/usage.md),
  [install](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/install.md),
  [overview](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/overview.md).
- Verification: [v0.7.0 record](https://github.com/mingulov/p11scope/blob/main/docs/releases/v0.7.0.md)
  (CI runs, receipt and artifact hashes; recorded at qualification).
