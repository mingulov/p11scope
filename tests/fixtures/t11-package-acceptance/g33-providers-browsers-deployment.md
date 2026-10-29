<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G33 runbook — real providers, browsers, deployment, concrete kernel lanes

No browser dependency is added to mandatory hosted CI. Base `fabbb0a4`.

## What exists (deployment + providers)

- Manifests: `deploy/k8s/` (`00-namespace.yaml`,
  `10-serviceaccount.yaml`, `20-daemonset.yaml`, `README.md`, `e2e/`),
  `deploy/Dockerfile.observer`, `deploy/Dockerfile.holder`,
  `deploy/holder-entry.sh`, `deploy/README.md`.
- Matrix lanes (confirm each CLI with `--help`/header before scheduling):
  `scripts/matrix/verify-docker.sh`, `verify-shared-layer.sh`,
  `verify-kind-pod.sh` (manifest-free; `P11SCOPE_BIN` reuses a prebuilt
  product; `P11SCOPE_KIND_CLUSTER` reuses a cluster),
  `verify-knative.sh` (preattached-provider cold-pod capture is the
  positive cell; node-wide late-provider discovery keeps its reproduced
  UNSUPPORTED/NON-PASS boundary — qualify it as a negative, never as a
  required positive without a separately reviewed change),
  `verify-proxy-stack.sh`, `scripts/kind-e2e.sh` + `kind-e2e-oracle.py`,
  `scripts/attach-pod.sh`, `scripts/verify-provider-matrix.sh`.
- Provider cells: real SoftHSM/OpenSC/available independent providers,
  multiple UIDs, p11-kit wrappers/forwarding/repeated interfaces, runtime
  namespace/deleted-memfd cases. Existing Docker shared layer, kind
  pod/attach-pod and Knative scale-from-zero cells get current installed
  scoped acceptance; cluster aggregation stays deferred.
- Kernel lanes: the release-matrix lanes in the G23 runbook; fixed
  6.1/6.6 runner enumeration is preserved (see G34 runbook).

## Exact commands (pattern; bind candidate + lane first)

```sh
# Harness self-tests before any live cell (unprivileged part):
sh scripts/matrix/verify-kind-pod.sh --help 2>&1 | head -20
# Live cells need authorized lanes + prebuilt candidate bytes:
P11SCOPE_BIN=/abs/path/to/candidate/p11scope sh scripts/matrix/verify-kind-pod.sh
# Knative / docker / shared-layer / proxy lanes follow their own headers;
# record binary SHA-256 with every result.
```

## Gaps for live T11 (load-bearing)

1. BROWSER HARNESS MISSING. No Firefox/NSS or Google Chrome application
   check exists anywhere in the product checkout at base: no script,
   doc, or qualification fixture (the only tree-wide "firefox" hits are
   incidental unit-test path strings in `src/discovery/noise.rs` and
   `src/inventory/present_tests.rs`; "chromium"/"chrome" have zero hits).
   G33 requires own fresh Firefox/NSS and Google Chrome profiles
   for the promised application checks: do not substitute Chromium for
   Chrome, do not infer PKCS#11 use from successful TLS, preserve strict
   failed Firefox counterexamples until explained, and confirm
   independently the provider activity each application actually
   exercises (controlled providers supply exact count ledgers where
   browsers cannot). Owner: controller dispatches a new D-lane harness
   (new disjoint files) or an explicit scope decision; this prep does not
   invent browser results.
2. Packaged 7.0 guest 12-cell public-command check: prepare it separately
   from H7 T1. The MT12 generated-guest machinery exists only as host-side
   coverage in `tests/python/test_release_matrix_contract.py`
   (`test_generated_guest_executes_mt12_exact_selectors_and_fails_bad_evidence`);
   the packaged-guest 12-cell gate on final bytes is still to run. Never
   treat three T1 loads as a 12-cell installed matrix, and never use a
   host result as a guest result.
3. Full advertised-kernel/backport/SELinux matrix with explicit current
   claim membership and actual capability-based backend results is open;
   unavailable hardware/software stays a named dependency, full Stage5
   stays owner-manual.
