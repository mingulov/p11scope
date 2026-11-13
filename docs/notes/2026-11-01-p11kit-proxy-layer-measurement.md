<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# p11-kit proxy-layer coverage measurement (2026-11-01)

p11-kit admission measurements, task 3. Measurement only; the 512 / 8192 /
16384 engineering limits are unchanged (held fixed for this measurement).

## Method

A scratch one-line build relaxed the shared-scope reserve for closure
arrays only (`reserved = shared && leaves_reserve && class !=
ClosureArray`), so one whole array fits at `inventory --system
--max-endpoints 8192`. The scratch was never committed and is reverted;
the worktree is clean and the release binary matches the fixed commit.
Base binary: the lane's fixed observer (rev `80379634f`).

Hosts: Ubuntu, kernel 7.0, p11-kit 0.4.8 (load ~10, noisy); Fedora,
kernel 7.2.9, p11-kit 0.4.11 (load ~2). Both attach via `uprobe-multi`.

## Per-copy demand and identities

- One libp11-kit copy decodes 67 lookalike tables and needs 6,734 attach
  slots (0.4.8 and 0.4.11 identical here).
- The snap gnome-platform 0.4.5 copy needs 5,966 slots.
- Backends on the Ubuntu host: opensc 105, p11-kit-trust 68, softhsm 68
  (241 total).
- Distinct libp11-kit identities: 3 on Ubuntu (host 0.4.8 on dev 0:35,
  the same bytes on dev 7:6, snap 0.4.5), 1 on Fedora (0.4.11).

## Attach time

The native lane attaches about 512 endpoints per pass (exact -512/pass
drain observed in the deferred-endpoint gaps on both hosts). A 6,734-endpoint
array needs about 14 passes to attach fully:

- Ubuntu, 45 s window, 9 passes: admitted 6,975 (array + backends),
  attached 4,608 (68%), 2,126 still deferred at close.
- Fedora, 49 s window, 25 passes: admitted and attached all 6,826.
- First-pass plan+attach increment for the array (uprobe-multi batch):
  about +100-170 ms for 6,734 endpoints (~15-25 us/endpoint, single
  samples under load). For contrast, the run path attaches about 480
  endpoints in about 900 ms (~1.9 ms/endpoint, different mechanism).
- Elapsed: 49.0 s base vs 49.7 s scratch (Ubuntu); 49.1 s vs 50.0 s
  (Fedora). The array adds under a second to a 49 s run.

## Observer RSS

`/usr/bin/time -v` maximum RSS: Ubuntu 204 MB base vs 204 MB scratch;
Fedora 110 MB vs 110 MB. No measurable delta; RSS is scan-state
dominated, not endpoint dominated.

## Per-call overhead (proxy-heavy workload)

`pkcs11-tool --module p11-kit-proxy.so -L -M -O`, 10x loop, 5 samples
(each sample = 10 tool runs, about 880 template-side + 860 backend-side
calls per sample):

- Native (no observer): about 113 ms per tool run.
- Under base inventory (about 300 backend probes): about 143 ms per run
  (+30 ms presence cost from the concurrent system scan load itself).
- Under scratch inventory (about 3,000 live template probes plus
  backends): about 132 ms per run, indistinguishable from base (delta
  within the +-20 ms run-to-run noise under load 10).

Cold template probes cost nothing observable; the 88 warm template hits
per run are immeasurable against the scan-load noise.

## Template vs backend fraction

Same target, same args; before = template-side counts (proxy admitted
as a prefix, backends dark), after = backend-side counts (proxy refused
whole, backends admitted):

| workload | template side | backend side | template share |
|---|---|---|---|
| trust list, full (Fedora) | 10 | 3,184 | 0.3% |
| trust list, ca-anchors (local, --module) | 6 | 744 | 0.8% |
| certutil -L (Fedora) | 11 | 88 | 11% |
| p11tool --list-tokens (Fedora) | 43 | 53 | 45% |
| pkcs11-tool -L -M -O (local) | 88 | 86 | 51% |

Data-heavy workloads land almost entirely on backends; proxy-management
calls (slot/token enumeration on the proxy module itself) always land on
the templates. An independent OpenSC `pkcs11-spy` ledger between p11-kit
and p11-kit-trust counted 744 calls for the local ca-anchors workload,
exactly matching the observer's `--module` count.

## What limits 1, 2 or 3 copies would need

Demand = copies + 241 backend endpoints. The standard reserve is 25% of
the limit; "relaxed" means the closure array may use the reserve.

| copies here | demand | 8,192 standard | 8,192 relaxed | 16,384 standard | 16,384 relaxed | 32,768 standard |
|---|---|---|---|---|---|---|
| 1 (6,734) | 6,975 | no (6,144) | yes (measured) | yes (12,288) | yes | yes |
| 2 (13,468) | 13,709 | no | no | no (12,288) | yes (16,143) | yes |
| 3 (19,434 incl. snap 5,966) | 19,675 | no | no | no | no (16,143) | yes (24,576) |

(Usable slots in parentheses.) One copy fits 8,192 only with the
reserve relaxed, or 16,384 as-is. Two copies need 16,384 relaxed or
32,768 as-is. All three copies on the Ubuntu host need 32,768 either
way. No limit change was made; this table is the input for the owner's
decision.
