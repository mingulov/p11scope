# Attach-first protection versus loader timing catalogs

Date: 2026-08-19
Campaign: `a227dabe7ab0fb62eee6ec9cca1f4afbad46eb03`
Loader BPF: `0bc026b49db29f5e6beb220ca988b9a1da8af071c912109eab94bb6a9e74a877`
Frozen A/B BPF: `e4973fd03ffb4d24cd81ab6c84c395ad18c90e23e28ae782c48328f4fce8b069`

Task 8 ran 20 fresh children for each provider/pause configuration on the
host and Noble guest. An independent validator checked all 160 attempt rows,
the exact three-program verifier inventory, byte identities, private file
modes, lifecycle facts, and aggregate results.

| Environment | Provider | Pauses | Result | Attach gap min/median/max | Export-to-slot min/median/max | Constructor result |
| --- | --- | ---: | --- | --- | --- | --- |
| host 7.0 / glibc 2.39 | exported | 1 | 20/20 | 22.195/26.348/27.803 ms | n/a | observed 20/20 |
| host 7.0 / glibc 2.39 | exported | 2 | 20/20 | 81.173/89.278/109.259 ms | n/a | observed 20/20 |
| host 7.0 / glibc 2.39 | hidden | 1 | 20/20 negative control | 0.435/0.499/0.928 ms | 23.609/30.629/54.090 ms | escaped 20/20 |
| host 7.0 / glibc 2.39 | hidden | 2 | 20/20 | 53.247/61.514/72.544 ms | 32.311/36.170/46.055 ms | observed 20/20 |
| Noble 6.8 / glibc 2.39 | exported | 1 | 20/20 | 4.271/4.847/5.581 ms | n/a | observed 20/20 |
| Noble 6.8 / glibc 2.39 | exported | 2 | 20/20 | 21.610/31.478/41.932 ms | n/a | observed 20/20 |
| Noble 6.8 / glibc 2.39 | hidden | 1 | 20/20 negative control | 0.156/0.300/0.701 ms | 5.307/6.775/10.527 ms | escaped 20/20 |
| Noble 6.8 / glibc 2.39 | hidden | 2 | 20/20 | 23.448/32.310/40.491 ms | 5.095/5.596/6.870 ms | observed 20/20 |

Bounded conclusions:

- At the confirmed loader pause, offset-based attachment to exported symbols
  observed `C_GetFunctionList` return and all 104 relocated pointers before
  the constructor's PKCS#11 call in every attempt.
- Exported providers also received constructor-time entry coverage from their
  dynamic symbols with one pause.
- Attach-first alone cannot cover constructor calls through hidden table
  functions: the call escaped in all 40 one-pause attempts.
- A second owned pause at the export-return hook attached all 104 hidden table
  slots before the constructor call in all 40 attempts. Cleanup used the
  original pidfd; final pause-owner maps were empty.

Decision D3: do **not** run the relocation-witness/catalog matrix on the
critical path. It would qualify a ptrace-dependent scan at a loader hit, but
does not remove the hidden-table race. The measured two-pause protocol closes
that race without a loader-version catalog. Keep catalog work diagnostic and
conditional on a future requirement to avoid the second pause.

This is spike evidence, not shipped support. Production still needs the
live-discovery engine, dynamic slots, attach cookies, completeness/loss
evidence, and the explicit `run` pause policy.
