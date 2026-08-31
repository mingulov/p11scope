# OpenSSL Scope Feasibility — Non-interposing eBPF Observation

**Date:** 2026-08-26  
**p11scope baseline:** `9bdca40da9ec2384668fc227fb48bc3fab6f32e9`  
**Review:** Sol xhigh architecture investigation; official OpenSSL and Linux sources only; no runtime or privileged experiment.

## Executive verdict

**Conditional GO** for a separate Linux x86-64 observer that can provide:

- aggregate counts and latency for a selected public `libcrypto` API surface;
- lifecycle discovery of dynamically loaded OpenSSL providers;
- actual provider algorithm-dispatch calls when the observer sees provider initialization and subsequent operation-query results;
- separate OpenSSL 3.x and 4.x public-header catalogs;
- owned `run` workloads, plus explicitly partial external PID/cgroup/container observation;
- aggregate-only output keyed by pinned object identity and finite operation/function IDs.

**NO-GO** for a universal claim covering every already-initialized provider, built-in provider, static/LTO application, OpenSSL 3 ENGINE, or exact application-to-provider causality without cooperation.

The decisive unsupported path is:

```text
attach after provider initialization
  -> OSSL_provider_init return was missed
  -> dispatch pointers are already in opaque libcrypto state
  -> no public API exposes the stored dispatch table to an external observer
  -> recovery needs unstable libcrypto internals or heuristic memory scanning
  -> exact provider-operation coverage is unavailable
```

Stripping and ASLR are not root blockers. Once a public dispatch function pointer is observed, p11scope's existing pointer-to-mapping-to-pinned-file-offset machinery can attach without a symbol.

The provider table format is simpler than PKCS#11 because entries carry function IDs and algorithms carry metadata. The supported product is not necessarily simpler: built-in providers, fetch caching, dynamic table lifetimes, many operation ABIs, aliases, and ENGINE divergence make honest end-to-end coverage roughly comparable.

## Confirmed OpenSSL 3 facts

1. Providers may be dynamically loaded, built into libcrypto, or built into an application. Dynamic providers export `OSSL_provider_init`; built-ins may use another initialization name. The init signature exposes core-to-provider and provider-to-core dispatch tables. This is public provider ABI. [Provider documentation](https://docs.openssl.org/3.5/man7/provider/)

2. `OSSL_DISPATCH` is a public `{ function_id, function }` tuple terminated by `OSSL_DISPATCH_END`. Unknown IDs must be ignored, supporting version evolution. Function IDs and signatures are public in `openssl/core_dispatch.h`. [OSSL_DISPATCH](https://docs.openssl.org/3.5/man3/OSSL_DISPATCH/), [provider-base](https://docs.openssl.org/3.5/man7/provider-base/)

3. `provider_query_operation` returns `OSSL_ALGORITHM[]` for an operation ID. `no_store` and `provider_unquery_operation` make table lifetime dynamic; pointers cannot be treated as a permanent manifest. [provider-base](https://docs.openssl.org/3.5/man7/provider-base/)

4. `OSSL_ALGORITHM` exposes algorithm names, property definition, description, and an implementation `OSSL_DISPATCH *`. That implementation table is the main feasibility basis for observing actual provider calls. [OSSL_ALGORITHM](https://docs.openssl.org/3.5/man3/OSSL_ALGORITHM/)

5. EVP fetches may be explicit or implicit and are cached internally. Watching only public `EVP_*_fetch` calls cannot reconstruct all provider selections. [crypto(7)](https://docs.openssl.org/3.5/man7/crypto/), [OpenSSL 3.0 design](https://docs.openssl.org/master/OpenSSL300Design/)

6. Providers can be activated by configuration, explicit `OSSL_PROVIDER_load`, or fallback/implicit loading. The default provider is built into libcrypto and may activate automatically. [Configuration](https://docs.openssl.org/3.5/man5/config/), [provider APIs](https://docs.openssl.org/3.6/man3/OSSL_PROVIDER/), [default provider](https://docs.openssl.org/3.5/man7/OSSL_PROVIDER-default/)

7. ENGINE remains in OpenSSL 3 builds but is deprecated. ENGINE/METHOD callbacks are a different architecture and are not provider-dispatch aliases. [Migration guide](https://docs.openssl.org/3.5/man7/ossl-guide-migration/), [ENGINE APIs](https://docs.openssl.org/3.5/man3/ENGINE_add/)

8. Independent contexts can execute the same provider functions concurrently. Entry/return state must be keyed by at least task and attach cookie. [Thread safety](https://docs.openssl.org/3.5/man7/openssl-threads/)

### Stability classification

| Surface | Classification |
| --- | --- |
| Dynamic-provider `OSSL_provider_init` signature | Public ABI |
| `OSSL_DISPATCH`, `OSSL_ALGORITHM`, operation/function IDs | Public ABI within the major |
| Function addresses and file offsets | Per-build runtime facts |
| Built-in-provider initialization symbol | Not stable; no mandatory name |
| `ossl_provider_*`, fetch internals, provider object layout | Internal; reject as product hooks |
| Public EVP and `OSSL_PROVIDER_*` symbols | Stable within a major, semantically incomplete |
| Provider strings and pointers | Untrusted, bounded inputs only |

## OpenSSL 4 facts and unknowns

OpenSSL 4 is no longer prospective: 4.0.0 was released on 2026-04-14 and 4.0.2 on 2026-08-25. OpenSSL 4.1 is planned for October 2026. [Official downloads](https://openssl-library.org/source/), [roadmap](https://openssl-library.org/roadmap/)

- OpenSSL 4.0 still publicly documents `OSSL_provider_init`, `OSSL_DISPATCH`, `OSSL_ALGORITHM`, `provider_query_operation`, and operation-specific IDs. [provider(7)](https://docs.openssl.org/4.0/man7/provider/), [OSSL_DISPATCH](https://docs.openssl.org/4.0/man3/OSSL_DISPATCH/), [OSSL_ALGORITHM](https://docs.openssl.org/4.0/man3/OSSL_ALGORITHM/), [provider-base](https://docs.openssl.org/4.0/man7/provider-base/)
- OpenSSL 4 is a major release; compatibility with OpenSSL 3 is not guaranteed. Separate catalogs/build validation are mandatory. [Migration guide](https://docs.openssl.org/4.0/man7/ossl-guide-migration/), [versioning policy](https://openssl-library.org/policies/general/versioning-policy/)
- API and ABI are guaranteed within one major series. [Release strategy](https://openssl-library.org/policies/releasestrat/index.html)
- ENGINE symbols were removed from the OpenSSL 4 shared library. ENGINE observation can only be a separate 3.x lane. [ENGINE removal](https://openssl-library.org/post/2025-12-18-remove-engines/index.html)
- OpenSSL 4.0.2's default provider remains built in with an internal init function, confirming that generic dynamic-init observation cannot cover it. [Default-provider source](https://github.com/openssl/openssl/blob/openssl-4.0.2/providers/defltprov.c), [provider-core source](https://github.com/openssl/openssl/blob/openssl-4.0.2/crypto/provider_core.c)

OpenSSL's FIPS support policy has a special cross-release compatibility promise for supported validated FIPS modules. It is not a general provider ABI or libcrypto-internals promise. [FIPS module support policy](https://openssl-library.org/policies/general/fips-module-support-policy/)

Open questions include OpenSSL 4.1 implementation details, vendor operation IDs, `no_store` prevalence, anonymous/JIT function pointers, and provider functions residing in secondary DSOs.

## Proposed observability architecture

```text
application / libssl
      |
      | selected public EVP calls (process-level API counts)
      v
libcrypto
      | provider load/config/fallback lifecycle
      | provider_query_operation via observed dispatch pointer
      v
OSSL_ALGORITHM[]
  {names, properties, implementation -> OSSL_DISPATCH[]}
      |
      v
provider algorithm functions
  count + latency only; no call buffers or return-value payloads

OSSL_provider_init + ld.so lifecycle
      |
      v
observer userspace
  ProcessView -> maps -> runtime pointer -> opened/pinned object
  -> SHA-256/full identity -> ELF file offset -> deduplicated attach plan
      |
      v
eBPF uprobes
  PID/cgroup authorization -> private bounded discovery ring
  -> generic entry/return aggregate maps
      |
      v
osslscope observed-profile/v1
  aggregate-only, monotonic PARTIAL, no raw pointers
```

Capture-private ownership should bind a provider generation to process generation, provider object identity, the observed `OSSL_CORE_HANDLE`, and initialization sequence. Provider contexts, dispatch addresses, and cookies never enter output. Multiple semantic claims sharing one `{object, offset}` must share one physical probe and publish an explicit alias group.

`no_store=1`, changed query results, unload/remapping, and unresolvable pointers produce new generations or explicit loss. Detach cannot prove cross-CPU quiescence, so final output remains `PARTIAL` under the same terminal-drain contract as p11scope.

## Design options

| Option | Coverage | Stability | Main risk | Complexity |
| --- | --- | --- | --- | --- |
| Public provider/libcrypto boundaries | Explicit load/unload/init and selected public APIs | High within a major | Misses config/autoload internals and direct dispatch calls | Low |
| Recover provider dispatch tables | Actual dynamic-provider query and algorithm calls | Public table layout; lifecycle-sensitive | Missed initialization, `no_store`, aliases, built-ins | Medium-high |
| EVP/fetch API observation | Process-level API/fetch surface | Public API | Cannot prove selected provider; implicit fetch/cache | Medium |
| Upstream USDT points | Exact semantic lifecycle if accepted | Potentially best | Requires upstream adoption and deployment support | External dependency |
| Loader audit only | Provider DSO load/unload/object facts | Stable ELF/loader basis | Loaded does not mean used | Low |
| tracefs uprobes | Fixed path/offset hits | Kernel interface | No native BPF scope/privacy/loss model; not a real privilege reduction | Poor fit |
| raw tracepoints | Kernel exec/exit lifecycle | Kernel-event-specific | Cannot observe provider functions | Supporting only |

Recommended composition: dispatch-table recovery plus loader audit, with a deliberately small public-EVP lane. Add upstream USDT only if experiments prove the non-cooperative lifecycle gap is materially limiting.

## Recommended MVP

1. Linux x86-64; dynamically linked OpenSSL 3.5 LTS and OpenSSL 4.0.
2. Owned `run` first; external PID/cgroup observation explicitly partial.
3. Dynamic providers whose `OSSL_provider_init` is observed:
   - retain init inputs/outputs only as bounded private state;
   - read the base dispatch and attach `provider_query_operation`;
   - read bounded `OSSL_ALGORITHM` and implementation dispatch arrays;
   - resolve each executable pointer to a pinned file and file offset.
4. One generic provider entry/return pair for aggregate count/latency only.
5. Known operation/function IDs map to finite labels; unknown values become `other`.
6. Loader audit reports provider load/unload timing and gaps.
7. Start the public lane with digest fetch/init/update/final counts only.
8. Every missed lifecycle event, unsupported provider, alias ambiguity, bounded omission, collision, attach failure, and transport loss makes evidence monotonically `PARTIAL`.

Do not extract a generic observability framework before a second working consumer proves the shared boundary.

### Non-goals

- arbitrary already-running-provider recovery;
- exact built-in default-provider dispatch observation;
- static/LTO support;
- ENGINE callback reconstruction;
- provider-to-core upcalls in the MVP;
- any key, plaintext, ciphertext, digest input/output, random data, IV, nonce, signature, encoded key, password, property string, or `OSSL_PARAM` value;
- raw untrusted algorithm/provider strings;
- FIPS-approved/compliant claims;
- exact public-EVP-to-provider causality;
- Windows, macOS, AArch64, 32-bit, or cluster operator in the MVP.

## p11scope lessons

### Reuse

- retained-fd plus ELF-offset attachment;
- opened identity rather than pathname authority;
- full mount identity and SHA-256;
- one probe per `{object, offset}` with explicit aliases;
- PID/cgroup scope authorization before reads;
- owned-child-only pause for first-call gaps;
- separate discovery loss from call-event loss;
- bounded hostile tables and strings;
- monotonic `PARTIAL` and unproven terminal drain;
- overlay collapse reported as uncertainty;
- output/BPF-map canary scanning.

### Do not copy

- PKCS#11 positional/version-prefix table assumptions: OpenSSL tables are ID-tagged and per operation;
- session/slot/mechanism/template/object-handle semantics;
- `C_GetFunctionList` export-registry assumptions for built-in providers;
- an offline helper that initializes providers, which could trigger self-tests or hardware activity and would not prove the target's fetch state;
- static dispatch manifests as authority for later dynamic results;
- PKCS#11 return-code decoding across heterogeneous provider signatures;
- the p11scope schema itself.

## Security, privacy, and FIPS

- Scope authorization precedes every target-memory read.
- Every provider pointer is hostile.
- Cap provider-base entries, operation queries, algorithms per operation, implementation entries, and allowlist comparison length.
- Resolve function pointers only to retained file-backed executable mappings. Reject anonymous/JIT executable memory.
- Do not emit provider strings, property strings, pointers, contexts, buffers, or return values in the MVP.
- Entry overwrite, recursion, missing return, map pressure, ring loss, and detach failure remain distinct evidence.
- Publish and freeze policy/catalog maps before provider-operation attachment.
- Provider identity change is sticky and forces `PARTIAL`.
- Retain p11scope's private-temp, fsync, rename publication sequence.

The validated FIPS provider is the cryptographic module boundary. Uprobes do not modify its file or interpose, but they do instrument code and change timing. No reviewed source establishes that this is validation-neutral. [FIPS module guide](https://docs.openssl.org/master/man7/fips_module/), [3.0.9 security policy](https://openssl-library.org/source/fips-doc/openssl-3.0.9-security-policy-2024-01-12.pdf)

Default FIPS posture should therefore be audit-only outside the provider boundary. Provider-function probes require the deployment owner's compliance interpretation and potentially vendor/lab guidance. Never infer “FIPS approved” from call location.

## Capability and deployment matrix

| Environment | Plausible live lane | Typical hardened requirement | Verdict |
| --- | --- | --- | --- |
| Same-UID host PID | `CAP_BPF` + `CAP_PERFMON` where policy permits | `CAP_SYS_ADMIN`; proc access may need `CAP_SYS_PTRACE` | Supported after runtime probe |
| Docker target, observer on host | Host BPF/perf plus target proc/cgroup access | Often `CAP_SYS_ADMIN` + `CAP_SYS_PTRACE` | Node-local supported |
| Ordinary observer container | Usually insufficient | Host BTF/procfs and near-privileged authority | Not a default lane |
| Kind, observer on host | Same as Docker-host lane | Measured-host capability set | Experiment lane |
| Kubernetes DaemonSet | Node-local hostPID/BTF/procfs/cgroup | Often `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` | Later productization |
| Unprivileged application user | ELF/config inventory only | No reliable live eBPF lane | Audit-only |
| Static/LTO application | Per-binary inventory | No general stable dynamic boundary | Unsupported MVP |

Tracefs does not normally remove fundamental tracing privilege and loses the BPF-side scope/privacy policy. Raw tracepoints can support exec/exit lifecycle but cannot replace userspace uprobes. [Kernel uprobes](https://docs.kernel.org/trace/uprobetracer.html), [perf_event_open(2)](https://man7.org/linux/man-pages/man2/perf_event_open.2.html), [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

## Experiment plan

No privileged experiment was run for this report.

| Hypothesis | Expected | Decisive evidence |
| --- | --- | --- |
| Public EVP/provider symbols reconstruct actual provider use | False | Default/custom providers look identical without dispatch evidence |
| Observed dynamic init/query tables enable exact aggregate calls | Feasible | Counts match independent fixture oracle |
| Stripping breaks dispatch capture | False | Pointer-to-mapping offsets remain exact |
| ASLR/PIE breaks capture | False | Different addresses resolve to the same file offsets |
| Owned-run pause closes the first-call gap | To prove | First provider call after query is counted |
| External attach can be complete after initialization | False by design | Evidence remains partial |
| Built-in default provider is generically recoverable | Expected false | No dispatch without private layout/symbol |
| `no_store=1` changes are safe | To prove | Bounded generations; no stale attribution |
| Shared function pointers avoid double counting | To prove | One physical count plus explicit alias group |

### Fixtures

Use released OpenSSL 3.0, 3.5 LTS, 3.6, and 4.0.2. Build:

1. one dynamic provider exporting `OSSL_provider_init`;
2. one deterministic digest and independent call oracle;
3. `no_store=0` and `no_store=1`;
4. shared implementation pointers across names and function IDs;
5. implementation pointer in a secondary DSO;
6. explicit load/unload/reload;
7. config activation and implicit default activation;
8. `OSSL_PROVIDER_add_builtin` negative/partial case;
9. multithreaded EVP contexts and OpenSSL ASYNC;
10. stripped, LTO, and static negative fixtures;
11. hostile pointer/string canaries;
12. FIPS audit-only lane unless separately approved.

The smallest decisive test is one C provider exposing one digest through `OSSL_provider_init -> provider_query_operation(OSSL_OP_DIGEST) -> OSSL_ALGORITHM -> {NEWCTX, INIT, UPDATE, FINAL, FREECTX}`. A tiny EVP app performs one fetch and two digest operations.

Pass only when counts match exactly, latency is present, aliases do not double count, stripped/PIE offsets resolve, lifecycle generations are explicit, external attach never upgrades completeness, every induced loss forces `PARTIAL`, and canaries are absent from output/logs/BPF maps.

Fail the architecture if the dynamic-provider happy path needs private `ossl_*` symbols or layouts, calls provider/libcrypto functions, cannot close owned first use, double counts aliases, or requires rendering untrusted strings.

## Implementation roadmap

| Phase | Work | Acceptance |
| --- | --- | --- |
| O0 ABI decoder spike | Separate 3.x/4.x catalogs; bounded dispatch/algorithm decoder | No internal headers/layout; malformed tables fail closed |
| O1 Dynamic provider proof | Observe init, query, one digest implementation, aggregate entry/return | Exact smallest fixture on 3.5 and 4.0.2 |
| O2 Identity/lifecycle | Reuse ProcessView, retained fds, offsets, unload generations, aliases | Stripped/PIE/reload/secondary-DSO/external-partial lanes |
| O3 Privacy/completeness | Frozen catalogs, bounded `other`, loss/collision/terminal evidence, canaries | No sentinel leakage; all induced losses gate verdict |
| O4 Version/environment matrix | 3.0/3.5/3.6/4.0; host/Docker/Kind; thread/ASYNC/`no_store` | Fresh candidate evidence; no p11scope inference |
| O5 Small EVP surface | Digest fetch/init/update/final counts | Useful without provider-causality overclaim |
| O6 Product decision | Separate `osslscope` product/schema; extract only proven shared code | No OpenSSL concepts in PKCS#11 schema |
| O7 Optional cooperation | Propose semantic USDT points if measured gaps remain | Stable bounded payload proposal |

## Risks and open questions

Confirmed limitations:

- already-loaded providers hide dispatch behind opaque state;
- built-in default-provider init is not generically named;
- ENGINE cannot span OpenSSL 3 and 4;
- public fetch hooks cannot prove provider choice;
- static/LTO builds may have no stable public boundary.

Remaining uncertainty:

- closing every owned-child init/query/first-use race;
- real-world `no_store=1` and mutable algorithm frequency;
- alias prevalence and recursive calls;
- unload during in-flight callbacks;
- anonymous executable provider code;
- distro backports and symbol versions;
- software-provider probe overhead;
- FIPS compliance acceptance;
- value of OpenSSL's opt-in, often build-disabled text trace API. [Trace environment](https://docs.openssl.org/4.0/man7/openssl-env/), [trace API](https://docs.openssl.org/3.0/man3/OSSL_trace_set_channel/)

## Relative complexity

| Scope | Relative to p11scope |
| --- | --- |
| Provider inventory only | ~0.25x |
| One dynamic-provider digest proof | ~0.5x |
| Honest aggregate dynamic-provider MVP | ~0.8–1.2x |
| Supported 3.x/4.x host/container product plus EVP lane | ~1.0–1.5x |
| Universal built-in/static/ENGINE/FIPS product | Greater and not achievable through stable non-cooperative hooks |

The parser is simpler; lifecycle and the supported matrix are harder. The smallest worthwhile product is a dynamic-provider aggregate observer, not a universal OpenSSL call tracer.
