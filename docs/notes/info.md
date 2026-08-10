# My reassessment: yes, but it should not be merely a “PKCS#11 tracer”

This is a **strong idea**, and it fits `pkcs11-lab` extremely well. But the valuable product is not:

> “Print every call to `C_Sign` using eBPF.”

That would be an interesting demonstration, but not much more sophisticated than a PKCS#11-aware `bpftrace` script.

The worthwhile product is:

> **A non-interposing PKCS#11 workload profiler and diagnostic observer that discovers the real function table used by an application, records safe semantic metadata, and converts it into migration and compatibility evidence.**

I would call the standalone component **`pkcs11-observe`**, with `pkcs11-lab` consuming its output.

## Three important corrections to the previous analysis

### 1. Transparent, not “absolutely invisible”

It can be completely transparent from the application's configuration perspective:

* no replacement PKCS#11 module;
* no `LD_PRELOAD`;
* no modified application;
* no wrapper in the cryptographic data path;
* potentially attachable to an already-running process.

But it is not literally invisible:

* uprobes add measurable execution overhead;
* the BPF programs and links are visible to sufficiently privileged host administrators;
* loading and attaching them normally requires host-level privileges or appropriate capabilities;
* kernel lockdown, container isolation, or security policy may prohibit them;
* an application deliberately looking for tracing could potentially detect timing or other effects.

So the honest claim is:

> **Zero application changes and no PKCS#11 interposition.**

Not “undetectable” or “zero overhead.”

### 2. Profile, not replay

The earlier phrase “capture and reproduce the workload” was too strong.

Real PKCS#11 execution depends on:

* session and object handles;
* pre-existing token objects;
* authentication state;
* stateful multipart operations;
* random outputs;
* application plaintext;
* signatures, wrapped keys and ciphertext;
* mechanism parameters containing nested pointers;
* concurrency and provider-specific state.

Capturing enough data for exact replay would be both dangerous and often impossible. You would risk recording precisely the material the tool must never collect.

The safe and realistic output is an **observed dependency profile**:

```text
Application was observed using:

C_SignInit + C_Sign
  CKM_RSA_PKCS_PSS
  hashAlg = CKM_SHA256
  mgf = CKG_MGF1_SHA256
  saltLen = 32

C_GenerateKey
  CKM_AES_KEY_GEN
  requested CKA_TOKEN = true
  requested CKA_EXTRACTABLE = false

C_GetAttributeValue
  requested CKA_KEY_TYPE
  requested CKA_MODULUS_BITS
  attempted CKA_VALUE -> CKR_ATTRIBUTE_SENSITIVE

Observed concurrency:
  14 simultaneous sessions
  8 simultaneous sign operations

Errors:
  CKR_DEVICE_ERROR: 7
  CKR_SESSION_HANDLE_INVALID: 2
```

That profile can select, prioritize and parameterize **synthetic** tests in `pkcs11-check`. It should not replay captured cryptographic inputs.

### 3. Syscall correlation is interesting, but not reliable enough for the core product

The earlier example:

```text
C_Sign
  -> sendmsg
  -> recvmsg
  -> CKR_OK
```

is valid only when the provider performs I/O synchronously on the same thread.

A network-HSM library may instead use:

* a background worker thread;
* persistent pooled connections;
* request queues;
* multiplexed RPCs;
* batching;
* asynchronous PKCS#11 3.2 operations.

In those cases, “network activity occurred while `C_Sign` was running” does not prove that the network event belonged to that call. This can become an experimental second-stage capability, but I would not make it part of the initial product claim.

---

# The technically distinctive part: function-table-aware tracing

The biggest problem is not argument decoding. It is finding the actual functions.

PKCS#11 applications commonly do this:

```c
C_GetFunctionList(&functions);
functions->C_Initialize(...);
functions->C_SignInit(...);
functions->C_Sign(...);
```

The calls are indirect. The provider may not expose convenient ELF symbols for every `C_*` function. It may export only the discovery entry points, strip its internal symbols, or return private implementation functions through the table.

PKCS#11 explicitly defines `C_GetFunctionList` as returning a structure containing pointers to all Cryptoki API functions. PKCS#11 3.x similarly provides `C_GetInterfaceList` and `C_GetInterface`; these discovery calls may be made before `C_Initialize`.

The good news is that uprobes do not fundamentally need symbol names. Linux can attach an entry probe or return probe to a **library path plus object offset**.

That enables a much better design.

## Recommended discovery method

```text
isolated discovery helper
        |
        | dlopen(provider.so)
        | C_GetFunctionList / C_GetInterfaceList
        v
function pointers
        |
        | map pointer -> executable mapping
        | calculate library path + ELF/file offset
        v
probe manifest
        |
        | attach PID/cgroup-scoped uprobes + uretprobes
        v
real unmodified application
```

The helper process would:

1. Load the provider module in a short-lived isolated process.
2. Call only the permitted discovery interfaces.
3. Read every returned function pointer.
4. Find the executable mapping containing each pointer.
5. Convert the runtime address into a file offset.
6. Record something like:

```json
{
  "api": "C_Sign",
  "object": "/opt/vendor/lib/libpkcs11.so",
  "offset": 942080,
  "interface": "PKCS 11",
  "version": "3.0"
}
```

7. Exit.
8. The main observer attaches to those offsets before launching or resuming the target.

This has several advantages:

* no dependency on debug information;
* no dependency on exported `C_Sign`, `C_Decrypt`, and similar symbols;
* ASLR does not matter because the probe is attached by object offset;
* tracing starts before the target's first PKCS#11 operation;
* the application continues to load the original provider directly.

A fallback live-discovery mode could watch the target's own `C_GetFunctionList` return and then attach dynamically. But that has a race: the application might call `C_Initialize` immediately after receiving the table. The isolated helper approach is therefore preferable when the module can safely be loaded independently.

## Edge cases that must be reported, not hidden

Some providers may return:

* pointers into another shared object;
* generated or anonymous executable memory;
* the same generic “unsupported” stub for several API entries;
* process-dependent dispatch thunks;
* functions differing between interfaces or versions.

These are manageable, but the report needs an explicit completeness section:

```text
Function-table entries:     68
Attached uniquely:          64
Aliased implementation:      3
Non-file-backed pointer:      1
Unobserved API entries:       1

Capture completeness: PARTIAL
```

If several logical PKCS#11 functions share one implementation address, an uprobe at that address cannot necessarily determine which logical table entry was called. That must be represented as an ambiguity rather than silently assigning the call to one function.

---

# What practical problem does it solve?

## 1. Black-box PKCS#11 diagnostics

This is the clearest immediate use case:

> “This application intermittently fails against our HSM. What is it actually doing?”

The observer can show:

* PKCS#11 calls and return codes;
* latency distributions;
* slow and stalled calls;
* calls per process, thread, container and cgroup;
* current and peak concurrency;
* session open/close balance;
* initialization/finalization behavior;
* login/logout frequency;
* repeated object searches;
* retry storms;
* errors following provider restart;
* which caller address or user stack initiated an operation.

This is useful even without `pkcs11-check`.

## 2. Migration dependency discovery

This is the strongest integration with your current work.

`pkcs11-check` already positions itself as a broad active test client for validating providers and comparing behavior during migrations.

The passive observer answers:

> “Which subset and parameter combinations does our application actually depend upon?”

The active tester answers:

> “How does the candidate provider behave on those combinations?”

The final workflow should be closer to:

```bash
pkcs11-observe profile \
    --pid 12345 \
    --module /opt/vendor/lib/pkcs11.so \
    --output observed-profile.json

pkcs11-check test \
    --module /opt/candidate/lib/pkcs11.so \
    --output json \
    --output-file candidate/results.json

pkcs11-lab assess \
    --profile observed-profile.json \
    --results candidate/results.json
```

The assessment might classify requirements as:

```text
OBSERVED AND VALIDATED
  CKM_RSA_PKCS_PSS / SHA-256 / MGF1-SHA256 / saltLen 32

OBSERVED BUT CANDIDATE DIFFERED
  C_GetAttributeValue(CKA_ALWAYS_AUTHENTICATE)

OBSERVED BUT NOT COVERED BY CURRENT TEST CORPUS
  vendor-defined mechanism 0x80001042

CANDIDATE TESTED, NOT OBSERVED
  CKM_AES_GCM with 96-bit IV

UNKNOWN
  capture did not include disaster-recovery or key-rotation scenarios
```

That last category matters. A trace only represents the scenarios and time interval that were actually exercised.

I would therefore avoid a command named:

```bash
pkcs11-check test --workload ...
```

because it suggests replay. `assess-profile`, `validate-surface`, or a `pkcs11-lab assess` operation is more accurate.

## 3. PKCS#11-aware security observations

This can become valuable, but it should be evidence-oriented rather than presented as universal vulnerability detection.

Examples:

* `C_WrapKey` and `C_UnwrapKey` use;
* attempts to read `CKA_VALUE`, private exponents, secret values, or other sensitive attributes;
* requested creation of extractable keys;
* omitted or questionable key-policy attributes;
* use of legacy or organization-disallowed mechanisms;
* raw RSA operations;
* unexpected object creation or destruction;
* repeated authentication attempts;
* `C_SetAttributeValue` attempts affecting key policy;
* unusual calls from an unexpected process/container.

One subtle but important distinction:

```text
C_GenerateKey requested CKA_EXTRACTABLE = false
```

is valid.

```text
The generated key is non-extractable
```

is not necessarily justified merely by observing the input template. The provider may apply defaults, reject attributes, or produce different effective values. The observer can state what the application requested and, where safe, what was subsequently returned through `C_GetAttributeValue`.

---

# Privacy must be a foundational design property

A generic tracer that can dump arbitrary buffers would be actively dangerous around PKCS#11.

The default mode should never record:

* PIN contents;
* secret or private key material;
* `CKA_VALUE`;
* plaintext;
* ciphertext;
* signatures;
* wrapped-key blobs;
* random output;
* state blobs from `C_GetOperationState`;
* labels and object IDs unless explicitly enabled;
* arbitrary mechanism parameter byte arrays.

Even ostensibly harmless metadata needs judgment:

* PIN length can reveal policy information;
* labels can contain tenant or certificate identities;
* `CKA_ID` may be operationally sensitive;
* input lengths can expose message characteristics.

I would implement three strict capture levels:

| Mode      | Contents                                                                                        |
| --------- | ----------------------------------------------------------------------------------------------- |
| `metrics` | Function, return code, latency, concurrency                                                     |
| `profile` | Metrics plus mechanisms, safe parameter fields, safe attribute types and selected policy values |
| `debug`   | More call sequencing and caller information, still never raw secret-bearing buffers             |

There should be no unrestricted “dump every pointer” mode.

The parser must use an allowlist of fields, not a denylist. Malformed pointers and lengths must be treated as hostile input. Since the observer is privileged, its attack surface deserves the same care as a security agent.

---

# Two operating modes make more sense than one tracer

## Profile mode — default

Designed for longer captures:

* aggregate counts in BPF maps;
* calculate latency histograms;
* maintain error distributions;
* emit only anomalies and occasional samples;
* low event volume;
* suitable for migration profiling and production diagnostics.

## Trace mode — short investigations

Designed for a limited time window:

* one event per completed call;
* call sequencing;
* selected argument metadata;
* caller instruction pointer or stack ID;
* session and operation correlation;
* explicit sampling and rate limits.

A BPF ring buffer is appropriate for detailed events because it preserves temporal ordering across CPUs. However, reservations can fail when the buffer is full, so the observer must maintain and report loss counters rather than pretending the trace is complete.

---

# PKCS#11-specific state is where much of the value lives

A raw call list is insufficient. For example, `C_Sign` itself does not contain a mechanism. The mechanism arrived earlier through `C_SignInit`.

The observer needs a semantic state machine:

```text
process + module + session handle
    |
    +-- active sign operation
    |       mechanism
    |       mechanism parameters
    |       key handle pseudonym
    |       multipart/single-part
    |
    +-- active decrypt operation
    +-- active digest operation
    +-- login state observed
```

Then it can report:

```text
C_Sign latency for CKM_RSA_PKCS_PSS:
  p50  2.1 ms
  p95  4.8 ms
  p99 11.2 ms
```

rather than merely:

```text
C_Sign: 12,840 calls
```

Similarly, it can follow:

* `C_EncryptInit` → `C_Encrypt` or update/final;
* `C_FindObjectsInit` → find calls → final;
* `C_GenerateKeyPair` templates;
* session lifecycle;
* operation cancellation and failures.

Handles should remain internal pseudonyms scoped to process/module lifetime. Raw handle values should not normally be written to reports.

---

# Where it belongs in your project family

I would use this separation:

| Component         | Responsibility                                                            |
| ----------------- | ------------------------------------------------------------------------- |
| `pkcs11-check`    | Actively exercises and validates a provider                               |
| `pkcs11-observe`  | Passively observes real application behavior                              |
| `pkcs11-proxy-ng` | Controlled interposition, transport, isolation, fault injection and chaos |
| `pkcs11-lab`      | Combines profiles, test results, comparisons and migration assessments    |

This is particularly important because `pkcs11-check` now has an explicitly cross-platform story across Linux, Windows, macOS and expected FreeBSD support. An eBPF collector is inherently Linux-specific and introduces a completely different build, privilege, release and support model.

Therefore:

> **Part of the `pkcs11-lab` product concept, but a separate repository/binary from `pkcs11-check`.**

A shared versioned schema would be the integration boundary.

OpenSC's existing `pkcs11-spy`, by contrast, constructs its own PKCS#11 function table and forwards operations to a “real module”; it is explicitly an interposition library.  Your observer would occupy a clearly different architectural position.

---

# Three implementation approaches

| Approach                                                        | Assessment                                |
| --------------------------------------------------------------- | ----------------------------------------- |
| Attach to exported `C_*` symbols                                | Good proof of concept, inadequate product |
| **Discover `CK_FUNCTION_LIST` and attach by object offsets**    | **Recommended product architecture**      |
| Trace transport/syscalls and perform runtime security analytics | Useful later, too broad for v1            |

The decisive experiment is not “can an uprobe print `C_Sign`?” It obviously can when the symbol is available.

The decisive experiment is:

> **Can an isolated helper obtain a stripped provider's function table, map internal function pointers to stable object offsets, attach before application launch, and capture every controlled-harness call with no module substitution?**

If that succeeds across SoftHSM plus at least one stripped or unusually structured provider, the core technical thesis is validated.

---

# What I would put in v1

1. **Linux x86-64 only initially**, followed by AArch64. Avoid 32-bit compatibility until the model is proven.

2. **Explicit module path and target PID/command.** Do not attempt magical system-wide PKCS#11 module discovery in the first release.

3. **Function-table discovery**, covering legacy `C_GetFunctionList` and PKCS#11 3.x interfaces.

4. **Entry/return tracing for all discovered standard functions**, initially recording only function ID, timing and `CK_RV`.

5. **Semantic parsing for a deliberately small high-value group:**

   * mechanism-init functions;
   * session lifecycle;
   * login user type, never PIN;
   * object-search attribute types;
   * selected safe attributes in create/generate/unwrap templates;
   * wrap/unwrap/derive operations;
   * safe mechanism parameters such as RSA-PSS hash/MGF/salt length and GCM length metadata.

6. **Two outputs:**

   * live diagnostic summary;
   * versioned `observed-profile.json`.

7. **Explicit evidence quality:**

   * probe attachment failures;
   * aliased functions;
   * truncated templates;
   * unreadable pointers;
   * event loss;
   * capture start/end;
   * sampling configuration;
   * observed processes/modules/interfaces.

8. **Automated secret-canary tests.** Place known sentinel values in PINs, key material, labels, input buffers and mechanism blobs, then assert that no output file or event contains them.

9. **Overhead benchmark.** Compare unobserved, aggregate-profile, and full-trace modes. Do not advertise low overhead before measuring it.

I would leave the following out of v1:

* network syscall correlation;
* enforcement or call blocking;
* automatic replay;
* Kubernetes-wide discovery;
* GUI/dashboard;
* generic raw-buffer capture;
* a large collection of opinionated “security findings.”

---

# Overall verdict

**Yes, pursue it.** It is one of the more coherent additions to your PKCS#11 work:

```text
pkcs11-observe
    What does the real application depend on?

pkcs11-check
    How does this provider actually behave?

pkcs11-proxy-ng
    What happens under controlled faults and altered transport?

pkcs11-lab
    What does all that evidence mean for deployment or migration?
```

But the eBPF part alone is not the defensibility. The defensible value would be the combination of:

* function-table-aware observation;
* safe PKCS#11 semantic decoding;
* evidence completeness reporting;
* the real-workload profile format;
* mapping observations onto the existing `pkcs11-check` test corpus;
* accumulated provider quirks and migration knowledge.

A good one-sentence positioning would be:

> **Observe the real PKCS#11 dependency surface of a running Linux application—functions, mechanisms, errors, latency and safe policy metadata—without replacing its module or changing its configuration.**

I would freeze the initial purpose as **migration profiling plus incident diagnostics**, with security-policy observations layered on afterward.
