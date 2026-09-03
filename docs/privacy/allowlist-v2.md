# Privacy allowlist v2 — interface-selection evidence

This version extends [`allowlist-v1.md`](allowlist-v1.md); every v1 decoder,
exclusion, hostile-pointer rule, and offline inventory-name exception remains
unchanged. No arbitrary-buffer or secret decoder is added.

The observer and `p11scope inspect` make zero PKCS #11 calls. Only the explicit
offline `p11scope-discover` helper loads a provider and makes exactly ten
pre-initialization `C_GetInterface` calls. The observer never launches that
helper and never executes provider code.

## Newly allowed finite evidence

| Value | Source and guard | Public output |
| --- | --- | --- |
| Selection request | An observed standard or custom selection hook; bounded name bytes are classified by exact equality and immediately discarded. Version and flags are scalar fields. | Finite request name/version classes and u64 flags only. |
| Selection result | Only after a successful observed call or one of the helper's ten fixed queries; the returned interface is bounded-read and checked against the exact provider/view generation and mapped object. | Finite result name/version classes, u64 flags, CK_RV, agreement booleans, and authority class. Never bytes, pointers, addresses, cookies, process identity, or private table ids. |
| Selection inventory relation | Exact pointer/object/offset equality against a separately accepted caller-independent inventory surface. Name/version equality alone grants no authority. | At most 512 finite `{module, ordinal, kind}` surface records and at most 16 sorted surface references per tuple. |
| Selection aggregate | One capture-wide reducer with at most 16 distinct tuples; repeated equal tuples increment one saturating u64 count. | `evidence.interface_selection`; only the exact fields and enums in the v3 schema. |
| Attach mechanism | Successfully owned links, after attachment succeeds. | Sorted duplicate-free `evidence.attach_mechanisms`, a subset of `per-offset` and `uprobe-multi`. |
| Descendant/rebuild loss | Saturating userspace counters; no task, PID, generation, link, or timing identity crosses the render boundary. | `evidence.pid_descendant_gaps` and `evidence.multi_rebuild_gaps`. |

The existing offline exception remains narrow: `p11scope inspect` and an
explicit `p11scope-discover` inventory may display provider interface names
because they are discovery tools. Profile, metrics, trace lines, and terminal
trace evidence never publish those bytes. Unknown, unterminated, or aliased
bytes become only `other` or `unreadable`; even exact `PKCS 11` bytes are
discarded after classification.

Metrics remains `aggregate-only`, reads no selection arguments, and retains
the exact `pkcs11-scope/observed-profile/v2-metrics` shape. Individual trace
lines likewise gain no selection fields. All selection loss is reduced to the
bounded aggregate and `PARTIAL` verdict.

## Still prohibited

No new PIN, username, label, `CKA_ID`, key material, plaintext, ciphertext,
signature, random output, operation-state blob, arbitrary input/output buffer,
raw interface name, vendor name, pointer, address, table contents, PID/TID,
process generation, attach cookie, private binding id, or helper error string
may enter a public capture artifact or observer-owned map as selection
evidence. The v1 release canaries and their positive controls remain mandatory.
V2 additionally invokes observed `C_GetInterface` calls with unique secret,
unterminated-at-the-observer-bound, and hostile-alias name buffers, then scans
every output/log artifact and every observer-owned map for those exact bytes.
Closed-shape mutations reject the same bytes if injected as JSON fields.
