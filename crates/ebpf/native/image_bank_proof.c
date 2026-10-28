/* SPDX-License-Identifier: GPL-2.0-only */
/* Kernel-side image-bank proof prototype (Choice B feasibility).
 * Dispatcher + two bank slots behind owner-shaped program arrays; the
 * route word rides the START row (R0, no new map). Bank A reuses the
 * production image maps, bank B mirrors them with proof-owned copies;
 * the A and B cores are textual duplicates compared by the checker and
 * behaviorally by the twin cells. Proof-only; never selected by the
 * observer. Field offsets into CallStart are pinned by static asserts in
 * the Rust proof module and by check-image-bank-object.py. */
#include "image_identity.h"
#include "image_identity_query.h"

#define BANK_HASH 1
#define BANK_PROG_ARRAY 3
#define BANK_WRONLY 16

/* START value bytes owned by the proof (R0 route rides the row). */
#define BANK_ROUTE_OFF 88
#define BANK_MARKER_OFF 264
#define BANK_COOKIE_OFF 272
#define BANK_EXEC_OFF 280
#define BANK_START_SIZE 288
/* Route word: bit63 valid, bit62 bank slot, low 32 bits incarnation. */
#define BANK_ROUTE_VALID (1ULL << 63)
#define BANK_ROUTE_BANK (1ULL << 62)
#define BANK_ROUTE_INC_MASK 0xffffffffULL
/* Attribution faults: bit0 records a stale-incarnation query refusal. */
#define BANK_FAULT_INC_MISMATCH 1ULL
/* Query request row 0 carries the load's bank incarnations. */
#define BANK_ROW0_GENERATION 0ULL
#define BANK_ROW_INDEX_MASK 0x3ffULL
#define BANK_ROW_BANK_BIT 10
#define BANK_ROW_INCARNATION_SHIFT 11

/* The flip word (bank, incarnation) moves under admissions, so a bank
 * entry must never stamp it: each slot carries a fixed incarnation
 * written at prepare while the slot is empty or reclaimed, never
 * while live. The entry stamps fixed_inc[its slot]; only the
 * selecting paths read the flip incarnation (to validate it). */
struct bank_select {
    u64 bank;
    u64 incarnation;
    u64 fixed_inc[2];
};

/* Bounded select retries across a flip: a call racing one flip still
 * admits (into the current bank), while a torn or stale read never
 * mints a ref for the wrong bank. Flips are Session-serialized with
 * millisecond gaps, so four tries cover any realistic burst; past
 * the bound select refuses (BANK_NO_SLOT, no ref held), which the
 * cells' conservation asserts would catch as admitted+failures short
 * of the ledger. Unbounded retry would livelock under a flip storm
 * and the verifier needs the bound. */
#define BANK_SELECT_TRIES 4

struct bank_account {
    u64 admitted;
    u64 completed;
    u64 live;
    u64 faults;
    u64 obs_cookie;
    u64 obs_ip;
    u64 stash_cookie;
    u64 stash_ip;
    u64 cookie_failures;
    u64 seed_failures;
    u64 start_present;
    u64 start_insert_failures;
    u64 start_insert_errno;
};

struct bank_start_key {
    u64 pid_tgid;
    u32 slot;
    u32 pad;
};

struct bank_cookie_out {
    u64 cookie;
    u32 status;
};

struct bank_iter_meta {
    void *seq;
    u64 session_id;
    u64 seq_num;
};

struct bank_iter_task {
    struct bank_iter_meta *meta;
    struct task_struct *task;
};

_Static_assert(sizeof(struct bank_select) == 32, "select ABI");
_Static_assert(sizeof(struct bank_account) == 104, "account ABI");
_Static_assert(sizeof(struct bank_start_key) == 16, "start key ABI");
_Static_assert(sizeof(struct control) == 40, "control ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bank_select);
} BANK_SELECT SEC(".maps");

/* Per-bank in-flight refs: a selected-but-unadmitted call holds its
 * bank's word until it admits or backs out, and closed-zero for a
 * bank requires its word drained (a call between select and its
 * START insert holds no live ref and no row yet). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} BANK_GATE SEC(".maps");

/* The entry-owner program arrays live in the Rust roots
 * (`image_bank_proof.rs`): the Rust dispatchers tail-call through them
 * directly, so no context pointer crosses the global-call boundary.
 * Only the birth owner stays here, with its native dispatcher. */
struct {
    __uint(type, BANK_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u32);
} BANK_PROGS_BIRTH SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, u64);
} TASK_COOKIE_B SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct control);
} COOKIE_CTL_B SEC(".maps");

struct {
    __uint(type, BANK_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC | BANK_WRONLY);
    __uint(max_entries, IMAGE_IDENTITY_TICKET_LIMIT);
    __type(key, u64);
    __type(value, struct image_continuity);
} IMAGE_CONTINUITY_B SEC(".maps");

struct {
    __uint(type, BANK_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC | BANK_WRONLY);
    __uint(max_entries, IMAGE_IDENTITY_TICKET_LIMIT);
    __type(key, u64);
    __type(value, u64);
} IMAGE_TGID_INDEX_B SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, struct bank_account);
} IMAGE_BANK_ACCOUNT SEC(".maps");

/* Bank A reuses the production image maps; START and the keep-stack guard
 * live in the Rust roots. Cross-unit map references link by symbol. */
extern unsigned char TASK_COOKIE;
extern unsigned char COOKIE_CTL;
extern unsigned char IMAGE_CONTINUITY;
extern unsigned char IMAGE_TGID_INDEX;
extern unsigned char IMAGE_QUERY_REQUESTS;
extern unsigned char IMAGE_QUERY_CTL;
extern unsigned char START;

static long (*bank_update)(void *, const void *, const void *, u64) = (void *)2;
static long (*bank_delete)(void *, const void *) = (void *)3;
static long (*bank_tail_call)(void *, void *, u32) = (void *)12;
static u64 (*bank_ktime)(void) = (void *)5;
static long (*bank_seq_write)(void *, const void *, u32) = (void *)127;

static __always_inline void bank_increment(u64 *counter)
{
    if (*(volatile u64 *)counter != U64_MAX_VALUE)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline void bank_decrement(u64 *counter)
{
    __sync_fetch_and_sub(counter, 1);
}

/* Faithful port of the production ticket allocator over bank A's maps:
 * existing-cookie fast path, checked CAS issue, quota, creation-failure
 * fallback lookup, retry exhaustion. Control layout shared by prefix. */
static __always_inline struct bank_cookie_out bank_cookie_for_a(struct task_struct *task)
{
    struct bank_cookie_out result = { 0, COOKIE_STATUS_BAD_TASK };
    u64 *cell;
    struct control *control;
    u32 key = 0;

    if (!task)
        return result;
    control = bpf_map_lookup_elem(&COOKIE_CTL, &key);
    if (!control) {
        result.status = COOKIE_STATUS_NO_CONTROL;
        return result;
    }
    if (control->limit != IMAGE_IDENTITY_TICKET_LIMIT ||
        control->next_ticket > IMAGE_IDENTITY_TICKET_LIMIT) {
        bank_increment(&control->unavailable);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }
    cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
    if (cell) {
        if (*cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
        } else {
            bank_increment(&control->unavailable);
            result.status = COOKIE_STATUS_ZERO_CELL;
        }
        return result;
    }
#pragma unroll
    for (int attempt = 0; attempt < COOKIE_CAS_TRIES; attempt++) {
        u64 ticket = control->next_ticket;
        u64 observed;
        u64 proposed;

        if (ticket >= control->limit) {
            bank_increment(&control->unavailable);
            result.status = COOKIE_STATUS_QUOTA;
            return result;
        }
        observed = __sync_val_compare_and_swap(&control->next_ticket, ticket, ticket + 1);
        if (observed != ticket)
            continue;
        proposed = ticket + 1;
        cell = bpf_task_storage_get(&TASK_COOKIE, task, &proposed,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cell) {
            if (*cell) {
                result.cookie = *cell;
                result.status = COOKIE_STATUS_OK;
            } else {
                bank_increment(&control->unavailable);
                result.status = COOKIE_STATUS_ZERO_CELL;
            }
            return result;
        }
        cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
        if (cell && *cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
            return result;
        }
        bank_increment(&control->create_failures);
        bank_increment(&control->unavailable);
        result.status = COOKIE_STATUS_CREATE_FAILED;
        return result;
    }
    bank_increment(&control->retry_exhausted);
    bank_increment(&control->unavailable);
    result.status = COOKIE_STATUS_RETRY_EXHAUSTED;
    return result;
}

/* Bank B twin of the ticket allocator over the proof-owned maps. */
static __always_inline struct bank_cookie_out bank_cookie_for_b(struct task_struct *task)
{
    struct bank_cookie_out result = { 0, COOKIE_STATUS_BAD_TASK };
    u64 *cell;
    struct control *control;
    u32 key = 0;

    if (!task)
        return result;
    control = bpf_map_lookup_elem(&COOKIE_CTL_B, &key);
    if (!control) {
        result.status = COOKIE_STATUS_NO_CONTROL;
        return result;
    }
    if (control->limit != IMAGE_IDENTITY_TICKET_LIMIT ||
        control->next_ticket > IMAGE_IDENTITY_TICKET_LIMIT) {
        bank_increment(&control->unavailable);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }
    cell = bpf_task_storage_get(&TASK_COOKIE_B, task, (void *)0, 0);
    if (cell) {
        if (*cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
        } else {
            bank_increment(&control->unavailable);
            result.status = COOKIE_STATUS_ZERO_CELL;
        }
        return result;
    }
#pragma unroll
    for (int attempt = 0; attempt < COOKIE_CAS_TRIES; attempt++) {
        u64 ticket = control->next_ticket;
        u64 observed;
        u64 proposed;

        if (ticket >= control->limit) {
            bank_increment(&control->unavailable);
            result.status = COOKIE_STATUS_QUOTA;
            return result;
        }
        observed = __sync_val_compare_and_swap(&control->next_ticket, ticket, ticket + 1);
        if (observed != ticket)
            continue;
        proposed = ticket + 1;
        cell = bpf_task_storage_get(&TASK_COOKIE_B, task, &proposed,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cell) {
            if (*cell) {
                result.cookie = *cell;
                result.status = COOKIE_STATUS_OK;
            } else {
                bank_increment(&control->unavailable);
                result.status = COOKIE_STATUS_ZERO_CELL;
            }
            return result;
        }
        cell = bpf_task_storage_get(&TASK_COOKIE_B, task, (void *)0, 0);
        if (cell && *cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
            return result;
        }
        bank_increment(&control->create_failures);
        bank_increment(&control->unavailable);
        result.status = COOKIE_STATUS_CREATE_FAILED;
        return result;
    }
    bank_increment(&control->retry_exhausted);
    bank_increment(&control->unavailable);
    result.status = COOKIE_STATUS_RETRY_EXHAUSTED;
    return result;
}

static __always_inline int bank_cookie_valid(u64 cookie)
{
    return cookie && cookie <= IMAGE_IDENTITY_TICKET_LIMIT;
}

/* Faithful port of the leader-index publication over bank A's maps:
 * match, lost-invalidation check, NOEXIST insert, CAS-max converge.
 * Anomalies fail closed without production poison side effects. */
static __always_inline int bank_index_a(u64 tgid, u64 cookie)
{
    u64 *cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX, &tgid);

    if (cell && *(volatile u64 *)cell == cookie)
        return 1;
    if (bpf_map_lookup_elem(&IMAGE_CONTINUITY, &cookie)) {
        cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX, &tgid);
        if (cell && *(volatile u64 *)cell == cookie)
            return 1;
        return 0;
    }
    if (!cell) {
        long rc = bank_update(&IMAGE_TGID_INDEX, &tgid, &cookie, 1);

        if (rc && rc != -17)
            return 0;
        cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX, &tgid);
        if (!cell)
            return 0;
    }
#pragma unroll
    for (int i = 0; i < IMG_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)cell;
        u64 prior;

        if (!bank_cookie_valid(seen))
            return 0;
        if (seen == cookie)
            return 1;
        if (seen > cookie)
            return 0;
        prior = __sync_val_compare_and_swap(cell, seen, cookie);
        if (prior == seen)
            return *(volatile u64 *)cell == cookie;
    }
    return 0;
}

static __always_inline int bank_snapshot(struct image_continuity *record,
                                         u64 exec_id, u64 *sequence)
{
    u64 seq = *(volatile u64 *)&record->seq;
    u64 id;
    u64 state;

    if (!seq || (seq & 1))
        return 0;
    __asm__ __volatile__("" ::: "memory");
    id = *(volatile u64 *)&record->exec_id;
    state = *(volatile u64 *)&record->state;
    __asm__ __volatile__("" ::: "memory");
    if (*(volatile u64 *)&record->seq != seq || id != exec_id || state != IMG_READY)
        return 0;
    *sequence = seq;
    return 1;
}

static __always_inline int bank_write(struct image_continuity *record,
                                      u64 exec_id, int poison)
{
#pragma unroll
    for (int i = 0; i < IMG_CAS_TRIES; i++) {
        u64 seq = *(volatile u64 *)&record->seq;
        u64 old_id;
        u64 state;
        int valid;

        if (!seq || (seq & 1) || seq > (~0ULL - 2))
            break;
        if (__sync_val_compare_and_swap(&record->seq, seq, seq + 1) != seq)
            continue;
        __asm__ __volatile__("" ::: "memory");
        old_id = *(volatile u64 *)&record->exec_id;
        state = *(volatile u64 *)&record->state;
        valid = (state == IMG_READY || state == IMG_POISONED);
        if (valid && poison) {
            *(volatile u64 *)&record->state = IMG_POISONED;
        } else if (valid && exec_id > old_id) {
            *(volatile u64 *)&record->exec_id = exec_id;
            *(volatile u64 *)&record->state = IMG_READY;
        } else {
            valid = 0;
        }
        __asm__ __volatile__("" ::: "memory");
        *(volatile u64 *)&record->seq = seq + 2;
        return valid;
    }
    return 0;
}

/* Bank A seed. The proof loads are ungated by construction (only proof
 * roots run in a cell), so no CONFIG/coverage check applies here. */
static __always_inline int bank_seed_a(u64 tgid, u64 cookie, u64 exec_id)
{
    struct image_continuity *record;
    u64 sequence = 0;
    u64 *index;

    if (!tgid || tgid > 0xffffffffULL || !bank_cookie_valid(cookie))
        return 0;
    if (!bank_index_a(tgid, cookie))
        return 0;
    record = bpf_map_lookup_elem(&IMAGE_CONTINUITY, &cookie);
    if (!record) {
        struct image_continuity initial = { 2, exec_id, IMG_READY };
        long rc = bank_update(&IMAGE_CONTINUITY, &cookie, &initial, 1);

        if (rc && rc != -17)
            return 0;
        record = bpf_map_lookup_elem(&IMAGE_CONTINUITY, &cookie);
        if (!record)
            return 0;
    }
    if (!bank_snapshot(record, exec_id, &sequence)) {
        if (!bank_write(record, exec_id, 0) ||
            !bank_snapshot(record, exec_id, &sequence))
            return 0;
    }
    index = bpf_map_lookup_elem(&IMAGE_TGID_INDEX, &tgid);
    if (!index || *(volatile u64 *)index != cookie)
        return 0;
    return 1;
}

/* Bank B twin of the leader-index publication. */
static __always_inline int bank_index_b(u64 tgid, u64 cookie)
{
    u64 *cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX_B, &tgid);

    if (cell && *(volatile u64 *)cell == cookie)
        return 1;
    if (bpf_map_lookup_elem(&IMAGE_CONTINUITY_B, &cookie)) {
        cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX_B, &tgid);
        if (cell && *(volatile u64 *)cell == cookie)
            return 1;
        return 0;
    }
    if (!cell) {
        long rc = bank_update(&IMAGE_TGID_INDEX_B, &tgid, &cookie, 1);

        if (rc && rc != -17)
            return 0;
        cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX_B, &tgid);
        if (!cell)
            return 0;
    }
#pragma unroll
    for (int i = 0; i < IMG_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)cell;
        u64 prior;

        if (!bank_cookie_valid(seen))
            return 0;
        if (seen == cookie)
            return 1;
        if (seen > cookie)
            return 0;
        prior = __sync_val_compare_and_swap(cell, seen, cookie);
        if (prior == seen)
            return *(volatile u64 *)cell == cookie;
    }
    return 0;
}

/* Bank B twin of the seed. */
static __always_inline int bank_seed_b(u64 tgid, u64 cookie, u64 exec_id)
{
    struct image_continuity *record;
    u64 sequence = 0;
    u64 *index;

    if (!tgid || tgid > 0xffffffffULL || !bank_cookie_valid(cookie))
        return 0;
    if (!bank_index_b(tgid, cookie))
        return 0;
    record = bpf_map_lookup_elem(&IMAGE_CONTINUITY_B, &cookie);
    if (!record) {
        struct image_continuity initial = { 2, exec_id, IMG_READY };
        long rc = bank_update(&IMAGE_CONTINUITY_B, &cookie, &initial, 1);

        if (rc && rc != -17)
            return 0;
        record = bpf_map_lookup_elem(&IMAGE_CONTINUITY_B, &cookie);
        if (!record)
            return 0;
    }
    if (!bank_snapshot(record, exec_id, &sequence)) {
        if (!bank_write(record, exec_id, 0) ||
            !bank_snapshot(record, exec_id, &sequence))
            return 0;
    }
    index = bpf_map_lookup_elem(&IMAGE_TGID_INDEX_B, &tgid);
    if (!index || *(volatile u64 *)index != cookie)
        return 0;
    return 1;
}

static __always_inline struct bank_account *bank_account(u32 slot)
{
    if (slot > 2)
        return 0;
    return bpf_map_lookup_elem(&IMAGE_BANK_ACCOUNT, &slot);
}

static __always_inline u64 bank_route_make(u64 bank, u64 incarnation)
{
    u64 route = BANK_ROUTE_VALID | (incarnation & BANK_ROUTE_INC_MASK);

    if (bank)
        route |= BANK_ROUTE_BANK;
    return route;
}

/* Admission-failure causes, one bucket each in the bank account. Bad
 * tasks and ticket failures share the cookie bucket; the ticket
 * control keeps their finer cause (quota, creation failure, retry
 * exhaustion). */
#define BANK_FAIL_COOKIE 0u
#define BANK_FAIL_SEED 1u
#define BANK_FAIL_PRESENT 2u
#define BANK_FAIL_INSERT 3u

/* Count one admission failure, release the dispatcher's gate ref, and
 * report the status. Every p11_bank_enter_* failure path funnels here
 * so no lost call goes uncounted: the Rust side asserts admitted plus
 * the counted buckets equals the ledger calls. */
static __always_inline u32 bank_enter_fail(u32 slot, u32 cause, long rc, u32 status)
{
    struct bank_account *account = bank_account(slot);
    u32 gate_key = slot;
    u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

    if (account) {
        if (cause == BANK_FAIL_COOKIE)
            bank_increment(&account->cookie_failures);
        else if (cause == BANK_FAIL_SEED)
            bank_increment(&account->seed_failures);
        else if (cause == BANK_FAIL_PRESENT)
            bank_increment(&account->start_present);
        else {
            bank_increment(&account->start_insert_failures);
            account->start_insert_errno = (u64)rc;
        }
    }
    if (gate)
        bank_decrement(gate);
    return status;
}

/* Admission for the current leader on bank A: ticket, seed, full START
 * row (route, identity, zero marker), attribution. Exported for the Rust
 * slot root; the Rust side passes the already-read pid, attach cookie and
 * IP so this core needs no context pointer. Every failure funnels through
 * bank_enter_fail: it lands in one per-cause account bucket and releases
 * the dispatcher's gate ref. The route stamps this slot's fixed
 * incarnation, never the flip word's: a flip landing between select and
 * admission must not lend this bank an identity it never owned. */
u32 p11_bank_enter_a(u64 pid_tgid, u64 bank, u64 observed, u64 ip)
{
    struct task_struct *current = bpf_get_current_task_btf();
    struct task_struct *leader;
    struct bank_cookie_out out;
    struct bank_account *account;
    struct bank_start_key key;
    struct bank_select *select;
    u64 row[BANK_START_SIZE / 8];
    u64 incarnation;
    u64 exec_id;
    u32 select_key = 0;
    u32 slot = 0;

    if (!current || !current->group_leader)
        return bank_enter_fail(slot, BANK_FAIL_COOKIE, 0, COOKIE_STATUS_BAD_TASK);
    leader = current->group_leader;
    out = bank_cookie_for_a(leader);
    if (out.status != COOKIE_STATUS_OK)
        return bank_enter_fail(slot, BANK_FAIL_COOKIE, 0, out.status);
    exec_id = *(volatile u64 *)&leader->self_exec_id;
    if (!bank_seed_a((u64)(u32)leader->tgid, out.cookie, exec_id))
        return bank_enter_fail(slot, BANK_FAIL_SEED, 0, COOKIE_STATUS_ZERO_CELL);
    key.pid_tgid = pid_tgid;
    key.slot = 0;
    key.pad = 0;
    if (bpf_map_lookup_elem(&START, &key))
        return bank_enter_fail(slot, BANK_FAIL_PRESENT, 0, COOKIE_STATUS_ZERO_CELL);
    select = bpf_map_lookup_elem(&BANK_SELECT, &select_key);
    /* A missing SELECT is impossible in practice (the array always
     * exists); incarnation 0 then stamps a route that never joins. */
    incarnation = select ? *(volatile u64 *)&select->fixed_inc[slot] : 0;
#pragma unroll
    for (int i = 0; i < BANK_START_SIZE / 8; i++)
        row[i] = 0;
    row[0] = bank_ktime();
    row[BANK_ROUTE_OFF / 8] = bank_route_make(bank, incarnation);
    row[BANK_MARKER_OFF / 8] = 0;
    row[BANK_COOKIE_OFF / 8] = out.cookie;
    row[BANK_EXEC_OFF / 8] = exec_id;
    {
        long rc = bank_update(&START, &key, row, 1);

        if (rc)
            return bank_enter_fail(slot, BANK_FAIL_INSERT, rc, COOKIE_STATUS_ZERO_CELL);
    }
    account = bank_account(slot);
    if (account) {
        bank_increment(&account->admitted);
        bank_increment(&account->live);
        account->obs_cookie = observed;
        account->obs_ip = ip;
        account->stash_cookie = observed;
        account->stash_ip = ip;
    }
    {
        u32 gate_key = slot;
        u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

        if (gate)
            bank_decrement(gate);
    }
    return COOKIE_STATUS_OK;
}

/* Bank B twin of admission, exported for the Rust slot root. Every
 * failure funnels through bank_enter_fail like bank A, and the route
 * stamps slot B's fixed incarnation. */
u32 p11_bank_enter_b(u64 pid_tgid, u64 bank, u64 observed, u64 ip)
{
    struct task_struct *current = bpf_get_current_task_btf();
    struct task_struct *leader;
    struct bank_cookie_out out;
    struct bank_account *account;
    struct bank_start_key key;
    struct bank_select *select;
    u64 row[BANK_START_SIZE / 8];
    u64 incarnation;
    u64 exec_id;
    u32 select_key = 0;
    u32 slot = 1;

    if (!current || !current->group_leader)
        return bank_enter_fail(slot, BANK_FAIL_COOKIE, 0, COOKIE_STATUS_BAD_TASK);
    leader = current->group_leader;
    out = bank_cookie_for_b(leader);
    if (out.status != COOKIE_STATUS_OK)
        return bank_enter_fail(slot, BANK_FAIL_COOKIE, 0, out.status);
    exec_id = *(volatile u64 *)&leader->self_exec_id;
    if (!bank_seed_b((u64)(u32)leader->tgid, out.cookie, exec_id))
        return bank_enter_fail(slot, BANK_FAIL_SEED, 0, COOKIE_STATUS_ZERO_CELL);
    key.pid_tgid = pid_tgid;
    key.slot = 0;
    key.pad = 0;
    if (bpf_map_lookup_elem(&START, &key))
        return bank_enter_fail(slot, BANK_FAIL_PRESENT, 0, COOKIE_STATUS_ZERO_CELL);
    select = bpf_map_lookup_elem(&BANK_SELECT, &select_key);
    /* A missing SELECT is impossible in practice (the array always
     * exists); incarnation 0 then stamps a route that never joins. */
    incarnation = select ? *(volatile u64 *)&select->fixed_inc[slot] : 0;
#pragma unroll
    for (int i = 0; i < BANK_START_SIZE / 8; i++)
        row[i] = 0;
    row[0] = bank_ktime();
    row[BANK_ROUTE_OFF / 8] = bank_route_make(bank, incarnation);
    row[BANK_MARKER_OFF / 8] = 0;
    row[BANK_COOKIE_OFF / 8] = out.cookie;
    row[BANK_EXEC_OFF / 8] = exec_id;
    {
        long rc = bank_update(&START, &key, row, 1);

        if (rc)
            return bank_enter_fail(slot, BANK_FAIL_INSERT, rc, COOKIE_STATUS_ZERO_CELL);
    }
    account = bank_account(slot);
    if (account) {
        bank_increment(&account->admitted);
        bank_increment(&account->live);
        account->obs_cookie = observed;
        account->obs_ip = ip;
        account->stash_cookie = observed;
        account->stash_ip = ip;
    }
    {
        u32 gate_key = slot;
        u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

        if (gate)
            bank_decrement(gate);
    }
    return COOKIE_STATUS_OK;
}

/* Return core: follow the route, never the current bank. Missing rows
 * and omitted routes retire quietly and count nothing. Exported for the
 * Rust uretprobe root. */
u32 p11_bank_complete(u64 pid_tgid)
{
    struct bank_start_key key;
    unsigned char *row;
    struct bank_account *account;
    u64 route;
    u64 bank;

    key.pid_tgid = pid_tgid;
    key.slot = 0;
    key.pad = 0;
    row = bpf_map_lookup_elem(&START, &key);
    if (!row)
        return 0;
    route = *(volatile u64 *)(row + BANK_ROUTE_OFF);
    if (!(route & BANK_ROUTE_VALID)) {
        bank_delete(&START, &key);
        return 0;
    }
    bank = (route & BANK_ROUTE_BANK) ? 1 : 0;
    account = bank_account((u32)bank);
    if (account) {
        bank_increment(&account->completed);
        bank_decrement(&account->live);
    }
    bank_delete(&START, &key);
    return 0;
}

/* Slot returned when no bank is selectable (never a valid bank). */
#define BANK_NO_SLOT 2u

/* Entry-shape dispatcher select: read the published flip word, take
 * that bank's gate ref, re-read, and on any bank or incarnation
 * change release and retry (bounded; BANK_SELECT_TRIES names why).
 * Scalar-only: the Rust dispatcher roots issue the tail call
 * themselves through their own owner array, so no context pointer
 * crosses the global-call boundary (the verifier refuses a
 * void-pointee reference argument with EINVAL). Exported for both
 * Rust dispatcher roots; the owner array is chosen by the caller.
 * Every return holds exactly one ref on the returned bank, or no
 * ref on BANK_NO_SLOT. */
u32 p11_bank_select(void)
{
    u32 zero = 0;
    struct bank_select *select = bpf_map_lookup_elem(&BANK_SELECT, &zero);

    if (!select)
        return BANK_NO_SLOT;
#pragma unroll
    for (int i = 0; i < BANK_SELECT_TRIES; i++) {
        u64 bank = *(volatile u64 *)&select->bank;
        u64 incarnation = *(volatile u64 *)&select->incarnation;
        u64 *gate;

        if (bank > 1)
            return BANK_NO_SLOT;
        u32 key = (u32)bank;
        gate = bpf_map_lookup_elem(&BANK_GATE, &key);
        if (!gate)
            return BANK_NO_SLOT;
        bank_increment(gate);
        if (*(volatile u64 *)&select->bank == bank &&
            *(volatile u64 *)&select->incarnation == incarnation)
            return (u32)(bank & 1);
        bank_decrement(gate);
    }
    return BANK_NO_SLOT;
}

/* Release one gate ref on the serving slot: the tail-call-failure
 * path in the Rust roots (a successful tail call never returns to
 * its caller). A failed tail-call releases exactly its ref and
 * admits nothing. Exported for both Rust dispatcher roots. */
u32 p11_bank_gate_release(u32 slot)
{
    u32 key = slot;
    u64 *gate;

    if (slot > 1)
        return 0;
    gate = bpf_map_lookup_elem(&BANK_GATE, &key);
    if (gate)
        bank_decrement(gate);
    return 0;
}

/* Birth spend on bank A: ticket only, no seed, no row, no count. */
static __always_inline u32 bank_birth_spend_a(struct task_struct *child)
{
    struct bank_cookie_out out = bank_cookie_for_a(child);
    u32 gate_key = 0;
    u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

    if (gate)
        bank_decrement(gate);
    return out.status;
}

/* Birth spend on bank B. */
static __always_inline u32 bank_birth_spend_b(struct task_struct *child)
{
    struct bank_cookie_out out = bank_cookie_for_b(child);
    u32 gate_key = 1;
    u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

    if (gate)
        bank_decrement(gate);
    return out.status;
}

/* Exec invalidation covers both banks of this load. */
static __always_inline u32 bank_exec_poison(void)
{
    struct task_struct *current = bpf_get_current_task_btf();
    struct task_struct *leader;
    u64 tgid;
    u64 *cell;
    struct image_continuity *record;

    if (!current || !current->group_leader)
        return 0;
    leader = current->group_leader;
    tgid = (u64)(u32)leader->tgid;
    cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX, &tgid);
    if (cell && *cell) {
        u64 cookie = *cell;

        record = bpf_map_lookup_elem(&IMAGE_CONTINUITY, &cookie);
        if (record)
            bank_write(record, 0, 1);
    }
    cell = bpf_map_lookup_elem(&IMAGE_TGID_INDEX_B, &tgid);
    if (cell && *cell) {
        u64 cookie = *cell;

        record = bpf_map_lookup_elem(&IMAGE_CONTINUITY_B, &cookie);
        if (record)
            bank_write(record, 0, 1);
    }
    return 0;
}

/* Directly attached reference core for the attach-cookie cell: records
 * what a probe observes without any dispatcher in the path. Exported for
 * the Rust reference root. */
u32 p11_bank_ref(u64 cookie, u64 ip)
{
    struct bank_account *account = bank_account(2);

    if (!account)
        return 0;
    account->obs_cookie = cookie;
    account->obs_ip = ip;
    return 0;
}

/* Birth dispatcher: same select protocol as the entry shape (read,
 * take that bank's ref, recheck, release and retry on change), kept
 * inline so this root takes no call edge (the stack census pins each
 * root's callees exactly). A birth racing the flip spends the current
 * bank's ticket. Tail-call failure falls through to the release. */
SEC("tp_btf/task_newtask")
int p11_bank_disp_birth(u64 *ctx)
{
    u32 zero = 0;
    struct bank_select *select = bpf_map_lookup_elem(&BANK_SELECT, &zero);

    if (!ctx || !select)
        return 0;
#pragma unroll
    for (int i = 0; i < BANK_SELECT_TRIES; i++) {
        u64 bank = *(volatile u64 *)&select->bank;
        u64 incarnation = *(volatile u64 *)&select->incarnation;
        u64 *gate;

        if (bank > 1)
            return 0;
        u32 key = (u32)bank;
        gate = bpf_map_lookup_elem(&BANK_GATE, &key);
        if (!gate)
            return 0;
        bank_increment(gate);
        if (*(volatile u64 *)&select->bank == bank &&
            *(volatile u64 *)&select->incarnation == incarnation) {
            bank_tail_call(ctx, &BANK_PROGS_BIRTH, (u32)(bank & 1));
            bank_decrement(gate);
            return 0;
        }
        bank_decrement(gate);
    }
    return 0;
}

SEC("tp_btf/task_newtask")
int p11_bank_birth_a(u64 *ctx)
{
    u64 clone_flags;
    struct task_struct *child;

    if (!ctx)
        return 0;
    clone_flags = ctx[1];
    child = (struct task_struct *)(unsigned long)ctx[0];
    if ((clone_flags & CLONE_THREAD) || !child) {
        u32 gate_key = 0;
        u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

        if (gate)
            bank_decrement(gate);
        return 0;
    }
    return bank_birth_spend_a(child);
}

SEC("tp_btf/task_newtask")
int p11_bank_birth_b(u64 *ctx)
{
    u64 clone_flags;
    struct task_struct *child;

    if (!ctx)
        return 0;
    clone_flags = ctx[1];
    child = (struct task_struct *)(unsigned long)ctx[0];
    if ((clone_flags & CLONE_THREAD) || !child) {
        u32 gate_key = 1;
        u64 *gate = bpf_map_lookup_elem(&BANK_GATE, &gate_key);

        if (gate)
            bank_decrement(gate);
        return 0;
    }
    return bank_birth_spend_b(child);
}

SEC("fentry/exec_mm_release")
int p11_bank_exec_cover(void *ctx)
{
    (void)ctx;
    return bank_exec_poison();
}

/* Dual-bank same-object query with the incarnation check. Requests carry
 * (row index, bank, incarnation) in the slot word; row 0 of the request
 * map publishes this load's bank incarnations. A stale request refuses
 * with a sticky fault and no emission or control touch. */
SEC("iter/task")
int p11_bank_query_cover(struct bank_iter_task *ctx)
{
    /* u64: shared by the u32 CTL key and the u64 REQUESTS row-0 key.
     * A u32 variable leaves the high row-0 key word as stack garbage,
     * so the lookup silently matches nothing whenever it is nonzero. */
    u64 zero = 0;
    struct image_query_control *ctl = bpf_map_lookup_elem(&IMAGE_QUERY_CTL, &zero);
    struct image_query_request *row0;
    u64 inc_a;
    u64 inc_b;
    struct task_struct *task;
    struct task_struct *leader;
    u64 cookies[2];
    int bank;

    if (!ctl || !ctx || !ctx->meta || !ctx->meta->seq)
        return 0;
    if (!ctl->generation || !ctl->count || ctl->count > IMG_REQUEST_LIMIT ||
        !ctl->visit_limit || ctl->visit_limit > IMG_VISIT_LIMIT || ctl->failed ||
        ctl->visits >= ctl->visit_limit || bank_ktime() >= ctl->deadline_ns) {
        *(volatile u64 *)&ctl->failed = 1;
        return 1;
    }
    *(volatile u64 *)&ctl->visits = *(volatile u64 *)&ctl->visits + 1;
    row0 = bpf_map_lookup_elem(&IMAGE_QUERY_REQUESTS, &zero);
    if (!row0 || row0->generation != BANK_ROW0_GENERATION)
        return 0;
    inc_a = row0->cookie;
    inc_b = (u64)(u32)row0->slot;
    task = ctx->task;
    if (!task) {
        struct image_query_row end;

        if (ctl->emitted != ctl->count) {
            *(volatile u64 *)&ctl->failed = 1;
            return 1;
        }
        end.generation = ctl->generation;
        end.cookie = 0;
        end.exec_id = ctl->emitted;
        end.sequence = ctl->visits;
        end.slot = (u32)ctl->count;
        end.status = IMG_ROW_END;
        if (bank_seq_write(ctx->meta->seq, &end, sizeof(end)))
            *(volatile u64 *)&ctl->failed = 1;
        return 0;
    }
    leader = task->group_leader;
    /* Leaders only: a thread visit would re-emit its leader's cookie.
     * Kernel threads carry no ticket (their storage cells read zero),
     * so they fall out at the cookie check below without a flags read. */
    if (!leader || leader != task)
        return 0;
    {
        u64 *cell_a = bpf_task_storage_get(&TASK_COOKIE, leader, (void *)0, 0);
        u64 *cell_b = bpf_task_storage_get(&TASK_COOKIE_B, leader, (void *)0, 0);

        cookies[0] = (cell_a && *cell_a) ? *cell_a : 0;
        cookies[1] = (cell_b && *cell_b) ? *cell_b : 0;
    }
#pragma unroll
    for (bank = 0; bank < 2; bank++) {
        u64 cookie = cookies[bank];
        u64 key = cookie | ((u64)(u32)bank << 32);
        struct image_query_request *request;
        struct image_continuity *record;
        struct image_query_row row;
        u64 req_slot;
        u64 req_bank;
        u64 req_inc;
        u64 want_inc;
        u64 exec_id;
        u64 sequence = 0;

        if (!bank_cookie_valid(cookie))
            continue;
        request = bpf_map_lookup_elem(&IMAGE_QUERY_REQUESTS, &key);
        if (!request || request->generation != ctl->generation ||
            request->cookie != cookie)
            continue;
        req_slot = request->slot;
        if ((req_slot & BANK_ROW_INDEX_MASK) >= ctl->count)
            continue;
        req_bank = (req_slot >> BANK_ROW_BANK_BIT) & 1;
        if (req_bank != (u64)bank)
            continue;
        req_inc = req_slot >> BANK_ROW_INCARNATION_SHIFT;
        want_inc = bank ? inc_b : inc_a;
        if (!want_inc || req_inc != want_inc) {
            struct bank_account *account = bank_account((u32)bank);

            if (account)
                account->faults |= BANK_FAULT_INC_MISMATCH;
            continue;
        }
        exec_id = *(volatile u64 *)&task->self_exec_id;
        if (bank)
            record = bpf_map_lookup_elem(&IMAGE_CONTINUITY_B, &cookie);
        else
            record = bpf_map_lookup_elem(&IMAGE_CONTINUITY, &cookie);
        row.generation = ctl->generation;
        row.cookie = cookie;
        row.exec_id = 0;
        row.sequence = 0;
        row.slot = (u32)((req_slot & BANK_ROW_INDEX_MASK) |
                         ((u64)(u32)bank << BANK_ROW_BANK_BIT) |
                         (req_inc << BANK_ROW_INCARNATION_SHIFT));
        row.status = IMG_ROW_UNKNOWN;
        if (record && bank_snapshot(record, exec_id, &sequence)) {
            __asm__ __volatile__("" ::: "memory");
            {
                u64 *fresh;

                if (bank)
                    fresh = bpf_task_storage_get(&TASK_COOKIE_B, task, (void *)0, 0);
                else
                    fresh = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
                if (fresh && *(volatile u64 *)fresh == cookie &&
                    task->group_leader == leader &&
                    *(volatile u64 *)&task->self_exec_id == exec_id &&
                    *(volatile u64 *)&record->seq == sequence) {
                    row.exec_id = exec_id;
                    row.sequence = sequence;
                    row.status = IMG_ROW_READY;
                }
            }
        }
        if (bank_seq_write(ctx->meta->seq, &row, sizeof(row))) {
            *(volatile u64 *)&ctl->failed = 1;
            return 1;
        }
        *(volatile u64 *)&ctl->emitted = *(volatile u64 *)&ctl->emitted + 1;
    }
    return 0;
}
