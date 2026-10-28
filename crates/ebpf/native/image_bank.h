/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host model of the image dispatcher/bank rollover protocol (Choice B).
 *
 * One permanently attached dispatcher fronts at most two immutable producer
 * banks. The dispatcher reads BANK_SELECT (incarnation, bank index), takes a
 * short gate ref, and tail-calls exactly one bank; entry records the chosen
 * bank in a per-call route (R0: bank field inside the START value; R1:
 * separate route table), and the return dispatcher follows the route, never
 * the current bank. Exec/mapping invalidators stay effective for both
 * banks. A bank slot is reused only as a new incarnation (new map objects
 * plus a freshly loaded program) after its predecessor reaches closed-zero
 * and is reclaimed; identity is (incarnation, ticket).
 *
 * Admission reuses the production ticket semantics from image_identity.h
 * (tickets 1..16384, QUOTA past the real limit, no reset of next_ticket).
 * This TU is plain single-threaded logic; the threaded harness scenario
 * serializes calls with a host mutex, which models kernel atomic ordering.
 */
#ifndef P11SCOPE_IMAGE_BANK_H
#define P11SCOPE_IMAGE_BANK_H

#include "image_identity.h"

#include <stdint.h>

#define P11_BANK_SLOTS 2
#define P11_BANK_CUT_HEADROOM 1024ULL
#define P11_BANK_MAX_LEADER 65536u
#define P11_BANK_MAX_CALL 65536u

enum p11_bank_status {
    P11_BANK_OK = 0,
    P11_BANK_QUOTA = 1,
    P11_BANK_REFUSED = 2,
    P11_BANK_DELETE_FAILED = 3,
    P11_BANK_TAILCALL_FAILED = 4,
    P11_BANK_PINNED = 5,
    P11_BANK_NOT_READY = 6,
    P11_BANK_BAD = 7,
};

enum p11_bank_route_mode {
    P11_BANK_ROUTE_R0 = 0,
    P11_BANK_ROUTE_R1 = 1,
};

struct p11_bank_identity {
    uint8_t bank;
    uint32_t incarnation;
    uint32_t ticket;
};

/* One bank incarnation's map objects. Fresh objects per incarnation. */
struct p11_bank_maps {
    uint64_t map_id;
    uint32_t incarnation;
    int program_id;
    int prepared;
    int admission_open;
    uint64_t next_ticket;
    uint64_t unavailable;
    uint64_t admitted;
    uint64_t burned;
    uint64_t completed;
    uint32_t ticket_leader[IMAGE_IDENTITY_TICKET_LIMIT];
    uint16_t leader_ticket[P11_BANK_MAX_LEADER];
    unsigned char exec_invalid[P11_BANK_MAX_LEADER];
};

struct p11_bank_route {
    uint8_t present;
    uint8_t bank;
    uint32_t incarnation;
    uint32_t ticket;
    uint32_t leader;
};

#define P11_BANK_NO_SLOT 2u

struct p11_bank_domain {
    uint8_t select_bank;
    uint32_t select_incarnation;
    /* In-flight dispatcher refs per bank (mirrors BANK_GATE[2]): a
     * selected-but-unadmitted call holds its bank's ref until it
     * admits or backs out. */
    long gate_ref[P11_BANK_SLOTS];
    enum p11_bank_route_mode route_mode;
    struct p11_bank_maps maps[P11_BANK_SLOTS];
    int progs[P11_BANK_SLOTS];
    struct p11_bank_route start0[P11_BANK_MAX_CALL];
    struct p11_bank_route route1[P11_BANK_MAX_CALL];
    unsigned char counted_by[P11_BANK_MAX_CALL];
    long routes_live[P11_BANK_SLOTS];
    long query_leases[P11_BANK_SLOTS];
    long cont_leases[P11_BANK_SLOTS];
    uint64_t map_seq;
    int prog_seq;
    uint32_t inc_seq;
    uint64_t retired_maps[16];
    int retired_count;
    unsigned long both_counted;
    unsigned long successor_mutations;
    int fail_route_delete;
    int fail_tailcall;
    /* Test-only race injection (precedent: fail_tailcall): when
     * nonzero, the next p11_bank_select performs the cut itself
     * between taking its gate ref and rechecking, then clears the
     * flag. Deterministically lands a flip inside one select, the
     * way a preemption does in the kernel. */
    int flip_before_recheck;
    char last_refusal[64];
};

void p11_bank_init(struct p11_bank_domain *d, enum p11_bank_route_mode mode);
/* Split-phase admission, mirroring the kernel dispatcher + bank
 * entry: select reads BANK_SELECT and takes the bank's gate ref
 * (rechecking across a flip, backing out and retrying on change,
 * P11_BANK_NO_SLOT past the bound); admit spends the ticket and
 * installs the route stamped with the bank's own fixed incarnation,
 * releasing the ref; select_release backs a ref out without
 * admitting (tail-call failure). p11_bank_enter fuses the two for
 * the race-free scenarios. */
uint8_t p11_bank_select(struct p11_bank_domain *d);
enum p11_bank_status p11_bank_admit(struct p11_bank_domain *d, uint32_t leader,
                                   uint32_t call, uint8_t bank,
                                   struct p11_bank_identity *out);
void p11_bank_select_release(struct p11_bank_domain *d, uint8_t bank);
enum p11_bank_status p11_bank_enter(struct p11_bank_domain *d, uint32_t leader,
                                   uint32_t call, struct p11_bank_identity *out);
uint32_t p11_bank_burn(struct p11_bank_domain *d);
enum p11_bank_status p11_bank_leave(struct p11_bank_domain *d, uint32_t call,
                                   struct p11_bank_identity *counted);
enum p11_bank_status p11_bank_prepare(struct p11_bank_domain *d, unsigned int slot);
enum p11_bank_status p11_bank_cut(struct p11_bank_domain *d);
int p11_bank_close_zero(struct p11_bank_domain *d, unsigned int slot);
/* Admission closed-zero, mirroring BankProofDriver::closed_zero
 * exactly: the bank's gate drained, nothing live, no START rows.
 * Query/continuation leases are model-only and excluded here, the
 * way the driver excludes them (its query links are run-and-done). */
int p11_bank_close_zero_admission(struct p11_bank_domain *d, unsigned int slot);
enum p11_bank_status p11_bank_reclaim(struct p11_bank_domain *d, unsigned int slot);
enum p11_bank_status p11_bank_callback(struct p11_bank_domain *d, unsigned int slot,
                                       uint32_t incarnation, uint32_t ticket);
void p11_bank_query_hold(struct p11_bank_domain *d, unsigned int slot);
void p11_bank_query_release(struct p11_bank_domain *d, unsigned int slot);
void p11_bank_cont_hold(struct p11_bank_domain *d, unsigned int slot);
void p11_bank_cont_release(struct p11_bank_domain *d, unsigned int slot);
unsigned int p11_bank_exec_invalidate(struct p11_bank_domain *d, uint32_t leader);
int p11_bank_query_invalidated(struct p11_bank_domain *d, unsigned int slot,
                               uint32_t leader);
int p11_bank_join(struct p11_bank_domain *d, unsigned int slot, uint32_t incarnation,
                  uint32_t ticket, uint32_t *leader);

#endif
