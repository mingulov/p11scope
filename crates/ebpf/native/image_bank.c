/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host model of the image dispatcher/bank rollover protocol. See
 * image_bank.h for the mechanism. Storage below stands in for the kernel
 * maps (stub semantics: lookup/update/delete over host memory); scenario
 * drivers live in image_bank_harness.c.
 */
#include "image_bank.h"

#include <stdio.h>
#include <string.h>

static struct p11_bank_route *bank_route_for(struct p11_bank_domain *d, uint32_t call)
{
    if (d->route_mode == P11_BANK_ROUTE_R1)
        return &d->route1[call];
    return &d->start0[call];
}

static int bank_ids_valid(uint32_t leader, uint32_t call)
{
    return leader > 0 && leader < P11_BANK_MAX_LEADER && call < P11_BANK_MAX_CALL;
}

void p11_bank_init(struct p11_bank_domain *d, enum p11_bank_route_mode mode)
{
    struct p11_bank_maps *a;

    memset(d, 0, sizeof(*d));
    d->route_mode = mode;
    d->map_seq = 1;
    d->prog_seq = 1;
    d->inc_seq = 1;
    /* Bank A is installed at attach: incarnation 1, admission open. */
    a = &d->maps[0];
    a->map_id = 1;
    a->incarnation = 1;
    a->program_id = 1;
    a->prepared = 1;
    a->admission_open = 1;
    d->progs[0] = 1;
    d->select_bank = 0;
    d->select_incarnation = 1;
}

#define P11_BANK_SELECT_TRIES 4

uint8_t p11_bank_select(struct p11_bank_domain *d)
{
    int i;

    for (i = 0; i < P11_BANK_SELECT_TRIES; i++) {
        uint8_t bank = d->select_bank;
        uint32_t incarnation = d->select_incarnation;

        if (bank >= P11_BANK_SLOTS)
            return P11_BANK_NO_SLOT;
        d->gate_ref[bank]++;
        if (d->flip_before_recheck) {
            d->flip_before_recheck = 0;
            p11_bank_cut(d);
        }
        if (d->select_bank == bank && d->select_incarnation == incarnation)
            return bank;
        d->gate_ref[bank]--;
    }
    return P11_BANK_NO_SLOT;
}

void p11_bank_select_release(struct p11_bank_domain *d, uint8_t bank)
{
    if (bank < P11_BANK_SLOTS)
        d->gate_ref[bank]--;
}

enum p11_bank_status p11_bank_admit(struct p11_bank_domain *d, uint32_t leader,
                                   uint32_t call, uint8_t bank,
                                   struct p11_bank_identity *out)
{
    struct p11_bank_maps *m;
    struct p11_bank_route *r;
    uint32_t ticket;

    if (bank >= P11_BANK_SLOTS)
        return P11_BANK_BAD;
    if (!bank_ids_valid(leader, call)) {
        p11_bank_select_release(d, bank);
        return P11_BANK_BAD;
    }
    m = &d->maps[bank];
    if (!m->prepared) {
        snprintf(d->last_refusal, sizeof(d->last_refusal), "admission-closed");
        p11_bank_select_release(d, bank);
        return P11_BANK_REFUSED;
    }
    /* A failed admission must not spend identity: refuse a reused call id
     * before issuing any ticket. */
    r = bank_route_for(d, call);
    if (r->present) {
        p11_bank_select_release(d, bank);
        return P11_BANK_BAD;
    }
    ticket = m->leader_ticket[leader];
    if (ticket == 0) {
        if (m->next_ticket >= IMAGE_IDENTITY_TICKET_LIMIT) {
            m->unavailable++;
            p11_bank_select_release(d, bank);
            return P11_BANK_QUOTA;
        }
        m->next_ticket++;
        ticket = (uint32_t)m->next_ticket;
        m->admitted++;
        m->leader_ticket[leader] = (uint16_t)ticket;
        m->ticket_leader[ticket - 1] = leader;
    }
    r->present = 1;
    r->bank = bank;
    r->incarnation = m->incarnation;
    r->ticket = ticket;
    r->leader = leader;
    d->routes_live[bank]++;
    out->bank = bank;
    out->incarnation = m->incarnation;
    out->ticket = ticket;
    p11_bank_select_release(d, bank);
    return P11_BANK_OK;
}

enum p11_bank_status p11_bank_enter(struct p11_bank_domain *d, uint32_t leader,
                                   uint32_t call, struct p11_bank_identity *out)
{
    uint8_t bank;

    if (!bank_ids_valid(leader, call))
        return P11_BANK_BAD;
    bank = p11_bank_select(d);
    if (bank >= P11_BANK_SLOTS)
        return P11_BANK_REFUSED;
    if (d->fail_tailcall) {
        p11_bank_select_release(d, bank);
        return P11_BANK_TAILCALL_FAILED;
    }
    return p11_bank_admit(d, leader, call, bank, out);
}

/*
 * Burns one ticket, modeling a lost CAS/creation race: the ticket is spent
 * from next_ticket with no identity installed. Returns the burned ticket,
 * or 0 past the limit (counted as unavailable, like a refused attempt).
 */
uint32_t p11_bank_burn(struct p11_bank_domain *d)
{
    struct p11_bank_maps *m = &d->maps[d->select_bank];

    d->gate_ref[d->select_bank]++;
    if (m->next_ticket >= IMAGE_IDENTITY_TICKET_LIMIT) {
        m->unavailable++;
        d->gate_ref[d->select_bank]--;
        return 0;
    }
    m->next_ticket++;
    m->burned++;
    d->gate_ref[d->select_bank]--;
    return (uint32_t)m->next_ticket;
}

enum p11_bank_status p11_bank_leave(struct p11_bank_domain *d, uint32_t call,
                                   struct p11_bank_identity *counted)
{
    struct p11_bank_route *r;
    struct p11_bank_maps *m;
    uint8_t bank;

    if (call >= P11_BANK_MAX_CALL)
        return P11_BANK_BAD;
    r = bank_route_for(d, call);
    if (!r->present)
        return P11_BANK_REFUSED;
    bank = r->bank;
    if (bank >= P11_BANK_SLOTS) {
        r->present = 0;
        return P11_BANK_REFUSED;
    }
    m = &d->maps[bank];
    /* The return follows the route; a reclaimed incarnation never counts. */
    if (!m->prepared || m->incarnation != r->incarnation) {
        r->present = 0;
        d->routes_live[bank]--;
        return P11_BANK_REFUSED;
    }
    if (d->route_mode == P11_BANK_ROUTE_R1 && d->fail_route_delete) {
        snprintf(d->last_refusal, sizeof(d->last_refusal), "route-delete");
        return P11_BANK_DELETE_FAILED;
    }
    r->present = 0;
    d->routes_live[bank]--;
    m->completed++;
    if (d->counted_by[call] != 0)
        d->both_counted++;
    d->counted_by[call] = (unsigned char)(bank + 1);
    counted->bank = bank;
    counted->incarnation = m->incarnation;
    counted->ticket = r->ticket;
    return P11_BANK_OK;
}

enum p11_bank_status p11_bank_prepare(struct p11_bank_domain *d, unsigned int slot)
{
    struct p11_bank_maps *m;

    if (slot >= P11_BANK_SLOTS)
        return P11_BANK_BAD;
    m = &d->maps[slot];
    if (m->prepared) {
        snprintf(d->last_refusal, sizeof(d->last_refusal), "slot-occupied");
        return P11_BANK_PINNED;
    }
    memset(m, 0, sizeof(*m));
    d->map_seq++;
    d->prog_seq++;
    d->inc_seq++;
    m->map_id = d->map_seq;
    m->incarnation = d->inc_seq;
    m->program_id = d->prog_seq;
    d->progs[slot] = m->program_id;
    m->prepared = 1;
    m->admission_open = 1;
    return P11_BANK_OK;
}

enum p11_bank_status p11_bank_cut(struct p11_bank_domain *d)
{
    uint8_t cur = d->select_bank;
    uint8_t other = (uint8_t)(1 - cur);

    if (!d->maps[other].prepared)
        return P11_BANK_NOT_READY;
    d->maps[cur].admission_open = 0;
    d->select_bank = other;
    d->select_incarnation = d->maps[other].incarnation;
    return P11_BANK_OK;
}

int p11_bank_close_zero(struct p11_bank_domain *d, unsigned int slot)
{
    struct p11_bank_maps *m;

    if (slot >= P11_BANK_SLOTS)
        return 0;
    m = &d->maps[slot];
    if (!m->prepared || m->admission_open)
        return 0;
    return d->gate_ref[slot] == 0 && d->routes_live[slot] == 0 &&
           d->query_leases[slot] == 0 && d->cont_leases[slot] == 0;
}

/* Admission closed-zero, mirroring BankProofDriver::closed_zero: live
 * count plus an explicit START scan, like the driver's live read plus
 * start_rows_for_slot scan. */
int p11_bank_close_zero_admission(struct p11_bank_domain *d, unsigned int slot)
{
    uint32_t call;

    if (slot >= P11_BANK_SLOTS)
        return 0;
    if (d->gate_ref[slot] != 0)
        return 0;
    if (d->routes_live[slot] != 0)
        return 0;
    for (call = 0; call < P11_BANK_MAX_CALL; call++) {
        struct p11_bank_route *r = bank_route_for(d, call);

        if (r->present && r->bank == slot)
            return 0;
    }
    return 1;
}

enum p11_bank_status p11_bank_reclaim(struct p11_bank_domain *d, unsigned int slot)
{
    struct p11_bank_maps *m;

    if (slot >= P11_BANK_SLOTS)
        return P11_BANK_BAD;
    if (!p11_bank_close_zero(d, slot)) {
        snprintf(d->last_refusal, sizeof(d->last_refusal), "not-closed-zero");
        return P11_BANK_PINNED;
    }
    m = &d->maps[slot];
    if (d->retired_count < (int)(sizeof(d->retired_maps) / sizeof(d->retired_maps[0])))
        d->retired_maps[d->retired_count++] = m->map_id;
    memset(m, 0, sizeof(*m));
    d->progs[slot] = 0;
    return P11_BANK_OK;
}

enum p11_bank_status p11_bank_callback(struct p11_bank_domain *d, unsigned int slot,
                                       uint32_t incarnation, uint32_t ticket)
{
    struct p11_bank_maps *m;

    if (slot >= P11_BANK_SLOTS)
        return P11_BANK_BAD;
    m = &d->maps[slot];
    if (!m->prepared || m->incarnation != incarnation)
        return P11_BANK_REFUSED;
    if (ticket == 0 || (uint64_t)ticket > m->next_ticket)
        return P11_BANK_REFUSED;
    d->successor_mutations++;
    return P11_BANK_OK;
}

void p11_bank_query_hold(struct p11_bank_domain *d, unsigned int slot)
{
    if (slot < P11_BANK_SLOTS)
        d->query_leases[slot]++;
}

void p11_bank_query_release(struct p11_bank_domain *d, unsigned int slot)
{
    if (slot < P11_BANK_SLOTS && d->query_leases[slot] > 0)
        d->query_leases[slot]--;
}

void p11_bank_cont_hold(struct p11_bank_domain *d, unsigned int slot)
{
    if (slot < P11_BANK_SLOTS)
        d->cont_leases[slot]++;
}

void p11_bank_cont_release(struct p11_bank_domain *d, unsigned int slot)
{
    if (slot < P11_BANK_SLOTS && d->cont_leases[slot] > 0)
        d->cont_leases[slot]--;
}

unsigned int p11_bank_exec_invalidate(struct p11_bank_domain *d, uint32_t leader)
{
    unsigned int mask = 0;
    unsigned int slot;

    if (leader == 0 || leader >= P11_BANK_MAX_LEADER)
        return 0;
    for (slot = 0; slot < P11_BANK_SLOTS; slot++) {
        if (d->maps[slot].prepared) {
            d->maps[slot].exec_invalid[leader] = 1;
            mask |= 1u << slot;
        }
    }
    return mask;
}

int p11_bank_query_invalidated(struct p11_bank_domain *d, unsigned int slot,
                               uint32_t leader)
{
    if (slot >= P11_BANK_SLOTS || leader >= P11_BANK_MAX_LEADER)
        return 0;
    return d->maps[slot].prepared && d->maps[slot].exec_invalid[leader] != 0;
}

int p11_bank_join(struct p11_bank_domain *d, unsigned int slot, uint32_t incarnation,
                  uint32_t ticket, uint32_t *leader)
{
    struct p11_bank_maps *m;

    if (slot >= P11_BANK_SLOTS || ticket == 0 ||
        (uint64_t)ticket > IMAGE_IDENTITY_TICKET_LIMIT)
        return 0;
    m = &d->maps[slot];
    if (!m->prepared || m->incarnation != incarnation)
        return 0;
    if ((uint64_t)ticket > m->next_ticket)
        return 0;
    *leader = m->ticket_leader[ticket - 1];
    return *leader != 0;
}
