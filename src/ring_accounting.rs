//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Independent per-ring cross-check accounting: the kernel counts every
//! record it submits (`produced`) and every reservation the ring refused
//! (`dropped`); userspace counts every record its drain takes off the ring
//! (`consumed`). At any point `produced - consumed - still_queued` must be
//! zero; a nonzero remainder is `unexplained` loss the reserve-failure
//! counter never saw, and is reported as a named gap, never as zero loss.
//!
//! `still_queued` is exact whenever the ring is drained to a verified empty
//! state (the terminal drain proves `consumer == producer`). On a live ring
//! it is exact for DISCOVERY (fixed 920-byte records plus the 8-byte ring
//! header) and unknowable for EVENTS (mixed record sizes), so a live EVENTS
//! account carries `still_queued: None` and its `unexplained` stays unknown
//! until the terminal drain makes it exact.

/// Ring bytes one DISCOVERY record occupies: the 920-byte record plus the
/// ring-buffer header. The record size is 8-aligned, so no padding applies.
pub(crate) const DISCOVERY_RING_RECORD_BYTES: u64 =
    core::mem::size_of::<p11scope_ebpf_common::DiscoveryRecord>() as u64 + 8;

/// One ring's cross-check account. `still_queued`/`unexplained` are `None`
/// exactly when the queued remainder is structurally unknowable (a live
/// EVENTS ring); everywhere else they are measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RingAccount {
    pub(crate) produced: u64,
    pub(crate) consumed: u64,
    pub(crate) dropped: u64,
    pub(crate) still_queued: Option<u64>,
    pub(crate) unexplained: Option<u64>,
}

/// Both rings' accounts. A ring is `None` when it has no counters in this
/// build or mode (EVENTS under inventory or metrics, which never drain it):
/// unknown, never zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RingAccounting {
    pub(crate) discovery: Option<RingAccount>,
    pub(crate) events: Option<RingAccount>,
}

/// Userspace consumed totals per ring: `None` when the ring was never
/// drained in this session (no consumer exists to count), never zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RingConsumed {
    pub(crate) discovery: Option<u64>,
    pub(crate) events: Option<u64>,
}

/// Live ring positions per ring (`producer`, `consumer` byte offsets):
/// `None` when the ring has no reader in this session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RingPositions {
    pub(crate) discovery: Option<(u64, u64)>,
    pub(crate) events: Option<(u64, u64)>,
}

/// One ring's raw cross-check inputs: kernel produced/dropped totals plus
/// the userspace consumed total and queued remainder. The engine stashes
/// these from the session's drains; the report computes the account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RingReading {
    pub(crate) produced: u64,
    pub(crate) consumed: Option<u64>,
    pub(crate) dropped: u64,
    pub(crate) queued: Option<u64>,
}

/// Both rings' raw readings. `consumed`/`queued` are `None` exactly when
/// the ring was never drained (no consumer) or the remainder is
/// structurally unknowable (a live EVENTS ring).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RingReadings {
    pub(crate) discovery: RingReading,
    pub(crate) events: RingReading,
}

impl RingReadings {
    /// Computes both rings' accounts. A ring with no consumed total has
    /// no cross-check to run and stays `None` (unknown, never zero).
    pub(crate) fn accounts(&self) -> RingAccounting {
        RingAccounting {
            discovery: self.discovery.account(),
            events: self.events.account(),
        }
    }
}

impl RingAccounting {
    /// True when either ring measured a dropped or unexplained record:
    /// known loss, never silence.
    pub(crate) fn has_loss(&self) -> bool {
        [self.discovery, self.events]
            .into_iter()
            .flatten()
            .any(|account| account.dropped > 0 || account.unexplained.is_some_and(|left| left > 0))
    }
}

/// One ring's loop-end fragment: `produced/consumed/dropped/queued/
/// unexplained`, with `?` for structurally unknown remainders.
fn ring_fragment(name: &str, account: Option<RingAccount>) -> String {
    match account {
        None => format!("{name}=?"),
        Some(account) => format!(
            "{name} produced={} consumed={} dropped={} queued={} unexplained={}",
            account.produced,
            account.consumed,
            account.dropped,
            account
                .still_queued
                .map_or_else(|| "?".to_string(), |queued| queued.to_string()),
            account
                .unexplained
                .map_or_else(|| "?".to_string(), |left| left.to_string()),
        ),
    }
}

/// The loop-end stderr line for both rings' accounts: `None` when
/// neither ring has counters (nothing drained), so modes without a
/// ring stay silent instead of printing zeros.
pub(crate) fn loop_end_line(accounts: &RingAccounting) -> Option<String> {
    if accounts.discovery.is_none() && accounts.events.is_none() {
        return None;
    }
    Some(format!(
        "p11scope: rings: {}; {}",
        ring_fragment("discovery", accounts.discovery),
        ring_fragment("events", accounts.events),
    ))
}

impl RingReading {
    fn account(&self) -> Option<RingAccount> {
        let consumed = self.consumed?;
        Some(account_ring(
            self.produced,
            consumed,
            self.dropped,
            self.queued,
        ))
    }
}

/// Builds one ring's account from its four inputs. `still_queued` is `None`
/// exactly when the queued remainder cannot be measured (a live EVENTS
/// ring); the terminal drain always passes `Some(0)` after it verifies the
/// ring empty. All arithmetic saturates: counters only grow, so a `consumed`
/// above `produced` is a counter inconsistency the caller names, never a
/// wrap into a huge unexplained value.
pub(crate) fn account_ring(
    produced: u64,
    consumed: u64,
    dropped: u64,
    still_queued: Option<u64>,
) -> RingAccount {
    let unexplained =
        still_queued.map(|queued| produced.saturating_sub(consumed).saturating_sub(queued));
    RingAccount {
        produced,
        consumed,
        dropped,
        still_queued,
        unexplained,
    }
}

/// Queued records at these ring positions (`producer`, `consumer` byte
/// offsets) with this per-record stride (`None` when records vary, as on
/// EVENTS). An empty ring is exactly zero; a non-empty ring with a known
/// stride divides the unread bytes; a non-empty ring with an unknown
/// stride is unknowable (`None`). Exact while no reservation is in
/// flight; a live producer mid-reserve skews the divided remainder by at
/// most that reservation, which is why the terminal account (producers
/// detached, ring verified empty) is the verdict and the live one is
/// diagnostic.
pub(crate) fn queued_records(positions: (u64, u64), stride: Option<u64>) -> Option<u64> {
    let (producer, consumer) = positions;
    let unread = producer.saturating_sub(consumer);
    if unread == 0 {
        return Some(0);
    }
    stride.and_then(|bytes| unread.checked_div(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_ring_has_no_unexplained_loss() {
        let account = account_ring(100, 90, 3, Some(10));
        assert_eq!(account.produced, 100);
        assert_eq!(account.consumed, 90);
        assert_eq!(account.dropped, 3);
        assert_eq!(account.still_queued, Some(10));
        assert_eq!(account.unexplained, Some(0));
    }

    #[test]
    fn missing_records_are_unexplained_never_zero_loss() {
        let account = account_ring(100, 80, 3, Some(10));
        assert_eq!(account.unexplained, Some(10));
    }

    #[test]
    fn terminal_drain_leaves_nothing_unexplained() {
        let account = account_ring(7_128, 7_128, 5, Some(0));
        assert_eq!(account.unexplained, Some(0));
    }

    #[test]
    fn unknown_queue_keeps_unexplained_unknown() {
        let account = account_ring(100, 80, 3, None);
        assert_eq!(account.still_queued, None);
        assert_eq!(account.unexplained, None);
    }

    #[test]
    fn consumed_above_produced_saturates_instead_of_wrapping() {
        let account = account_ring(10, 12, 0, Some(0));
        assert_eq!(account.unexplained, Some(0));
    }

    #[test]
    fn queued_records_divide_unread_bytes_by_record_size() {
        assert_eq!(
            queued_records((928 * 3, 928), Some(DISCOVERY_RING_RECORD_BYTES)),
            Some(2)
        );
        assert_eq!(
            queued_records((928 * 3, 928 * 3), Some(DISCOVERY_RING_RECORD_BYTES)),
            Some(0)
        );
    }

    #[test]
    fn record_stride_is_920_plus_header() {
        assert_eq!(
            DISCOVERY_RING_RECORD_BYTES,
            size_of::<p11scope_ebpf_common::DiscoveryRecord>() as u64 + 8
        );
        assert_eq!(DISCOVERY_RING_RECORD_BYTES, 928);
    }

    #[test]
    fn empty_ring_queues_zero_whatever_the_stride() {
        assert_eq!(queued_records((100, 100), None), Some(0));
        assert_eq!(
            queued_records((100, 100), Some(DISCOVERY_RING_RECORD_BYTES)),
            Some(0)
        );
    }

    #[test]
    fn unknown_stride_queues_unknown_until_drained() {
        assert_eq!(queued_records((1_000, 100), None), None);
        assert_eq!(queued_records((1_000, 1_000), None), Some(0));
    }

    #[test]
    fn loop_end_line_names_every_counter_per_ring() {
        let accounts = RingAccounting {
            discovery: Some(RingAccount {
                produced: 100,
                consumed: 90,
                dropped: 7,
                still_queued: Some(3),
                unexplained: Some(0),
            }),
            events: Some(RingAccount {
                produced: 200,
                consumed: 180,
                dropped: 0,
                still_queued: None,
                unexplained: None,
            }),
        };
        assert!(accounts.has_loss());
        assert_eq!(
            loop_end_line(&accounts).as_deref(),
            Some(
                "p11scope: rings: discovery produced=100 consumed=90 dropped=7 \
                 queued=3 unexplained=0; events produced=200 consumed=180 dropped=0 \
                 queued=? unexplained=?"
            ),
        );
    }

    #[test]
    fn loop_end_line_stays_silent_without_counters() {
        let accounts = RingAccounting::default();
        assert!(!accounts.has_loss());
        assert_eq!(loop_end_line(&accounts), None);
    }

    #[test]
    fn loop_end_line_marks_only_the_missing_ring_unknown() {
        let accounts = RingAccounting {
            discovery: None,
            events: Some(RingAccount {
                produced: 5,
                consumed: 5,
                dropped: 0,
                still_queued: Some(0),
                unexplained: Some(0),
            }),
        };
        assert!(!accounts.has_loss());
        assert_eq!(
            loop_end_line(&accounts).as_deref(),
            Some(
                "p11scope: rings: discovery=?; events produced=5 consumed=5 dropped=0 \
                 queued=0 unexplained=0"
            ),
        );
    }

    #[test]
    fn readings_without_consumed_stay_unknown() {
        let readings = RingReadings {
            discovery: RingReading {
                produced: 10,
                consumed: None,
                dropped: 1,
                queued: Some(0),
            },
            events: RingReading {
                produced: 20,
                consumed: Some(18),
                dropped: 0,
                queued: Some(2),
            },
        };
        let accounts = readings.accounts();
        assert_eq!(accounts.discovery, None);
        assert_eq!(
            accounts.events,
            Some(RingAccount {
                produced: 20,
                consumed: 18,
                dropped: 0,
                still_queued: Some(2),
                unexplained: Some(0),
            })
        );
    }
}
