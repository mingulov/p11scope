//! SPDX-License-Identifier: GPL-3.0-or-later
//! One acknowledgement decision per capture, made by its control thread.

use std::cell::Cell;

#[derive(Default)]
pub(super) struct CaptureCancellation {
    reported: Cell<bool>,
}

impl CaptureCancellation {
    /// A handler updates signal state; only the capture's cooperative poll
    /// consumes the first observed signal and authorizes its reporter call.
    pub(super) fn observe(&self, first_signal: Option<i32>) -> Option<i32> {
        let signal = first_signal?;
        (!self.reported.replace(true)).then_some(signal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signal_does_not_acknowledge_an_already_requested_stop() {
        let capture = CaptureCancellation::default();
        for _ in 0..4 {
            assert_eq!(capture.observe(None), None);
        }
        assert!(!capture.reported.get());
    }

    #[test]
    fn signal_first_observed_during_finalization_gets_one_acknowledgement() {
        let capture = CaptureCancellation::default();
        // Main loop ended by duration. Its signal-free stop observation
        // cannot consume the later cancellation acknowledgement.
        assert_eq!(capture.observe(None), None);
        assert_eq!(capture.observe(Some(15)), Some(15));
        assert_eq!(capture.observe(Some(15)), None);
    }

    #[test]
    fn repeated_signals_preserve_the_first_report_and_cannot_report_again() {
        let capture = CaptureCancellation::default();
        assert_eq!(capture.observe(Some(2)), Some(2));
        assert_eq!(capture.observe(Some(15)), None);
        assert_eq!(capture.observe(Some(2)), None);
    }
}
