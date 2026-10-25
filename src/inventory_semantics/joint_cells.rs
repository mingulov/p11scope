//! SPDX-License-Identifier: GPL-3.0-or-later
//! Joint state/event cell table (§8.7 "Homes"): every constructible
//! (state, event) pair exactly once, with the home that proves it.
//! `Deferred` rows are driver cells waiting on the R1.5 commit path;
//! `Unconstructible` pairs (retire_own before any completion exists)
//! stay absent from the table.

/// Joint terminal states J0–J16 (§8.7 "States").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JointState {
    J0,
    J1,
    J2,
    J3,
    J4,
    J5,
    J6,
    J7,
    J8,
    J9,
    J10,
    J11,
    J12,
    J13,
    J14,
    J15,
    J16,
}

/// Joint terminal events (§8.7 "Events").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JointEvent {
    Stop,
    Deadline,
    Cancel,
    Promote,
    RetireOwn,
    ReplaceForeign,
    CaptureError,
    SinkFailure,
    HeldInstall,
    Sigint2,
}

/// The home proving one cell (§8.7 "Homes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CellHome {
    Machine,
    Driver,
    Native,
    Deferred(&'static str),
    Unconstructible(&'static str),
}

use CellHome::{Deferred, Driver, Machine, Native, Unconstructible};
use JointEvent::{
    Cancel, CaptureError, Deadline, HeldInstall, Promote, ReplaceForeign, RetireOwn, Sigint2,
    SinkFailure, Stop,
};
use JointState::{J0, J1, J2, J3, J4, J5, J6, J7, J8, J9, J10, J11, J12, J13, J14, J15, J16};

/// Every constructible cell exactly once: 40 Machine + 27 Native +
/// 69 Driver + 18 Deferred(R1.5) = 154. The 16 retire_own pairs on
/// J0–J15 are unconstructible (a completion exists only after
/// Complete) and stay absent.
pub(crate) const JOINT_CELLS: &[(JointState, JointEvent, CellHome)] = &[
    // Machine: J0–J8, J10 × {stop, deadline, capture_error, sink_failure}.
    (J0, Stop, Machine),
    (J0, Deadline, Machine),
    (J0, CaptureError, Machine),
    (J0, SinkFailure, Machine),
    (J1, Stop, Machine),
    (J1, Deadline, Machine),
    (J1, CaptureError, Machine),
    (J1, SinkFailure, Machine),
    (J2, Stop, Machine),
    (J2, Deadline, Machine),
    (J2, CaptureError, Machine),
    (J2, SinkFailure, Machine),
    (J3, Stop, Machine),
    (J3, Deadline, Machine),
    (J3, CaptureError, Machine),
    (J3, SinkFailure, Machine),
    (J4, Stop, Machine),
    (J4, Deadline, Machine),
    (J4, CaptureError, Machine),
    (J4, SinkFailure, Machine),
    (J5, Stop, Machine),
    (J5, Deadline, Machine),
    (J5, CaptureError, Machine),
    (J5, SinkFailure, Machine),
    (J6, Stop, Machine),
    (J6, Deadline, Machine),
    (J6, CaptureError, Machine),
    (J6, SinkFailure, Machine),
    (J7, Stop, Machine),
    (J7, Deadline, Machine),
    (J7, CaptureError, Machine),
    (J7, SinkFailure, Machine),
    (J8, Stop, Machine),
    (J8, Deadline, Machine),
    (J8, CaptureError, Machine),
    (J8, SinkFailure, Machine),
    (J10, Stop, Machine),
    (J10, Deadline, Machine),
    (J10, CaptureError, Machine),
    (J10, SinkFailure, Machine),
    // Native: J14–J16 × the nine events other than retire_own.
    (J14, Stop, Native),
    (J14, Deadline, Native),
    (J14, Cancel, Native),
    (J14, Promote, Native),
    (J14, ReplaceForeign, Native),
    (J14, CaptureError, Native),
    (J14, SinkFailure, Native),
    (J14, HeldInstall, Native),
    (J14, Sigint2, Native),
    (J15, Stop, Native),
    (J15, Deadline, Native),
    (J15, Cancel, Native),
    (J15, Promote, Native),
    (J15, ReplaceForeign, Native),
    (J15, CaptureError, Native),
    (J15, SinkFailure, Native),
    (J15, HeldInstall, Native),
    (J15, Sigint2, Native),
    (J16, Stop, Native),
    (J16, Deadline, Native),
    (J16, Cancel, Native),
    (J16, Promote, Native),
    (J16, ReplaceForeign, Native),
    (J16, CaptureError, Native),
    (J16, SinkFailure, Native),
    (J16, HeldInstall, Native),
    (J16, Sigint2, Native),
    // Driver: J0–J11 × {cancel, promote, held_install, replace_foreign, sigint2}.
    (J0, Cancel, Driver),
    (J0, Promote, Driver),
    (J0, HeldInstall, Driver),
    (J0, ReplaceForeign, Driver),
    (J0, Sigint2, Driver),
    (J1, Cancel, Driver),
    (J1, Promote, Driver),
    (J1, HeldInstall, Driver),
    (J1, ReplaceForeign, Driver),
    (J1, Sigint2, Driver),
    (J2, Cancel, Driver),
    (J2, Promote, Driver),
    (J2, HeldInstall, Driver),
    (J2, ReplaceForeign, Driver),
    (J2, Sigint2, Driver),
    (J3, Cancel, Driver),
    (J3, Promote, Driver),
    (J3, HeldInstall, Driver),
    (J3, ReplaceForeign, Driver),
    (J3, Sigint2, Driver),
    (J4, Cancel, Driver),
    (J4, Promote, Driver),
    (J4, HeldInstall, Driver),
    (J4, ReplaceForeign, Driver),
    (J4, Sigint2, Driver),
    (J5, Cancel, Driver),
    (J5, Promote, Driver),
    (J5, HeldInstall, Driver),
    (J5, ReplaceForeign, Driver),
    (J5, Sigint2, Driver),
    (J6, Cancel, Driver),
    (J6, Promote, Driver),
    (J6, HeldInstall, Driver),
    (J6, ReplaceForeign, Driver),
    (J6, Sigint2, Driver),
    (J7, Cancel, Driver),
    (J7, Promote, Driver),
    (J7, HeldInstall, Driver),
    (J7, ReplaceForeign, Driver),
    (J7, Sigint2, Driver),
    (J8, Cancel, Driver),
    (J8, Promote, Driver),
    (J8, HeldInstall, Driver),
    (J8, ReplaceForeign, Driver),
    (J8, Sigint2, Driver),
    (J9, Cancel, Driver),
    (J9, Promote, Driver),
    (J9, HeldInstall, Driver),
    (J9, ReplaceForeign, Driver),
    (J9, Sigint2, Driver),
    (J10, Cancel, Driver),
    (J10, Promote, Driver),
    (J10, HeldInstall, Driver),
    (J10, ReplaceForeign, Driver),
    (J10, Sigint2, Driver),
    (J11, Cancel, Driver),
    (J11, Promote, Driver),
    (J11, HeldInstall, Driver),
    (J11, ReplaceForeign, Driver),
    (J11, Sigint2, Driver),
    // Driver: J9/J11 × {stop, deadline, capture_error, sink_failure}.
    (J9, Stop, Driver),
    (J9, Deadline, Driver),
    (J9, CaptureError, Driver),
    (J9, SinkFailure, Driver),
    (J11, Stop, Driver),
    (J11, Deadline, Driver),
    (J11, CaptureError, Driver),
    (J11, SinkFailure, Driver),
    // Driver: J16 × retire_own (ok once, then X).
    (J16, RetireOwn, Driver),
    // Deferred(R1.5): J12/J13 × every event except retire_own.
    (J12, Stop, Deferred("R1.5")),
    (J12, Deadline, Deferred("R1.5")),
    (J12, Cancel, Deferred("R1.5")),
    (J12, Promote, Deferred("R1.5")),
    (J12, ReplaceForeign, Deferred("R1.5")),
    (J12, CaptureError, Deferred("R1.5")),
    (J12, SinkFailure, Deferred("R1.5")),
    (J12, HeldInstall, Deferred("R1.5")),
    (J12, Sigint2, Deferred("R1.5")),
    (J13, Stop, Deferred("R1.5")),
    (J13, Deadline, Deferred("R1.5")),
    (J13, Cancel, Deferred("R1.5")),
    (J13, Promote, Deferred("R1.5")),
    (J13, ReplaceForeign, Deferred("R1.5")),
    (J13, CaptureError, Deferred("R1.5")),
    (J13, SinkFailure, Deferred("R1.5")),
    (J13, HeldInstall, Deferred("R1.5")),
    (J13, Sigint2, Deferred("R1.5")),
];

const ALL_STATES: [JointState; 17] = [
    J0, J1, J2, J3, J4, J5, J6, J7, J8, J9, J10, J11, J12, J13, J14, J15, J16,
];

const ALL_EVENTS: [JointEvent; 10] = [
    Stop,
    Deadline,
    Cancel,
    Promote,
    RetireOwn,
    ReplaceForeign,
    CaptureError,
    SinkFailure,
    HeldInstall,
    Sigint2,
];

/// Every constructible pair appears exactly once; the 16
/// retire_own pairs on J0–J15 stay absent.
#[test]
fn joint_cells_cover_every_pair_once() {
    assert_eq!(
        JOINT_CELLS.len(),
        154,
        "Machine 40 + Native 27 + Driver 69 + Deferred 18"
    );
    let mut counts = (0, 0, 0, 0);
    for (_, _, home) in JOINT_CELLS {
        match home {
            Machine => counts.0 += 1,
            Native => counts.1 += 1,
            Driver => counts.2 += 1,
            Deferred(_) => counts.3 += 1,
            Unconstructible(_) => panic!("unconstructible pairs stay out of the table"),
        }
    }
    assert_eq!(
        counts,
        (40, 27, 69, 18),
        "the Homes split pins each home's cell count"
    );
    for state in ALL_STATES {
        for event in ALL_EVENTS {
            let hits = JOINT_CELLS
                .iter()
                .filter(|(s, e, _)| *s == state && *e == event)
                .count();
            let retired_before_completion = matches!(event, RetireOwn) && !matches!(state, J16);
            if retired_before_completion {
                let home = CellHome::Unconstructible("a completion exists only after Complete");
                assert_eq!(
                    hits, 0,
                    "{state:?}×{event:?} is {home:?}: it must stay absent"
                );
            } else {
                assert_eq!(hits, 1, "{state:?}×{event:?}: missing or duplicate pair");
            }
        }
    }
}
