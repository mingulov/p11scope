//! SPDX-License-Identifier: GPL-3.0-or-later
//! Offline comparison of saved inventory evidence.

// The reader is integrated by the separately scoped comparator and CLI tasks.
#[allow(dead_code)]
mod input;

// Consumed by the separately scoped offline rendering and command task.
#[allow(dead_code)]
mod compare;
#[allow(dead_code)]
mod model;

#[cfg(test)]
mod input_tests;

#[cfg(test)]
mod compare_tests;
