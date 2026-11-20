//! Debit-before-read credit for the bounded recovery cursors.
//!
//! A recovery cursor ([`super::recovery_cursor`]) never holds the journal
//! adapter or the model. It sees only [`super::journal::JournalLeaves`] and
//! [`super::state::ModelLeaves`], whose fields are private to their owning
//! modules, and every accessor on them consumes a [`Paid`] token (or a
//! decision token minted by a paid probe). Only [`Credit::pay`] mints a
//! `Paid`, after debiting one unit from the slice and from the caller's
//! service budget. Reading a leaf without paying for it therefore does not
//! compile.
//!
//! One unit pays for one leaf: one row visited (an open entry, a refused
//! begin, a key, a claim, a model view/session/binding/call/deferred
//! record) plus the constant number of indexed lookups that decide it.
//! Iterating a nested collection is never part of a unit: each element is
//! its own leaf, paid before it is read. O(1) emptiness/length metadata
//! of an owned collection and bulk frees that read no leaf are unpaid
//! (owner rule 2026-11-13).

/// One debited unit of recovery credit. It has no public constructor and
/// is neither `Clone` nor `Copy`: each leaf accessor consumes one.
#[must_use = "a paid unit is spent on the leaf it pays for"]
#[derive(Debug)]
pub(in crate::semantics_objects) struct Paid {
    _sealed: (),
}

/// One slice of recovery credit: at most a slice cap of units, never more
/// than the caller's service budget, both debited in lockstep.
pub(in crate::semantics_objects) struct Credit<'a> {
    left: usize,
    budget: &'a mut usize,
}

impl<'a> Credit<'a> {
    /// A slice of at most `cap` units drawn from `budget`.
    pub(in crate::semantics_objects) fn slice(cap: usize, budget: &'a mut usize) -> Self {
        Self {
            left: cap.min(*budget),
            budget,
        }
    }

    /// Units left in this slice.
    pub(in crate::semantics_objects) fn left(&self) -> usize {
        self.left
    }

    /// Debit one unit, or `None` when the slice is spent (the caller
    /// yields with its resume position, having read nothing).
    pub(in crate::semantics_objects) fn pay(&mut self) -> Option<Paid> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        *self.budget = self.budget.saturating_sub(1);
        Some(Paid { _sealed: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_never_pays_past_its_slice_or_budget() {
        let mut budget = 3usize;
        let mut credit = Credit::slice(64, &mut budget);
        assert_eq!(credit.left(), 3);
        assert!(credit.pay().is_some() && credit.pay().is_some());
        assert_eq!(credit.left(), 1);
        assert!(credit.pay().is_some());
        assert!(credit.pay().is_none(), "a spent slice mints nothing");
        assert_eq!(budget, 0);
        let mut budget = 100usize;
        let mut credit = Credit::slice(2, &mut budget);
        assert!(credit.pay().is_some() && credit.pay().is_some());
        assert!(
            credit.pay().is_none(),
            "the slice cap binds below the budget"
        );
        assert_eq!(budget, 98);
    }

    /// The recovery cursor never mints its own credit: every slice it
    /// spends comes from the service budget its caller passed in.
    #[test]
    fn recovery_cursor_never_constructs_credit() {
        let source = include_str!("recovery_cursor.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("source");
        for forbidden in ["Credit::slice", "Credit {", "usize::MAX"] {
            assert!(
                !production.contains(forbidden),
                "the recovery cursor must not contain `{forbidden}`"
            );
        }
    }
}
