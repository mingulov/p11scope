//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retain each actual producer before attempting the next acquisition.
pub(super) fn attach_retained_with<T, E>(
    owners: &mut Vec<T>,
    mut attach: impl FnMut(&'static str) -> Result<T, E>,
) -> Result<(), E> {
    for program in ["sched_process_exec", "sched_process_exit", "task_newtask"] {
        owners.push(attach(program)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct NativeOwner(Arc<AtomicUsize>);
    impl Drop for NativeOwner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn every_partial_lifecycle_failure_keeps_acquired_owners_for_terminal_transfer() {
        for fail_at in 0..3 {
            let closed = Arc::new(AtomicUsize::new(0));
            let mut retained = Vec::new();
            let mut attempted = 0;
            let result = attach_retained_with(&mut retained, |_| {
                let index = attempted;
                attempted += 1;
                if index == fail_at {
                    Err(())
                } else {
                    Ok(NativeOwner(Arc::clone(&closed)))
                }
            });
            assert!(result.is_err());
            assert_eq!(attempted, fail_at + 1);
            assert_eq!(retained.len(), fail_at);
            assert_eq!(
                closed.load(Ordering::SeqCst),
                0,
                "failure must not inline-drop acquired producers"
            );
            // The terminal owner receives exactly the same acquired owners.
            let transferred = std::mem::take(&mut retained);
            assert_eq!(closed.load(Ordering::SeqCst), 0);
            drop(transferred);
            assert_eq!(closed.load(Ordering::SeqCst), fail_at);
        }
    }
}
