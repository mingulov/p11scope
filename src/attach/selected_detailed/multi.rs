//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native leaves enter Session custody before bisect can encounter another error.
pub(in crate::attach) fn retain_success<T, E>(
    result: Result<T, E>,
    retain: impl FnOnce(T),
) -> Result<(), E> {
    result.map(retain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_bpf_multi::{GroupHalt, bisect_attach};
    use std::os::fd::{AsRawFd as _, OwnedFd};

    #[test]
    fn partial_bisect_success_then_unsupported_or_exhausted_retains_actual_fd() {
        for errno in [libc::EOPNOTSUPP, libc::EMFILE] {
            // A pinned unique object: the live link keeps this inode from
            // being recycled, so the post-drop identity check cannot meet
            // another test's fd with the same (dev, ino). Every open of
            // /dev/null would share one identity across the parallel suite.
            let anchor = tempfile::NamedTempFile::new().unwrap();
            let mut owned: Vec<OwnedFd> = Vec::new();
            let mut calls = 0;
            let sites = [(0, 0), (1, 1), (2, 2), (3, 3)];
            let result = bisect_attach(
                &mut |slice| {
                    calls += 1;
                    let acquired = if slice.len() == 4 {
                        Err(std::io::Error::from_raw_os_error(libc::EINVAL))
                    } else if slice[0].0 == 0 {
                        Ok(std::fs::File::open(anchor.path()).unwrap().into())
                    } else {
                        Err(std::io::Error::from_raw_os_error(errno))
                    };
                    retain_success(acquired, |fd| owned.push(fd))
                },
                &sites,
            );
            assert!(matches!(
                result,
                Err(GroupHalt::Unsupported(_)) | Err(GroupHalt::Exhausted(_))
            ));
            assert_eq!(calls, 3);
            assert_eq!(owned.len(), 1);
            let original_fd = owned[0].as_raw_fd();
            assert!(
                unsafe { libc::fcntl(original_fd, libc::F_GETFD) } >= 0,
                "bisect halt must not close an acquired native owner"
            );
            // The fd number may be reused by a parallel test the moment
            // `owned` drops, so prove closure by object identity instead:
            // afterwards the number is free or names a different object.
            let identity = crate::discovery::identity::test_fixture::record_open_fd(original_fd);
            drop(owned);
            crate::discovery::identity::test_fixture::assert_fd_closed(original_fd, identity);
            drop(anchor);
        }
    }

    #[test]
    fn mixed_singleton_refusal_keeps_successful_leaves_after_unit_bundles_drop() {
        let mut owned: Vec<OwnedFd> = Vec::new();
        let sites = [(0, 0), (1, 1), (2, 2), (3, 3)];
        let result = bisect_attach(
            &mut |slice| {
                let acquired = if slice.len() > 1 {
                    Err(std::io::Error::from_raw_os_error(libc::EINVAL))
                } else if slice[0].0 == 2 {
                    Err(std::io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    Ok(std::fs::File::open("/dev/null").unwrap().into())
                };
                retain_success(acquired, |fd| owned.push(fd))
            },
            &sites,
        )
        .unwrap();
        assert_eq!(result.0.len(), 3);
        assert_eq!(result.1.len(), 1);
        assert_eq!(result.1[0].index, 2);
        drop(result);
        assert_eq!(owned.len(), 3);
        assert!(
            owned
                .iter()
                .all(|fd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0)
        );
    }
}
