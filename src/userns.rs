//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Which user namespace this observer runs in.
//!
//! BPF (`PROG_LOAD`, `MAP_CREATE`, `BPF_LINK_CREATE` for uprobes) checks
//! capabilities in the **initial** user namespace: `capable()` from any
//! non-initial namespace is unconditionally false
//! (`security/commoncap.c`). An observer in a child user namespace — a
//! rootless Docker/Podman container, or any userns without host
//! capabilities — can hold `CAP_BPF` in its own namespace and still
//! load nothing. There is no BPF token yet (planned later), so capture
//! is unavailable there, whatever the effective set claims.
//!
//! Like [`crate::pidns`], the comparison is exact and needs no BPF: the
//! initial user namespace has the fixed nsfs inode `PROC_USER_INIT_INO`
//! (`include/linux/proc_ns.h`), and `/proc/self/ns/user`
//! (`user:[<inode>]`) names the reading task's own namespace. The
//! initial inode → initial; any other inode → nested; unreadable or
//! not a user namespace link → unknown, which every caller treats as
//! unproven (the old diagnostics stand, never the userns cause).

use std::sync::OnceLock;

/// `PROC_USER_INIT_INO`: the nsfs inode of the initial user namespace.
pub const INIT_USER_NS_INODE: u64 = 0xEFFF_FFFD;

/// The stable machine reason for the userns cause, carried by the plain
/// cause line and hence by every JSON gap reason that embeds it.
pub const CAUSE_CODE: &str = "user-namespace-without-host-capabilities";

/// The one plain line every surface names the proven userns cause with:
/// doctor's cause line and row, and every capture refusal. One line, no
/// trailing period (callers punctuate their own sentences around it). The
/// stable code is spelled out (`concat!` takes literals only); the test
/// below pins that this line carries [`CAUSE_CODE`], so the two cannot
/// drift.
pub const CAUSE_LINE: &str = "capture is unavailable here because BPF and uprobes need \
    capabilities in the host user namespace (user-namespace-without-host-capabilities); run \
    p11scope on the host or with the five-capability rootful command (see deploy/README.md)";

/// The `Next:` step while the userns cause is proven: the remedy half of
/// [`CAUSE_LINE`], without the diagnosis the verdict line already states.
pub const NEXT_STEP: &str =
    "run p11scope on the host or with the five-capability rootful command (see deploy/README.md)";

/// Where this observer runs, relative to the namespace BPF judges
/// capabilities in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverUserNs {
    /// The initial user namespace: capabilities held here count for BPF.
    Initial,
    /// A child user namespace: capabilities held here count for nothing
    /// BPF or uprobe-related.
    Nested,
    /// The namespace could not be read. Never treated as proven either way.
    Unknown(String),
}

impl ObserverUserNs {
    /// The published label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Nested => "non-initial",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether the initial namespace is proven (`Some(true)`), a child
    /// namespace is proven (`Some(false)`), or nothing is proven (`None`).
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Initial => Some(true),
            Self::Nested => Some(false),
            Self::Unknown(_) => None,
        }
    }

    /// Whether a child user namespace is proven: the only state that
    /// names the userns cause. Unknown keeps the old diagnostics.
    pub fn is_nested_proven(&self) -> bool {
        matches!(self, Self::Nested)
    }
}

/// Classifies the target of `/proc/self/ns/user` (or why it was unreadable).
///
/// The link text is `user:[<inode>]`. Anything else is not a user
/// namespace link and reads as unknown: the link text is the evidence,
/// never a bare inode.
pub fn classify(link: std::io::Result<String>) -> ObserverUserNs {
    let link = match link {
        Ok(link) => link,
        Err(error) => return ObserverUserNs::Unknown(format!("/proc/self/ns/user: {error}")),
    };
    match parse_user_ns_link(&link) {
        Some(INIT_USER_NS_INODE) => ObserverUserNs::Initial,
        Some(_) => ObserverUserNs::Nested,
        None => ObserverUserNs::Unknown(format!(
            "/proc/self/ns/user: unexpected link {:?}",
            crate::render::escape_controls(&link)
        )),
    }
}

/// `user:[4026531837]` → `4026531837`; any other shape → `None`.
pub fn parse_user_ns_link(link: &str) -> Option<u64> {
    let digits = link.strip_prefix("user:[")?.strip_suffix(']')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Reads this process's user namespace link. `/proc/self` always names the
/// reading task, whichever procfs instance serves it.
fn read_own_userns_link() -> std::io::Result<String> {
    std::fs::read_link("/proc/self/ns/user").map(|link| link.to_string_lossy().into_owned())
}

/// This observer's user namespace. A task's own user namespace never
/// changes for the task itself, so one read serves the whole process.
pub fn observer() -> &'static ObserverUserNs {
    static OBSERVER: OnceLock<ObserverUserNs> = OnceLock::new();
    OBSERVER.get_or_init(|| classify(read_own_userns_link()))
}

/// Whether this process runs in the initial user namespace; `None` when
/// `/proc/self/ns/user` was unreadable or not a user namespace link.
pub fn in_init_user_ns() -> Option<bool> {
    observer().as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reads_initial_nested_and_unknown() {
        assert_eq!(
            classify(Ok("user:[4026531837]".to_string())),
            ObserverUserNs::Initial
        );
        assert_eq!(
            classify(Ok("user:[4026532001]".to_string())),
            ObserverUserNs::Nested
        );
        assert!(matches!(
            classify(Ok("pid:[4026531837]".to_string())),
            ObserverUserNs::Unknown(_)
        ));
        assert!(matches!(
            classify(Err(std::io::Error::from_raw_os_error(libc::EACCES))),
            ObserverUserNs::Unknown(_)
        ));
        assert_eq!(
            parse_user_ns_link("user:[4026531837]"),
            Some(INIT_USER_NS_INODE)
        );
    }

    #[test]
    fn cause_line_is_one_plain_line_with_the_stable_code() {
        assert_eq!(CAUSE_LINE.lines().count(), 1);
        assert!(CAUSE_LINE.contains(CAUSE_CODE), "{CAUSE_LINE}");
        assert!(
            CAUSE_LINE.starts_with("capture is unavailable here because BPF and uprobes need"),
            "{CAUSE_LINE}"
        );
        assert!(CAUSE_LINE.contains("deploy/README.md"), "{CAUSE_LINE}");
        assert!(CAUSE_LINE.len() < 1024, "{CAUSE_LINE}");
        assert!(NEXT_STEP.len() < 256, "{NEXT_STEP}");
    }
}
