//! SPDX-License-Identifier: GPL-3.0-or-later
//! Integer-only selected bootstrap wire decoder. This grants no admission.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct SelectedTarget {
    pub mode: u32,
    pub tgid: u32,
    pub cookie: u64,
    pub exec_id: u64,
    pub parent_kind: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct BootstrapControl {
    pub generation: u64,
    pub deadline_ns: u64,
    pub visit_limit: u64,
    pub visits: u64,
    pub emitted: u64,
    pub failed: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BootstrapImage {
    pub cookie: u64,
    pub exec_id: u64,
    pub visits: u64,
}
const _: () = assert!(size_of::<SelectedTarget>() == 32);
const _: () = assert!(size_of::<BootstrapControl>() == 48);
pub(super) fn parse_bootstrap(
    bytes: &[u8],
    generation: u64,
    tgid: u32,
    limit: u64,
) -> Option<BootstrapImage> {
    if bytes.len() != 80 || generation == 0 || tgid == 0 || !(2..=65536).contains(&limit) {
        return None;
    }
    let word = |row: &[u8], at: usize| u64::from_ne_bytes(row[at..at + 8].try_into().unwrap());
    let half = |row: &[u8], at: usize| u32::from_ne_bytes(row[at..at + 4].try_into().unwrap());
    let first = &bytes[..40];
    let end = &bytes[40..];
    let cookie = word(first, 8);
    let visits = word(end, 24);
    if word(first, 0) != generation
        || word(end, 0) != generation
        || half(first, 32) != tgid
        || half(end, 32) != tgid
        || half(first, 36) != 1
        || half(end, 36) != 2
        || !(1..=16384).contains(&cookie)
        || word(end, 8) != 0
        || word(end, 16) != 0
        || word(first, 24) == 0
        || visits <= word(first, 24)
        || visits > limit
    {
        return None;
    }
    Some(BootstrapImage {
        cookie,
        exec_id: word(first, 16),
        visits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(
        generation: u64,
        cookie: u64,
        exec: u64,
        visits: u64,
        tgid: u32,
        status: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [generation, cookie, exec, visits] {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.extend_from_slice(&tgid.to_ne_bytes());
        bytes.extend_from_slice(&status.to_ne_bytes());
        bytes
    }
    fn healthy(exec: u64) -> Vec<u8> {
        let mut bytes = row(4, 7, exec, 1, 400, 1);
        bytes.extend(row(4, 0, 0, 2, 400, 2));
        bytes
    }
    #[test]
    fn bootstrap_requires_exact_identity_and_terminal_rows() {
        for exec in [0, 0x8000_0000_0000_0001] {
            let image = parse_bootstrap(&healthy(exec), 4, 400, 8).unwrap();
            assert_eq!((image.cookie, image.exec_id, image.visits), (7, exec, 2));
        }
        let good = healthy(0);
        for bytes in [&good[..40], &good[..79], &good[..0]] {
            assert!(parse_bootstrap(bytes, 4, 400, 8).is_none());
        }
        assert!(parse_bootstrap(&good, 5, 400, 8).is_none());
        assert!(parse_bootstrap(&good, 4, 401, 8).is_none());
        assert!(parse_bootstrap(&good, 4, 400, 1).is_none());
        for replacement in [
            row(4, 7, 0, 2, 400, 1),
            row(4, 0, 0, 2, 400, 9),
            row(4, 0, 1, 2, 400, 2),
        ] {
            let mut bytes = good[..40].to_vec();
            bytes.extend(replacement);
            assert!(parse_bootstrap(&bytes, 4, 400, 8).is_none());
        }
        let mut zero_cookie = good.clone();
        zero_cookie[8..16].fill(0);
        assert!(parse_bootstrap(&zero_cookie, 4, 400, 8).is_none());
    }
}

pub(super) struct BaselineImage {
    pub cookie: u64,
    pub exec_id: u64,
}
pub(super) struct ParsedBaseline {
    pub images: Vec<BaselineImage>,
    pub visits: u64,
}
pub(super) fn parse_baseline(
    bytes: &[u8],
    generation: u64,
    count: usize,
    limit: u64,
) -> Option<ParsedBaseline> {
    if generation == 0
        || !(1..=1024).contains(&count)
        || bytes.len() != (count + 1) * 40
        || !(2..=65536).contains(&limit)
    {
        return None;
    }
    let word = |row: &[u8], at: usize| u64::from_ne_bytes(row[at..at + 8].try_into().unwrap());
    let half = |row: &[u8], at: usize| u32::from_ne_bytes(row[at..at + 4].try_into().unwrap());
    let end = &bytes[count * 40..];
    let visits = word(end, 24);
    if word(end, 0) != generation
        || word(end, 8) != 0
        || word(end, 16) != 0
        || half(end, 32) as usize != count
        || half(end, 36) != 2
        || visits < count as u64 + 1
        || visits > limit
    {
        return None;
    }
    let mut images: Vec<Option<BaselineImage>> = (0..count).map(|_| None).collect();
    let mut cookies = std::collections::BTreeSet::new();
    let mut last_visit = 0;
    for row in bytes[..count * 40].chunks_exact(40) {
        let slot = half(row, 32) as usize;
        let cookie = word(row, 8);
        let visit = word(row, 24);
        if word(row, 0) != generation
            || half(row, 36) != 1
            || slot >= count
            || images[slot].is_some()
            || !(1..=16384).contains(&cookie)
            || !cookies.insert(cookie)
            || visit <= last_visit
            || visit >= visits
        {
            return None;
        }
        images[slot] = Some(BaselineImage {
            cookie,
            exec_id: word(row, 16),
        });
        last_visit = visit;
    }
    Some(ParsedBaseline {
        images: images.into_iter().collect::<Option<Vec<_>>>()?,
        visits,
    })
}

#[cfg(test)]
mod baseline_tests {
    use super::*;
    fn row(cookie: u64, exec_id: u64, visits: u64, slot: u32, status: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [9u64, cookie, exec_id, visits] {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.extend_from_slice(&slot.to_ne_bytes());
        bytes.extend_from_slice(&status.to_ne_bytes());
        bytes
    }
    #[test]
    fn baseline_requires_complete_unique_order_independent_slots() {
        let mut good = row(8, 0x8000000000000001, 1, 1, 1);
        good.extend(row(7, 0, 2, 0, 1));
        good.extend(row(0, 0, 3, 2, 2));
        let parsed = parse_baseline(&good, 9, 2, 65536).unwrap();
        assert_eq!((parsed.images[0].cookie, parsed.images[0].exec_id), (7, 0));
        assert_eq!(parsed.images[1].exec_id, 0x8000000000000001);
        assert!(parse_baseline(&good[..80], 9, 2, 65536).is_none());
        assert!(parse_baseline(&good, 8, 2, 65536).is_none());
        assert!(parse_baseline(&good, 9, 2, 2).is_none());
        let mut duplicate = good.clone();
        duplicate[72..76].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_baseline(&duplicate, 9, 2, 65536).is_none());
        let mut cookie_duplicate = good.clone();
        cookie_duplicate[48..56].copy_from_slice(&8u64.to_ne_bytes());
        assert!(parse_baseline(&cookie_duplicate, 9, 2, 65536).is_none());
    }
}
