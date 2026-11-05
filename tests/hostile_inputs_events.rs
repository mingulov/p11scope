//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile event-record regression tests: ring-buffer bytes of the wrong
//! length or with an invalid root affiliation must decode to `None`, and
//! every decoded event must carry an affiliation the gate allowed. Length
//! and affiliation are the only gates; all other field values pass through.

use p11scope::events::decode;

/// Fixed seed for the mutation loop below; recorded so a failure reproduces.
const MUTATION_SEED: u64 = 0xC2E1_F00D_0000_0003;
const MUTATIONS: usize = 2000;

/// The exact record length `decode` accepts, found without layout knowledge:
// all-zero bytes carry affiliation 0 and decode only at the true length.
fn record_len() -> usize {
    let mut found = None;
    for len in 0..4096 {
        if decode(&vec![0u8; len]).is_some() {
            assert_eq!(found, None, "decode accepted two lengths");
            found = Some(len);
        }
    }
    found.expect("decode must accept exactly one length below 4096")
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn only_the_exact_length_decodes() {
    let len = record_len();
    assert!(len > 64, "record length {len} is implausibly small");
    for candidate in 0..len + 65 {
        assert_eq!(
            decode(&vec![0u8; candidate]).is_some(),
            candidate == len,
            "length {candidate} (record length {len})"
        );
    }
    for candidate in [len + 4096, len + 1024 * 1024] {
        assert!(
            decode(&vec![0u8; candidate]).is_none(),
            "oversize length {candidate} must not decode"
        );
    }
    assert!(decode(&[]).is_none());
}

#[test]
fn only_affiliation_zero_and_one_decode() {
    let len = record_len();
    // Probe every byte: setting it to 2 must break decoding exactly on the
    // affiliation field and nowhere else.
    let mut gating = Vec::new();
    for offset in 0..len {
        let mut bytes = vec![0u8; len];
        bytes[offset] = 2;
        if decode(&bytes).is_none() {
            gating.push(offset);
        }
    }
    assert_eq!(
        gating.len(),
        8,
        "exactly the 8 affiliation bytes must gate decoding: {gating:?}"
    );
    for window in gating.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "affiliation bytes must be contiguous"
        );
    }
    let base = gating[0];
    for value in [0u64, 1] {
        let mut bytes = vec![0u8; len];
        bytes[base..base + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            decode(&bytes).is_some_and(|event| event.root_affiliation == value),
            "affiliation {value} must decode with its value intact"
        );
    }
    for value in [2u64, 3, 0xff, 0x100, u64::MAX - 1, u64::MAX] {
        let mut bytes = vec![0u8; len];
        bytes[base..base + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            decode(&bytes).is_none(),
            "affiliation {value} must not decode"
        );
    }
    // Big-endian placement of the same values must not smuggle past the gate:
    // bytes 2..=255 anywhere in the field still refuse.
    let mut bytes = vec![0u8; len];
    bytes[base + 7] = 1;
    assert!(
        decode(&bytes).is_none(),
        "affiliation 0x0100_0000_0000_0000 must not decode"
    );
}

#[test]
fn seeded_mutations_decode_only_with_a_valid_affiliation() {
    let len = record_len();
    let seed = vec![0u8; len];
    let mut rng = MUTATION_SEED;
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for _ in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut bytes = seed.clone();
        for _ in 0..flips {
            let offset = (xorshift64(&mut rng) % len as u64) as usize;
            bytes[offset] = (xorshift64(&mut rng) % 256) as u8;
        }
        match decode(&bytes) {
            Some(event) => {
                accepted += 1;
                assert!(
                    event.root_affiliation <= 1,
                    "decoded an event with affiliation {}",
                    event.root_affiliation
                );
            }
            None => refused += 1,
        }
        // Truncation and extension of the same mutant never decode.
        for end in [0, 1, len - 1, len + 1] {
            let mut framed = bytes.clone();
            framed.resize(end, 0xaa);
            if end == len {
                continue;
            }
            assert!(
                decode(&framed).is_none(),
                "mutant at wrong length {end} must not decode"
            );
        }
    }
    assert_eq!(refused + accepted, MUTATIONS);
    assert!(
        refused > 0 && accepted > 0,
        "both outcomes must occur (refused {refused}, accepted {accepted})"
    );
}
