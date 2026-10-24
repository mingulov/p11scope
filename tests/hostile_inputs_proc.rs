//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile `/proc` regression tests: malformed statm/stat/io text must be
//! refused or yield only values the input supports. Untrusted counters
//! never overflow a conversion. (Cgroup membership is `pub(crate)`; its
//! hostile tests live in that module's own test section.)

use p11scope::timing::{parse_io_bytes, parse_stat_cpu_ms, parse_statm_rss_kb};

/// Fixed seed for the mutation loops below; recorded so a failure reproduces.
const STAT_SEED: u64 = 0xC2E1_F00D_0000_0004;
const MUTATIONS: usize = 2000;

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn statm_values_multiply_without_overflow() {
    assert_eq!(parse_statm_rss_kb("100 200 0 0 0 0 0", 4), Some(800));
    assert_eq!(parse_statm_rss_kb("100 0 0 0 0 0 0", 4), Some(0));
    assert_eq!(parse_statm_rss_kb("", 4), None);
    assert_eq!(parse_statm_rss_kb("100", 4), None);
    assert_eq!(parse_statm_rss_kb("100 xx 0 0 0 0 0", 4), None);
    assert_eq!(parse_statm_rss_kb("100 -5 0 0 0 0 0", 4), None);
    assert_eq!(
        parse_statm_rss_kb("100 18446744073709551616 0 0 0 0 0", 4),
        None
    );
    // Counter x page-size overflow refuses instead of wrapping.
    assert_eq!(
        parse_statm_rss_kb("0 18446744073709551615 0 0 0 0 0", 2),
        None
    );
    assert_eq!(
        parse_statm_rss_kb("0 18446744073709551615 0 0 0 0 0", 1),
        Some(u64::MAX)
    );
    // Second field wins even with extra columns or surrounding whitespace.
    assert_eq!(parse_statm_rss_kb("  7\t42  0 ", 1), Some(42));
}

#[test]
fn statm_mutations_match_checked_arithmetic() {
    let mut rng = STAT_SEED;
    for _ in 0..MUTATIONS {
        // Random short whitespace-separated tokens, hostile by construction.
        let fields = 1 + (xorshift64(&mut rng) % 9) as usize;
        let mut tokens = Vec::new();
        for _ in 0..fields {
            tokens.push(match xorshift64(&mut rng) % 8 {
                0 => "0".to_string(),
                1 => "1".to_string(),
                2 => xorshift64(&mut rng).to_string(),
                3 => u64::MAX.to_string(),
                4 => "18446744073709551616".to_string(),
                5 => "-1".to_string(),
                6 => String::new(),
                _ => "abc".to_string(),
            });
        }
        let input = tokens.join(if xorshift64(&mut rng).is_multiple_of(2) {
            " "
        } else {
            "\t"
        });
        let page_kb = match xorshift64(&mut rng) % 5 {
            0 => 0,
            1 => 1,
            2 => 4,
            3 => u64::MAX,
            _ => xorshift64(&mut rng),
        };
        let expected = input
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|token| token.parse::<u64>().ok())
            .and_then(|pages| pages.checked_mul(page_kb));
        assert_eq!(
            parse_statm_rss_kb(&input, page_kb),
            expected,
            "input {input:?} page_kb {page_kb}"
        );
    }
}

fn stat_line(comm: &str, utime: &str, stime: &str) -> String {
    // pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt
    // majflt cmajflt utime stime ... — fields 3..=13 precede utime.
    format!("4242 ({comm}) R 1 1 1 0 0 0 0 0 0 0 {utime} {stime} 0 0 0 0 0")
}

#[test]
fn stat_cpu_counts_from_the_last_paren() {
    assert_eq!(
        parse_stat_cpu_ms(&stat_line("p11scope", "100", "50"), 100),
        Some((1000, 500))
    );
    // Spaces and parentheses inside comm do not shift the fields.
    assert_eq!(
        parse_stat_cpu_ms(&stat_line("my ) proc (x", "100", "50"), 100),
        Some((1000, 500))
    );
    assert_eq!(parse_stat_cpu_ms(&stat_line("p", "100", "50"), 0), None);
    assert_eq!(parse_stat_cpu_ms("no parens here", 100), None);
    assert_eq!(parse_stat_cpu_ms("1 (x) R", 100), None);
    assert_eq!(parse_stat_cpu_ms(&stat_line("p", "xx", "50"), 100), None);
    assert_eq!(parse_stat_cpu_ms(&stat_line("p", "100", "-1"), 100), None);
    // Saturating millisecond conversion: the maximum tick count converts to
    // the maximum millisecond count, never wraps or refuses.
    assert_eq!(
        parse_stat_cpu_ms(&stat_line("p", "18446744073709551615", "0"), 100),
        Some((u64::MAX / 100, 0))
    );
    assert_eq!(
        parse_stat_cpu_ms(
            &stat_line("p", "18446744073709551615", "18446744073709551615"),
            1
        ),
        Some((u64::MAX, u64::MAX))
    );
}

#[test]
fn stat_cpu_mutations_match_saturating_arithmetic() {
    let mut rng = STAT_SEED ^ 0x51a7;
    for _ in 0..MUTATIONS {
        let comm_len = (xorshift64(&mut rng) % 24) as usize;
        let mut comm = String::new();
        for _ in 0..comm_len {
            let byte = (xorshift64(&mut rng) % 96) as u8 + 32;
            comm.push(byte as char);
        }
        let mut token = || match xorshift64(&mut rng) % 7 {
            0 => "0".to_string(),
            1 => "1".to_string(),
            2 => xorshift64(&mut rng).to_string(),
            3 => u64::MAX.to_string(),
            4 => "18446744073709551616".to_string(),
            5 => "-3".to_string(),
            _ => "zz".to_string(),
        };
        let input = stat_line(&comm, &token(), &token());
        let tps = match xorshift64(&mut rng) % 4 {
            0 => 0,
            1 => 1,
            2 => 100,
            _ => xorshift64(&mut rng),
        };
        let expected = (tps != 0)
            .then(|| {
                let after = input.rsplit_once(')')?.1;
                let mut fields = after.split_ascii_whitespace();
                let utime: u64 = fields.nth(11)?.parse().ok()?;
                let stime: u64 = fields.next()?.parse().ok()?;
                Some((
                    utime.saturating_mul(1000).checked_div(tps)?,
                    stime.saturating_mul(1000).checked_div(tps)?,
                ))
            })
            .flatten();
        assert_eq!(
            parse_stat_cpu_ms(&input, tps),
            expected,
            "input {input:?} tps {tps}"
        );
    }
}

#[test]
fn io_bytes_require_both_keys_and_clean_lines() {
    let valid = "rchar: 1\nwchar: 2\nread_bytes: 100\nwrite_bytes: 50\n";
    assert_eq!(parse_io_bytes(valid), Some((100, 50)));
    assert_eq!(parse_io_bytes("read_bytes: 1\n"), None);
    assert_eq!(parse_io_bytes("write_bytes: 1\n"), None);
    assert_eq!(parse_io_bytes(""), None);
    assert_eq!(parse_io_bytes("read_bytes: xx\nwrite_bytes: 1\n"), None);
    assert_eq!(
        parse_io_bytes("read_bytes: 18446744073709551616\nwrite_bytes: 1\n"),
        None
    );
    // A line without a colon fails the whole read closed: partial counters
    // are never reported.
    assert_eq!(
        parse_io_bytes("read_bytes: 1\ngarbage line\nwrite_bytes: 2\n"),
        None
    );
    // Later duplicates win; surrounding whitespace is tolerated.
    assert_eq!(
        parse_io_bytes("read_bytes: 1\nread_bytes:   7  \nwrite_bytes: 2\n"),
        Some((7, 2))
    );
}

#[test]
fn io_mutations_report_only_present_counters() {
    let mut rng = STAT_SEED ^ 0x10b;
    for _ in 0..MUTATIONS {
        let lines = 1 + (xorshift64(&mut rng) % 6) as usize;
        let mut input = String::new();
        for _ in 0..lines {
            match xorshift64(&mut rng) % 8 {
                0 => input.push_str(&format!("read_bytes: {}\n", xorshift64(&mut rng) % 1000)),
                1 => input.push_str(&format!("write_bytes: {}\n", xorshift64(&mut rng) % 1000)),
                2 => input.push_str(&format!("read_bytes: {}\n", u64::MAX)),
                3 => input.push_str("read_bytes: 18446744073709551616\n"),
                4 => input.push_str("other: 5\n"),
                5 => input.push_str("colon-free line\n"),
                6 => input.push_str(":\n"),
                _ => input.push_str("read_bytes: -1\n"),
            }
        }
        if let Some((read, write)) = parse_io_bytes(&input) {
            assert!(
                input.contains(&read.to_string()) && input.contains(&write.to_string()),
                "counters {read}/{write} not present in {input:?}"
            );
        }
    }
}
