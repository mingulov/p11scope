//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7-E shared adapter core: instrumented target memory plus the exact
//! read-log assertions shared by the object-producer adapter regressions.
//! Suite-local mirrors (continuity stamps, argument spies, root sequencing)
//! live in the owning suite file so every helper here is used by every
//! suite that includes it and `dead_code` stays armed.
//!
//! Every test built on this fixture calls REAL production protocol code
//! (`p11scope_ebpf_common::object_capture`, `instance::stamp_joinable`,
//! `read_ia32_arg_with`) with instrumented readers and asserts exact read
//! sets. Each mirror states the exact `crates/ebpf/src/main.rs` lines it
//! tracks, and a source-shape pin in the owning test binds the mirror to
//! the root. A moved gate fails the read counters even if the emitted tail
//! is later suppressed.

use p11scope_ebpf_common::object_capture::{CKR_OK, ReturnAuthority};
use std::cell::RefCell;

pub const READ_WORD: u8 = 0;
pub const READ_BYTES: u8 = 1;

/// Instrumented fake target memory. Unprogrammed addresses fail: every
/// successful read is explicit test setup, and the log proves which
/// addresses (and byte lengths) the production protocol touched.
pub struct FakeTarget {
    word_len: u64,
    words: Vec<(u64, u64)>,
    bytes: Vec<(u64, u8)>,
    failing: Vec<u64>,
    log: Vec<(u8, u64, u64)>,
}

impl FakeTarget {
    pub fn new(word_len: u64) -> Self {
        Self {
            word_len,
            words: Vec::new(),
            bytes: Vec::new(),
            failing: Vec::new(),
            log: Vec::new(),
        }
    }

    pub fn set_word(&mut self, addr: u64, value: u64) {
        self.words.push((addr, value));
    }

    pub fn set_bytes(&mut self, addr: u64, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            self.bytes.push((addr + i as u64, *byte));
        }
    }

    pub fn set_fail(&mut self, addr: u64) {
        self.failing.push(addr);
    }

    fn lookup_word(&self, addr: u64) -> Option<u64> {
        self.words
            .iter()
            .rev()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
    }

    fn lookup_byte(&self, addr: u64) -> Option<u8> {
        self.bytes
            .iter()
            .rev()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
    }

    pub fn read_word(&mut self, addr: u64) -> Result<u64, ()> {
        self.log.push((READ_WORD, addr, self.word_len));
        if self.failing.contains(&addr) {
            return Err(());
        }
        self.lookup_word(addr).ok_or(())
    }

    pub fn read_bytes(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), ()> {
        self.log.push((READ_BYTES, addr, buf.len() as u64));
        if self.failing.contains(&addr) {
            return Err(());
        }
        for (i, slot) in buf.iter_mut().enumerate() {
            let byte_addr = addr.checked_add(i as u64).ok_or(())?;
            *slot = self.lookup_byte(byte_addr).ok_or(())?;
        }
        Ok(())
    }

    /// One little-endian u32 load for ia32 argument-stack modeling.
    /// Used by the adapters suite's `ArgSpy`; allowed dead for suites
    /// that share this file without argument modeling.
    #[allow(dead_code)]
    pub fn read_u32(&mut self, addr: u64) -> Result<u32, ()> {
        let mut buf = [0u8; 4];
        self.read_bytes(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn log(&self) -> &[(u8, u64, u64)] {
        &self.log
    }

    pub fn reads_of(&self, addr: u64) -> usize {
        self.log.iter().filter(|(_, a, _)| *a == addr).count()
    }
}

#[allow(clippy::type_complexity)]
pub fn readers(
    target: &RefCell<FakeTarget>,
) -> (
    impl FnMut(u64) -> Result<u64, ()> + '_,
    impl FnMut(u64, &mut [u8]) -> Result<(), ()> + '_,
) {
    (
        |addr: u64| target.borrow_mut().read_word(addr),
        |addr: u64, buf: &mut [u8]| target.borrow_mut().read_bytes(addr, buf),
    )
}

/// CKR_OK alias for readability at fixture call sites.
pub fn rv_ok() -> u64 {
    CKR_OK
}

/// Fully authorized return authority (live owner, ready phase). The
/// continuity conjunct arrives with the E1 fix.
pub fn owner_ready_authority() -> ReturnAuthority {
    ReturnAuthority::AUTHORIZED
}

pub fn assert_no_target_reads(target: &RefCell<FakeTarget>, what: &str) {
    assert_eq!(
        target.borrow().log(),
        &[],
        "{what} must perform zero target reads"
    );
}
