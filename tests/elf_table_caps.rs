//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! ELF table caps end to end: a mapped file with a giant
//! program-header table refuses with its named gap instead of
//! blowing up the observer's memory (B1).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;
use support::DieWithParent as _;

#[allow(dead_code)]
mod support;

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct OwnedTarget(Child);
impl Drop for OwnedTarget {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A valid-ELF64 file with `segments` executable PT_LOAD segments with
/// distinct biases and in-bounds ranges: without the table gate the
/// export parse builds one map entry per segment plus one range per
/// executable segment. 2M segments is 112 MiB on disk.
fn write_many_load_elf(path: &Path, segments: u32) {
    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&2u16.to_le_bytes());
    header[18..20].copy_from_slice(&62u16.to_le_bytes());
    header[20..24].copy_from_slice(&1u32.to_le_bytes());
    header[52..54].copy_from_slice(&64u16.to_le_bytes());
    header[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum tops out at 65534 without the extended encoding; the
    // count here rides section 0's sh_info instead.
    header[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
    header[58..60].copy_from_slice(&64u16.to_le_bytes());
    let phoff = 128u64;
    header[32..40].copy_from_slice(&phoff.to_le_bytes());
    header[40..48].copy_from_slice(&64u64.to_le_bytes());
    let mut section0 = [0u8; 64];
    section0[44..48].copy_from_slice(&segments.to_le_bytes());
    let file = std::fs::File::create(path).unwrap();
    let mut out = std::io::BufWriter::new(file);
    out.write_all(&header).unwrap();
    out.write_all(&section0).unwrap();
    let mut phdr = [0u8; 56];
    phdr[0..4].copy_from_slice(&1u32.to_le_bytes());
    phdr[4..8].copy_from_slice(&5u32.to_le_bytes());
    phdr[32..40].copy_from_slice(&1u64.to_le_bytes());
    phdr[40..48].copy_from_slice(&1u64.to_le_bytes());
    phdr[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
    for index in 0..segments {
        let vaddr = u64::from(index) * 0x1000;
        phdr[16..24].copy_from_slice(&vaddr.to_le_bytes());
        // file_range (0, 1): in bounds, distinct bias per segment.
        out.write_all(&phdr).unwrap();
    }
    out.flush().unwrap();
}

/// Spawn `cmd` while sampling its peak RSS from `/proc/<pid>/status`.
/// `VmHWM` is kernel-tracked peak, so the max over 5 ms samples is the
/// run's peak. Mirrors `inventory_scale::spawn_with_peak`: stderr goes
/// to a file, stdout is drained mid-run.
fn spawn_with_peak(cmd: &mut Command, stderr_log: &Path) -> (std::process::Output, u64) {
    cmd.stderr(std::fs::File::create(stderr_log).unwrap());
    cmd.stdout(std::process::Stdio::piped());
    cmd.die_with_parent();
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    let stdout = child.stdout.take().expect("piped stdout");
    let drain = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdout = stdout;
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).expect("drain stdout");
        bytes
    });
    let mut peak = 0u64;
    loop {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:")
                    && let Some(kb) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                {
                    peak = peak.max(kb * 1024);
                }
            }
        }
        match child.try_wait().unwrap() {
            Some(_) => break,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let mut output = child.wait_with_output().unwrap();
    output.stdout = drain.join().expect("stdout drain thread");
    (output, peak)
}

/// Map `path` executable in a helper process. Candidate groups need an
/// `x` mapping, so plain `ACCESS_READ` would never be parsed.
fn spawn_mapper(path: &Path) -> OwnedTarget {
    let script = format!(
        "import mmap, time; f = open({path:?}, 'rb'); \
         m = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_PRIVATE, \
         prot=mmap.PROT_READ | mmap.PROT_EXEC); time.sleep(120)"
    );
    let child = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .die_with_parent()
        .spawn()
        .expect("spawn the mapping helper");
    let target = OwnedTarget(child);
    let pid = target.0.id();
    let needle = path.to_string_lossy().into_owned();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            && maps
                .lines()
                .any(|line| line.contains(" r-x") && line.contains(needle.as_str()))
        {
            return target;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the helper never mapped {needle} executable");
}

/// B1: a 112 MiB program-header table (2M segments) refuses with its
/// named gap; the observer's peak RSS stays far below the ungated
/// parse (563 MiB here, about 1 GiB for a 224 MiB table in the
/// reviewer's probe). Scan mode parses mapped files without capture
/// privileges; plain `inspect` stays maps-only unprivileged.
#[test]
fn giant_program_table_refuses_with_a_named_gap_under_an_rss_bound() {
    let d = tmp("elf-table-cap-product");
    let path = d.join("many-loads.so");
    write_many_load_elf(&path, 2_000_000);
    let target = spawn_mapper(&path);
    let pid = target.0.id().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    cmd.args([
        "inventory",
        "--pid",
        &pid,
        "--capture",
        "scan",
        "--duration",
        "5s",
    ]);
    let (output, peak) = spawn_with_peak(&mut cmd, &d.join("stderr.log"));
    drop(target);
    let _ = std::fs::remove_dir_all(&d);
    assert!(
        output.status.success(),
        "inventory must stay up: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ELF program-header table is 112000000 bytes; limit is 65536"),
        "the named gap must surface, got:\n{stdout}"
    );
    assert!(
        peak < 256 << 20,
        "peak RSS {peak} exceeds the 256 MiB bound"
    );
}

/// Sparse Mach-O 64 with `nsects` sections: 104 header bytes on disk,
/// the section headers a sparse hole. 16M sections is 1.28 GB
/// logical (4 KiB on disk); without the C1 gate the Mach-O parse
/// builds one entry per section (653 MB anonymous, 2.0 GB peak RSS
/// end to end in the reviewer's probe).
fn write_sparse_macho(path: &Path, nsects: u32) {
    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    header[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    header[8..12].copy_from_slice(&3u32.to_le_bytes());
    header[12..16].copy_from_slice(&2u32.to_le_bytes());
    header[16..20].copy_from_slice(&1u32.to_le_bytes());
    let sizeofcmds = 72u32.saturating_add(nsects.saturating_mul(80));
    header[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    let mut segment = [0u8; 72];
    segment[0..4].copy_from_slice(&0x19u32.to_le_bytes());
    segment[4..8].copy_from_slice(&sizeofcmds.to_le_bytes());
    segment[56..60].copy_from_slice(&5u32.to_le_bytes());
    segment[60..64].copy_from_slice(&5u32.to_le_bytes());
    segment[64..68].copy_from_slice(&nsects.to_le_bytes());
    let file = std::fs::File::create(path).unwrap();
    let mut out = std::io::BufWriter::new(&file);
    out.write_all(&header).unwrap();
    out.write_all(&segment).unwrap();
    out.flush().unwrap();
    drop(out);
    let logical = 32u64
        .saturating_add(72)
        .saturating_add(u64::from(nsects).saturating_mul(80));
    file.set_len(logical).unwrap();
}

/// C1: a 1.28 GB sparse Mach-O (16M sections, 4 KiB on disk) refuses
/// with its legacy gap before any parse; the observer's peak RSS
/// stays under the 256 MiB bound (2.0 GB ungated in the probe).
#[test]
fn sparse_macho_refuses_with_a_named_gap_under_an_rss_bound() {
    let d = tmp("elf-c1-macho-product");
    let path = d.join("sparse-macho");
    write_sparse_macho(&path, 16_000_000);
    let target = spawn_mapper(&path);
    let pid = target.0.id().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    cmd.args([
        "inventory",
        "--pid",
        &pid,
        "--capture",
        "scan",
        "--duration",
        "5s",
    ]);
    let (output, peak) = spawn_with_peak(&mut cmd, &d.join("stderr.log"));
    drop(target);
    let _ = std::fs::remove_dir_all(&d);
    assert!(
        output.status.success(),
        "inventory must stay up: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not an ELF object (MachO)"),
        "the legacy gap must surface, got:\n{stdout}"
    );
    assert!(
        peak < 256 << 20,
        "peak RSS {peak} exceeds the 256 MiB bound"
    );
}
