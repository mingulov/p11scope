//! SPDX-License-Identifier: GPL-3.0-or-later
//! D4 ext4 cells: a recycled inode number never joins a stale holder to
//! the new file. The recycled row exits the original holder, deletes and
//! re-creates the path (different bytes, same number), maps the new file
//! in a new holder, and refuses the stale sweep on both backends; the
//! equal-bytes twin proves identical content still refuses. The live-copy
//! row maps a byte-identical copy under a fresh number while the holder
//! lives and refuses it on both backends. A separate
//! deleted-mapping row pins the live ` (deleted)` refusal (temp+rename
//! takes a fresh number, so that row is not inode reuse). Most ext4 rows
//! are identity-keyed (no per-range proof) and classify "no kernel proof
//! (identity key)"; the deleted-mapping row binds the replacement under
//! the stale key, so its key stays per-range and the leg classifies "no
//! kernel proof (unusable line)" — the unusable line refuses before any
//! proof runs. Every leg runs zero targets — never kernel parity. Each
//! privileged row also records its BRSV (stat-vs-map_files
//! pair) and fails closed when the rendering changes. Where the BTF
//! gate refuses (5.15 included) the cell fails closed at that check;
//! no shutdown leg runs there.

use super::*;
use std::time::{Duration, Instant};

/// Named-precondition gate: root (loop mounts), loop, mkfs.ext4 and
/// the map_files capability. Any miss FAILS with its name; nothing
/// here ever skips.
fn ext4_preflight() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("EXT4-PREFLIGHT root: loop mounts and map_files need root".into());
    }
    if std::fs::metadata("/dev/loop-control").is_err() {
        return Err("EXT4-PREFLIGHT loop: /dev/loop-control is missing".into());
    }
    if !mkfs_ext4_present() {
        return Err("EXT4-PREFLIGHT mkfs.ext4: no mkfs.ext4 on PATH".into());
    }
    probe_map_files_capability()
}

fn mkfs_ext4_present() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join("mkfs.ext4").is_file())
    })
}

/// Open one of this process's own file-map map_files entries: without
/// the capability no range proof is possible. Only real file lines
/// count as attempts.
fn probe_map_files_capability() -> Result<(), String> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("EXT4-PREFLIGHT map_files: /proc/self/maps: {error}"))?;
    let mut tried = 0;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let pathname = fields.nth(4).unwrap_or("");
        if !pathname.contains('/') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        tried += 1;
        let entry = format!("/proc/self/map_files/{start}-{end}");
        match std::fs::File::open(&entry) {
            Ok(_) => return Ok(()),
            Err(error) if tried < 8 => {
                use std::io::ErrorKind as Kind;
                match error.kind() {
                    Kind::NotFound => continue,
                    _ => {
                        return Err(format!("EXT4-PREFLIGHT map_files: {entry}: {error}"));
                    }
                }
            }
            Err(error) => {
                return Err(format!("EXT4-PREFLIGHT map_files: {entry}: {error}"));
            }
        }
    }
    Err(format!(
        "EXT4-PREFLIGHT map_files: no provable file mapping found ({tried} tried)"
    ))
}

/// Whether the running kernel predates 6.x (the denial path asserts
/// a probe failure there instead of qualifying the cell; the BTF gate
/// still refuses first where BTF is ineligible).
fn ext4_pre_6() -> Result<bool, String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|error| format!("EXT4-PREFLIGHT kernel-release: {error}"))?;
    let major = release
        .trim()
        .split('.')
        .next()
        .ok_or_else(|| format!("EXT4-PREFLIGHT kernel-release: no major in {release:?}"))?;
    let major: u64 = major
        .parse()
        .map_err(|_| format!("EXT4-PREFLIGHT kernel-release: no major in {release:?}"))?;
    Ok(major < 6)
}

/// One side of a BRSV (stat-vs-map_files pair): the identity numbers
/// plus the staleness witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ext4Stat {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_secs: i64,
    mtime_nanos: i64,
}

impl Ext4Stat {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mtime_secs: metadata.mtime(),
            mtime_nanos: metadata.mtime_nsec(),
        }
    }
}

/// Ground truth recorded per side: the rendered maps line, the
/// map_files stat, the path stat (the BRSV pair) and the statfs magic.
struct Ext4Truth {
    maps_line: String,
    map_files: Ext4Stat,
    path_stat: Ext4Stat,
    statfs_magic: u64,
}

impl Ext4Truth {
    /// The maps key of the recorded line, parsed with the production
    /// parser (a line that refuses to parse fails the row, never joins
    /// by luck).
    fn maps_key(&self) -> ObjectKey {
        let entries = p11scope_manifest::maps::parse_maps(self.maps_line.as_bytes())
            .expect("recorded maps line parses");
        assert_eq!(entries.len(), 1, "one recorded line");
        ObjectKey::of(&entries[0])
    }

    /// The BRSV agrees on identity and staleness: one live file.
    fn brsv_equal(&self) -> bool {
        self.map_files == self.path_stat
    }

    /// The BRSV agrees on identity numbers alone: recycled or live.
    fn brsv_ino_equal(&self) -> bool {
        self.map_files.dev == self.path_stat.dev && self.map_files.ino == self.path_stat.ino
    }
}

/// Record ground truth for one mapped range of `pid`: the actual
/// /proc/<pid>/maps line, the map_files stat, the path stat and the
/// map_files statfs magic.
fn record_ext4_truth(
    pid: u32,
    range: (u64, u64),
    path: &std::path::Path,
) -> Result<Ext4Truth, String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|error| format!("ext4 truth maps {pid}: {error}"))?;
    let prefix = format!("{:x}-{:x} ", range.0, range.1);
    let maps_line = maps
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("ext4 truth: no maps line for {prefix:?} of {pid}"))?
        .to_string();
    let entry = format!("/proc/{pid}/map_files/{:x}-{:x}", range.0, range.1);
    let map_files = std::fs::metadata(&entry)
        .map_err(|error| format!("ext4 truth map_files {entry}: {error}"))?;
    let path_stat = std::fs::metadata(path)
        .map_err(|error| format!("ext4 truth path {}: {error}", path.display()))?;
    Ok(Ext4Truth {
        maps_line,
        map_files: Ext4Stat::of(&map_files),
        path_stat: Ext4Stat::of(&path_stat),
        statfs_magic: statfs_magic(&entry)?,
    })
}

fn statfs_magic(path: &str) -> Result<u64, String> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_path =
        std::ffi::CString::new(path).map_err(|error| format!("ext4 statfs path: {error}"))?;
    // SAFETY: a valid path with a writable buffer, read only on success.
    if unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "ext4 statfs {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: initialized by the successful statfs.
    Ok(unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff)
}

/// The live-side BRSV: identity and staleness all agree.
fn assert_brsv_live(truth: &Ext4Truth) -> Result<(), String> {
    if !truth.brsv_equal() {
        return Err(format!(
            "ext4 BRSV: live side must agree, map_files {:?} vs path {:?}",
            truth.map_files, truth.path_stat
        ));
    }
    Ok(())
}

/// The replaced-path BRSV with a FRESH number: map_files still names
/// the old (deleted) file while the path names its temp+rename
/// replacement. A recycled number here would fail the row — a live
/// deleted-mapping holder and a recycled number cannot coexist.
fn assert_brsv_changed(truth: &Ext4Truth) -> Result<(), String> {
    if truth.brsv_ino_equal() {
        return Err(format!(
            "ext4 BRSV: temp+rename must take a fresh number, map_files {:?} vs path {:?}",
            truth.map_files, truth.path_stat
        ));
    }
    Ok(())
}

/// One-token BRSV summary for the verdict log.
fn brsv_verdict(truth: &Ext4Truth) -> &'static str {
    if truth.brsv_equal() {
        "brsv=live"
    } else if truth.brsv_ino_equal() {
        "brsv=replaced"
    } else {
        "brsv=changed"
    }
}

/// Replacement through a temp sibling plus rename: the new file takes
/// a FRESH number (allocated while the old file still exists), so this
/// never recycles — the deleted-mapping row's shape, never inode reuse.
/// Returns the old and new inode numbers.
fn replace_file(path: &std::path::Path, bytes: Vec<u8>) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt as _;
    let old_ino = std::fs::metadata(path)
        .map_err(|error| format!("ext4 replace stat {}: {error}", path.display()))?
        .ino();
    let sibling = path.with_extension("new");
    std::fs::write(&sibling, bytes)
        .map_err(|error| format!("ext4 replace write {}: {error}", sibling.display()))?;
    std::fs::rename(&sibling, path)
        .map_err(|error| format!("ext4 replace rename {}: {error}", path.display()))?;
    let new_ino = std::fs::metadata(path)
        .map_err(|error| format!("ext4 replace restat {}: {error}", path.display()))?
        .ino();
    Ok((old_ino, new_ino))
}

/// A filesystem identity number pair: (st_dev, st_ino).
type Ext4Identity = (u64, u64);

/// Delete-then-create replacement: the old path is unlinked BEFORE the
/// new bytes are written, so a freed inode number is immediately
/// reusable on a journaled ext4. `between` runs after the unlink and
/// before the create (the ordinary guard observes the path missing
/// there). Returns the old and new identity; the rows fail closed
/// when the number is not recycled.
fn replace_by_delete_create(
    path: &std::path::Path,
    bytes: Vec<u8>,
    mut between: impl FnMut(),
) -> Result<(Ext4Identity, Ext4Identity), String> {
    use std::os::unix::fs::MetadataExt as _;
    let old = std::fs::metadata(path)
        .map_err(|error| format!("ext4 replace stat {}: {error}", path.display()))?;
    let before = (old.dev(), old.ino());
    std::fs::remove_file(path)
        .map_err(|error| format!("ext4 replace unlink {}: {error}", path.display()))?;
    between();
    std::fs::write(path, bytes)
        .map_err(|error| format!("ext4 replace write {}: {error}", path.display()))?;
    let new = std::fs::metadata(path)
        .map_err(|error| format!("ext4 replace restat {}: {error}", path.display()))?;
    Ok((before, (new.dev(), new.ino())))
}

fn find_line(snapshot: &[MapEntry], range: (u64, u64), perms: [u8; 4]) -> Result<MapEntry, String> {
    snapshot
        .iter()
        .find(|entry| (entry.start, entry.end) == range && entry.permissions == perms)
        .cloned()
        .ok_or_else(|| format!("ext4 snapshot: no {perms:?} line for {range:08x?} in {snapshot:?}"))
}

/// The dead holder's line: the range still maps, but its pathname
/// carries the ` (deleted)` suffix. A range-matching line without the
/// suffix fails the row — the premise, not the verdict, broke.
fn find_line_deleted(snapshot: &[MapEntry], range: (u64, u64)) -> Result<MapEntry, String> {
    let line = snapshot
        .iter()
        .find(|entry| (entry.start, entry.end) == range)
        .cloned()
        .ok_or_else(|| format!("ext4 snapshot: no line for {range:08x?} in {snapshot:?}"))?;
    let deleted = line
        .raw_path
        .as_deref()
        .is_some_and(|raw| raw.ends_with(b" (deleted)"));
    if !deleted {
        return Err(format!(
            "ext4 snapshot: line for {range:08x?} lost its (deleted) suffix: {line:?}"
        ));
    }
    Ok(line)
}

/// Pin the held file through the loop path on the anchor key, like
/// production pins a provider (self-mapping probe included).
fn ext4_pin(
    path: &std::path::Path,
    key: ObjectKey,
) -> Result<
    (
        crate::discovery::identity::PinnedObjects,
        crate::discovery::identity::PinnedObjectId,
    ),
    String,
> {
    use crate::discovery::identity::test_fixture::real_scan_pin;
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|error| format!("ext4 pin read: {error}"))?;
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins = real_scan_pin(path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("held-file pin").id;
    Ok((pins, object))
}

fn ext4_index(
    key: ObjectKey,
    object: crate::discovery::identity::PinnedObjectId,
    pins: &crate::discovery::identity::PinnedObjects,
) -> KnownKeyIndex {
    let (index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        pins,
    );
    assert!(
        refused.is_empty(),
        "index admission refuses nothing: {refused:?}"
    );
    index
}

/// What the kernel leg observably did: the fallback ledger, the
/// userspace reads it performed, the instrumented `bpf()` wrapper calls
/// across the leg, and the index preconditions. Identity rows carry the
/// no-proof classification with no per-range key; the stale-key row
/// carries its unusable-line classification with the key in the prove
/// set (refused before proof). (Installed anchor slots are asserted on
/// the index directly by the drivers: anchors install for arena-mapped
/// files on any filesystem.)
struct Ext4LegEvidence {
    fallback: crate::discovery::kernel_identity::KernelFallbackTotals,
    userspace_reads: usize,
    bpf_calls: u64,
    per_range_key: bool,
    no_proof_classification: Option<&'static str>,
}

/// The tabled outcome for one ext4 row: the stale sweep's refusal
/// under a recycled number, the deleted line's named refusal under a
/// fresh number, the live holder's identity edge, the wrong-file
/// negative, the live byte-identical copy's refusal under a fresh
/// number, or the data-only zero-demand row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ext4Expect {
    RecycledRefused,
    DeletedMappingStaleKey,
    LiveHolderEdge,
    WrongFileNone,
    LiveCopyNone,
    DataOnlyNone,
}

/// Whether the row behind `expected` binds a replacement file under a stale
/// key, so its index key needs per-range proof: only the deleted-mapping
/// row does (its kernel leg still runs zero proof — the unusable line
/// refuses first). The stale-key driver asserts this; the ordinary
/// precondition test pins it per row shape without root.
fn ext4_row_takes_per_range_proof(expected: Ext4Expect) -> bool {
    matches!(expected, Ext4Expect::DeletedMappingStaleKey)
}

fn ext4_edge(pid: u32, key: ObjectKey, out: &SweepAttribution, side: &str) -> Result<(), String> {
    let members: Vec<u32> = out.members.iter().map(|member| member.pid).collect();
    if members != [pid] {
        return Err(format!(
            "ext4 {side}: expected edge for {pid}, members {members:?} losses {:?} probed {}",
            out.losses, out.probed
        ));
    }
    if !out.losses.is_empty() {
        return Err(format!("ext4 {side}: edge with losses {:?}", out.losses));
    }
    if out.probed != 1 {
        return Err(format!("ext4 {side}: edge with probed {}", out.probed));
    }
    let keys: Vec<ObjectKey> = out.members[0].objects.iter().map(|o| o.key).collect();
    if keys != [key] {
        return Err(format!(
            "ext4 {side}: edge for {keys:?}, row key is {key:?}"
        ));
    }
    Ok(())
}

/// The deleted-mapping refusal: the all-unusable early return, so no
/// probe ran and probed stays zero on both backends.
fn ext4_deleted(out: &SweepAttribution, side: &str) -> Result<(), String> {
    if !out.members.is_empty()
        || out.losses != BTreeMap::from([(AttributionLoss::DeletedMapping, 1)])
        || out.probed != 0
    {
        return Err(format!(
            "ext4 {side}: expected named deleted refusal, members {:?} losses {:?} probed {}",
            out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            out.losses,
            out.probed
        ));
    }
    Ok(())
}

/// The exited-holder refusal: the stale sweep probed once, the holder
/// was provably gone, and nothing joined on either backend.
fn ext4_exited(pid: u32, out: &SweepAttribution, side: &str) -> Result<(), String> {
    if !out.members.is_empty()
        || !out.losses.is_empty()
        || out.probed != 1
        || out.exited != BTreeSet::from([pid])
    {
        return Err(format!(
            "ext4 {side}: expected exited-holder refusal, members {:?} losses {:?} probed {} exited {:?}",
            out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            out.losses,
            out.probed,
            out.exited
        ));
    }
    Ok(())
}

fn ext4_no_candidate(out: &SweepAttribution, side: &str) -> Result<(), String> {
    if !out.members.is_empty() || out.probed != 0 || !out.losses.is_empty() {
        return Err(format!(
            "ext4 {side}: expected no candidate, members {:?} losses {:?} probed {}",
            out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            out.losses,
            out.probed
        ));
    }
    Ok(())
}

/// Assert one ext4 row: the maps-key premise from both sides'
/// recorded lines first (a violated premise fails the row, never
/// passes by luck), then the statfs-magic and BRSV premises, then the
/// per-backend outcomes, then the kernel-leg evidence — always a
/// no-proof classification, never kernel parity.
#[allow(clippy::too_many_arguments)]
fn assert_ext4_outcome(
    pid: u32,
    target: &Ext4Truth,
    anchor: &Ext4Truth,
    userspace: &SweepAttribution,
    kernel: &SweepAttribution,
    evidence: &Ext4LegEvidence,
    expected: Ext4Expect,
) -> Result<(), String> {
    fn classified(evidence: &Ext4LegEvidence) -> Result<(), String> {
        if evidence.no_proof_classification != Some("no kernel proof (identity key)") {
            return Err("ext4 kernel: every ext4 leg needs its no-proof classification".into());
        }
        // Identity keys skip per-range proof through the map_files_keys
        // exclusion, not through missing slots: anchors install for
        // arena-mapped files on any filesystem, and the drivers assert
        // the installed slots directly.
        if evidence.per_range_key {
            return Err("ext4 kernel: an identity key takes no per-range proof".into());
        }
        Ok(())
    }
    fn classified_stale(evidence: &Ext4LegEvidence) -> Result<(), String> {
        if evidence.no_proof_classification != Some("no kernel proof (unusable line)") {
            return Err("ext4 kernel: the stale-key leg needs its no-proof classification".into());
        }
        // The stale key names the deleted file while the pinned object is
        // its replacement, so the key stays a per-range key: the
        // unusable-line early return refuses before any proof runs (zero
        // fallback, zero reads), never because the key is identity.
        if !evidence.per_range_key {
            return Err("ext4 kernel: a stale key stays a per-range key".into());
        }
        Ok(())
    }
    fn zero_run(evidence: &Ext4LegEvidence) -> Result<(), String> {
        let fallback = &evidence.fallback;
        if fallback.passes != 0
            || fallback.pids != 0
            || fallback.keys != 0
            || fallback.first_reason.is_some()
        {
            return Err(format!(
                "ext4 kernel: zero targets means zero fallback, yet {fallback:?}"
            ));
        }
        if evidence.userspace_reads != 0 {
            return Err("ext4 kernel: zero targets means zero userspace reads".into());
        }
        Ok(())
    }
    if target.statfs_magic != 0xef53 || anchor.statfs_magic != 0xef53 {
        return Err(format!(
            "ext4 row needs the ext4 magic on both sides, {:#x} vs {:#x}",
            target.statfs_magic, anchor.statfs_magic
        ));
    }
    let keys_equal = target.maps_key() == anchor.maps_key();
    let row_key = target.maps_key();
    match expected {
        Ext4Expect::RecycledRefused => {
            if target.maps_line.contains("(deleted)") || anchor.maps_line.contains("(deleted)") {
                return Err("ext4 recycled premise needs two live lines".into());
            }
            if !keys_equal {
                return Err("ext4 recycled premise needs the recycled key".into());
            }
            assert_brsv_live(target)?;
            assert_brsv_live(anchor)?;
            ext4_exited(pid, userspace, "userspace")?;
            ext4_exited(pid, kernel, "kernel")?;
            classified(evidence)?;
            zero_run(evidence)?;
            Ok(())
        }
        Ext4Expect::DeletedMappingStaleKey => {
            if !target.maps_line.contains("(deleted)") {
                return Err("ext4 deleted-mapping premise needs the (deleted) line".into());
            }
            if anchor.maps_line.contains("(deleted)") {
                return Err("ext4 deleted-mapping premise needs a live anchor line".into());
            }
            if keys_equal {
                return Err("ext4 deleted-mapping premise needs a fresh number".into());
            }
            assert_brsv_changed(target)?;
            assert_brsv_live(anchor)?;
            ext4_deleted(userspace, "userspace")?;
            ext4_deleted(kernel, "kernel")?;
            classified_stale(evidence)?;
            zero_run(evidence)?;
            Ok(())
        }
        Ext4Expect::LiveHolderEdge => {
            if target.maps_line.contains("(deleted)") || anchor.maps_line.contains("(deleted)") {
                return Err("ext4 live-holder premise needs live lines".into());
            }
            if !keys_equal {
                return Err("ext4 live-holder premise needs equal maps keys".into());
            }
            assert_brsv_live(target)?;
            assert_brsv_live(anchor)?;
            ext4_edge(pid, row_key, userspace, "userspace")?;
            // The kernel leg reaches the same edge through its
            // AnchorNotInstalled userspace fallback, proving nothing —
            // and reading nothing, since the prove set is empty.
            ext4_edge(pid, row_key, kernel, "kernel")?;
            classified(evidence)?;
            if evidence.fallback.first_reason
                != Some(crate::discovery::kernel_identity::KernelFallbackReason::AnchorNotInstalled)
            {
                return Err(format!(
                    "ext4 live-holder needs AnchorNotInstalled, got {:?}",
                    evidence.fallback.first_reason
                ));
            }
            if evidence.userspace_reads != 0 {
                return Err("ext4 live-holder: the identity-key fallback reads nothing".into());
            }
            Ok(())
        }
        Ext4Expect::WrongFileNone => {
            if keys_equal {
                return Err("ext4 wrong-file premise needs differing maps keys".into());
            }
            assert_brsv_live(target)?;
            assert_brsv_live(anchor)?;
            ext4_no_candidate(userspace, "userspace")?;
            ext4_no_candidate(kernel, "kernel")?;
            classified(evidence)?;
            zero_run(evidence)?;
            Ok(())
        }
        Ext4Expect::LiveCopyNone => {
            if keys_equal {
                return Err(
                    "ext4 live-copy premise needs differing maps keys (a different inode)".into(),
                );
            }
            assert_brsv_live(target)?;
            assert_brsv_live(anchor)?;
            ext4_no_candidate(userspace, "userspace")?;
            ext4_no_candidate(kernel, "kernel")?;
            classified(evidence)?;
            zero_run(evidence)?;
            Ok(())
        }
        Ext4Expect::DataOnlyNone => {
            if !keys_equal {
                return Err("ext4 data-only premise needs equal maps keys (same file)".into());
            }
            assert_brsv_live(target)?;
            assert_brsv_live(anchor)?;
            ext4_no_candidate(userspace, "userspace")?;
            ext4_no_candidate(kernel, "kernel")?;
            classified(evidence)?;
            zero_run(evidence)?;
            Ok(())
        }
    }
}

/// Userspace attribution of one ext4 mapper through the production
/// probe.
fn d4_ext4_attribute_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    index: &KnownKeyIndex,
) -> SweepAttribution {
    attribute_unselected(
        &[(pid, snapshot)],
        &BTreeSet::new(),
        &BTreeSet::new(),
        index,
        &mut OsMemberProbe::default(),
        &mut CaptureWorkBudget::default(),
    )
}

/// Kernel leg for a row whose confirm never reaches proof (the stale
/// sweep names an exited holder, the line is unusable, the keys differ,
/// or a data-only mapping): zero fallback and zero reads — so a vacuous
/// kernel leg cannot pass. The outcome carries the refusal or nothing,
/// per row.
#[allow(clippy::too_many_arguments)]
fn d4_ext4_kernel_no_run_identity_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> (SweepAttribution, Ext4LegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    let mut index = ext4_index(key, object, pins);
    assert!(
        !index.map_files_keys().contains(&key),
        "ext4 identity key takes no per-range proof"
    );
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, generation, deadline)
        .expect("install actual held-file anchors");
    let trace = Arc::new(Mutex::new(ProofTrace::default()));
    let out = {
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            OsConfirmIo::with_pool(None).observing(trace.clone()),
            deadline,
        );
        probe
            .install_expectations(&mut index)
            .expect("actual validated anchor expectations");
        assert!(
            index
                .match_slots
                .get(&key)
                .is_some_and(|slots| !slots.is_empty()),
            "anchors install for the arena-mapped file on any filesystem"
        );
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "exercise actual kernel proof, not scoped fallback"
        );
        attribute_unselected(
            &[(pid, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        )
    };
    assert!(out.members.is_empty(), "no candidate confirms: {out:?}");
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.pids, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.keys, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.first_reason, None, "no-run leg falls back nowhere");
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(reads, 0, "no-run leg reads nothing");
    let evidence = Ext4LegEvidence {
        fallback,
        userspace_reads: reads,
        bpf_calls: 0,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    (out, evidence)
}

/// Kernel leg for a row whose key is stale: the deleted file's number
/// bound to its replacement object, so the key stays a per-range key even
/// though the unusable-line early return refuses before any proof runs —
/// zero fallback and zero reads, with the named refusal as the outcome, so
/// a vacuous kernel leg cannot pass.
#[allow(clippy::too_many_arguments)]
fn d4_ext4_kernel_no_run_stale_key_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
    expected: Ext4Expect,
) -> (SweepAttribution, Ext4LegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    assert!(
        ext4_row_takes_per_range_proof(expected),
        "ext4 {expected:?} is not a stale-key row"
    );
    let mut index = ext4_index(key, object, pins);
    assert!(
        index.map_files_keys().contains(&key),
        "ext4 stale key stays a per-range key: the pinned object is its replacement"
    );
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, generation, deadline)
        .expect("install actual held-file anchors");
    let trace = Arc::new(Mutex::new(ProofTrace::default()));
    let out = {
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            OsConfirmIo::with_pool(None).observing(trace.clone()),
            deadline,
        );
        probe
            .install_expectations(&mut index)
            .expect("actual validated anchor expectations");
        assert!(
            index
                .match_slots
                .get(&key)
                .is_some_and(|slots| !slots.is_empty()),
            "anchors install for the arena-mapped file on any filesystem"
        );
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "exercise actual kernel proof, not scoped fallback"
        );
        attribute_unselected(
            &[(pid, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        )
    };
    assert!(out.members.is_empty(), "no candidate confirms: {out:?}");
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.pids, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.keys, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.first_reason, None, "no-run leg falls back nowhere");
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(reads, 0, "no-run leg reads nothing");
    let evidence = Ext4LegEvidence {
        fallback,
        userspace_reads: reads,
        bpf_calls: 0,
        per_range_key: true,
        no_proof_classification: Some("no kernel proof (unusable line)"),
    };
    (out, evidence)
}

/// Kernel leg for the live holder: the identity key draws an empty
/// proof scope, and the edge arrives through the AnchorNotInstalled
/// userspace fallback with zero reads — never kernel parity.
#[allow(clippy::too_many_arguments)]
fn d4_ext4_kernel_live_holder_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> (SweepAttribution, Ext4LegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    let mut index = ext4_index(key, object, pins);
    assert!(
        !index.map_files_keys().contains(&key),
        "ext4 identity key takes no per-range proof"
    );
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, generation, deadline)
        .expect("install actual held-file anchors");
    let trace = Arc::new(Mutex::new(ProofTrace::default()));
    let out = {
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            OsConfirmIo::with_pool(None).observing(trace.clone()),
            deadline,
        );
        probe
            .install_expectations(&mut index)
            .expect("actual validated anchor expectations");
        assert!(
            index
                .match_slots
                .get(&key)
                .is_some_and(|slots| !slots.is_empty()),
            "anchors install for the arena-mapped file on any filesystem"
        );
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "exercise actual kernel proof, not scoped fallback"
        );
        attribute_unselected(
            &[(pid, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        )
    };
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(
        fallback.first_reason,
        Some(crate::discovery::kernel_identity::KernelFallbackReason::AnchorNotInstalled),
        "identity-key edge classifies AnchorNotInstalled: {fallback:?}"
    );
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(
        reads, 0,
        "the identity-key fallback reads nothing: the prove set is empty"
    );
    let evidence = Ext4LegEvidence {
        fallback,
        userspace_reads: reads,
        bpf_calls: 0,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    (out, evidence)
}

/// Step 1a: the ext4 identity key takes no per-range proof (the
/// empty-scope premise, straight from production classification), so
/// the kernel leg runs zero targets and the evaluator classifies the
/// no-proof evidence — while kernel-proof evidence is rejected.
#[test]
fn ext4_reuse_kernel_leg_runs_zero_targets() {
    use p11scope_manifest::maps::Device;
    let key = ObjectKey {
        device: Device { major: 7, minor: 2 },
        inode: 13,
    };
    let identity = FileIdentity {
        dev: libc::makedev(7, 2),
        ino: 13,
    };
    let index = index_binding(key, identity, Some(0xef53));
    assert!(
        index.map_files_keys().is_empty(),
        "an ext4 identity key takes no per-range proof"
    );
    // The evaluator classifies the zero-run evidence for the recycled
    // live pair — and rejects kernel-proof evidence for it.
    let pid = 4343u32;
    let live = |size: u64, mtime: i64| Ext4Stat {
        dev: libc::makedev(7, 2),
        ino: 13,
        size,
        mtime_secs: mtime,
        mtime_nanos: 0,
    };
    let target = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: live(8192, 100),
        path_stat: live(8192, 100),
        statfs_magic: 0xef53,
    };
    let anchor = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: live(4096, 200),
        path_stat: live(4096, 200),
        statfs_magic: 0xef53,
    };
    let exited = synthetic_exited(pid);
    assert_ext4_outcome(
        pid,
        &target,
        &anchor,
        &exited,
        &exited,
        &synthetic_no_run_identity_evidence(),
        Ext4Expect::RecycledRefused,
    )
    .expect("the recycled live pair classifies zero-run no-proof");
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &exited,
            &exited,
            &synthetic_quad_evidence(),
            Ext4Expect::RecycledRefused,
        )
        .is_err(),
        "zero targets means no kernel-proof evidence"
    );
    // A leg that issued bpf() calls ran a target (one run needs at
    // least link + iterator creation): zero targets means a zero
    // instrumented delta.
    let called = Ext4LegEvidence {
        bpf_calls: 2,
        ..synthetic_no_run_identity_evidence()
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &exited,
            &exited,
            &called,
            Ext4Expect::RecycledRefused,
        )
        .is_err(),
        "zero targets means zero bpf() calls"
    );
}

/// The recycled replacement deletes before it creates: the between-hook
/// observes the path missing exactly once, the old identity is recorded
/// and the new bytes land. (A temp+rename mutant keeps the path present
/// under the hook and fails this test.)
#[test]
fn ext4_recycled_replacement_deletes_before_it_creates() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lib.so");
    std::fs::write(&path, vec![0xE4u8; 8]).unwrap();
    let before_stat = std::fs::metadata(&path).unwrap();
    let before_id = (before_stat.dev(), before_stat.ino());
    let mut visits = 0;
    let mut saw_missing = false;
    let (before, _after) = replace_by_delete_create(&path, vec![0xE5u8; 8], || {
        visits += 1;
        saw_missing |= std::fs::metadata(&path).is_err();
    })
    .expect("delete-then-create replaces");
    assert_eq!(visits, 1, "the between-hook runs once");
    assert!(saw_missing, "the path is missing between delete and create");
    assert_eq!(
        before, before_id,
        "the recorded old identity is the deleted file's"
    );
    assert_eq!(std::fs::read(&path).unwrap(), vec![0xE5u8; 8]);
}

/// The recycled evaluator refuses the stale sweep: two live truths under
/// the recycled key with an exited-holder oracle on both backends — while
/// an edge, a deleted line or differing keys fail.
#[test]
fn ext4_recycled_evaluator_refuses_the_stale_sweep() {
    let pid = 4345u32;
    let live = |size: u64, mtime: i64| Ext4Stat {
        dev: libc::makedev(7, 2),
        ino: 13,
        size,
        mtime_secs: mtime,
        mtime_nanos: 0,
    };
    // Position 0: the recorded live line of the exited holder against
    // the new holder's live line — same recycled key, both coherent.
    let target = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: live(8192, 100),
        path_stat: live(8192, 100),
        statfs_magic: 0xef53,
    };
    let anchor = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: live(4096, 200),
        path_stat: live(4096, 200),
        statfs_magic: 0xef53,
    };
    assert!(target.maps_key() == anchor.maps_key(), "recycled key");
    let exited = synthetic_exited(pid);
    assert_ext4_outcome(
        pid,
        &target,
        &anchor,
        &exited,
        &exited,
        &synthetic_no_run_identity_evidence(),
        Ext4Expect::RecycledRefused,
    )
    .expect("the stale sweep of the exited holder refuses");
    // An edge for the recycled key joins and must fail.
    let edged = synthetic_edged(pid, target.maps_key());
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::RecycledRefused,
        )
        .is_err(),
        "the recycled identity must never join"
    );
    // A deleted line is the deleted-mapping row, not this one.
    let deleted = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so (deleted)".into(),
        map_files: live(8192, 100),
        path_stat: live(4096, 200),
        statfs_magic: 0xef53,
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &deleted,
            &anchor,
            &exited,
            &exited,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::RecycledRefused,
        )
        .is_err(),
        "refusal needs two live lines"
    );
    // Differing keys are the wrong-file row, not this one.
    let other = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 14 /lib.so".into(),
        map_files: Ext4Stat {
            dev: libc::makedev(7, 2),
            ino: 14,
            size: 4096,
            mtime_secs: 200,
            mtime_nanos: 0,
        },
        path_stat: Ext4Stat {
            dev: libc::makedev(7, 2),
            ino: 14,
            size: 4096,
            mtime_secs: 200,
            mtime_nanos: 0,
        },
        statfs_magic: 0xef53,
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &other,
            &exited,
            &exited,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::RecycledRefused,
        )
        .is_err(),
        "refusal needs the recycled key"
    );
}

/// The live-copy evaluator refuses despite identical bytes: a live pair
/// under DIFFERING keys (the copy is a different inode) with the same
/// size on both sides (byte-identical content) and no candidate on
/// either backend — while an edge or equal keys fail.
#[test]
fn ext4_live_copy_evaluator_refuses_despite_identical_bytes() {
    let pid = 4349u32;
    let stat = |ino: u64| Ext4Stat {
        dev: libc::makedev(7, 2),
        ino,
        size: 8192,
        mtime_secs: 100,
        mtime_nanos: 0,
    };
    // Position 0: the copy's live line (fresh inode) against the held
    // file's live line — same size (identical bytes), differing keys.
    let target = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 14 /copy.so".into(),
        map_files: stat(14),
        path_stat: stat(14),
        statfs_magic: 0xef53,
    };
    let anchor = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: stat(13),
        path_stat: stat(13),
        statfs_magic: 0xef53,
    };
    assert!(target.maps_key() != anchor.maps_key(), "a different inode");
    assert_eq!(
        target.map_files.size, anchor.map_files.size,
        "identical bytes, equal size"
    );
    let none = SweepAttribution::default();
    assert_ext4_outcome(
        pid,
        &target,
        &anchor,
        &none,
        &none,
        &synthetic_no_run_identity_evidence(),
        Ext4Expect::LiveCopyNone,
    )
    .expect("the live copy refuses on both backends");
    // An edge for the copy's key joins and must fail.
    let edged = synthetic_edged(pid, target.maps_key());
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::LiveCopyNone,
        )
        .is_err(),
        "the byte-identical copy must never join"
    );
    // Equal keys are the live-holder row, not this one.
    let same = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: stat(13),
        path_stat: stat(13),
        statfs_magic: 0xef53,
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &same,
            &anchor,
            &none,
            &none,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::LiveCopyNone,
        )
        .is_err(),
        "refusal needs differing keys"
    );
}

/// The per-row proof precondition, pinned without root: each privileged
/// row's (key, pinned identity, filesystem) shape classifies in production
/// exactly as its kernel driver asserts. Only the deleted-mapping row binds
/// a replacement file under a stale key, so only its key needs per-range
/// proof.
#[test]
fn ext4_row_proof_classification_matches_index_shape() {
    use p11scope_manifest::maps::Device;
    let key = ObjectKey {
        device: Device { major: 7, minor: 2 },
        inode: 13,
    };
    let identity = |ino: u64| FileIdentity {
        dev: libc::makedev(7, 2),
        ino,
    };
    // (row, expectation, pinned inode): the recycled shape covers both the
    // recycled and the equal-bytes rows (one shared setup).
    let rows = [
        ("recycled", Ext4Expect::RecycledRefused, 13),
        ("deleted-mapping", Ext4Expect::DeletedMappingStaleKey, 14),
        ("wrong-file", Ext4Expect::WrongFileNone, 13),
        ("data-only", Ext4Expect::DataOnlyNone, 13),
        ("equal-bytes", Ext4Expect::RecycledRefused, 13),
        ("live-copy", Ext4Expect::LiveCopyNone, 13),
        ("live-holder", Ext4Expect::LiveHolderEdge, 13),
    ];
    for (row, expected, pinned_ino) in rows {
        let index = index_binding(key, identity(pinned_ino), Some(0xef53));
        let takes_proof = ext4_row_takes_per_range_proof(expected);
        assert_eq!(
            index.map_files_keys().contains(&key),
            takes_proof,
            "ext4 {row}: the row's proof precondition must match its index shape"
        );
    }
}

/// The stale-key evaluator refuses the unusable line before proof: a deleted
/// target line against a live anchor line under a FRESH number, with the
/// per-range no-run evidence — while identity evidence (the uniform
/// assumption), an edge, recycled numbers or live lines fail.
#[test]
fn ext4_stale_key_evaluator_refuses_before_proof() {
    let pid = 4348u32;
    let stat = |ino: u64, size: u64, mtime: i64| Ext4Stat {
        dev: libc::makedev(7, 2),
        ino,
        size,
        mtime_secs: mtime,
        mtime_nanos: 0,
    };
    // Position 0: the live holder's deleted line (old number) against
    // the current file's live line (fresh number from temp+rename).
    let target = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so (deleted)".into(),
        map_files: stat(13, 8192, 100),
        path_stat: stat(14, 4096, 200),
        statfs_magic: 0xef53,
    };
    let anchor = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 14 /lib.so".into(),
        map_files: stat(14, 4096, 200),
        path_stat: stat(14, 4096, 200),
        statfs_magic: 0xef53,
    };
    assert!(target.maps_key() != anchor.maps_key(), "a fresh number");
    let refused = synthetic_deleted();
    assert_ext4_outcome(
        pid,
        &target,
        &anchor,
        &refused,
        &refused,
        &synthetic_no_run_stale_evidence(),
        Ext4Expect::DeletedMappingStaleKey,
    )
    .expect("the stale key refuses before proof with its named loss");
    // Identity evidence misrecords the stale key: it stays per-range.
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &refused,
            &refused,
            &synthetic_no_run_identity_evidence(),
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "the stale key stays a per-range key"
    );
    // Stale classification with a misrecorded key shape: the per-range
    // half refuses on its own.
    let misrecorded = Ext4LegEvidence {
        per_range_key: false,
        ..synthetic_no_run_stale_evidence()
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &refused,
            &refused,
            &misrecorded,
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "a stale classification with per_range_key=false must fail"
    );
    // The stale leg runs zero targets too: a nonzero instrumented
    // delta (one run needs at least link + iterator creation) fails.
    let called = Ext4LegEvidence {
        bpf_calls: 2,
        ..synthetic_no_run_stale_evidence()
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &refused,
            &refused,
            &called,
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "the stale leg runs zero targets: zero bpf() calls"
    );
    // An edge for the stale key joins and must fail.
    let edged = synthetic_edged(pid, target.maps_key());
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &synthetic_no_run_stale_evidence(),
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "the stale identity must never join"
    );
    // Recycled numbers under a deleted line are not this row: a live
    // deleted-mapping holder and a recycled number cannot coexist.
    let recycled_anchor = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: stat(13, 4096, 200),
        path_stat: stat(13, 4096, 200),
        statfs_magic: 0xef53,
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &target,
            &recycled_anchor,
            &refused,
            &refused,
            &synthetic_no_run_stale_evidence(),
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "temp+rename takes a fresh number"
    );
    // Two live lines are not a deleted mapping.
    let live_target = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: stat(13, 8192, 100),
        path_stat: stat(13, 8192, 100),
        statfs_magic: 0xef53,
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &live_target,
            &anchor,
            &refused,
            &refused,
            &synthetic_no_run_stale_evidence(),
            Ext4Expect::DeletedMappingStaleKey,
        )
        .is_err(),
        "refusal needs the deleted line"
    );
}

/// The live-holder evaluator edges without per-range proof: a live pair
/// under one key with an edge on both backends, the kernel leg through
/// its AnchorNotInstalled fallback with zero reads — while a refusal, a
/// reading fallback or a deleted line fail.
#[test]
fn ext4_live_evaluator_edges_without_per_range_proof() {
    let pid = 4347u32;
    let live = |size: u64, mtime: i64| Ext4Stat {
        dev: libc::makedev(7, 2),
        ino: 13,
        size,
        mtime_secs: mtime,
        mtime_nanos: 0,
    };
    let truth = Ext4Truth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /lib.so".into(),
        map_files: live(8192, 100),
        path_stat: live(8192, 100),
        statfs_magic: 0xef53,
    };
    let edged = synthetic_edged(pid, truth.maps_key());
    assert_ext4_outcome(
        pid,
        &truth,
        &truth,
        &edged,
        &edged,
        &synthetic_live_identity_evidence(),
        Ext4Expect::LiveHolderEdge,
    )
    .expect("the live holder edges on both backends");
    // The identity-key fallback reads nothing: the prove set is empty.
    let reading = Ext4LegEvidence {
        userspace_reads: 1,
        ..synthetic_live_identity_evidence()
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &truth,
            &truth,
            &edged,
            &edged,
            &reading,
            Ext4Expect::LiveHolderEdge,
        )
        .is_err(),
        "the identity-key fallback reads nothing"
    );
    // The identity-key fallback reaches its edge without a target run:
    // a nonzero instrumented delta fails.
    let called = Ext4LegEvidence {
        bpf_calls: 2,
        ..synthetic_live_identity_evidence()
    };
    assert!(
        assert_ext4_outcome(
            pid,
            &truth,
            &truth,
            &edged,
            &edged,
            &called,
            Ext4Expect::LiveHolderEdge,
        )
        .is_err(),
        "the live edge without proof runs zero targets"
    );
    // A refusal is not a live edge.
    let refused = synthetic_deleted();
    assert!(
        assert_ext4_outcome(
            pid,
            &truth,
            &truth,
            &refused,
            &refused,
            &synthetic_live_identity_evidence(),
            Ext4Expect::LiveHolderEdge,
        )
        .is_err(),
        "the live holder edges"
    );
}

fn synthetic_exited(pid: u32) -> SweepAttribution {
    SweepAttribution {
        probed: 1,
        exited: BTreeSet::from([pid]),
        ..SweepAttribution::default()
    }
}

fn synthetic_live_identity_evidence() -> Ext4LegEvidence {
    Ext4LegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 0,
            first_reason: Some(
                crate::discovery::kernel_identity::KernelFallbackReason::AnchorNotInstalled,
            ),
        },
        userspace_reads: 0,
        bpf_calls: 0,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    }
}

fn synthetic_edged(pid: u32, key: ObjectKey) -> SweepAttribution {
    SweepAttribution {
        members: vec![SweptMember {
            pid,
            start_time: 1,
            exe: crate::discovery::caller_registry::ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 0,
                mtime_nanos: 0,
                path: Some("synthetic".into()),
            },
            objects: vec![MatchedObject {
                key,
                object: crate::discovery::identity::PinnedObjectId(0),
                path: "/lib.so".into(),
                double_loaded: false,
            }],
            unexamined: 0,
        }],
        probed: 1,
        ..SweepAttribution::default()
    }
}

fn synthetic_deleted() -> SweepAttribution {
    SweepAttribution {
        losses: BTreeMap::from([(AttributionLoss::DeletedMapping, 1)]),
        ..SweepAttribution::default()
    }
}

fn synthetic_quad_evidence() -> Ext4LegEvidence {
    Ext4LegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        bpf_calls: 0,
        per_range_key: true,
        no_proof_classification: None,
    }
}

fn synthetic_no_run_identity_evidence() -> Ext4LegEvidence {
    Ext4LegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        bpf_calls: 0,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    }
}

fn synthetic_no_run_stale_evidence() -> Ext4LegEvidence {
    Ext4LegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        bpf_calls: 0,
        per_range_key: true,
        no_proof_classification: Some("no kernel proof (unusable line)"),
    }
}

/// ext4 inode-reuse confirmation parity: delete-then-create recycles
/// the inode number after the holder exits, so the stale sweep names a
/// live recycled key — and both legs refuse it while a live holder
/// still edges. The deleted-mapping row pins the live ` (deleted)`
/// refusal separately (temp+rename takes a fresh number). Every kernel
/// leg classifies its no-proof evidence with zero target runs (never
/// kernel parity): identity rows "no kernel proof (identity key)", the
/// deleted-mapping row "no kernel proof (unusable line)"; every row
/// records its BRSV and fails closed when the rendering changes. Where
/// the BTF gate refuses (5.15 included) the cell fails closed at that
/// check; the denial path below only runs if BTF passes but the probe
/// fails, with userspace-only legs plus BRSVs.
#[test]
#[ignore = "root: loop ext4 mounts plus eligible BTF/task_vma identity (fails closed without it, including 5.15)"]
fn privileged_d4_ext4_inode_reuse_confirmation_parity() {
    ext4_preflight().expect("ext4 preconditions hold");
    let pre_6 = ext4_pre_6().expect("kernel release parses");
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let probe_dir = tempfile::tempdir().unwrap();
    // Capability-driven: a loaded session runs the full cell; a denial
    // runs the shutdown leg only on pre-6 (else it cannot qualify).
    let mut session = match crate::discovery::kernel_identity::IdentitySession::probe_and_load(
        &btf,
        probe_dir.path(),
    ) {
        Ok(session) => Some(session),
        Err(denial) => {
            if !pre_6 {
                panic!("kernel session refused on a qualifying lane: {denial}");
            }
            eprintln!("D4_EXT4_SHUTDOWN denial={denial} verdict=5.15-denial-asserted");
            None
        }
    };
    let shutdown = session.is_none();
    let mut rows = Ext4Rows {
        session: session.as_mut(),
        generation: 0,
        shutdown,
    };
    let work = tempfile::tempdir().unwrap();
    rows.run_all(work.path()).expect("ext4 inode-reuse rows");
    eprintln!("D4_EXT4 shutdown={} verdict=table", rows.shutdown,);
}

/// One ignored run's shared kernel session (None only on the pre-6
/// denial path), generation counter and shutdown flag.
struct Ext4Rows<'s> {
    session: Option<&'s mut crate::discovery::kernel_identity::IdentitySession>,
    generation: u64,
    shutdown: bool,
}

impl Ext4Rows<'_> {
    fn run_all(&mut self, work: &std::path::Path) -> Result<(), String> {
        // The live holder runs last: its AnchorNotInstalled note is
        // cumulative in the shared session, and any later no-run row
        // would fail its absolute-zero fallback assert.
        self.row_recycled(work)?;
        self.row_deleted_mapping(work)?;
        self.row_wrong_file(work)?;
        self.row_data_only(work)?;
        self.row_equal_bytes(work)?;
        self.row_live_copy(work)?;
        self.row_live_holder(work)?;
        Ok(())
    }

    /// Recycled identity, different bytes: the original holder maps
    /// the file and genuinely edges; then it exits (reaped), the path is
    /// deleted and re-created with different bytes under the recycled
    /// number, and a new holder maps the new file. The stale sweep
    /// refuses on both backends (probed once, holder exited). The kernel
    /// leg proves nothing (identity key, zero runs).
    fn row_recycled(&mut self, work: &std::path::Path) -> Result<(), String> {
        self.row_recycled_shape("recycled", vec![0xE5u8; 4096], false, work)
    }

    /// The recycled-identity shape shared by the recycled and
    /// equal-bytes rows: exit, delete-then-create, new holder, stale
    /// refusal. `bytes_must_equal` selects the G28 premise (identical
    /// bytes) over the differing-bytes premise.
    fn row_recycled_shape(
        &mut self,
        row: &str,
        new_bytes: Vec<u8>,
        bytes_must_equal: bool,
        work: &std::path::Path,
    ) -> Result<(), String> {
        eprintln!("D4_EXT4 start row={row}");
        let _ = work;
        let fs = Ext4Loop::new();
        let path = fs.mount.join("lib.so");
        let old_bytes = vec![0xE4u8; 8192];
        std::fs::write(&path, &old_bytes).map_err(|error| format!("ext4 {row} write: {error}"))?;
        let holder = SwapChild::spawn(&path);
        let stale_pid = holder.pid as u32;
        let stale_range = child_range(&holder);
        let sweep = holder.maps();
        let pre_line = find_line(&sweep, stale_range, *b"r-xp")?;
        let key = ObjectKey::of(&pre_line);
        let recorded = record_ext4_truth(stale_pid, stale_range, &path)?;
        assert_brsv_live(&recorded)?;
        // The recorded holder genuinely edges before the replacement: a
        // stale sweep that never edged would refuse vacuously. The pins
        // drop here — the open file would pin the inode across the
        // unlink and the number could never recycle.
        {
            let (pins, object) = ext4_pin(&path, key)?;
            let index = ext4_index(key, object, &pins);
            let live = d4_ext4_attribute_pid(stale_pid, sweep.clone(), &index);
            ext4_edge(stale_pid, key, &live, "userspace")?;
        }
        drop(holder);
        if std::fs::metadata(format!("/proc/{stale_pid}")).is_ok() {
            return Err(format!("ext4 {row}: the holder must be reaped"));
        }
        let (before, after) = replace_by_delete_create(&path, new_bytes, || {})?;
        if before != after {
            return Err(format!(
                "ext4 {row}: ino not recycled (was {before:?}, now {after:?})"
            ));
        }
        let current =
            std::fs::read(&path).map_err(|error| format!("ext4 {row} reread: {error}"))?;
        if current == old_bytes && !bytes_must_equal {
            return Err(format!("ext4 {row}: premise needs different bytes"));
        }
        if current != old_bytes && bytes_must_equal {
            return Err(format!("ext4 {row}: premise needs identical bytes"));
        }
        let anchor = SwapChild::spawn(&path);
        let anchor_pid = anchor.pid as u32;
        if anchor_pid == stale_pid {
            return Err(format!("ext4 {row}: pid reuse across the replacement"));
        }
        let anchor_range = child_range(&anchor);
        let anchor_snap = anchor.maps();
        let anchor_line = find_line(&anchor_snap, anchor_range, *b"r-xp")?;
        if ObjectKey::of(&anchor_line) != key {
            return Err(format!(
                "ext4 {row}: premise needs the recycled key live again"
            ));
        }
        let live_truth = record_ext4_truth(anchor_pid, anchor_range, &path)?;
        assert_brsv_live(&live_truth)?;
        let (pins, object) = ext4_pin(&path, key)?;
        let index = ext4_index(key, object, &pins);
        let userspace = d4_ext4_attribute_pid(stale_pid, sweep.clone(), &index);
        ext4_exited(stale_pid, &userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_no_run_identity_for_pid(
                stale_pid,
                sweep,
                &pins,
                object,
                key,
                session,
                self.generation,
            );
            assert_ext4_outcome(
                stale_pid,
                &recorded,
                &live_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::RecycledRefused,
            )?;
        }
        eprintln!(
            "D4_EXT4 row={row} verdict=stale-refused target-{}",
            brsv_verdict(&recorded)
        );
        Ok(())
    }

    /// Deleted mapping (not inode reuse): the live holder keeps a
    /// ` (deleted)` line under the old number while temp+rename takes a
    /// fresh one, and both legs refuse the unusable line with the named
    /// loss. The stale key stays per-range (the pinned object is the
    /// replacement), but the kernel leg still proves nothing: the
    /// unusable line refuses before proof (zero runs).
    fn row_deleted_mapping(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_EXT4 start row=deleted-mapping");
        let _ = work;
        let fs = Ext4Loop::new();
        let path = fs.mount.join("lib.so");
        std::fs::write(&path, vec![0xE4u8; 8192])
            .map_err(|error| format!("ext4 deleted-mapping write: {error}"))?;
        let target = SwapChild::spawn(&path);
        let pre = target.maps();
        let pre_line = find_line(&pre, child_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&pre_line);
        let (old_ino, new_ino) = replace_file(&path, vec![0xE5u8; 4096])?;
        if old_ino == new_ino {
            return Err("ext4 deleted-mapping: temp+rename must take a fresh number".into());
        }
        let post = target.maps();
        let post_line = find_line_deleted(&post, child_range(&target))?;
        let anchor = SwapChild::spawn(&path);
        let a_snap = anchor.maps();
        let a_line = find_line(&a_snap, child_range(&anchor), *b"r-xp")?;
        if ObjectKey::of(&a_line) == key {
            return Err("ext4 deleted-mapping: premise needs a fresh number".into());
        }
        let (pins, object) = ext4_pin(&path, key)?;
        let index = ext4_index(key, object, &pins);
        let t_truth = record_ext4_truth(target.pid as u32, child_range(&target), &path)?;
        let a_truth = record_ext4_truth(anchor.pid as u32, child_range(&anchor), &path)?;
        let _ = (&pre_line, &post_line, &a_line);
        assert_brsv_changed(&t_truth)?;
        assert_brsv_live(&a_truth)?;
        let pid = target.pid as u32;
        let userspace = d4_ext4_attribute_pid(pid, post, &index);
        ext4_deleted(&userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_no_run_stale_key_for_pid(
                pid,
                target.maps(),
                &pins,
                object,
                key,
                session,
                self.generation,
                Ext4Expect::DeletedMappingStaleKey,
            );
            assert_ext4_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::DeletedMappingStaleKey,
            )?;
        }
        eprintln!(
            "D4_EXT4 row=deleted-mapping verdict=named-refusal target-{}",
            brsv_verdict(&t_truth)
        );
        Ok(())
    }

    /// Live holder on ext4: the identity-key edge, with the kernel leg
    /// reaching it through the AnchorNotInstalled userspace fallback
    /// (never kernel parity).
    fn row_live_holder(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_EXT4 start row=live-holder");
        let _ = work;
        let fs = Ext4Loop::new();
        let path = fs.mount.join("lib.so");
        std::fs::write(&path, vec![0xE4u8; 8192])
            .map_err(|error| format!("ext4 live-holder write: {error}"))?;
        let anchor = SwapChild::spawn(&path);
        let target = SwapChild::spawn(&path);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, child_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, child_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = ext4_pin(&path, key)?;
        let index = ext4_index(key, object, &pins);
        let t_truth = record_ext4_truth(target.pid as u32, child_range(&target), &path)?;
        let a_truth = record_ext4_truth(anchor.pid as u32, child_range(&anchor), &path)?;
        let _ = t_line;
        assert_brsv_live(&t_truth)?;
        assert_brsv_live(&a_truth)?;
        let pid = target.pid as u32;
        let userspace = d4_ext4_attribute_pid(pid, t_snap.clone(), &index);
        ext4_edge(pid, key, &userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_live_holder_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                session,
                self.generation,
            );
            assert_ext4_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::LiveHolderEdge,
            )?;
        }
        eprintln!(
            "D4_EXT4 row=live-holder verdict=identity-edge target-{}",
            brsv_verdict(&t_truth)
        );
        Ok(())
    }

    /// Wrong-file negative: the mapper names a different file, so no
    /// candidate exists on either backend.
    fn row_wrong_file(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_EXT4 start row=wrong-file");
        let _ = work;
        let fs = Ext4Loop::new();
        let held = fs.mount.join("lib.so");
        let other = fs.mount.join("other.so");
        std::fs::write(&held, vec![0xE4u8; 8192])
            .map_err(|error| format!("ext4 wrong-file write held: {error}"))?;
        std::fs::write(&other, vec![0xE5u8; 8192])
            .map_err(|error| format!("ext4 wrong-file write other: {error}"))?;
        let anchor = SwapChild::spawn(&held);
        let target = SwapChild::spawn(&other);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, child_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, child_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = ext4_pin(&held, key)?;
        let index = ext4_index(key, object, &pins);
        let t_truth = record_ext4_truth(target.pid as u32, child_range(&target), &other)?;
        let a_truth = record_ext4_truth(anchor.pid as u32, child_range(&anchor), &held)?;
        let _ = t_line;
        assert_brsv_live(&t_truth)?;
        assert_brsv_live(&a_truth)?;
        let pid = target.pid as u32;
        let userspace = d4_ext4_attribute_pid(pid, t_snap.clone(), &index);
        ext4_no_candidate(&userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_no_run_identity_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                session,
                self.generation,
            );
            assert_ext4_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::WrongFileNone,
            )?;
        }
        eprintln!(
            "D4_EXT4 row=wrong-file verdict=parity-none target-{}",
            brsv_verdict(&t_truth)
        );
        Ok(())
    }

    /// Data-only negative: the mapper holds the file without execute
    /// permission, so proof demand stays zero on both backends.
    fn row_data_only(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_EXT4 start row=data-only");
        let _ = work;
        let fs = Ext4Loop::new();
        let path = fs.mount.join("lib.so");
        std::fs::write(&path, vec![0xE4u8; 8192])
            .map_err(|error| format!("ext4 data-only write: {error}"))?;
        let anchor = SwapChild::spawn(&path);
        let target = SwapChild::spawn_with(&[(&path, false)]);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, child_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, child_range(&target), *b"r--p")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = ext4_pin(&path, key)?;
        let index = ext4_index(key, object, &pins);
        let t_truth = record_ext4_truth(target.pid as u32, child_range(&target), &path)?;
        let a_truth = record_ext4_truth(anchor.pid as u32, child_range(&anchor), &path)?;
        let _ = t_line;
        assert_brsv_live(&t_truth)?;
        assert_brsv_live(&a_truth)?;
        let pid = target.pid as u32;
        let userspace = d4_ext4_attribute_pid(pid, t_snap.clone(), &index);
        ext4_no_candidate(&userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_no_run_identity_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                session,
                self.generation,
            );
            assert_ext4_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::DataOnlyNone,
            )?;
        }
        eprintln!(
            "D4_EXT4 row=data-only verdict=zero-demand target-{}",
            brsv_verdict(&t_truth)
        );
        Ok(())
    }

    /// G28 equal-bytes mutation: the same recycled shape, but the
    /// replacement carries identical bytes — equal bytes are not
    /// physical identity, so the stale sweep still refuses both ways.
    fn row_equal_bytes(&mut self, work: &std::path::Path) -> Result<(), String> {
        self.row_recycled_shape("equal-bytes", vec![0xE4u8; 8192], true, work)
    }

    /// Live byte-identical copy (not inode reuse): a second file with the
    /// same bytes under a FRESH number is mapped while the held file's
    /// holder lives, and both legs refuse the copy — equal bytes are not
    /// physical identity. The recycled rows refuse only because their
    /// holder exited; this row's holder lives, so a bytes-joining mutant
    /// would edge here.
    fn row_live_copy(&mut self, work: &std::path::Path) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        eprintln!("D4_EXT4 start row=live-copy");
        let _ = work;
        let fs = Ext4Loop::new();
        let held = fs.mount.join("lib.so");
        let copy = fs.mount.join("copy.so");
        let bytes = vec![0xE4u8; 8192];
        std::fs::write(&held, &bytes)
            .map_err(|error| format!("ext4 live-copy write held: {error}"))?;
        std::fs::write(&copy, &bytes)
            .map_err(|error| format!("ext4 live-copy write copy: {error}"))?;
        // Premise: identical bytes, different inodes.
        let held_bytes =
            std::fs::read(&held).map_err(|error| format!("ext4 live-copy reread held: {error}"))?;
        let copy_bytes =
            std::fs::read(&copy).map_err(|error| format!("ext4 live-copy reread copy: {error}"))?;
        if held_bytes != copy_bytes {
            return Err("ext4 live-copy: premise needs identical bytes".into());
        }
        let held_ino = std::fs::metadata(&held)
            .map_err(|error| format!("ext4 live-copy stat held: {error}"))?
            .ino();
        let copy_ino = std::fs::metadata(&copy)
            .map_err(|error| format!("ext4 live-copy stat copy: {error}"))?
            .ino();
        if held_ino == copy_ino {
            return Err("ext4 live-copy: premise needs a different inode".into());
        }
        let anchor = SwapChild::spawn(&held);
        let target = SwapChild::spawn(&copy);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, child_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, child_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        if ObjectKey::of(&t_line) == key {
            return Err("ext4 live-copy: premise needs differing maps keys".into());
        }
        let (pins, object) = ext4_pin(&held, key)?;
        let index = ext4_index(key, object, &pins);
        let t_truth = record_ext4_truth(target.pid as u32, child_range(&target), &copy)?;
        let a_truth = record_ext4_truth(anchor.pid as u32, child_range(&anchor), &held)?;
        let _ = t_line;
        assert_brsv_live(&t_truth)?;
        assert_brsv_live(&a_truth)?;
        let pid = target.pid as u32;
        let userspace = d4_ext4_attribute_pid(pid, t_snap.clone(), &index);
        ext4_no_candidate(&userspace, "userspace")?;
        if let Some(session) = self.session.as_deref_mut() {
            self.generation += 1;
            let (kernel, evidence) = d4_ext4_kernel_no_run_identity_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                session,
                self.generation,
            );
            assert_ext4_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                Ext4Expect::LiveCopyNone,
            )?;
        }
        eprintln!(
            "D4_EXT4 row=live-copy verdict=parity-none target-{}",
            brsv_verdict(&t_truth)
        );
        Ok(())
    }
}

fn child_range(child: &SwapChild) -> (u64, u64) {
    (child.address, child.address + 4096)
}
