//! SPDX-License-Identifier: GPL-3.0-or-later
//! D4 overlay cells: xino on/off/same-fs backend parity and divergence.
//!
//! Lane A (pre-6.8) renders the backing inode in maps; lane B (6.8+)
//! the overlay inode, while map_files follows the overlay path on both
//! (D-C7 finding 1). The corrected lane table binds every row: lower
//! parity, post-copy-up parity (A) or D-C7-3 (B), two-mount D-C7-2 (A)
//! or parity-none (B), the xino-off collision (parity-none on A, named
//! mismatch on B), and wrong-file/data-only negatives. Same-fs rows
//! qualify the usual container layout against xino-on behavior.
//!
//! If the recorded truth ever shows map_files rendering the backing
//! file on ext4 layers instead, the N4 identity-key branch takes over:
//! the key is its own identity, the kernel leg classifies "no kernel
//! proof (identity key)", and no lane-A row flips as kernel parity. A
//! row that takes the branch prints a distinct verdict and trips the
//! cell: the top level then fails named instead of printing its table
//! verdict, so a ready pair can never qualify silently.
//! The stat-based xino verdict (never mountinfo) gates the requested
//! mode; a contradiction fails the cell.

use super::*;
use std::time::{Duration, Instant};

/// Overlay lane by the `file_user_inode` boundary: A renders the
/// backing inode in maps (pre-6.8), B the overlay inode (6.8+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayLane {
    A,
    B,
}

impl OverlayLane {
    /// Pure lane rule over a `/proc/sys/kernel/osrelease` string: below
    /// 6.8 is A, 6.8+ is B; pre-6 and garbage refuse.
    fn of_release(release: &str) -> Result<Self, String> {
        let (major, minor) = crate::doctor::parse_major_minor(release.trim())
            .ok_or_else(|| format!("OVERLAY-PREFLIGHT lane: unparseable release {release:?}"))?;
        if major < 6 {
            return Err(format!(
                "OVERLAY-PREFLIGHT lane: pre-6 kernel {major}.{minor} has no BPF identity lane"
            ));
        }
        if (major, minor) < (6, 8) {
            Ok(OverlayLane::A)
        } else {
            Ok(OverlayLane::B)
        }
    }

    fn detect() -> Result<Self, String> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| format!("OVERLAY-PREFLIGHT kernel-release: {error}"))?;
        Self::of_release(&release)
    }
}

/// Named-precondition gate: root (mounts), loop, mkfs.ext4, the overlay
/// module and the map_files capability. Any miss FAILS with its name;
/// nothing here ever skips.
fn overlay_preflight() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("OVERLAY-PREFLIGHT root: overlay mounts and map_files need root".into());
    }
    if std::fs::metadata("/dev/loop-control").is_err() {
        return Err("OVERLAY-PREFLIGHT loop: /dev/loop-control is missing".into());
    }
    if !mkfs_ext4_present() {
        return Err("OVERLAY-PREFLIGHT mkfs.ext4: no mkfs.ext4 on PATH".into());
    }
    let filesystems = std::fs::read_to_string("/proc/filesystems")
        .map_err(|error| format!("OVERLAY-PREFLIGHT overlay: /proc/filesystems: {error}"))?;
    if !filesystems.lines().any(|line| line.ends_with("overlay")) {
        return Err("OVERLAY-PREFLIGHT overlay: overlayfs not in /proc/filesystems".into());
    }
    probe_map_files_capability()
}

fn mkfs_ext4_present() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join("mkfs.ext4").is_file())
    })
}

/// Open one of this process's own file-map map_files entries: without
/// the capability this fails EPERM/EACCES and no range proof is
/// possible. Anonymous and bracket mappings have no entries, so only
/// real file lines count as attempts.
fn probe_map_files_capability() -> Result<(), String> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("OVERLAY-PREFLIGHT map_files: /proc/self/maps: {error}"))?;
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
                    // A mapping that vanished mid-scan proves nothing;
                    // try the next file line.
                    Kind::NotFound => continue,
                    _ => {
                        return Err(format!("OVERLAY-PREFLIGHT map_files: {entry}: {error}"));
                    }
                }
            }
            Err(error) => {
                return Err(format!("OVERLAY-PREFLIGHT map_files: {entry}: {error}"));
            }
        }
    }
    Err(format!(
        "OVERLAY-PREFLIGHT map_files: no provable file mapping found ({tried} tried)"
    ))
}

/// Overlay xino mode under test: distinct-filesystem layers with xino
/// forced on or off, or the same-filesystem qualification row (all
/// layers on one loop ext4, no xino option — the usual container
/// layout, expected to behave like xino on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XinoMode {
    On,
    Off,
    SameFs,
}

/// One mounted overlay merge; unmounted (lazily if busy) on drop.
/// Always dropped before the loop layers (locals drop before the
/// fixture that owns them, fields in order).
struct MergedMount {
    mountpoint: std::path::PathBuf,
}

impl Drop for MergedMount {
    fn drop(&mut self) {
        let unmounted = std::process::Command::new("umount")
            .arg(&self.mountpoint)
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(&self.mountpoint)
                .status();
        }
    }
}

/// Two fresh loop ext4 layers (distinct filesystems, so xino changes
/// something) or one (same-fs mode), with the primary merged mount.
/// Upper/work dirs live on the upper layer; second mounts reuse the
/// same lower through fresh upper/work subdirs.
struct OverlayFixture {
    merged: MergedMount,
    lower: Ext4Loop,
    upper: Option<Ext4Loop>,
    mode: XinoMode,
}

impl OverlayFixture {
    /// Mount one overlay: fresh loop ext4 layers (two, or one for
    /// same-fs), lower/upper/work subdirs, and the merged mount under
    /// `root`. Fails closed with the failed step named.
    fn mount(root: &std::path::Path, xino: XinoMode) -> Result<Self, String> {
        let lower = Ext4Loop::new();
        let upper = match xino {
            XinoMode::SameFs => None,
            XinoMode::On | XinoMode::Off => Some(Ext4Loop::new()),
        };
        let fixture = Self {
            merged: MergedMount {
                mountpoint: root.join("merged1"),
            },
            lower,
            upper,
            mode: xino,
        };
        let lowerdir = fixture.lowerdir();
        let upperdir = fixture.upper_base().join("upper1");
        let workdir = fixture.upper_base().join("work1");
        for dir in [&lowerdir, &upperdir, &workdir, &fixture.merged.mountpoint] {
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("overlay mkdir {}: {error}", dir.display()))?;
        }
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}{}",
            lowerdir.display(),
            upperdir.display(),
            workdir.display(),
            fixture.xino_opt()
        );
        mount_overlay(&opts, &fixture.merged.mountpoint)?;
        Ok(fixture)
    }

    /// A second merged mount over the SAME lower with fresh upper/work
    /// (the two-mounts row): a distinct overlay s_dev over the same
    /// backing files.
    fn mount_second(&self, root: &std::path::Path, tag: &str) -> Result<MergedMount, String> {
        let upperdir = self.upper_base().join(format!("upper{tag}"));
        let workdir = self.upper_base().join(format!("work{tag}"));
        let mountpoint = root.join(format!("merged{tag}"));
        for dir in [&upperdir, &workdir, &mountpoint] {
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("overlay mkdir {}: {error}", dir.display()))?;
        }
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}{}",
            self.lowerdir().display(),
            upperdir.display(),
            workdir.display(),
            self.xino_opt()
        );
        mount_overlay(&opts, &mountpoint)?;
        Ok(MergedMount { mountpoint })
    }

    fn xino_opt(&self) -> &'static str {
        match self.mode {
            XinoMode::On => ",xino=on",
            XinoMode::Off => ",xino=off",
            XinoMode::SameFs => "",
        }
    }

    fn upper_base(&self) -> std::path::PathBuf {
        self.upper
            .as_ref()
            .map_or_else(|| self.lower.mount.clone(), |fs| fs.mount.clone())
    }

    fn lowerdir(&self) -> std::path::PathBuf {
        self.lower.mount.join("lower")
    }

    fn lower_path(&self, name: &str) -> std::path::PathBuf {
        self.lowerdir().join(name)
    }

    fn upper_path(&self, name: &str) -> std::path::PathBuf {
        self.upper_base().join("upper1").join(name)
    }

    fn merged_path(&self, name: &str) -> std::path::PathBuf {
        self.merged.mountpoint.join(name)
    }

    /// The N3 stat verdict on a lower-layer non-directory seen through
    /// the primary merge: effective when its st_dev equals the merge
    /// root's (distinct-fs layers), off when it reports another
    /// (pseudo) device. Fails when the observed mode contradicts the
    /// requested one; same-fs only records alongside xino_auto.
    fn xino_verdict(&self, lower_name: &str) -> Result<(bool, String), String> {
        use std::os::unix::fs::MetadataExt as _;
        let through = std::fs::metadata(self.merged_path(lower_name))
            .map_err(|error| format!("overlay xino stat {lower_name}: {error}"))?;
        let root = std::fs::metadata(&self.merged.mountpoint)
            .map_err(|error| format!("overlay xino stat merge root: {error}"))?;
        let effective = through.dev() == root.dev();
        match self.mode {
            XinoMode::On if !effective => {
                return Err(format!(
                    "overlay xino: requested on but stat reports pseudo device {} (root {})",
                    through.dev(),
                    root.dev()
                ));
            }
            XinoMode::Off if effective => {
                return Err(format!(
                    "overlay xino: requested off but stat reports the merge device {}",
                    root.dev()
                ));
            }
            XinoMode::On | XinoMode::Off | XinoMode::SameFs => {}
        }
        let auto = std::fs::read_to_string("/sys/module/overlay/parameters/xino_auto")
            .map(|text| text.trim().to_string())
            .unwrap_or_else(|_| "missing".to_string());
        Ok((effective, auto))
    }
}

fn mount_overlay(opts: &str, mountpoint: &std::path::Path) -> Result<(), String> {
    let status = std::process::Command::new("mount")
        .args(["-t", "overlay", "-o", opts])
        .arg("overlay")
        .arg(mountpoint)
        .status()
        .map_err(|error| format!("overlay mount: mount(8) is required: {error}"))?;
    if !status.success() {
        return Err(format!("overlay mount -o {opts}: {status}"));
    }
    Ok(())
}

/// Ground truth recorded per side and leg: the rendered maps line, the
/// map_files stat and statfs magic, the held fd's fstat, the stat-based
/// xino verdict, and whether map_files shows the backing file (the N4
/// identity-key branch input).
struct OverlayTruth {
    maps_line: String,
    map_files_dev: u64,
    map_files_ino: u64,
    statfs_magic: u64,
    held_fstat: (u64, u64),
    xino_effective: bool,
    xino_auto: String,
    map_files_backing: bool,
    /// xino-off × post-copy-up only: whether consecutive map_files stats
    /// agree (non-persistent st_ino makes the userspace edge follow
    /// recorded truth instead of a fixed shape).
    xino_off_copy_up_stable: Option<bool>,
}

impl OverlayTruth {
    /// The maps key of the recorded line, parsed with the production
    /// parser (a line that refuses to parse fails the row, never joins
    /// by luck).
    fn maps_key(&self) -> ObjectKey {
        let entries = p11scope_manifest::maps::parse_maps(self.maps_line.as_bytes())
            .expect("recorded maps line parses");
        assert_eq!(entries.len(), 1, "one recorded line");
        ObjectKey::of(&entries[0])
    }

    fn map_files_identity(&self) -> FileIdentity {
        FileIdentity {
            dev: self.map_files_dev,
            ino: self.map_files_ino,
        }
    }
}

/// Record ground truth for one mapped range of `pid`: the actual
/// /proc/<pid>/maps line, the map_files stat plus statfs magic, the
/// held fd's fstat, and whether map_files is stat-equal to the side's
/// backing file. `xino` carries the fixture-level N3 verdict.
#[allow(clippy::too_many_arguments)]
fn record_truth(
    pid: u32,
    range: (u64, u64),
    held: &std::fs::File,
    backing_path: &std::path::Path,
    xino: (bool, String),
    stable: Option<bool>,
) -> Result<OverlayTruth, String> {
    use std::os::unix::fs::MetadataExt as _;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|error| format!("overlay truth maps {pid}: {error}"))?;
    let prefix = format!("{:x}-{:x} ", range.0, range.1);
    let maps_line = maps
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("overlay truth: no maps line for {prefix:?} of {pid}"))?
        .to_string();
    let entry = format!("/proc/{pid}/map_files/{:x}-{:x}", range.0, range.1);
    let stat = std::fs::metadata(&entry)
        .map_err(|error| format!("overlay truth map_files {entry}: {error}"))?;
    let magic = statfs_magic(&entry)?;
    let fstat = held
        .metadata()
        .map_err(|error| format!("overlay truth held fstat: {error}"))?;
    let backing = std::fs::metadata(backing_path)
        .map_err(|error| format!("overlay truth backing {}: {error}", backing_path.display()))?;
    Ok(OverlayTruth {
        maps_line,
        map_files_dev: stat.dev(),
        map_files_ino: stat.ino(),
        statfs_magic: magic,
        held_fstat: (fstat.dev(), fstat.ino()),
        xino_effective: xino.0,
        xino_auto: xino.1,
        map_files_backing: stat.dev() == backing.dev() && stat.ino() == backing.ino(),
        xino_off_copy_up_stable: stable,
    })
}

fn statfs_magic(path: &str) -> Result<u64, String> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_path =
        std::ffi::CString::new(path).map_err(|error| format!("overlay statfs path: {error}"))?;
    // SAFETY: a valid path with a writable buffer, read only on success.
    if unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "overlay statfs {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: initialized by the successful statfs.
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    Ok(unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff)
}

/// One-line ground-truth summary for the verdict log: rendering,
/// statfs magic, the xino verdict and the held fstat.
fn truth_verdict(truth: &OverlayTruth) -> String {
    format!(
        "backing={} magic={:#x} xino={} auto={} held={:?} mapfiles=({},{})",
        truth.map_files_backing,
        truth.statfs_magic,
        truth.xino_effective,
        truth.xino_auto,
        truth.held_fstat,
        truth.map_files_dev,
        truth.map_files_ino,
    )
}

/// Whether consecutive map_files stats of one range agree (the
/// xino-off × post-copy-up expectation input: non-persistent st_ino
/// reads its userspace edge from this instead of a fixed shape).
fn map_files_stable(pid: u32, range: (u64, u64)) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt as _;
    let entry = format!("/proc/{pid}/map_files/{:x}-{:x}", range.0, range.1);
    let first =
        std::fs::metadata(&entry).map_err(|error| format!("overlay stability {entry}: {error}"))?;
    for _ in 0..4 {
        let next = std::fs::metadata(&entry)
            .map_err(|error| format!("overlay stability {entry}: {error}"))?;
        if (next.dev(), next.ino()) != (first.dev(), first.ino()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Both merges of a two-mounts row share one lowerdir: read back from
/// mountinfo (not from the construction call), so the "same backing
/// files" premise behind the zero-false-edges claim is observed.
fn assert_shared_lower(first: &std::path::Path, second: &std::path::Path) -> Result<(), String> {
    fn lower_of(mountpoint: &std::path::Path) -> Result<String, String> {
        let info = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|error| format!("overlay mountinfo: {error}"))?;
        for line in info.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(4) != Some(&mountpoint.to_str().unwrap_or("")) {
                continue;
            }
            let options = fields.last().unwrap_or(&"");
            for opt in options.split(',') {
                if let Some(lower) = opt.strip_prefix("lowerdir=") {
                    return Ok(lower.to_string());
                }
            }
            return Err(format!(
                "overlay mountinfo: no lowerdir for {}",
                mountpoint.display()
            ));
        }
        Err(format!(
            "overlay mountinfo: no entry for {}",
            mountpoint.display()
        ))
    }
    let a = lower_of(first)?;
    let b = lower_of(second)?;
    if a != b {
        return Err(format!("two mounts diverge at lowerdir: {a} vs {b}"));
    }
    Ok(())
}

/// Copy a merged file up by writing through the merge, then prove the
/// copy-up happened: the merged bytes changed, the upper file exists
/// and matches the merge, and the lower file is untouched.
fn trigger_copy_up(
    merged: &std::path::Path,
    upper: &std::path::Path,
    lower: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write as _;
    let before =
        std::fs::read(merged).map_err(|error| format!("overlay copy-up read before: {error}"))?;
    {
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(merged)
            .map_err(|error| format!("overlay copy-up open for write: {error}"))?;
        writer
            .write_all(b"X")
            .map_err(|error| format!("overlay copy-up write: {error}"))?;
    }
    let after =
        std::fs::read(merged).map_err(|error| format!("overlay copy-up read after: {error}"))?;
    if before == after {
        return Err("overlay copy-up wrote nothing observable".into());
    }
    if !upper.exists() {
        return Err(format!(
            "overlay copy-up did not materialize {}",
            upper.display()
        ));
    }
    let still_lower =
        std::fs::read(lower).map_err(|error| format!("overlay copy-up read lower: {error}"))?;
    if still_lower != before {
        return Err("overlay copy-up modified the lower file".into());
    }
    let upper_bytes =
        std::fs::read(upper).map_err(|error| format!("overlay copy-up read upper: {error}"))?;
    if upper_bytes != after {
        return Err("overlay copy-up left the merge behind the upper file".into());
    }
    Ok(())
}

/// Two different files with equal real inode numbers, one per layer:
/// a fixed lower set first, then upper files through the merge until
/// one's upper-filesystem inode lands in the set. Returns the merged
/// names (lower file, upper file).
fn equal_ino_pair(fixture: &OverlayFixture) -> Result<(String, String), String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut lower_inos = BTreeSet::new();
    for i in 0..8u8 {
        let name = format!("cf1_{i}.so");
        std::fs::write(
            fixture.lower_path(&name),
            vec![0xC1u8.wrapping_add(i); 4096],
        )
        .map_err(|error| format!("overlay collision write {name}: {error}"))?;
        let ino = std::fs::metadata(fixture.lower_path(&name))
            .map_err(|error| format!("overlay collision stat {name}: {error}"))?
            .ino();
        lower_inos.insert(ino);
    }
    for i in 0..8u8 {
        let name = format!("cf2_{i}.so");
        std::fs::write(
            fixture.merged_path(&name),
            vec![0xD1u8.wrapping_add(i); 4096],
        )
        .map_err(|error| format!("overlay collision write {name}: {error}"))?;
        // The real upper-filesystem inode, read through the upperdir:
        // the merged stat would show overlay rendering instead.
        let upper = fixture.upper_path(&name);
        if !upper.exists() {
            return Err(format!(
                "overlay collision: {} never landed on the upper layer",
                upper.display()
            ));
        }
        let ino = std::fs::metadata(&upper)
            .map_err(|error| format!("overlay collision stat upper {name}: {error}"))?
            .ino();
        if lower_inos.contains(&ino) {
            let lower_name = (0..8u8)
                .map(|j| format!("cf1_{j}.so"))
                .find(|candidate| {
                    std::fs::metadata(fixture.lower_path(candidate))
                        .is_ok_and(|meta| meta.ino() == ino)
                })
                .ok_or_else(|| "overlay collision: lower match vanished".to_string())?;
            return Ok((lower_name, name));
        }
    }
    Err("overlay collision: no equal-inode pair in eight upper files".into())
}

fn find_line(snapshot: &[MapEntry], range: (u64, u64), perms: [u8; 4]) -> Result<MapEntry, String> {
    snapshot
        .iter()
        .find(|entry| (entry.start, entry.end) == range && entry.permissions == perms)
        .cloned()
        .ok_or_else(|| {
            format!("overlay snapshot: no {perms:?} line for {range:08x?} in {snapshot:?}")
        })
}

/// Pin the held file through the merged path on the anchor key, like
/// production pins a provider (self-mapping probe included).
fn overlay_pin(
    merged: &std::path::Path,
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
    let bytes = std::fs::read(merged).map_err(|error| format!("overlay pin read: {error}"))?;
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins = real_scan_pin(merged, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("held-file pin").id;
    Ok((pins, object))
}

fn overlay_index(
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

/// What the kernel leg observably did: the fallback ledger (zero for
/// a real kernel proof, AnchorNotInstalled for the identity-key
/// branch), the userspace reads it performed (zero for a real proof
/// and for the identity-key fallback, whose prove set is empty), and
/// the index preconditions (a per-range key exactly off the
/// identity-key branch; validated slots always — anchors install for
/// arena-mapped files on any filesystem).
struct KernelLegEvidence {
    fallback: crate::discovery::kernel_identity::KernelFallbackTotals,
    userspace_reads: usize,
    slots_nonempty: bool,
    per_range_key: bool,
    no_proof_classification: Option<&'static str>,
}

/// The tabled outcome for one overlay row: agreement (edge or
/// no-candidate none), the two allowed divergences, a named-mismatch
/// negative, a zero-demand data-only row, or the N4 identity-key branch
/// (userspace decides alone; the kernel leg proves nothing by
/// construction and the row never flips as kernel parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayExpect {
    Parity(bool),
    DivergenceC72(bool, bool),
    DivergenceC73,
    Negative,
    DataOnly,
    IdentityKeyNoProof,
}

/// Assert one overlay row: the maps-key premise from both sides'
/// recorded lines first (a violated premise fails the row, never
/// passes by luck), then the per-backend members/losses/demand, then
/// the kernel-leg evidence (a claimed kernel edge needs a real kernel
/// proof; the identity-key branch needs its classification).
#[allow(clippy::too_many_arguments)]
fn assert_overlay_outcome(
    pid: u32,
    target: &OverlayTruth,
    anchor: &OverlayTruth,
    userspace: &SweepAttribution,
    kernel: &SweepAttribution,
    evidence: &KernelLegEvidence,
    expected: OverlayExpect,
) -> Result<(), String> {
    fn edge(pid: u32, key: ObjectKey, out: &SweepAttribution, side: &str) -> Result<(), String> {
        let members: Vec<u32> = out.members.iter().map(|member| member.pid).collect();
        if members != [pid] {
            return Err(format!(
                "overlay {side}: expected edge for {pid}, members {members:?} losses {:?} probed {}",
                out.losses, out.probed
            ));
        }
        if !out.losses.is_empty() {
            return Err(format!("overlay {side}: edge with losses {:?}", out.losses));
        }
        if out.probed != 1 {
            return Err(format!("overlay {side}: edge with probed {}", out.probed));
        }
        let keys: Vec<ObjectKey> = out.members[0].objects.iter().map(|o| o.key).collect();
        if keys != [key] {
            return Err(format!(
                "overlay {side}: edge for {keys:?}, row key is {key:?}"
            ));
        }
        Ok(())
    }
    fn no_candidate(out: &SweepAttribution, side: &str) -> Result<(), String> {
        if !out.members.is_empty() || out.probed != 0 || !out.losses.is_empty() {
            return Err(format!(
                "overlay {side}: expected no candidate, members {:?} losses {:?} probed {}",
                out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
                out.losses,
                out.probed
            ));
        }
        Ok(())
    }
    fn mismatch(out: &SweepAttribution, side: &str) -> Result<(), String> {
        if !out.members.is_empty()
            || out.losses != BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
            || out.probed != 1
        {
            return Err(format!(
                "overlay {side}: expected named mismatch, members {:?} losses {:?} probed {}",
                out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
                out.losses,
                out.probed
            ));
        }
        Ok(())
    }
    let keys_equal = target.maps_key() == anchor.maps_key();
    let row_key = target.maps_key();
    let backing = target.map_files_backing || anchor.map_files_backing;
    let kernel_proof = || -> Result<(), String> {
        if !evidence.per_range_key {
            return Err("overlay kernel: leg ran without a per-range key".into());
        }
        if !evidence.slots_nonempty {
            return Err("overlay kernel: leg ran with no validated slots".into());
        }
        let fallback = &evidence.fallback;
        if fallback.passes != 0 || fallback.pids != 0 || fallback.keys != 0 {
            return Err(format!(
                "overlay kernel: leg fell back (passes {} pids {} keys {} first {:?})",
                fallback.passes, fallback.pids, fallback.keys, fallback.first_reason
            ));
        }
        if fallback.first_reason.is_some() {
            return Err(format!(
                "overlay kernel: leg has a fallback reason {:?}",
                fallback.first_reason
            ));
        }
        if evidence.userspace_reads != 0 {
            return Err(format!(
                "overlay kernel: leg performed {} userspace reads",
                evidence.userspace_reads
            ));
        }
        Ok(())
    };
    match expected {
        OverlayExpect::Parity(want_edge) => {
            if want_edge {
                if backing {
                    return Err(
                        "overlay parity edge needs overlay rendering; backing rendering is the identity-key branch"
                            .into(),
                    );
                }
                if !keys_equal {
                    return Err("overlay parity edge needs equal maps keys".into());
                }
                edge(pid, row_key, userspace, "userspace")?;
                edge(pid, row_key, kernel, "kernel")?;
                kernel_proof()?;
            } else {
                if keys_equal {
                    return Err("overlay parity none needs differing maps keys".into());
                }
                no_candidate(userspace, "userspace")?;
                no_candidate(kernel, "kernel")?;
                // Nothing ran, so rendering cannot matter; it only has
                // to agree with the evidence shape (per-range proof
                // exactly when not backing).
                check_no_run_evidence(evidence, backing)?;
            }
            Ok(())
        }
        OverlayExpect::DivergenceC72(want_userspace_edge, want_kernel_edge) => {
            if backing {
                return Err(
                    "overlay D-C7-2 needs overlay rendering; backing rendering is the identity-key branch"
                        .into(),
                );
            }
            if !keys_equal {
                return Err(
                    "overlay D-C7-2 needs equal maps keys (same lower through two mounts)".into(),
                );
            }
            if want_userspace_edge {
                edge(pid, row_key, userspace, "userspace")?;
            } else {
                mismatch(userspace, "userspace")?;
            }
            if want_kernel_edge {
                edge(pid, row_key, kernel, "kernel")?;
                kernel_proof()?;
            } else {
                mismatch(kernel, "kernel")?;
                // A kernel mismatch still answers (Unmatched), never
                // falls back: the proof ran clean.
                kernel_proof()?;
            }
            Ok(())
        }
        OverlayExpect::DivergenceC73 => {
            if backing {
                return Err(
                    "overlay D-C7-3 needs overlay rendering; backing rendering is the identity-key branch"
                        .into(),
                );
            }
            if !keys_equal {
                return Err(
                    "overlay D-C7-3 needs equal maps keys (stable overlay inode across copy-up)"
                        .into(),
                );
            }
            // Userspace follows recorded truth on xino-off ×
            // post-copy-up (non-persistent st_ino); otherwise it edges
            // against the stale anchor while the kernel says other.
            let want_edge = target.xino_off_copy_up_stable.unwrap_or(true);
            if want_edge {
                edge(pid, row_key, userspace, "userspace")?;
            } else {
                mismatch(userspace, "userspace")?;
            }
            mismatch(kernel, "kernel")?;
            kernel_proof()?;
            Ok(())
        }
        OverlayExpect::Negative => {
            if backing {
                return Err(
                    "overlay negative needs overlay rendering; backing rendering is the identity-key branch"
                        .into(),
                );
            }
            if !keys_equal {
                return Err(
                    "overlay named-mismatch negative needs equal maps keys (xino-off collision)"
                        .into(),
                );
            }
            mismatch(userspace, "userspace")?;
            mismatch(kernel, "kernel")?;
            kernel_proof()?;
            Ok(())
        }
        OverlayExpect::DataOnly => {
            // Nothing runs, so rendering cannot matter; it only has to
            // agree with the evidence shape (per-range proof exactly
            // when not backing).
            if !keys_equal {
                return Err("overlay data-only needs equal maps keys (same file)".into());
            }
            no_candidate(userspace, "userspace")?;
            no_candidate(kernel, "kernel")?;
            check_no_run_evidence(evidence, backing)?;
            Ok(())
        }
        OverlayExpect::IdentityKeyNoProof => {
            if !(target.map_files_backing && anchor.map_files_backing) {
                return Err(
                    "overlay identity-key branch needs backing rendering on both sides".into(),
                );
            }
            // Userspace decides alone through the identity path; the
            // kernel leg reaches the same edge through its
            // AnchorNotInstalled userspace fallback, proving nothing
            // and reading nothing: the prove set is empty.
            edge(pid, row_key, userspace, "userspace")?;
            edge(pid, row_key, kernel, "kernel")?;
            if evidence.no_proof_classification != Some("no kernel proof (identity key)") {
                return Err("overlay identity-key branch needs its no-proof classification".into());
            }
            if evidence.fallback.first_reason
                != Some(crate::discovery::kernel_identity::KernelFallbackReason::AnchorNotInstalled)
            {
                return Err(format!(
                    "overlay identity-key branch needs AnchorNotInstalled, got {:?}",
                    evidence.fallback.first_reason
                ));
            }
            if evidence.userspace_reads != 0 {
                return Err("overlay identity-key fallback reads nothing".into());
            }
            if evidence.per_range_key {
                return Err("overlay identity key takes no per-range proof".into());
            }
            if !evidence.slots_nonempty {
                return Err("overlay identity key still installs its anchor slots".into());
            }
            Ok(())
        }
    }
}

/// The no-run evidence shape follows the rendering: a per-range key
/// exactly when not backing, the no-proof classification exactly when
/// backing, installed slots either way (anchors install for
/// arena-mapped files on any filesystem), and zero fallback plus zero
/// reads either way (nothing ran to fall back or read).
fn check_no_run_evidence(evidence: &KernelLegEvidence, backing: bool) -> Result<(), String> {
    if evidence.per_range_key == backing {
        return Err("overlay no-run: per-range key must match non-backing rendering".into());
    }
    if !evidence.slots_nonempty {
        return Err("overlay no-run: anchors install on any filesystem".into());
    }
    if backing && evidence.no_proof_classification != Some("no kernel proof (identity key)") {
        return Err("overlay no-run: backing rendering needs the no-proof classification".into());
    }
    if !backing && evidence.no_proof_classification.is_some() {
        return Err("overlay no-run: overlay rendering takes no classification".into());
    }
    let fallback = &evidence.fallback;
    if fallback.passes != 0
        || fallback.pids != 0
        || fallback.keys != 0
        || fallback.first_reason.is_some()
    {
        return Err(format!(
            "overlay no-run: nothing ran, yet fallback is {fallback:?}"
        ));
    }
    if evidence.userspace_reads != 0 {
        return Err("overlay no-run: nothing ran, yet userspace read".into());
    }
    Ok(())
}

/// Userspace attribution of one overlay mapper through the production
/// probe.
fn d4_overlay_attribute_pid(
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

/// Kernel attribution of one overlay mapper: a fresh generation with a
/// per-range key, validated slots, zero fallback and zero userspace
/// reads — so a vacuous kernel leg cannot pass. Returns the evidence
/// alongside for the outcome evaluator.
#[allow(clippy::too_many_arguments)]
fn d4_overlay_kernel_attribution_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> (SweepAttribution, KernelLegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    let mut index = overlay_index(key, object, pins);
    assert!(
        index.map_files_keys().contains(&key),
        "overlay key must require actual per-range proof"
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
            "overlay key holds validated slots"
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
    assert_eq!(fallback.passes, 0, "{fallback:?}");
    assert_eq!(fallback.pids, 0, "{fallback:?}");
    assert_eq!(fallback.keys, 0, "{fallback:?}");
    assert!(fallback.first_reason.is_none(), "{fallback:?}");
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(
        reads, 0,
        "the required kernel leg performed userspace range-proof reads"
    );
    let evidence = KernelLegEvidence {
        fallback,
        userspace_reads: reads,
        slots_nonempty: true,
        per_range_key: true,
        no_proof_classification: None,
    };
    (out, evidence)
}

/// Kernel leg on the N4 identity-key branch (backing rendering on ext4
/// layers): the key takes no per-range proof, so the leg classifies "no
/// kernel proof (identity key)" — AnchorNotInstalled with the edge, if
/// any, from the userspace fallback, which reads nothing since the
/// prove set is empty; anchors still install. Never kernel parity.
#[allow(clippy::too_many_arguments)]
fn d4_overlay_kernel_identity_key_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> (SweepAttribution, KernelLegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    let mut index = overlay_index(key, object, pins);
    assert!(
        !index.map_files_keys().contains(&key),
        "identity-key branch needs no per-range proof"
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
        "identity-key branch classifies AnchorNotInstalled: {fallback:?}"
    );
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(
        reads, 0,
        "the identity-key fallback reads nothing: the prove set is empty"
    );
    let evidence = KernelLegEvidence {
        fallback,
        userspace_reads: reads,
        slots_nonempty: true,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    (out, evidence)
}

/// Kernel side for a row no confirm can run on (keys differ, or a
/// data-only mapping): the setup asserts follow the rendering (a
/// per-range key exactly when not backing; slots install either way),
/// then the empty outcome with zero fallback and zero reads.
#[allow(clippy::too_many_arguments)]
fn d4_overlay_kernel_no_run_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
    backing: bool,
) -> (SweepAttribution, KernelLegEvidence) {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};
    let mut index = overlay_index(key, object, pins);
    assert_eq!(
        index.map_files_keys().contains(&key),
        !backing,
        "no-run setup follows the rendering"
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
    assert_eq!(out.probed, 0, "no candidate confirms: {out:?}");
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.pids, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.keys, 0, "no-run leg falls back nowhere");
    assert_eq!(fallback.first_reason, None, "no-run leg falls back nowhere");
    let reads = trace.lock().unwrap().reads.len();
    assert_eq!(reads, 0, "no-run leg reads nothing");
    let evidence = KernelLegEvidence {
        fallback,
        userspace_reads: reads,
        slots_nonempty: true,
        per_range_key: !backing,
        no_proof_classification: backing.then_some("no kernel proof (identity key)"),
    };
    (out, evidence)
}

/// Step 1: the truth recording names the maps identity apart from the
/// map_files identity — pre-6.8 vectors carry the backing inode on the
/// maps line and the overlay inode in map_files; 6.8+ vectors carry
/// the overlay inode on both. A backing-render vector sets the N4
/// branch input instead of the plan-default rendering.
#[test]
fn overlay_truth_recording_names_maps_and_map_files() {
    use p11scope_manifest::maps::Device;
    // Pre-6.8: maps line carries the backing inode (loop 7:2, ino 13);
    // map_files stat carries the overlay inode (s_dev 0:42, ino 7).
    let pre = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so".into(),
        map_files_dev: 42,
        map_files_ino: 7,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: false,
        xino_off_copy_up_stable: None,
    };
    assert_eq!(
        pre.maps_key(),
        ObjectKey {
            device: Device { major: 7, minor: 2 },
            inode: 13,
        }
    );
    assert_eq!(pre.map_files_identity(), FileIdentity { dev: 42, ino: 7 });
    assert!(
        !pre.map_files_backing,
        "plan-default rendering: map_files shows the overlay inode"
    );
    assert_eq!(
        pre.statfs_magic,
        p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC
    );
    assert_eq!(pre.held_fstat, (42, 7));
    assert!(pre.xino_effective);
    assert_eq!(pre.xino_auto, "N");
    // 6.8+: maps line carries the overlay inode too.
    let post = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 7 /merged/lib.so".into(),
        map_files_dev: 42,
        map_files_ino: 7,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: false,
        xino_off_copy_up_stable: None,
    };
    assert_eq!(
        post.maps_key(),
        ObjectKey {
            device: Device {
                major: 0,
                minor: 42
            },
            inode: 7,
        }
    );
    assert_eq!(post.maps_key().inode, post.map_files_ino);
    // N4 input shape: map_files stat IS the backing file (ext4).
    let backing = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so".into(),
        map_files_dev: libc::makedev(7, 2),
        map_files_ino: 13,
        statfs_magic: 0xef53,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: true,
        xino_off_copy_up_stable: None,
    };
    assert!(
        backing.map_files_backing,
        "the N4 branch input is recorded, not derived"
    );
    assert_ne!(
        backing.map_files_identity(),
        FileIdentity { dev: 42, ino: 7 },
        "backing rendering differs from the overlay fstat"
    );
    assert_eq!(backing.statfs_magic, 0xef53, "backing file on ext4");
    assert_eq!(backing.held_fstat, (42, 7));
    assert!(backing.xino_effective);
    assert_eq!(backing.xino_auto, "N");
}

/// Step 2: the xino-off collision rejects the join on both lanes. Lane
/// A keeps each layer's own real device in the maps key, so the equal
/// real-inode pair is no candidate (parity none); lane B shows the
/// overlay s_dev plus the real inode, so the pair IS a candidate with
/// a userspace named mismatch and a kernel other (negative).
#[test]
fn overlay_xino_off_collision_rejects_join() {
    let pid = 4242u32;
    let key = |line: &str| OverlayTruth {
        maps_line: line.into(),
        map_files_dev: 42,
        map_files_ino: 101,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 101),
        xino_effective: false,
        xino_auto: "N".into(),
        map_files_backing: false,
        xino_off_copy_up_stable: None,
    };
    // Lane A: (7:2, 12) vs (7:3, 12) differ — no candidate.
    let a_target = key("7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 12 /merged/f2.so");
    let a_anchor = key("7f2b4c000000-7f2b4c001000 r-xp 00000000 07:03 12 /merged/f1.so");
    let none = synthetic_none();
    let evidence = synthetic_quad_evidence();
    assert_overlay_outcome(
        pid,
        &a_target,
        &a_anchor,
        &none,
        &none,
        &evidence,
        OverlayExpect::Parity(false),
    )
    .expect("lane-A xino-off pair is no candidate");
    // And the evaluator rejects joining it as an edge.
    let edged = synthetic_edged(pid, a_target.maps_key());
    assert!(
        assert_overlay_outcome(
            pid,
            &a_target,
            &a_anchor,
            &edged,
            &edged,
            &evidence,
            OverlayExpect::Parity(true),
        )
        .is_err(),
        "the lane-A pair must not join as an edge"
    );
    // Lane B: (0:42, 12) on both sides — a candidate with a named
    // mismatch on userspace and a kernel other.
    let b_target = key("7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 12 /merged/f2.so");
    let b_anchor = key("7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 12 /merged/f1.so");
    let mismatch = synthetic_mismatch();
    assert_overlay_outcome(
        pid,
        &b_target,
        &b_anchor,
        &mismatch,
        &mismatch,
        &evidence,
        OverlayExpect::Negative,
    )
    .expect("lane-B xino-off pair is a named-mismatch negative");
    assert!(
        assert_overlay_outcome(
            pid,
            &b_target,
            &b_anchor,
            &edged,
            &edged,
            &evidence,
            OverlayExpect::Parity(true),
        )
        .is_err(),
        "the lane-B pair must not join as an edge"
    );
}

/// The N4 identity-key branch: backing rendering on ext4 layers makes
/// the key its own identity, so userspace decides alone and the kernel
/// leg classifies "no kernel proof (identity key)" — never parity.
#[test]
fn overlay_backing_render_is_identity_key_no_proof() {
    let pid = 4243u32;
    let backing = |line: &str| OverlayTruth {
        maps_line: line.into(),
        map_files_dev: libc::makedev(7, 2),
        map_files_ino: 13,
        statfs_magic: 0xef53,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: true,
        xino_off_copy_up_stable: None,
    };
    let target = backing("7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so");
    let anchor = backing("7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so");
    let edged = synthetic_edged(pid, target.maps_key());
    // The measured identity-key mechanism: anchors install for the
    // arena-mapped file on any filesystem (slots nonempty) and the
    // AnchorNotInstalled fallback reads nothing (the prove set is
    // empty) — never kernel parity.
    let evidence = KernelLegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(
                crate::discovery::kernel_identity::KernelFallbackReason::AnchorNotInstalled,
            ),
        },
        userspace_reads: 0,
        slots_nonempty: true,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    assert_overlay_outcome(
        pid,
        &target,
        &anchor,
        &edged,
        &edged,
        &evidence,
        OverlayExpect::IdentityKeyNoProof,
    )
    .expect("backing rendering classifies as identity-key no-proof");
    // Fail-closed: the branch refuses evidence that misrecords the
    // mechanism — empty slots, or reads the empty prove set never
    // performs.
    let misrecorded = |reads: usize, slots: bool| KernelLegEvidence {
        fallback: evidence.fallback.clone(),
        userspace_reads: reads,
        slots_nonempty: slots,
        per_range_key: evidence.per_range_key,
        no_proof_classification: evidence.no_proof_classification,
    };
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &misrecorded(0, false),
            OverlayExpect::IdentityKeyNoProof,
        )
        .is_err(),
        "the branch refuses empty slots: anchors install on any filesystem"
    );
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &misrecorded(1, true),
            OverlayExpect::IdentityKeyNoProof,
        )
        .is_err(),
        "the branch refuses phantom reads: the prove set is empty"
    );
    // A real kernel proof is not an identity-key no-proof.
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &synthetic_quad_evidence(),
            OverlayExpect::IdentityKeyNoProof,
        )
        .is_err(),
        "the branch must not accept kernel-proof evidence"
    );
    // And backing rendering never takes the parity-edge shape.
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &evidence,
            OverlayExpect::Parity(true),
        )
        .is_err(),
        "backing rendering must not take the parity-edge shape"
    );
    // But a backing no-run row (differing keys, nothing confirms)
    // takes parity none with the matching no-proof evidence shape.
    let upper = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:03 21 /merged/lib.so".into(),
        map_files_dev: libc::makedev(7, 3),
        map_files_ino: 21,
        statfs_magic: 0xef53,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: true,
        xino_off_copy_up_stable: None,
    };
    let no_run_backing = KernelLegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        slots_nonempty: true,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    assert_overlay_outcome(
        pid,
        &upper,
        &anchor,
        &synthetic_none(),
        &synthetic_none(),
        &no_run_backing,
        OverlayExpect::Parity(false),
    )
    .expect("a backing no-run row takes parity none");
    // With kernel-proof evidence instead, the same row is rejected.
    assert!(
        assert_overlay_outcome(
            pid,
            &upper,
            &anchor,
            &synthetic_none(),
            &synthetic_none(),
            &synthetic_quad_evidence(),
            OverlayExpect::Parity(false),
        )
        .is_err(),
        "parity none must match evidence to rendering"
    );
    // And slots stay installed when backing: empty slots fail closed.
    let no_run_empty_slots = KernelLegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        slots_nonempty: false,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    assert!(
        assert_overlay_outcome(
            pid,
            &upper,
            &anchor,
            &synthetic_none(),
            &synthetic_none(),
            &no_run_empty_slots,
            OverlayExpect::Parity(false),
        )
        .is_err(),
        "a backing no-run row refuses empty slots"
    );
}

/// The N4 tripwire: a row whose truths render backing on either side
/// takes the identity-key branch (never the parity shape), and once any
/// row has taken it the top-level gate fails the cell named — a ready
/// pair can never qualify silently. All six branch-taking rows trip the
/// flag on lane A (row_lower, row_upper, row_two_mounts, row_collision,
/// row_wrong_file, row_data_only); lane B refuses backing outright at
/// every row.
#[test]
fn overlay_n4_branch_tripwire_fails_the_cell() {
    let truth = |line: &str, backing: bool| OverlayTruth {
        maps_line: line.into(),
        map_files_dev: 42,
        map_files_ino: 7,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: backing,
        xino_off_copy_up_stable: None,
    };
    let line = "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so";
    let backing = truth(line, true);
    let overlay = truth(line, false);
    assert!(
        takes_identity_key_branch(&backing, &backing),
        "backing on both sides takes the branch"
    );
    assert!(
        takes_identity_key_branch(&backing, &overlay),
        "backing on the target side alone takes the branch"
    );
    assert!(
        takes_identity_key_branch(&overlay, &backing),
        "backing on the anchor side alone takes the branch"
    );
    assert!(
        !takes_identity_key_branch(&overlay, &overlay),
        "overlay rendering on both sides stays on the parity shape"
    );
    assert_eq!(
        n4_gate(false),
        Ok(()),
        "a dormant branch leaves the table verdict"
    );
    assert_eq!(
        n4_gate(true),
        Err("N4 active: lane cannot qualify as kernel parity".to_string()),
        "an active branch fails the cell named"
    );
}

/// The N4 tripwire per no-run row shape: when `row_lower` renders
/// overlay while a later no-run row renders backing on either side, the
/// evaluator alone would still accept the row's no-run shape, so the
/// row must take the identity-key branch and the top-level gate must
/// fail the cell named. One case per row shape that feeds backing into
/// `d4_overlay_kernel_no_run_for_pid`: upper, collision and wrong-file
/// (parity none) plus data-only (zero demand).
#[test]
fn overlay_n4_tripwire_trips_when_a_later_row_renders_backing() {
    let pid = 4244u32;
    let truth = |line: &str, backing: bool| OverlayTruth {
        maps_line: line.into(),
        map_files_dev: 42,
        map_files_ino: 7,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: backing,
        xino_off_copy_up_stable: None,
    };
    // row_lower renders overlay on both sides: it takes no branch.
    let line = "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so";
    let lower = truth(line, false);
    assert!(
        !takes_identity_key_branch(&lower, &lower),
        "row_lower on overlay rendering takes no branch"
    );
    // The no-run driver shape under backing: no per-range key, the
    // no-proof classification, installed slots, zero fallback and reads.
    let evidence = KernelLegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        slots_nonempty: true,
        per_range_key: false,
        no_proof_classification: Some("no kernel proof (identity key)"),
    };
    let none = synthetic_none();
    // (row, target line, anchor line, target backing, anchor backing,
    // expected shape).
    let cases = [
        (
            "upper",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:03 21 /merged/lib.so",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so",
            true,
            false,
            OverlayExpect::Parity(false),
        ),
        (
            "collision",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:03 12 /merged/f2.so",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 12 /merged/f1.so",
            false,
            true,
            OverlayExpect::Parity(false),
        ),
        (
            "wrong-file",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 44 /merged/other.so",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so",
            true,
            true,
            OverlayExpect::Parity(false),
        ),
        (
            "data-only",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so",
            "7f2b4c000000-7f2b4c001000 r-xp 00000000 07:02 13 /merged/lib.so",
            true,
            false,
            OverlayExpect::DataOnly,
        ),
    ];
    for (row, target_line, anchor_line, target_backing, anchor_backing, expected) in cases {
        let target = truth(target_line, target_backing);
        let anchor = truth(anchor_line, anchor_backing);
        assert_overlay_outcome(pid, &target, &anchor, &none, &none, &evidence, expected)
            .unwrap_or_else(|error| {
                panic!("{row}: the evaluator alone accepts backing rendering: {error}")
            });
        assert!(
            takes_identity_key_branch(&target, &anchor),
            "{row}: backing rendering takes the identity-key branch"
        );
        let mut n4_active = false;
        if takes_identity_key_branch(&target, &anchor) {
            n4_active = true;
        }
        assert_eq!(
            n4_gate(n4_active),
            Err("N4 active: lane cannot qualify as kernel parity".to_string()),
            "{row}: the tripped row fails the cell named"
        );
    }
}

/// Every preflight miss fails with its named reason; nothing skips.
/// Unprivileged this observes the root gate; privileged it observes
/// the pass (or a later named probe).
#[test]
fn overlay_preflight_fails_named_never_skips() {
    match overlay_preflight() {
        Ok(()) => {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "preflight passes only with privilege"
            );
        }
        Err(reason) => {
            assert!(
                reason.starts_with("OVERLAY-PREFLIGHT "),
                "named reason, never a skip: {reason}"
            );
        }
    }
}

/// The lane rule is pure over the release string: below 6.8 is A
/// (backing inode in maps), 6.8+ is B; pre-6 and garbage refuse.
#[test]
fn overlay_lane_follows_the_user_inode_boundary() {
    assert_eq!(OverlayLane::of_release("6.1.188"), Ok(OverlayLane::A));
    assert_eq!(OverlayLane::of_release("6.6.157"), Ok(OverlayLane::A));
    assert_eq!(
        OverlayLane::of_release("6.8.0-142-generic"),
        Ok(OverlayLane::B)
    );
    assert_eq!(OverlayLane::of_release("6.12.111"), Ok(OverlayLane::B));
    assert_eq!(OverlayLane::of_release("7.0.14"), Ok(OverlayLane::B));
    assert!(OverlayLane::of_release("5.15.0-142-generic").is_err());
    assert!(OverlayLane::of_release("not-a-release").is_err());
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
                path: "/merged/lib.so".into(),
                double_loaded: false,
            }],
            unexamined: 0,
        }],
        probed: 1,
        ..SweepAttribution::default()
    }
}

fn synthetic_mismatch() -> SweepAttribution {
    SweepAttribution {
        probed: 1,
        losses: BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)]),
        ..SweepAttribution::default()
    }
}

fn synthetic_none() -> SweepAttribution {
    SweepAttribution::default()
}

/// The E3 prototype: the strongest copy-up guard expressible from
/// already-crossed fields — exact identity, the current join rule.
fn prototype_copy_up_guard(expected: FileIdentity, mapped: FileIdentity) -> bool {
    expected == mapped
}

/// E3 prototype verdict against the Task-5 vectors: the proof boundary
/// carries (dev, ino) per side; the pin's (size, ctime) never crosses
/// into FileIdentity or RangeProof; nothing else is captured. The
/// pre-copy-up lower vector (must allow) and the post-copy-up upper
/// vector (must refuse) render identically through the real accessors,
/// so refusing breaks the lower edge and allowing keeps the re-edge:
/// no pure guard separates them. Any staleness check needs new fields
/// on the proof boundary plus a ConfirmIo change — outside E3's land
/// criteria. RED remains, disclosure final.
#[test]
fn overlay_copy_up_prototype_guard_cannot_separate() {
    let vector = |line: &str| OverlayTruth {
        maps_line: line.into(),
        map_files_dev: 42,
        map_files_ino: 7,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 7),
        xino_effective: true,
        xino_auto: "N".into(),
        map_files_backing: false,
        xino_off_copy_up_stable: None,
    };
    // Pre-copy-up lower (must allow) and post-copy-up upper (must
    // refuse): the stable overlay inode renders identically on both.
    let lower = vector("7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 7 /merged/lib.so");
    let upper = vector("7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 7 /merged/lib.so");
    let lower_inputs = (lower.maps_key(), lower.map_files_identity());
    let upper_inputs = (upper.maps_key(), upper.map_files_identity());
    assert_eq!(
        lower_inputs, upper_inputs,
        "stability: the guard sees identical inputs"
    );
    assert!(
        prototype_copy_up_guard(lower.map_files_identity(), lower.map_files_identity()),
        "the lower edge must stay allowed"
    );
    assert!(
        prototype_copy_up_guard(upper.map_files_identity(), upper.map_files_identity()),
        "and so the re-edge stays allowed too: separation impossible"
    );
}

fn synthetic_quad_evidence() -> KernelLegEvidence {
    KernelLegEvidence {
        fallback: crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 0,
            pids: 0,
            keys: 0,
            first_reason: None,
        },
        userspace_reads: 0,
        slots_nonempty: true,
        per_range_key: true,
        no_proof_classification: None,
    }
}

/// Overlay xino backend parity across the corrected lane table: three
/// modes (xino on, xino off, same-fs) over real loop-ext4 layers, every
/// kernel leg through the attested driver (a vacuous kernel leg cannot
/// pass), every row through the outcome evaluator. Preflight misses,
/// lane surprises and rendering contradictions fail named; nothing
/// skips. Guest lanes stage this binary plus the work dir on the same
/// vng --rwdir path and run with TMPDIR on the rwdir disk (vng hides
/// /var/tmp), so loop images never sit on tmpfs or 9p.
#[test]
#[ignore = "root: loop overlay mounts (mkfs.ext4, mount, umount) plus eligible BTF/task_vma identity"]
fn privileged_d4_overlay_xino_backend_parity() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session =
        crate::discovery::kernel_identity::IdentitySession::probe_and_load(&btf, probe_dir.path())
            .expect("strict-loaded kernel session; no refused/fallback positive");
    let mut rows = OverlayRows {
        session: &mut session,
        generation: 0,
        lane,
        mode: XinoMode::On,
        n4_active: false,
    };
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        rows.mode = mode;
        let work = tempfile::tempdir().unwrap();
        rows.run_all(work.path())
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    // N4: backing rendering on any row means overlay keys are identity
    // keys — the lane never qualifies as kernel parity, even if every
    // row passed. Fail named instead of printing the table verdict.
    if let Err(message) = n4_gate(rows.n4_active) {
        eprintln!("D4_OVERLAY lane={lane:?} modes=on,off,same-fs {message}");
        panic!("{message}");
    }
    eprintln!("D4_OVERLAY lane={lane:?} modes=on,off,same-fs verdict=table");
}

/// Task 6 copy-up reproducer (lanes B only): the upper mapper after
/// copy-up must NOT re-edge to the stale lower anchor on the userspace
/// leg. RED while D-C7-3 stands (the stable overlay inode joins them);
/// the lower control proves the test sees real edges. Lane A fails
/// outright (keys differ there, so absence would pass vacuously).
#[test]
#[ignore = "root: loop overlay mounts plus eligible BTF/task_vma identity (lanes B only)"]
fn overlay_copy_up_userspace_edge_absent() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    if lane != OverlayLane::B {
        panic!(
            "OVERLAY-COPY-UP lane: lanes B only (lane-A keys differ, absence would pass vacuously)"
        );
    }
    let work = tempfile::tempdir().unwrap();
    let fixture = OverlayFixture::mount(work.path(), XinoMode::On).expect("overlay mount");
    std::fs::write(fixture.lower_path("lib.so"), vec![0xF6u8; 8192]).unwrap();
    let xino = fixture.xino_verdict("lib.so").expect("xino on effective");
    let merged = fixture.merged_path("lib.so");
    // Lower control first: pre-copy-up, the userspace leg edges.
    let control = SwapChild::spawn(&merged);
    let c_snap = control.maps();
    let c_range = (control.address, control.address + 4096);
    let c_line = find_line(&c_snap, c_range, *b"r-xp").expect("control line");
    let key = ObjectKey::of(&c_line);
    let (pins, object) = overlay_pin(&merged, key).expect("pin");
    let index = overlay_index(key, object, &pins);
    let userspace = d4_overlay_attribute_pid(control.pid as u32, c_snap, &index);
    let members: Vec<u32> = userspace.members.iter().map(|member| member.pid).collect();
    assert_eq!(
        members,
        [control.pid as u32],
        "lower control edges: {userspace:?}"
    );
    // Copy up, then map the upper file through the same merged path.
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )
    .expect("copy-up");
    let upper = SwapChild::spawn(&merged);
    let u_snap = upper.maps();
    let u_range = (upper.address, upper.address + 4096);
    let u_line = find_line(&u_snap, u_range, *b"r-xp").expect("upper line");
    // Same key (stable overlay inode): the join under test.
    assert_eq!(ObjectKey::of(&u_line), key, "post-copy-up key stability");
    let held = std::fs::File::open(&merged).unwrap();
    let truth = record_truth(
        upper.pid as u32,
        u_range,
        &held,
        &fixture.upper_path("lib.so"),
        xino,
        None,
    )
    .expect("truth");
    eprintln!(
        "D4_OVERLAY_COPY_UP lane={lane:?} target-{}",
        truth_verdict(&truth)
    );
    let userspace = d4_overlay_attribute_pid(upper.pid as u32, u_snap, &index);
    let members: Vec<u32> = userspace.members.iter().map(|member| member.pid).collect();
    assert!(
        members.is_empty(),
        "D-C7-3 stands: upper mapper re-edged to the stale anchor: {userspace:?}"
    );
}

/// Whether this row's recorded truths take the N4 identity-key
/// branch: map_files renders the backing file on either side (lane A
/// only — lane B refuses backing outright at every row).
fn takes_identity_key_branch(target: &OverlayTruth, anchor: &OverlayTruth) -> bool {
    target.map_files_backing || anchor.map_files_backing
}

/// The N4 top-level gate: once any row has taken the identity-key
/// branch, overlay keys on ext4 layers are identity keys and the lane
/// can never qualify as kernel parity — the cell fails named instead
/// of printing its table verdict.
fn n4_gate(n4_active: bool) -> Result<(), String> {
    if n4_active {
        Err("N4 active: lane cannot qualify as kernel parity".into())
    } else {
        Ok(())
    }
}

/// One ignored run's shared kernel session, generation counter, lane,
/// mode and N4 trip flag. Every row mounts a fresh fixture (row
/// isolation: copy-ups and upper files never leak across rows).
struct OverlayRows<'s> {
    session: &'s mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
    lane: OverlayLane,
    mode: XinoMode,
    n4_active: bool,
}

impl OverlayRows<'_> {
    fn run_all(&mut self, work: &std::path::Path) -> Result<(), String> {
        self.row_lower(work)?;
        self.row_upper(work)?;
        self.row_two_mounts(work)?;
        if self.mode == XinoMode::Off {
            self.row_collision(work)?;
        }
        self.row_wrong_file(work)?;
        self.row_data_only(work)?;
        Ok(())
    }

    /// Lower mapper through the merge: parity edge on both lanes.
    fn row_lower(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=lower", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        std::fs::write(fixture.lower_path("lib.so"), vec![0xA1u8; 8192])
            .map_err(|error| format!("overlay lower write: {error}"))?;
        let xino = fixture.xino_verdict("lib.so")?;
        let merged = fixture.merged_path("lib.so");
        let anchor = SwapChild::spawn(&merged);
        let target = SwapChild::spawn(&merged);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, target_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = overlay_pin(&merged, key)?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(&merged)
            .map_err(|error| format!("overlay lower held open: {error}"))?;
        let backing = fixture.lower_path("lib.so");
        let _ = t_line;
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            target.pid as u32,
            target_range(&target),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let pid = target.pid as u32;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let branch = takes_identity_key_branch(&t_truth, &a_truth);
        if branch {
            if self.lane != OverlayLane::A {
                return Err("unexpected backing rendering on lane B".into());
            }
            self.generation += 1;
            let (kernel, evidence) = d4_overlay_kernel_identity_key_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                &mut *self.session,
                self.generation,
            );
            assert_overlay_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                OverlayExpect::IdentityKeyNoProof,
            )?;
            self.n4_active = true;
        } else {
            self.generation += 1;
            let (kernel, evidence) = d4_overlay_kernel_attribution_for_pid(
                pid,
                t_snap,
                &pins,
                object,
                key,
                &mut *self.session,
                self.generation,
            );
            assert_overlay_outcome(
                pid,
                &t_truth,
                &a_truth,
                &userspace,
                &kernel,
                &evidence,
                OverlayExpect::Parity(true),
            )?;
        }
        let verdict = if branch {
            "N4-identity-key-no-proof"
        } else {
            "parity-edge"
        };
        eprintln!(
            "D4_OVERLAY mode={:?} row=lower lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            verdict,
            truth_verdict(&t_truth)
        );
        Ok(())
    }

    /// Upper mapper after copy-up, anchor opened before: parity none on
    /// lane A (keys differ), D-C7-3 on lane B (stable overlay inode, a
    /// userspace edge the kernel correctly refuses).
    fn row_upper(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=upper", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        std::fs::write(fixture.lower_path("lib.so"), vec![0xB2u8; 8192])
            .map_err(|error| format!("overlay upper write: {error}"))?;
        let xino = fixture.xino_verdict("lib.so")?;
        let merged = fixture.merged_path("lib.so");
        let anchor = SwapChild::spawn(&merged);
        let a_snap = anchor.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        // The anchor opens before the copy-up: its mapping and the held
        // fd both name the lower file for the rest of the row.
        let (pins, object) = overlay_pin(&merged, key)?;
        trigger_copy_up(
            &merged,
            &fixture.upper_path("lib.so"),
            &fixture.lower_path("lib.so"),
        )?;
        let target = SwapChild::spawn(&merged);
        let t_snap = target.maps();
        let t_line = find_line(&t_snap, target_range(&target), *b"r-xp")?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(&merged)
            .map_err(|error| format!("overlay upper held open: {error}"))?;
        let pid = target.pid as u32;
        // xino-off × post-copy-up reads its userspace expectation from
        // recorded truth: non-persistent st_ino makes a fixed shape
        // dishonest, so consecutive map_files stats decide.
        let stable = if self.lane == OverlayLane::B && self.mode == XinoMode::Off {
            Some(map_files_stable(pid, target_range(&target))?)
        } else {
            None
        };
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &fixture.lower_path("lib.so"),
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            pid,
            target_range(&target),
            &held,
            &fixture.upper_path("lib.so"),
            xino.clone(),
            stable,
        )?;
        let _ = t_line;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let branch = takes_identity_key_branch(&t_truth, &a_truth);
        match self.lane {
            OverlayLane::A => {
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_no_run_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                    branch,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::Parity(false),
                )?;
                if branch {
                    self.n4_active = true;
                }
            }
            OverlayLane::B => {
                if branch {
                    return Err("unexpected backing rendering on lane B".into());
                }
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_attribution_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::DivergenceC73,
                )?;
            }
        }
        eprintln!(
            "D4_OVERLAY mode={:?} row=upper lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            match self.lane {
                OverlayLane::A if branch => "N4-identity-key-no-proof",
                OverlayLane::A => "parity-none",
                OverlayLane::B => "D-C7-3",
            },
            truth_verdict(&t_truth)
        );
        Ok(())
    }

    /// The same lower through two mounts (shared lowerdir, fresh upper
    /// and work): D-C7-2 on lane A (equal backing keys: the kernel
    /// correctly reports the same underlying file while the userspace
    /// side reports a named mismatch) and parity none on lane B
    /// (distinct overlay devices).
    fn row_two_mounts(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=two-mounts", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        std::fs::write(fixture.lower_path("lib.so"), vec![0xC3u8; 8192])
            .map_err(|error| format!("overlay two-mounts write: {error}"))?;
        let xino = fixture.xino_verdict("lib.so")?;
        let second = fixture.mount_second(work, "2")?;
        assert_shared_lower(&fixture.merged.mountpoint, &second.mountpoint)?;
        let anchor = SwapChild::spawn(&fixture.merged_path("lib.so"));
        let target = SwapChild::spawn(&second.mountpoint.join("lib.so"));
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, target_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = overlay_pin(&fixture.merged_path("lib.so"), key)?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(fixture.merged_path("lib.so"))
            .map_err(|error| format!("overlay two-mounts held open: {error}"))?;
        let backing = fixture.lower_path("lib.so");
        let _ = t_line;
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            target.pid as u32,
            target_range(&target),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let pid = target.pid as u32;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let rendered_backing = takes_identity_key_branch(&t_truth, &a_truth);
        match self.lane {
            OverlayLane::A if rendered_backing => {
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_identity_key_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::IdentityKeyNoProof,
                )?;
                self.n4_active = true;
            }
            OverlayLane::A => {
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_attribution_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::DivergenceC72(false, true),
                )?;
            }
            OverlayLane::B => {
                if rendered_backing {
                    return Err("unexpected backing rendering on lane B".into());
                }
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_no_run_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                    false,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::Parity(false),
                )?;
            }
        }
        let verdict = if rendered_backing && self.lane == OverlayLane::A {
            "N4-identity-key-no-proof"
        } else {
            match self.lane {
                OverlayLane::A => "D-C7-2",
                OverlayLane::B => "parity-none",
            }
        };
        eprintln!(
            "D4_OVERLAY mode={:?} row=two-mounts lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            verdict,
            truth_verdict(&t_truth)
        );
        Ok(())
    }

    /// Two different files with equal real inode numbers on the two
    /// layers (xino-off mode only): parity none on lane A (each layer
    /// keeps its own real device in the maps key) and a named-mismatch
    /// negative on lane B (overlay s_dev plus the real inode collides).
    fn row_collision(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=collision", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        let (lower_name, upper_name) = equal_ino_pair(&fixture)?;
        let xino = fixture.xino_verdict(&lower_name)?;
        let lower_bytes = std::fs::read(fixture.lower_path(&lower_name))
            .map_err(|error| format!("overlay collision read lower: {error}"))?;
        let upper_bytes = std::fs::read(fixture.upper_path(&upper_name))
            .map_err(|error| format!("overlay collision read upper: {error}"))?;
        assert_ne!(
            lower_bytes, upper_bytes,
            "the colliding pair must be different files"
        );
        let anchor = SwapChild::spawn(&fixture.merged_path(&lower_name));
        let target = SwapChild::spawn(&fixture.merged_path(&upper_name));
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, target_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = overlay_pin(&fixture.merged_path(&lower_name), key)?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(fixture.merged_path(&lower_name))
            .map_err(|error| format!("overlay collision held open: {error}"))?;
        let _ = t_line;
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &fixture.lower_path(&lower_name),
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            target.pid as u32,
            target_range(&target),
            &held,
            &fixture.upper_path(&upper_name),
            xino.clone(),
            None,
        )?;
        let pid = target.pid as u32;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let branch = takes_identity_key_branch(&t_truth, &a_truth);
        match self.lane {
            OverlayLane::A => {
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_no_run_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                    branch,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::Parity(false),
                )?;
                if branch {
                    self.n4_active = true;
                }
            }
            OverlayLane::B => {
                if branch {
                    return Err("unexpected backing rendering on lane B".into());
                }
                self.generation += 1;
                let (kernel, evidence) = d4_overlay_kernel_attribution_for_pid(
                    pid,
                    t_snap,
                    &pins,
                    object,
                    key,
                    &mut *self.session,
                    self.generation,
                );
                assert_overlay_outcome(
                    pid,
                    &t_truth,
                    &a_truth,
                    &userspace,
                    &kernel,
                    &evidence,
                    OverlayExpect::Negative,
                )?;
            }
        }
        eprintln!(
            "D4_OVERLAY mode={:?} row=collision lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            match self.lane {
                OverlayLane::A if branch => "N4-identity-key-no-proof",
                OverlayLane::A => "parity-none",
                OverlayLane::B => "named-mismatch-negative",
            },
            truth_verdict(&t_truth)
        );
        Ok(())
    }

    /// Wrong-file negative: the mapper names a different file, so no
    /// candidate exists on either lane or backend.
    fn row_wrong_file(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=wrong-file", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        std::fs::write(fixture.lower_path("lib.so"), vec![0xE5u8; 8192])
            .map_err(|error| format!("overlay wrong-file write held: {error}"))?;
        std::fs::write(fixture.lower_path("other.so"), vec![0xE6u8; 8192])
            .map_err(|error| format!("overlay wrong-file write other: {error}"))?;
        let xino = fixture.xino_verdict("lib.so")?;
        let anchor = SwapChild::spawn(&fixture.merged_path("lib.so"));
        let target = SwapChild::spawn(&fixture.merged_path("other.so"));
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, target_range(&target), *b"r-xp")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = overlay_pin(&fixture.merged_path("lib.so"), key)?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(fixture.merged_path("lib.so"))
            .map_err(|error| format!("overlay wrong-file held open: {error}"))?;
        let _ = t_line;
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &fixture.lower_path("lib.so"),
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            target.pid as u32,
            target_range(&target),
            &held,
            &fixture.lower_path("other.so"),
            xino.clone(),
            None,
        )?;
        let pid = target.pid as u32;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let branch = takes_identity_key_branch(&t_truth, &a_truth);
        if branch && self.lane != OverlayLane::A {
            return Err("unexpected backing rendering on lane B".into());
        }
        self.generation += 1;
        let (kernel, evidence) = d4_overlay_kernel_no_run_for_pid(
            pid,
            t_snap,
            &pins,
            object,
            key,
            &mut *self.session,
            self.generation,
            branch,
        );
        assert_overlay_outcome(
            pid,
            &t_truth,
            &a_truth,
            &userspace,
            &kernel,
            &evidence,
            OverlayExpect::Parity(false),
        )?;
        if branch {
            self.n4_active = true;
        }
        let verdict = if branch {
            "N4-identity-key-no-proof"
        } else {
            "parity-none"
        };
        eprintln!(
            "D4_OVERLAY mode={:?} row=wrong-file lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            verdict,
            truth_verdict(&t_truth)
        );
        Ok(())
    }

    /// Data-only negative: the mapper holds the file without execute
    /// permission, so proof demand stays zero on both backends.
    fn row_data_only(&mut self, work: &std::path::Path) -> Result<(), String> {
        eprintln!("D4_OVERLAY start mode={:?} row=data-only", self.mode);
        let fixture = OverlayFixture::mount(work, self.mode)?;
        std::fs::write(fixture.lower_path("lib.so"), vec![0xD0u8; 8192])
            .map_err(|error| format!("overlay data-only write: {error}"))?;
        let xino = fixture.xino_verdict("lib.so")?;
        let merged = fixture.merged_path("lib.so");
        let anchor = SwapChild::spawn(&merged);
        let target = SwapChild::spawn_with(&[(&merged, false)]);
        let a_snap = anchor.maps();
        let t_snap = target.maps();
        let a_line = find_line(&a_snap, anchor_range(&anchor), *b"r-xp")?;
        let t_line = find_line(&t_snap, target_range(&target), *b"r--p")?;
        let key = ObjectKey::of(&a_line);
        let (pins, object) = overlay_pin(&merged, key)?;
        let index = overlay_index(key, object, &pins);
        let held = std::fs::File::open(&merged)
            .map_err(|error| format!("overlay data-only open: {error}"))?;
        let _ = t_line;
        let backing = fixture.lower_path("lib.so");
        let a_truth = record_truth(
            anchor.pid as u32,
            anchor_range(&anchor),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let t_truth = record_truth(
            target.pid as u32,
            target_range(&target),
            &held,
            &backing,
            xino.clone(),
            None,
        )?;
        let pid = target.pid as u32;
        let userspace = d4_overlay_attribute_pid(pid, t_snap.clone(), &index);
        let branch = takes_identity_key_branch(&t_truth, &a_truth);
        if branch && self.lane != OverlayLane::A {
            return Err("unexpected backing rendering on lane B".into());
        }
        self.generation += 1;
        let (kernel, evidence) = d4_overlay_kernel_no_run_for_pid(
            pid,
            t_snap,
            &pins,
            object,
            key,
            &mut *self.session,
            self.generation,
            branch,
        );
        assert_overlay_outcome(
            pid,
            &t_truth,
            &a_truth,
            &userspace,
            &kernel,
            &evidence,
            OverlayExpect::DataOnly,
        )?;
        if branch {
            self.n4_active = true;
        }
        let verdict = if branch {
            "N4-identity-key-no-proof"
        } else {
            "zero-demand"
        };
        eprintln!(
            "D4_OVERLAY mode={:?} row=data-only lane={:?} verdict={} target-{}",
            self.mode,
            self.lane,
            verdict,
            truth_verdict(&t_truth)
        );
        Ok(())
    }
}

fn anchor_range(child: &SwapChild) -> (u64, u64) {
    (child.address, child.address + 4096)
}

fn target_range(child: &SwapChild) -> (u64, u64) {
    (child.address, child.address + 4096)
}
