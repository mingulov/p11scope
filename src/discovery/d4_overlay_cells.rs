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
use crate::discovery::scan::lower_candidates_from_mountinfo;
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
        Self::mount_with_extra(root, xino, "")
    }

    /// [`mount`](Self::mount) with one extra mount option appended
    /// verbatim (for example `,metacopy=on`): the metacopy row mounts
    /// the same layers with metadata-only copy-up.
    fn mount_with_extra(
        root: &std::path::Path,
        xino: XinoMode,
        extra: &str,
    ) -> Result<Self, String> {
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
            "lowerdir={},upperdir={},workdir={}{}{}",
            lowerdir.display(),
            upperdir.display(),
            workdir.display(),
            fixture.xino_opt(),
            extra
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
    // Prove the mount really is overlayfs: a misconfigured mountpoint
    // (a stale mount, the wrong fstype) fails here instead of running
    // the cell against the wrong filesystem.
    let magic = statfs_magic(&mountpoint.to_string_lossy())?;
    if magic != p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC {
        return Err(format!(
            "overlay mount {} is not overlayfs (statfs magic {magic:#x})",
            mountpoint.display()
        ));
    }
    Ok(())
}

/// Ground truth recorded per side and leg: the rendered maps line, the
/// map_files stat and statfs magic, the held fd's fstat, the stat-based
/// xino verdict, and whether map_files shows the backing file (the N4
/// identity-key branch input).
#[derive(Clone)]
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
    /// The sweep-side no-fallback shape: the kernel leg edges on a real
    /// kernel proof while the userspace leg yields the exact named loss
    /// (no userspace-identity edge for overlay keys).
    DivergenceK2,
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
    fn k2_loss(out: &SweepAttribution, side: &str) -> Result<(), String> {
        if !out.members.is_empty()
            || out.losses != BTreeMap::from([(AttributionLoss::OverlayKernelUnavailable, 1)])
            || out.probed != 1
        {
            return Err(format!(
                "overlay {side}: expected no-fallback loss, members {:?} losses {:?} probed {}",
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
            // post-copy-up (non-persistent st_ino); otherwise it refuses
            // with the named no-fallback loss while the kernel says other.
            let want_edge = target.xino_off_copy_up_stable.unwrap_or(true);
            if want_edge {
                k2_loss(userspace, "userspace")?;
            } else {
                mismatch(userspace, "userspace")?;
            }
            mismatch(kernel, "kernel")?;
            kernel_proof()?;
            Ok(())
        }
        OverlayExpect::DivergenceK2 => {
            if backing {
                return Err(
                    "overlay K2 needs overlay rendering; backing rendering is the identity-key branch"
                        .into(),
                );
            }
            if !keys_equal {
                return Err("overlay K2 needs equal maps keys".into());
            }
            k2_loss(userspace, "userspace")?;
            edge(pid, row_key, kernel, "kernel")?;
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

/// The K2 evaluator shape: a same-file overlay pair takes a kernel edge
/// with the userspace named loss — and the evaluator rejects a userspace
/// edge, a kernel mismatch, differing keys, or backing rendering for it.
#[test]
fn overlay_k2_divergence_needs_kernel_edge_and_userspace_loss() {
    let pid = 4242u32;
    let target = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 12 /merged/lib.so".into(),
        map_files_dev: 42,
        map_files_ino: 12,
        statfs_magic: p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC,
        held_fstat: (42, 12),
        xino_effective: true,
        xino_auto: "Y".into(),
        map_files_backing: false,
        xino_off_copy_up_stable: None,
    };
    let anchor = target.clone();
    let evidence = synthetic_quad_evidence();
    assert_overlay_outcome(
        pid,
        &target,
        &anchor,
        &synthetic_k2_loss(),
        &synthetic_edged(pid, target.maps_key()),
        &evidence,
        OverlayExpect::DivergenceK2,
    )
    .expect("same-file overlay pair takes kernel edge with userspace loss");
    let edged = synthetic_edged(pid, target.maps_key());
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &edged,
            &edged,
            &evidence,
            OverlayExpect::DivergenceK2,
        )
        .is_err(),
        "K2 must not accept a userspace edge"
    );
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &anchor,
            &synthetic_k2_loss(),
            &synthetic_mismatch(),
            &evidence,
            OverlayExpect::DivergenceK2,
        )
        .is_err(),
        "K2 must not accept a kernel mismatch"
    );
    let other = OverlayTruth {
        maps_line: "7f2b4c000000-7f2b4c001000 r-xp 00000000 00:2a 13 /merged/other.so".into(),
        ..target.clone()
    };
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &other,
            &synthetic_k2_loss(),
            &edged,
            &evidence,
            OverlayExpect::DivergenceK2,
        )
        .is_err(),
        "K2 needs equal maps keys"
    );
    let backing = OverlayTruth {
        map_files_backing: true,
        ..target.clone()
    };
    assert!(
        assert_overlay_outcome(
            pid,
            &target,
            &backing,
            &synthetic_k2_loss(),
            &edged,
            &evidence,
            OverlayExpect::DivergenceK2,
        )
        .is_err(),
        "backing rendering is the identity-key branch, not K2"
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

fn synthetic_k2_loss() -> SweepAttribution {
    SweepAttribution {
        probed: 1,
        losses: BTreeMap::from([(AttributionLoss::OverlayKernelUnavailable, 1)]),
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
/// leg. The sweep-side no-fallback rule refuses with the named loss where
/// D-C7-3's stable overlay inode used to join; the lower control proves
/// the fixture still edges on the kernel leg. Lane A fails outright (keys
/// differ there, so absence would pass vacuously).
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
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session =
        crate::discovery::kernel_identity::IdentitySession::probe_and_load(&btf, probe_dir.path())
            .expect("strict-loaded kernel session; no refused/fallback positive");
    let work = tempfile::tempdir().unwrap();
    let fixture = OverlayFixture::mount(work.path(), XinoMode::On).expect("overlay mount");
    std::fs::write(fixture.lower_path("lib.so"), vec![0xF6u8; 8192]).unwrap();
    let xino = fixture.xino_verdict("lib.so").expect("xino on effective");
    let merged = fixture.merged_path("lib.so");
    // Lower control first: pre-copy-up, the userspace leg refuses with the
    // named no-fallback loss while the kernel leg edges on a real proof.
    let control = SwapChild::spawn(&merged);
    let c_snap = control.maps();
    let c_range = (control.address, control.address + 4096);
    let c_line = find_line(&c_snap, c_range, *b"r-xp").expect("control line");
    let key = ObjectKey::of(&c_line);
    let (pins, object) = overlay_pin(&merged, key).expect("pin");
    let index = overlay_index(key, object, &pins);
    let userspace = d4_overlay_attribute_pid(control.pid as u32, c_snap.clone(), &index);
    assert!(
        userspace.members.is_empty(),
        "lower control joined by userspace: {userspace:?}"
    );
    assert_eq!(
        userspace.losses,
        BTreeMap::from([(AttributionLoss::OverlayKernelUnavailable, 1)]),
        "lower control refuses named: {userspace:?}"
    );
    let (kernel, _) = d4_overlay_kernel_attribution_for_pid(
        control.pid as u32,
        c_snap,
        &pins,
        object,
        key,
        &mut session,
        1,
    );
    let members: Vec<u32> = kernel.members.iter().map(|member| member.pid).collect();
    assert_eq!(
        members,
        [control.pid as u32],
        "lower control edges on the kernel leg: {kernel:?}"
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
        "upper mapper re-edged to the stale anchor: {userspace:?}"
    );
    assert_eq!(
        userspace.losses,
        BTreeMap::from([(AttributionLoss::OverlayKernelUnavailable, 1)]),
        "upper mapper refuses named: {userspace:?}"
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

    /// Lower mapper through the merge: the kernel leg edges on a real
    /// proof while the userspace leg yields the named no-fallback loss
    /// (no userspace-identity edge for overlay keys), on both lanes.
    /// (The N4 backing branch on lane A keeps its own expectation.)
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
                OverlayExpect::DivergenceK2,
            )?;
        }
        let verdict = if branch {
            "N4-identity-key-no-proof"
        } else {
            "k2-divergence"
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
    /// userspace no-fallback loss where the kernel correctly reports
    /// another file).
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

/// Production K1 twins: one caller through the PRODUCTION deep-scan
/// guard (`mapped_file_guard` + `ProcScanIo` + the production
/// original-file witness) over live loop-overlay inputs, in the B16
/// direction. The stale twin refuses with the finite gap; the fresh
/// twin joins exactly; the budget twin proves exhaustion refuses
/// without running a query. Refusing every overlay caller would fail
/// acceptance, so the fresh join is asserted strictly wherever the
/// kernel proof can run.
///
/// Lane A (pre-6.8) renders the backing inode in maps. The stale row
/// asserts its exact production shape per rendering: a witness refusal
/// when the fixture takes the witness-requiring shape, the legacy
/// `(dev, ino)` refusal when the stale mapping already separates —
/// both with exact spend — and the truth record pins which rendering
/// the lane took. The fresh row joins through the witness on both
/// lanes. Nothing skips by lane. Where the kernel proof cannot run at
/// all (no BTF/task_vma on the tier), the fresh row asserts the exact
/// unavailable gap instead of the join — still a refusal, never
/// silence — while the capable lane-B hosts prove the join strictly.
fn k1_witness_capable() -> bool {
    crate::attach::identity_iter::ensure_kernel_identity_btf().is_ok()
}

/// Mirror the production deep-scan call site over live inputs: open the
/// held file, resolve its held identity through the budget cache plus
/// the IO (exactly like `scan_view_examined_mode`), group the target's
/// live maps like production, and run the real guard plus the provider
/// prove step, exactly as the production group loop does for a provider
/// file. Returns the join outcome and the global witness-query delta
/// across the call.
fn k1_production_guard(
    pid: u32,
    merged: &std::path::Path,
    key: ObjectKey,
    maps: &[MapEntry],
    budget: &mut crate::discovery::scan::CaptureWorkBudget,
    io: &mut crate::discovery::scan::ProcScanIo,
) -> Result<(Result<(), String>, u64), String> {
    use crate::discovery::overlay_witness::witness_stats_for_test;
    use crate::discovery::scan::{
        GuardOutcome, ScanIo, candidate_groups, mapped_file_guard, witness_join,
    };
    use crate::process::{ProcessView, ProcessViewId};
    let view = ProcessView::open(ProcessViewId(pid), pid)
        .map_err(|error| format!("k1 production view {pid}: {error}"))?;
    let file = std::fs::File::open(merged)
        .map_err(|error| format!("k1 production held open {}: {error}", merged.display()))?;
    let held = budget
        .retained_mapped_identity(&file)
        .or_else(|| io.held_identity(&file));
    let groups = candidate_groups(maps);
    let group = groups
        .get(&key)
        .ok_or_else(|| format!("k1 production: key {key:?} has no candidate group"))?;
    let (before, _) = witness_stats_for_test();
    let guarded = mapped_file_guard(io, &view, held, key, group, budget);
    let result = match guarded {
        Err(reason) => Err(reason),
        Ok(GuardOutcome::Proven) => Ok(()),
        Ok(GuardOutcome::UnprovenOverlay { range }) => match held {
            Some(held) => match witness_join(io, &view, &file, &held, key, range, budget) {
                Some(reason) => Err(reason),
                None => Ok(()),
            },
            None => Err("k1 production: unproven join without a held file".into()),
        },
    };
    let (after, _) = witness_stats_for_test();
    Ok((result, after.saturating_sub(before)))
}

/// Retry the production guard across transient witness-infrastructure
/// loss. A vCPU deschedule longer than 10ms trips the identity
/// file-descriptor census and the query fail-closes unavailable; that
/// exercises the fail-closed path, not the join/refuse logic the row
/// asserts. Each attempt carries the fresh scan budget a later
/// production pass would, spends exactly one query, and re-reads the
/// child's maps; only the unavailable gap retries, at most three
/// attempts. Systematic unavailability still fails: the third strike
/// returns the outcome. Returns the outcome, the total queries spent,
/// and the attempts used.
fn k1_production_guard_retry(
    label: &str,
    pid: u32,
    merged: &std::path::Path,
    key: ObjectKey,
    maps: &dyn Fn() -> Vec<MapEntry>,
) -> Result<(Result<(), String>, u64, u32), String> {
    use crate::discovery::overlay_witness::witness_unavailable_refusal;
    let mut total = 0u64;
    for attempt in 1..=3u32 {
        let live = maps();
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let mut io = crate::discovery::scan::ProcScanIo::new();
        let (result, queries) = k1_production_guard(pid, merged, key, &live, &mut budget, &mut io)?;
        total += queries;
        if io.witness_used() != 1 || queries != 1 {
            return Err(format!(
                "{label}: attempt {attempt} spent {} queries and ran {queries}, not one",
                io.witness_used()
            ));
        }
        let retry =
            matches!(&result, Err(reason) if witness_unavailable_refusal(reason)) && attempt < 3;
        if retry {
            eprintln!("K1_DEEP_SCAN {label} attempt {attempt}: transient unavailable, retrying");
            continue;
        }
        return Ok((result, total, attempt));
    }
    unreachable!("k1 {label}: retry loop returns on attempt 3");
}

/// Stale-negative twin (privileged): in the B16 direction the observer
/// holds the post-copy-up (upper) file while the target still runs the
/// pre-copy-up (lower) mapping; the production guard must refuse. Lane B
/// refuses with the finite gap after exactly one witness query; lane A
/// asserts its exact shape per rendering (witness or legacy refusal),
/// pinned against the truth record.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness"]
fn privileged_k1_deep_scan_stale_lower_refuses() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_stale_row(work.path(), mode, lane)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "K1_DEEP_SCAN direction=stale-lower lane={lane:?} modes=on,off,same-fs verdict=refuse"
    );
}

/// One stale-lower row over a fresh fixture.
fn k1_stale_row(work: &std::path::Path, mode: XinoMode, lane: OverlayLane) -> Result<(), String> {
    use crate::discovery::overlay_witness::{GAP_WITNESS_REFUSED, original_file_witness_required};
    eprintln!("K1_DEEP_SCAN start mode={mode:?} row=stale-lower lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE1u8; 8192])
        .map_err(|error| format!("k1 stale lower write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    // B16 direction: the target maps BEFORE the copy-up and keeps running
    // the lower file.
    let stale = SwapChild::spawn(&merged);
    let key = ObjectKey::of(&find_line(&stale.maps(), target_range(&stale), *b"r-xp")?);
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    // The observer-held file is the CURRENT one, opened after the copy-up.
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k1 stale held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k1 stale held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k1 stale held file is not on overlayfs: {held:?}"));
    }
    // Anchor stand-in: a fresh upper mapping provides the anchor maps
    // key and truth.
    let anchor = SwapChild::spawn(&merged);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    match lane {
        OverlayLane::B if ObjectKey::of(&a_line) != key => {
            return Err("k1 stale lane-B premise broken: anchor key moved across copy-up".into());
        }
        OverlayLane::A if ObjectKey::of(&a_line) == key => {
            return Err("k1 stale lane-A premise broken: anchor key equals the stale key".into());
        }
        _ => {}
    }
    let pid = stale.pid as u32;
    let t_range = target_range(&stale);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let t_truth = record_truth(
        pid,
        t_range,
        &held_file,
        &fixture.lower_path("lib.so"),
        xino.clone(),
        stable,
    )?;
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &fixture.upper_path("lib.so"),
        xino,
        None,
    )?;
    // Anchor currency: the held file is the current upper file, not the
    // lower one.
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k1 stale held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    let branch = takes_identity_key_branch(&t_truth, &a_truth);
    let required = original_file_witness_required(&held, &t_truth.map_files_identity());
    // The predicate must agree with the truth record: the witness shape
    // is required exactly when the stale mapping does not render the
    // backing file. Lane B takes the witness shape strictly.
    if branch == required {
        return Err(format!(
            "k1 stale predicate disagrees with the rendering: branch={branch} required={required}"
        ));
    }
    if lane == OverlayLane::B && !required {
        return Err(format!(
            "k1 stale fixture misses the witness-requiring shape: {held:?} vs {:?}",
            t_truth.map_files_identity()
        ));
    }
    let started = Instant::now();
    if required {
        // The witness refusal: each attempt spends exactly one query and
        // the settled outcome proves another file. A join here, or a
        // fallback edge, would fail the cell.
        let (result, queries, attempts) =
            k1_production_guard_retry("k1 stale", pid, &merged, key, &|| stale.maps())?;
        match result {
            Err(reason) if reason == GAP_WITNESS_REFUSED => {}
            other => return Err(format!("k1 stale: guard refused to refuse: {other:?}")),
        }
        eprintln!(
            "K1_DEEP_SCAN mode={mode:?} row=stale-lower lane={lane:?} verdict=refuse wall_ms={} queries={queries} attempts={attempts} target-{}",
            started.elapsed().as_millis(),
            truth_verdict(&t_truth)
        );
    } else {
        // The legacy refusal: the stale mapping already separates by
        // `(dev, ino)` and no witness work is spent.
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let mut io = crate::discovery::scan::ProcScanIo::new();
        let (result, queries) =
            k1_production_guard(pid, &merged, key, &stale.maps(), &mut budget, &mut io)?;
        match result {
            Err(reason) if reason.contains("names more than one file") => {}
            other => {
                return Err(format!(
                    "k1 stale legacy shape must keep the legacy refusal: {other:?}"
                ));
            }
        }
        if io.witness_used() != 0 || queries != 0 {
            return Err(format!(
                "k1 stale legacy shape spent witness work: used {} queries {queries}",
                io.witness_used()
            ));
        }
        eprintln!(
            "K1_DEEP_SCAN mode={mode:?} row=stale-lower lane={lane:?} verdict=refuse wall_ms={} queries={queries} used={} target-{}",
            started.elapsed().as_millis(),
            io.witness_used(),
            truth_verdict(&t_truth)
        );
    }
    Ok(())
}

/// Fresh-positive twin (privileged): the target maps the current upper
/// file after the copy-up; the production guard must join. Refusing here
/// would fail acceptance. The join runs the kernel proof on both lanes
/// (a fallback edge can never join: the witness IO refuses it); where
/// the kernel proof cannot run at all, the row asserts the exact
/// unavailable gap instead — a refusal either way, never silence.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness"]
fn privileged_k1_deep_scan_fresh_upper_joins() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_fresh_row(work.path(), mode, lane)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!("K1_DEEP_SCAN direction=fresh-upper lane={lane:?} modes=on,off,same-fs verdict=join");
}

/// One fresh-upper row over a fresh fixture.
fn k1_fresh_row(work: &std::path::Path, mode: XinoMode, lane: OverlayLane) -> Result<(), String> {
    use crate::discovery::overlay_witness::{
        original_file_witness_required, witness_unavailable_refusal,
    };
    eprintln!("K1_DEEP_SCAN start mode={mode:?} row=fresh-upper lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE2u8; 8192])
        .map_err(|error| format!("k1 fresh lower write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    // Fresh-positive: the target maps the current upper file.
    let anchor = SwapChild::spawn(&merged);
    let target = SwapChild::spawn(&merged);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    let t_line = find_line(&target.maps(), target_range(&target), *b"r-xp")?;
    let key = ObjectKey::of(&a_line);
    if ObjectKey::of(&t_line) != key {
        return Err("k1 fresh premise broken: target key differs from the anchor key".into());
    }
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k1 fresh held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k1 fresh held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k1 fresh held file is not on overlayfs: {held:?}"));
    }
    let pid = target.pid as u32;
    let t_range = target_range(&target);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let backing = fixture.upper_path("lib.so");
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &backing,
        xino.clone(),
        None,
    )?;
    let t_truth = record_truth(pid, t_range, &held_file, &backing, xino, stable)?;
    if lane == OverlayLane::B && takes_identity_key_branch(&t_truth, &a_truth) {
        return Err("k1 fresh: unexpected backing rendering on lane B".into());
    }
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k1 fresh held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    // The witness path is required on these live inputs on both lanes
    // (else the cell would prove the legacy path, not the join
    // question): target and held are the same file, so both renderings
    // agree.
    if !original_file_witness_required(&held, &t_truth.map_files_identity()) {
        return Err(format!(
            "k1 fresh fixture misses the witness-requiring shape: {held:?} vs {:?}",
            t_truth.map_files_identity()
        ));
    }
    let capable = k1_witness_capable();
    if lane == OverlayLane::B && !capable {
        return Err(
            "k1 fresh lane B requires the kernel identity capability (BTF/task_vma)".into(),
        );
    }
    let started = Instant::now();
    let (result, queries, attempts) =
        k1_production_guard_retry("k1 fresh", pid, &merged, key, &|| target.maps())?;
    match (capable, result) {
        (true, Ok(())) => {}
        (true, Err(reason)) => {
            return Err(format!(
                "k1 fresh: guard refused the fresh upper: {reason:?}"
            ));
        }
        (false, Err(reason)) if witness_unavailable_refusal(&reason) => {}
        (false, other) => {
            return Err(format!(
                "k1 fresh without the kernel proof must refuse unavailable: {other:?}"
            ));
        }
    }
    eprintln!(
        "K1_DEEP_SCAN mode={mode:?} row=fresh-upper lane={lane:?} verdict={} wall_ms={} queries={queries} attempts={attempts} target-{}",
        if capable {
            "join"
        } else {
            "refuse-unavailable"
        },
        started.elapsed().as_millis(),
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// Budget-exhaustion twin (privileged): a fresh-upper caller driven with
/// a spent witness budget refuses with the exact exhaustion gap and
/// runs zero queries, on both lanes.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness"]
fn privileged_k1_witness_budget_exhaustion_refuses() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_budget_row(work.path(), mode, lane)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "K1_DEEP_SCAN direction=budget-exhausted lane={lane:?} modes=on,off,same-fs verdict=refuse"
    );
}

/// One budget-exhaustion row over a fresh fixture.
fn k1_budget_row(work: &std::path::Path, mode: XinoMode, lane: OverlayLane) -> Result<(), String> {
    use crate::discovery::overlay_witness::{
        GAP_BUDGET_EXHAUSTED, OVERLAY_WITNESS_QUERIES_PER_SCAN, original_file_witness_required,
    };
    eprintln!("K1_DEEP_SCAN start mode={mode:?} row=budget-exhausted lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE3u8; 8192])
        .map_err(|error| format!("k1 budget lower write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let target = SwapChild::spawn(&merged);
    let t_line = find_line(&target.maps(), target_range(&target), *b"r-xp")?;
    let key = ObjectKey::of(&t_line);
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k1 budget held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k1 budget held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k1 budget held file is not on overlayfs: {held:?}"));
    }
    let pid = target.pid as u32;
    let t_range = target_range(&target);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let t_truth = record_truth(
        pid,
        t_range,
        &held_file,
        &fixture.upper_path("lib.so"),
        xino,
        stable,
    )?;
    // The spent budget must be the only reason for the refusal: the
    // fixture takes the witness-requiring shape on both lanes.
    if !original_file_witness_required(&held, &t_truth.map_files_identity()) {
        return Err(format!(
            "k1 budget fixture misses the witness-requiring shape: {held:?} vs {:?}",
            t_truth.map_files_identity()
        ));
    }
    let started = Instant::now();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let mut io =
        crate::discovery::scan::ProcScanIo::with_witness_used(OVERLAY_WITNESS_QUERIES_PER_SCAN);
    let (result, queries) =
        k1_production_guard(pid, &merged, key, &target.maps(), &mut budget, &mut io)?;
    match result {
        Err(reason) if reason == GAP_BUDGET_EXHAUSTED => {}
        other => {
            return Err(format!(
                "k1 budget: exhaustion must refuse with the exact gap: {other:?}"
            ));
        }
    }
    if io.witness_used() != OVERLAY_WITNESS_QUERIES_PER_SCAN {
        return Err(format!(
            "k1 budget: spent budget moved to {}",
            io.witness_used()
        ));
    }
    if queries != 0 {
        return Err(format!("k1 budget: exhaustion ran {queries} queries"));
    }
    eprintln!(
        "K1_DEEP_SCAN mode={mode:?} row=budget-exhausted lane={lane:?} verdict=refuse wall_ms={} queries=0 target-{}",
        started.elapsed().as_millis(),
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// Same-key-twice twin (privileged): the D1 shape — two scans of the same
/// provider key in one observer process (two passes, or two mappers of the
/// same lower file). The process-wide session serves every query, so the
/// second install must succeed exactly like the first; both joins prove.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness"]
fn privileged_k1_same_key_twice_proves() {
    overlay_preflight().expect("overlay preconditions hold");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_same_key_twice_row(work.path(), mode)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!("K1_DEEP_SCAN direction=same-key-twice modes=on,off,same-fs verdict=join");
}

/// One same-key-twice row over a fresh fixture: two production prove
/// steps over the same key, each with the fresh scan state a later
/// pass would carry.
fn k1_same_key_twice_row(work: &std::path::Path, mode: XinoMode) -> Result<(), String> {
    use crate::discovery::overlay_witness::witness_unavailable_refusal;
    eprintln!("K1_DEEP_SCAN start mode={mode:?} row=same-key-twice");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE2u8; 8192])
        .map_err(|error| format!("k1 twice lower write: {error}"))?;
    let merged = fixture.merged_path("lib.so");
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let anchor = SwapChild::spawn(&merged);
    let target = SwapChild::spawn(&merged);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    let t_line = find_line(&target.maps(), target_range(&target), *b"r-xp")?;
    let key = ObjectKey::of(&a_line);
    if ObjectKey::of(&t_line) != key {
        return Err("k1 twice premise broken: target key differs from the anchor key".into());
    }
    let pids = [anchor.pid as u32, target.pid as u32];
    let capable = k1_witness_capable();
    let mut attempts_total = 0u32;
    for (pass, pid) in pids.into_iter().enumerate() {
        let pass = pass + 1;
        let maps = || {
            if pid == anchor.pid as u32 {
                anchor.maps()
            } else {
                target.maps()
            }
        };
        let (result, queries, attempts) =
            k1_production_guard_retry("k1 twice", pid, &merged, key, &maps)?;
        attempts_total += attempts;
        if queries != attempts as u64 {
            return Err(format!(
                "k1 twice pass {pass}: ran {queries} queries in {attempts} attempts, not one per attempt"
            ));
        }
        match (capable, result) {
            (true, Ok(())) => {}
            (true, Err(reason)) => {
                return Err(format!(
                    "k1 twice pass {pass}: guard refused the fresh upper: {reason:?}"
                ));
            }
            (false, Err(reason)) if witness_unavailable_refusal(&reason) => {}
            (false, other) => {
                return Err(format!(
                    "k1 twice pass {pass} without the kernel proof must refuse unavailable: {other:?}"
                ));
            }
        }
    }
    eprintln!(
        "K1_DEEP_SCAN mode={mode:?} row=same-key-twice verdict=join passes=2 attempts={attempts_total}"
    );
    Ok(())
}

/// The K2 named loss label, asserted as a string so the RED run compiles
/// before the production label exists.
const K2_LOSS_LABEL: &str = "overlay_kernel_unavailable";

/// The exact K2 shape: no userspace-identity edge, one confirmation, the
/// named loss on this pid and nothing else.
fn k2_assert_loss(out: &SweepAttribution, pid: u32, what: &str) -> Result<(), String> {
    if !out.members.is_empty() {
        return Err(format!(
            "k2 {what}: userspace identity joined: {:?}",
            out.members
        ));
    }
    if out.probed != 1 {
        return Err(format!("k2 {what}: probed {} not 1", out.probed));
    }
    let labels: Vec<&str> = out.losses.keys().map(|loss| loss.label()).collect();
    if labels != [K2_LOSS_LABEL] {
        return Err(format!(
            "k2 {what}: losses {labels:?} member {:?}",
            out.member_losses
        ));
    }
    if !out.member_losses.contains_key(&pid) {
        return Err(format!(
            "k2 {what}: the loss names no pid {pid}: {:?}",
            out.member_losses
        ));
    }
    Ok(())
}

/// The exact named-mismatch shape (unstable xino-off rendering): no edge,
/// one confirmation, `identity_mismatch` and nothing else.
fn k2_assert_mismatch(out: &SweepAttribution, what: &str) -> Result<(), String> {
    if !out.members.is_empty()
        || out.losses != BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
        || out.probed != 1
    {
        return Err(format!(
            "k2 {what}: expected named mismatch, members {:?} losses {:?} probed {}",
            out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            out.losses,
            out.probed
        ));
    }
    Ok(())
}

/// The exact edge shape: this pid attributed to the row key, no losses.
fn k2_assert_edge(
    out: &SweepAttribution,
    pid: u32,
    key: ObjectKey,
    what: &str,
) -> Result<(), String> {
    let members: Vec<u32> = out.members.iter().map(|member| member.pid).collect();
    if members != [pid] {
        return Err(format!(
            "k2 {what}: expected edge for {pid}, members {members:?} losses {:?} probed {}",
            out.losses, out.probed
        ));
    }
    if !out.losses.is_empty() {
        return Err(format!("k2 {what}: edge with losses {:?}", out.losses));
    }
    if out.probed != 1 {
        return Err(format!("k2 {what}: edge with probed {}", out.probed));
    }
    let keys: Vec<ObjectKey> = out.members[0].objects.iter().map(|o| o.key).collect();
    if keys != [key] {
        return Err(format!("k2 {what}: edge for {keys:?}, row key is {key:?}"));
    }
    Ok(())
}

/// The exact no-candidate shape: the key never appears, so nothing
/// confirms and nothing is lost.
fn k2_assert_no_candidate(out: &SweepAttribution, what: &str) -> Result<(), String> {
    if !out.members.is_empty() || out.probed != 0 || !out.losses.is_empty() {
        return Err(format!(
            "k2 {what}: expected no candidate, members {:?} losses {:?} probed {}",
            out.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            out.losses,
            out.probed
        ));
    }
    Ok(())
}

/// K2 sweep-side no-fallback (privileged): over real loop-overlay
/// fixtures, the sweep never joins on userspace identity for the overlay
/// key. Stale-lower row: the userspace leg yields the exact named loss
/// (lane B) or finds no candidate (lane A, where the stale key already
/// differs); the kernel leg reports the stale mapping as another file
/// (lane B) or does not run (lane A). Fresh-upper row: the kernel leg
/// edges exactly on both lanes; the userspace leg yields the exact named
/// loss wherever the key renders overlay (lane B always; lane A only off
/// the N4 backing branch, where the key is its file's identity and both
/// legs edge without proof). A userspace-identity edge for an overlay key
/// anywhere, or a refused fresh kernel edge, fails the cell.
#[test]
#[ignore = "root: loop overlay mounts drive the sweep-side overlay no-fallback"]
fn privileged_k2_sweep_overlay_no_fallback() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session =
        crate::discovery::kernel_identity::IdentitySession::probe_and_load(&btf, probe_dir.path())
            .expect("strict-loaded kernel session; no refused/fallback positive");
    let mut generation = 0u64;
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k2_sweep_stale_row(work.path(), mode, lane, &mut session, &mut generation)
            .unwrap_or_else(|error| panic!("mode {mode:?} stale: {error}"));
        k2_sweep_fresh_row(work.path(), mode, lane, &mut session, &mut generation)
            .unwrap_or_else(|error| panic!("mode {mode:?} fresh: {error}"));
    }
    eprintln!("K2_SWEEP lane={lane:?} modes=on,off,same-fs verdict=no-fallback");
}

/// K1 sweep-side private-witness cell (privileged): over real loop-overlay
/// fixtures with the capture watching the held provider file (attach-set
/// exclusion), the sweep kernel run refuses the watched overlay key with
/// no sweep route, and the production `KernelSweepWitness` proves it
/// through its private session: the fresh-upper row joins, the stale-lower
/// row keeps the named `overlay_kernel_unavailable` loss, and the
/// no-witness RED run keeps the loss on the fresh row (the edge needs the
/// witness). With only the excluded anchor admitted, the install fails
/// and the same witness route proves the shape: the fresh row joins,
/// the stale row keeps the loss, and the no-witness run keeps the loss.
#[test]
#[ignore = "root: loop overlay mounts drive the sweep-side witness cell"]
fn privileged_k1_sweep_witness_fresh_joins_stale_refuses() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session =
        crate::discovery::kernel_identity::IdentitySession::probe_and_load(&btf, probe_dir.path())
            .expect("strict-loaded kernel session; no refused/fallback positive");
    let mut generation = 0u64;
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_sweep_witness_fresh_row(work.path(), mode, lane, &mut session, &mut generation)
            .unwrap_or_else(|error| panic!("mode {mode:?} fresh: {error}"));
        k1_sweep_witness_stale_row(work.path(), mode, lane, &mut session, &mut generation)
            .unwrap_or_else(|error| panic!("mode {mode:?} stale: {error}"));
    }
    eprintln!(
        "K1_SWEEP_WITNESS lane={lane:?} modes=on,off,same-fs verdict=join-fresh-refuse-stale"
    );
}

/// R1 no-route collect cell (privileged): over real loop-overlay
/// fixtures with SoftHSM as the provider, `collect_system_with_identity`
/// (Auto + scripted no-kernel checks) runs twice plus one single-shot
/// `collect()`. The fresh-upper child joins, the stale-lower child
/// refuses, and the shared witness window advances by the spent sweep
/// queries. Lane B asserts the sweep witness ran (spent>0); lane A
/// takes the legacy stale refusal without one.
#[test]
#[ignore = "root: loop overlay mounts drive the no-route collect cell"]
fn privileged_k1_no_route_collect_system_witness() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        k1_no_route_collect_row(work.path(), mode, lane)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "K1_NO_ROUTE_COLLECT lane={lane:?} modes=on,off,same-fs verdict=join-fresh-refuse-stale"
    );
}

/// One no-route collect row over a fresh fixture.
fn k1_no_route_collect_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
) -> Result<(), String> {
    use crate::discovery::overlay_witness::witness_stats_for_test;
    eprintln!("K1_NO_ROUTE_COLLECT start mode={mode:?} lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    let provider = k1_no_route_provider_path()?;
    std::fs::copy(&provider, fixture.lower_path("lib.so"))
        .map_err(|error| format!("k1 no-route provider copy: {error}"))?;
    let _xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    // Stale maps before the copy-up and keeps running the lower file.
    let stale = SwapChild::spawn(&merged);
    let stale_pid = stale.pid as u32;
    k1_no_route_copy_up_append(&merged, &fixture.upper_path("lib.so"))?;
    // Fresh maps the current upper file after the copy-up.
    let fresh = SwapChild::spawn(&merged);
    let fresh_pid = fresh.pid as u32;
    // Auto with scripted no-kernel checks: cheap numbering refusal, so
    // every pass with proof demand takes the no-route witness path and
    // never attempts a session load.
    let checks = crate::inspect_system::ScriptedIdentityChecks::refuse(
        crate::inspect_system::IdentityUnavailable::NumberingMismatch,
    );
    let shared = std::sync::Arc::new(std::sync::Mutex::new(
        crate::inspect_system::IdentityRunShared::new(
            crate::cli::IdentityBackendSelection::Auto,
            Box::new(checks),
        ),
    ));
    let policy = crate::plan::AdmissionPolicy::inventory(
        crate::capacity::InventoryBudget::new(4096, 4096 * 8)
            .map_err(|error| format!("k1 no-route inventory budget: {error:?}"))?,
    );
    let hooks = crate::discovery::hooks::HookRegistry::builtin();
    // Fresh-first selection with every pid except fresh already
    // scanned: the fixture group (holding the only never-scanned pid)
    // is picked first, and its representative is fresh (stale counts
    // as scanned). Fresh deep-scans (pinning the provider), stale
    // sweeps (needing the witness on lane B). Rebuilt per pass from a
    // live enumeration so pid churn cannot strand the selection.
    let scanned_for_fresh = || {
        let (pids, _) = crate::discovery::engine::scope_pids(&crate::attach::Scope::System);
        pids.into_iter().filter(|pid| *pid != fresh_pid).collect()
    };
    let window_of = || {
        shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .witness_window_for_test()
    };
    assert_eq!(window_of(), (0, 0));
    let catalog_of = |pid: u32, catalog: &crate::inspect_system::Catalog| {
        catalog
            .processes
            .iter()
            .find(|process| process.pid == pid)
            .map(|process| (process.objects.len(), format!("{:?}", process.status)))
    };
    for pass in [1, 2] {
        let (queries_before, _) = witness_stats_for_test();
        let scanned: BTreeSet<u32> = scanned_for_fresh();
        let catalog = crate::inspect_system::collect_system_with_identity(
            &[],
            &hooks,
            Some(1),
            policy,
            shared.clone(),
            crate::discovery::scan::CaptureWorkBudget::default(),
            &scanned,
            &[],
            0,
            0,
            &crate::inspect_system::ScanPriors::empty(),
        )
        .map_err(|error| format!("k1 no-route collect_system pass {pass}: {error:#}"))?;
        let (queries_after, _) = witness_stats_for_test();
        let (fresh_objects, fresh_status) = catalog_of(fresh_pid, &catalog)
            .ok_or_else(|| format!("k1 no-route pass {pass}: fresh pid missing"))?;
        let (stale_objects, stale_status) = catalog_of(stale_pid, &catalog)
            .ok_or_else(|| format!("k1 no-route pass {pass}: stale pid missing"))?;
        if fresh_objects == 0 {
            return Err(format!(
                "k1 no-route pass {pass}: fresh-upper must join, got {fresh_status}"
            ));
        }
        if stale_objects != 0 {
            return Err(format!(
                "k1 no-route pass {pass}: stale-lower must refuse, got {stale_status}"
            ));
        }
        if lane == OverlayLane::B {
            if queries_after <= queries_before {
                return Err(format!(
                    "k1 no-route pass {pass}: witness must run on lane B"
                ));
            }
            let (start, denominator) = window_of();
            if start != pass as u64 || denominator != 1 {
                return Err(format!(
                    "k1 no-route pass {pass}: window must advance by spent, got ({start}, {denominator})"
                ));
            }
        }
        eprintln!(
            "K1_NO_ROUTE_COLLECT mode={mode:?} pass={pass} fresh-objects={fresh_objects} \
             stale-objects={stale_objects} queries={} window={:?}",
            queries_after - queries_before,
            window_of(),
        );
    }
    // Single-shot collect() proves its sweep overlays through the same
    // no-route witness budget.
    let (single_before, _) = witness_stats_for_test();
    let single_scanned: BTreeSet<u32> = scanned_for_fresh();
    let single = crate::inspect_system::collect(&[], &[], &hooks, Some(1), policy, &single_scanned)
        .map_err(|error| format!("k1 no-route single-shot collect: {error:#}"))?;
    let (single_after, _) = witness_stats_for_test();
    let (fresh_objects, fresh_status) =
        catalog_of(fresh_pid, &single).ok_or("k1 no-route single-shot: fresh pid missing")?;
    let (stale_objects, stale_status) =
        catalog_of(stale_pid, &single).ok_or("k1 no-route single-shot: stale pid missing")?;
    if fresh_objects == 0 {
        return Err(format!(
            "k1 no-route single-shot: fresh-upper must join, got {fresh_status}"
        ));
    }
    if stale_objects != 0 {
        return Err(format!(
            "k1 no-route single-shot: stale-lower must refuse, got {stale_status}"
        ));
    }
    if lane == OverlayLane::B && single_after - single_before < 2 {
        return Err(
            "k1 no-route single-shot: deep-scan and sweep witnesses must run on lane B".into(),
        );
    }
    eprintln!(
        "K1_NO_ROUTE_COLLECT mode={mode:?} single-shot fresh-objects={fresh_objects} \
         stale-objects={stale_objects} queries={}",
        single_after - single_before,
    );
    Ok(())
}

/// SoftHSM provider bytes for the no-route collect fixture, probed
/// across distributions (never hard-coded to one path).
fn k1_no_route_provider_path() -> Result<String, String> {
    for candidate in [
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }
    Err("k1 no-route: SoftHSM2 provider is missing (tried Debian, Ubuntu and Fedora paths)".into())
}

/// Trigger a copy-up by appending one byte to the merged file. The
/// provider stays a valid ELF (trailing bytes are ignored), unlike an
/// in-place overwrite of the header.
fn k1_no_route_copy_up_append(
    merged: &std::path::Path,
    upper: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write as _;
    let before =
        std::fs::read(merged).map_err(|error| format!("k1 no-route copy-up read: {error}"))?;
    {
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(merged)
            .map_err(|error| format!("k1 no-route copy-up open: {error}"))?;
        writer
            .write_all(b"X")
            .map_err(|error| format!("k1 no-route copy-up write: {error}"))?;
    }
    if !upper.exists() {
        return Err(format!(
            "k1 no-route copy-up did not materialize {}",
            upper.display()
        ));
    }
    let after =
        std::fs::read(merged).map_err(|error| format!("k1 no-route copy-up reread: {error}"))?;
    if after.len() != before.len() + 1 || after[..before.len()] != before[..] {
        return Err("k1 no-route copy-up did not append exactly one byte".into());
    }
    Ok(())
}

/// One install-and-sweep round over the witnessed fixture: admit the held
/// key plus the unwatched anchor, exclude the held file, install, and
/// drive the sweep with (or, for the RED run, without) the production
/// witness. Returns the attribution and the witness query count.
#[allow(clippy::too_many_arguments)]
fn k1_witness_round(
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    object2: crate::discovery::identity::PinnedObjectId,
    key: ObjectKey,
    key2: ObjectKey,
    pid: u32,
    snapshot: Vec<MapEntry>,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: &mut u64,
    with_witness: bool,
) -> Result<(SweepAttribution, u32), String> {
    use crate::discovery::kernel_identity::{
        AnchorPass, ExaminedCustody, KernelAnchorExclusions, KernelMemberProbe,
    };
    let (mut index, refused) = KnownKeyIndex::build(
        [(key, Some(object)), (key2, Some(object2))],
        &BTreeMap::from([(key, object), (key2, object2)]),
        [],
        pins,
    );
    if !refused.is_empty() {
        return Err(format!("k1 witness index admission refuses: {refused:?}"));
    }
    let watched_target = pins
        .retain_inventory_target(object)
        .map_err(|error| format!("k1 witness retain watched: {error}"))?;
    let exclusions = KernelAnchorExclusions::from_targets([&watched_target]);
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).map_err(|error| format!("k1 witness census: {error}"))?,
        0,
    );
    let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
    custody
        .reconcile(
            SegmentPolicy::try_snapshot(1, 1)
                .map_err(|error| format!("k1 witness confirm census: {error}"))?,
        )
        .map_err(|error| format!("k1 witness reconcile: {error}"))?;
    // The sweep driver below reuses this same owner: the segment hook
    // refuses with `FdHeadroom` unless its batch resources share the
    // anchor pass's owner (production shares one owner the same way).
    let sweep_owner = owner.clone();
    let pass =
        AnchorPass::prepare_excluding(pins, [(key, object), (key2, object2)], custody, &exclusions);
    if pass.fallback.get(&key)
        != Some(&crate::discovery::kernel_identity::AnchorDeny::CaptureWatched)
    {
        return Err(format!(
            "k1 witness premise broken: held anchor not capture-watched: {:?}",
            pass.fallback
        ));
    }
    if pass.fallback.contains_key(&key2) {
        return Err(format!(
            "k1 witness premise broken: unwatched anchor refused: {:?}",
            pass.fallback
        ));
    }
    *generation += 1;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, *generation, deadline)
        .map_err(|error| format!("k1 witness install: {error}"))?;
    let mut probe = KernelMemberProbe::new(&mut installed, OsConfirmIo::with_pool(None), deadline);
    probe
        .install_expectations(&mut index)
        .map_err(|error| format!("k1 witness expectations: {error}"))?;
    if index
        .match_slots
        .get(&key)
        .is_some_and(|slots| !slots.is_empty())
    {
        return Err("k1 witness premise broken: held key holds sweep slots".into());
    }
    if !index
        .match_slots
        .get(&key2)
        .is_some_and(|slots| !slots.is_empty())
    {
        return Err("k1 witness premise broken: unwatched anchor holds no slots".into());
    }
    let mut budget = CaptureWorkBudget::default();
    if budget.has_collection_work() {
        return Err("k1 witness premise broken: scoped collection fallback".into());
    }
    let policy = SegmentPolicy::from_headroom(16, 1, 1);
    let sweep = vec![(pid, snapshot)];
    let mut witness = crate::discovery::overlay_witness::KernelSweepWitness::new();
    let out = match with_witness {
        true => {
            crate::discovery::confirm_shards::attribute_unselected_with_segment_proof_with_witness(
                &sweep,
                &BTreeSet::new(),
                &BTreeSet::new(),
                &index,
                &mut budget,
                policy,
                &sweep_owner,
                1,
                &|| OsConfirmIo::with_pool(None),
                probe.segment_proof(),
                pins,
                &mut witness,
                0,
                0,
            )
            .0
        }
        false => crate::discovery::confirm_shards::attribute_unselected_with_segment_proof(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut budget,
            policy,
            &sweep_owner,
            1,
            &|| OsConfirmIo::with_pool(None),
            probe.segment_proof(),
        ),
    };
    drop(probe);
    drop(installed);
    Ok((out, witness.used()))
}

/// One fresh-upper sweep row through the production witness: the watched
/// overlay key has no sweep route, the private session proves the mapping
/// is the held file, and the row joins; the RED run without the witness
/// keeps the named loss. With only the excluded anchor the install fails
/// (every anchor watched) and userspace keeps the loss with no witness.
#[allow(clippy::too_many_lines)]
fn k1_sweep_witness_fresh_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: &mut u64,
) -> Result<(), String> {
    eprintln!("K1_SWEEP_WITNESS start mode={mode:?} row=fresh-upper lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE2u8; 8192])
        .map_err(|error| format!("k1 fresh lower write: {error}"))?;
    std::fs::write(fixture.lower_path("lib2.so"), vec![0xE3u8; 8192])
        .map_err(|error| format!("k1 fresh lib2 write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    let merged2 = fixture.merged_path("lib2.so");
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let anchor = SwapChild::spawn(&merged);
    let target = SwapChild::spawn(&merged);
    let anchor2 = SwapChild::spawn(&merged2);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    let t_line = find_line(&target.maps(), target_range(&target), *b"r-xp")?;
    let key = ObjectKey::of(&a_line);
    if ObjectKey::of(&t_line) != key {
        return Err("k1 fresh premise broken: target key differs from the anchor key".into());
    }
    let line2 = find_line(&anchor2.maps(), target_range(&anchor2), *b"r-xp")?;
    let key2 = ObjectKey::of(&line2);
    if key2 == key {
        return Err("k1 fresh premise broken: unwatched key collides with the held key".into());
    }
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k1 fresh held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k1 fresh held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k1 fresh held file is not on overlayfs: {held:?}"));
    }
    let (mut pins, object) = overlay_pin(&merged, key)?;
    {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(&merged2).map_err(|error| format!("k1 fresh lib2 read: {error}"))?;
        let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
        let skipped = pins.absorb(crate::discovery::identity::test_fixture::real_scan_pin(
            &merged2,
            Some(key2),
            0,
            &digest,
        ));
        if !skipped.is_empty() {
            return Err(format!("k1 fresh lib2 pin skipped: {skipped:?}"));
        }
    }
    let object2 = pins
        .pinned()
        .find(|summary| summary.key == key2)
        .map(|summary| summary.id)
        .ok_or_else(|| "k1 fresh premise broken: unwatched pin missing".to_string())?;
    if object2 == object {
        return Err("k1 fresh premise broken: pins share one object".into());
    }
    let pid = target.pid as u32;
    let t_range = target_range(&target);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let backing = fixture.upper_path("lib.so");
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &backing,
        xino.clone(),
        None,
    )?;
    let t_truth = record_truth(pid, t_range, &held_file, &backing, xino, stable)?;
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k1 fresh held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    let branch = takes_identity_key_branch(&t_truth, &a_truth);
    let n4 = lane == OverlayLane::A && branch;
    if lane == OverlayLane::B && branch {
        return Err("unexpected backing rendering on lane B".into());
    }
    let (scratch, _) = KnownKeyIndex::build(
        [(key, Some(object)), (key2, Some(object2))],
        &BTreeMap::from([(key, object), (key2, object2)]),
        [],
        &pins,
    );
    if n4 && scratch.map_files_keys().contains(&key) {
        return Err("k1 fresh N4 premise broken: identity key needs no per-range proof".into());
    }
    if !n4 && !scratch.map_files_keys().contains(&key) {
        return Err("k1 fresh premise broken: overlay key needs per-range proof".into());
    }
    // GREEN: the private witness proves the fresh mapping and the row joins.
    let (out, used) = k1_witness_round(
        &pins,
        object,
        object2,
        key,
        key2,
        pid,
        target.maps(),
        session,
        generation,
        true,
    )?;
    if n4 {
        k2_assert_edge(&out, pid, key, "fresh witnessed (N4)")?;
        if used != 0 {
            return Err(format!("k1 fresh N4 ran {used} witness queries, want 0"));
        }
    } else {
        k2_assert_edge(&out, pid, key, "fresh witnessed")?;
        if used != 1 {
            return Err(format!("k1 fresh witnessed ran {used} queries, want 1"));
        }
    }
    // RED: the same install shape without the witness keeps the loss.
    let (red, red_used) = k1_witness_round(
        &pins,
        object,
        object2,
        key,
        key2,
        pid,
        target.maps(),
        session,
        generation,
        false,
    )?;
    if red_used != 0 {
        return Err(format!(
            "k1 fresh RED ran {red_used} witness queries, want 0"
        ));
    }
    if n4 {
        k2_assert_edge(&red, pid, key, "fresh RED (N4)")?;
    } else {
        k2_assert_loss(&red, pid, "fresh RED")?;
    }
    // Only the excluded anchor: the install fails (every anchor watched)
    // and the same production witness route proves the shape: the fresh
    // row joins with one query, while the same shape without the witness
    // keeps the loss.
    {
        use crate::discovery::kernel_identity::{
            AnchorPass, ExaminedCustody, KernelAnchorExclusions,
        };
        let (index, _) = KnownKeyIndex::build(
            [(key, Some(object))],
            &BTreeMap::from([(key, object)]),
            [],
            &pins,
        );
        let watched_target = pins
            .retain_inventory_target(object)
            .map_err(|error| format!("k1 only-excluded retain watched: {error}"))?;
        let exclusions = KernelAnchorExclusions::from_targets([&watched_target]);
        let owner = ReservationOwner::for_examined(
            SegmentPolicy::try_snapshot(0, 0)
                .map_err(|error| format!("k1 only-excluded census: {error}"))?,
            0,
        );
        let sweep_owner = owner.clone();
        let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
        custody
            .reconcile(
                SegmentPolicy::try_snapshot(1, 1)
                    .map_err(|error| format!("k1 only-excluded confirm census: {error}"))?,
            )
            .map_err(|error| format!("k1 only-excluded reconcile: {error}"))?;
        let pass = AnchorPass::prepare_excluding(&pins, [(key, object)], custody, &exclusions);
        if !pass.only_capture_excluded() {
            return Err(format!(
                "k1 only-excluded premise broken: {:?}",
                pass.fallback
            ));
        }
        *generation += 1;
        let deadline = Instant::now() + Duration::from_secs(10);
        if session.install_anchors(pass, *generation, deadline).is_ok() {
            return Err(
                "k1 only-excluded premise broken: install succeeded with no anchors".into(),
            );
        }
        let policy = SegmentPolicy::from_headroom(16, 1, 1);
        let sweep = vec![(pid, target.maps())];
        // GREEN: the production witness route joins the fresh row.
        let mut budget = CaptureWorkBudget::default();
        let mut witness = crate::discovery::overlay_witness::KernelSweepWitness::new();
        let (out, _) =
            crate::discovery::confirm_shards::attribute_unselected_capture_excluded_with_witness(
                &sweep,
                &BTreeSet::new(),
                &BTreeSet::new(),
                &index,
                &mut budget,
                policy,
                &sweep_owner,
                1,
                &|| OsConfirmIo::with_pool(None),
                &pins,
                &mut witness,
                0,
                0,
            );
        let used = witness.used();
        if n4 {
            k2_assert_edge(&out, pid, key, "fresh only-excluded (N4)")?;
            if used != 0 {
                return Err(format!(
                    "k1 fresh only-excluded N4 ran {used} witness queries, want 0"
                ));
            }
        } else {
            k2_assert_edge(&out, pid, key, "fresh only-excluded")?;
            if used != 1 {
                return Err(format!(
                    "k1 fresh only-excluded ran {used} witness queries, want 1"
                ));
            }
        }
        // RED: the same refused shape without the witness keeps the loss.
        let mut red_budget = CaptureWorkBudget::default();
        let mut hook = crate::discovery::kernel_identity::AnchorRefusedHook::new(&index);
        let red = crate::discovery::confirm_shards::attribute_unselected_with_segment_proof(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut red_budget,
            policy,
            &sweep_owner,
            1,
            &|| OsConfirmIo::with_pool(None),
            &mut hook,
        );
        if n4 {
            k2_assert_edge(&red, pid, key, "fresh only-excluded RED (N4)")?;
        } else {
            k2_assert_loss(&red, pid, "fresh only-excluded RED")?;
        }
    }
    eprintln!(
        "K1_SWEEP_WITNESS mode={mode:?} row=fresh-upper lane={lane:?} verdict={} target-{}",
        if n4 { "N4-edge" } else { "join" },
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// One stale-lower sweep row through the production witness: the target
/// maps before the copy-up and keeps running the lower file while the
/// observer holds the fresh upper file, so the private session proves
/// another file and the row keeps the named loss (lane B), or the stale
/// key never matches (lane A).
#[allow(clippy::too_many_lines)]
fn k1_sweep_witness_stale_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: &mut u64,
) -> Result<(), String> {
    eprintln!("K1_SWEEP_WITNESS start mode={mode:?} row=stale-lower lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE1u8; 8192])
        .map_err(|error| format!("k1 stale lower write: {error}"))?;
    std::fs::write(fixture.lower_path("lib2.so"), vec![0xE3u8; 8192])
        .map_err(|error| format!("k1 stale lib2 write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    let merged2 = fixture.merged_path("lib2.so");
    let stale = SwapChild::spawn(&merged);
    let t_line = find_line(&stale.maps(), target_range(&stale), *b"r-xp")?;
    let stale_key = ObjectKey::of(&t_line);
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k1 stale held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k1 stale held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k1 stale held file is not on overlayfs: {held:?}"));
    }
    let anchor = SwapChild::spawn(&merged);
    let anchor2 = SwapChild::spawn(&merged2);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    let key = ObjectKey::of(&a_line);
    match lane {
        OverlayLane::B if key != stale_key => {
            return Err("k1 stale lane-B premise broken: anchor key moved across copy-up".into());
        }
        OverlayLane::A if key == stale_key => {
            return Err("k1 stale lane-A premise broken: anchor key equals the stale key".into());
        }
        _ => {}
    }
    let line2 = find_line(&anchor2.maps(), target_range(&anchor2), *b"r-xp")?;
    let key2 = ObjectKey::of(&line2);
    if key2 == key {
        return Err("k1 stale premise broken: unwatched key collides with the held key".into());
    }
    let (mut pins, object) = overlay_pin(&merged, key)?;
    {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(&merged2).map_err(|error| format!("k1 stale lib2 read: {error}"))?;
        let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
        let skipped = pins.absorb(crate::discovery::identity::test_fixture::real_scan_pin(
            &merged2,
            Some(key2),
            0,
            &digest,
        ));
        if !skipped.is_empty() {
            return Err(format!("k1 stale lib2 pin skipped: {skipped:?}"));
        }
    }
    let object2 = pins
        .pinned()
        .find(|summary| summary.key == key2)
        .map(|summary| summary.id)
        .ok_or_else(|| "k1 stale premise broken: unwatched pin missing".to_string())?;
    if object2 == object {
        return Err("k1 stale premise broken: pins share one object".into());
    }
    let pid = stale.pid as u32;
    let t_range = target_range(&stale);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let t_truth = record_truth(
        pid,
        t_range,
        &held_file,
        &fixture.lower_path("lib.so"),
        xino.clone(),
        stable,
    )?;
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &fixture.upper_path("lib.so"),
        xino,
        None,
    )?;
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k1 stale held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    let branch = takes_identity_key_branch(&t_truth, &a_truth);
    if lane == OverlayLane::B && branch {
        return Err("unexpected backing rendering on lane B".into());
    }
    if lane == OverlayLane::B
        && stable != Some(false)
        && held.identity != t_truth.map_files_identity()
    {
        return Err(format!(
            "k1 stale premise broken: expected agreeing userspace identity: {:?} vs {:?}",
            held.identity,
            t_truth.map_files_identity()
        ));
    }
    let (out, used) = k1_witness_round(
        &pins,
        object,
        object2,
        key,
        key2,
        pid,
        stale.maps(),
        session,
        generation,
        true,
    )?;
    match lane {
        OverlayLane::B => {
            k2_assert_loss(&out, pid, "stale witnessed")?;
            if used != 1 {
                return Err(format!("k1 stale witnessed ran {used} queries, want 1"));
            }
        }
        OverlayLane::A => {
            k2_assert_no_candidate(&out, "stale witnessed")?;
            if used != 0 {
                return Err(format!(
                    "k1 stale lane-A ran {used} witness queries, want 0"
                ));
            }
        }
    }
    // Only the excluded anchor: the install fails (every anchor watched)
    // and the same production witness route proves the shape: the stale
    // row keeps the named loss on lane B with one query, while lane A
    // never admits the stale key.
    {
        use crate::discovery::kernel_identity::{
            AnchorPass, ExaminedCustody, KernelAnchorExclusions,
        };
        let (index, _) = KnownKeyIndex::build(
            [(key, Some(object))],
            &BTreeMap::from([(key, object)]),
            [],
            &pins,
        );
        let watched_target = pins
            .retain_inventory_target(object)
            .map_err(|error| format!("k1 only-excluded retain watched: {error}"))?;
        let exclusions = KernelAnchorExclusions::from_targets([&watched_target]);
        let owner = ReservationOwner::for_examined(
            SegmentPolicy::try_snapshot(0, 0)
                .map_err(|error| format!("k1 only-excluded census: {error}"))?,
            0,
        );
        let sweep_owner = owner.clone();
        let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
        custody
            .reconcile(
                SegmentPolicy::try_snapshot(1, 1)
                    .map_err(|error| format!("k1 only-excluded confirm census: {error}"))?,
            )
            .map_err(|error| format!("k1 only-excluded reconcile: {error}"))?;
        let pass = AnchorPass::prepare_excluding(&pins, [(key, object)], custody, &exclusions);
        if !pass.only_capture_excluded() {
            return Err(format!(
                "k1 only-excluded premise broken: {:?}",
                pass.fallback
            ));
        }
        *generation += 1;
        let deadline = Instant::now() + Duration::from_secs(10);
        if session.install_anchors(pass, *generation, deadline).is_ok() {
            return Err(
                "k1 only-excluded premise broken: install succeeded with no anchors".into(),
            );
        }
        let policy = SegmentPolicy::from_headroom(16, 1, 1);
        let sweep = vec![(pid, stale.maps())];
        let mut budget = CaptureWorkBudget::default();
        let mut witness = crate::discovery::overlay_witness::KernelSweepWitness::new();
        let (out, _) =
            crate::discovery::confirm_shards::attribute_unselected_capture_excluded_with_witness(
                &sweep,
                &BTreeSet::new(),
                &BTreeSet::new(),
                &index,
                &mut budget,
                policy,
                &sweep_owner,
                1,
                &|| OsConfirmIo::with_pool(None),
                &pins,
                &mut witness,
                0,
                0,
            );
        let used = witness.used();
        match lane {
            OverlayLane::B => {
                k2_assert_loss(&out, pid, "stale only-excluded")?;
                if used != 1 {
                    return Err(format!("k1 stale only-excluded ran {used} queries, want 1"));
                }
            }
            OverlayLane::A => {
                k2_assert_no_candidate(&out, "stale only-excluded")?;
                if used != 0 {
                    return Err(format!(
                        "k1 stale only-excluded lane-A ran {used} witness queries, want 0"
                    ));
                }
            }
        }
    }
    eprintln!(
        "K1_SWEEP_WITNESS mode={mode:?} row=stale-lower lane={lane:?} verdict=refuse target-{}",
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// One stale-lower sweep row over a fresh fixture: the target maps before
/// the copy-up and keeps running the lower file while the observer holds
/// the fresh upper file under the fresh key.
#[allow(clippy::too_many_lines)]
fn k2_sweep_stale_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: &mut u64,
) -> Result<(), String> {
    eprintln!("K2_SWEEP start mode={mode:?} row=stale-lower lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE1u8; 8192])
        .map_err(|error| format!("k2 stale lower write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    let stale = SwapChild::spawn(&merged);
    let t_line = find_line(&stale.maps(), target_range(&stale), *b"r-xp")?;
    let stale_key = ObjectKey::of(&t_line);
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k2 stale held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k2 stale held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k2 stale held file is not on overlayfs: {held:?}"));
    }
    let anchor = SwapChild::spawn(&merged);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    // The index models the pinned fresh file under the fresh key.
    let key = ObjectKey::of(&a_line);
    match lane {
        OverlayLane::B if key != stale_key => {
            return Err("k2 stale lane-B premise broken: anchor key moved across copy-up".into());
        }
        OverlayLane::A if key == stale_key => {
            return Err("k2 stale lane-A premise broken: anchor key equals the stale key".into());
        }
        _ => {}
    }
    let (pins, object) = overlay_pin(&merged, key)?;
    let index = overlay_index(key, object, &pins);
    let pid = stale.pid as u32;
    let t_range = target_range(&stale);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let t_truth = record_truth(
        pid,
        t_range,
        &held_file,
        &fixture.lower_path("lib.so"),
        xino.clone(),
        stable,
    )?;
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &fixture.upper_path("lib.so"),
        xino,
        None,
    )?;
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k2 stale held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    let branch = takes_identity_key_branch(&t_truth, &a_truth);
    let userspace = d4_overlay_attribute_pid(pid, stale.maps(), &index);
    match lane {
        OverlayLane::B => {
            if branch {
                return Err("unexpected backing rendering on lane B".into());
            }
            // Non-vacuous: the named loss is asserted only where userspace
            // identity agrees (else the honest outcome is a mismatch).
            if stable != Some(false) && held.identity != t_truth.map_files_identity() {
                return Err(format!(
                    "k2 stale premise broken: expected agreeing userspace identity: {:?} vs {:?}",
                    held.identity,
                    t_truth.map_files_identity()
                ));
            }
            if stable == Some(false) {
                k2_assert_mismatch(&userspace, "stale userspace (unstable)")?;
            } else {
                k2_assert_loss(&userspace, pid, "stale userspace")?;
            }
            *generation += 1;
            let (kernel, _) = d4_overlay_kernel_attribution_for_pid(
                pid,
                stale.maps(),
                &pins,
                object,
                key,
                session,
                *generation,
            );
            k2_assert_mismatch(&kernel, "stale kernel")?;
        }
        OverlayLane::A => {
            k2_assert_no_candidate(&userspace, "stale userspace")?;
            *generation += 1;
            let (kernel, _) = d4_overlay_kernel_no_run_for_pid(
                pid,
                stale.maps(),
                &pins,
                object,
                key,
                session,
                *generation,
                branch,
            );
            k2_assert_no_candidate(&kernel, "stale kernel")?;
        }
    }
    eprintln!(
        "K2_SWEEP mode={mode:?} row=stale-lower lane={lane:?} verdict=refuse target-{}",
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// One fresh-upper sweep row over a fresh fixture: the target maps the
/// current upper file after the copy-up; the observer holds the same file.
#[allow(clippy::too_many_lines)]
fn k2_sweep_fresh_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: &mut u64,
) -> Result<(), String> {
    eprintln!("K2_SWEEP start mode={mode:?} row=fresh-upper lane={lane:?}");
    let fixture = OverlayFixture::mount(work, mode)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE2u8; 8192])
        .map_err(|error| format!("k2 fresh lower write: {error}"))?;
    let xino = fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let anchor = SwapChild::spawn(&merged);
    let target = SwapChild::spawn(&merged);
    let a_line = find_line(&anchor.maps(), anchor_range(&anchor), *b"r-xp")?;
    let t_line = find_line(&target.maps(), target_range(&target), *b"r-xp")?;
    let key = ObjectKey::of(&a_line);
    if ObjectKey::of(&t_line) != key {
        return Err("k2 fresh premise broken: target key differs from the anchor key".into());
    }
    let held_file =
        std::fs::File::open(&merged).map_err(|error| format!("k2 fresh held open: {error}"))?;
    let held = crate::discovery::identity::self_mapped_file(&held_file)
        .map_err(|error| format!("k2 fresh held identity: {error}"))?;
    if held.fs_magic != Some(p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC) {
        return Err(format!("k2 fresh held file is not on overlayfs: {held:?}"));
    }
    let (pins, object) = overlay_pin(&merged, key)?;
    let index = overlay_index(key, object, &pins);
    let pid = target.pid as u32;
    let t_range = target_range(&target);
    let stable = if mode == XinoMode::Off {
        Some(map_files_stable(pid, t_range)?)
    } else {
        None
    };
    let backing = fixture.upper_path("lib.so");
    let a_truth = record_truth(
        anchor.pid as u32,
        anchor_range(&anchor),
        &held_file,
        &backing,
        xino.clone(),
        None,
    )?;
    let t_truth = record_truth(pid, t_range, &held_file, &backing, xino, stable)?;
    if held.identity != a_truth.map_files_identity() {
        return Err(format!(
            "k2 fresh held file is not the current upper file: held {:?} vs upper {:?}",
            held.identity,
            a_truth.map_files_identity()
        ));
    }
    let branch = takes_identity_key_branch(&t_truth, &a_truth);
    // N4: backing rendering on lane A makes the key its file's identity,
    // so both legs edge without proof (K2 does not apply to the ext4 key).
    let n4 = lane == OverlayLane::A && branch;
    if lane == OverlayLane::B && branch {
        return Err("unexpected backing rendering on lane B".into());
    }
    let userspace = d4_overlay_attribute_pid(pid, target.maps(), &index);
    if n4 {
        if index.map_files_keys().contains(&key) {
            return Err("k2 fresh N4 premise broken: identity key needs no per-range proof".into());
        }
        k2_assert_edge(&userspace, pid, key, "fresh userspace (N4)")?;
        *generation += 1;
        let (kernel, _) = d4_overlay_kernel_identity_key_for_pid(
            pid,
            target.maps(),
            &pins,
            object,
            key,
            session,
            *generation,
        );
        k2_assert_edge(&kernel, pid, key, "fresh kernel (N4)")?;
    } else {
        if !index.map_files_keys().contains(&key) {
            return Err("k2 fresh premise broken: overlay key needs per-range proof".into());
        }
        if stable != Some(false) && held.identity != t_truth.map_files_identity() {
            return Err(format!(
                "k2 fresh premise broken: expected agreeing userspace identity: {:?} vs {:?}",
                held.identity,
                t_truth.map_files_identity()
            ));
        }
        if stable == Some(false) {
            k2_assert_mismatch(&userspace, "fresh userspace (unstable)")?;
        } else {
            k2_assert_loss(&userspace, pid, "fresh userspace")?;
        }
        *generation += 1;
        let (kernel, _) = d4_overlay_kernel_attribution_for_pid(
            pid,
            target.maps(),
            &pins,
            object,
            key,
            session,
            *generation,
        );
        k2_assert_edge(&kernel, pid, key, "fresh kernel")?;
    }
    eprintln!(
        "K2_SWEEP mode={mode:?} row=fresh-upper lane={lane:?} verdict={} target-{}",
        if n4 { "N4-edge" } else { "join" },
        truth_verdict(&t_truth)
    );
    Ok(())
}

/// Copy-up old-file feasibility: after an overlayfs copy-up the observer
/// holds the fresh upper file while a pre-copy-up mapper still runs the
/// lower file. The deep-scan witness proves the stale range is another
/// file (the K1 stale twin pins the refusal); the cells below prove the
/// same kernel primitive can also positively identify the lower file, so
/// each mapper can later be attributed to its real file without guessing.
/// The lower path is read back from the live mount table (never from the
/// construction call) and then proved — the open alone never joins.
///
/// One setup serves both twins: a stale child maps before the copy-up,
/// a fresh child maps after, and the held file opens after (the B16
/// direction).
struct CopyUpOldFile {
    fixture: OverlayFixture,
    stale: SwapChild,
    fresh: SwapChild,
    merged: std::path::PathBuf,
}

/// Mount one overlay merge with a provider-shaped lower file, map it
/// from the stale child, copy it up, then map it from the fresh child.
/// The stale and fresh keys pin the lane's rendering premise: on lane B
/// (except xino-off, whose file numbers are non-persistent) both keys
/// are equal — the userspace indistinguishability — while on lane A the
/// copy-up moves the key.
fn copyup_old_file_setup(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
) -> Result<CopyUpOldFile, String> {
    copyup_old_file_setup_with(work, mode, lane, "")
}

/// [`copyup_old_file_setup`] with one extra overlay mount option (for
/// example `,metacopy=on`).
fn copyup_old_file_setup_with(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    extra: &str,
) -> Result<CopyUpOldFile, String> {
    let fixture = OverlayFixture::mount_with_extra(work, mode, extra)?;
    std::fs::write(fixture.lower_path("lib.so"), vec![0xE4u8; 8192])
        .map_err(|error| format!("copyup old-file lower write: {error}"))?;
    fixture.xino_verdict("lib.so")?;
    let merged = fixture.merged_path("lib.so");
    let stale = SwapChild::spawn(&merged);
    trigger_copy_up(
        &merged,
        &fixture.upper_path("lib.so"),
        &fixture.lower_path("lib.so"),
    )?;
    let fresh = SwapChild::spawn(&merged);
    let stale_key = ObjectKey::of(&find_line(&stale.maps(), target_range(&stale), *b"r-xp")?);
    let fresh_key = ObjectKey::of(&find_line(&fresh.maps(), target_range(&fresh), *b"r-xp")?);
    match lane {
        OverlayLane::B if mode != XinoMode::Off && stale_key != fresh_key => {
            return Err(
                "copyup old-file lane-B premise broken: stale key moved across copy-up".into(),
            );
        }
        OverlayLane::A if stale_key == fresh_key => {
            return Err(
                "copyup old-file lane-A premise broken: stale key equals the fresh key".into(),
            );
        }
        _ => {}
    }
    Ok(CopyUpOldFile {
        fixture,
        stale,
        fresh,
        merged,
    })
}

/// One diagnosed original-file query against an explicitly opened file
/// (held upper or a lower candidate), with the global query spend delta.
/// The caller picks the anchor; the verdict names which file the range
/// maps.
#[allow(clippy::type_complexity)]
fn copyup_old_file_prove(
    pid: u32,
    file: &std::fs::File,
    held: &crate::discovery::identity::MappedFile,
    key: ObjectKey,
    ranges: &[(u64, u64)],
) -> Result<
    (
        crate::discovery::overlay_witness::WitnessVerdict,
        Option<crate::discovery::overlay_witness::WitnessDiagnosis>,
        u64,
    ),
    String,
> {
    use crate::discovery::overlay_witness::{
        prove_original_file_diagnosed, witness_stats_for_test,
    };
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let (before, _) = witness_stats_for_test();
    let outcome = prove_original_file_diagnosed(pid, file, held, key, ranges, &mut budget);
    let (after, _) = witness_stats_for_test();
    Ok((
        outcome.verdict,
        outcome.diagnosis,
        after.saturating_sub(before),
    ))
}

/// Retry a direct prove across transient witness-infrastructure loss:
/// only the unavailable verdict retries (at most three attempts, each
/// spending exactly one query), mirroring the K1 guard retry. A
/// systematic refusal returns on the third strike.
#[allow(clippy::type_complexity)]
fn copyup_old_file_prove_retry(
    label: &str,
    pid: u32,
    file: &std::fs::File,
    held: &crate::discovery::identity::MappedFile,
    key: ObjectKey,
    ranges: &[(u64, u64)],
) -> Result<
    (
        crate::discovery::overlay_witness::WitnessVerdict,
        Option<crate::discovery::overlay_witness::WitnessDiagnosis>,
        u64,
        u32,
    ),
    String,
> {
    use crate::discovery::overlay_witness::{WitnessFailure, WitnessVerdict};
    let mut total = 0u64;
    for attempt in 1..=3u32 {
        let (verdict, diagnosis, queries) = copyup_old_file_prove(pid, file, held, key, ranges)?;
        total += queries;
        if queries != 1 {
            return Err(format!(
                "{label}: attempt {attempt} spent {queries} queries, not one"
            ));
        }
        let retry =
            matches!(verdict, WitnessVerdict::Failed(WitnessFailure::Unavailable)) && attempt < 3;
        if retry {
            eprintln!("COPYUP_OLD_FILE {label} attempt {attempt}: transient unavailable, retrying");
            continue;
        }
        return Ok((verdict, diagnosis, total, attempt));
    }
    unreachable!("copyup old-file {label}: retry loop returns on attempt 3");
}

/// Old-file positive twin (privileged): the stale range proves same-file
/// against the lower file opened through the mount-table read-back. The
/// kernel primitive positively identifies the old file — the witness an
/// old-vs-fresh attribution needs exists.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness against the lower file"]
fn privileged_copyup_lower_anchor_proves_stale_mapping() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        copyup_lower_row(work.path(), mode, lane, true)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "COPYUP_OLD_FILE direction=stale-lower lane={lane:?} modes=on,off,same-fs verdict=same-file"
    );
}

/// Old-file negative twin (privileged): the fresh range proves
/// another-file against the lower file — the lower anchor refuses
/// exactly the mapper it must refuse.
#[test]
#[ignore = "root: loop overlay mounts drive the production original-file witness against the lower file"]
fn privileged_copyup_lower_anchor_refuses_fresh_mapping() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        copyup_lower_row(work.path(), mode, lane, false)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "COPYUP_OLD_FILE direction=fresh-upper lane={lane:?} modes=on,off,same-fs verdict=other-file"
    );
}

/// One old-file row over a fresh fixture: discover the lower file from
/// the live mount table, prove the chosen side's range against it, and
/// require the verdict the side needs. Where the kernel proof cannot run
/// at all the row asserts the exact unavailable shape instead — still a
/// refusal, never silence.
fn copyup_lower_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    stale_side: bool,
) -> Result<(), String> {
    use crate::discovery::overlay_witness::{WitnessFailure, WitnessVerdict};
    let side = if stale_side {
        "stale-lower"
    } else {
        "fresh-upper"
    };
    eprintln!("COPYUP_OLD_FILE start mode={mode:?} row={side} lane={lane:?}");
    let setup = copyup_old_file_setup(work, mode, lane)?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("copyup old-file mountinfo: {error}"))?;
    let candidates = lower_candidates_from_mountinfo(&mountinfo, &setup.merged);
    let candidate = candidates.first().ok_or_else(|| {
        "copyup old-file: mount table names no lowerdir for the merge".to_string()
    })?;
    let lower_file = std::fs::File::open(candidate).map_err(|error| {
        format!(
            "copyup old-file lower open {}: {error}",
            candidate.display()
        )
    })?;
    {
        use std::os::unix::fs::MetadataExt as _;
        let got = lower_file
            .metadata()
            .map_err(|error| format!("copyup old-file candidate fstat: {error}"))?;
        let want = std::fs::metadata(setup.fixture.lower_path("lib.so"))
            .map_err(|error| format!("copyup old-file lower fstat: {error}"))?;
        if (got.dev(), got.ino()) != (want.dev(), want.ino()) {
            return Err(format!(
                "copyup old-file premise broken: {} is not the lower file (candidate {:?} vs lower {:?})",
                candidate.display(),
                (got.dev(), got.ino()),
                (want.dev(), want.ino())
            ));
        }
    }
    let lower_held = crate::discovery::identity::self_mapped_file(&lower_file)
        .map_err(|error| format!("copyup old-file lower identity: {error}"))?;
    let child = if stale_side {
        &setup.stale
    } else {
        &setup.fresh
    };
    let pid = child.pid as u32;
    let range = target_range(child);
    let key = ObjectKey::of(&find_line(&child.maps(), range, *b"r-xp")?);
    if !k1_witness_capable() {
        let (verdict, diagnosis, queries) =
            copyup_old_file_prove(pid, &lower_file, &lower_held, key, &[range])?;
        match verdict {
            WitnessVerdict::Failed(WitnessFailure::Unavailable) => {
                eprintln!(
                    "COPYUP_OLD_FILE mode={mode:?} row={side} lane={lane:?} verdict=unavailable queries={queries} diagnosis={diagnosis:?}"
                );
                return Ok(());
            }
            other => {
                return Err(format!(
                    "copyup old-file {side}: expected unavailable without kernel proof, got {other:?}"
                ));
            }
        }
    }
    let (verdict, diagnosis, queries, attempts) =
        copyup_old_file_prove_retry(side, pid, &lower_file, &lower_held, key, &[range])?;
    let want = if stale_side {
        WitnessVerdict::SameFile
    } else {
        WitnessVerdict::OtherFile
    };
    if verdict != want {
        return Err(format!(
            "copyup old-file {side}: expected {want:?}, got {verdict:?} diagnosis={diagnosis:?} queries={queries} attempts={attempts}"
        ));
    }
    eprintln!(
        "COPYUP_OLD_FILE mode={mode:?} row={side} lane={lane:?} verdict={verdict:?} queries={queries} attempts={attempts}"
    );
    Ok(())
}

#[test]
fn lower_candidates_single_layer_joins_the_remainder() {
    let table = "31 23 0:27 / /var/tmp/x/merged1 rw,relatime - overlay overlay rw,lowerdir=/var/tmp/x/lower,upperdir=/var/tmp/x/upper1,workdir=/var/tmp/x/work1\n";
    let got =
        lower_candidates_from_mountinfo(table, std::path::Path::new("/var/tmp/x/merged1/lib.so"));
    assert_eq!(
        got,
        vec![std::path::PathBuf::from("/var/tmp/x/lower/lib.so")]
    );
}

#[test]
fn lower_candidates_stack_keeps_kernel_order() {
    let table = "31 23 0:27 / /mnt/r rw,relatime - overlay overlay rw,lowerdir=/l1:/l2:/l3,upperdir=/u,workdir=/w\n";
    let got = lower_candidates_from_mountinfo(table, std::path::Path::new("/mnt/r/a/b.so"));
    assert_eq!(
        got,
        vec![
            std::path::PathBuf::from("/l1/a/b.so"),
            std::path::PathBuf::from("/l2/a/b.so"),
            std::path::PathBuf::from("/l3/a/b.so"),
        ]
    );
}

#[test]
fn lower_candidates_longest_overlay_prefix_wins() {
    let table = concat!(
        "20 1 0:17 / / rw,relatime - overlay overlay rw,lowerdir=/base/rootfs,upperdir=/base/upper,workdir=/base/work\n",
        "31 23 0:27 / /var/tmp/x/merged1 rw,relatime - overlay overlay rw,lowerdir=/var/tmp/x/lower,upperdir=/var/tmp/x/upper1,workdir=/var/tmp/x/work1\n",
    );
    let got =
        lower_candidates_from_mountinfo(table, std::path::Path::new("/var/tmp/x/merged1/lib.so"));
    assert_eq!(
        got,
        vec![std::path::PathBuf::from("/var/tmp/x/lower/lib.so")]
    );
}

#[test]
fn lower_candidates_root_mount_serves_container_paths() {
    // D1-extended live failure: every container root is mountpoint "/",
    // where the prefix consumes the only separator. The remainder is
    // already relative; only the root falls through (a mid-path prefix
    // like /var/tmp/x against /var/tmp/xbin still refuses).
    let table = "9433 9341 0:104 / / rw,relatime - overlay overlay rw,lowerdir=/snap/1/fs:/snap/2/fs,upperdir=/snap/3/fs,workdir=/snap/3/work,nouserxattr\\n";
    let got = lower_candidates_from_mountinfo(
        table,
        std::path::Path::new("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
    );
    assert_eq!(
        got,
        vec![
            std::path::PathBuf::from("/snap/1/fs/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
            std::path::PathBuf::from("/snap/2/fs/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        ]
    );
    let sibling = "31 23 0:27 / /var/tmp/x rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\\n";
    assert!(
        lower_candidates_from_mountinfo(sibling, std::path::Path::new("/var/tmp/xbin/lib.so"))
            .is_empty()
    );
}

#[test]
fn lower_candidates_skips_non_overlay_and_prefix_siblings() {
    let table = concat!(
        "10 1 8:1 / /var/tmp/x rw,relatime - ext4 /dev/sda3 rw\n",
        "31 23 0:27 / /var/tmp/x/merged1 rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n",
    );
    assert!(
        lower_candidates_from_mountinfo(table, std::path::Path::new("/var/tmp/x/plain.so"))
            .is_empty()
    );
    assert!(
        lower_candidates_from_mountinfo(table, std::path::Path::new("/var/tmp/x/merged10/lib.so"))
            .is_empty()
    );
}

#[test]
fn lower_candidates_decodes_mountinfo_escapes() {
    let table = "31 23 0:27 / /var/tmp/my\\040x/merged1 rw,relatime - overlay overlay rw,lowerdir=/var/tmp/my\\040x/lower,upperdir=/u,workdir=/w\n";
    let got = lower_candidates_from_mountinfo(
        table,
        std::path::Path::new("/var/tmp/my x/merged1/lib.so"),
    );
    assert_eq!(
        got,
        vec![std::path::PathBuf::from("/var/tmp/my x/lower/lib.so")]
    );
}

#[test]
fn lower_candidates_refuses_escapes_and_missing_lowerdir() {
    let table =
        "31 23 0:27 / /mnt/r rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n";
    assert!(
        lower_candidates_from_mountinfo(table, std::path::Path::new("/mnt/r/../evil.so"))
            .is_empty()
    );
    let no_lower = "31 23 0:27 / /mnt/r rw,relatime - overlay overlay rw,upperdir=/u,workdir=/w\n";
    assert!(
        lower_candidates_from_mountinfo(no_lower, std::path::Path::new("/mnt/r/a.so")).is_empty()
    );
    assert!(lower_candidates_from_mountinfo("", std::path::Path::new("/mnt/r/a.so")).is_empty());
}

/// What the copy-up join mirror concluded over live inputs: the guard
/// refused before any witness work (the legacy shape), the join proved
/// (held or proven lower), or the join refused with the gap reason.
enum CopyUpProductionOutcome {
    LegacyRefused(String),
    Joined(crate::discovery::scan::CopyUpJoin),
    Refused(String),
}

/// Mirror the production provider branch over live inputs: open the
/// held file, group the target's live maps like production, and run the
/// real guard plus the copy-up join step. Returns the outcome and the
/// global witness-query delta across the call.
fn copyup_production_join(
    pid: u32,
    merged: &std::path::Path,
    key: ObjectKey,
    maps: &[MapEntry],
    budget: &mut crate::discovery::scan::CaptureWorkBudget,
    io: &mut crate::discovery::scan::ProcScanIo,
) -> Result<(CopyUpProductionOutcome, u64), String> {
    use crate::discovery::overlay_witness::witness_stats_for_test;
    use crate::discovery::scan::{
        GuardOutcome, ScanIo, candidate_groups, mapped_file_guard, witness_join_with_copyup,
    };
    use crate::process::{ProcessView, ProcessViewId};
    let view = ProcessView::open(ProcessViewId(pid), pid)
        .map_err(|error| format!("copyup join production view {pid}: {error}"))?;
    let file = std::fs::File::open(merged).map_err(|error| {
        format!(
            "copyup join production held open {}: {error}",
            merged.display()
        )
    })?;
    let held = budget
        .retained_mapped_identity(&file)
        .or_else(|| io.held_identity(&file));
    let groups = candidate_groups(maps);
    let group = groups
        .get(&key)
        .ok_or_else(|| format!("copyup join production: key {key:?} has no candidate group"))?;
    let (before, _) = witness_stats_for_test();
    let guarded = mapped_file_guard(io, &view, held, key, group, budget);
    let outcome = match guarded {
        Err(reason) => CopyUpProductionOutcome::LegacyRefused(reason),
        Ok(GuardOutcome::Proven) => {
            return Err(
                "copyup join production: the stale shape proved without the witness".into(),
            );
        }
        Ok(GuardOutcome::UnprovenOverlay { range }) => match held {
            Some(held) => {
                match witness_join_with_copyup(io, &view, &file, &held, key, range, merged, budget)
                {
                    Ok(join) => CopyUpProductionOutcome::Joined(join),
                    Err(reason) => CopyUpProductionOutcome::Refused(reason),
                }
            }
            None => return Err("copyup join production: unproven join without a held file".into()),
        },
    };
    let (after, _) = witness_stats_for_test();
    Ok((outcome, after.saturating_sub(before)))
}

/// Retry the copy-up join mirror across transient
/// witness-infrastructure loss, mirroring the K1 guard retry: each
/// attempt carries a fresh scan budget and re-reads the child's maps;
/// only the unavailable gap retries, at most three attempts. Returns
/// the settled outcome, the spend of the settling attempt, and the
/// attempts used.
fn copyup_production_join_retry(
    label: &str,
    pid: u32,
    merged: &std::path::Path,
    key: ObjectKey,
    maps: &dyn Fn() -> Vec<MapEntry>,
) -> Result<(CopyUpProductionOutcome, u64, u32), String> {
    use crate::discovery::overlay_witness::witness_unavailable_refusal;
    for attempt in 1..=3u32 {
        let live = maps();
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let mut io = crate::discovery::scan::ProcScanIo::new();
        let (outcome, queries) =
            copyup_production_join(pid, merged, key, &live, &mut budget, &mut io)?;
        if io.witness_used() as u64 != queries || queries > 2 {
            return Err(format!(
                "{label}: attempt {attempt} spent {} queries and ran {queries}, not one held plus one lower",
                io.witness_used()
            ));
        }
        let retry = matches!(&outcome, CopyUpProductionOutcome::Refused(reason) if witness_unavailable_refusal(reason))
            && attempt < 3;
        if retry {
            eprintln!("COPYUP_JOIN {label} attempt {attempt}: transient unavailable, retrying");
            continue;
        }
        return Ok((outcome, queries, attempt));
    }
    unreachable!("copyup join {label}: retry loop returns on attempt 3");
}

/// Copy-up join acceptance (privileged): the stale mapper's ranges
/// attribute after the copy-up through the production provider branch.
/// On the witness-requiring shape the join proves the pre-copy-up lower
/// file (exactly two queries: held plus lower); where the stale mapping
/// already separates, the legacy refusal stands with no witness spent;
/// where the kernel proof cannot run at all, the row asserts the exact
/// unavailable gap instead — still a refusal, never silence.
#[test]
#[ignore = "root: loop overlay mounts drive the production copy-up join"]
fn privileged_copyup_stale_mapper_joins_proven_lower_file() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        copyup_join_row(work.path(), mode, lane, "", "stale-lower")
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "COPYUP_JOIN direction=stale-lower lane={lane:?} modes=on,off,same-fs verdict=join-lower"
    );
}

/// One copy-up join row over a fresh fixture.
fn copyup_join_row(
    work: &std::path::Path,
    mode: XinoMode,
    lane: OverlayLane,
    extra: &str,
    row: &str,
) -> Result<(), String> {
    use crate::discovery::overlay_witness::witness_unavailable_refusal;
    use crate::discovery::scan::CopyUpJoin;
    eprintln!("COPYUP_JOIN start mode={mode:?} row={row} lane={lane:?}");
    let setup = copyup_old_file_setup_with(work, mode, lane, extra)?;
    let stale_maps = setup.stale.maps();
    let key = ObjectKey::of(&find_line(
        &stale_maps,
        target_range(&setup.stale),
        *b"r-xp",
    )?);
    let pid = setup.stale.pid as u32;
    if !k1_witness_capable() {
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let mut io = crate::discovery::scan::ProcScanIo::new();
        let (outcome, queries) =
            copyup_production_join(pid, &setup.merged, key, &stale_maps, &mut budget, &mut io)?;
        match outcome {
            CopyUpProductionOutcome::LegacyRefused(reason)
                if reason.contains("names more than one file") =>
            {
                eprintln!(
                    "COPYUP_JOIN mode={mode:?} row={row} lane={lane:?} verdict=legacy queries={queries}"
                );
                return Ok(());
            }
            CopyUpProductionOutcome::Refused(reason) if witness_unavailable_refusal(&reason) => {
                eprintln!(
                    "COPYUP_JOIN mode={mode:?} row={row} lane={lane:?} verdict=unavailable queries={queries}"
                );
                return Ok(());
            }
            other => {
                return Err(format!(
                    "copyup join: expected the legacy or unavailable refusal without kernel proof, got {}",
                    match other {
                        CopyUpProductionOutcome::LegacyRefused(reason)
                        | CopyUpProductionOutcome::Refused(reason) => reason,
                        CopyUpProductionOutcome::Joined(_) => "a join".to_string(),
                    }
                ));
            }
        }
    }
    let (outcome, queries, attempts) =
        copyup_production_join_retry("copyup join", pid, &setup.merged, key, &|| {
            setup.stale.maps()
        })?;
    match outcome {
        CopyUpProductionOutcome::LegacyRefused(reason)
            if reason.contains("names more than one file") =>
        {
            if queries != 0 {
                return Err(format!(
                    "copyup join legacy shape spent witness work: {queries} queries"
                ));
            }
            eprintln!(
                "COPYUP_JOIN mode={mode:?} row={row} lane={lane:?} verdict=legacy queries={queries} attempts={attempts}"
            );
            Ok(())
        }
        CopyUpProductionOutcome::Joined(CopyUpJoin::LowerProven(proof)) => {
            if queries != 2 {
                return Err(format!(
                    "copyup join proved the lower file with {queries} queries, not one held plus one lower"
                ));
            }
            {
                use std::os::unix::fs::MetadataExt as _;
                let lower = std::fs::File::open(setup.fixture.lower_path("lib.so"))
                    .map_err(|error| format!("copyup join lower open: {error}"))?;
                let metadata = lower
                    .metadata()
                    .map_err(|error| format!("copyup join lower fstat: {error}"))?;
                if (metadata.dev(), metadata.ino())
                    != (proof.mapped.identity.dev, proof.mapped.identity.ino)
                {
                    return Err(format!(
                        "copyup join proof names the wrong file: proof {:?} vs lower {:?}",
                        (proof.mapped.identity.dev, proof.mapped.identity.ino),
                        (metadata.dev(), metadata.ino())
                    ));
                }
                if proof.candidate != 0 {
                    return Err(format!(
                        "copyup join proof selects candidate {}, not the first lower layer",
                        proof.candidate
                    ));
                }
            }
            eprintln!(
                "COPYUP_JOIN mode={mode:?} row={row} lane={lane:?} verdict=join-lower queries={queries} attempts={attempts}"
            );
            Ok(())
        }
        CopyUpProductionOutcome::Joined(CopyUpJoin::Held) => Err(
            "copyup join: the stale mapper joined the held upper file instead of the proven lower file"
                .into(),
        ),
        CopyUpProductionOutcome::Refused(reason) => Err(format!(
            "copyup join: the stale mapper is unattributed after copy-up (queries={queries}): {reason}"
        )),
        CopyUpProductionOutcome::LegacyRefused(reason) => Err(format!(
            "copyup join legacy shape refused without the legacy reason: {reason}"
        )),
    }
}

/// Copy-up join under `metacopy=on` (privileged): the same stale-lower
/// flow over layers mounted with metadata-only copy-up. The data write
/// still copies the file data up; the stale mapper must join the
/// proven lower file with exactly two queries, like the base row.
#[test]
#[ignore = "root: loop overlay mounts with metacopy drive the production copy-up join"]
fn privileged_copyup_metacopy_stale_mapper_joins_lower() {
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        copyup_join_row(
            work.path(),
            mode,
            lane,
            ",metacopy=on",
            "stale-lower-metacopy",
        )
        .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
    }
    eprintln!(
        "COPYUP_JOIN direction=stale-lower-metacopy lane={lane:?} modes=on,off,same-fs verdict=join-lower"
    );
}

/// A two-layer lower stack with the provider only in the second layer:
/// one loop ext4 carries both lowerdirs plus upper/work, and the
/// merged mount stacks them `low0:low1`.
struct MultiLowerFixture {
    merged: MergedMount,
    _fs: Ext4Loop,
    low0: std::path::PathBuf,
    low1: std::path::PathBuf,
    upper: std::path::PathBuf,
}

impl MultiLowerFixture {
    fn mount(root: &std::path::Path, mode: XinoMode) -> Result<Self, String> {
        let fs = Ext4Loop::new();
        let low0 = fs.mount.join("low0");
        let low1 = fs.mount.join("low1");
        let upperdir = fs.mount.join("upper1");
        let workdir = fs.mount.join("work1");
        let mountpoint = root.join("merged1");
        for dir in [&low0, &low1, &upperdir, &workdir, &mountpoint] {
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("overlay mkdir {}: {error}", dir.display()))?;
        }
        let xino = match mode {
            XinoMode::On => ",xino=on",
            XinoMode::Off => ",xino=off",
            XinoMode::SameFs => "",
        };
        let opts = format!(
            "lowerdir={}:{},upperdir={},workdir={}{xino}",
            low0.display(),
            low1.display(),
            upperdir.display(),
            workdir.display(),
        );
        mount_overlay(&opts, &mountpoint)?;
        Ok(Self {
            merged: MergedMount { mountpoint },
            _fs: fs,
            low0,
            low1,
            upper: upperdir,
        })
    }
}

/// Copy-up join across a multi-lower stack (privileged): the provider
/// lives only in the second lower layer, so the production fallback
/// must walk past the missing first candidate and prove index 1. The
/// proof names the second layer's file, never the first.
#[test]
#[ignore = "root: loop overlay mounts with two lower layers drive the production copy-up join"]
fn privileged_copyup_second_lower_candidate_wins() {
    use crate::discovery::scan::CopyUpJoin;
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        eprintln!("COPYUP_JOIN start mode={mode:?} row=second-lower lane={lane:?}");
        let fixture = MultiLowerFixture::mount(work.path(), mode)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        std::fs::write(fixture.low1.join("lib.so"), vec![0xE4u8; 8192])
            .unwrap_or_else(|error| panic!("mode {mode:?}: lower write: {error}"));
        assert!(
            !fixture.low0.join("lib.so").exists(),
            "mode {mode:?}: the first layer must not carry the provider"
        );
        let merged = fixture.merged.mountpoint.join("lib.so");
        let stale = SwapChild::spawn(&merged);
        trigger_copy_up(
            &merged,
            &fixture.upper.join("lib.so"),
            &fixture.low1.join("lib.so"),
        )
        .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        let stale_maps = stale.maps();
        let key = ObjectKey::of(
            &find_line(&stale_maps, target_range(&stale), *b"r-xp")
                .unwrap_or_else(|error| panic!("mode {mode:?}: {error}")),
        );
        let (outcome, queries, attempts) = copyup_production_join_retry(
            "copyup second lower",
            stale.pid as u32,
            &merged,
            key,
            &|| stale.maps(),
        )
        .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        match outcome {
            CopyUpProductionOutcome::Joined(CopyUpJoin::LowerProven(proof)) => {
                use std::os::unix::fs::MetadataExt as _;
                let metadata = std::fs::metadata(fixture.low1.join("lib.so"))
                    .unwrap_or_else(|error| panic!("mode {mode:?}: lower fstat: {error}"));
                assert_eq!(
                    (proof.mapped.identity.dev, proof.mapped.identity.ino),
                    (metadata.dev(), metadata.ino()),
                    "mode {mode:?}: the proof must name the second layer's file"
                );
                assert_eq!(
                    proof.candidate, 1,
                    "mode {mode:?}: the proof must select candidate 1"
                );
                // Held plus the missing first candidate (skipped without
                // a query) plus the proven second: two queries.
                assert_eq!(
                    queries, 2,
                    "mode {mode:?}: expected one held plus one lower query, spent {queries}"
                );
                eprintln!(
                    "COPYUP_JOIN mode={mode:?} row=second-lower lane={lane:?} verdict=join-lower queries={queries} attempts={attempts}"
                );
            }
            other => panic!(
                "mode {mode:?}: the stale mapper did not join the second lower file: {}",
                match other {
                    CopyUpProductionOutcome::LegacyRefused(reason)
                    | CopyUpProductionOutcome::Refused(reason) => reason,
                    CopyUpProductionOutcome::Joined(_) => "a held join".to_string(),
                }
            ),
        }
    }
    eprintln!(
        "COPYUP_JOIN direction=second-lower lane={lane:?} modes=on,off,same-fs verdict=join-lower"
    );
}

/// In-place upper rewrite after copy-up (privileged): the upper file is
/// rewritten through the upperdir (same inode, new bytes) while the
/// Lower candidates open in the observer's mount namespace (privileged):
/// a container's lowerdir paths are host paths, invisible under the
/// target's `/proc/<pid>/root`. The covered leaf proves the split: its
/// own root lacks the host file, yet the candidate open still succeeds
/// and serves the host file's bytes.
#[test]
#[ignore = "root: mount namespace with a tmpfs cover drives the candidate open"]
fn privileged_copyup_candidate_opens_in_observer_namespace() {
    use crate::discovery::scan::{CaptureWorkBudget, ProcScanIo, ScanIo};
    use crate::process::{ProcessView, ProcessViewId};
    let work = tempfile::tempdir().unwrap();
    let host_file = work.path().join("lower.so");
    std::fs::write(&host_file, vec![0xE4u8; 8192]).unwrap();
    let side = tempfile::tempdir().unwrap();
    let pidfile = side.path().join("leaf.pid");
    // The leaf privatizes its namespace copy (so the cover never
    // propagates to the host), covers the work dir, reports its pid,
    // and sleeps. A failed mount aborts the chain before the cover.
    let leaf = std::process::Command::new("unshare")
        .args([
            "-m",
            "sh",
            "-c",
            &format!(
                "mount --make-rprivate / && mount -t tmpfs tmpfs '{}' && echo $$ > '{}' && exec sleep 600",
                work.path().display(),
                pidfile.display()
            ),
        ])
        .spawn()
        .expect("unshare -m runs the covered leaf");
    let leaf_pid: u32 = {
        let mut pid = None;
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(&pidfile)
                && let Ok(number) = text.trim().parse::<u32>()
            {
                pid = Some(number);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        pid.expect("the covered leaf reports its pid")
    };
    struct Reap(u32, std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0 as i32, libc::SIGKILL);
            }
            let _ = self.1.wait();
        }
    }
    let _reap = Reap(leaf_pid, leaf);
    // The split is real: the target's own root no longer shows the file.
    let target_path = format!("/proc/{leaf_pid}/root{}", host_file.display());
    assert!(
        std::fs::File::open(&target_path).is_err(),
        "the tmpfs cover must hide the host file from the target, opened {target_path}"
    );
    let view = ProcessView::open(ProcessViewId(leaf_pid), leaf_pid).expect("the leaf view opens");
    let mut budget = CaptureWorkBudget::default();
    let mut io = ProcScanIo::new();
    let mut file = io
        .open_lower_candidate(&view, &host_file, &mut budget)
        .unwrap_or_else(|error| {
            panic!("the candidate must open in the observer namespace: {error}")
        });
    let mut bytes = [0u8; 8192];
    use std::io::Read as _;
    file.read_exact(&mut bytes).unwrap();
    assert!(
        bytes.iter().all(|byte| *byte == 0xE4),
        "the open must serve the host file's bytes"
    );
}

/// stale mapper still runs the lower file. The stale ranges must still
/// join the proven lower file — upper churn must never capture stale
/// attribution — and a mapper started after the rewrite tracks the
/// live upper file through the K1 held path with one query.
#[test]
#[ignore = "root: loop overlay mounts with an in-place upper rewrite drive the production copy-up join"]
fn privileged_copyup_upper_rewrite_keeps_stale_on_lower() {
    use crate::discovery::scan::CopyUpJoin;
    overlay_preflight().expect("overlay preconditions hold");
    let lane = OverlayLane::detect().expect("overlay lane detects");
    for mode in [XinoMode::On, XinoMode::Off, XinoMode::SameFs] {
        let work = tempfile::tempdir().unwrap();
        eprintln!("COPYUP_JOIN start mode={mode:?} row=upper-rewrite lane={lane:?}");
        let setup = copyup_old_file_setup(work.path(), mode, lane)
            .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        // Rewrite the upper file in place: same inode, different bytes.
        {
            use std::io::Write as _;
            use std::os::unix::fs::MetadataExt as _;
            let upper = setup.fixture.upper_path("lib.so");
            let before = std::fs::metadata(&upper)
                .unwrap_or_else(|error| panic!("mode {mode:?}: upper stat: {error}"));
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&upper)
                .unwrap_or_else(|error| panic!("mode {mode:?}: upper open: {error}"));
            writer
                .write_all(&[0x1Fu8; 8192])
                .unwrap_or_else(|error| panic!("mode {mode:?}: upper write: {error}"));
            drop(writer);
            let after = std::fs::metadata(&upper)
                .unwrap_or_else(|error| panic!("mode {mode:?}: upper restat: {error}"));
            assert_eq!(
                (before.dev(), before.ino()),
                (after.dev(), after.ino()),
                "mode {mode:?}: the rewrite must keep the upper inode"
            );
            let lower = std::fs::read(setup.fixture.lower_path("lib.so"))
                .unwrap_or_else(|error| panic!("mode {mode:?}: lower read: {error}"));
            assert!(
                lower.iter().all(|byte| *byte == 0xE4u8),
                "mode {mode:?}: the rewrite must not touch the lower file"
            );
        }
        // The stale mapper still joins the proven lower file.
        let stale_maps = setup.stale.maps();
        let key = ObjectKey::of(
            &find_line(&stale_maps, target_range(&setup.stale), *b"r-xp")
                .unwrap_or_else(|error| panic!("mode {mode:?}: {error}")),
        );
        let (outcome, queries, attempts) = copyup_production_join_retry(
            "copyup upper rewrite",
            setup.stale.pid as u32,
            &setup.merged,
            key,
            &|| setup.stale.maps(),
        )
        .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        match outcome {
            CopyUpProductionOutcome::Joined(CopyUpJoin::LowerProven(proof)) => {
                use std::os::unix::fs::MetadataExt as _;
                let metadata = std::fs::metadata(setup.fixture.lower_path("lib.so"))
                    .unwrap_or_else(|error| panic!("mode {mode:?}: lower fstat: {error}"));
                assert_eq!(
                    (proof.mapped.identity.dev, proof.mapped.identity.ino),
                    (metadata.dev(), metadata.ino()),
                    "mode {mode:?}: the proof must still name the lower file"
                );
                assert_eq!(proof.candidate, 0, "mode {mode:?}: candidate 0");
                assert_eq!(
                    queries, 2,
                    "mode {mode:?}: expected one held plus one lower query, spent {queries}"
                );
                eprintln!(
                    "COPYUP_JOIN mode={mode:?} row=upper-rewrite lane={lane:?} verdict=join-lower queries={queries} attempts={attempts}"
                );
            }
            other => panic!(
                "mode {mode:?}: the stale mapper left the lower file after the upper rewrite: {}",
                match other {
                    CopyUpProductionOutcome::LegacyRefused(reason)
                    | CopyUpProductionOutcome::Refused(reason) => reason,
                    CopyUpProductionOutcome::Joined(_) => "a held join".to_string(),
                }
            ),
        }
        // A mapper started after the rewrite tracks the live file: its
        // ranges join the held (rewritten) upper through the K1 witness
        // path with exactly one query, never the lower fallback.
        let fresh = SwapChild::spawn(&setup.merged);
        let fresh_maps = fresh.maps();
        let fresh_key = ObjectKey::of(
            &find_line(&fresh_maps, target_range(&fresh), *b"r-xp")
                .unwrap_or_else(|error| panic!("mode {mode:?}: {error}")),
        );
        let (fresh_outcome, fresh_queries, fresh_attempts) = copyup_production_join_retry(
            "copyup upper rewrite fresh",
            fresh.pid as u32,
            &setup.merged,
            fresh_key,
            &|| fresh.maps(),
        )
        .unwrap_or_else(|error| panic!("mode {mode:?}: {error}"));
        match fresh_outcome {
            CopyUpProductionOutcome::Joined(CopyUpJoin::Held) => {}
            other => panic!(
                "mode {mode:?}: the post-rewrite mapper did not join the held upper: {}",
                match other {
                    CopyUpProductionOutcome::LegacyRefused(reason)
                    | CopyUpProductionOutcome::Refused(reason) => reason,
                    CopyUpProductionOutcome::Joined(_) => "a lower join".to_string(),
                }
            ),
        }
        assert_eq!(
            fresh_queries, 1,
            "mode {mode:?}: the fresh mapper must spend one held query, spent {fresh_queries}"
        );
        eprintln!(
            "COPYUP_JOIN mode={mode:?} row=upper-rewrite lane={lane:?} verdict=fresh-held queries={fresh_queries} attempts={fresh_attempts}"
        );
    }
    eprintln!(
        "COPYUP_JOIN direction=upper-rewrite lane={lane:?} modes=on,off,same-fs verdict=join-lower"
    );
}

/// Pre-arm witness calibration over xino overlay files: the BPF slot
/// carries the backing inode while the mapped-range identity carries
/// the overlay (xino) inode. Calibration must accept the lower-layer
/// file (backing vs backing through the lower candidates) as well as
/// the upper and copied-up files (direct equality). Each row starts
/// its own witness so one refusal cannot mask the other rows; all
/// three verdicts print before the assertion. Fails loud without
/// root/loop/overlay/BTF/ftrace — never a skip.
#[test]
#[ignore = "root: loop overlay mounts (xino=on) plus a live witness start (BTF, ftrace_enabled=1)"]
fn privileged_witness_calibration_accepts_xino_overlay_files() {
    overlay_preflight().expect("overlay preconditions hold");
    let ftrace = std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled")
        .expect("witness needs readable ftrace_enabled");
    assert_eq!(
        ftrace.trim(),
        "1",
        "witness needs /proc/sys/kernel/ftrace_enabled = 1"
    );
    assert!(
        matches!(
            crate::pidns::observer(),
            crate::pidns::ObserverPidNs::Initial
        ),
        "witness needs the initial PID namespace"
    );
    let work = tempfile::tempdir().unwrap();
    let fixture = OverlayFixture::mount(work.path(), XinoMode::On).expect("overlay mount xino=on");
    // Lower-only file: the xino split (small backing ino, huge overlay ino).
    std::fs::write(fixture.lower_path("lower.so"), vec![0xB3u8; 8192]).unwrap();
    let (effective, auto) = fixture.xino_verdict("lower.so").expect("xino on effective");
    assert!(
        effective,
        "xino=on must render the merge device (xino_auto={auto})"
    );
    // Upper file: written through the merge, lives in upperdir.
    std::fs::write(fixture.merged_path("upper.so"), vec![0xB4u8; 8192]).unwrap();
    assert!(
        fixture.upper_path("upper.so").exists(),
        "the upper file must materialize in upperdir"
    );
    // Copied-up file: lower content, then a merged write copies it up.
    std::fs::write(fixture.lower_path("cup.so"), vec![0xB5u8; 8192]).unwrap();
    trigger_copy_up(
        &fixture.merged_path("cup.so"),
        &fixture.upper_path("cup.so"),
        &fixture.lower_path("cup.so"),
    )
    .expect("copy-up");
    use std::os::unix::fs::MetadataExt as _;
    let rows = [
        ("lower", fixture.merged_path("lower.so")),
        ("upper", fixture.merged_path("upper.so")),
        ("cup", fixture.merged_path("cup.so")),
    ];
    for (tag, path) in &rows {
        let meta = std::fs::metadata(path).expect("merged stat");
        eprintln!(
            "WITNESS_XINO {tag} merged dev={} ino={}",
            meta.dev(),
            meta.ino()
        );
    }
    let backing = std::fs::metadata(fixture.lower_path("lower.so")).expect("lower direct stat");
    eprintln!(
        "WITNESS_XINO lower backing dev={} ino={}",
        backing.dev(),
        backing.ino()
    );
    let scope = crate::attach::Scope::System;
    let mut refused = Vec::new();
    for (tag, path) in &rows {
        match crate::attach::prearm_witness::start(std::slice::from_ref(path), &scope, true) {
            Ok(witness) => {
                assert_eq!(witness.files.len(), 1, "{tag}: one calibrated file");
                eprintln!(
                    "WITNESS_XINO {tag} calibrated key=({},{})",
                    witness.files[0].key.s_dev, witness.files[0].key.i_ino
                );
            }
            Err(reason) => {
                eprintln!("WITNESS_XINO {tag} REFUSED: {reason:?}");
                refused.push(*tag);
            }
        }
    }
    assert!(
        refused.is_empty(),
        "the witness refused overlay rows: {refused:?}"
    );
    eprintln!("WITNESS_XINO modes=on rows=lower,upper,cup verdict=calibrated");
}
