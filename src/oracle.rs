use crate::attach::Scope;
use anyhow::{Context as _, Result, anyhow};
use p11scope_manifest::identity::{
    ElfLoader, MappingFileKey, inspect_elf_loader, mapping_file_key, open_object,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path};

const GLIBC_INTERP: &str = "/lib64/ld-linux-x86-64.so.2";
const GLIBC_LOADER: &str = "ld-linux-x86-64.so.2";
const GLIBC_SEARCH_DIRECTORIES: [&str; 2] = ["/usr/lib/x86_64-linux-gnu", "/usr/lib64"];
const GLIBC_STAGING_DIRECTORY: &str = "/run/p11scope";
const MAX_SYMLINK_HOPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OracleMode {
    TrustedWorkload,
    Hardened,
}

pub(crate) struct OracleSelection {
    pub(crate) mode: OracleMode,
}

struct HardenedFacts<'a> {
    observer_loader: ElfLoader,
    observer_owner: u32,
    observer_mode: u32,
    observer_status: &'a str,
    target_status: &'a str,
    observer_uid_map: &'a str,
    observer_user_namespace: (u64, u64),
    init_user_namespace: (u64, u64),
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessStatus {
    uids: [u32; 4],
    capabilities: u64,
}

fn trusted_required(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "{reason}; pass --trusted-workload only when the observed workload is explicitly trusted"
    )
}

fn select_from_facts(
    scope: &Scope,
    trusted_workload: bool,
    facts: Option<HardenedFacts<'_>>,
) -> Result<OracleMode> {
    let eligible = (|| -> Result<()> {
        if matches!(scope, Scope::Cgroup { .. }) {
            return Err(anyhow!(
                "hostile-workload oracle mode cannot prove the identity of future cgroup members"
            ));
        }
        let facts = facts.ok_or_else(|| anyhow!("hardened oracle facts are unavailable"))?;
        if facts.observer_loader.interpreter.is_some() || !facts.observer_loader.needed.is_empty() {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the fully static observer",
            ));
        }
        if facts.observer_owner != 0
            || facts.observer_mode & libc::S_IFMT != libc::S_IFREG
            || facts.observer_mode & 0o022 != 0
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires a root-owned non-group/world-writable observer",
            ));
        }
        let observer = parse_status(facts.observer_status)?;
        if observer.uids != [0; 4] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires all observer UIDs to be root",
            ));
        }
        let mut uid_map_lines = facts.observer_uid_map.lines();
        let uid_map = uid_map_lines
            .next()
            .ok_or_else(|| anyhow!("observer user namespace has no UID mapping"))?;
        let uid_map = uid_map
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
            .map_err(|_| anyhow!("observer user namespace has an invalid UID mapping"))?;
        if uid_map_lines.next().is_some() || uid_map != [0, 0, u64::from(u32::MAX)] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires one full initial-namespace UID mapping"
            ));
        }
        if facts.observer_user_namespace.1 == 0
            || facts.observer_user_namespace != facts.init_user_namespace
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the observer and PID 1 user namespaces to match"
            ));
        }
        let target = parse_status(facts.target_status)?;
        if target.uids.contains(&0) {
            return Err(anyhow!(
                "the observed process has a root UID and can share authority with the observer",
            ));
        }
        let dangerous = (1u64 << 5) | (1u64 << 7) | (1u64 << 19);
        if target.capabilities & dangerous != 0 {
            return Err(anyhow!(
                "the observed process has signal, set-UID, or ptrace capability over the observer",
            ));
        }
        Ok(())
    })();
    match eligible {
        Ok(()) => Ok(OracleMode::Hardened),
        Err(_) if trusted_workload => Ok(OracleMode::TrustedWorkload),
        Err(error) => Err(trusted_required(error)),
    }
}

pub(crate) fn select(scope: &Scope, trusted_workload: bool) -> Result<OracleSelection> {
    let Scope::Pid(pid) = scope else {
        return select_from_facts(scope, trusted_workload, None)
            .map(|mode| OracleSelection { mode });
    };
    let selected = (|| -> Result<OracleMode> {
        let observer = open_object(Path::new("/proc/self/exe")).map_err(|error| {
            trusted_required(format!("opening the running observer failed: {error}"))
        })?;
        let metadata = observer.metadata().map_err(|error| {
            trusted_required(format!(
                "reading the running observer metadata failed: {error}"
            ))
        })?;
        let observer_loader = inspect_elf_loader(&observer).map_err(|error| {
            trusted_required(format!("inspecting the running observer failed: {error}"))
        })?;
        let observer_status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
            trusted_required(format!(
                "reading the observer process status failed: {error}"
            ))
        })?;
        let target_status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|error| {
                trusted_required(format!(
                    "reading observed process {pid} status failed: {error}"
                ))
            })?;
        let observer_uid_map = std::fs::read_to_string("/proc/self/uid_map").map_err(|error| {
            trusted_required(format!("reading the observer UID map failed: {error}"))
        })?;
        let observer_user_namespace =
            namespace_id(Path::new("/proc/self/ns/user")).map_err(|error| {
                trusted_required(format!(
                    "opening the observer user namespace failed: {error}"
                ))
            })?;
        let init_user_namespace = namespace_id(Path::new("/proc/1/ns/user")).map_err(|error| {
            trusted_required(format!("opening the PID 1 user namespace failed: {error}"))
        })?;
        select_from_facts(
            scope,
            false,
            Some(HardenedFacts {
                observer_loader,
                observer_owner: metadata.uid(),
                observer_mode: metadata.mode(),
                observer_status: &observer_status,
                target_status: &target_status,
                observer_uid_map: &observer_uid_map,
                observer_user_namespace,
                init_user_namespace,
            }),
        )
    })();
    let mode = match selected {
        Err(_) if trusted_workload => Ok(OracleMode::TrustedWorkload),
        result => result,
    }?;
    Ok(OracleSelection { mode })
}

fn namespace_id(path: &Path) -> Result<(u64, u64)> {
    let metadata = std::fs::File::open(path)?.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn prepare_glibc_graph(
    helper: &ElfLoader,
    mut resolve: impl FnMut(&OsStr) -> Result<ElfLoader>,
) -> Result<BTreeMap<OsString, ElfLoader>> {
    if helper.interpreter.as_deref() != Some(Path::new(GLIBC_INTERP)) || helper.soname.is_some() {
        return Err(anyhow!(
            "hardened glibc helper must use the exact supported interpreter and have no SONAME"
        ));
    }
    let mut pending = VecDeque::from([OsString::from(GLIBC_LOADER)]);
    pending.extend(helper.needed.iter().cloned());
    let mut graph = BTreeMap::new();
    while let Some(name) = pending.pop_front() {
        validate_runtime_name(&name)?;
        if graph.contains_key(&name) {
            continue;
        }
        let facts = resolve(&name)?;
        if facts
            .interpreter
            .as_deref()
            .is_some_and(|interpreter| interpreter != Path::new(GLIBC_INTERP))
            || facts.soname.as_deref() != Some(name.as_os_str())
        {
            return Err(anyhow!(
                "runtime object {name:?} has an unexpected interpreter or SONAME"
            ));
        }
        if name == OsStr::new(GLIBC_LOADER)
            && (facts.interpreter.is_some() || !facts.needed.is_empty())
        {
            return Err(anyhow!(
                "the glibc interpreter has an unexpected interpreter or dependencies"
            ));
        }
        for needed in &facts.needed {
            pending.push_back(needed.clone());
        }
        graph.insert(name, facts);
    }
    Ok(graph)
}

fn validate_runtime_name(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&b'$')
        || bytes.contains(&0)
        || !matches!(
            bytes,
            b"ld-linux-x86-64.so.2" | b"libc.so.6" | b"libgcc_s.so.1"
        )
    {
        return Err(anyhow!("unsupported hardened glibc runtime name {name:?}"));
    }
    Ok(())
}

fn unique_runtime_candidate(mut candidates: Vec<std::fs::File>) -> Result<std::fs::File> {
    let selected = candidates
        .pop()
        .ok_or_else(|| anyhow!("required hardened glibc runtime object is unresolved"))?;
    let key = mapping_file_key(&selected).map_err(anyhow::Error::msg)?;
    for candidate in candidates {
        if mapping_file_key(&candidate).map_err(anyhow::Error::msg)? != key {
            return Err(anyhow!(
                "hardened glibc runtime name is ambiguous across distinct inodes"
            ));
        }
    }
    Ok(selected)
}

fn pinned_loader_candidate(
    interpreter: &std::fs::File,
    candidates: Vec<std::fs::File>,
) -> Result<()> {
    if candidates.is_empty() {
        return Err(anyhow!(
            "required hardened glibc loader candidate is unresolved"
        ));
    }
    let interpreter = mapping_file_key(interpreter).map_err(anyhow::Error::msg)?;
    for candidate in candidates {
        if mapping_file_key(&candidate).map_err(anyhow::Error::msg)? != interpreter {
            return Err(anyhow!(
                "a loader search candidate is not the pinned glibc interpreter"
            ));
        }
    }
    Ok(())
}

fn runtime_candidates<'a>(
    directories: impl IntoIterator<Item = &'a File>,
    name: &OsStr,
    owner: u32,
) -> Result<Vec<File>> {
    validate_runtime_name(name)?;
    let mut candidates = Vec::new();
    for directory in directories {
        if let Some(candidate) = open_runtime_candidate(directory, name, owner)? {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn open_runtime_candidate(directory: &File, name: &OsStr, owner: u32) -> Result<Option<File>> {
    let mut name = name.to_os_string();
    let mut symlink_hops = 0usize;
    loop {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| anyhow!("runtime candidate name contains NUL"))?;
        let entry = match stat_at(directory, &c_name) {
            Ok(entry) => entry,
            Err(error) if symlink_hops == 0 && error.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).context("opening hardened glibc runtime candidate");
            }
        };
        if entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
            if entry.st_uid != owner {
                return Err(anyhow!("runtime candidate symlink has an unexpected owner"));
            }
            symlink_hops += 1;
            if symlink_hops > MAX_SYMLINK_HOPS {
                return Err(anyhow!(
                    "runtime candidate exceeds the {MAX_SYMLINK_HOPS}-symlink limit"
                ));
            }
            let target = readlink_at(directory, &c_name)?;
            let target_bytes = target.as_bytes();
            if target_bytes.is_empty()
                || target_bytes == b"."
                || target_bytes == b".."
                || target_bytes.contains(&b'/')
                || target_bytes.contains(&b'$')
                || target_bytes.contains(&0)
            {
                return Err(anyhow!(
                    "runtime candidate has an unsafe same-directory symlink target"
                ));
            }
            let current =
                stat_at(directory, &c_name).context("revalidating runtime candidate symlink")?;
            if !same_stat(&entry, &current) {
                return Err(anyhow!("runtime candidate symlink changed while inspected"));
            }
            name = target;
            continue;
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            return Err(std::io::Error::last_os_error())
                .context("opening hardened glibc runtime candidate");
        }
        let file = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
        if !same_stat_file(&entry, &file)? {
            return Err(anyhow!("runtime candidate changed while it was opened"));
        }
        validate_protected_regular(&file, owner, Path::new(&name))?;
        return Ok(Some(file));
    }
}

struct AuthorityRoot {
    root: File,
    owner: u32,
}

#[derive(Clone, Copy)]
enum ExpectedEntry {
    Directory,
    Regular,
    RegularNoSymlink,
}

enum WalkComponent {
    Parent,
    Normal(OsString),
}

impl AuthorityRoot {
    fn open(path: &Path, owner: u32) -> Result<Self> {
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("opening authority root {}", path.display()))?;
        validate_protected_directory(&root, owner, path)?;
        Ok(Self {
            root: normalize_file_fd(root)?,
            owner,
        })
    }

    fn open_directory(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::Directory)
    }

    fn open_regular(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::Regular)
    }

    fn open_regular_nofollow(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::RegularNoSymlink)
    }

    fn open_entry(
        &self,
        path: &Path,
        optional: bool,
        expected: ExpectedEntry,
    ) -> Result<Option<File>> {
        if !path.is_absolute() {
            return Err(anyhow!("authority path must be absolute"));
        }
        let mut pending = path_components(path)?.1;
        if pending.is_empty() {
            return match expected {
                ExpectedEntry::Directory => Ok(Some(normalize_file_fd(self.root.try_clone()?)?)),
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => {
                    Err(anyhow!("authority root is not a regular file"))
                }
            };
        }
        let mut directories = vec![normalize_file_fd(self.root.try_clone()?)?];
        let mut symlink_hops = 0usize;
        while let Some(component) = pending.pop_front() {
            if matches!(component, WalkComponent::Parent) {
                if directories.len() == 1 {
                    return Err(anyhow!("authority symlink target escapes its root"));
                }
                directories.pop();
                continue;
            }
            let WalkComponent::Normal(name) = component else {
                unreachable!()
            };
            let name = CString::new(name.as_bytes())
                .map_err(|_| anyhow!("authority path component contains NUL"))?;
            let parent = directories.last().expect("authority root remains retained");
            let entry = match stat_at(parent, &name) {
                Ok(entry) => entry,
                Err(error) if optional && error.raw_os_error() == Some(libc::ENOENT) => {
                    return Ok(None);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("opening protected authority path {}", path.display())
                    });
                }
            };
            if entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
                if pending.is_empty() && matches!(expected, ExpectedEntry::RegularNoSymlink) {
                    return Err(anyhow!(
                        "authority path {} has a symlink leaf",
                        path.display()
                    ));
                }
                if entry.st_uid != self.owner {
                    return Err(anyhow!(
                        "authority symlink {} is not owned by uid {}",
                        path.display(),
                        self.owner
                    ));
                }
                symlink_hops += 1;
                if symlink_hops > MAX_SYMLINK_HOPS {
                    return Err(anyhow!(
                        "authority path {} exceeds the {MAX_SYMLINK_HOPS}-symlink limit",
                        path.display(),
                    ));
                }
                let target = readlink_at(parent, &name)?;
                let current = stat_at(parent, &name)
                    .context("revalidating authority symlink after readlink")?;
                if !same_stat(&entry, &current) {
                    return Err(anyhow!(
                        "authority symlink {} changed while it was inspected",
                        path.display()
                    ));
                }
                let (absolute, target) = path_components(Path::new(&target))?;
                if target.is_empty() {
                    return Err(anyhow!("authority symlink has an empty target"));
                }
                if absolute {
                    directories.truncate(1);
                }
                for component in target.into_iter().rev() {
                    pending.push_front(component);
                }
                continue;
            }

            let final_component = pending.is_empty();
            let kind = if final_component {
                expected
            } else {
                ExpectedEntry::Directory
            };
            let flags = match kind {
                ExpectedEntry::Directory => libc::O_RDONLY | libc::O_DIRECTORY,
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => libc::O_RDONLY,
            } | libc::O_NOFOLLOW
                | libc::O_CLOEXEC;
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd == -1 {
                let error = std::io::Error::last_os_error();
                if optional && error.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(None);
                }
                return Err(error).with_context(|| {
                    format!("opening protected authority path {}", path.display())
                });
            }
            let opened = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
            if !same_stat_file(&entry, &opened)? {
                return Err(anyhow!(
                    "authority path {} changed while it was opened",
                    path.display()
                ));
            }
            match kind {
                ExpectedEntry::Directory => {
                    validate_protected_directory(&opened, self.owner, path)?;
                    if final_component {
                        return Ok(Some(opened));
                    }
                    directories.push(opened);
                }
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => {
                    validate_protected_regular(&opened, self.owner, path)?;
                    return Ok(Some(opened));
                }
            }
        }
        Err(anyhow!("authority path did not resolve to an entry"))
    }
}

fn path_components(path: &Path) -> Result<(bool, VecDeque<WalkComponent>)> {
    let mut absolute = false;
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => components.push_back(WalkComponent::Parent),
            Component::Normal(name) => {
                components.push_back(WalkComponent::Normal(name.to_os_string()));
            }
            Component::Prefix(_) => {
                return Err(anyhow!("authority path has an unsupported prefix"));
            }
        }
    }
    Ok((absolute, components))
}

fn stat_at(parent: &File, name: &CString) -> std::io::Result<libc::stat> {
    loop {
        let mut stat = std::mem::MaybeUninit::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != -1
        {
            return Ok(unsafe { stat.assume_init() });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn readlink_at(parent: &File, name: &CString) -> Result<OsString> {
    let mut bytes = [0u8; 4096];
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length == -1 {
        return Err(std::io::Error::last_os_error()).context("reading authority symlink");
    }
    let length = usize::try_from(length).map_err(|_| anyhow!("invalid symlink length"))?;
    if length == bytes.len() {
        return Err(anyhow!("authority symlink target is too long"));
    }
    Ok(OsStr::from_bytes(&bytes[..length]).to_os_string())
}

fn same_stat(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode & libc::S_IFMT == right.st_mode & libc::S_IFMT
}

fn same_stat_file(entry: &libc::stat, file: &File) -> Result<bool> {
    let metadata = file.metadata()?;
    Ok(entry.st_dev == metadata.dev()
        && entry.st_ino == metadata.ino()
        && entry.st_mode & libc::S_IFMT == metadata.mode() & libc::S_IFMT)
}

#[derive(Debug)]
enum PreloadState {
    Absent {
        etc: File,
    },
    Empty {
        etc: File,
        preload: File,
        owner: u32,
    },
}

impl PreloadState {
    fn capture(
        authority: &AuthorityRoot,
        mut retain: impl FnMut(&File) -> Result<()>,
    ) -> Result<Self> {
        let etc = authority
            .open_directory(Path::new("/etc"), false)?
            .ok_or_else(|| anyhow!("protected /etc directory is absent"))?;
        let Some(preload) = open_preload_entry(&etc)? else {
            return Ok(Self::Absent { etc });
        };
        validate_protected_regular(&preload, authority.owner, Path::new("/etc/ld.so.preload"))?;
        retain(&preload)?;
        revalidate_preload_entry(&etc, &preload, authority.owner)?;
        validate_empty_file(&preload)?;
        Ok(Self::Empty {
            etc,
            preload,
            owner: authority.owner,
        })
    }

    #[cfg(test)]
    fn is_absent(&self) -> bool {
        matches!(self, Self::Absent { .. })
    }

    fn etc(&self) -> &File {
        match self {
            Self::Absent { etc } | Self::Empty { etc, .. } => etc,
        }
    }

    fn revalidate(&self) -> Result<()> {
        match self {
            Self::Absent { etc } => {
                if open_preload_entry(etc)?.is_some() {
                    return Err(anyhow!("/etc/ld.so.preload appeared after preparation"));
                }
                Ok(())
            }
            Self::Empty {
                etc,
                preload,
                owner,
            } => {
                revalidate_preload_entry(etc, preload, *owner)?;
                validate_empty_file(preload)
            }
        }
    }
}

#[derive(Debug)]
struct AliasExpectation {
    link_text: OsString,
    target: MappingFileKey,
}

struct PrivateAliasDir {
    parent: File,
    name: OsString,
    directory: Option<File>,
    child_identity: Option<(u64, u64)>,
    owner: u32,
    aliases: BTreeMap<OsString, AliasExpectation>,
    ready: bool,
    cleaned: bool,
}

impl PrivateAliasDir {
    fn create(parent: &File, owner: u32, aliases: Vec<(OsString, &File)>) -> Result<Self> {
        validate_protected_directory(parent, owner, Path::new("private alias parent"))?;
        let parent = normalize_file_fd(parent.try_clone()?)?;
        for _ in 0..128 {
            let name = random_alias_directory_name()?;
            let c_name = CString::new(name.as_bytes()).expect("generated alias directory name");
            if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(error).context("creating private glibc alias directory");
            }
            let mut private = Self {
                parent,
                name,
                directory: None,
                child_identity: None,
                owner,
                aliases: BTreeMap::new(),
                ready: false,
                cleaned: false,
            };
            let initialized = private.initialize(aliases);
            if let Err(error) = initialized {
                return match private.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(anyhow!(
                        "{error:#}; private alias cleanup also failed: {cleanup:#}"
                    )),
                };
            }
            return Ok(private);
        }
        Err(anyhow!(
            "could not allocate a unique private glibc alias directory"
        ))
    }

    fn initialize(&mut self, aliases: Vec<(OsString, &File)>) -> Result<()> {
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("pinning newly created private glibc alias directory")?;
        self.child_identity = Some((entry.st_dev, entry.st_ino));
        let directory = open_child_directory(&self.parent, &name)?;
        if !same_stat_file(&entry, &directory)? {
            return Err(anyhow!("private glibc alias directory changed after mkdir"));
        }
        self.directory = Some(directory);
        for (alias, target) in aliases {
            validate_runtime_name(&alias)?;
            if target.as_raw_fd() <= 2 {
                return Err(anyhow!("private glibc alias target fd is not above stdio"));
            }
            if self.aliases.contains_key(&alias) {
                return Err(anyhow!("duplicate private glibc alias {alias:?}"));
            }
            let target_key = mapping_file_key(target).map_err(anyhow::Error::msg)?;
            let link_text = OsString::from(format!("/proc/self/fd/{}", target.as_raw_fd()));
            let c_link = CString::new(link_text.as_bytes()).expect("numeric proc fd alias target");
            let c_alias = CString::new(alias.as_bytes())
                .map_err(|_| anyhow!("private glibc alias contains NUL"))?;
            if unsafe { libc::symlinkat(c_link.as_ptr(), self.directory_fd(), c_alias.as_ptr()) }
                == -1
            {
                return Err(std::io::Error::last_os_error())
                    .context("creating private glibc fd alias");
            }
            self.aliases.insert(
                alias,
                AliasExpectation {
                    link_text,
                    target: target_key,
                },
            );
        }
        if unsafe { libc::fchmod(self.directory_fd(), 0o511) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("protecting private glibc alias directory");
        }
        self.ready = true;
        self.revalidate()
    }

    #[cfg(test)]
    fn name(&self) -> &OsStr {
        &self.name
    }

    fn directory_fd(&self) -> i32 {
        self.directory
            .as_ref()
            .expect("private alias directory is initialized")
            .as_raw_fd()
    }

    fn validate_child(&self, require_ready_mode: bool) -> Result<()> {
        validate_protected_directory(&self.parent, self.owner, Path::new("private alias parent"))?;
        let expected = self
            .child_identity
            .ok_or_else(|| anyhow!("private alias child identity was never pinned"))?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("revalidating private glibc alias directory entry")?;
        if (entry.st_dev, entry.st_ino) != expected {
            return Err(anyhow!("private glibc alias child entry was replaced"));
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?;
        if !same_stat_file(&entry, directory)? {
            return Err(anyhow!("private glibc alias child fd was replaced"));
        }
        let metadata = directory.metadata()?;
        let mode = metadata.mode() & 0o7777;
        let valid_mode = if require_ready_mode {
            mode == 0o511
        } else {
            matches!(mode, 0o511 | 0o700)
        };
        if !metadata.is_dir() || metadata.uid() != self.owner || !valid_mode {
            return Err(anyhow!(
                "private glibc alias directory has unexpected owner or mode"
            ));
        }
        Ok(())
    }

    fn recover_child_fd(&mut self) -> Result<()> {
        if self.directory.is_some() {
            return Ok(());
        }
        validate_protected_directory(&self.parent, self.owner, Path::new("private alias parent"))?;
        let expected = self
            .child_identity
            .ok_or_else(|| anyhow!("private alias child identity was never pinned"))?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("recovering private glibc alias directory entry")?;
        if (entry.st_dev, entry.st_ino) != expected
            || entry.st_mode & libc::S_IFMT != libc::S_IFDIR
            || entry.st_uid != self.owner
        {
            return Err(anyhow!(
                "private glibc alias child entry cannot be safely recovered"
            ));
        }
        if self.directory.is_none() {
            let directory = open_child_directory(&self.parent, &name)?;
            if !same_stat_file(&entry, &directory)? {
                return Err(anyhow!("recovered private alias authority fd changed"));
            }
            self.directory = Some(directory);
        }
        Ok(())
    }

    fn entries(&self) -> Result<BTreeSet<OsString>> {
        let directory_fd = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?
            .as_raw_fd();
        if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("rewinding private glibc alias directory");
        }
        let fd = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error())
                .context("duplicating private glibc listing fd");
        }
        let directory = unsafe { libc::fdopendir(fd) };
        if directory.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error).context("opening private glibc directory stream");
        }
        let mut entries = BTreeSet::new();
        let result = loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(0) {
                    break Ok(());
                }
                break Err(error).context("enumerating private glibc alias directory");
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                entries.insert(OsString::from_vec(name.to_vec()));
            }
        };
        let close = unsafe { libc::closedir(directory) };
        let rewind = unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) };
        result?;
        if close == -1 {
            return Err(std::io::Error::last_os_error())
                .context("closing private glibc directory stream");
        }
        if rewind == -1 {
            return Err(std::io::Error::last_os_error())
                .context("restoring private glibc directory offset");
        }
        Ok(entries)
    }

    fn validate_aliases(&self) -> Result<()> {
        let entries = self.entries()?;
        let expected = self.aliases.keys().cloned().collect::<BTreeSet<_>>();
        if entries != expected {
            return Err(anyhow!("private glibc alias entry set changed"));
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?;
        for (name, expected) in &self.aliases {
            let c_name = CString::new(name.as_bytes())
                .map_err(|_| anyhow!("private glibc alias contains NUL"))?;
            let entry = stat_at(directory, &c_name)?;
            if entry.st_mode & libc::S_IFMT != libc::S_IFLNK || entry.st_uid != self.owner {
                return Err(anyhow!(
                    "private glibc alias {name:?} changed type or owner"
                ));
            }
            let link = readlink_at(directory, &c_name)?;
            let current = stat_at(directory, &c_name)?;
            if !same_stat(&entry, &current) || link != expected.link_text {
                return Err(anyhow!("private glibc alias {name:?} was retargeted"));
            }
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("following private glibc fd alias");
            }
            let followed = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
            if mapping_file_key(&followed).map_err(anyhow::Error::msg)? != expected.target {
                return Err(anyhow!("private glibc alias {name:?} target changed"));
            }
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<()> {
        self.validate_child(true)?;
        self.validate_aliases()
    }

    fn unlink_aliases(
        &mut self,
        mut unlink: impl FnMut(i32, &CStr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let directory = self.directory_fd();
        let names = self.aliases.keys().cloned().collect::<Vec<_>>();
        for name in names {
            let c_name = CString::new(name.as_bytes()).expect("validated glibc alias name");
            unlink(directory, &c_name)?;
            self.aliases.remove(&name);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.recover_child_fd()?;
        self.validate_child(self.ready)?;
        self.validate_aliases()?;
        if unsafe { libc::fchmod(self.directory_fd(), 0o700) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("opening private glibc alias directory for cleanup");
        }
        self.ready = false;
        self.unlink_aliases(|directory, name| {
            if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
        .context("removing private glibc fd alias")?;
        if !self.entries()?.is_empty() {
            return Err(anyhow!(
                "private glibc alias directory was not empty after cleanup"
            ));
        }
        self.validate_child(false)?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
            == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("removing private glibc alias directory");
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateAliasDir {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn random_alias_directory_name() -> Result<OsString> {
    let mut random = [0u8; 16];
    let mut filled = 0usize;
    while filled < random.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                random[filled..].as_mut_ptr(),
                random.len() - filled,
                0,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("generating private glibc alias directory name");
        }
        if read == 0 {
            return Err(anyhow!(
                "getrandom returned EOF for private glibc alias directory name"
            ));
        }
        filled += usize::try_from(read).map_err(|_| anyhow!("invalid getrandom length"))?;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(7 + random.len() * 2);
    name.push_str("oracle-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(OsString::from(name))
}

fn open_child_directory(parent: &File, name: &CStr) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error())
            .context("opening private glibc alias directory");
    }
    normalize_file_fd(unsafe { File::from_raw_fd(fd) })
}

enum FixedDirectory {
    Absent { path: &'static str },
    Present { path: &'static str, file: File },
}

impl FixedDirectory {
    fn capture(authority: &AuthorityRoot, path: &'static str) -> Result<Self> {
        Ok(match authority.open_directory(Path::new(path), true)? {
            Some(file) => Self::Present { path, file },
            None => Self::Absent { path },
        })
    }

    fn file(&self) -> Option<&File> {
        match self {
            Self::Absent { .. } => None,
            Self::Present { file, .. } => Some(file),
        }
    }

    fn revalidate(&self, authority: &AuthorityRoot) -> Result<()> {
        match self {
            Self::Absent { path } => {
                if authority.open_directory(Path::new(path), true)?.is_some() {
                    return Err(anyhow!(
                        "hardened glibc search directory {path} appeared after preparation"
                    ));
                }
            }
            Self::Present { path, file } => {
                let current = authority
                    .open_directory(Path::new(path), false)?
                    .ok_or_else(|| anyhow!("hardened glibc search directory {path} vanished"))?;
                require_same_mapping(&current, file, "hardened glibc search directory")?;
            }
        }
        Ok(())
    }
}

pub(crate) struct PreparedGlibc<'a> {
    // This guard must clean its child before any retained path or lease can drop.
    private: PrivateAliasDir,
    leases: &'a crate::discover_cmd::ClosureLeases,
    authority: AuthorityRoot,
    helper_path: &'a Path,
    helper_fd: RawFd,
    runtime_fds: BTreeMap<OsString, RawFd>,
    search_directories: Vec<FixedDirectory>,
    preload: PreloadState,
    staging_parent: File,
    owner: u32,
}

impl PreparedGlibc<'_> {
    pub(crate) fn revalidate(&self) -> Result<()> {
        revalidate_glibc_pins(
            &self.authority,
            self.helper_path,
            self.helper_fd,
            &self.runtime_fds,
            &self.search_directories,
            &self.preload,
            &self.staging_parent,
            self.owner,
            self.leases,
        )?;
        self.private.revalidate()
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        self.private.cleanup()
    }
}

pub(crate) fn prepare_glibc<'a>(
    helper: File,
    helper_path: &'a Path,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!(
            "hardened glibc preparation requires effective host uid 0"
        ));
    }
    let authority = AuthorityRoot::open(Path::new("/"), 0)?;
    prepare_glibc_in_root(authority, helper, helper_path, 0, leases)
}

#[cfg(test)]
pub(crate) fn prepare_glibc_test_root<'a>(
    root: &Path,
    helper_path: &'a Path,
    owner: u32,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    let authority = AuthorityRoot::open(root, owner)?;
    let helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper is absent"))?;
    prepare_glibc_in_root(authority, helper, helper_path, owner, leases)
}

fn prepare_glibc_in_root<'a>(
    authority: AuthorityRoot,
    helper: File,
    helper_path: &'a Path,
    owner: u32,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    validate_hardened_helper(&helper, owner)?;
    let current_helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper is absent"))?;
    require_same_mapping(&current_helper, &helper, "hardened glibc helper")?;
    let helper_fd = leases.retain_influence(helper, "hardened glibc helper")?;
    let helper_facts = inspect_elf_loader(
        leases
            .file(helper_fd)
            .ok_or_else(|| anyhow!("retained hardened glibc helper fd is missing"))?,
    )
    .map_err(anyhow::Error::msg)
    .context("inspecting hardened glibc helper")?;
    let interpreter = authority
        .open_regular(Path::new(GLIBC_INTERP), false)?
        .ok_or_else(|| anyhow!("hardened glibc interpreter is absent"))?;
    let interpreter_fd = leases.retain_influence(interpreter, "hardened glibc interpreter")?;
    let search_directories = GLIBC_SEARCH_DIRECTORIES
        .into_iter()
        .map(|path| FixedDirectory::capture(&authority, path))
        .collect::<Result<Vec<_>>>()?;
    let search_files = search_directories
        .iter()
        .filter_map(FixedDirectory::file)
        .collect::<Vec<_>>();
    let mut runtime_fds = BTreeMap::new();
    let _graph = prepare_glibc_graph(&helper_facts, |name| {
        let candidates = runtime_candidates(search_files.iter().copied(), name, owner)?;
        let (fd, facts) = if name == OsStr::new(GLIBC_LOADER) {
            let interpreter = leases
                .file(interpreter_fd)
                .ok_or_else(|| anyhow!("retained hardened glibc interpreter fd is missing"))?;
            pinned_loader_candidate(interpreter, candidates)?;
            let facts = inspect_elf_loader(interpreter)
                .map_err(anyhow::Error::msg)
                .context("inspecting retained hardened glibc interpreter")?;
            (interpreter_fd, facts)
        } else {
            let file = unique_runtime_candidate(candidates)?;
            let fd = leases.retain_influence(file, &format!("hardened glibc runtime {name:?}"))?;
            let facts = inspect_elf_loader(
                leases
                    .file(fd)
                    .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?,
            )
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("inspecting hardened glibc runtime {name:?}"))?;
            (fd, facts)
        };
        runtime_fds.insert(name.to_os_string(), fd);
        Ok(facts)
    })?;
    let preload = PreloadState::capture(&authority, |file| {
        leases
            .retain_influence(file.try_clone()?, "/etc/ld.so.preload")
            .map(|_| ())
    })?;
    let staging_parent = open_or_create_staging_parent(&authority, owner)?;

    leases.ensure().map_err(anyhow::Error::msg)?;
    revalidate_glibc_pins(
        &authority,
        helper_path,
        helper_fd,
        &runtime_fds,
        &search_directories,
        &preload,
        &staging_parent,
        owner,
        leases,
    )?;
    leases.ensure().map_err(anyhow::Error::msg)?;

    let aliases = runtime_fds
        .iter()
        .map(|(name, fd)| {
            let file = leases
                .file(*fd)
                .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?;
            Ok((name.clone(), file))
        })
        .collect::<Result<Vec<_>>>()?;
    let private = PrivateAliasDir::create(&staging_parent, owner, aliases)?;
    Ok(PreparedGlibc {
        private,
        leases,
        authority,
        helper_path,
        helper_fd,
        runtime_fds,
        search_directories,
        preload,
        staging_parent,
        owner,
    })
}

fn validate_hardened_helper(helper: &File, owner: u32) -> Result<()> {
    validate_protected_regular(helper, owner, Path::new("hardened glibc helper"))?;
    if helper.metadata()?.mode() & 0o111 == 0 {
        return Err(anyhow!("hardened glibc helper is not executable"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn revalidate_glibc_pins(
    authority: &AuthorityRoot,
    helper_path: &Path,
    helper_fd: RawFd,
    runtime_fds: &BTreeMap<OsString, RawFd>,
    search_directories: &[FixedDirectory],
    preload: &PreloadState,
    staging_parent: &File,
    owner: u32,
    leases: &crate::discover_cmd::ClosureLeases,
) -> Result<()> {
    let retained_helper = leases
        .file(helper_fd)
        .ok_or_else(|| anyhow!("retained hardened glibc helper fd is missing"))?;
    let current_helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper vanished"))?;
    require_same_mapping(&current_helper, retained_helper, "hardened glibc helper")?;
    for directory in search_directories {
        directory.revalidate(authority)?;
    }
    let current_staging = authority
        .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
        .ok_or_else(|| anyhow!("protected {GLIBC_STAGING_DIRECTORY} vanished"))?;
    validate_staging_parent(&current_staging, owner)?;
    require_same_mapping(
        &current_staging,
        staging_parent,
        "private glibc staging parent",
    )?;
    let current_etc = authority
        .open_directory(Path::new("/etc"), false)?
        .ok_or_else(|| anyhow!("protected /etc vanished"))?;
    require_same_mapping(&current_etc, preload.etc(), "protected /etc")?;
    preload.revalidate()?;

    let loader_fd = runtime_fds
        .get(OsStr::new(GLIBC_LOADER))
        .ok_or_else(|| anyhow!("pinned hardened glibc interpreter fd is missing"))?;
    let retained_interpreter = leases
        .file(*loader_fd)
        .ok_or_else(|| anyhow!("retained hardened glibc interpreter fd is missing"))?;
    let current_interpreter = authority
        .open_regular(Path::new(GLIBC_INTERP), false)?
        .ok_or_else(|| anyhow!("hardened glibc interpreter vanished"))?;
    require_same_mapping(
        &current_interpreter,
        retained_interpreter,
        "hardened glibc interpreter",
    )?;

    let search_files = search_directories
        .iter()
        .filter_map(FixedDirectory::file)
        .collect::<Vec<_>>();
    for (name, fd) in runtime_fds {
        let retained = leases
            .file(*fd)
            .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?;
        let candidates = runtime_candidates(search_files.iter().copied(), name, owner)?;
        if name == OsStr::new(GLIBC_LOADER) {
            pinned_loader_candidate(retained, candidates)?;
        } else {
            let current = unique_runtime_candidate(candidates)?;
            require_same_mapping(&current, retained, "hardened glibc runtime candidate")?;
        }
    }

    let helper_facts = inspect_elf_loader(retained_helper)
        .map_err(anyhow::Error::msg)
        .context("revalidating hardened glibc helper facts")?;
    let graph = prepare_glibc_graph(&helper_facts, |name| {
        let fd = runtime_fds
            .get(name)
            .ok_or_else(|| anyhow!("hardened glibc graph gained an unresolved object"))?;
        inspect_elf_loader(
            leases
                .file(*fd)
                .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?,
        )
        .map_err(anyhow::Error::msg)
    })?;
    if graph.keys().ne(runtime_fds.keys()) {
        return Err(anyhow!(
            "hardened glibc runtime graph changed after preparation"
        ));
    }
    Ok(())
}

fn validate_staging_parent(parent: &File, owner: u32) -> Result<()> {
    let metadata = parent.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o755 {
        return Err(anyhow!(
            "{GLIBC_STAGING_DIRECTORY} must be an owner-controlled mode-0755 directory"
        ));
    }
    Ok(())
}

fn open_or_create_staging_parent(authority: &AuthorityRoot, owner: u32) -> Result<File> {
    if let Some(parent) = authority.open_directory(Path::new(GLIBC_STAGING_DIRECTORY), true)? {
        validate_staging_parent(&parent, owner)?;
        return Ok(parent);
    }
    let run = authority
        .open_directory(Path::new("/run"), false)?
        .ok_or_else(|| anyhow!("protected /run is absent"))?;
    let name = c"p11scope";
    if unsafe { libc::mkdirat(run.as_raw_fd(), name.as_ptr(), 0o755) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).context("creating protected /run/p11scope");
        }
        let parent = authority
            .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
            .ok_or_else(|| anyhow!("raced /run/p11scope creation vanished"))?;
        validate_staging_parent(&parent, owner)?;
        return Ok(parent);
    }
    let created = open_child_directory(&run, name)?;
    if unsafe { libc::fchmod(created.as_raw_fd(), 0o755) } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("setting protected /run/p11scope mode");
    }
    validate_staging_parent(&created, owner)?;
    let current = authority
        .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
        .ok_or_else(|| anyhow!("new /run/p11scope vanished"))?;
    require_same_mapping(&current, &created, "new /run/p11scope")?;
    Ok(created)
}

fn require_same_mapping(current: &File, retained: &File, label: &str) -> Result<()> {
    if mapping_file_key(current).map_err(anyhow::Error::msg)?
        != mapping_file_key(retained).map_err(anyhow::Error::msg)?
    {
        return Err(anyhow!("{label} changed after preparation"));
    }
    Ok(())
}

fn open_preload_entry(etc: &File) -> Result<Option<File>> {
    let name = c"ld.so.preload";
    let fd = unsafe {
        libc::openat(
            etc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(error).context("opening protected /etc/ld.so.preload entry");
    }
    normalize_file_fd(unsafe { File::from_raw_fd(fd) }).map(Some)
}

fn revalidate_preload_entry(etc: &File, preload: &File, owner: u32) -> Result<()> {
    let current = open_preload_entry(etc)?
        .ok_or_else(|| anyhow!("/etc/ld.so.preload changed after preparation"))?;
    if mapping_file_key(&current).map_err(anyhow::Error::msg)?
        != mapping_file_key(preload).map_err(anyhow::Error::msg)?
    {
        return Err(anyhow!("/etc/ld.so.preload changed after preparation"));
    }
    validate_protected_regular(&current, owner, Path::new("/etc/ld.so.preload"))
}

fn validate_protected_regular(file: &File, owner: u32, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "authority file {} is not protected (uid {}, mode {:#o})",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}

fn validate_empty_file(file: &File) -> Result<()> {
    if file.metadata()?.len() != 0 {
        return Err(anyhow!("/etc/ld.so.preload is not empty"));
    }
    let mut byte = [0u8; 1];
    if file.read_at(&mut byte, 0)? != 0 {
        return Err(anyhow!("/etc/ld.so.preload is not empty"));
    }
    Ok(())
}

fn validate_protected_directory(file: &File, owner: u32, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "authority directory {} is not protected (uid {}, mode {:#o})",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}

fn normalize_file_fd(file: File) -> Result<File> {
    if file.as_raw_fd() > 2 {
        return Ok(file);
    }
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).context("moving authority fd above stdio");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn parse_status(status: &str) -> Result<ProcessStatus> {
    let mut uids = None;
    let mut capabilities = 0u64;
    let mut seen_caps = 0u8;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            if uids.is_some() {
                return Err(anyhow!("process status contains duplicate Uid fields"));
            }
            let values = value
                .split_ascii_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .map_err(|_| anyhow!("process status contains an invalid Uid field"))?;
            uids = Some(
                values
                    .try_into()
                    .map_err(|_| anyhow!("process status Uid field must contain four values"))?,
            );
            continue;
        }
        for (index, name) in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            .into_iter()
            .enumerate()
        {
            let Some(value) = line.strip_prefix(name) else {
                continue;
            };
            let bit = 1u8 << index;
            if seen_caps & bit != 0 {
                return Err(anyhow!("process status contains duplicate {name} fields"));
            }
            seen_caps |= bit;
            capabilities |= u64::from_str_radix(value.trim(), 16)
                .map_err(|_| anyhow!("process status contains an invalid {name} field"))?;
        }
    }
    if seen_caps != 0b1111 {
        return Err(anyhow!("process status is missing capability fields"));
    }
    Ok(ProcessStatus {
        uids: uids.ok_or_else(|| anyhow!("process status is missing its Uid field"))?,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::Scope;
    use p11scope_manifest::identity::ElfLoader;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    const ROOT_STATUS: &str = "Uid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    const TARGET_STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    const FULL_UID_MAP: &str = "         0          0 4294967295\n";

    fn static_loader() -> ElfLoader {
        ElfLoader {
            interpreter: None,
            needed: vec![],
            soname: None,
        }
    }

    #[test]
    fn valid_static_root_pid_facts_select_hardened_mode() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            false,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();

        assert_eq!(mode, OracleMode::Hardened);
    }

    #[test]
    fn trusted_acknowledgement_is_only_a_fallback() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            true,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();
        assert_eq!(mode, OracleMode::Hardened);
        assert_eq!(
            select_from_facts(&Scope::Pid(42), true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn cgroup_requires_explicit_trusted_acknowledgement() {
        let scope = Scope::Cgroup {
            id: 7,
            path: PathBuf::from("/sys/fs/cgroup/test"),
        };
        let error = select_from_facts(&scope, false, None).unwrap_err();

        assert!(
            error.to_string().contains("--trusted-workload"),
            "{error:#}"
        );
        assert_eq!(
            select_from_facts(&scope, true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn dynamic_or_non_root_observer_facts_are_refused() {
        for (loader, owner, mode, status) in [
            (
                ElfLoader {
                    interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                    needed: vec![OsString::from("libc.so.6")],
                    soname: None,
                },
                0,
                0o100755,
                ROOT_STATUS,
            ),
            (static_loader(), 1000, 0o100755, ROOT_STATUS),
            (static_loader(), 0, 0o100775, ROOT_STATUS),
            (static_loader(), 0, 0o100755, TARGET_STATUS),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: loader,
                    observer_owner: owner,
                    observer_mode: mode,
                    observer_status: status,
                    target_status: TARGET_STATUS,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn target_root_or_kill_setuid_ptrace_capability_is_refused() {
        for status in [
            ROOT_STATUS.to_string(),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "0\t1000\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t0\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t1000\t0"),
            TARGET_STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000080000"),
            TARGET_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000080"),
            TARGET_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000080000"),
            TARGET_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000020"),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: &status,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn partial_or_different_user_namespace_is_refused() {
        for (uid_map, observer_namespace, init_namespace) in [
            ("0 0 65536\n", (4, 1), (4, 1)),
            ("0 0 4294967295\n1 1 1\n", (4, 1), (4, 1)),
            (FULL_UID_MAP, (4, 1), (4, 2)),
            (FULL_UID_MAP, (0, 0), (0, 0)),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: TARGET_STATUS,
                    observer_uid_map: uid_map,
                    observer_user_namespace: observer_namespace,
                    init_user_namespace: init_namespace,
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn malformed_or_incomplete_proc_status_is_refused() {
        for status in [
            "",
            "Uid:\t1000\t1000\t1000\n",
            "Uid:\t1000\t1000\t1000\t1000\nCapInh:\tnot-hex\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
            "Uid:\t1000\t1000\t1000\t1000\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
        ] {
            let error = parse_status(status).unwrap_err();
            assert!(error.to_string().contains("process status"), "{error:#}");
        }
    }

    #[test]
    fn glibc_official_graph_is_resolved_once() {
        let helper = ElfLoader {
            interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
            needed: ["libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            soname: None,
        };
        let mut resolved = Vec::new();

        let graph = prepare_glibc_graph(&helper, |name: &std::ffi::OsStr| -> Result<ElfLoader> {
            let name = name.to_string_lossy().into_owned();
            resolved.push(name.clone());
            let needed = match name.as_str() {
                "ld-linux-x86-64.so.2" => vec![],
                "libc.so.6" => vec![OsString::from("ld-linux-x86-64.so.2")],
                "libgcc_s.so.1" => vec![
                    OsString::from("libc.so.6"),
                    OsString::from("ld-linux-x86-64.so.2"),
                ],
                _ => return Err(anyhow!("unexpected runtime object {name}")),
            };
            Ok(ElfLoader {
                interpreter: None,
                needed,
                soname: Some(OsString::from(name)),
            })
        })
        .unwrap();

        assert_eq!(
            graph.keys().cloned().collect::<Vec<_>>(),
            ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]
        );
        resolved.sort();
        assert_eq!(
            resolved,
            ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]
        );
    }

    #[test]
    fn glibc_runtime_names_are_exact_safe_basenames() {
        for invalid in [
            OsString::from(""),
            OsString::from("$ORIGIN"),
            OsString::from("bad/name"),
            OsString::from("."),
            OsString::from(".."),
            OsString::from("libm.so.6"),
            OsString::from_vec(b"bad\0name".to_vec()),
        ] {
            let helper = ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![invalid.clone()],
                soname: None,
            };
            let error =
                prepare_glibc_graph(&helper, |name: &std::ffi::OsStr| -> Result<ElfLoader> {
                    Ok(ElfLoader {
                        interpreter: None,
                        needed: vec![],
                        soname: Some(name.to_os_string()),
                    })
                })
                .unwrap_err();
            assert!(error.to_string().contains("runtime name"), "{error:#}");
        }
    }

    #[test]
    fn glibc_helper_loader_and_soname_facts_are_exact() {
        let resolve = |name: &std::ffi::OsStr| -> Result<ElfLoader> {
            Ok(ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: Some(name.to_os_string()),
            })
        };
        for helper in [
            ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: None,
            },
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: None,
            },
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: Some(OsString::from("helper")),
            },
        ] {
            assert!(prepare_glibc_graph(&helper, resolve).is_err());
        }

        let helper = ElfLoader {
            interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
            needed: vec![],
            soname: None,
        };
        for loader in [
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: Some(OsString::from("ld-linux-x86-64.so.2")),
            },
            ElfLoader {
                interpreter: None,
                needed: vec![OsString::from("libc.so.6")],
                soname: Some(OsString::from("ld-linux-x86-64.so.2")),
            },
            ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: Some(OsString::from("libc.so.6")),
            },
        ] {
            let result = prepare_glibc_graph(&helper, |name| {
                if name == "ld-linux-x86-64.so.2" {
                    Ok(loader.clone())
                } else {
                    resolve(name)
                }
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn glibc_nonloader_runtime_may_name_the_exact_interpreter() {
        let helper = ElfLoader {
            interpreter: Some(PathBuf::from(GLIBC_INTERP)),
            needed: vec![OsString::from("libc.so.6")],
            soname: None,
        };

        let graph = prepare_glibc_graph(&helper, |name| {
            Ok(if name == OsStr::new(GLIBC_LOADER) {
                ElfLoader {
                    interpreter: None,
                    needed: vec![],
                    soname: Some(OsString::from(GLIBC_LOADER)),
                }
            } else {
                ElfLoader {
                    interpreter: Some(PathBuf::from(GLIBC_INTERP)),
                    needed: vec![OsString::from(GLIBC_LOADER)],
                    soname: Some(name.to_os_string()),
                }
            })
        })
        .unwrap();

        assert_eq!(graph.len(), 2);
    }

    #[test]
    fn glibc_distinct_runtime_candidates_are_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.so");
        let second = dir.path().join("second.so");
        let alias = dir.path().join("alias.so");
        std::fs::copy("/bin/true", &first).unwrap();
        std::fs::copy(&first, &second).unwrap();
        std::fs::hard_link(&first, &alias).unwrap();

        let error = unique_runtime_candidate(vec![
            std::fs::File::open(&first).unwrap(),
            std::fs::File::open(&second).unwrap(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error:#}");
        let selected = unique_runtime_candidate(vec![
            std::fs::File::open(&first).unwrap(),
            std::fs::File::open(&alias).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            selected.metadata().unwrap().ino(),
            first.metadata().unwrap().ino()
        );
    }

    #[test]
    fn glibc_loader_candidate_must_be_the_pinned_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let interpreter = dir.path().join("interpreter");
        let alias = dir.path().join("alias");
        let replacement = dir.path().join("replacement");
        std::fs::copy("/bin/true", &interpreter).unwrap();
        std::fs::hard_link(&interpreter, &alias).unwrap();
        std::fs::copy(&interpreter, &replacement).unwrap();

        let error =
            pinned_loader_candidate(&std::fs::File::open(&interpreter).unwrap(), Vec::new())
                .unwrap_err();
        assert!(error.to_string().contains("unresolved"), "{error:#}");
        pinned_loader_candidate(
            &std::fs::File::open(&interpreter).unwrap(),
            vec![std::fs::File::open(&alias).unwrap()],
        )
        .unwrap();
        let error = pinned_loader_candidate(
            &std::fs::File::open(&interpreter).unwrap(),
            vec![std::fs::File::open(&replacement).unwrap()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("interpreter"), "{error:#}");
    }

    #[test]
    fn glibc_search_directories_are_dirfd_walked_and_protected() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();

        let directory = authority
            .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), true)
            .unwrap()
            .unwrap();
        assert!(directory.as_raw_fd() > 2);
        assert!(
            authority
                .open_directory(Path::new("/usr/lib64"), true)
                .unwrap()
                .is_none()
        );

        std::fs::set_permissions(
            root.path().join("usr/lib"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let error = authority
            .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), true)
            .unwrap_err();
        assert!(error.to_string().contains("protected"), "{error:#}");
    }

    #[test]
    fn glibc_preload_is_exactly_absent_or_leased_empty() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::fs::set_permissions(
            root.path().join("etc"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();
        let preload = root.path().join("etc/ld.so.preload");

        let state =
            PreloadState::capture(&authority, |_| panic!("absent preload was retained")).unwrap();
        assert!(state.is_absent());
        state.revalidate().unwrap();

        std::fs::write(&preload, []).unwrap();
        std::fs::set_permissions(&preload, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = state.revalidate().unwrap_err();
        assert!(error.to_string().contains("appeared"), "{error:#}");
        std::fs::remove_file(&preload).unwrap();

        std::fs::write(&preload, []).unwrap();
        std::fs::set_permissions(&preload, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut retained = 0;
        let state = PreloadState::capture(&authority, |_| {
            retained += 1;
            Ok(())
        })
        .unwrap();
        assert!(!state.is_absent());
        assert_eq!(retained, 1);
        state.revalidate().unwrap();

        std::fs::write(&preload, b"injected.so\n").unwrap();
        retained = 0;
        assert!(
            PreloadState::capture(&authority, |_| {
                retained += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(retained, 1, "content was checked before retention");

        std::fs::write(&preload, []).unwrap();
        let replacement = root.path().join("etc/replacement");
        let error = PreloadState::capture(&authority, |_| {
            std::fs::rename(&preload, root.path().join("etc/original"))?;
            std::fs::write(&replacement, [])?;
            std::fs::rename(&replacement, &preload)?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed"), "{error:#}");
    }

    #[test]
    fn glibc_interpreter_path_walks_bounded_protected_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let loader = root
            .path()
            .join("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        std::fs::copy("/bin/true", &loader).unwrap();
        std::fs::set_permissions(&loader, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("usr/lib/x86_64-linux-gnu", root.path().join("lib64")).unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();

        let interpreter = authority
            .open_regular(Path::new(GLIBC_INTERP), false)
            .unwrap()
            .unwrap();
        assert_eq!(
            mapping_file_key(&interpreter).unwrap(),
            mapping_file_key(&std::fs::File::open(&loader).unwrap()).unwrap()
        );

        for index in 0..9 {
            let target = if index == 8 {
                OsString::from("usr/lib/x86_64-linux-gnu")
            } else {
                OsString::from(format!("link{}", index + 1))
            };
            std::os::unix::fs::symlink(target, root.path().join(format!("link{index}"))).unwrap();
        }
        let error = authority
            .open_regular(Path::new("/link0/ld-linux-x86-64.so.2"), false)
            .unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
    }

    #[test]
    fn glibc_runtime_candidates_use_strict_same_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu", "usr/lib64"] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let first = root.path().join("usr/lib/x86_64-linux-gnu");
        let second = root.path().join("usr/lib64");
        std::fs::copy("/bin/true", first.join("libc.so.6")).unwrap();
        std::fs::set_permissions(
            first.join("libc.so.6"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::hard_link(first.join("libc.so.6"), second.join("libc-real.so.6")).unwrap();
        std::os::unix::fs::symlink("libc-real.so.6", second.join("libc.so.6")).unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();
        let directories = [
            authority
                .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), false)
                .unwrap()
                .unwrap(),
            authority
                .open_directory(Path::new("/usr/lib64"), false)
                .unwrap()
                .unwrap(),
        ];

        let candidates = runtime_candidates(&directories, OsStr::new("libc.so.6"), unsafe {
            libc::geteuid()
        })
        .unwrap();
        assert_eq!(candidates.len(), 2);
        unique_runtime_candidate(candidates).unwrap();

        std::fs::copy("/bin/true", first.join("libgcc_s.so.1")).unwrap();
        std::fs::set_permissions(
            first.join("libgcc_s.so.1"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../lib/x86_64-linux-gnu/libgcc_s.so.1",
            second.join("libgcc_s.so.1"),
        )
        .unwrap();
        let error = runtime_candidates(&directories, OsStr::new("libgcc_s.so.1"), unsafe {
            libc::geteuid()
        })
        .unwrap_err();
        assert!(error.to_string().contains("symlink target"), "{error:#}");
    }

    #[test]
    fn glibc_private_alias_directory_revalidates_and_cleans_exactly() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("run/p11scope")).unwrap();
        for directory in ["run", "run/p11scope"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();
        let parent = authority
            .open_directory(Path::new("/run/p11scope"), false)
            .unwrap()
            .unwrap();
        let target = normalize_file_fd(std::fs::File::open("/bin/true").unwrap()).unwrap();
        let replacement = normalize_file_fd(std::fs::File::open("/bin/false").unwrap()).unwrap();
        assert!(target.as_raw_fd() > 2);
        assert!(replacement.as_raw_fd() > 2);
        let mut private =
            PrivateAliasDir::create(&parent, owner, vec![(OsString::from("libc.so.6"), &target)])
                .unwrap();
        let random_name = private
            .name()
            .to_str()
            .unwrap()
            .strip_prefix("oracle-")
            .unwrap();
        assert_eq!(random_name.len(), 32);
        assert!(random_name.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let child = root.path().join("run/p11scope").join(private.name());
        let alias = child.join("libc.so.6");
        assert_eq!(
            std::fs::read_link(&alias).unwrap(),
            PathBuf::from(format!("/proc/self/fd/{}", target.as_raw_fd()))
        );
        private.revalidate().unwrap();

        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::os::unix::fs::symlink("/proc/self/fd/0", child.join("extra")).unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        assert!(
            private
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("entry set")
        );
        assert!(private.cleanup().is_err());
        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::fs::remove_file(child.join("extra")).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", replacement.as_raw_fd()), &alias)
            .unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        assert!(
            private
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("alias")
        );
        assert!(private.cleanup().is_err());
        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", target.as_raw_fd()), &alias)
            .unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        private.cleanup().unwrap();
        assert!(!child.exists());

        let dropped_name = {
            let private = PrivateAliasDir::create(
                &parent,
                owner,
                vec![(OsString::from("libc.so.6"), &target)],
            )
            .unwrap();
            private.name().to_os_string()
        };
        assert!(!root.path().join("run/p11scope").join(dropped_name).exists());
    }

    #[test]
    fn glibc_private_alias_cleanup_retries_after_partial_unlink() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("run/p11scope")).unwrap();
        for directory in ["run", "run/p11scope"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();
        let parent = authority
            .open_directory(Path::new("/run/p11scope"), false)
            .unwrap()
            .unwrap();
        let target = normalize_file_fd(std::fs::File::open("/bin/true").unwrap()).unwrap();
        let mut private = PrivateAliasDir::create(
            &parent,
            owner,
            vec![
                (OsString::from("libc.so.6"), &target),
                (OsString::from("libgcc_s.so.1"), &target),
            ],
        )
        .unwrap();
        private.revalidate().unwrap();
        assert_eq!(unsafe { libc::fchmod(private.directory_fd(), 0o700) }, 0);
        private.ready = false;
        let mut unlinks = 0;
        let error = private
            .unlink_aliases(|directory, name| {
                unlinks += 1;
                if unlinks == 2 {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(private.aliases.len(), 1);
        private.cleanup().unwrap();

        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0
        );
        let failed =
            PrivateAliasDir::create(&parent, owner, vec![(OsString::from("$ORIGIN"), &target)]);
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0,
            "initialization failure leaked the exact empty child"
        );

        let mut partial = PrivateAliasDir::create(&parent, owner, Vec::new()).unwrap();
        let partial_name = partial.name().to_os_string();
        assert_eq!(unsafe { libc::fchmod(partial.directory_fd(), 0o700) }, 0);
        partial.ready = false;
        partial.directory = None;
        partial.cleanup().unwrap();
        assert!(
            std::fs::symlink_metadata(root.path().join("run/p11scope").join(partial_name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        );
    }
}
