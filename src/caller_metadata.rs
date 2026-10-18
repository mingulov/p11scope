// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, private parsing of cgroup-v2 membership paths into display-only hints.
//!
//! This module performs no I/O. The input path is borrowed only for the duration
//! of parsing and is never copied into the returned value.

pub(crate) mod acquisition;
pub(crate) mod consumer;
pub(crate) mod presentation;
pub(crate) mod runtime;

/// Maximum complete cgroup-file size accepted by the parser.
pub const MAX_CGROUP_BYTES: usize = 16 * 1024;
/// Maximum number of complete membership rows accepted.
pub const MAX_CGROUP_ROWS: usize = 32;
/// Maximum path components accepted in a unified membership path.
pub const MAX_PATH_COMPONENTS: usize = 64;
/// Maximum bytes in one path component.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Result of parsing one complete `/proc/<pid>/cgroup` snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupMembership {
    pub status: ParseStatus,
    pub reason: Option<ParseReason>,
    pub container: Option<ContainerHint>,
    pub pod: Option<PodHint>,
}

/// A finite parse outcome. `Unrecognized` means a valid v2 membership whose
/// path does not match a supported workload grammar; it does not mean outside a
/// container or pod.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseStatus {
    Recognized,
    Unrecognized,
    Refused,
}

/// Finite reasons for refusing or failing to recognize cgroup metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseReason {
    ByteLimit,
    RowLimit,
    ComponentLimit,
    ComponentTooLong,
    Malformed,
    MalformedEscape,
    HierarchyUnsupported,
    MembershipAmbiguous,
    Unrecognized,
    AmbiguousPattern,
}

/// Fixed-size, canonical lowercase 64-character container ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerId([u8; 64]);

impl ContainerId {
    pub fn as_str(&self) -> &str {
        // Construction accepts only ASCII hexadecimal bytes.
        std::str::from_utf8(&self.0).expect("container id is ASCII")
    }
}

/// Fixed-size, canonical lowercase 36-character pod UID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PodUid([u8; 36]);

impl PodUid {
    pub fn as_str(&self) -> &str {
        // Construction accepts only ASCII hexadecimal bytes and separators.
        std::str::from_utf8(&self.0).expect("pod UID is ASCII")
    }
}

/// Finite runtime inference from an exact cgroup component grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHint {
    Unknown,
    Docker,
    Containerd,
    CriO,
}

/// Lexical hints always carry this provenance and are never runtime verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HintSource {
    CgroupPathPattern,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerHint {
    pub id: ContainerId,
    pub runtime: RuntimeHint,
    pub source: HintSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PodHint {
    pub uid: PodUid,
    pub source: HintSource,
}

impl CgroupMembership {
    fn refused(reason: ParseReason) -> Self {
        Self {
            status: ParseStatus::Refused,
            reason: Some(reason),
            container: None,
            pod: None,
        }
    }
}

/// Parse complete cgroup membership bytes without retaining or exposing paths.
/// The caller must use a bounded read with a 16 KiB + 1 probe so a truncated
/// prefix cannot be mistaken for the whole file.
pub fn parse_cgroup_membership(input: &[u8]) -> CgroupMembership {
    if input.len() > MAX_CGROUP_BYTES {
        return CgroupMembership::refused(ParseReason::ByteLimit);
    }
    if input.is_empty()
        || input.ends_with(b"\n\n")
        || input
            .iter()
            .any(|b| *b == 0 || (*b < 0x20 && *b != b'\n') || *b == 0x7f)
    {
        return CgroupMembership::refused(ParseReason::Malformed);
    }

    let input = input.strip_suffix(b"\n").unwrap_or(input);
    let mut rows = 0usize;
    let mut unified_path: Option<&[u8]> = None;
    let mut has_v1 = false;
    let mut remaining = input;
    while !remaining.is_empty() {
        let (line, rest) = match remaining.iter().position(|b| *b == b'\n') {
            Some(n) => (&remaining[..n], &remaining[n + 1..]),
            None => (remaining, &[][..]),
        };
        remaining = rest;
        if line.is_empty() {
            return CgroupMembership::refused(ParseReason::Malformed);
        }
        rows += 1;
        if rows > MAX_CGROUP_ROWS {
            return CgroupMembership::refused(ParseReason::RowLimit);
        }

        let mut fields = line.split(|b| *b == b':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || hierarchy.is_empty()
            || !hierarchy.iter().all(u8::is_ascii_digit)
            || (hierarchy.len() > 1 && hierarchy[0] == b'0')
            || !path.starts_with(b"/")
        {
            return CgroupMembership::refused(ParseReason::Malformed);
        }
        if hierarchy == b"0" && controllers.is_empty() {
            if unified_path.replace(path).is_some() {
                return CgroupMembership::refused(ParseReason::MembershipAmbiguous);
            }
        } else {
            if !valid_controller_list(controllers) {
                return CgroupMembership::refused(ParseReason::Malformed);
            }
            has_v1 = true;
        }
    }
    if rows == 0 {
        return CgroupMembership::refused(ParseReason::Malformed);
    }
    if has_v1 {
        return CgroupMembership::refused(ParseReason::HierarchyUnsupported);
    }
    let Some(path) = unified_path else {
        return CgroupMembership::refused(ParseReason::HierarchyUnsupported);
    };

    let components = match validate_path(path) {
        Ok(components) => components,
        Err(reason) => return CgroupMembership::refused(reason),
    };
    let ParsedHints { container, pod } = match recognize_components(&components) {
        Ok(Some(hints)) => hints,
        Ok(None) => {
            return CgroupMembership {
                status: ParseStatus::Unrecognized,
                reason: Some(ParseReason::Unrecognized),
                container: None,
                pod: None,
            };
        }
        Err(reason) => return CgroupMembership::refused(reason),
    };
    CgroupMembership {
        status: ParseStatus::Recognized,
        reason: None,
        container,
        pod,
    }
}

fn valid_controller_list(controllers: &[u8]) -> bool {
    !controllers.is_empty()
        && controllers.split(|b| *b == b',').all(|name| {
            !name.is_empty()
                && name
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        })
}

fn validate_path(path: &[u8]) -> Result<Vec<&[u8]>, ParseReason> {
    if !path.starts_with(b"/") || path.is_empty() {
        return Err(ParseReason::Malformed);
    }
    if path.len() == 1 {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in path[1..].split(|b| *b == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(ParseReason::Malformed);
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(ParseReason::ComponentTooLong);
        }
        validate_escapes(component)?;
        components.push(component);
        if components.len() > MAX_PATH_COMPONENTS {
            return Err(ParseReason::ComponentLimit);
        }
    }
    Ok(components)
}

fn validate_escapes(component: &[u8]) -> Result<(), ParseReason> {
    let mut index = 0;
    while index < component.len() {
        if component[index] != b'\\' {
            index += 1;
            continue;
        }
        if component.get(index + 1) != Some(&b'x')
            || !component.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            || !component.get(index + 3).is_some_and(u8::is_ascii_hexdigit)
        {
            return Err(ParseReason::MalformedEscape);
        }
        index += 4;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ContainerCandidate {
    hint: ContainerHint,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct PodCandidate {
    hint: PodHint,
    container: ContainerCandidate,
}

#[derive(Clone, Copy)]
struct ParsedHints {
    container: Option<ContainerHint>,
    pod: Option<PodHint>,
}

fn recognize_components(components: &[&[u8]]) -> Result<Option<ParsedHints>, ParseReason> {
    let mut containers = Vec::new();
    let mut pods = Vec::new();
    for start in 0..components.len() {
        if let Some(candidate) = parse_docker_cgroupfs(components, start) {
            containers.push(candidate);
        }
        if let Some(candidate) = parse_runtime_unit(components[start]) {
            containers.push(ContainerCandidate {
                hint: candidate,
                start,
                end: start + 1,
            });
        }
        if let Some(candidate) = parse_k8s_cgroupfs(components, start) {
            containers.push(candidate.container);
            pods.push(candidate);
        }
        if let Some(candidate) = parse_k8s_systemd(components, start) {
            containers.push(candidate.container);
            pods.push(candidate);
        }
    }
    if containers.is_empty() && pods.is_empty() {
        return Ok(None);
    }
    if pods
        .windows(2)
        .any(|pair| pair[0].hint.uid != pair[1].hint.uid)
    {
        return Err(ParseReason::AmbiguousPattern);
    }
    let pod = pods.iter().max_by_key(|p| p.container.end).copied();
    let container = containers.iter().max_by_key(|c| c.end).copied();
    if let (Some(pod), Some(container)) = (pod, container) {
        if container.end > pod.container.end && container.start >= pod.container.end {
            return Err(ParseReason::AmbiguousPattern);
        }
        if container.start == pod.container.start && container.hint.id != pod.container.hint.id {
            return Err(ParseReason::AmbiguousPattern);
        }
    }
    Ok(Some(ParsedHints {
        container: container.map(|c| c.hint),
        pod: pod.map(|p| p.hint),
    }))
}

fn parse_docker_cgroupfs(components: &[&[u8]], start: usize) -> Option<ContainerCandidate> {
    if components.get(start).copied() != Some(&b"docker"[..]) {
        return None;
    }
    let id = parse_container_id(components.get(start + 1).copied()?)?;
    Some(ContainerCandidate {
        hint: ContainerHint {
            id,
            runtime: RuntimeHint::Docker,
            source: HintSource::CgroupPathPattern,
        },
        start,
        end: start + 2,
    })
}

fn parse_runtime_unit(component: &[u8]) -> Option<ContainerHint> {
    let (prefix, suffix, runtime) =
        if component.starts_with(b"docker-") && component.ends_with(b".scope") {
            (
                b"docker-".as_slice(),
                b".scope".as_slice(),
                RuntimeHint::Docker,
            )
        } else if component.starts_with(b"cri-containerd-") && component.ends_with(b".scope") {
            (
                b"cri-containerd-".as_slice(),
                b".scope".as_slice(),
                RuntimeHint::Containerd,
            )
        } else if component.starts_with(b"crio-") && component.ends_with(b".scope") {
            (b"crio-".as_slice(), b".scope".as_slice(), RuntimeHint::CriO)
        } else {
            return None;
        };
    let id_bytes = component.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let id = parse_container_id(id_bytes)?;
    Some(ContainerHint {
        id,
        runtime,
        source: HintSource::CgroupPathPattern,
    })
}

fn parse_k8s_cgroupfs(components: &[&[u8]], start: usize) -> Option<PodCandidate> {
    if components.get(start).copied() != Some(&b"kubepods"[..]) {
        return None;
    }
    let mut pod_index = start + 1;
    if matches!(
        components.get(pod_index),
        Some(&b"burstable" | &b"besteffort")
    ) {
        pod_index += 1;
    }
    let pod_uid = parse_pod_component(components.get(pod_index).copied()?)?;
    let container_index = pod_index + 1;
    let id = parse_container_id(components.get(container_index).copied()?)?;
    let container = ContainerCandidate {
        hint: ContainerHint {
            id,
            runtime: RuntimeHint::Unknown,
            source: HintSource::CgroupPathPattern,
        },
        start,
        end: container_index + 1,
    };
    Some(PodCandidate {
        hint: PodHint {
            uid: pod_uid,
            source: HintSource::CgroupPathPattern,
        },
        container,
    })
}

fn parse_k8s_systemd(components: &[&[u8]], start: usize) -> Option<PodCandidate> {
    if components.get(start).copied() != Some(&b"kubepods.slice"[..]) {
        return None;
    }
    let mut pod_index = start + 1;
    let qos = match components.get(pod_index).copied() {
        Some(b"kubepods-burstable.slice") => {
            pod_index += 1;
            Some(b"burstable".as_slice())
        }
        Some(b"kubepods-besteffort.slice") => {
            pod_index += 1;
            Some(b"besteffort".as_slice())
        }
        _ => None,
    };
    let pod_uid = parse_systemd_pod_component(components.get(pod_index).copied()?, qos)?;
    let runtime_index = pod_index + 1;
    let hint = parse_runtime_unit(components.get(runtime_index).copied()?)?;
    let container = ContainerCandidate {
        hint,
        start,
        end: runtime_index + 1,
    };
    Some(PodCandidate {
        hint: PodHint {
            uid: pod_uid,
            source: HintSource::CgroupPathPattern,
        },
        container,
    })
}

fn parse_pod_component(component: &[u8]) -> Option<PodUid> {
    parse_pod_uid(component.strip_prefix(b"pod")?)
}

fn parse_systemd_pod_component(component: &[u8], qos: Option<&[u8]>) -> Option<PodUid> {
    let prefix: &[u8] = match qos {
        Some(qos) if qos == b"burstable" => b"kubepods-burstable-pod",
        Some(qos) if qos == b"besteffort" => b"kubepods-besteffort-pod",
        Some(_) => return None,
        None => b"kubepods-pod",
    };
    let uid = component.strip_prefix(prefix)?.strip_suffix(b".slice")?;
    let mut normalized = [0; 36];
    if uid.len() != 36
        || ![8, 13, 18, 23].iter().all(|i| uid[*i] == b'_')
        || !uid
            .iter()
            .enumerate()
            .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
    {
        return None;
    }
    for (index, byte) in uid.iter().copied().enumerate() {
        normalized[index] = if byte == b'_' { b'-' } else { byte };
    }
    parse_pod_uid(&normalized)
}

fn parse_container_id(bytes: &[u8]) -> Option<ContainerId> {
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut id = [0; 64];
    for (out, byte) in id.iter_mut().zip(bytes.iter().copied()) {
        *out = byte.to_ascii_lowercase();
    }
    Some(ContainerId(id))
}

fn parse_pod_uid(bytes: &[u8]) -> Option<PodUid> {
    if bytes.len() != 36
        || ![8, 13, 18, 23].iter().all(|i| bytes[*i] == b'-')
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut uid = [0; 36];
    for (out, byte) in uid.iter_mut().zip(bytes.iter().copied()) {
        *out = byte.to_ascii_lowercase();
    }
    Some(PodUid(uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(path: &str) -> Vec<u8> {
        format!("0::/{path}\n").into_bytes()
    }

    #[test]
    fn parses_exact_docker_cgroupfs_and_systemd_forms() {
        for (path, expected_id) in [
            (format!("docker/{}", "a".repeat(64)), "a".repeat(64)),
            (
                format!("system.slice/docker-{}.scope", "B".repeat(64)),
                "b".repeat(64),
            ),
        ] {
            let parsed = parse_cgroup_membership(&membership(&path));
            assert_eq!(parsed.status, ParseStatus::Recognized);
            let container = parsed.container.expect("container hint");
            assert_eq!(container.runtime, RuntimeHint::Docker);
            assert_eq!(container.id.as_str(), expected_id);
            assert_eq!(parsed.pod, None);
            assert_eq!(container.source, HintSource::CgroupPathPattern);
        }
        let eof_terminated = format!("0::/docker/{}", "a".repeat(64));
        let parsed = parse_cgroup_membership(eof_terminated.as_bytes());
        assert_eq!(parsed.status, ParseStatus::Recognized);
    }

    #[test]
    fn parses_exact_cri_and_kubernetes_forms() {
        let id = "c".repeat(64);
        for (unit, runtime) in [
            (
                format!("cri-containerd-{id}.scope"),
                RuntimeHint::Containerd,
            ),
            (format!("crio-{id}.scope"), RuntimeHint::CriO),
        ] {
            let parsed = parse_cgroup_membership(&membership(&format!("kubepods.slice/{unit}")));
            assert_eq!(parsed.container.unwrap().runtime, runtime);
        }

        let pod = "12345678-1234-abcd-9876-1234567890ab";
        let parsed =
            parse_cgroup_membership(&membership(&format!("kubepods/burstable/pod{pod}/{id}")));
        assert_eq!(parsed.status, ParseStatus::Recognized);
        assert_eq!(parsed.container.unwrap().runtime, RuntimeHint::Unknown);
        assert_eq!(parsed.pod.unwrap().uid.as_str(), pod);

        let systemd_pod = pod.replace('-', "_");
        let parsed = parse_cgroup_membership(&membership(&format!(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{systemd_pod}.slice/cri-containerd-{id}.scope"
        )));
        assert_eq!(parsed.status, ParseStatus::Recognized);
        assert_eq!(parsed.container.unwrap().runtime, RuntimeHint::Containerd);
        assert_eq!(parsed.pod.unwrap().uid.as_str(), pod);
    }

    #[test]
    fn recognizes_every_supported_kubernetes_qos_sequence() {
        let uid = "12345678-1234-abcd-9876-1234567890ab";
        let id = "d".repeat(64);
        for path in [
            format!("kubepods/pod{uid}/{id}"),
            format!("kubepods/burstable/pod{uid}/{id}"),
            format!("kubepods/besteffort/pod{uid}/{id}"),
        ] {
            let parsed = parse_cgroup_membership(&membership(&path));
            assert_eq!(parsed.status, ParseStatus::Recognized, "{path}");
            assert_eq!(parsed.container.unwrap().runtime, RuntimeHint::Unknown);
            assert_eq!(parsed.pod.unwrap().uid.as_str(), uid);
        }

        let systemd_uid = uid.replace('-', "_");
        for (qos_dir, pod_prefix) in [
            (None, "kubepods-pod"),
            (Some("kubepods-burstable.slice"), "kubepods-burstable-pod"),
            (Some("kubepods-besteffort.slice"), "kubepods-besteffort-pod"),
        ] {
            let qos_dir = qos_dir.map(|s| format!("{s}/")).unwrap_or_default();
            let path = format!(
                "kubepods.slice/{qos_dir}{pod_prefix}{systemd_uid}.slice/crio-{}.scope",
                id.to_uppercase()
            );
            let parsed = parse_cgroup_membership(&membership(&path));
            assert_eq!(parsed.status, ParseStatus::Recognized, "{path}");
            assert_eq!(parsed.container.unwrap().runtime, RuntimeHint::CriO);
            assert_eq!(parsed.pod.unwrap().uid.as_str(), uid);
        }
    }

    #[test]
    fn unknown_is_not_reported_as_outside_container() {
        let parsed = parse_cgroup_membership(&membership("user.slice/workload"));
        assert_eq!(parsed.status, ParseStatus::Unrecognized);
        assert_eq!(parsed.reason, Some(ParseReason::Unrecognized));
        assert_eq!(parsed.container, None);
        assert_eq!(parsed.pod, None);
    }

    #[test]
    fn rejects_near_misses_and_unsafe_or_unbounded_inputs() {
        let id = "a".repeat(64);
        for path in [
            format!("docker/{}", &id[..12]),
            format!("prefix-docker-{id}.scope"),
            format!("docker/{id}x"),
            format!("docker/../{id}"),
            format!("docker//{id}"),
            format!("docker/{id}/."),
            format!("docker/{id}\\x2"),
        ] {
            let mut bytes = membership(&path);
            if path.contains("../") || path.ends_with("/.") {
                assert_eq!(parse_cgroup_membership(&bytes).status, ParseStatus::Refused);
            } else if path.contains("\\x2") {
                assert_eq!(
                    parse_cgroup_membership(&bytes).reason,
                    Some(ParseReason::MalformedEscape)
                );
            } else {
                assert_ne!(
                    parse_cgroup_membership(&bytes).status,
                    ParseStatus::Recognized,
                    "unexpected recognition for {path:?}"
                );
            }
            bytes.fill(0);
        }

        assert_eq!(
            parse_cgroup_membership(&vec![b'x'; MAX_CGROUP_BYTES + 1]).reason,
            Some(ParseReason::ByteLimit)
        );
        let rows = (0..MAX_CGROUP_ROWS + 1)
            .map(|i| format!("{}:cpu:/x\n", i + 1))
            .collect::<String>();
        assert_eq!(
            parse_cgroup_membership(rows.as_bytes()).reason,
            Some(ParseReason::RowLimit)
        );
        let boundary_rows = std::iter::once("0::/known\n".to_owned())
            .chain((1..MAX_CGROUP_ROWS).map(|i| format!("{i}:cpu:/legacy\n")))
            .collect::<String>();
        assert_eq!(
            parse_cgroup_membership(boundary_rows.as_bytes()).reason,
            Some(ParseReason::HierarchyUnsupported)
        );

        let too_deep = format!("{}/docker/{id}", vec!["a"; MAX_PATH_COMPONENTS].join("/"));
        assert_eq!(
            parse_cgroup_membership(&membership(&too_deep)).reason,
            Some(ParseReason::ComponentLimit)
        );
        let too_long = format!("{}/docker/{id}", "a".repeat(MAX_COMPONENT_BYTES + 1));
        assert_eq!(
            parse_cgroup_membership(&membership(&too_long)).reason,
            Some(ParseReason::ComponentTooLong)
        );
        let boundary_path = format!(
            "{}/docker/{id}",
            vec!["a"; MAX_PATH_COMPONENTS - 2].join("/")
        );
        assert_eq!(
            parse_cgroup_membership(&membership(&boundary_path)).status,
            ParseStatus::Recognized
        );
        let max_component_path = format!("{}/docker/{id}", "a".repeat(MAX_COMPONENT_BYTES));
        assert_eq!(
            parse_cgroup_membership(&membership(&max_component_path)).status,
            ParseStatus::Recognized
        );
        assert_eq!(
            parse_cgroup_membership(b"0::/docker/a\x01\n").reason,
            Some(ParseReason::Malformed)
        );
        assert_eq!(
            parse_cgroup_membership(b"0::/docker/a\n\n").reason,
            Some(ParseReason::Malformed)
        );
    }

    #[test]
    fn rejects_pod_near_misses_and_malformed_uid_shapes() {
        let id = "e".repeat(64);
        for (path, has_container) in [
            (
                format!("kubepods/pod12345678-1234-abcd-987-1234567890ab/{id}"),
                false,
            ),
            (
                format!("kubepods/notburstable/pod12345678-1234-abcd-9876-1234567890ab/{id}"),
                false,
            ),
            (
                format!(
                    "kubepods/pod12345678-1234-abcd-9876-1234567890ac/{}/tail",
                    "f".repeat(63)
                ),
                false,
            ),
            (
                format!(
                    "kubepods.slice/kubepods.slice-pod12345678_1234_abcd_9876_1234567890ab.slice/unknown-{id}.scope"
                ),
                false,
            ),
            (
                format!(
                    "kubepods.slice/kubepods-pod12345678-1234-abcd-9876-1234567890ab.slice/cri-containerd-{id}.scope"
                ),
                true,
            ),
        ] {
            let parsed = parse_cgroup_membership(&membership(&path));
            assert_eq!(parsed.pod, None);
            assert_eq!(parsed.container.is_some(), has_container, "{path}");
        }
    }

    #[test]
    fn refuses_unsupported_ambiguous_and_malformed_membership() {
        assert_eq!(
            parse_cgroup_membership(b"2:cpu:/legacy\n").reason,
            Some(ParseReason::HierarchyUnsupported)
        );
        assert_eq!(
            parse_cgroup_membership(b"0::/a\n2:cpu:/legacy\n").reason,
            Some(ParseReason::HierarchyUnsupported)
        );
        assert_eq!(
            parse_cgroup_membership(b"0::/a\n0::/b\n").reason,
            Some(ParseReason::MembershipAmbiguous)
        );
        assert_eq!(
            parse_cgroup_membership(b"0::relative\n").reason,
            Some(ParseReason::Malformed)
        );
        assert_eq!(
            parse_cgroup_membership(b"0::/a\0b\n").reason,
            Some(ParseReason::Malformed)
        );
        assert_eq!(
            parse_cgroup_membership(b"00:cpu:/legacy\n").reason,
            Some(ParseReason::Malformed)
        );
        assert_eq!(
            parse_cgroup_membership(b"2:cpu,,:/legacy\n").reason,
            Some(ParseReason::Malformed)
        );
    }

    #[test]
    fn selects_innermost_context_and_refuses_conflicting_pods() {
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        let parsed =
            parse_cgroup_membership(&membership(&format!("docker/{outer}/docker/{inner}")));
        assert_eq!(parsed.container.unwrap().id.as_str(), inner);

        let p1 = "12345678-1234-abcd-9876-1234567890ab";
        let p2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let parsed = parse_cgroup_membership(&membership(&format!(
            "kubepods/pod{p1}/{outer}/kubepods/pod{p2}/{inner}"
        )));
        assert_eq!(parsed.status, ParseStatus::Refused);
        assert_eq!(parsed.reason, Some(ParseReason::AmbiguousPattern));
    }
}
