//! Probe-manifest schema v1. Offsets are ELF object-file byte offsets —
//! aya 0.14 `UProbeAttachLocation::AbsoluteOffset` semantics, pinned in
//! docs/notes/aya-offset-semantics.md. Evidence (NULL entries, vendor
//! interfaces, non-file-backed pointers, acquisition failures) is recorded,
//! never dropped.

use crate::identity::ObjectIdentity;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "p11scope-manifest/1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    /// The dlopen target as given on the command line.
    pub module_path: String,
    /// Every distinct object file some pointer resolved into. Identity is
    /// per object: a table entry may legally live outside the module .so.
    pub objects: Vec<ObjectRecord>,
    /// Outcome of the C_GetInterfaceList enumeration as a whole (the
    /// legacy surface records its own acquisition inside its record).
    pub interface_list: Acquisition,
    pub surfaces: Vec<SurfaceRecord>,
    /// Present-but-undecoded evidence; never walked.
    pub vendor_interfaces: Vec<VendorInterface>,
    /// ≥2 distinct logical names resolving to one {object, file_offset}.
    pub alias_groups: Vec<AliasGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub id: u32,
    pub path: String,
    pub identity: ObjectIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRecord {
    pub source: SurfaceSource,
    pub acquisition: Acquisition,
    /// Reported CK_VERSION of this surface's function list, if any.
    pub version: Option<Version>,
    pub walk: WalkOutcome,
    pub functions: Vec<FunctionRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SurfaceSource {
    /// The legacy 2.40 table from C_GetFunctionList.
    LegacyFunctionList,
    /// One C_GetInterfaceList entry whose name is exactly "PKCS 11".
    Interface { index: usize, raw_name_hex: String, name_lossy: String, flags: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Acquisition {
    Ok,
    /// Symbol not exported — the only proven fact; no generation inference.
    Absent,
    /// Export present, zero interfaces reported.
    Empty,
    Error { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkOutcome {
    /// Every field table for the reported version was walked.
    Full,
    /// 3.x minor > 2: walked tables are a safe prefix; excess exists.
    KnownPrefix,
    /// tables_for refused the layout; nothing walked.
    Refused,
    /// Surface present but unwalkable (NULL function list, failed acquisition).
    NotWalked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub name: String,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Resolution {
    Resolved { object: u32, file_offset: u64 },
    NullPointer,
    /// Pointer lands in an anonymous mapping — evidence gap, not an entry.
    NonFileBacked,
    /// Pointer inside no mapping at all — evidence gap.
    Unmapped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VendorInterface {
    pub index: usize,
    /// Lossless raw bytes of pInterfaceName; None when the pointer was NULL.
    pub raw_name_hex: Option<String>,
    pub name_lossy: Option<String>,
    pub version: Option<Version>,
    pub flags: u64,
    pub func_list_null: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AliasGroup {
    pub object: u32,
    pub file_offset: u64,
    /// Every (surface, name) resolving here — includes same-name
    /// corroborations once the group qualifies (≥2 distinct names).
    pub entries: Vec<AliasEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AliasEntry {
    pub surface: usize,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityKind, ObjectIdentity};

    #[test]
    fn round_trips_through_json() {
        let m = Manifest {
            schema: SCHEMA.to_string(),
            module_path: "/opt/p11.so".into(),
            objects: vec![ObjectRecord {
                id: 0,
                path: "/opt/p11.so".into(),
                identity: ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some("aa".into()),
                    reusable: true,
                    note: None,
                },
            }],
            interface_list: Acquisition::Error { detail: "boom".into() },
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: 2, minor: 40 }),
                walk: WalkOutcome::Full,
                functions: vec![
                    FunctionRecord {
                        name: "C_Initialize".into(),
                        resolution: Resolution::Resolved { object: 0, file_offset: 0x1000 },
                    },
                    FunctionRecord {
                        name: "C_GetFunctionStatus".into(),
                        resolution: Resolution::NullPointer,
                    },
                ],
            }],
            vendor_interfaces: vec![VendorInterface {
                index: 1,
                raw_name_hex: Some("41".into()),
                name_lossy: Some("A".into()),
                version: None,
                flags: 0,
                func_list_null: false,
            }],
            alias_groups: vec![],
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        assert!(json.contains("\"schema\": \"p11scope-manifest/1\""));
        assert!(json.contains("\"status\": \"null_pointer\""));
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}
