//! /proc/<pid>/maps parsing and vaddr → ELF-file-offset resolution now live in
//! `p11scope-manifest::maps` so the observer resolves pointers exactly as this
//! helper does (spec §4.1 step 5).

pub use p11scope_manifest::maps::{
    Device, MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve,
};
