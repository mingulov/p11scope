//! Manifest reuse gate. A manifest's offsets are only meaningful for the
//! exact file image they came from; reusing one against a changed
//! provider would probe the wrong instructions silently. Refuse instead.

use p11scope_manifest::identity::identify;
use p11scope_manifest::manifest::Manifest;
use std::path::Path;

/// `Ok(())` when every recorded object still matches. `Err` lists one
/// reason per object that does not — the caller reports all of them
/// rather than stopping at the first.
pub fn check_reuse(m: &Manifest) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    for obj in &m.objects {
        if !obj.identity.reusable {
            problems.push(format!(
                "{}: manifest identity is not reusable ({})",
                obj.path,
                obj.identity.note.as_deref().unwrap_or("no identity recorded")
            ));
            continue;
        }
        let current = identify(Path::new(&obj.path));
        if !current.reusable {
            problems.push(format!(
                "{}: cannot identify the file now ({})",
                obj.path,
                current.note.as_deref().unwrap_or("unreadable")
            ));
            continue;
        }
        if current.kind != obj.identity.kind || current.value != obj.identity.value {
            problems.push(format!(
                "{}: identity changed since discovery (manifest {:?} {}, current {:?} {}) — \
                 re-run `p11scope discover`",
                obj.path,
                obj.identity.kind,
                obj.identity.value.as_deref().unwrap_or("-"),
                current.kind,
                current.value.as_deref().unwrap_or("-"),
            ));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems) }
}
