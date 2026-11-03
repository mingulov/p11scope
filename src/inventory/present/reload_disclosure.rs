//! SPDX-License-Identifier: GPL-3.0-or-later
//! B17 leg-2 inventory projection of the staged reload-disclosure ledger.
//!
//! The projection resolves each ledger identity's router IDs through their
//! registered instances and groups them by the module conversion recorded,
//! so the published object names only capture-local `mN`/`iN` references
//! plus the exact router count snapshots. Unregistered IDs are omitted and
//! identities with nothing nameable are dropped; the counts stay exact.

/// Insert the staged reload disclosure as the top-level
/// `instance_reload_not_excluded` object: exact router counts plus one
/// entry per affected module with its disclosed `iN` references. The key
/// stays absent (never null) when the capture produced no disclosure.
pub(crate) fn insert_reload_disclosure_json(
    document: &mut serde_json::Value,
    presentation: &super::Presentation,
) {
    let Some(view) = presentation.instance_reload_not_excluded.as_ref() else {
        return;
    };
    let Some(object) = document.as_object_mut() else {
        return;
    };
    object.insert(
        "instance_reload_not_excluded".to_string(),
        serde_json::json!({
            "continued_across_global": view.continued_across_global,
            "joined_across_global": view.joined_across_global,
            "identities": view.identities.iter().map(|identity| serde_json::json!({
                "module": identity.module.label(),
                "instances": identity.instances.iter().map(|id| id.label()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }),
    );
}

#[cfg(test)]
mod tests {
    use crate::attach::Scope;
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{
        AdmittedInstance, InstanceKey, RegistryInstanceId,
    };
    use crate::discovery::caller_registry::{
        CallerId, ImageAuthority, ModuleKey, OsProcessSource, RegistryLimits,
    };
    use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::instances::{InstanceId, RELOAD_NOT_EXCLUDED_LABEL};
    use crate::inventory_present::Presentation;
    use crate::semantic_capture::ReloadNotExcludedReport;
    use p11scope_ebpf_common::ImageIdentity;

    const SLOT_A: u32 = 918273;
    const SLOT_B: u32 = 918274;
    const ROUTER_A: u64 = 745021;
    const ROUTER_B: u64 = 745022;
    const IMAGE_A: ImageIdentity = ImageIdentity {
        task_cookie: 6071428351,
        exec_id: 824619,
    };
    const IMAGE_B: ImageIdentity = ImageIdentity {
        task_cookie: 6071428352,
        exec_id: 824620,
    };

    struct Seam {
        coordinator: InventoryCoordinator<OsProcessSource>,
        domain: NativeDomainId,
        caller: CallerId,
        module_a: String,
        module_b: String,
    }

    fn module_key(ino: u64) -> ModuleKey {
        ModuleKey::Physical {
            dev_major: 8,
            dev_minor: 1,
            ino,
            sha256: None,
        }
    }

    /// A coordinator with an admitted caller, two modules with one caller
    /// edge each, and one registered instance each (`i0` under A, `i1`
    /// under B): the seam state a live capture produces, without the lane.
    fn seam() -> Seam {
        let domain = NativeDomainId::try_mint().expect("a fresh test domain");
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        // The presentation resolves every edge caller in the adapter, so
        // admit this test process as the calling incarnation (scan-pinned:
        // no BPF identity in an unprivileged test).
        let caller = coordinator
            .adapter_mut()
            .admit(std::process::id(), ImageAuthority::ScanPinned, 1000)
            .expect("self admission pins /proc");
        let key_a = module_key(1001);
        let key_b = module_key(1002);
        let module_a = coordinator
            .registry_mut()
            .scripted_module_edge(key_a.clone(), caller)
            .label();
        let module_b = coordinator
            .registry_mut()
            .scripted_module_edge(key_b.clone(), caller)
            .label();
        for (image, router, module) in [(IMAGE_A, ROUTER_A, key_a), (IMAGE_B, ROUTER_B, key_b)] {
            let key = InstanceKey::scripted(domain, image, InstanceId::from_raw(router), module);
            coordinator
                .registry_mut()
                .note_instance(AdmittedInstance::scripted(key, caller));
        }
        coordinator.registry_mut().publish();
        assert_eq!(coordinator.registry().instances().count(), 2);
        Seam {
            coordinator,
            domain,
            caller,
            module_a,
            module_b,
        }
    }

    fn disclose(
        seam: &mut Seam,
        image: ImageIdentity,
        slot: u32,
        ids: Vec<u64>,
        continued: u64,
        joined: u64,
    ) {
        seam.coordinator.drain_reload_disclosures_into_ledger(
            seam.domain,
            vec![ReloadNotExcludedReport {
                label: RELOAD_NOT_EXCLUDED_LABEL,
                image,
                file_slot: slot,
                ids: ids.into_iter().map(InstanceId::from_raw).collect(),
            }],
            continued,
            joined,
            0,
        );
    }

    fn document(seam: &Seam) -> serde_json::Value {
        let presentation = Presentation::capture(&seam.coordinator, "seam", 1000, 2000, 1);
        crate::inventory::render_json_from_presentation(&presentation)
    }

    fn instance0() -> String {
        RegistryInstanceId::from_raw(0).label()
    }

    /// (a) One churned identity renders the object with its module and
    /// instance, exact closed shape.
    #[test]
    fn disclosed_identity_renders_module_and_instance() {
        let mut seam = seam();
        disclose(&mut seam, IMAGE_A, SLOT_A, vec![ROUTER_A], 1, 1);
        let document = document(&seam);
        // The fixture itself is a live two-instance capture: both rows
        // render under the admitted caller before the disclosure does.
        let rows = document["instances"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(rows.len(), 2, "both instances render: {rows:?}");
        assert!(
            rows.iter().any(|row| row["module"] == seam.module_a
                && row["caller"] == seam.caller.label()
                && row["id"] == instance0()),
            "the churned instance row renders: {rows:?}"
        );
        let key = &document["instance_reload_not_excluded"];
        assert_eq!(
            *key,
            serde_json::json!({
                "continued_across_global": 1,
                "joined_across_global": 1,
                "identities": [
                    {"module": seam.module_a, "instances": [instance0()]}
                ],
            }),
            "the churned identity renders exactly"
        );
    }

    /// (b) A capture with no disclosure omits the key entirely (never
    /// null): the absent-by-default control.
    #[test]
    fn clean_capture_omits_the_key() {
        let seam = seam();
        let document = document(&seam);
        assert!(
            document.get("instance_reload_not_excluded").is_none(),
            "no disclosure means no key"
        );
    }

    /// (c) Mint exhaustion (counts without identities) renders the counts
    /// with an empty list: activity is disclosed, nothing is invented.
    #[test]
    fn mint_exhaustion_renders_counts_with_empty_identities() {
        let mut seam = seam();
        seam.coordinator
            .drain_reload_disclosures_into_ledger(seam.domain, Vec::new(), 3, 2, 0);
        let document = document(&seam);
        assert_eq!(
            document["instance_reload_not_excluded"],
            serde_json::json!({
                "continued_across_global": 3,
                "joined_across_global": 2,
                "identities": [],
            }),
        );
    }

    /// (d) A two-identity capture names only the churned one: the live
    /// control module has no entry.
    #[test]
    fn two_identity_capture_names_only_the_churned_one() {
        let mut seam = seam();
        disclose(&mut seam, IMAGE_A, SLOT_A, vec![ROUTER_A], 2, 1);
        let document = document(&seam);
        let identities = document["instance_reload_not_excluded"]["identities"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(identities.len(), 1, "only the churned one: {identities:?}");
        assert_eq!(identities[0]["module"], seam.module_a);
        assert!(
            !identities
                .iter()
                .any(|identity| identity["module"] == seam.module_b),
            "the control must stay unnamed"
        );
    }

    /// (d2) Two ledger entries under one module merge into one entry with
    /// the sorted union of instances.
    #[test]
    fn same_module_identities_merge_sorted() {
        let domain = NativeDomainId::try_mint().expect("a fresh test domain");
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let caller = coordinator
            .adapter_mut()
            .admit(std::process::id(), ImageAuthority::ScanPinned, 1000)
            .expect("self admission pins /proc");
        let key = module_key(2001);
        let module = coordinator
            .registry_mut()
            .scripted_module_edge(key.clone(), caller)
            .label();
        for (image, router) in [(IMAGE_A, ROUTER_A), (IMAGE_B, ROUTER_B)] {
            let instance =
                InstanceKey::scripted(domain, image, InstanceId::from_raw(router), key.clone());
            coordinator
                .registry_mut()
                .note_instance(AdmittedInstance::scripted(instance, caller));
        }
        coordinator.registry_mut().publish();
        for (image, slot, router) in [(IMAGE_A, SLOT_A, ROUTER_A), (IMAGE_B, SLOT_B, ROUTER_B)] {
            coordinator.drain_reload_disclosures_into_ledger(
                domain,
                vec![ReloadNotExcludedReport {
                    label: RELOAD_NOT_EXCLUDED_LABEL,
                    image,
                    file_slot: slot,
                    ids: vec![InstanceId::from_raw(router)],
                }],
                2,
                2,
                0,
            );
        }
        let seam = Seam {
            coordinator,
            domain,
            caller,
            module_a: module.clone(),
            module_b: module.clone(),
        };
        let document = document(&seam);
        assert_eq!(
            document["instance_reload_not_excluded"]["identities"],
            serde_json::json!([
                {"module": module, "instances": [instance0(), RegistryInstanceId::from_raw(1).label()]}
            ]),
        );
    }

    /// (d3) Twelve modules disclosed in reverse ledger order still
    /// render in numeric module order: multi-module ordering follows
    /// the minted module sequence, not disclosure order — and with
    /// `m10`/`m11` present a label-string sort would observably differ.
    #[test]
    fn twelve_modules_disclosed_in_reverse_render_in_numeric_order() {
        const COUNT: u32 = 12;
        let domain = NativeDomainId::try_mint().expect("a fresh test domain");
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let caller = coordinator
            .adapter_mut()
            .admit(std::process::id(), ImageAuthority::ScanPinned, 1000)
            .expect("self admission pins /proc");
        let mut minted = Vec::new();
        let mut reports = Vec::new();
        for i in 0..COUNT {
            let key = module_key(3001 + u64::from(i));
            minted.push(
                coordinator
                    .registry_mut()
                    .scripted_module_edge(key.clone(), caller)
                    .label(),
            );
            let image = ImageIdentity {
                task_cookie: 6071429000 + u64::from(i),
                exec_id: 825000 + u64::from(i),
            };
            let router = 746000 + u64::from(i);
            let instance =
                InstanceKey::scripted(domain, image, InstanceId::from_raw(router), key.clone());
            coordinator
                .registry_mut()
                .note_instance(AdmittedInstance::scripted(instance, caller));
            reports.push(ReloadNotExcludedReport {
                label: RELOAD_NOT_EXCLUDED_LABEL,
                image,
                file_slot: 919000 + i,
                ids: vec![InstanceId::from_raw(router)],
            });
        }
        coordinator.registry_mut().publish();
        reports.reverse();
        coordinator.drain_reload_disclosures_into_ledger(
            domain,
            reports,
            u64::from(COUNT),
            u64::from(COUNT),
            0,
        );
        let seam = Seam {
            coordinator,
            domain,
            caller,
            module_a: minted[0].clone(),
            module_b: minted[1].clone(),
        };
        let document = document(&seam);
        let identities = document["instance_reload_not_excluded"]["identities"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let rendered: Vec<String> = identities
            .iter()
            .map(|identity| identity["module"].as_str().unwrap_or("!?").to_string())
            .collect();
        assert_eq!(rendered, minted, "disclosure follows minted module order");
        let numeric: Vec<u32> = rendered
            .iter()
            .map(|label| label.trim_start_matches('m').parse().expect("mN label"))
            .collect();
        let mut sorted = numeric.clone();
        sorted.sort_unstable();
        assert_eq!(numeric, sorted, "the pinned order is numeric: {rendered:?}");
        let mut lexicographic = rendered.clone();
        lexicographic.sort();
        assert_ne!(
            rendered, lexicographic,
            "the fixture must separate numeric from label order"
        );
        for (identity, i) in identities.iter().zip(0..COUNT) {
            assert_eq!(
                identity["instances"],
                serde_json::json!([RegistryInstanceId::from_raw(i).label()]),
                "each module names only its own instance"
            );
        }
    }

    /// An unregistered router ID is omitted from its identity rather than
    /// invented: only the registered instance is named.
    #[test]
    fn unregistered_router_id_is_omitted() {
        let mut seam = seam();
        disclose(&mut seam, IMAGE_A, SLOT_A, vec![ROUTER_A, 999999], 1, 1);
        let document = document(&seam);
        assert_eq!(
            document["instance_reload_not_excluded"]["identities"],
            serde_json::json!([
                {"module": seam.module_a, "instances": [instance0()]}
            ]),
        );
    }

    /// An identity whose every router ID is unregistered is dropped
    /// whole, while the key stays present with exact counts: the
    /// router observed continuations it could not attribute.
    #[test]
    fn all_unregistered_identity_is_dropped_with_exact_counts() {
        let mut seam = seam();
        disclose(&mut seam, IMAGE_A, SLOT_A, vec![999998, 999999], 3, 7);
        let document = document(&seam);
        let key = &document["instance_reload_not_excluded"];
        assert!(key.is_object(), "the key stays present: {document}");
        assert_eq!(key["identities"], serde_json::json!([]));
        assert_eq!(key["continued_across_global"], 3);
        assert_eq!(key["joined_across_global"], 7);
    }

    /// (e) The rendered disclosure carries no private identity: no file
    /// slot, router ID, task cookie or exec ID in field names or values —
    /// only `mN`/`iN` references and counts.
    #[test]
    fn rendered_disclosure_carries_no_private_identity() {
        let mut seam = seam();
        disclose(&mut seam, IMAGE_A, SLOT_A, vec![ROUTER_A], 1, 1);
        let document = document(&seam);
        let rendered = serde_json::to_string(&document["instance_reload_not_excluded"]).unwrap();
        for private in [
            SLOT_A.to_string(),
            ROUTER_A.to_string(),
            IMAGE_A.task_cookie.to_string(),
            IMAGE_A.exec_id.to_string(),
            "file_slot".to_string(),
            "task_cookie".to_string(),
            "exec_id".to_string(),
            "router".to_string(),
        ] {
            assert!(
                !rendered.contains(&private),
                "private value {private} must not render: {rendered}"
            );
        }
        assert!(
            rendered.contains(&format!("\"{}\"", seam.module_a)),
            "the module reference renders: {rendered}"
        );
        assert!(
            rendered.contains(&format!("\"{}\"", instance0())),
            "the instance reference renders: {rendered}"
        );
    }
}
